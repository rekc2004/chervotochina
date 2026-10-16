//! Приглашение друга от начала до конца (спецификация 13, часть C4, критично).
//!
//! Живое приглашение хранится только в памяти (`State::invites`) и в книге как запись
//! pending. Любой конец приглашения проходит через `finish_invite`/`complete_friend`:
//! запись приглашения и гостевая пара снимаются под тем же замком и в том же вызове
//! `update_book`, что и изменение книги, поэтому один `set_peers` одновременно добавляет
//! друга и убирает гостя; исход выдаётся ровно один раз тому, кто снял запись.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chervo_addr::{PublishCtx, from_invite, note_contact};
use chervo_friends::{FriendBook, FriendsError, MAX_NAME_BYTES, NewFriend, PendingRole};
use chervo_identity::{GuestSecret, KxPeer, KxPublicKey, ListKeyStore, PairId, PublicKey};
use chervo_identity::{SecretStore, load};
use chervo_token::flow::{InviteChannel, exchange_decision, invitee_exchange, inviter_exchange};
use chervo_token::{
    CLOCK_TOLERANCE_SECS, FlowError, InviteDraft, InviteError, InviteeSession, M1_LEN,
    MAX_INVITE_SESSIONS, MAX_TTL_SECS, MIN_TTL_SECS, PendingInvite, Sas, Token, TokenError, decode,
    issue_invite,
};
use chervo_transport::{Connection, ManagedTransport};
use tokio::sync::oneshot;
use tokio::task::AbortHandle;
use tokio::time::{Instant, timeout, timeout_at};

use crate::engine::{ConnectError, Engine, EngineEvent, Inner, InviteAddrs, InviteOutcome, State};
use crate::limiter::add_sat;

/// Пауза после обмена решениями: сторона, прочитавшая решение собеседника, не рвёт гостевое
/// соединение раньше, чем собеседник успеет прочитать её решение. Прерывается закрытием
/// соединения собеседником.
const DECISION_SETTLE: Duration = Duration::from_millis(300);

/// Идущая сессия на гостевом соединении: ручка задачи и соединение (для отмены).
pub(crate) struct ActiveSession<C> {
    abort: AbortHandle,
    conn: C,
}

/// Что известно стороне приглашения.
// Запись приглашения живёт в HashMap и по значению почти не перемещается: размер варианта
// (ключи Ed25519) не важен.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Role {
    Inviter {
        /// `None`, пока идёт сессия (её ведёт задача): второе соединение отклоняется.
        pending: Option<Box<PendingInvite>>,
        our_ed: PublicKey,
        our_x: KxPublicKey,
    },
    Invitee {
        session: Option<Box<InviteeSession>>,
        m1: [u8; M1_LEN],
        inviter_ed: PublicKey,
        inviter_x: KxPublicKey,
        our_ed: PublicKey,
        our_x: KxPublicKey,
        token_addrs: Vec<SocketAddr>,
        sessions_used: u32,
        m1_sent: bool,
    },
}

pub(crate) struct Invite<C> {
    pub(crate) role: Role,
    /// Срок токена (секунды Unix): сессия не длиннее него.
    expires_at: u64,
    /// Когда запись снимается таймером: у пригласившего срок токена, у приглашённого срок
    /// токена с допуском на часы (как срок записи pending в книге).
    dies_at: u64,
    confirm: Option<oneshot::Sender<(bool, String)>>,
    active: Option<ActiveSession<C>>,
}

/// Начало сессии на новом гостевом соединении.
// Короткоживущее значение, создаётся на каждое гостевое соединение.
#[allow(clippy::large_enum_variant)]
enum Begin {
    Inviter {
        pending: Box<PendingInvite>,
        our_ed: PublicKey,
        our_x: KxPublicKey,
        len: Duration,
    },
    Invitee {
        session: Box<InviteeSession>,
        m1: [u8; M1_LEN],
        seed: InviteeSeed,
        len: Duration,
    },
    /// Соединение закрывается, приглашение живёт дальше.
    Reject,
    /// Приглашение кончилось этим исходом; соединение закрывается.
    Finish(InviteOutcome),
}

struct InviteeSeed {
    inviter_ed: PublicKey,
    inviter_x: KxPublicKey,
    our_ed: PublicKey,
    our_x: KxPublicKey,
    token_addrs: Vec<SocketAddr>,
}

/// Исход фазы SAS и решений.
enum SasEnd {
    Decided {
        ours: bool,
        theirs: bool,
        name: String,
    },
    /// Срок, отмена или ошибка обмена после M1.
    Fatal,
}

enum Verdict<X> {
    Done(X),
    Finish(InviteOutcome),
    /// Сессия не удалась до M1 (или M1 отвергнут): приглашение живёт, сессия учтена.
    Retry {
        timed_out: bool,
    },
}

impl<C> Invite<C> {
    /// Приглашённый не набирает гостя во время сессии и после отправки M1: автоповторов
    /// после M1 нет. Пригласивший не набирает никогда.
    pub(crate) fn no_dial(&self) -> bool {
        match &self.role {
            Role::Inviter { .. } => true,
            Role::Invitee {
                session,
                sessions_used,
                m1_sent,
                ..
            } => session.is_none() || *m1_sent || *sessions_used >= MAX_INVITE_SESSIONS,
        }
    }

    fn session_len(&self, unix: u64, cap: Duration) -> Duration {
        cap.min(Duration::from_secs(self.expires_at.saturating_sub(unix)))
    }

    fn begin(&mut self, unix: u64, cap: Duration) -> Begin {
        let len = self.session_len(unix, cap);
        match &mut self.role {
            Role::Inviter {
                pending,
                our_ed,
                our_x,
            } => {
                let Some(mut p) = pending.take() else {
                    return Begin::Reject;
                };
                match p.begin_session(unix) {
                    Ok(()) => Begin::Inviter {
                        pending: p,
                        our_ed: *our_ed,
                        our_x: *our_x,
                        len,
                    },
                    Err(e) => {
                        *pending = Some(p);
                        match e {
                            InviteError::Expired => Begin::Finish(InviteOutcome::Expired),
                            InviteError::TooManySessions => Begin::Finish(InviteOutcome::Failed),
                            _ => Begin::Reject,
                        }
                    }
                }
            }
            Role::Invitee {
                session,
                m1,
                inviter_ed,
                inviter_x,
                our_ed,
                our_x,
                token_addrs,
                sessions_used,
                m1_sent,
            } => {
                // после M1 повторов нет (ревью 11, п. 3): соединение закрывается, исход
                // решает уже идущая или завершённая сессия
                if *m1_sent {
                    return Begin::Reject;
                }
                if *sessions_used >= MAX_INVITE_SESSIONS {
                    return Begin::Finish(InviteOutcome::Failed);
                }
                if unix >= self.expires_at {
                    return Begin::Finish(InviteOutcome::Expired);
                }
                let Some(s) = session.take() else {
                    return Begin::Reject;
                };
                *sessions_used = sessions_used.saturating_add(1);
                // сразу перед записью M1 (её делает `invitee_exchange`)
                *m1_sent = true;
                Begin::Invitee {
                    session: s,
                    m1: *m1,
                    seed: InviteeSeed {
                        inviter_ed: *inviter_ed,
                        inviter_x: *inviter_x,
                        our_ed: *our_ed,
                        our_x: *our_x,
                        token_addrs: token_addrs.clone(),
                    },
                    len,
                }
            }
        }
    }
}

/// Имя допустимо для книги (те же правила, что в `chervo_friends`: непусто, не длиннее
/// `MAX_NAME_BYTES`, без управляющих символов). Книга проверит ещё раз при записи друга.
fn name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_BYTES && !name.chars().any(char::is_control)
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    // ------------------------------------------------------------ снятие записи

    /// Снять запись приглашения и гостевую пару (под замком); память набора пары сбрасывается.
    fn take_invite_locked(st: &mut State<T::Conn>, pair: &PairId) -> Option<Invite<T::Conn>> {
        let inv = st.invites.remove(pair)?;
        st.guests.remove(pair);
        st.friends.remove(pair);
        Some(inv)
    }

    /// Приглашение кончилось без друга: запись и гость снимаются под замком, pending
    /// прерывается, публикация идёт в том же `update_book`. Исход выдаётся, только если
    /// запись снял этот вызов. `abort_active`: остановить задачу сессии (если вызывает не
    /// она сама).
    pub(crate) fn finish_invite(&self, pair: PairId, outcome: InviteOutcome, abort_active: bool) {
        let Some(inv) = self.drop_invite(pair) else {
            return;
        };
        if let Some(a) = inv.active {
            if abort_active {
                a.abort.abort();
            }
            a.conn.close();
        }
        self.emit(EngineEvent::InviteFinished { pair, outcome });
    }

    /// Снять приглашение и прервать pending (без события). `None`: записи уже нет.
    fn drop_invite(&self, pair: PairId) -> Option<Invite<T::Conn>> {
        let slot: RefCell<Option<Invite<T::Conn>>> = RefCell::new(None);
        let r = self.update_book_with(
            |st| *slot.borrow_mut() = Self::take_invite_locked(st, &pair),
            |book: &mut FriendBook, store: &S| {
                if slot.borrow().is_none() {
                    return Err(FriendsError::UnknownPair);
                }
                book.abort_pair(store, &pair)
            },
        );
        // ошибка книги или публикации не возвращает запись: pending уберёт перезапуск
        let _ = r;
        slot.into_inner()
    }

    /// Обе стороны подтвердили: друг записывается, гость снимается в том же вызове
    /// `update_book`, то есть тем же `set_peers`, который добавляет друга.
    fn complete_friend(&self, pair: PairId, nf: NewFriend) {
        let slot: RefCell<Option<Invite<T::Conn>>> = RefCell::new(None);
        let _ = self.update_book_with(
            |st| *slot.borrow_mut() = Self::take_invite_locked(st, &pair),
            |book: &mut FriendBook, store: &S| {
                if slot.borrow().is_none() {
                    return Err(FriendsError::UnknownPair);
                }
                book.finish_pair(store, &pair, nf)
            },
        );
        if slot.borrow().is_none() {
            // запись уже снята отменой или сроком: друг не создан
            return;
        }
        let added = self.lock().book.get(&pair).is_some();
        if added {
            let mut st = self.lock();
            self.start_fast_pair(&mut st, pair, Instant::now());
            drop(st);
            self.emit(EngineEvent::InviteFinished {
                pair,
                outcome: InviteOutcome::Added,
            });
        } else {
            // запись друга не создана (имя, хранилище): pending прерывается
            let _ = self.update_book(|book, store| book.abort_pair(store, &pair));
            self.emit(EngineEvent::InviteFinished {
                pair,
                outcome: InviteOutcome::Failed,
            });
        }
    }

    // ------------------------------------------------------------------- срок

    /// Приглашения со вставшим сроком снимаются (`Expired`); вызывается раз в
    /// `expire_interval`.
    pub(crate) fn expire_invites(&self) {
        let unix = self.clock.now_unix();
        let due: Vec<PairId> = {
            let st = self.lock();
            st.invites
                .iter()
                .filter(|(_, i)| unix >= i.dies_at)
                .map(|(p, _)| *p)
                .collect()
        };
        for pair in due {
            self.finish_invite(pair, InviteOutcome::Expired, true);
        }
    }

    // ---------------------------------------------------------------- выдача (A)

    pub(crate) fn create_invite(
        &self,
        ttl_secs: u64,
        addrs: InviteAddrs,
    ) -> Result<(PairId, String), ConnectError> {
        if self.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(ConnectError::Token(TokenError::BadTtl));
        }
        let unix = self.clock.now_unix();
        let addrs: Vec<SocketAddr> = match addrs {
            InviteAddrs::Auto { same_network } => {
                let v = {
                    let st = self.lock();
                    st.own
                        .publishable(
                            PublishCtx {
                                include_lan: same_network,
                            },
                            unix,
                        )
                        .socket_addrs()
                };
                if v.is_empty() {
                    return Err(ConnectError::NoAddresses);
                }
                v
            }
            InviteAddrs::Manual(v) => v,
        };
        let expires_at = unix.saturating_add(ttl_secs);
        let (pair, key) = self
            .update_book(|book, store| book.begin_pair(store, PendingRole::Inviter, expires_at))?;
        let our_ed = key.public_key();
        let our_x = key.kx_public();
        let issued = issue_invite(
            &InviteDraft {
                issued_at: unix,
                ttl_secs,
                addrs,
            },
            &key,
        );
        drop(key);
        let (pending, text) = match issued {
            Ok(v) => v,
            Err(e) => {
                let _ = self.update_book(|book, store| book.abort_pair(store, &pair));
                return Err(ConnectError::Token(e));
            }
        };
        let guest_public = pending.guest_public();
        let store = self.store.clone();
        let peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync> = Box::new(move || {
            let key = load(&*store, &pair, &our_ed).ok()?;
            Some(KxPeer::new(pair, key.into_kx(), guest_public))
        });
        self.register(
            pair,
            Invite {
                role: Role::Inviter {
                    pending: Some(Box::new(pending)),
                    our_ed,
                    our_x,
                },
                expires_at,
                dies_at: expires_at,
                confirm: None,
                active: None,
            },
            Vec::new(),
            peer,
        )?;
        Ok((pair, text))
    }

    /// Запись приглашения и гостя, публикация. При ошибке публикации всё откатывается.
    fn register(
        &self,
        pair: PairId,
        invite: Invite<T::Conn>,
        token_addrs: Vec<SocketAddr>,
        peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync>,
    ) -> Result<(), ConnectError> {
        self.lock().invites.insert(pair, invite);
        if let Err(e) = self.add_guest(pair, token_addrs, peer) {
            let _ = self.drop_invite(pair);
            return Err(e);
        }
        Ok(())
    }

    // -------------------------------------------------------------- приём (B)

    pub(crate) fn accept_invite(&self, text: &str) -> Result<PairId, ConnectError> {
        if self.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let unix = self.clock.now_unix();
        let token = match decode(text).map_err(ConnectError::Token)? {
            Token::Invite(t) => t,
            _ => return Err(ConnectError::Token(TokenError::BadKind)),
        };
        token.check_time(unix).map_err(ConnectError::Token)?;
        let expires_at = token.expires_at();
        let dies_at = expires_at.saturating_add(CLOCK_TOLERANCE_SECS);
        let (pair, key) =
            self.update_book(|book, store| book.begin_pair(store, PendingRole::Invitee, dies_at))?;
        let started = InviteeSession::start(&token, &key);
        let guest = token.guest_secret();
        let (our_ed, our_x) = (key.public_key(), key.kx_public());
        drop(key);
        let (session, m1) = match started {
            Ok(v) => v,
            Err(e) => {
                let _ = self.update_book(|book, store| book.abort_pair(store, &pair));
                return Err(ConnectError::Invite(e));
            }
        };
        let guest_bytes = match guest {
            Ok(g) => g.to_token_bytes(),
            Err(e) => {
                let _ = self.update_book(|book, store| book.abort_pair(store, &pair));
                return Err(ConnectError::Token(e));
            }
        };
        let inviter_ed = token.inviter_ed();
        let inviter_x = token.inviter_x();
        let token_addrs = token.addrs().to_vec();
        drop(token);
        let peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync> = Box::new(move || {
            let g = GuestSecret::from_bytes(guest_bytes.as_slice()).ok()?;
            Some(KxPeer::new(pair, g.into_kx(), inviter_x))
        });
        self.register(
            pair,
            Invite {
                role: Role::Invitee {
                    session: Some(Box::new(session)),
                    m1,
                    inviter_ed,
                    inviter_x,
                    our_ed,
                    our_x,
                    token_addrs: token_addrs.clone(),
                    sessions_used: 0,
                    m1_sent: false,
                },
                expires_at,
                dies_at,
                confirm: None,
                active: None,
            },
            token_addrs,
            peer,
        )?;
        {
            let mut st = self.lock();
            self.start_fast_pair(&mut st, pair, Instant::now());
        }
        Ok(pair)
    }

    // ------------------------------------------------------- решение человека

    pub(crate) fn confirm_sas(
        &self,
        pair: &PairId,
        confirm: bool,
        name: &str,
    ) -> Result<(), ConnectError> {
        if confirm && !name_ok(name) {
            return Err(ConnectError::Friends(FriendsError::InvalidName));
        }
        let tx = {
            let mut st = self.lock();
            let inv = st.invites.get_mut(pair).ok_or(ConnectError::UnknownPair)?;
            inv.confirm.take().ok_or(ConnectError::UnknownPair)?
        };
        tx.send((confirm, name.to_owned()))
            .map_err(|_| ConnectError::UnknownPair)
    }

    pub(crate) fn cancel_invite(&self, pair: &PairId) -> Result<(), ConnectError> {
        let inv = self.drop_invite(*pair).ok_or(ConnectError::UnknownPair)?;
        if let Some(a) = inv.active {
            a.abort.abort();
            a.conn.close();
        }
        Ok(())
    }

    // ------------------------------------------------- гостевое соединение

    /// Гостевая пара: соединение либо начинает сессию приглашения, либо закрывается.
    /// Потоков ADDR_INFO и прикладных данных на гостевых парах нет.
    pub(crate) fn on_guest_connection(self: &Arc<Self>, conn: T::Conn) {
        if self.is_shut() {
            conn.close();
            return;
        }
        let pair = conn.remote_pair();
        let unix = self.clock.now_unix();
        let mut reject = false;
        let mut finish: Option<InviteOutcome> = None;
        {
            let mut st = self.lock();
            let Some(inv) = st.invites.get_mut(&pair) else {
                drop(st);
                conn.close();
                return;
            };
            match inv.begin(unix, self.cfg.invite_session) {
                Begin::Reject => reject = true,
                Begin::Finish(o) => finish = Some(o),
                Begin::Inviter {
                    pending,
                    our_ed,
                    our_x,
                    len,
                } => {
                    let deadline = add_sat(Instant::now(), len);
                    let (inner, c) = (self.clone(), conn.clone());
                    let abort = self.spawn_task(async move {
                        inner
                            .run_inviter(pair, c, pending, our_ed, our_x, deadline)
                            .await;
                    });
                    inv.active = Some(ActiveSession {
                        abort,
                        conn: conn.clone(),
                    });
                }
                Begin::Invitee {
                    session,
                    m1,
                    seed,
                    len,
                } => {
                    let deadline = add_sat(Instant::now(), len);
                    let (inner, c) = (self.clone(), conn.clone());
                    let abort = self.spawn_task(async move {
                        inner
                            .run_invitee(pair, c, session, m1, seed, deadline)
                            .await;
                    });
                    inv.active = Some(ActiveSession {
                        abort,
                        conn: conn.clone(),
                    });
                }
            }
        }
        if reject {
            conn.close();
        } else if let Some(o) = finish {
            conn.close();
            self.finish_invite(pair, o, true);
        }
    }

    /// Вернуть `PendingInvite` после неудачной сессии до M1.
    fn return_pending(&self, pair: &PairId, pending: Box<PendingInvite>) {
        let mut st = self.lock();
        if let Some(inv) = st.invites.get_mut(pair) {
            if let Role::Inviter { pending: slot, .. } = &mut inv.role {
                *slot = Some(pending);
            }
            inv.active = None;
        }
    }

    /// Сторона A: M1 читается, срок проверяется по часам сразу перед `on_m1`.
    async fn run_inviter(
        self: Arc<Self>,
        pair: PairId,
        conn: T::Conn,
        mut pending: Box<PendingInvite>,
        our_ed: PublicKey,
        our_x: KxPublicKey,
        deadline: Instant,
    ) {
        let reached = Arc::new(AtomicBool::new(false));
        let (flag, clock) = (reached.clone(), self.clock.clone());
        let res = timeout_at(
            deadline,
            inviter_exchange(&conn, &mut pending, move || {
                flag.store(true, Ordering::SeqCst);
                clock.now_unix()
            }),
        )
        .await;
        // M1 прочитан целиком: любая неудача дальше (запись M2, SAS, решения) смертельна для
        // приглашения (решение владельца этапа 11, п. 4)
        let after_m1 = reached.load(Ordering::SeqCst);
        let verdict = match res {
            Ok(Ok(done)) => Verdict::Done(done),
            Ok(Err(FlowError::Invite(InviteError::Expired))) => {
                Verdict::Finish(InviteOutcome::Expired)
            }
            Ok(Err(FlowError::Invite(_))) => Verdict::Retry { timed_out: false },
            Ok(Err(_)) if after_m1 => Verdict::Finish(InviteOutcome::PeerUnreachable),
            Ok(Err(_)) => Verdict::Retry { timed_out: false },
            Err(_) if after_m1 => Verdict::Finish(InviteOutcome::PeerUnreachable),
            Err(_) => Verdict::Retry { timed_out: true },
        };
        match verdict {
            Verdict::Done((ch, sas, keys)) => {
                match self.sas_phase(pair, &conn, ch, sas, deadline).await {
                    SasEnd::Decided {
                        ours: true,
                        theirs: true,
                        name,
                    } => {
                        let unix = self.clock.now_unix();
                        let mut addrs = Vec::new();
                        note_contact(&mut addrs, conn.remote_addr(), unix);
                        self.complete_friend(
                            pair,
                            NewFriend {
                                name,
                                friend_ed: keys.ed,
                                friend_x: keys.x,
                                our_ed,
                                our_x,
                                addrs,
                                now_unix: unix,
                            },
                        );
                    }
                    SasEnd::Decided { .. } => {
                        self.finish_invite(pair, InviteOutcome::Declined, false);
                    }
                    SasEnd::Fatal => {
                        self.finish_invite(pair, InviteOutcome::PeerUnreachable, false);
                    }
                }
                conn.close();
            }
            Verdict::Finish(o) => {
                conn.close();
                self.finish_invite(pair, o, false);
            }
            Verdict::Retry { timed_out } => {
                conn.close();
                self.return_pending(&pair, pending);
                // сессию оборвал срок токена: приглашение кончилось
                let over = timed_out && {
                    let st = self.lock();
                    st.invites
                        .get(&pair)
                        .is_some_and(|i| self.clock.now_unix() >= i.expires_at)
                };
                if over {
                    self.finish_invite(pair, InviteOutcome::Expired, false);
                }
            }
        }
    }

    /// Сторона B: после M1 повторов нет, любая неудача смертельна.
    async fn run_invitee(
        self: Arc<Self>,
        pair: PairId,
        conn: T::Conn,
        session: Box<InviteeSession>,
        m1: [u8; M1_LEN],
        seed: InviteeSeed,
        deadline: Instant,
    ) {
        let res = timeout_at(deadline, invitee_exchange(&conn, *session, &m1)).await;
        match res {
            Ok(Ok((ch, sas))) => {
                match self.sas_phase(pair, &conn, ch, sas, deadline).await {
                    SasEnd::Decided {
                        ours: true,
                        theirs: true,
                        name,
                    } => {
                        let unix = self.clock.now_unix();
                        self.complete_friend(
                            pair,
                            NewFriend {
                                name,
                                friend_ed: seed.inviter_ed,
                                friend_x: seed.inviter_x,
                                our_ed: seed.our_ed,
                                our_x: seed.our_x,
                                addrs: from_invite(&seed.token_addrs, unix),
                                now_unix: unix,
                            },
                        );
                    }
                    SasEnd::Decided { .. } => {
                        self.finish_invite(pair, InviteOutcome::Declined, false);
                    }
                    SasEnd::Fatal => {
                        self.finish_invite(pair, InviteOutcome::PeerUnreachable, false);
                    }
                }
                conn.close();
            }
            _ => {
                conn.close();
                self.finish_invite(pair, InviteOutcome::PeerUnreachable, false);
            }
        }
    }

    /// SAS показан (`SasReady`), ждём решение человека до срока сессии, затем обмен решениями.
    async fn sas_phase(
        &self,
        pair: PairId,
        conn: &T::Conn,
        mut ch: InviteChannel<T::Conn>,
        sas: Sas,
        deadline: Instant,
    ) -> SasEnd {
        let (tx, rx) = oneshot::channel::<(bool, String)>();
        {
            let mut st = self.lock();
            match st.invites.get_mut(&pair) {
                Some(inv) => inv.confirm = Some(tx),
                None => return SasEnd::Fatal,
            }
        }
        // получатель уже зарегистрирован: `confirm_sas` может прийти сразу после события
        self.emit(EngineEvent::SasReady { pair, sas });
        let Ok(Ok((ours, name))) = timeout_at(deadline, rx).await else {
            return SasEnd::Fatal;
        };
        let Ok(Ok(theirs)) = timeout_at(deadline, exchange_decision(&mut ch, ours)).await else {
            return SasEnd::Fatal;
        };
        let _ = timeout(DECISION_SETTLE, conn.closed()).await;
        SasEnd::Decided { ours, theirs, name }
    }
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Выдать приглашение: пара pending, токен, гостевая пара в наборе транспорта.
    /// `Auto`: адреса из `publishable` (`same_network` добавляет LAN); пусто: `NoAddresses`.
    pub fn create_invite(
        &self,
        ttl_secs: u64,
        addrs: InviteAddrs,
    ) -> Result<(PairId, String), ConnectError> {
        self.inner.create_invite(ttl_secs, addrs)
    }

    /// Принять приглашение (текст токена): гостевая пара, быстрое окно, набор адресов токена.
    pub fn accept_invite(&self, text: &str) -> Result<PairId, ConnectError> {
        self.inner.accept_invite(text)
    }

    /// Решение человека по SAS (после `SasReady`). Имя нужно при `confirm`.
    pub fn confirm_sas(
        &self,
        pair: &PairId,
        confirm: bool,
        name: &str,
    ) -> Result<(), ConnectError> {
        self.inner.confirm_sas(pair, confirm, name)
    }

    /// Отменить приглашение (любая сторона): сессия останавливается, pending прерывается.
    pub fn cancel_invite(&self, pair: &PairId) -> Result<(), ConnectError> {
        self.inner.cancel_invite(pair)
    }
}
