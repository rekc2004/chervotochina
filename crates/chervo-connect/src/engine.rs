//! Ядро слоя соединения: состояние, публикация набора пар, планировщик набора номера,
//! соединения и события транспорта (спецификация 13, C3).
//!
//! Всё изменяемое состояние лежит под одним `std::sync::Mutex`. Замок никогда не держится
//! через `.await`: перед ожиданием гарды сбрасываются (в блоках).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chervo_addr::{
    AddrClass, MapStatus, NatView, OwnAddrs, PublishSet, classify, confirmed_addrs, normalize,
};
use chervo_friends::{FriendBook, FriendsError, KeyStatus};
use chervo_identity::{KxPeer, ListKeyStore, PairId, SecretStore};
use chervo_token::{InviteError, Sas, SignedAddrUpdate, TokenError};
use chervo_transport::{Connection, EventSource, ManagedTransport, PeerAddr};
use chervo_transport::{TransportError, TransportEvent};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

use crate::allow::AllowSet;
use crate::clock::{Clock, RouteProbe};
use crate::config::ConnectConfig;
use crate::diag::{Diagnosis, NoDirectPath};
use crate::gateway::Gateway;
use crate::inbox::IncomingStream;
use crate::invite::Invite;
use crate::lan::{LanSlot, prepend_hint};
use crate::limiter::{Limiter, add_sat};
use crate::plan::{Candidate, PathKind, friend_plan_confirmed, guest_plan, path_kind, select};

const EVENTS_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    Friends(FriendsError),
    Token(TokenError),
    Invite(InviteError),
    NoAddresses,
    UnknownPair,
    NotActive,
    InviteSessionsExhausted,
    Internal,
    Shutdown,
    /// Вид потока для приёмника не годится (0, ADDR_INFO, повтор, пустой список).
    InvalidKind,
    /// Вид потока уже закреплён за живым приёмником.
    KindTaken,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Friends(_) => "friends list error",
            Self::Token(_) => "token error",
            Self::Invite(_) => "invite error",
            Self::NoAddresses => "no addresses to publish",
            Self::UnknownPair => "unknown pair",
            Self::NotActive => "friend is not active",
            Self::InviteSessionsExhausted => "invite sessions exhausted",
            Self::Internal => "internal error",
            Self::Shutdown => "engine is shut down",
            Self::InvalidKind => "invalid stream kind",
            Self::KindTaken => "stream kind already registered",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ConnectError {}

impl From<FriendsError> for ConnectError {
    fn from(e: FriendsError) -> Self {
        Self::Friends(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteOutcome {
    Added,
    Declined,
    PeerUnreachable,
    Expired,
    Failed,
}

/// Откуда брать адреса для приглашения.
pub enum InviteAddrs {
    Auto {
        same_network: bool,
    },
    /// Введены пользователем (проброс, белый IP); также тесты.
    Manual(Vec<SocketAddr>),
}

/// `Debug` скрыт: в событиях есть SAS.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineEvent {
    Connected {
        pair: PairId,
        path: PathKind,
    },
    Disconnected {
        pair: PairId,
    },
    SasReady {
        pair: PairId,
        sas: Sas,
    },
    InviteFinished {
        pair: PairId,
        outcome: InviteOutcome,
    },
    KeyProblem {
        pair: PairId,
        status: KeyStatus,
    },
    OwnAddrsChanged,
    /// Итог автоматического проброса порта изменился (один раз на смену статуса).
    MappingChanged {
        status: MapStatus,
    },
    ClockSkew {
        pair: PairId,
    },
    Unreachable {
        pair: PairId,
        diagnosis: Diagnosis,
    },
    Internal,
}

impl fmt::Debug for EngineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EngineEvent(..)")
    }
}

pub struct EngineEvents {
    rx: broadcast::Receiver<EngineEvent>,
}

impl EngineEvents {
    /// Отставание пропускается молча; `None`: движок остановлен.
    pub async fn recv(&mut self) -> Option<EngineEvent> {
        loop {
            match self.rx.recv().await {
                Ok(e) => return Some(e),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl fmt::Debug for EngineEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EngineEvents(..)")
    }
}

/// Одна неудача набора для диагностики.
pub(crate) struct DialRecord {
    pub(crate) at: Instant,
    pub(crate) no_response: bool,
}

/// Память по одному другу (или гостю): только в оперативной памяти.
#[derive(Default)]
pub(crate) struct FriendRt {
    /// Последний отправленный набор и выпущенный для него токен.
    pub(crate) last_sent: Option<(chervo_addr::PublishSet, chervo_token::IssuedAddrUpdate)>,
    pub(crate) last_sent_at: Option<Instant>,
    pub(crate) want_addr_info: bool,
    pub(crate) sending: bool,
    /// Обновление, отклонённое по частоте: ждёт срока (unix) и повтора тактом.
    pub(crate) deferred: Option<(SignedAddrUpdate, u64)>,
    pub(crate) fast_until: Option<Instant>,
    pub(crate) consecutive_fails: u32,
    pub(crate) history: VecDeque<DialRecord>,
    pub(crate) last_reported: Option<NoDirectPath>,
    pub(crate) last_dial_at: Option<Instant>,
    /// Когда с этим другом в последний раз установлено соединение (любое направление):
    /// следующий наш набор не раньше `min_redial` после него.
    pub(crate) last_conn_at: Option<Instant>,
}

pub(crate) struct LiveConn<C> {
    pub(crate) conn: C,
    pub(crate) id: u64,
    pub(crate) since: Instant,
}

/// Гостевая пара живого приглашения (регистрируется частью C4). Для приглашённого
/// `token_addrs` — адреса токена; для пригласившего пусто.
pub(crate) struct Guest {
    pub(crate) token_addrs: Vec<SocketAddr>,
    pub(crate) peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync>,
}

pub(crate) struct State<C> {
    pub(crate) book: FriendBook,
    pub(crate) own: OwnAddrs,
    pub(crate) limiter: Limiter,
    pub(crate) live: HashMap<PairId, LiveConn<C>>,
    pub(crate) inflight: HashSet<PairId>,
    pub(crate) friends: HashMap<PairId, FriendRt>,
    pub(crate) guests: HashMap<PairId, Guest>,
    /// Живые приглашения (только в памяти: после перезапуска теряются, `drop_all_pending`).
    pub(crate) invites: HashMap<PairId, Invite<C>>,
    pub(crate) fast_global_until: Option<Instant>,
    pub(crate) key_problems: HashMap<PairId, KeyStatus>,
    pub(crate) last_success_any: Option<Instant>,
    /// Удержания соединений: пара -> (`conn_id` соединения, число живых удержаний). Удержание
    /// относится к одному соединению; запись другого `conn_id` на живое не действует.
    pub(crate) holds: HashMap<PairId, (u64, usize)>,
    /// F2: последний объявленный (или принятый за исходный) глобальный набор адресов.
    pub(crate) ext_announced: Option<PublishSet>,
    /// F2: исходный набор уже запомнен (первый непустой набор молчит).
    pub(crate) ext_baseline: bool,
    /// F2: когда объявление было в последний раз.
    pub(crate) ext_last: Option<Instant>,
    /// S2, L4: последняя публикация не удалась; не раньше этого момента `tick` повторяет её.
    /// Иначе удалённый или заблокированный друг оставался бы в наборе транспорта до следующего
    /// изменения книги.
    pub(crate) publish_retry_at: Option<Instant>,
    /// S2, L4: набор, последний раз принятый транспортом (общие ссылки на ключи, без повторной
    /// загрузки). Из него при неудачной публикации сразу убираются пары, переставшие быть
    /// допущенными.
    pub(crate) published: Vec<KxPeer>,
    /// S2, L4: `EngineEvent::Internal` по неудаче публикации уже выдан в текущей серии неудач
    /// (повтор каждые 5 с его не повторяет); сбрасывается успешной публикацией.
    pub(crate) publish_internal_reported: bool,
    /// 13в: подсказки поиска в LAN (одна на пару, только в памяти, не в книге). Пишет только `lan.rs`.
    pub(crate) lan_hints: HashMap<PairId, (SocketAddrV4, Instant)>,
}

/// Через сколько `tick` повторяет неудавшуюся публикацию набора пар.
const PUBLISH_RETRY: Duration = Duration::from_secs(5);

pub(crate) struct Inner<T: ManagedTransport, S> {
    pub(crate) transport: Arc<T>,
    pub(crate) allow: Arc<AllowSet>,
    pub(crate) store: Arc<S>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) probe: Arc<dyn RouteProbe>,
    pub(crate) cfg: ConnectConfig,
    pub(crate) state: Mutex<State<T::Conn>>,
    pub(crate) events: broadcast::Sender<EngineEvent>,
    pub(crate) shutdown: watch::Sender<bool>,
    pub(crate) shut: AtomicBool,
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
    pub(crate) gw: Gateway,
    pub(crate) lan: LanSlot,
    /// Зарегистрированные виды потоков -> отправитель в приёмник. Замок листовой: берётся
    /// отдельно от `state`, не вместе с ним.
    pub(crate) kinds: Mutex<HashMap<u8, mpsc::Sender<IncomingStream<T::Conn>>>>,
}

async fn wait_shutdown(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

/// Соединение уже закрыто (одним опросом `closed()` без ожидания).
fn closed_now<C: Connection>(conn: &C) -> bool {
    let mut fut = std::pin::pin!(conn.closed());
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    fut.as_mut().poll(&mut cx).is_ready()
}

/// Пауза цикла не короче миллисекунды: нулевой период превратил бы цикл в busy loop.
pub(crate) fn period(d: Duration) -> Duration {
    d.max(Duration::from_millis(1))
}

pub struct Engine<T: ManagedTransport, S: SecretStore + ListKeyStore + 'static>
where
    T::Conn: Clone,
{
    pub(crate) inner: Arc<Inner<T, S>>,
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    pub(crate) fn lock(&self) -> MutexGuard<'_, State<T::Conn>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn emit(&self, e: EngineEvent) {
        let _ = self.events.send(e);
    }

    pub(crate) fn subscribe_events(&self) -> EngineEvents {
        EngineEvents {
            rx: self.events.subscribe(),
        }
    }

    pub(crate) fn kinds_lock(
        &self,
    ) -> MutexGuard<'_, HashMap<u8, mpsc::Sender<IncomingStream<T::Conn>>>> {
        self.kinds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn is_shut(&self) -> bool {
        self.shut.load(Ordering::SeqCst)
    }

    /// Запустить задачу, которая завершается при остановке движка. Возвращает ручку отмены
    /// (сессии приглашений отменяются при отмене и сроке приглашения).
    pub(crate) fn spawn_task<F>(&self, f: F) -> AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let rx = self.shutdown.subscribe();
        let handle = tokio::spawn(async move {
            tokio::select! {
                () = f => {},
                () = wait_shutdown(rx) => {},
            }
        });
        let abort = handle.abort_handle();
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.retain(|h| !h.is_finished());
        tasks.push(handle);
        abort
    }

    pub(crate) fn shutdown_now(&self) {
        self.shut.store(true, Ordering::SeqCst);
        let _ = self.shutdown.send(true);
        let handles: Vec<JoinHandle<()>> = {
            let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *tasks)
        };
        for h in &handles {
            h.abort();
        }
        let conns: Vec<T::Conn> = {
            let mut st = self.lock();
            st.inflight.clear();
            st.published.clear();
            let drained: Vec<(PairId, LiveConn<T::Conn>)> = st.live.drain().collect();
            for (pair, _) in &drained {
                st.own.reporter_down(pair);
            }
            drained.into_iter().map(|(_, l)| l.conn).collect()
        };
        for c in &conns {
            c.close();
        }
        // отправители приёмников снимаются: `StreamInbox::recv` вернёт `None`
        self.kinds_lock().clear();
        // 13в: поиск в LAN закрывается вместе с движком
        self.lan_detach();
    }

    // ---------------------------------------------------------------- публикация

    /// Набор пар транспорта и разрешённые пары: друзья `Active` и гостевые пары живых
    /// приглашений, которые ещё не стали друзьями. При `DuplicatePairError` прежний набор
    /// разрешений восстанавливается, транспорт сохраняет прежний набор пар.
    pub(crate) fn publish(&self, st: &mut State<T::Conn>) -> Result<(), ConnectError> {
        let res = self.publish_once(st);
        // S2, L4: неудача (хранилище ключей, транспорт) помечается, `tick` повторит
        st.publish_retry_at = match res {
            Ok(()) => {
                st.publish_internal_reported = false;
                None
            }
            Err(_) => {
                // полная публикация не удалась: пары, переставшие быть допущенными, убираются
                // из набора сразу, без загрузки ключей; полный набор повторит `tick`
                self.drop_stale_pairs(st);
                Some(add_sat(Instant::now(), PUBLISH_RETRY))
            }
        };
        res
    }

    /// Убрать из набора транспорта и из разрешений пары, переставшие быть допущенными (блок,
    /// удаление, отзыв), по набору, принятому транспортом в последний раз: ключи не
    /// загружаются, хранилище не нужно. Неудача транспорта оставляет всё как есть.
    ///
    /// Запись активного друга остаётся, только если её ключ собеседника это `friend_x` друга из
    /// книги. Гостевая запись той же пары (`guest_public`, секрет которого знает держатель
    /// токена) после превращения гостя в друга не остаётся: иначе она принимала бы такого
    /// держателя как друга, пока полная публикация не удалась.
    fn drop_stale_pairs(&self, st: &mut State<T::Conn>) {
        let kept: Vec<KxPeer> = st
            .published
            .iter()
            .filter(|p| {
                let pair = p.pair();
                match st.book.get(&pair) {
                    Some(f) => st.book.is_active(&pair) && p.theirs() == f.friend_x,
                    None => st.guests.contains_key(&pair),
                }
            })
            .cloned()
            .collect();
        if kept.len() == st.published.len() {
            return;
        }
        let allowed: HashSet<PairId> = kept.iter().map(KxPeer::pair).collect();
        let old = self.allow.replace(allowed);
        if self.transport.set_peers(kept.clone()).is_err() {
            self.allow.replace(old);
            return;
        }
        st.published = kept;
    }

    fn publish_once(&self, st: &mut State<T::Conn>) -> Result<(), ConnectError> {
        let (mut peers, bad) = st
            .book
            .kx_peers(&*self.store)
            .map_err(ConnectError::Friends)?;
        let mut allowed: HashSet<PairId> = peers.iter().map(KxPeer::pair).collect();
        for (pair, guest) in &st.guests {
            if st.book.get(pair).is_some() || allowed.contains(pair) {
                continue;
            }
            if let Some(p) = (guest.peer)() {
                allowed.insert(*pair);
                peers.push(p);
            }
        }
        let old = self.allow.replace(allowed);
        if self.transport.set_peers(peers.clone()).is_err() {
            self.allow.replace(old);
            // повтор каждые 5 с не засыпает событиями: одно на серию неудач
            if !st.publish_internal_reported {
                st.publish_internal_reported = true;
                self.emit(EngineEvent::Internal);
            }
            return Err(ConnectError::Internal);
        }
        st.published = peers;
        let mut now_bad: HashMap<PairId, KeyStatus> = HashMap::new();
        for (pair, status) in bad {
            if st.key_problems.get(&pair) != Some(&status) {
                self.emit(EngineEvent::KeyProblem { pair, status });
            }
            now_bad.insert(pair, status);
        }
        st.key_problems = now_bad;
        Ok(())
    }

    /// После изменения книги: пары, переставшие быть `Active`, теряют наблюдения, соединения
    /// и память. Закрываемые соединения возвращаются вызывающему.
    pub(crate) fn cleanup_inactive(
        &self,
        st: &mut State<T::Conn>,
        before: &[PairId],
        to_close: &mut Vec<T::Conn>,
    ) {
        for pair in before {
            if !st.book.is_active(pair) {
                st.own.forget_reporter(pair);
                if let Some(l) = st.live.remove(pair) {
                    to_close.push(l.conn);
                }
                st.key_problems.remove(pair);
            }
        }
        let State {
            friends,
            guests,
            book,
            ..
        } = st;
        friends.retain(|p, _| book.get(p).is_some() || guests.contains_key(p));
    }

    // -------------------------------------------------------------- быстрое окно

    pub(crate) fn fast_active(&self, st: &State<T::Conn>, pair: &PairId, now: Instant) -> bool {
        st.fast_global_until.is_some_and(|t| t > now)
            || st
                .friends
                .get(pair)
                .and_then(|r| r.fast_until)
                .is_some_and(|t| t > now)
    }

    /// Быстрое окно пары: только по нашим собственным событиям.
    pub(crate) fn start_fast_pair(&self, st: &mut State<T::Conn>, pair: PairId, now: Instant) {
        let until = add_sat(now, self.cfg.fast_window);
        st.friends.entry(pair).or_default().fast_until = Some(until);
    }

    pub(crate) fn start_fast_global(&self, st: &mut State<T::Conn>, now: Instant) {
        st.fast_global_until = Some(add_sat(now, self.cfg.fast_window));
    }

    /// Все адреса пары из книги (для сброса ограничителя после нового номера обновления).
    pub(crate) fn friend_addrs(st: &State<T::Conn>, pair: &PairId) -> Vec<SocketAddr> {
        st.book.get(pair).map_or_else(Vec::new, |f| {
            f.known_addrs.iter().map(|k| normalize(k.addr)).collect()
        })
    }

    // --------------------------------------------------------------- соединения

    /// Соединение пришло из `connect` или `accept`.
    pub(crate) fn on_connection(self: &Arc<Self>, conn: T::Conn) {
        if self.is_shut() {
            conn.close();
            return;
        }
        let pair = conn.remote_pair();
        let id = conn.conn_id();
        let now = Instant::now();
        let unix = self.clock.now_unix();
        let mut closing: Vec<T::Conn> = Vec::new();
        let mut events: Vec<EngineEvent> = Vec::new();
        let mut sends: Vec<(PairId, T::Conn)> = Vec::new();
        {
            let mut st = self.lock();
            if st.guests.contains_key(&pair) && st.book.get(&pair).is_none() {
                drop(st);
                self.on_guest_connection(conn);
                return;
            }
            if !st.book.is_active(&pair) {
                drop(st);
                conn.close();
                return;
            }
            if st.live.get(&pair).is_some_and(|l| l.id == id) {
                return;
            }
            // Уже закрытое соединение (проигравшее при одновременном наборе или сброшенное
            // другом сразу) запись не вытесняет: иначе оно стёрло бы живого победителя, а
            // повтор набора ждал бы `min_redial`. Само соединение считается коротким:
            // минимальная задержка набора идёт от него.
            if closed_now(&conn) {
                st.friends.entry(pair).or_default().last_conn_at = Some(now);
                drop(st);
                conn.close();
                return;
            }
            let own_stable = st.own.stable_reachable(unix);
            let path = path_kind(
                conn.remote_addr(),
                conn.is_initiator(),
                st.book
                    .get(&pair)
                    .map_or(&[][..], |f| f.known_addrs.as_slice()),
                own_stable,
            );
            st.live.insert(
                pair,
                LiveConn {
                    conn: conn.clone(),
                    id,
                    since: now,
                },
            );
            // F1: наблюдения этого друга до сих пор не текущие, пока он не сообщит заново
            st.own.reporter_up(pair);
            // удержания прежнего соединения новому не принадлежат
            if st.holds.get(&pair).is_some_and(|(hid, _)| *hid != id) {
                st.holds.remove(&pair);
            }
            events.push(EngineEvent::Connected { pair, path });
            // сверх предела закрывается самое давнее соединение без удержания (идёт передача:
            // `hold`); если таких нет, новое остаётся и предел превышается (число удержаний
            // ограничено числом активных передач)
            while st.live.len() > self.cfg.max_live {
                let oldest = st
                    .live
                    .iter()
                    .filter(|(p, l)| {
                        **p != pair && !st.holds.get(*p).is_some_and(|(hid, _)| *hid == l.id)
                    })
                    .min_by_key(|(_, l)| l.since)
                    .map(|(p, _)| *p);
                let Some(victim) = oldest else { break };
                if let Some(l) = st.live.remove(&victim) {
                    st.own.reporter_down(&victim);
                    closing.push(l.conn);
                    events.push(EngineEvent::Disconnected { pair: victim });
                }
            }
            // `Contact` берётся с адреса установки соединения: текущий `remote_addr()` мог
            // смениться миграцией пути, которая ещё не проверена
            let _ = st
                .book
                .note_contact(&*self.store, &pair, conn.established_addr(), unix);
            let rt = st.friends.entry(pair).or_default();
            rt.last_conn_at = Some(now);
            rt.consecutive_fails = 0;
            rt.history.clear();
            rt.last_reported = None;
            rt.fast_until = None;
            rt.want_addr_info = conn.is_initiator();
            self.collect_sends(&mut st, now, &mut sends);
        }
        for c in &closing {
            c.close();
        }
        for e in events {
            self.emit(e);
        }
        let inner = self.clone();
        let watched = conn.clone();
        self.spawn_task(async move {
            watched.closed().await;
            inner.on_closed(pair, id);
        });
        let inner = self.clone();
        let streams = conn.clone();
        self.spawn_task(async move { inner.run_streams(pair, streams).await });
        for (p, c) in sends {
            self.spawn_send(p, c);
        }
    }

    /// Соединение закрыто: запись снимается, только если она ещё принадлежит этому соединению.
    pub(crate) fn on_closed(&self, pair: PairId, id: u64) {
        let removed = {
            let mut st = self.lock();
            if st.live.get(&pair).is_some_and(|l| l.id == id) {
                st.live.remove(&pair);
                st.own.reporter_down(&pair);
                if let Some(rt) = st.friends.get_mut(&pair) {
                    rt.want_addr_info = false;
                }
                true
            } else {
                false
            }
        };
        if removed {
            self.emit(EngineEvent::Disconnected { pair });
        }
    }

    // ---------------------------------------------------------------- планировщик

    /// Гость с адресами токена или пара-друг, готовая к набору.
    fn plan_dials(
        &self,
        st: &mut State<T::Conn>,
        local: &[SocketAddr],
        now: Instant,
        unix: u64,
        out: &mut Vec<(PairId, Vec<Candidate>)>,
    ) {
        let mut pairs: Vec<(PairId, Option<Instant>)> = Vec::new();
        for f in st.book.friends() {
            if st.book.is_active(&f.pair) && !st.key_problems.contains_key(&f.pair) {
                pairs.push((f.pair, st.friends.get(&f.pair).and_then(|r| r.last_dial_at)));
            }
        }
        for (pair, g) in &st.guests {
            // гость набирается, пока нет сессии и не отправлен M1 (после M1 повторов нет)
            let dialable = st.invites.get(pair).is_none_or(|i| !i.no_dial());
            if st.book.get(pair).is_none() && !g.token_addrs.is_empty() && dialable {
                pairs.push((*pair, st.friends.get(pair).and_then(|r| r.last_dial_at)));
            }
        }
        // давно не набиравшиеся пары первыми: при лимите одновременных наборов никто не голодает
        pairs.sort_by_key(|(_, last)| *last);
        for (pair, _) in pairs {
            if st.inflight.len() >= self.cfg.max_concurrent_dials {
                break;
            }
            if st.live.contains_key(&pair) || st.inflight.contains(&pair) {
                continue;
            }
            // ревью 13, M1: после только что установленного соединения не набирать раньше
            // `min_redial` (друг-лжец обрывает каждое соединение)
            let too_soon = st
                .friends
                .get(&pair)
                .and_then(|r| r.last_conn_at)
                .is_some_and(|t| add_sat(t, self.cfg.min_redial) > now);
            if too_soon {
                continue;
            }
            let plan = match st.guests.get(&pair) {
                Some(g) if st.book.get(&pair).is_none() => guest_plan(&g.token_addrs, local),
                _ => {
                    let confirmed = st
                        .book
                        .get(&pair)
                        .map(|f| confirmed_addrs(&f.known_addrs, unix))
                        .unwrap_or_default();
                    let entries =
                        prepend_hint(st, &pair, now, unix, st.book.usable_known(&pair, unix));
                    friend_plan_confirmed(&entries, &confirmed, local)
                }
            };
            if plan.cands.is_empty() {
                continue;
            }
            let chosen = select(&plan, &mut st.limiter, now);
            if chosen.is_empty() {
                continue;
            }
            st.inflight.insert(pair);
            st.friends.entry(pair).or_default().last_dial_at = Some(now);
            out.push((pair, chosen));
        }
    }

    fn spawn_dial(self: &Arc<Self>, pair: PairId, chosen: Vec<Candidate>) {
        let inner = self.clone();
        self.spawn_task(async move {
            let peer = PeerAddr {
                pair,
                addrs: chosen.iter().map(|c| c.addr).collect(),
            };
            let res = inner.transport.connect(&peer).await;
            inner.on_dial_result(pair, &chosen, res);
        });
    }

    fn on_dial_result(
        self: &Arc<Self>,
        pair: PairId,
        chosen: &[Candidate],
        res: Result<T::Conn, TransportError>,
    ) {
        let now = Instant::now();
        let unix = self.clock.now_unix();
        let local = self.transport.local_addrs();
        let mut events: Vec<EngineEvent> = Vec::new();
        match res {
            Ok(conn) => {
                {
                    let mut st = self.lock();
                    st.inflight.remove(&pair);
                    // ревью 13, M1: списаны были все выбранные адреса, поэтому все, кроме
                    // победителя, получают неудачу (рост задержки). Иначе лгущий друг с
                    // адресами жертв перед рабочим и обрывом каждого соединения гнал бы
                    // стук на жертв при каждом наборе. Не быстрое окно: рост всегда.
                    let won = normalize(conn.remote_addr());
                    let plain: Vec<SocketAddr> = chosen
                        .iter()
                        .filter(|c| !c.hint && normalize(c.addr) != won)
                        .map(|c| c.addr)
                        .collect();
                    let hints: Vec<SocketAddr> = chosen
                        .iter()
                        .filter(|c| c.hint && normalize(c.addr) != won)
                        .map(|c| c.addr)
                        .collect();
                    st.limiter.failed(&plain, false, false, now);
                    st.limiter.failed(&hints, true, false, now);
                    st.limiter.succeeded(conn.remote_addr());
                    st.last_success_any = Some(now);
                }
                self.on_connection(conn);
            }
            Err(e) => {
                {
                    let mut st = self.lock();
                    st.inflight.remove(&pair);
                    let fast = self.fast_active(&st, &pair, now);
                    let plain: Vec<SocketAddr> =
                        chosen.iter().filter(|c| !c.hint).map(|c| c.addr).collect();
                    let hints: Vec<SocketAddr> =
                        chosen.iter().filter(|c| c.hint).map(|c| c.addr).collect();
                    st.limiter.failed(&plain, false, fast, now);
                    st.limiter.failed(&hints, true, fast, now);
                    let rt = st.friends.entry(pair).or_default();
                    rt.consecutive_fails = rt.consecutive_fails.saturating_add(1);
                    rt.history.push_back(DialRecord {
                        at: now,
                        no_response: e == TransportError::NoResponse,
                    });
                    while rt.history.len() > 32 {
                        rt.history.pop_front();
                    }
                    let reached = rt.consecutive_fails >= self.cfg.unreachable_after_fails;
                    if e == TransportError::Busy {
                        // одиночный набор на пару исключает `Busy`: это ошибка слоя
                        events.push(EngineEvent::Internal);
                    }
                    if reached {
                        self.evaluate_unreachable(&mut st, &pair, &local, now, unix, &mut events);
                    }
                }
            }
        }
        for e in events {
            self.emit(e);
        }
    }

    /// Диагноз пары; `Unreachable` выдаётся один раз на смену причины.
    pub(crate) fn evaluate_unreachable(
        &self,
        st: &mut State<T::Conn>,
        pair: &PairId,
        local: &[SocketAddr],
        now: Instant,
        unix: u64,
        events: &mut Vec<EngineEvent>,
    ) {
        if st.book.get(pair).is_none() {
            return;
        }
        let Some(d) = self.diagnose_locked(st, pair, local, now, unix) else {
            return;
        };
        let rt = st.friends.entry(*pair).or_default();
        if rt.last_reported != Some(d.reason) {
            rt.last_reported = Some(d.reason);
            events.push(EngineEvent::Unreachable {
                pair: *pair,
                diagnosis: d,
            });
        }
    }

    /// Конец быстрых окон без успеха: диагноз для пар без соединения.
    fn fast_window_ends(
        &self,
        st: &mut State<T::Conn>,
        local: &[SocketAddr],
        now: Instant,
        unix: u64,
        events: &mut Vec<EngineEvent>,
    ) {
        let mut due: Vec<PairId> = Vec::new();
        if st.fast_global_until.is_some_and(|t| t <= now) {
            st.fast_global_until = None;
            due.extend(
                st.book
                    .friends()
                    .iter()
                    .filter(|f| st.book.is_active(&f.pair))
                    .map(|f| f.pair),
            );
        }
        for (pair, rt) in &mut st.friends {
            if rt.fast_until.is_some_and(|t| t <= now) {
                rt.fast_until = None;
                due.push(*pair);
            }
        }
        for pair in due {
            if st.live.contains_key(&pair) || !st.book.is_active(&pair) {
                continue;
            }
            self.evaluate_unreachable(st, &pair, local, now, unix, events);
        }
    }

    pub(crate) fn tick(self: &Arc<Self>) {
        let now = Instant::now();
        let unix = self.clock.now_unix();
        let local = self.transport.local_addrs();
        let mut events: Vec<EngineEvent> = Vec::new();
        let mut dials: Vec<(PairId, Vec<Candidate>)> = Vec::new();
        let mut sends: Vec<(PairId, T::Conn)> = Vec::new();
        let announce;
        {
            let mut st = self.lock();
            if st.publish_retry_at.is_some_and(|t| t <= now) {
                let _ = self.publish(&mut st);
            }
            self.fast_window_ends(&mut st, &local, now, unix, &mut events);
            self.retry_deferred(&mut st, now, unix);
            // F2: до `collect_sends`, чтобы ADDR_INFO ушёл этим же тактом
            announce = self.check_external(&mut st, now, unix);
            self.collect_sends(&mut st, now, &mut sends);
            self.plan_dials(&mut st, &local, now, unix, &mut dials);
        }
        if announce {
            self.transport.reknock();
            self.emit(EngineEvent::OwnAddrsChanged);
        }
        for e in events {
            self.emit(e);
        }
        for (pair, conn) in sends {
            self.spawn_send(pair, conn);
        }
        for (pair, chosen) in dials {
            self.spawn_dial(pair, chosen);
        }
    }

    pub(crate) async fn run_scheduler(self: Arc<Self>) {
        loop {
            tokio::time::sleep(period(self.cfg.tick)).await;
            self.tick();
        }
    }

    // ------------------------------------------------------ соединения: приём

    pub(crate) async fn run_accept(self: Arc<Self>) {
        loop {
            match self.transport.accept().await {
                Ok(conn) => self.on_connection(conn),
                Err(TransportError::Closed) => {
                    self.emit(EngineEvent::Internal);
                    return;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    // ------------------------------------------------------- события транспорта

    pub(crate) async fn run_events(self: Arc<Self>, mut events: T::Events) {
        while let Some(ev) = events.recv().await {
            match ev {
                TransportEvent::RemoteAddrChanged { pair } => {
                    let unix = self.clock.now_unix();
                    let mut st = self.lock();
                    // quinn не сообщает, проверен ли новый путь: в `Contact` идёт адрес
                    // установки, а не текущий `remote_addr()` (его мог подменить источник)
                    let addr = st.live.get(&pair).map(|l| l.conn.established_addr());
                    if let Some(addr) = addr {
                        let _ = st.book.note_contact(&*self.store, &pair, addr, unix);
                        // F3: другу сообщаем, как мы видим его теперь; не чаще
                        // `addr_info_out_interval` (отправляет `collect_sends`). Не наше
                        // собственное событие: ни стука, ни быстрого окна, ни сброса.
                        if st.book.is_active(&pair) {
                            st.friends.entry(pair).or_default().want_addr_info = true;
                        }
                    }
                }
                TransportEvent::ClockSkewSuspected { pair } => {
                    self.emit(EngineEvent::ClockSkew { pair });
                }
                TransportEvent::Lagged => self.resync_live().await,
                // замену и удаление обрабатывает `closed()` соединения
                _ => {}
            }
        }
        self.emit(EngineEvent::Internal);
    }

    /// После потери событий: записи с уже закрытым соединением снимаются.
    async fn resync_live(&self) {
        let snapshot: Vec<(PairId, u64, T::Conn)> = {
            let st = self.lock();
            st.live
                .iter()
                .map(|(p, l)| (*p, l.id, l.conn.clone()))
                .collect()
        };
        for (pair, id, conn) in snapshot {
            if tokio::time::timeout(Duration::ZERO, conn.closed())
                .await
                .is_ok()
            {
                self.on_closed(pair, id);
            }
        }
    }

    // ------------------------------------------------------------------- срок

    pub(crate) async fn run_expire(self: Arc<Self>) {
        loop {
            tokio::time::sleep(period(self.cfg.expire_interval)).await;
            self.expire_invites();
            let unix = self.clock.now_unix();
            let mut st = self.lock();
            if matches!(st.book.expire(&*self.store, unix), Ok(n) if n > 0) {
                let _ = self.publish(&mut st);
            }
            self.refresh_private_contacts(&mut st, unix);
        }
    }

    /// П2c: живое соединение по частному адресу продлевает запись `Contact` (не чаще раза в
    /// `CONTACT_REFRESH_SECS`, это решает `note_contact`). Только доказанный адрес: живое
    /// соединение с ним.
    fn refresh_private_contacts(&self, st: &mut State<T::Conn>, unix: u64) {
        let private: Vec<(PairId, SocketAddr)> = st
            .live
            .iter()
            .filter(|(pair, _)| st.book.is_active(pair))
            .map(|(pair, l)| (*pair, l.conn.established_addr()))
            .filter(|(_, remote)| classify(normalize(*remote).ip()) == AddrClass::Private)
            .collect();
        for (pair, remote) in private {
            let _ = st.book.note_contact(&*self.store, &pair, remote, unix);
        }
    }

    /// Единственный способ изменить книгу (см. `Engine::update_book`).
    pub(crate) fn update_book<R>(
        &self,
        f: impl FnOnce(&mut FriendBook, &S) -> Result<R, FriendsError>,
    ) -> Result<R, ConnectError> {
        self.update_book_with(|_| {}, f)
    }

    /// `update_book` с шагом `pre` над состоянием под тем же замком, до `f` и публикации:
    /// приглашение снимается вместе с изменением книги, одной публикацией.
    pub(crate) fn update_book_with<R>(
        &self,
        pre: impl FnOnce(&mut State<T::Conn>),
        f: impl FnOnce(&mut FriendBook, &S) -> Result<R, FriendsError>,
    ) -> Result<R, ConnectError> {
        if self.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let mut to_close: Vec<T::Conn> = Vec::new();
        let (result, published) = {
            let mut st = self.lock();
            pre(&mut st);
            let before: Vec<PairId> = st.book.friends().iter().map(|x| x.pair).collect();
            let seqs: HashMap<PairId, u64> = st
                .book
                .friends()
                .iter()
                .map(|x| (x.pair, x.last_addr_seq))
                .collect();
            let result = f(&mut st.book, &self.store);
            let published = self.publish(&mut st);
            self.cleanup_inactive(&mut st, &before, &mut to_close);
            // новый номер обновления от друга (например, вставленный токен) сбрасывает
            // ограничитель только адресов этого друга; быстрого окна он не открывает
            let now = Instant::now();
            let advanced: Vec<PairId> = st
                .book
                .friends()
                .iter()
                .filter(|x| seqs.get(&x.pair).is_some_and(|s| x.last_addr_seq > *s))
                .map(|x| x.pair)
                .collect();
            for pair in advanced {
                let addrs = Self::friend_addrs(&st, &pair);
                st.limiter.reset_pair(&addrs, now);
            }
            (result, published)
        };
        for c in &to_close {
            c.close();
        }
        let value = result.map_err(ConnectError::Friends)?;
        published?;
        Ok(value)
    }

    /// Гостевая пара живого приглашения: регистрация и публикация (гость входит в набор пар
    /// транспорта и в набор разрешённых).
    pub(crate) fn add_guest(
        &self,
        pair: PairId,
        token_addrs: Vec<SocketAddr>,
        peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync>,
    ) -> Result<(), ConnectError> {
        let mut st = self.lock();
        st.guests.insert(pair, Guest { token_addrs, peer });
        self.publish(&mut st)
    }
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Внутри среды tokio. Порядок: `drop_all_pending`, ручной проброс, первый снимок
    /// адресов, публикация, запуск задач. Быстрое окно начинается сразу.
    pub fn start(
        transport: Arc<T>,
        allow: Arc<AllowSet>,
        mut book: FriendBook,
        store: Arc<S>,
        clock: Arc<dyn Clock>,
        probe: Arc<dyn RouteProbe>,
        cfg: ConnectConfig,
    ) -> Result<(Self, EngineEvents), ConnectError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ConnectError::Internal);
        }
        book.drop_all_pending(&*store)
            .map_err(ConnectError::Friends)?;
        let mut own = OwnAddrs::new();
        own.set_manual_forward(cfg.manual_forward);
        let (events, rx) = broadcast::channel(EVENTS_CAPACITY);
        let (shutdown, _) = watch::channel(false);
        let now = Instant::now();
        let state = State {
            book,
            own,
            limiter: Limiter::new(&cfg),
            live: HashMap::new(),
            inflight: HashSet::new(),
            friends: HashMap::new(),
            guests: HashMap::new(),
            invites: HashMap::new(),
            fast_global_until: Some(add_sat(now, cfg.fast_window)),
            key_problems: HashMap::new(),
            last_success_any: None,
            holds: HashMap::new(),
            ext_announced: None,
            ext_baseline: false,
            ext_last: None,
            publish_retry_at: None,
            published: Vec::new(),
            publish_internal_reported: false,
            lan_hints: HashMap::new(),
        };
        let inner = Arc::new(Inner {
            transport,
            allow,
            store,
            clock,
            probe,
            cfg,
            state: Mutex::new(state),
            events,
            shutdown,
            shut: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            gw: Gateway::new(),
            lan: LanSlot::default(),
            kinds: Mutex::new(HashMap::new()),
        });
        let transport_events = inner.transport.subscribe();
        {
            let mut st = inner.lock();
            // первый снимок только запоминается: сравнивать пока не с чем
            inner.snapshot_local(&mut st);
            inner.publish(&mut st)?;
        }
        inner.spawn_task(inner.clone().run_watcher());
        inner.spawn_task(inner.clone().run_accept());
        inner.spawn_task(inner.clone().run_scheduler());
        inner.spawn_task(inner.clone().run_events(transport_events));
        inner.spawn_task(inner.clone().run_expire());
        Ok((Self { inner }, EngineEvents { rx }))
    }

    /// Единственный способ изменить книгу: выполнить `f`, затем публикация (разрешения и
    /// `set_peers`), `forget_reporter` для пар, переставших быть `Active`, и снятие их
    /// живых соединений. Публикация выполняется и после ошибки `f`.
    pub fn update_book<R>(
        &self,
        f: impl FnOnce(&mut FriendBook, &S) -> Result<R, FriendsError>,
    ) -> Result<R, ConnectError> {
        self.inner.update_book(f)
    }

    pub fn read_book<R>(&self, f: impl FnOnce(&FriendBook) -> R) -> R {
        let st = self.inner.lock();
        f(&st.book)
    }

    /// Только `Active`; быстрое окно этой пары и сброс её ограничителя.
    pub fn connect_now(&self, pair: &PairId) -> Result<(), ConnectError> {
        if self.inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let now = Instant::now();
        let mut st = self.inner.lock();
        if st.book.get(pair).is_none() {
            return Err(ConnectError::UnknownPair);
        }
        if !st.book.is_active(pair) {
            return Err(ConnectError::NotActive);
        }
        if st.live.contains_key(pair) {
            return Ok(());
        }
        let addrs = Inner::<T, S>::friend_addrs(&st, pair);
        st.limiter.reset_pair(&addrs, now);
        // местное событие пользователя снимает и минимальную задержку повторного набора
        if let Some(rt) = st.friends.get_mut(pair) {
            rt.last_conn_at = None;
        }
        self.inner.start_fast_pair(&mut st, *pair, now);
        drop(st);
        // 13в: серия маяков поиска в LAN по действию пользователя
        self.inner.lan_trigger();
        Ok(())
    }

    pub fn connection(&self, pair: &PairId) -> Option<T::Conn> {
        self.inner.lock().live.get(pair).map(|l| l.conn.clone())
    }

    /// `None`: соединение есть или причину пока не решить.
    pub fn diagnose(&self, pair: &PairId) -> Result<Option<Diagnosis>, ConnectError> {
        let now = Instant::now();
        let unix = self.inner.clock.now_unix();
        let local = self.inner.transport.local_addrs();
        let st = self.inner.lock();
        if st.book.get(pair).is_none() {
            return Err(ConnectError::UnknownPair);
        }
        if !st.book.is_active(pair) {
            return Err(ConnectError::NotActive);
        }
        Ok(self.inner.diagnose_locked(&st, pair, &local, now, unix))
    }

    pub fn nat_view(&self) -> NatView {
        let unix = self.inner.clock.now_unix();
        self.inner.lock().own.nat_view(unix)
    }

    pub fn shutdown(&self) {
        self.inner.shutdown_now();
    }

    /// Только для тестов: гостевая пара без приглашения.
    #[cfg(test)]
    pub(crate) fn add_guest(
        &self,
        pair: PairId,
        token_addrs: Vec<SocketAddr>,
        peer: Box<dyn Fn() -> Option<KxPeer> + Send + Sync>,
    ) -> Result<(), ConnectError> {
        self.inner.add_guest(pair, token_addrs, peer)
    }
}

impl<T, S> Drop for Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    fn drop(&mut self) {
        self.inner.shutdown_now();
    }
}
