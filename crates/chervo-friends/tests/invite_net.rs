#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Сквозные сетевые тесты приглашения (О1): две `QuinnTransport` на loopback со стуком,
//! порядок приложения из документации `chervo_friends::FriendBook`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chervo_friends::{FriendBook, FriendState, NewFriend, PendingRole};
use chervo_identity::{KxPeer, KxPublicKey, PairId, PublicKey, create};
use chervo_token::flow::{exchange_decision, invitee_exchange, inviter_exchange};
use chervo_token::{
    CLOCK_TOLERANCE_SECS, FlowError, InviteDraft, InviteError, InviteeKeys, InviteeSession, M1_LEN,
    PendingInvite, RevocationReason, Token, decode, issue_invite,
};
use chervo_transport::{Connection, PeerAddr, PeerFilter, Transport, TransportError};
use chervo_transport_quinn::{QuinnConfig, QuinnConn, QuinnTransport};
use common::*;

struct AllowAll;

impl PeerFilter for AllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cfg(deadline: Duration) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: deadline,
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

struct Party {
    _dir: TestDir,
    store: MemStore,
    book: FriendBook,
    t: QuinnTransport,
    addr: SocketAddr,
}

impl Party {
    fn new() -> Self {
        Self::with(cfg(Duration::from_secs(5)))
    }

    fn with(cfg: QuinnConfig) -> Self {
        let dir = TestDir::new();
        let store = MemStore::default();
        let book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
        let t =
            QuinnTransport::bind("127.0.0.1:0".parse().unwrap(), cfg, Arc::new(AllowAll)).unwrap();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), t.local_addrs()[0].port());
        Self {
            _dir: dir,
            store,
            book,
            t,
            addr,
        }
    }

    /// `set_peers(kx_peers + extra)`: после любого изменения книги.
    fn publish(&self, extra: Vec<KxPeer>) {
        let (mut peers, bad) = self.book.kx_peers(&self.store).unwrap();
        assert!(bad.is_empty());
        peers.extend(extra);
        self.t.set_peers(peers).unwrap();
    }
}

struct Inviter {
    pair: PairId,
    ed: PublicKey,
    x: KxPublicKey,
    pending: PendingInvite,
    text: String,
}

/// Сторона A: `begin_pair`, `issue_invite`, `set_peers(+ гость)`.
fn start_invite(a: &mut Party, ttl: u64, now: u64) -> Inviter {
    let (pair, key) = a
        .book
        .begin_pair(&a.store, PendingRole::Inviter, now + ttl)
        .unwrap();
    let (ed, x) = (key.public_key(), key.kx_public());
    let (pending, text) = issue_invite(
        &InviteDraft {
            issued_at: now,
            ttl_secs: ttl,
            addrs: vec![a.addr],
        },
        &key,
    )
    .unwrap();
    let guest = KxPeer::new(pair, key.into_kx(), pending.guest_public());
    a.publish(vec![guest]);
    Inviter {
        pair,
        ed,
        x,
        pending,
        text,
    }
}

struct Invitee {
    pair: PairId,
    ed: PublicKey,
    x: KxPublicKey,
    session: Option<InviteeSession>,
    m1: [u8; M1_LEN],
    inviter_ed: PublicKey,
    inviter_x: KxPublicKey,
    addrs: Vec<SocketAddr>,
}

/// Сторона B: `decode`, `check_time`, `begin_pair`, `InviteeSession::start`, `set_peers(+ гость)`.
fn accept_invite(b: &mut Party, text: &str, now: u64) -> Invitee {
    let Token::Invite(token) = decode(text).unwrap() else {
        panic!("не приглашение");
    };
    token.check_time(now).unwrap();
    let (pair, key) = b
        .book
        .begin_pair(
            &b.store,
            PendingRole::Invitee,
            token.expires_at() + CLOCK_TOLERANCE_SECS,
        )
        .unwrap();
    let (session, m1) = InviteeSession::start(&token, &key).unwrap();
    let guest = KxPeer::new(
        pair,
        token.guest_secret().unwrap().into_kx(),
        token.inviter_x(),
    );
    b.publish(vec![guest]);
    Invitee {
        pair,
        ed: key.public_key(),
        x: key.kx_public(),
        session: Some(session),
        m1,
        inviter_ed: token.inviter_ed(),
        inviter_x: token.inviter_x(),
        addrs: token.addrs().to_vec(),
    }
}

struct Outcome {
    sas_a: String,
    sas_b: String,
    a_got: bool,
    b_got: bool,
    b_keys: InviteeKeys,
    conn_a: QuinnConn,
    conn_b: QuinnConn,
}

/// Соединение гостевой пары, SAS и обмен решениями. Решения читаются до любых `set_peers`.
async fn exchange(
    a: &Party,
    ia: &mut Inviter,
    b: &Party,
    ib: &mut Invitee,
    a_ok: bool,
    b_ok: bool,
    now: u64,
) -> Outcome {
    let session = ib.session.take().unwrap();
    let addr = PeerAddr {
        pair: ib.pair,
        addrs: ib.addrs.clone(),
    };
    let m1 = ib.m1;
    let side_a = async {
        let conn = a.t.accept().await.unwrap();
        ia.pending.begin_session(now).unwrap();
        let (mut ch, sas, keys) = inviter_exchange(&conn, &mut ia.pending, || now)
            .await
            .unwrap();
        let got = exchange_decision(&mut ch, a_ok).await.unwrap();
        (conn, sas.digits(), keys, got)
    };
    let side_b = async {
        let conn = b.t.connect(&addr).await.unwrap();
        let (mut ch, sas) = invitee_exchange(&conn, session, &m1).await.unwrap();
        let got = exchange_decision(&mut ch, b_ok).await.unwrap();
        (conn, sas.digits(), got)
    };
    let ((conn_a, sas_a, b_keys, a_got), (conn_b, sas_b, b_got)) = tokio::join!(side_a, side_b);
    Outcome {
        sas_a,
        sas_b,
        a_got,
        b_got,
        b_keys,
        conn_a,
        conn_b,
    }
}

/// Итог по правилам спецификации: друг создаётся, только если подтвердили обе стороны.
fn finish(
    a: &mut Party,
    ia: &Inviter,
    b: &mut Party,
    ib: &Invitee,
    out: &Outcome,
    (a_ok, b_ok): (bool, bool),
    now: u64,
) {
    if a_ok && out.a_got {
        a.book
            .finish_pair(
                &a.store,
                &ia.pair,
                NewFriend {
                    name: "Борис".to_owned(),
                    friend_ed: out.b_keys.ed,
                    friend_x: out.b_keys.x,
                    our_ed: ia.ed,
                    our_x: ia.x,
                    addrs: Vec::new(),
                    now_unix: now,
                },
            )
            .unwrap();
    } else {
        a.book.abort_pair(&a.store, &ia.pair).unwrap();
    }
    a.publish(Vec::new());
    if b_ok && out.b_got {
        b.book
            .finish_pair(
                &b.store,
                &ib.pair,
                NewFriend {
                    name: "Анна".to_owned(),
                    friend_ed: ib.inviter_ed,
                    friend_x: ib.inviter_x,
                    our_ed: ib.ed,
                    our_x: ib.x,
                    addrs: Vec::new(),
                    now_unix: now,
                },
            )
            .unwrap();
    } else {
        b.book.abort_pair(&b.store, &ib.pair).unwrap();
    }
    b.publish(Vec::new());
}

async fn is_dead(c: &QuinnConn) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(3), c.accept_bi()).await,
        Ok(Err(_))
    )
}

/// `from` звонит `to`; результаты звонящего и принимающего.
async fn link(
    from: &Party,
    from_pair: PairId,
    to: &Party,
) -> (
    Result<QuinnConn, TransportError>,
    Result<QuinnConn, TransportError>,
) {
    let addr = PeerAddr {
        pair: from_pair,
        addrs: vec![to.addr],
    };
    tokio::join!(from.t.connect(&addr), to.t.accept())
}

struct Friends {
    a: Party,
    b: Party,
    pair_a: PairId,
    pair_b: PairId,
}

/// Полное успешное приглашение (A приглашает B).
async fn befriend() -> Friends {
    let (mut a, mut b) = (Party::new(), Party::new());
    let now = now_unix();
    let mut ia = start_invite(&mut a, 900, now);
    let mut ib = accept_invite(&mut b, &ia.text, now);
    let out = exchange(&a, &mut ia, &b, &mut ib, true, true, now).await;
    assert_eq!(out.sas_a, out.sas_b);
    finish(&mut a, &ia, &mut b, &ib, &out, (true, true), now);
    Friends {
        pair_a: ia.pair,
        pair_b: ib.pair,
        a,
        b,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_end_to_end_quinn() {
    let (mut a, mut b) = (Party::new(), Party::new());
    let now = now_unix();
    let mut ia = start_invite(&mut a, 900, now);
    let mut ib = accept_invite(&mut b, &ia.text, now);
    let out = exchange(&a, &mut ia, &b, &mut ib, true, true, now).await;
    // SAS на обоих экранах равны: 8 цифр
    assert_eq!(out.sas_a, out.sas_b);
    assert_eq!(out.sas_a.chars().filter(char::is_ascii_digit).count(), 8);
    assert_eq!(out.conn_a.remote_pair(), ia.pair);
    assert!(out.a_got && out.b_got);
    assert_eq!(out.b_keys.ed, ib.ed);
    assert_eq!(out.b_keys.x, ib.x);
    // до set_peers гостевое соединение живо
    assert!(
        tokio::time::timeout(Duration::from_millis(300), out.conn_a.accept_bi())
            .await
            .is_err()
    );
    finish(&mut a, &ia, &mut b, &ib, &out, (true, true), now);
    // книги: у каждого один друг, нет pending, по одному ключу пары
    assert_eq!(a.book.friends().len(), 1);
    assert_eq!(b.book.friends().len(), 1);
    assert!(a.book.pending().is_empty() && b.book.pending().is_empty());
    assert_eq!((a.store.pair_count(), b.store.pair_count()), (1, 1));
    assert_eq!(a.book.get(&ia.pair).unwrap().friend_ed, ib.ed);
    assert_eq!(b.book.get(&ib.pair).unwrap().friend_ed, ia.ed);
    assert_eq!(a.book.get(&ia.pair).unwrap().state, FriendState::Active);
    // после set_peers гостевое соединение закрыто с обеих сторон
    assert!(is_dead(&out.conn_a).await, "гостевое соединение A живо");
    assert!(is_dead(&out.conn_b).await, "гостевое соединение B живо");
    // новое соединение настоящими ключами проходит KK; пары верные
    let (cb, ca) = link(&b, ib.pair, &a).await;
    let (cb, ca) = (cb.unwrap(), ca.unwrap());
    assert_eq!(ca.remote_pair(), ia.pair);
    assert_eq!(cb.remote_pair(), ib.pair);
    // гостевая пара больше не принимается: старый токен мёртв
    let c_party = Party::with(cfg(Duration::from_millis(1500)));
    let Token::Invite(tok) = decode(&ia.text).unwrap() else {
        panic!()
    };
    let key_c = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    let _ = InviteeSession::start(&tok, &key_c).unwrap();
    let pair_c = PairId::generate().unwrap();
    c_party
        .t
        .set_peers(vec![KxPeer::new(
            pair_c,
            tok.guest_secret().unwrap().into_kx(),
            tok.inviter_x(),
        )])
        .unwrap();
    let r = c_party
        .t
        .connect(&PeerAddr {
            pair: pair_c,
            addrs: vec![a.addr],
        })
        .await;
    assert!(r.is_err(), "гость принят после завершения приглашения");
    c_party.t.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_reject_creates_nothing() {
    for decisions in [(true, false), (false, true), (false, false)] {
        let (mut a, mut b) = (Party::new(), Party::new());
        let now = now_unix();
        let mut ia = start_invite(&mut a, 900, now);
        let mut ib = accept_invite(&mut b, &ia.text, now);
        let out = exchange(&a, &mut ia, &b, &mut ib, decisions.0, decisions.1, now).await;
        assert_eq!(out.sas_a, out.sas_b);
        // собеседник видит отказ
        assert_eq!(out.a_got, decisions.1);
        assert_eq!(out.b_got, decisions.0);
        finish(&mut a, &ia, &mut b, &ib, &out, decisions, now);
        for p in [&a, &b] {
            assert!(p.book.friends().is_empty(), "{decisions:?}");
            assert!(p.book.pending().is_empty());
            assert_eq!(p.store.pair_count(), 0, "ключ пары не удалён");
        }
        // и на диске
        assert!(
            FriendBook::open_unanchored(&a._dir.file(), &a.store)
                .unwrap()
                .friends()
                .is_empty()
        );
        assert!(is_dead(&out.conn_a).await && is_dead(&out.conn_b).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_expired_refused() {
    let (mut a, mut b) = (Party::new(), Party::new());
    let now = now_unix();
    let mut ia = start_invite(&mut a, 60, now);
    // B по своим часам спустя много времени токен не принимает
    let Token::Invite(tok) = decode(&ia.text).unwrap() else {
        panic!()
    };
    assert!(tok.check_time(now + 60 + CLOCK_TOLERANCE_SECS + 1).is_err());
    assert!(tok.check_time(now + 60).is_ok());
    let mut ib = accept_invite(&mut b, &ia.text, now);
    let session = ib.session.take().unwrap();
    let addr = PeerAddr {
        pair: ib.pair,
        addrs: ib.addrs.clone(),
    };
    let m1 = ib.m1;
    let late = ia.pending.expires_at();
    let side_a = async {
        let conn = a.t.accept().await.unwrap();
        // по часам A приглашение истекло: сессия не начинается, соединение закрывается
        let r = ia.pending.begin_session(late);
        conn.close();
        r
    };
    let side_b = async {
        let conn = b.t.connect(&addr).await.unwrap();
        invitee_exchange(&conn, session, &m1).await.err()
    };
    let (ra, rb) = tokio::join!(side_a, side_b);
    assert_eq!(ra, Err(InviteError::Expired));
    assert!(rb.is_some(), "B получил M2 от просроченного приглашения");
    // истёкшая запись убирается вместе с ключом
    assert_eq!(a.book.expire(&a.store, late).unwrap(), 1);
    assert_eq!(a.store.pair_count(), 0);
    assert!(a.book.friends().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_token_holder_after_m1_gets_nothing() {
    let (mut a, mut b) = (Party::new(), Party::new());
    let c = Party::new();
    let now = now_unix();
    let mut ia = start_invite(&mut a, 900, now);
    let mut ib = accept_invite(&mut b, &ia.text, now);
    // B честно дошёл до SAS: M1 принят, приглашение использовано
    let out = exchange(&a, &mut ia, &b, &mut ib, true, true, now).await;
    drop(out);
    // третий, увидевший токен, проходит стук и KK как гость, но M2 не получает
    let Token::Invite(tok) = decode(&ia.text).unwrap() else {
        panic!()
    };
    let key_c = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    let (session_c, m1_c) = InviteeSession::start(&tok, &key_c).unwrap();
    let pair_c = PairId::generate().unwrap();
    c.t.set_peers(vec![KxPeer::new(
        pair_c,
        tok.guest_secret().unwrap().into_kx(),
        tok.inviter_x(),
    )])
    .unwrap();
    let addr = PeerAddr {
        pair: pair_c,
        addrs: vec![a.addr],
    };
    let side_a = async {
        let conn = a.t.accept().await.unwrap();
        // приглашение использовано: Used уже на begin_session, M2 не отправляется
        let r = match ia.pending.begin_session(now) {
            Err(e) => Some(FlowError::Invite(e)),
            Ok(()) => inviter_exchange(&conn, &mut ia.pending, || now).await.err(),
        };
        conn.close();
        r
    };
    let side_c = async {
        let conn = c.t.connect(&addr).await.unwrap();
        invitee_exchange(&conn, session_c, &m1_c).await.err()
    };
    let (ra, rc) = tokio::join!(side_a, side_c);
    assert!(
        matches!(ra, Some(FlowError::Invite(InviteError::Used))),
        "A должен ответить Used"
    );
    assert!(rc.is_some(), "держатель токена получил M2");
    // друга для третьего нет ни у кого
    assert!(a.book.friends().is_empty());
    assert!(c.book.friends().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_wrong_token_never_connects() {
    let a = Party::with(cfg(Duration::from_secs(5)));
    let mut b = Party::with(cfg(Duration::from_millis(1500)));
    let now = now_unix();
    // токен подписан другим ключом пары, адрес A: стука для A не существует
    let key_m = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    let (_p, text) = issue_invite(
        &InviteDraft {
            issued_at: now,
            ttl_secs: 900,
            addrs: vec![a.addr],
        },
        &key_m,
    )
    .unwrap();
    let ib = accept_invite(&mut b, &text, now);
    let r =
        b.t.connect(&PeerAddr {
            pair: ib.pair,
            addrs: ib.addrs.clone(),
        })
        .await;
    assert!(
        matches!(r, Err(TransportError::NoResponse)),
        "connect должен дать NoResponse"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), a.t.accept())
            .await
            .is_err(),
        "A получил соединение"
    );
    let st = a.t.stats();
    assert_eq!((st.auth_ok, st.knock_ok), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_friend_live_conn_closed() {
    let mut f = befriend().await;
    let (cb, ca) = link(&f.b, f.pair_b, &f.a).await;
    let (cb, ca) = (cb.unwrap(), ca.unwrap());
    assert_eq!(ca.remote_pair(), f.pair_a);
    // гостевое соединение приглашения уже закрыто при завершении: счётчик не нулевой
    let closed_before = f.a.t.stats().removed_closed;
    f.a.book.block(&f.a.store, &f.pair_a).unwrap();
    assert_eq!(f.a.book.get(&f.pair_a).unwrap().state, FriendState::Blocked);
    f.a.publish(Vec::new());
    assert!(is_dead(&ca).await, "соединение A живо после блокировки");
    assert!(is_dead(&cb).await, "соединение B живо после блокировки");
    assert_eq!(f.a.t.stats().removed_closed, closed_before + 1);
    // заблокированный не дозвонится
    let addr = PeerAddr {
        pair: f.pair_b,
        addrs: vec![f.a.addr],
    };
    let quick = tokio::time::timeout(Duration::from_secs(8), f.b.t.connect(&addr)).await;
    assert!(quick.map(|r| r.is_err()).unwrap_or(true));
    // разблокировка возвращает связь
    f.a.book.unblock(&f.a.store, &f.pair_a).unwrap();
    f.a.publish(Vec::new());
    let (cb, ca) = link(&f.b, f.pair_b, &f.a).await;
    assert!(cb.is_ok() && ca.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_end_to_end() {
    let mut f = befriend().await;
    let (cb, ca) = link(&f.b, f.pair_b, &f.a).await;
    let (cb, ca) = (cb.unwrap(), ca.unwrap());
    let now = now_unix();
    // A удаляет друга: отзыв подписан старым ключом пары, соединение рвётся
    let text =
        f.a.book
            .remove(&f.a.store, &f.pair_a, now)
            .unwrap()
            .unwrap();
    assert!(!f.a.store.has(&f.pair_a));
    f.a.publish(Vec::new());
    assert!(is_dead(&ca).await && is_dead(&cb).await);
    // запись удалённого друга стала `Retired` (текст отзыва в ней), в наборе пар её нет
    assert_eq!(f.a.book.retired(), vec![(f.pair_a, text.clone())]);
    assert!(f.a.book.kx_peers(&f.a.store).unwrap().0.is_empty());
    f.a.book.forget_retired(&f.a.store, &f.pair_a).unwrap();
    assert!(f.a.book.friends().is_empty());
    // B принимает отзыв: друг помечен, ключ пары удалён, набор пар пуст
    assert_eq!(
        f.b.book.apply_revocation(&f.b.store, &text).unwrap(),
        Some(f.pair_b)
    );
    assert_eq!(
        f.b.book.get(&f.pair_b).unwrap().state,
        FriendState::RevokedByPeer
    );
    assert!(!f.b.store.has(&f.pair_b));
    f.b.publish(Vec::new());
    let (peers, bad) = f.b.book.kx_peers(&f.b.store).unwrap();
    assert!(peers.is_empty() && bad.is_empty());
    // отзыв с причиной «Removed»
    let Token::Revocation(n) = decode(&text).unwrap() else {
        panic!()
    };
    assert_eq!(n.reason, RevocationReason::Removed);
    // дозвониться больше нельзя ни с одной стороны
    let addr = PeerAddr {
        pair: f.pair_b,
        addrs: vec![f.a.addr],
    };
    let r = tokio::time::timeout(Duration::from_secs(8), f.b.t.connect(&addr)).await;
    assert!(r.map(|x| x.is_err()).unwrap_or(true));
}
