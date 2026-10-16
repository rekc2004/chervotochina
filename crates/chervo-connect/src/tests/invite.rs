//! Часть C4 на поддельном транспорте: сессии приглашения, сроки, публикация гостя и друга.

use std::sync::{Arc, Mutex};

use chervo_friends::PendingRole;
use chervo_identity::{PairId, create};
use chervo_token::{InviteeSession, Token, decode};
use chervo_transport::{Connection, PeerFilter, SendStream};

use super::kit::*;
use crate::invite::Role;
use crate::{ConnectConfig, ConnectError, EngineEvent, InviteAddrs, InviteOutcome};

const A_ADDR: &str = "10.0.0.1:4000";
const B_ADDR: &str = "10.0.0.2:5000";

struct Duo {
    a: Node,
    b: Node,
    pa: PairId,
    pb: PairId,
    text: String,
}

fn manual() -> InviteAddrs {
    InviteAddrs::Manual(vec![addr(A_ADDR)])
}

/// A выдал приглашение, B его принял; сети между ними нет.
fn duo_with(ttl: u64, cfg: ConnectConfig) -> Duo {
    let a = Node::start(Pre::new(), cfg.clone());
    let b = Node::start(Pre::new(), cfg);
    let (pa, text) = a.engine.create_invite(ttl, manual()).unwrap();
    let pb = b.engine.accept_invite(&text).unwrap();
    Duo { a, b, pa, pb, text }
}

fn duo(ttl: u64) -> Duo {
    duo_with(ttl, ConnectConfig::default())
}

fn finished(e: &EngineEvent) -> bool {
    matches!(e, EngineEvent::InviteFinished { .. })
}

fn is_sas(e: &EngineEvent) -> bool {
    matches!(e, EngineEvent::SasReady { .. })
}

fn outcome(e: Option<EngineEvent>) -> Option<InviteOutcome> {
    match e {
        Some(EngineEvent::InviteFinished { outcome, .. }) => Some(outcome),
        _ => None,
    }
}

/// Оба узла соединены; возвращает SAS, показанные сторонам.
async fn reach_sas(d: &mut Duo) -> (String, String) {
    let _ = link_nodes(&d.b, d.pb, A_ADDR, &d.a, d.pa, B_ADDR);
    let Some(EngineEvent::SasReady { sas: sa, .. }) =
        wait_event(&mut d.a.events, secs(30), is_sas).await
    else {
        panic!("A: no SAS")
    };
    let Some(EngineEvent::SasReady { sas: sb, .. }) =
        wait_event(&mut d.b.events, secs(30), is_sas).await
    else {
        panic!("B: no SAS")
    };
    (sa.digits(), sb.digits())
}

fn pending_count(n: &Node) -> usize {
    n.engine.read_book(|b| b.pending().len())
}

// -------------------------------------------------------------------- B: сессии

#[tokio::test(start_paused = true)]
async fn invitee_max_three_sessions() {
    let mut d = duo(300);
    {
        let mut st = d.b.engine.inner.lock();
        let inv = st.invites.get_mut(&d.pb).unwrap();
        let Role::Invitee { sessions_used, .. } = &mut inv.role else {
            panic!("not an invitee");
        };
        *sessions_used = 3;
    }
    let c = FakeConn::lonely(d.pb, addr(A_ADDR), true);
    d.b.t.push_incoming(c.clone());
    let e = wait_event(&mut d.b.events, secs(10), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::Failed));
    assert!(c.is_closed());
    assert_eq!(c.opened(), 0, "M1 sent on the fourth session");
    assert_eq!(pending_count(&d.b), 0);
    assert_eq!(d.b.store.pair_count(), 0);
    assert!(!d.b.allow.is_allowed(&d.pb));
}

#[tokio::test(start_paused = true)]
async fn invitee_no_auto_retry_after_m1() {
    let mut d = duo(900);
    let made: Arc<Mutex<Vec<FakeConn>>> = Arc::new(Mutex::new(Vec::new()));
    let (m, pb) = (made.clone(), d.pb);
    d.b.t.set_script(move |pair, _| {
        assert_eq!(*pair, pb);
        let c = FakeConn::lonely(pb, addr(A_ADDR), true);
        m.lock().unwrap().push(c.clone());
        Action::Ok(c, secs(0))
    });
    tokio::time::sleep(secs(5)).await;
    assert_eq!(d.b.t.calls_for(&d.pb).len(), 1);
    let first = made.lock().unwrap()[0].clone();
    assert_eq!(first.opened(), 1, "M1 stream not opened");
    // вторая гостевая связь во время сессии закрывается без единого потока
    let second = FakeConn::lonely(d.pb, addr(A_ADDR), false);
    d.b.t.push_incoming(second.clone());
    tokio::time::sleep(secs(1)).await;
    assert!(second.is_closed());
    assert_eq!(second.opened(), 0);
    // пока идёт сессия, повторных наборов нет
    tokio::time::sleep(secs(200)).await;
    assert_eq!(d.b.t.calls_for(&d.pb).len(), 1);
    // срок сессии: исход PeerUnreachable, приглашение снято
    let e = wait_event(&mut d.b.events, secs(400), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::PeerUnreachable));
    assert!(first.is_closed());
    tokio::time::sleep(secs(900)).await;
    assert_eq!(d.b.t.calls_for(&d.pb).len(), 1, "redial after M1");
    assert_eq!(pending_count(&d.b), 0);
    assert_eq!(d.b.store.pair_count(), 0);
}

// -------------------------------------------------------------------- A: сессии

#[tokio::test(start_paused = true)]
async fn inviter_max_three_sessions() {
    let mut d = duo(900);
    for _ in 0..3 {
        let c = FakeConn::lonely(d.pa, addr(B_ADDR), false);
        d.a.t.push_incoming(c.clone());
        tokio::time::sleep(secs(1)).await;
        c.close();
        tokio::time::sleep(secs(1)).await;
        assert!(pending_count(&d.a) == 1, "invite died early");
    }
    let fourth = FakeConn::lonely(d.pa, addr(B_ADDR), false);
    d.a.t.push_incoming(fourth.clone());
    let e = wait_event(&mut d.a.events, secs(10), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::Failed));
    assert!(fourth.is_closed());
    assert_eq!(pending_count(&d.a), 0);
    assert_eq!(d.a.store.pair_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn inviter_session_capped_by_token_expiry() {
    // таймер срока не успевает: конец приглашения обеспечивает только срок сессии
    let cfg = ConnectConfig {
        expire_interval: secs(3600),
        ..ConnectConfig::default()
    };
    let mut d = duo_with(60, cfg);
    let start = tokio::time::Instant::now();
    let c = FakeConn::lonely(d.pa, addr(B_ADDR), false);
    d.a.t.push_incoming(c.clone());
    let e = wait_event(&mut d.a.events, secs(120), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::Expired));
    let took = tokio::time::Instant::now() - start;
    assert!(took <= secs(62), "session outlived the token: {took:?}");
    assert!(c.is_closed());
    assert_eq!(pending_count(&d.a), 0);
}

#[tokio::test(start_paused = true)]
async fn inviter_on_m1_after_expiry_rejected() {
    let mut d = duo(60);
    let Token::Invite(tok) = decode(&d.text).unwrap() else {
        panic!("not an invite")
    };
    let key = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    let (_s, m1) = InviteeSession::start(&tok, &key).unwrap();
    let (ca, cb) = FakeConn::pair(
        d.pa,
        addr(B_ADDR),
        PairId::from_bytes([9; 16]),
        addr(A_ADDR),
        false,
    );
    d.a.t.push_incoming(ca);
    tokio::time::sleep(secs(1)).await;
    // сессия началась до срока; часы прыгают за срок, и только потом приходит M1
    d.a.clock.skew(100);
    let (mut tx, _rx) = cb.open_bi().await.unwrap();
    tx.write_all(&m1).await.unwrap();
    let first = wait_event(&mut d.a.events, secs(10), |e| finished(e) || is_sas(e)).await;
    assert_eq!(outcome(first), Some(InviteOutcome::Expired));
    assert_eq!(pending_count(&d.a), 0);
}

#[tokio::test(start_paused = true)]
async fn invite_expire_every_minute() {
    let a = Node::start(Pre::new(), ConnectConfig::default());
    let (p1, _) = a.engine.create_invite(60, manual()).unwrap();
    let (p2, _) = a.engine.create_invite(120, manual()).unwrap();
    let mut a = a;
    assert_eq!(pending_count(&a), 2);
    let e = wait_event(&mut a.events, secs(61), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::Expired));
    assert_eq!(pending_count(&a), 1);
    assert!(!a.allow.is_allowed(&p1) && a.allow.is_allowed(&p2));
    let e = wait_event(&mut a.events, secs(61), finished).await;
    assert_eq!(outcome(e), Some(InviteOutcome::Expired));
    assert_eq!(pending_count(&a), 0);
    assert_eq!(a.store.pair_count(), 0);
    assert!(a.t.last_peers().is_empty());
}

#[tokio::test(start_paused = true)]
async fn drop_all_pending_on_start() {
    let mut pre = Pre::new();
    for _ in 0..2 {
        pre.book
            .begin_pair(&*pre.store, PendingRole::Inviter, u64::MAX)
            .unwrap();
    }
    assert_eq!(pre.store.pair_count(), 2);
    let n = Node::start(pre, ConnectConfig::default());
    assert_eq!(pending_count(&n), 0);
    assert_eq!(n.store.pair_count(), 0);
}

// ----------------------------------------------------------------- адреса токена

fn token_addrs(text: &str) -> Vec<std::net::SocketAddr> {
    let Token::Invite(t) = decode(text).unwrap() else {
        panic!("not an invite")
    };
    t.addrs().to_vec()
}

#[tokio::test(start_paused = true)]
async fn invite_auto_lan_only_by_choice() {
    // маршрут: частный адрес; порт прослушивания 4000 (поддельный транспорт)
    let n = Node::start_with(
        Pre::new(),
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("192.168.1.5")),
    );
    assert_eq!(
        n.engine
            .create_invite(
                300,
                InviteAddrs::Auto {
                    same_network: false
                }
            )
            .map(|_| ()),
        Err(ConnectError::NoAddresses)
    );
    assert_eq!(pending_count(&n), 0, "pair left behind after NoAddresses");
    let (_, text) = n
        .engine
        .create_invite(300, InviteAddrs::Auto { same_network: true })
        .unwrap();
    assert_eq!(token_addrs(&text), vec![addr("192.168.1.5:4000")]);
    // белый адрес входит всегда, частный только по выбору
    let w = Node::start_with(
        Pre::new(),
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    let (_, t1) = w
        .engine
        .create_invite(
            300,
            InviteAddrs::Auto {
                same_network: false,
            },
        )
        .unwrap();
    assert_eq!(token_addrs(&t1), vec![addr("7.7.7.7:4000")]);
}

#[tokio::test(start_paused = true)]
async fn invite_auto_no_addresses_error() {
    let n = Node::start_with(
        Pre::new(),
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(None),
    );
    for same_network in [false, true] {
        assert_eq!(
            n.engine
                .create_invite(300, InviteAddrs::Auto { same_network })
                .map(|_| ()),
            Err(ConnectError::NoAddresses)
        );
    }
    assert_eq!(pending_count(&n), 0);
    assert_eq!(n.store.pair_count(), 0);
    // срок вне пределов токена: ошибка до создания пары
    assert!(matches!(
        n.engine.create_invite(1, manual()),
        Err(ConnectError::Token(_))
    ));
    assert_eq!(pending_count(&n), 0);
    // неверный адрес: пара откатывается
    assert!(matches!(
        n.engine
            .create_invite(300, InviteAddrs::Manual(vec![addr("0.0.0.0:0")])),
        Err(ConnectError::Token(_))
    ));
    assert_eq!(pending_count(&n), 0);
    assert_eq!(n.store.pair_count(), 0);
}

// ----------------------------------------------------- друг вместо гостя

#[tokio::test(start_paused = true)]
async fn publish_guest_removed_with_friend_added_same_call() {
    let mut d = duo(300);
    let (sa, sb) = reach_sas(&mut d).await;
    assert_eq!(sa, sb);
    d.a.engine.confirm_sas(&d.pa, true, "Борис").unwrap();
    d.b.engine.confirm_sas(&d.pb, true, "Анна").unwrap();
    assert_eq!(
        outcome(wait_event(&mut d.a.events, secs(30), finished).await),
        Some(InviteOutcome::Added)
    );
    assert_eq!(
        outcome(wait_event(&mut d.b.events, secs(30), finished).await),
        Some(InviteOutcome::Added)
    );
    for (n, pair) in [(&d.a, d.pa), (&d.b, d.pb)] {
        let calls = n.t.peers_calls.lock().unwrap().clone();
        // записи этой пары в каждом вызове `set_peers` после выдачи приглашения
        let per_call: Vec<Vec<_>> = calls
            .iter()
            .map(|c| c.iter().filter(|(p, _, _)| *p == pair).collect::<Vec<_>>())
            .collect();
        let first = per_call.iter().position(|v| !v.is_empty()).unwrap();
        let guest_triple = (per_call[first][0].1, per_call[first][0].2);
        let mut transitions = 0;
        let mut was_guest = true;
        for v in &per_call[first..] {
            assert_eq!(v.len(), 1, "gap or duplicate triple for the pair");
            let is_guest = (v[0].1, v[0].2) == guest_triple;
            if was_guest && !is_guest {
                transitions += 1;
            }
            assert!(!(is_guest && !was_guest), "guest came back");
            was_guest = is_guest;
        }
        assert_eq!(
            transitions, 1,
            "exactly one set_peers switches guest to friend"
        );
        assert!(!was_guest, "guest triple still published");
    }
    // у обоих друг записан, гость снят, ключ один
    for (n, pair) in [(&d.a, d.pa), (&d.b, d.pb)] {
        assert!(n.engine.read_book(|b| b.get(&pair).is_some()));
        assert_eq!(pending_count(n), 0);
        assert_eq!(n.store.pair_count(), 1);
    }
    // у A один адрес друга: Contact от гостевого соединения
    let known =
        d.a.engine
            .read_book(|b| b.get(&d.pa).unwrap().known_addrs.clone());
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].source, chervo_addr::AddrSource::Contact);
    assert_eq!(known[0].addr, addr(B_ADDR));
    let known_b =
        d.b.engine
            .read_book(|b| b.get(&d.pb).unwrap().known_addrs.clone());
    assert_eq!(known_b[0].source, chervo_addr::AddrSource::Invite);
}

#[tokio::test(start_paused = true)]
async fn invite_declined_nothing_saved() {
    for (a_ok, b_ok) in [(true, false), (false, true), (false, false)] {
        let mut d = duo(300);
        let _ = reach_sas(&mut d).await;
        d.a.engine.confirm_sas(&d.pa, a_ok, "Борис").unwrap();
        d.b.engine.confirm_sas(&d.pb, b_ok, "Анна").unwrap();
        for n in [&mut d.a, &mut d.b] {
            assert_eq!(
                outcome(wait_event(&mut n.events, secs(30), finished).await),
                Some(InviteOutcome::Declined),
                "{a_ok} {b_ok}"
            );
            assert_eq!(n.engine.read_book(|b| b.friends().len()), 0);
            assert_eq!(n.engine.read_book(|b| b.pending().len()), 0);
            assert_eq!(n.store.pair_count(), 0);
            assert!(n.t.last_peers().is_empty());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn confirm_and_cancel_errors() {
    let mut d = duo(300);
    // до SAS подтверждать нечего
    assert_eq!(
        d.a.engine.confirm_sas(&d.pa, true, "Борис"),
        Err(ConnectError::UnknownPair)
    );
    let _ = reach_sas(&mut d).await;
    // имя проверяется сразу, приглашение остаётся
    for bad in ["", "a\nb"] {
        assert!(matches!(
            d.a.engine.confirm_sas(&d.pa, true, bad),
            Err(ConnectError::Friends(_))
        ));
    }
    d.a.engine.confirm_sas(&d.pa, true, "Борис").unwrap();
    assert_eq!(
        d.a.engine.confirm_sas(&d.pa, true, "Борис"),
        Err(ConnectError::UnknownPair)
    );
    // отмена: сессия останавливается, пара прервана, исхода нет
    d.b.engine.cancel_invite(&d.pb).unwrap();
    assert_eq!(pending_count(&d.b), 0);
    assert_eq!(d.b.store.pair_count(), 0);
    assert_eq!(
        d.b.engine.cancel_invite(&d.pb),
        Err(ConnectError::UnknownPair)
    );
    // B ушёл: A не дождётся решения B и закончит сроком или ошибкой обмена
    let e = wait_event(&mut d.a.events, secs(400), finished).await;
    assert!(matches!(
        outcome(e),
        Some(InviteOutcome::PeerUnreachable | InviteOutcome::Declined)
    ));
}
