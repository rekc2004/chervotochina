//! ADDR_INFO: обмен, ограничения, ленивый выпуск токена, отложенное обновление.

use std::sync::{Arc, Mutex};

use chervo_addr::{AddrSource, LocalSnapshot, NatView, OwnAddrs, PublishCtx, RouteSources};
use chervo_identity::PairId;
use chervo_token::addr_flow::{PeerAddrInfo, decode_addr_info, encode_addr_info};
use chervo_token::{SignedAddrUpdate, decode_addr_update_bin};
use chervo_transport::{Connection, RecvStream, SendStream};
use tokio::time::Instant;

use super::kit::*;
use crate::{Clock, ConnectConfig, EngineEvent};

/// Токен друга `pair` из его книги: так выглядит обновление от настоящего друга.
fn issue_from(pre: &mut Pre, pair: &PairId, route: &str, unix: u64) -> SignedAddrUpdate {
    let mut own = OwnAddrs::new();
    own.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some(route.parse().unwrap()),
            v6: None,
        },
        listen: vec![addr("0.0.0.0:4000")],
    });
    let set = own.publishable(PublishCtx::default(), unix);
    let t = pre
        .book
        .issue_addr_update(&*pre.store, pair, &set, unix)
        .unwrap();
    decode_addr_update_bin(t.bytes()).unwrap()
}

fn info(update: Option<SignedAddrUpdate>) -> PeerAddrInfo {
    PeerAddrInfo {
        observed_me: addr("9.9.9.9:4000"),
        via: addr("5.6.7.8:4000"),
        update,
    }
}

fn apply(n: &Node, pair: PairId, update: Option<SignedAddrUpdate>) {
    let now = Instant::now();
    let unix = n.clock.now_unix();
    // обмен идёт по живому соединению друга, если оно есть (иначе наблюдение не засчитывается)
    let id = n.engine.connection(&pair).map_or(0, |c| c.conn_id());
    let mut st = n.engine.inner.lock();
    n.engine
        .inner
        .apply_peer_info(&mut st, pair, id, info(update), now, unix);
}

fn known_has(n: &Node, pair: &PairId, a: &str) -> bool {
    let a = addr(a);
    n.engine.read_book(|b| {
        b.get(pair)
            .unwrap()
            .known_addrs
            .iter()
            .any(|k| k.addr == a && k.source == AddrSource::AddressUpdate)
    })
}

fn last_seq(n: &Node, pair: &PairId) -> u64 {
    n.engine.read_book(|b| b.get(pair).unwrap().last_addr_seq)
}

/// Собеседник-запись: принимает потоки ADDR_INFO, читает кадр до конца, отвечает пустым кадром.
/// В списке номер обновления из каждого полученного кадра (`None`: обновления нет).
fn spawn_recorder(peer: FakeConn) -> Arc<Mutex<Vec<Option<u64>>>> {
    let seen: Arc<Mutex<Vec<Option<u64>>>> = Arc::new(Mutex::new(Vec::new()));
    let out = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut tx, mut rx)) = peer.accept_bi().await {
            let mut bytes = Vec::new();
            let mut buf = [0u8; 64];
            while let Ok(Some(n)) = rx.read(&mut buf).await {
                bytes.extend_from_slice(&buf[..n]);
            }
            let (_, upd) = decode_addr_info(&bytes).unwrap();
            out.lock().unwrap().push(upd.map(|u| u.unverified_seq()));
            let frame = encode_addr_info(addr("1.2.3.4:5"), None).unwrap();
            let _ = tx.write_all(&frame).await;
            let _ = tx.finish();
        }
    });
    seen
}

async fn read_some(rx: &mut FakeRx) -> bool {
    let mut buf = [0u8; 8];
    matches!(
        tokio::time::timeout(secs(2), rx.read(&mut buf)).await,
        Ok(Ok(Some(n))) if n > 0
    )
}

#[tokio::test(start_paused = true)]
async fn addrinfo_initiator_opens_acceptor_answers() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let a = Node::start_with(
        pre_a,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    // у B ручной проброс: вид сети меняется только от наблюдения друга
    let b = Node::start(
        pre_b,
        ConnectConfig {
            manual_forward: Some(4000),
            ..ConnectConfig::default()
        },
    );
    assert_ne!(b.engine.nat_view(), NatView::ManualForward);
    let links = link_nodes(&a, pa, "5.6.7.8:4000", &b, pb, "7.7.7.7:4000");
    tokio::time::sleep(secs(4)).await;
    let (conn_a, conn_b) = links.lock().unwrap()[0].clone();
    assert_eq!(conn_a.opened(), 1);
    assert_eq!(conn_b.accepted(), 1);
    assert_eq!(conn_b.opened(), 0, "the acceptor only answers");
    // принявший применил обновление и наблюдение инициатора
    assert!(known_has(&b, &pb, "7.7.7.7:4000"));
    assert_eq!(b.engine.nat_view(), NatView::ManualForward);
    assert!(a.engine.connection(&pa).is_some());
    assert!(b.engine.connection(&pb).is_some());
}

#[tokio::test(start_paused = true)]
async fn addrinfo_timeout_keeps_connection() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), true);
    let cc = c.clone();
    n.t.set_script(move |_, _| Action::Ok(cc.clone(), secs(0)));
    tokio::time::sleep(secs(12)).await;
    assert_eq!(c.opened(), 1, "exchange started");
    assert!(n.engine.connection(&p).is_some());
    assert!(!c.is_closed());
    assert!(
        !drain(&mut n.events)
            .await
            .iter()
            .any(|e| matches!(e, EngineEvent::Disconnected { .. }))
    );
}

#[tokio::test(start_paused = true)]
async fn addrinfo_incoming_cap_per_min() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(1)).await;
    let peer = c.peer();
    let frame = encode_addr_info(addr("1.2.3.4:5"), None).unwrap();
    let mut answered = Vec::new();
    for _ in 0..6 {
        let (mut tx, mut rx) = peer.open_bi().await.unwrap();
        tx.write_all(&frame).await.unwrap();
        tx.finish().unwrap();
        answered.push(read_some(&mut rx).await);
    }
    assert_eq!(answered, [true, true, true, true, false, false]);
    assert!(!c.is_closed(), "overflow drops streams, not the connection");
    tokio::time::sleep(secs(61)).await;
    let (mut tx, mut rx) = peer.open_bi().await.unwrap();
    tx.write_all(&frame).await.unwrap();
    tx.finish().unwrap();
    assert!(read_some(&mut rx).await, "the window is a minute");
}

#[tokio::test(start_paused = true)]
async fn addrinfo_never_on_guest() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let guest = PairId::from_bytes([0x55; 16]);
    n.engine
        .add_guest(guest, vec![addr("8.8.8.8:1")], Box::new(|| None))
        .unwrap();
    let c = FakeConn::lonely(guest, addr("8.8.8.8:1"), true);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(30)).await;
    assert_eq!(c.opened(), 0);
    assert_eq!(c.accepted(), 0);
    assert!(n.engine.connection(&guest).is_none());
    assert!(
        !drain(&mut n.events)
            .await
            .iter()
            .any(|e| matches!(e, EngineEvent::Connected { pair, .. } if *pair == guest))
    );
}

#[tokio::test(start_paused = true)]
async fn addrinfo_observe_only_active() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(
        pre,
        ConnectConfig {
            manual_forward: Some(4000),
            ..ConnectConfig::default()
        },
    );
    // наблюдение засчитывается по живому соединению (F1): сначала соединение, затем блокировка
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(1)).await;
    assert!(n.engine.connection(&p).is_some());
    n.engine.update_book(|b, s| b.block(s, &p)).unwrap();
    apply(&n, p, None);
    assert_ne!(n.engine.nat_view(), NatView::ManualForward);
    n.engine.update_book(|b, s| b.unblock(s, &p)).unwrap();
    let c2 = FakeConn::lonely(p, addr("5.6.7.8:4000"), false);
    n.t.push_incoming(c2);
    tokio::time::sleep(secs(1)).await;
    apply(&n, p, None);
    assert_eq!(n.engine.nat_view(), NatView::ManualForward);
}

#[tokio::test(start_paused = true)]
async fn addrinfo_stale_ignored() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let n = Node::start(pre_a, ConnectConfig::default());
    let u1 = issue_from(&mut pre_b, &pb, "8.8.8.8", BASE_UNIX);
    apply(&n, pa, Some(u1.clone()));
    let seq = last_seq(&n, &pa);
    assert_eq!(seq, u1.unverified_seq());
    assert!(known_has(&n, &pa, "8.8.8.8:4000"));
    // тот же токен ещё раз: молча игнорируется, ничего не откладывается
    apply(&n, pa, Some(u1));
    assert_eq!(last_seq(&n, &pa), seq);
    assert!(
        n.engine
            .inner
            .lock()
            .friends
            .get(&pa)
            .unwrap()
            .deferred
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn addrinfo_ratelimited_retried_later() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let n = Node::start(pre_a, ConnectConfig::default());
    let u1 = issue_from(&mut pre_b, &pb, "8.8.8.8", BASE_UNIX);
    let u2 = issue_from(&mut pre_b, &pb, "8.8.4.4", BASE_UNIX + 1);
    apply(&n, pa, Some(u1));
    apply(&n, pa, Some(u2.clone()));
    // второе обновление внутри 10 с отклонено по частоте и ждёт
    assert!(!known_has(&n, &pa, "8.8.4.4:4000"));
    assert!(
        n.engine
            .inner
            .lock()
            .friends
            .get(&pa)
            .unwrap()
            .deferred
            .is_some()
    );
    tokio::time::sleep(secs(13)).await;
    assert!(known_has(&n, &pa, "8.8.4.4:4000"));
    assert_eq!(last_seq(&n, &pa), u2.unverified_seq());
    assert!(
        n.engine
            .inner
            .lock()
            .friends
            .get(&pa)
            .unwrap()
            .deferred
            .is_none()
    );
}

/// Живая сторона-инициатор с записывающим собеседником. Возвращает узел, соединение, запись.
async fn live_initiator(
    route: &str,
    friends: usize,
) -> (Node, FakeConn, Arc<Mutex<Vec<Option<u64>>>>, PairId) {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    for i in 1..friends {
        pre.solo_friend(vec![inv(&format!("6.6.6.{i}:4000"))]);
    }
    let n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some(route)),
    );
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), true);
    let seen = spawn_recorder(c.peer());
    let cc = c.clone();
    n.t.set_script(move |pair, _| {
        if *pair == p {
            Action::Ok(cc.clone(), secs(0))
        } else {
            Action::Hang
        }
    });
    tokio::time::sleep(secs(3)).await;
    (n, c, seen, p)
}

#[tokio::test(start_paused = true)]
async fn addrinfo_issue_only_on_change() {
    let (n, _c, seen, p) = live_initiator("7.7.7.7", 1).await;
    let s1 = n.engine.read_book(|b| b.get(&p).unwrap().addr_seq_out);
    assert!(s1 > 0, "first exchange issues the token");
    assert_eq!(seen.lock().unwrap().len(), 1);
    // изменился снимок, но набор публикации тот же: новый токен не выпускается
    n.probe.set_v6(Some("fe80::1"));
    tokio::time::sleep(secs(12)).await;
    assert_eq!(seen.lock().unwrap().len(), 2, "second exchange happened");
    assert_eq!(n.engine.read_book(|b| b.get(&p).unwrap().addr_seq_out), s1);
    // набор изменился: номер растёт
    n.probe.set_v4(Some("7.7.7.9"));
    tokio::time::sleep(secs(12)).await;
    let s2 = n.engine.read_book(|b| b.get(&p).unwrap().addr_seq_out);
    assert!(s2 > s1);
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn addrinfo_sender_includes_latest_update() {
    let (n, _c, seen, p) = live_initiator("7.7.7.7", 1).await;
    let s1 = n.engine.read_book(|b| b.get(&p).unwrap().addr_seq_out);
    n.probe.set_v6(Some("fe80::1"));
    tokio::time::sleep(secs(12)).await;
    // каждый кадр несёт последний токен (повтор покрывает отказ `RateLimited` у получателя)
    assert_eq!(*seen.lock().unwrap(), vec![Some(s1), Some(s1)]);
}

#[tokio::test(start_paused = true)]
async fn addrinfo_issue_lazy_only_live() {
    let mut pre = Pre::new();
    let pairs: Vec<PairId> = (1..=10)
        .map(|i| pre.solo_friend(vec![inv(&format!("6.6.6.{i}:4000"))]))
        .collect();
    let n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    // живое соединение только с первым другом, входящее: сами мы при подключении не шлём
    let c = FakeConn::lonely(pairs[0], addr("6.6.6.1:4000"), false);
    let _seen = spawn_recorder(c.peer());
    n.t.push_incoming(c);
    tokio::time::sleep(secs(3)).await;
    let issued = |n: &Node| -> usize {
        n.engine
            .read_book(|b| b.friends().iter().filter(|f| f.addr_seq_out > 0).count())
    };
    assert_eq!(issued(&n), 0);
    n.probe.set_v4(Some("7.7.7.9"));
    tokio::time::sleep(secs(6)).await;
    assert_eq!(issued(&n), 1, "only the friend with a live connection");
    assert!(
        n.engine
            .read_book(|b| b.get(&pairs[0]).unwrap().addr_seq_out)
            > 0
    );
}

#[tokio::test(start_paused = true)]
async fn unknown_stream_kind_dropped() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(1)).await;
    let peer = c.peer();
    for kind in [0x7Fu8, 0x00, 0xFF] {
        let (mut tx, mut rx) = peer.open_bi().await.unwrap();
        tx.write_all(&[kind, 1, 2, 3]).await.unwrap();
        let mut buf = [0u8; 4];
        // собеседник сбросил поток: чтение кончается без данных
        assert!(matches!(rx.read(&mut buf).await, Ok(None)));
    }
    assert!(!c.is_closed());
    // обычный поток после этого отвечается
    let frame = encode_addr_info(addr("1.2.3.4:5"), None).unwrap();
    let (mut tx, mut rx) = peer.open_bi().await.unwrap();
    tx.write_all(&frame).await.unwrap();
    tx.finish().unwrap();
    assert!(read_some(&mut rx).await);
}

#[tokio::test(start_paused = true)]
async fn kind_byte_timeout() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(1)).await;
    let peer = c.peer();
    let t0 = Instant::now();
    // поток открыт, байт вида не приходит
    let (_tx, mut rx) = peer.open_bi().await.unwrap();
    let mut buf = [0u8; 1];
    assert!(matches!(rx.read(&mut buf).await, Ok(None)));
    let waited = Instant::now().saturating_duration_since(t0);
    assert!(waited >= secs(5) && waited < secs(6), "waited {waited:?}");
    assert!(!c.is_closed());
    let frame = encode_addr_info(addr("1.2.3.4:5"), None).unwrap();
    let (mut tx, mut rx) = peer.open_bi().await.unwrap();
    tx.write_all(&frame).await.unwrap();
    tx.finish().unwrap();
    assert!(read_some(&mut rx).await);
}
