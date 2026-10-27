//! Общий приёмник потоков, удержание соединения, второй получатель событий и диспетчер без
//! блокировки на байте вида (этап 14, X0). Соединения в памяти из `kit.rs`.

use std::time::Duration;

use chervo_identity::PairId;
use chervo_token::STREAM_ADDR_INFO;
use chervo_token::addr_flow::encode_addr_info;
use chervo_transport::{Connection, RecvStream, SendStream};
use tokio::time::Instant;

use super::kit::*;
use crate::{ConnectConfig, ConnectError, EngineEvent, StreamInbox};

type Inbox = StreamInbox<FakeConn>;

/// Узел с `n` друзьями (адреса разные) и их парами.
fn node(n: usize, cfg: ConnectConfig) -> (Node, Vec<PairId>) {
    let mut pre = Pre::new();
    let ps: Vec<PairId> = (1..=n)
        .map(|i| pre.solo_friend(vec![inv(&format!("5.6.7.{i}:4000"))]))
        .collect();
    (Node::start(pre, cfg), ps)
}

/// Входящее соединение друга `p`; ждёт, пока движок его примет.
async fn arrive(n: &Node, p: PairId, i: usize) -> FakeConn {
    let c = FakeConn::lonely(p, addr(&format!("5.6.7.{}:4000", i + 1)), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(1)).await;
    c
}

/// Собеседник открывает поток и пишет `bytes`.
async fn open_with(peer: &FakeConn, bytes: &[u8]) -> (FakeTx, FakeRx) {
    let (mut tx, rx) = peer.open_bi().await.unwrap();
    if !bytes.is_empty() {
        tx.write_all(bytes).await.unwrap();
    }
    (tx, rx)
}

/// Поток сброшен движком: чтение даёт конец без данных.
async fn dropped(rx: &mut FakeRx, within: Duration) -> bool {
    let mut b = [0u8; 4];
    matches!(
        tokio::time::timeout(within, rx.read(&mut b)).await,
        Ok(Ok(None))
    )
}

async fn got(inbox: &mut Inbox, within: Duration) -> Option<crate::IncomingStream<FakeConn>> {
    tokio::time::timeout(within, inbox.recv())
        .await
        .ok()
        .flatten()
}

async fn answered(rx: &mut FakeRx, within: Duration) -> bool {
    let mut buf = [0u8; 8];
    matches!(
        tokio::time::timeout(within, rx.read(&mut buf)).await,
        Ok(Ok(Some(n))) if n > 0
    )
}

fn addr_frame() -> Vec<u8> {
    encode_addr_info(addr("1.2.3.4:5"), None).unwrap()
}

#[tokio::test(start_paused = true)]
async fn inbox_receives_registered_kind() {
    let (n, ps) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31, 0x32]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    for kind in [0x31u8, 0x32] {
        let (mut ptx, mut prx) = open_with(&peer, &[kind, 9, 8]).await;
        let mut s = got(&mut inbox, secs(1)).await.expect("stream delivered");
        assert_eq!((s.pair, s.kind), (ps[0], kind));
        assert_eq!(s.conn.conn_id(), c.conn_id());
        // после байта вида поток отдаётся нетронутым
        let mut buf = [0u8; 4];
        assert_eq!(s.rx.read(&mut buf).await.unwrap(), Some(2));
        assert_eq!(&buf[..2], &[9, 8]);
        // и в обе стороны
        s.tx.write_all(&[7]).await.unwrap();
        assert_eq!(prx.read(&mut buf).await.unwrap(), Some(1));
        assert_eq!(buf[0], 7);
        ptx.write_all(&[6]).await.unwrap();
        assert_eq!(s.rx.read(&mut buf).await.unwrap(), Some(1));
        assert_eq!(format!("{s:?}"), "IncomingStream(..)");
    }
    assert!(!c.is_closed());
    assert_eq!(format!("{inbox:?}"), "StreamInbox(..)");
}

#[tokio::test(start_paused = true)]
async fn inbox_kind_rules() {
    let (n, _) = node(1, ConnectConfig::default());
    let e = |r: Result<Inbox, ConnectError>| r.err();
    assert_eq!(
        e(n.engine.stream_inbox(&[0])),
        Some(ConnectError::InvalidKind)
    );
    assert_eq!(
        e(n.engine.stream_inbox(&[STREAM_ADDR_INFO])),
        Some(ConnectError::InvalidKind)
    );
    assert_eq!(
        e(n.engine.stream_inbox(&[0x31, STREAM_ADDR_INFO])),
        Some(ConnectError::InvalidKind)
    );
    assert_eq!(
        e(n.engine.stream_inbox(&[0x40, 0x40])),
        Some(ConnectError::InvalidKind)
    );
    assert_eq!(
        e(n.engine.stream_inbox(&[])),
        Some(ConnectError::InvalidKind)
    );
    // отказы ничего не зарегистрировали
    let first = n.engine.stream_inbox(&[0x31, 0x32]).unwrap();
    assert_eq!(
        e(n.engine.stream_inbox(&[0x31])),
        Some(ConnectError::KindTaken)
    );
    // всё или ничего: 0x40 свободен, но список с занятым 0x32 не регистрируется целиком
    assert_eq!(
        e(n.engine.stream_inbox(&[0x40, 0x32])),
        Some(ConnectError::KindTaken)
    );
    let third = n.engine.stream_inbox(&[0x40]).unwrap();
    // сброшенный приёмник вид освобождает
    drop(first);
    assert!(n.engine.stream_inbox(&[0x31, 0x32]).is_ok());
    drop(third);
    assert_eq!(ConnectError::InvalidKind.to_string(), "invalid stream kind");
    assert_eq!(
        ConnectError::KindTaken.to_string(),
        "stream kind already registered"
    );
}

#[tokio::test(start_paused = true)]
async fn unregistered_kind_dropped() {
    let (n, ps) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    for kind in [0x32u8, 0x7F, 0xFF] {
        let (_tx, mut rx) = open_with(&peer, &[kind, 1, 2, 3]).await;
        assert!(dropped(&mut rx, secs(2)).await, "kind {kind:#x}");
    }
    assert!(got(&mut inbox, secs(1)).await.is_none());
    assert!(!c.is_closed());
}

#[tokio::test(start_paused = true)]
async fn inbox_full_drops_stream() {
    let cfg = ConnectConfig {
        stream_inbox_capacity: 2,
        ..ConnectConfig::default()
    };
    let (n, ps) = node(1, cfg);
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let mut keep = Vec::new();
    let mut verdicts = Vec::new();
    for _ in 0..4 {
        let (tx, mut rx) = open_with(&peer, &[0x31, 1]).await;
        // принятый в очередь поток живёт (читать нечего), лишний сброшен
        verdicts.push(dropped(&mut rx, secs(1)).await);
        keep.push((tx, rx));
    }
    assert_eq!(verdicts, [false, false, true, true]);
    assert!(got(&mut inbox, secs(1)).await.is_some());
    assert!(got(&mut inbox, secs(1)).await.is_some());
    assert!(got(&mut inbox, secs(1)).await.is_none());
    assert!(!c.is_closed(), "overflow drops streams, not the connection");
    // место освободилось
    let (_tx, mut rx) = open_with(&peer, &[0x31, 1]).await;
    assert!(!dropped(&mut rx, secs(1)).await);
    assert!(got(&mut inbox, secs(1)).await.is_some());
}

#[tokio::test(start_paused = true)]
async fn inbox_per_min_cap() {
    let cfg = ConnectConfig {
        extra_streams_in_per_min: 3,
        ..ConnectConfig::default()
    };
    let (n, ps) = node(1, cfg);
    let mut inbox = n.engine.stream_inbox(&[0x31, 0x32]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let mut delivered = Vec::new();
    let mut keep = Vec::new();
    // пределом делятся все зарегистрированные виды
    for kind in [0x31u8, 0x32, 0x31, 0x32, 0x31] {
        keep.push(open_with(&peer, &[kind, 1]).await);
        delivered.push(got(&mut inbox, secs(1)).await.is_some());
    }
    assert_eq!(delivered, [true, true, true, false, false]);
    assert!(!c.is_closed());
    tokio::time::sleep(secs(61)).await;
    keep.push(open_with(&peer, &[0x31, 1]).await);
    assert!(
        got(&mut inbox, secs(1)).await.is_some(),
        "the window is a minute"
    );
}

#[tokio::test(start_paused = true)]
async fn inbox_not_active_dropped() {
    let (n, ps) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let (_t1, mut r1) = open_with(&peer, &[0x31, 1]).await;
    let first = got(&mut inbox, secs(1)).await;
    assert!(first.is_some());
    assert!(!dropped(&mut r1, secs(1)).await);
    // пара перестала быть `Active`, пока соединение ещё не снято (окно гонки): в книге
    // напрямую, без `update_book`, который сам закрыл бы соединение
    n.engine.inner.lock().book.block(&*n.store, &ps[0]).unwrap();
    let (_t2, mut r2) = open_with(&peer, &[0x31, 1]).await;
    assert!(dropped(&mut r2, secs(2)).await);
    assert!(got(&mut inbox, secs(1)).await.is_none());
    drop(first);
}

#[tokio::test(start_paused = true)]
async fn inbox_never_guest() {
    let (n, _) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let guest = PairId::from_bytes([0x55; 16]);
    n.engine
        .add_guest(guest, vec![addr("8.8.8.8:1")], Box::new(|| None))
        .unwrap();
    let c = FakeConn::lonely(guest, addr("8.8.8.8:1"), true);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(5)).await;
    // соединение гостя не обслуживается: ни потоков, ни приёма
    assert!(got(&mut inbox, secs(5)).await.is_none());
    assert_eq!(c.opened(), 0);
    assert_eq!(c.accepted(), 0, "the dispatcher never runs for a guest");
    assert!(n.engine.connection(&guest).is_none());
}

#[tokio::test(start_paused = true)]
async fn slow_kind_byte_does_not_block_others() {
    let (n, ps) = node(1, ConnectConfig::default());
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let t0 = Instant::now();
    // 4 молчащих потока занимают все места чтения байта вида
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(open_with(&peer, &[]).await);
    }
    let (mut tx, mut rx) = open_with(&peer, &[]).await;
    tx.write_all(&addr_frame()).await.unwrap();
    tx.finish().unwrap();
    assert!(answered(&mut rx, secs(7)).await, "ADDR_INFO never answered");
    let waited = Instant::now().saturating_duration_since(t0);
    // место освобождается по сроку молчащих (один `addr_info_timeout`), а не друг за другом
    assert!(waited <= secs(6), "waited {waited:?}");
    for (_, r) in &mut silent {
        assert!(dropped(r, secs(1)).await);
    }
    assert!(!c.is_closed());
}

#[tokio::test(start_paused = true)]
async fn kind_read_permits_leave_room() {
    let (n, ps) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let mut silent = Vec::new();
    for _ in 0..3 {
        silent.push(open_with(&peer, &[]).await);
    }
    let t0 = Instant::now();
    let (mut tx, mut rx) = open_with(&peer, &[]).await;
    tx.write_all(&addr_frame()).await.unwrap();
    tx.finish().unwrap();
    let _kept = open_with(&peer, &[0x31, 1]).await;
    assert!(got(&mut inbox, secs(1)).await.is_some());
    assert!(answered(&mut rx, secs(1)).await);
    assert!(Instant::now().saturating_duration_since(t0) < secs(2));
}

#[tokio::test(start_paused = true)]
async fn addr_info_no_longer_blocks_accept() {
    let (n, ps) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    let c = arrive(&n, ps[0], 0).await;
    let peer = c.peer();
    let t0 = Instant::now();
    // ADDR_INFO начат и не закончен: диспетчер ждёт кадр до `addr_info_timeout`
    let (_stuck_tx, _stuck_rx) = open_with(&peer, &[STREAM_ADDR_INFO]).await;
    let _other = open_with(&peer, &[0x31, 1]).await;
    assert!(got(&mut inbox, secs(1)).await.is_some());
    assert!(Instant::now().saturating_duration_since(t0) < secs(2));
    // и обычный обмен ADDR_INFO идёт тут же
    let (mut tx, mut rx) = open_with(&peer, &[]).await;
    tx.write_all(&addr_frame()).await.unwrap();
    tx.finish().unwrap();
    assert!(answered(&mut rx, secs(1)).await);
}

#[tokio::test(start_paused = true)]
async fn hold_prevents_max_live_eviction() {
    let cfg = ConnectConfig {
        max_live: 2,
        ..ConnectConfig::default()
    };
    let (n, ps) = node(4, cfg);
    assert!(n.engine.hold(&ps[0]).is_none(), "no live connection");
    let c0 = arrive(&n, ps[0], 0).await;
    let c1 = arrive(&n, ps[1], 1).await;
    let h0 = n.engine.hold(&ps[0]).unwrap();
    let h1 = n.engine.hold(&ps[1]).unwrap();
    assert_eq!(format!("{h0:?}"), "ConnHold(..)");
    // оба старых заняты: новое остаётся, предел превышен
    let c2 = arrive(&n, ps[2], 2).await;
    assert!(!c0.is_closed() && !c1.is_closed() && !c2.is_closed());
    for p in &ps[..3] {
        assert!(n.engine.connection(p).is_some());
    }
    // следующее вытесняет единственное свободное, занятые живы
    let c3 = arrive(&n, ps[3], 3).await;
    assert!(c2.is_closed());
    assert!(!c0.is_closed() && !c1.is_closed() && !c3.is_closed());
    assert!(n.engine.connection(&ps[2]).is_none());
    drop((h0, h1));
}

#[tokio::test(start_paused = true)]
async fn hold_released_on_drop() {
    let cfg = ConnectConfig {
        max_live: 2,
        ..ConnectConfig::default()
    };
    let (n, ps) = node(4, cfg);
    let c0 = arrive(&n, ps[0], 0).await;
    let c1 = arrive(&n, ps[1], 1).await;
    let ha = n.engine.hold(&ps[0]).unwrap();
    let hb = n.engine.hold(&ps[0]).unwrap();
    drop(ha);
    // второе удержание ещё действует
    let c2 = arrive(&n, ps[2], 2).await;
    assert!(!c0.is_closed());
    assert!(c1.is_closed());
    drop(hb);
    assert!(n.engine.inner.lock().holds.is_empty());
    let c3 = arrive(&n, ps[3], 3).await;
    assert!(c0.is_closed(), "the oldest goes once nothing holds it");
    assert!(!c2.is_closed() && !c3.is_closed());
}

#[tokio::test(start_paused = true)]
async fn hold_of_replaced_conn_ignored() {
    let cfg = ConnectConfig {
        max_live: 2,
        ..ConnectConfig::default()
    };
    let (n, ps) = node(3, cfg);
    let c0 = arrive(&n, ps[0], 0).await;
    let h = n.engine.hold(&ps[0]).unwrap();
    // то же соединение друга заменено другим: удержание старого на новое не действует
    let c0b = arrive(&n, ps[0], 0).await;
    assert_eq!(
        n.engine.connection(&ps[0]).unwrap().conn_id(),
        c0b.conn_id()
    );
    let c1 = arrive(&n, ps[1], 1).await;
    let c2 = arrive(&n, ps[2], 2).await;
    assert!(
        c0b.is_closed(),
        "the replacement is the oldest and not held"
    );
    assert!(!c1.is_closed() && !c2.is_closed());
    // сброс старого удержания не задевает чужих
    let h1 = n.engine.hold(&ps[1]).unwrap();
    drop(h);
    assert!(n.engine.inner.lock().holds.contains_key(&ps[1]));
    drop(h1);
    assert!(n.engine.inner.lock().holds.is_empty());
    drop(c0);
}

/// R2-2: удержание закрытого и снятого соединения не переходит к новому соединению пары и не
/// уменьшает его счётчик при сбросе (номера соединений не повторяются).
#[tokio::test(start_paused = true)]
async fn hold_not_inherited_by_new_conn() {
    let (n, ps) = node(1, ConnectConfig::default());
    let c1 = arrive(&n, ps[0], 0).await;
    let id1 = n.engine.connection(&ps[0]).unwrap().conn_id();
    let old = n.engine.hold(&ps[0]).unwrap();
    // соединение 1 закрыто и снято с учёта, запись удержания осталась за ним
    c1.close();
    tokio::time::sleep(secs(1)).await;
    assert!(n.engine.connection(&ps[0]).is_none());
    assert_eq!(n.engine.inner.lock().holds.get(&ps[0]), Some(&(id1, 1)));
    // соединение 2 живо: чужое удержание ему не принадлежит
    let c2 = arrive(&n, ps[0], 1).await;
    let id2 = n.engine.connection(&ps[0]).unwrap().conn_id();
    assert_ne!(id1, id2, "номера соединений не повторяются");
    assert!(!n.engine.inner.lock().holds.contains_key(&ps[0]));
    let h2 = n.engine.hold(&ps[0]).unwrap();
    assert_eq!(n.engine.inner.lock().holds.get(&ps[0]), Some(&(id2, 1)));
    // сброс старого удержания счётчик нового соединения не меняет
    drop(old);
    assert_eq!(n.engine.inner.lock().holds.get(&ps[0]), Some(&(id2, 1)));
    drop(h2);
    assert!(n.engine.inner.lock().holds.is_empty());
    drop(c2);
}

#[tokio::test(start_paused = true)]
async fn subscribe_second_receiver_gets_events() {
    let (mut n, ps) = node(1, ConnectConfig::default());
    let mut second = n.engine.subscribe();
    assert_eq!(format!("{second:?}"), "EngineEvents(..)");
    let _c = arrive(&n, ps[0], 0).await;
    let is_conn = |e: &EngineEvent| matches!(e, EngineEvent::Connected { .. });
    assert!(wait_event(&mut n.events, secs(5), is_conn).await.is_some());
    assert!(wait_event(&mut second, secs(5), is_conn).await.is_some());
}

#[tokio::test(start_paused = true)]
async fn inbox_closes_on_shutdown() {
    let (n, _) = node(1, ConnectConfig::default());
    let mut inbox = n.engine.stream_inbox(&[0x31]).unwrap();
    n.engine.shutdown();
    assert!(inbox.recv().await.is_none());
    assert_eq!(
        n.engine.stream_inbox(&[0x40]).err(),
        Some(ConnectError::Shutdown)
    );
}
