//! Поиск в LAN в движке (этап 13в): поддельная `LanLink` записывает вызовы, время
//! приостановлено, сети нет.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{AddrSource, LanFound, LanLink, LanPeer, LanStatus};
use chervo_identity::{KxPeer, PairId, SecretStore, create};
use chervo_transport::TransportError;
use tokio::time::Instant;

use super::kit::*;
use crate::{
    Clock, ConnectConfig, ConnectError, EngineEvent, LAN_DISCOVERY_TEXT, LAN_FIRST_RUN_TEXT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Local(Option<SocketAddrV4>),
    Peers(Vec<PairId>),
    Wanted(Vec<PairId>),
    Trigger,
    Shutdown,
}

/// Записывает вызовы; найденное задают тесты.
struct FakeLink {
    calls: Mutex<Vec<Call>>,
    found: Mutex<Vec<LanFound>>,
    /// Постоянный источник: отдаётся при каждом `take_found` (пока не очищен).
    repeat: Mutex<Vec<LanFound>>,
    takes: AtomicUsize,
}

impl FakeLink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            found: Mutex::new(Vec::new()),
            repeat: Mutex::new(Vec::new()),
            takes: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn count(&self, f: impl Fn(&Call) -> bool) -> usize {
        self.calls().iter().filter(|c| f(c)).count()
    }

    fn last_peers(&self) -> Vec<PairId> {
        self.calls()
            .iter()
            .rev()
            .find_map(|c| match c {
                Call::Peers(p) => Some(p.clone()),
                _ => None,
            })
            .unwrap()
    }

    fn last_wanted(&self) -> Vec<PairId> {
        self.calls()
            .iter()
            .rev()
            .find_map(|c| match c {
                Call::Wanted(p) => Some(p.clone()),
                _ => None,
            })
            .unwrap()
    }

    fn push_found(&self, pair: PairId, addr: &str) {
        self.found.lock().unwrap().push(LanFound {
            pair,
            addr: addr.parse().unwrap(),
        });
    }
}

impl LanLink for FakeLink {
    fn set_local(&self, local: Option<SocketAddrV4>) {
        self.calls.lock().unwrap().push(Call::Local(local));
    }

    fn set_peers(&self, peers: Vec<LanPeer>) {
        let pairs = peers.iter().map(|p| p.pair).collect();
        self.calls.lock().unwrap().push(Call::Peers(pairs));
    }

    fn set_wanted(&self, wanted: Vec<PairId>) {
        self.calls.lock().unwrap().push(Call::Wanted(wanted));
    }

    fn trigger(&self) {
        self.calls.lock().unwrap().push(Call::Trigger);
    }

    fn take_found(&self) -> Vec<LanFound> {
        self.takes.fetch_add(1, Ordering::SeqCst);
        let mut out: Vec<LanFound> = std::mem::take(&mut *self.found.lock().unwrap());
        out.extend(self.repeat.lock().unwrap().iter().copied());
        out
    }

    fn status(&self) -> LanStatus {
        LanStatus::Running
    }

    fn shutdown(&self) {
        self.calls.lock().unwrap().push(Call::Shutdown);
    }
}

fn sorted(mut v: Vec<PairId>) -> Vec<PairId> {
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v
}

async fn ticks(n: u64) {
    tokio::time::sleep(secs(n)).await;
}

/// Все адреса всех вызовов `connect` (в порядке вызовов) для пары.
fn dialed(n: &Node, pair: &PairId) -> Vec<Vec<SocketAddr>> {
    n.t.calls_for(pair)
}

fn sock(s: &str) -> SocketAddr {
    addr(s)
}

#[tokio::test(start_paused = true)]
async fn lan_attach_pushes_state_then_triggers() {
    let mut pre = Pre::new();
    let a = pre.solo_friend(vec![]);
    let b = pre.solo_friend(vec![]);
    let blocked = pre.solo_friend(vec![]);
    let broken = pre.solo_friend(vec![]);
    pre.book.block(&*pre.store, &blocked).unwrap();
    pre.store.delete(&broken).unwrap();
    let n = Node::start(pre, ConnectConfig::default());
    // гость живого приглашения: ключи есть, но он не друг
    let guest = PairId::generate().unwrap();
    let gk = create(&MemStore::default(), &guest).unwrap();
    let other = create(&MemStore::default(), &guest).unwrap();
    let gx = other.kx_public();
    let gkx = std::sync::Mutex::new(Some(gk.into_kx()));
    n.engine
        .add_guest(
            guest,
            vec![],
            Box::new(move || {
                gkx.lock()
                    .unwrap()
                    .take()
                    .map(|k| KxPeer::new(guest, k, gx))
            }),
        )
        .unwrap();
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    let calls = link.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert_eq!(
        calls[0],
        Call::Local(Some("192.168.1.5:4000".parse().unwrap()))
    );
    assert_eq!(calls[1], Call::Peers(sorted(vec![a, b])));
    assert_eq!(calls[2], Call::Wanted(sorted(vec![a, b])));
    assert_eq!(calls[3], Call::Trigger);
    // ничего лишнего через несколько тактов
    ticks(10).await;
    assert_eq!(link.calls().len(), 4);
    assert_eq!(n.engine.lan_status(), Some(LanStatus::Running));
}

#[tokio::test(start_paused = true)]
async fn lan_local_none_when_not_private() {
    let cases: [(Option<&str>, Vec<SocketAddr>); 6] = [
        (Some("7.7.7.7"), vec![sock("0.0.0.0:4000")]),
        (Some("100.64.0.9"), vec![sock("0.0.0.0:4000")]),
        (Some("169.254.1.2"), vec![sock("0.0.0.0:4000")]),
        (None, vec![sock("0.0.0.0:4000")]),
        (Some("192.168.1.5"), vec![sock("0.0.0.0:0")]),
        (Some("192.168.1.5"), vec![sock("[::]:4000")]),
    ];
    for (v4, local) in cases {
        let mut pre = Pre::new();
        pre.solo_friend(vec![]);
        let t = FakeTransport::new();
        t.set_local(local.clone());
        let n = Node::start_with(pre, ConnectConfig::default(), t, FakeProbe::new(v4));
        let link = FakeLink::new();
        n.engine.attach_lan(link.clone()).unwrap();
        assert_eq!(link.calls()[0], Call::Local(None), "{v4:?} {local:?}");
    }
    // при смене маршрута на частный новая точка входа уходит ссылке
    let mut pre = Pre::new();
    pre.solo_friend(vec![]);
    let n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(None),
    );
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    n.probe.set_v4(Some("10.1.2.3"));
    ticks(5).await;
    assert_eq!(
        link.count(|c| matches!(c, Call::Local(Some(_)))),
        1,
        "{:?}",
        link.calls()
    );
}

#[tokio::test(start_paused = true)]
async fn lan_found_dials_friend_first() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    ticks(2).await;
    link.push_found(p, "192.168.1.77:4001");
    ticks(3).await;
    let hint = sock("192.168.1.77:4001");
    let call = dialed(&n, &p)
        .into_iter()
        .find(|c| c.contains(&hint))
        .expect("the hint was dialed");
    assert_eq!(call[0], hint, "{call:?}");
}

#[tokio::test(start_paused = true)]
async fn lan_found_ignored() {
    let mut pre = Pre::new();
    let ok = pre.solo_friend(vec![]);
    let blocked = pre.solo_friend(vec![]);
    let live = pre.solo_friend(vec![]);
    let broken = pre.solo_friend(vec![]);
    let unknown = PairId::generate().unwrap();
    pre.book.block(&*pre.store, &blocked).unwrap();
    pre.store.delete(&broken).unwrap();
    let guest = PairId::generate().unwrap();
    let n = Node::start(pre, ConnectConfig::default());
    n.engine
        .add_guest(guest, vec![], Box::new(|| None))
        .unwrap();
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    n.t.push_incoming(FakeConn::lonely(live, sock("192.168.1.60:4000"), false));
    ticks(2).await;
    assert!(n.engine.connection(&live).is_some());
    for (pair, a) in [
        (unknown, "192.168.1.70:4001"),
        (blocked, "192.168.1.71:4001"),
        (guest, "192.168.1.72:4001"),
        (live, "192.168.1.73:4001"),
        (broken, "192.168.1.74:4001"),
        (ok, "8.8.8.8:4001"),
        (ok, "192.168.1.75:0"),
        (ok, "224.0.0.251:4001"),
        (ok, "255.255.255.255:4001"),
        (ok, "100.64.0.9:4001"),
        (ok, "169.254.1.1:4001"),
        (ok, "192.168.1.5:4001"),
    ] {
        link.push_found(pair, a);
    }
    ticks(5).await;
    assert_eq!(n.t.call_count(), 0, "{:?}", n.t.calls.lock().unwrap());
    assert!(n.engine.inner.lock().lan_hints.is_empty());
    // положительный контроль: правильный адрес принимается
    link.push_found(ok, "192.168.1.76:4001");
    ticks(3).await;
    assert!(
        dialed(&n, &ok)
            .iter()
            .any(|c| c.contains(&sock("192.168.1.76:4001")))
    );
}

#[tokio::test(start_paused = true)]
async fn lan_hint_strict_limiter() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let hint = sock("192.168.1.77:4001");
    let times: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
    let t2 = times.clone();
    n.t.set_script(move |_, addrs| {
        if addrs.contains(&hint) {
            t2.lock().unwrap().push(Instant::now());
        }
        Action::Fail(TransportError::TimedOut, secs(0))
    });
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    // «найден» каждую секунду (повтор маяков) две минуты
    link.repeat.lock().unwrap().push(LanFound {
        pair: p,
        addr: "192.168.1.77:4001".parse().unwrap(),
    });
    ticks(120).await;
    let t = times.lock().unwrap().clone();
    assert!(!t.is_empty());
    assert!(t.len() <= 4, "{} dials in 120 s", t.len());
    for w in t.windows(2) {
        assert!(
            w[1] - w[0] >= secs(32),
            "two dials of one IP {:?} apart",
            w[1] - w[0]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn lan_hint_expires() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let hint = sock("192.168.1.77:4001");
    let late = Arc::new(AtomicUsize::new(0));
    let l2 = late.clone();
    let start = Instant::now();
    n.t.set_script(move |_, addrs| {
        if addrs.contains(&hint) && Instant::now() - start > secs(186) {
            l2.fetch_add(1, Ordering::SeqCst);
        }
        Action::Fail(TransportError::TimedOut, secs(0))
    });
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    ticks(1).await;
    link.push_found(p, "192.168.1.77:4001");
    ticks(2).await;
    assert_eq!(n.engine.inner.lock().lan_hints.len(), 1);
    assert!(n.t.call_count() >= 1);
    ticks(200).await;
    assert!(n.engine.inner.lock().lan_hints.is_empty(), "TTL 180 s");
    ticks(100).await;
    assert_eq!(late.load(Ordering::SeqCst), 0, "an expired hint is dialed");
}

#[tokio::test(start_paused = true)]
async fn lan_hint_never_persisted() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let before = n
        .engine
        .read_book(|b| b.get(&p).unwrap().known_addrs.clone());
    assert!(before.is_empty());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    link.push_found(p, "192.168.1.77:4001");
    ticks(5).await;
    assert!(n.t.call_count() >= 1, "the hint was dialed and failed");
    let after = n
        .engine
        .read_book(|b| b.get(&p).unwrap().known_addrs.clone());
    assert!(before == after, "a failed dial leaves no trace in the book");
    // успешное соединение: в книге только Contact, через note_contact
    n.t.set_script(move |_, _| {
        Action::Ok(
            FakeConn::lonely(p, sock("192.168.1.77:4001"), true),
            secs(0),
        )
    });
    link.push_found(p, "192.168.1.77:4001");
    let e = wait_event(&mut n.events, secs(120), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await;
    assert!(e.is_some());
    let book = n
        .engine
        .read_book(|b| b.get(&p).unwrap().known_addrs.clone());
    assert_eq!(book.len(), 1);
    assert_eq!(book[0].source, AddrSource::Contact);
    assert_eq!(book[0].addr, sock("192.168.1.77:4001"));
    assert!(!book[0].hint);
}

#[tokio::test(start_paused = true)]
async fn lan_hint_not_published() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let q = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let unix = n.clock.now_unix();
    let publishable = |n: &Node| {
        n.engine
            .inner
            .lock()
            .own
            .publishable(chervo_addr::PublishCtx::default(), unix)
    };
    let set_before = publishable(&n);
    let q_before = n
        .engine
        .read_book(|b| b.get(&q).unwrap().known_addrs.clone());
    let p_before = n
        .engine
        .read_book(|b| b.get(&p).unwrap().known_addrs.clone());
    let _ = drain(&mut n.events).await;
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    link.push_found(p, "192.168.1.77:4001");
    ticks(5).await;
    assert!(n.t.call_count() >= 1);
    assert_eq!(publishable(&n), set_before);
    assert!(
        n.engine
            .read_book(|b| b.get(&q).unwrap().known_addrs.clone())
            == q_before
    );
    assert!(
        n.engine
            .read_book(|b| b.get(&p).unwrap().known_addrs.clone())
            == p_before
    );
    // ни наблюдений, ни события смены своих адресов
    assert!(
        !drain(&mut n.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
    assert_eq!(n.engine.nat_view(), chervo_addr::NatView::Unknown);
    // подсказка не лежит ни в одной записи пары q
    assert!(
        n.engine
            .read_book(|b| b.get(&q).unwrap().known_addrs.clone())
            .iter()
            .all(|k| k.source != AddrSource::Lan)
    );
}

#[tokio::test(start_paused = true)]
async fn lan_connect_now_triggers() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    // без ссылки connect_now работает как прежде
    n.engine.connect_now(&p).unwrap();
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    assert_eq!(link.count(|c| *c == Call::Trigger), 1);
    n.engine.connect_now(&p).unwrap();
    assert_eq!(link.count(|c| *c == Call::Trigger), 2);
    assert_eq!(
        n.engine.connect_now(&PairId::generate().unwrap()),
        Err(ConnectError::UnknownPair)
    );
    assert_eq!(link.count(|c| *c == Call::Trigger), 2);
}

#[tokio::test(start_paused = true)]
async fn lan_peers_refreshed_on_book_change() {
    let mut pre = Pre::new();
    let a = pre.solo_friend(vec![]);
    let b = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    assert_eq!(sorted(link.last_peers()), sorted(vec![a, b]));
    n.engine.update_book(|bk, s| bk.block(s, &b)).unwrap();
    ticks(3).await;
    assert_eq!(link.last_peers(), vec![a]);
    assert_eq!(link.last_wanted(), vec![a]);
    // добавление друга
    let c = n
        .engine
        .update_book(|bk, s| add_solo_friend(bk, s, vec![]))
        .unwrap();
    ticks(3).await;
    assert_eq!(sorted(link.last_peers()), sorted(vec![a, c]));
    assert_eq!(link.count(|c| matches!(c, Call::Peers(_))), 3);
}

#[tokio::test(start_paused = true)]
async fn lan_wanted_follows_connections() {
    let mut pre = Pre::new();
    let a = pre.solo_friend(vec![]);
    let b = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    assert_eq!(link.last_wanted(), sorted(vec![a, b]));
    let conn = FakeConn::lonely(a, sock("192.168.1.60:4000"), false);
    n.t.push_incoming(conn.clone());
    ticks(3).await;
    assert_eq!(link.last_wanted(), vec![b]);
    // друг остаётся в наборе: ключи нужны и для живого (его слот не объявляется, но метка
    // принимается), поэтому набор друзей не менялся
    assert_eq!(sorted(link.last_peers()), sorted(vec![a, b]));
    chervo_transport::Connection::close(&conn);
    ticks(3).await;
    assert_eq!(link.last_wanted(), sorted(vec![a, b]));
}

#[tokio::test(start_paused = true)]
async fn lan_detach_stops() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    link.push_found(p, "192.168.1.77:4001");
    ticks(3).await;
    assert_eq!(n.engine.inner.lock().lan_hints.len(), 1);
    n.engine.detach_lan();
    assert_eq!(link.count(|c| *c == Call::Shutdown), 1);
    assert!(n.engine.inner.lock().lan_hints.is_empty());
    assert_eq!(n.engine.lan_status(), None);
    // найденное после отключения игнорируется, ссылку больше не трогают
    let takes = link.takes.load(Ordering::SeqCst);
    let calls = link.calls().len();
    link.push_found(p, "192.168.1.78:4001");
    let dials = n.t.call_count();
    ticks(10).await;
    assert_eq!(link.takes.load(Ordering::SeqCst), takes);
    assert_eq!(link.calls().len(), calls);
    assert_eq!(n.t.call_count(), dials);
    assert!(n.engine.inner.lock().lan_hints.is_empty());
    // повторное отключение безвредно, а подключиться снова можно
    n.engine.detach_lan();
    assert_eq!(link.count(|c| *c == Call::Shutdown), 1);
    let link2 = FakeLink::new();
    n.engine.attach_lan(link2.clone()).unwrap();
    assert_eq!(link2.calls().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn lan_attach_twice_internal() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let one = FakeLink::new();
    let two = FakeLink::new();
    n.engine.attach_lan(one.clone()).unwrap();
    assert_eq!(
        n.engine.attach_lan(two.clone()),
        Err(ConnectError::Internal)
    );
    assert!(two.calls().is_empty(), "the second link is never touched");
    assert_eq!(one.count(|c| *c == Call::Shutdown), 0);
}

#[tokio::test(start_paused = true)]
async fn lan_attach_after_shutdown() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    n.engine.shutdown();
    let link = FakeLink::new();
    assert_eq!(
        n.engine.attach_lan(link.clone()),
        Err(ConnectError::Shutdown)
    );
    assert!(link.calls().is_empty());
    assert_eq!(n.engine.lan_status(), None);
}

#[tokio::test(start_paused = true)]
async fn lan_engine_shutdown_detaches() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let link = FakeLink::new();
    n.engine.attach_lan(link.clone()).unwrap();
    n.engine.shutdown();
    assert_eq!(link.count(|c| *c == Call::Shutdown), 1);
    assert_eq!(n.engine.lan_status(), None);
    n.engine.shutdown();
    drop(n);
    assert_eq!(link.count(|c| *c == Call::Shutdown), 1);
}

#[test]
fn lan_texts_are_russian_and_fixed() {
    for t in [LAN_DISCOVERY_TEXT, LAN_FIRST_RUN_TEXT] {
        assert!(t.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)));
        assert!(!t.contains('{'));
        assert!(!t.chars().any(|c| c.is_ascii_digit()), "{t}");
    }
    let _ = Ipv4Addr::LOCALHOST;
    let _ = Duration::ZERO;
}
