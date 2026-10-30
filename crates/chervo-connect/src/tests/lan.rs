//! Подключение службы поиска в локальной сети (13в, L4): поддельная служба записывает вызовы
//! и отдаёт находки по команде теста. Сети нет, время приостановлено.

use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chervo_addr::{LanDiscovery, LanLocal, LanSighting, LanStatus};
use chervo_identity::{KxPeer, PairId, SecretStore, create};
use chervo_transport::TransportError;

use super::fake_mapper::wait_until;
use super::kit::*;
use crate::{ConnectConfig, ConnectError, EngineEvent};

/// Служба, которая только записывает вызовы.
pub struct FakeLan {
    pub locals: Mutex<Vec<Option<LanLocal>>>,
    pub peers: Mutex<Vec<Vec<PairId>>>,
    queue: Mutex<Vec<LanSighting>>,
    status: Mutex<LanStatus>,
    pub shutdowns: AtomicUsize,
    pub takes: AtomicUsize,
}

impl FakeLan {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            locals: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            queue: Mutex::new(Vec::new()),
            status: Mutex::new(LanStatus::Listening),
            shutdowns: AtomicUsize::new(0),
            takes: AtomicUsize::new(0),
        })
    }

    pub fn push(&self, pair: PairId, a: &str) {
        let addr: SocketAddrV4 = a.parse().unwrap();
        self.queue.lock().unwrap().push(LanSighting { pair, addr });
    }

    pub fn set_status(&self, s: LanStatus) {
        *self.status.lock().unwrap() = s;
    }

    pub fn last_local(&self) -> Option<LanLocal> {
        *self.locals.lock().unwrap().last().unwrap()
    }

    pub fn local_calls(&self) -> usize {
        self.locals.lock().unwrap().len()
    }

    pub fn last_peers(&self) -> Vec<PairId> {
        let mut v = self
            .peers
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default();
        v.sort_by_key(|p| *p.as_bytes());
        v
    }

    pub fn call_total(&self) -> usize {
        self.locals.lock().unwrap().len()
            + self.peers.lock().unwrap().len()
            + self.takes.load(Ordering::SeqCst)
    }
}

impl LanDiscovery for FakeLan {
    fn set_local(&self, local: Option<LanLocal>) {
        self.locals.lock().unwrap().push(local);
    }

    fn set_peers(&self, peers: Vec<KxPeer>) {
        self.peers
            .lock()
            .unwrap()
            .push(peers.iter().map(KxPeer::pair).collect());
    }

    fn take_sightings(&self) -> Vec<LanSighting> {
        self.takes.fetch_add(1, Ordering::SeqCst);
        std::mem::take(&mut *self.queue.lock().unwrap())
    }

    fn status(&self) -> LanStatus {
        *self.status.lock().unwrap()
    }

    fn shutdown(&self) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

fn sorted(mut v: Vec<PairId>) -> Vec<PairId> {
    v.sort_by_key(|p| *p.as_bytes());
    v
}

/// Узел с одним другом и подключённой поддельной службой.
fn node_with_lan() -> (Node, PairId, Arc<FakeLan>) {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let lan = FakeLan::new();
    n.engine.attach_lan(lan.clone()).unwrap();
    (n, x, lan)
}

fn lan_events(evs: &[EngineEvent]) -> Vec<LanStatus> {
    evs.iter()
        .filter_map(|e| match e {
            EngineEvent::LanStatusChanged { status } => Some(*status),
            _ => None,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn lan_not_called_without_attach() {
    let mut pre = Pre::new();
    let _x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let lan = FakeLan::new();
    // не подключена: ни вызовов, ни событий, ни состояния
    tokio::time::sleep(secs(30)).await;
    n.probe.set_v4(Some("10.0.0.2"));
    tokio::time::sleep(secs(30)).await;
    n.engine.update_book(|_, _| Ok(())).unwrap();
    assert_eq!(lan.call_total(), 0);
    assert_eq!(n.engine.lan_status(), None);
    assert!(lan_events(&drain(&mut n.events).await).is_empty());
}

#[tokio::test(start_paused = true)]
async fn lan_attach_twice_rejected() {
    let (n, _x, lan) = node_with_lan();
    let other = FakeLan::new();
    assert_eq!(
        n.engine.attach_lan(other.clone()),
        Err(ConnectError::Internal)
    );
    assert_eq!(other.call_total(), 0, "вторая служба не получила вызовов");
    assert_eq!(n.engine.lan_status(), Some(LanStatus::Listening));
    lan.set_status(LanStatus::Announcing);
    assert_eq!(n.engine.lan_status(), Some(LanStatus::Announcing));
    n.engine.shutdown();
    assert_eq!(
        n.engine.attach_lan(FakeLan::new()),
        Err(ConnectError::Shutdown)
    );
}

#[tokio::test(start_paused = true)]
async fn lan_local_any_class() {
    // класс адреса не проверяется: под VPN маршрут по умолчанию идёт в туннель (198.18.0.1,
    // 100.64.0.9, 172.18.0.1), частные интерфейсы находит сама служба
    for v4 in [
        "7.7.7.7",
        "100.64.0.9",
        "198.18.0.1",
        "172.18.0.1",
        "169.254.3.4",
        "192.168.1.5",
    ] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            FakeTransport::new(),
            FakeProbe::new(Some(v4)),
        );
        let lan = FakeLan::new();
        n.engine.attach_lan(lan.clone()).unwrap();
        tokio::time::sleep(secs(30)).await;
        let l = lan.last_local().unwrap_or_else(|| panic!("{v4}: None"));
        assert_eq!(l.own, v4.parse::<std::net::Ipv4Addr>().unwrap(), "{v4}");
        assert_eq!(l.listen_port, 4000);
    }
    // нет маршрутного IPv4 (петля и неуказанный пробой отбрасывает, здесь ещё и защита): `None`
    for v4 in [None, Some("127.0.0.1"), Some("0.0.0.0")] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            FakeTransport::new(),
            FakeProbe::new(v4),
        );
        let lan = FakeLan::new();
        n.engine.attach_lan(lan.clone()).unwrap();
        tokio::time::sleep(secs(30)).await;
        assert_eq!(lan.last_local(), None, "{v4:?}");
    }
    // маршрут есть, но порта прослушивания IPv4 нет: тоже `None`
    for local in [vec![addr("0.0.0.0:0")], vec![addr("[::]:4000")], vec![]] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let t = FakeTransport::new();
        t.set_local(local.clone());
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            t,
            FakeProbe::new(Some("192.168.1.5")),
        );
        let lan = FakeLan::new();
        n.engine.attach_lan(lan.clone()).unwrap();
        tokio::time::sleep(secs(30)).await;
        assert_eq!(lan.last_local(), None, "{local:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn lan_local_on_own_change() {
    let (n, _x, lan) = node_with_lan();
    assert_eq!(lan.local_calls(), 1);
    // без смены адреса новых вызовов нет
    tokio::time::sleep(secs(10)).await;
    assert_eq!(lan.local_calls(), 1);
    // адрес туннеля по умолчанию: службе уходит он (любой класс), фильтрует служба
    n.probe.set_v4(Some("7.7.7.7"));
    tokio::time::sleep(secs(5)).await;
    let l = lan.last_local().unwrap();
    assert_eq!(l.own, "7.7.7.7".parse::<std::net::Ipv4Addr>().unwrap());
    // другой частный адрес: службе новый адрес
    n.probe.set_v4(Some("10.0.0.2"));
    tokio::time::sleep(secs(5)).await;
    let l = lan.last_local().unwrap();
    assert_eq!(l.own, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(l.listen_port, 4000);
    // маршрута нет вовсе: `None`
    n.probe.set_v4(None);
    tokio::time::sleep(secs(5)).await;
    assert_eq!(lan.last_local(), None);
}

/// Гостевая пара с настоящими ключами (в наборе транспорта она есть, у службы быть не должна).
fn guest_peer(guest: PairId) -> KxPeer {
    let a = create(&MemStore::default(), &guest).unwrap();
    let b = create(&MemStore::default(), &guest).unwrap();
    let theirs = b.kx_public();
    KxPeer::new(guest, a.into_kx(), theirs)
}

#[tokio::test(start_paused = true)]
async fn lan_peers_active_only_no_guests() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let y = pre.solo_friend(vec![inv("6.6.6.6:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let lan = FakeLan::new();
    n.engine.attach_lan(lan.clone()).unwrap();
    assert_eq!(lan.last_peers(), sorted(vec![x, y]));

    // гость входит в набор транспорта, но службе не передаётся
    let g = PairId::from_bytes([0x77; 16]);
    let peer = guest_peer(g);
    n.engine
        .add_guest(
            g,
            vec![addr("8.8.8.8:1")],
            Box::new(move || Some(peer.clone())),
        )
        .unwrap();
    assert!(n.t.last_peers().contains(&g), "гость в наборе транспорта");
    assert_eq!(lan.last_peers(), sorted(vec![x, y]));

    // заблокированный друг уходит
    n.engine.update_book(|b, s| b.block(s, &y)).unwrap();
    assert_eq!(lan.last_peers(), vec![x]);
}

#[tokio::test(start_paused = true)]
async fn lan_peers_after_block_and_remove() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let y = pre.solo_friend(vec![inv("6.6.6.6:4000")]);
    let z = pre.solo_friend(vec![inv("7.7.7.7:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let lan = FakeLan::new();
    n.engine.attach_lan(lan.clone()).unwrap();

    n.engine.update_book(|b, s| b.block(s, &x)).unwrap();
    assert_eq!(lan.last_peers(), sorted(vec![y, z]));
    n.engine.update_book(|b, s| b.unblock(s, &x)).unwrap();
    assert_eq!(lan.last_peers(), sorted(vec![x, y, z]));
    n.engine
        .update_book(|b, s| b.remove(s, &z, BASE_UNIX).map(|_| ()))
        .unwrap();
    assert_eq!(lan.last_peers(), sorted(vec![x, y]));

    // хранилище ключей не отвечает: блокировка всё равно сразу убирает друга и у службы
    n.store.set_fail_reads(true);
    let res = n.engine.update_book(|b, s| b.block(s, &x));
    assert!(matches!(res.unwrap_err(), ConnectError::Friends(_)));
    assert_eq!(lan.last_peers(), vec![y]);
}

/// Узел для проверки набора по находке: книга с адресом из приглашения; наборы не удаются сразу.
fn dial_node() -> (Node, PairId, Arc<FakeLan>) {
    let (n, x, lan) = node_with_lan();
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    (n, x, lan)
}

fn dials_with(n: &Node, pair: &PairId, lan_addr: &str) -> Vec<Vec<std::net::SocketAddr>> {
    let a = addr(lan_addr);
    n.t.calls_for(pair)
        .into_iter()
        .filter(|c| c.contains(&a))
        .collect()
}

#[tokio::test(start_paused = true)]
async fn lan_sighting_dials_first_and_strict() {
    let (n, x, lan) = dial_node();
    tokio::time::sleep(secs(5)).await;
    let before = n.t.calls_for(&x).len();
    assert!(before >= 1, "обычный набор по адресу книги идёт");
    lan.push(x, "192.168.1.20:4001");
    tokio::time::sleep(secs(3)).await;
    let first = dials_with(&n, &x, "192.168.1.20:4001");
    assert_eq!(first.len(), 1, "набор по находке на ближайшем такте");
    assert_eq!(
        first[0][0],
        addr("192.168.1.20:4001"),
        "адрес из маяка первый"
    );

    // та же находка ещё раз: на этот IP не чаще раза в 32 с в любом режиме
    lan.push(x, "192.168.1.20:4001");
    tokio::time::sleep(secs(25)).await;
    assert_eq!(dials_with(&n, &x, "192.168.1.20:4001").len(), 1);
    // другой порт того же IP тоже не набирается раньше срока
    lan.push(x, "192.168.1.20:4002");
    tokio::time::sleep(secs(2)).await;
    assert!(dials_with(&n, &x, "192.168.1.20:4002").is_empty());
    // срок прошёл (находка свежая): набор возможен снова
    lan.push(x, "192.168.1.20:4001");
    tokio::time::sleep(secs(40)).await;
    assert!(dials_with(&n, &x, "192.168.1.20:4001").len() >= 2);
}

/// Повтор находки с того же IP каждые 5 с (запись маяка, которую гонят по кругу): наборов на этот
/// IP не чаще раза в 32 с, и они не пропадают совсем (проверка не пустая). Свойство, которое
/// стенд LAN5 проверяет по сети; здесь без сети и без разбора пакетов.
#[tokio::test(start_paused = true)]
async fn lan_sighting_replay_every_5s_one_dial_per_32s() {
    let (n, x, lan) = dial_node();
    tokio::time::sleep(secs(5)).await;
    let mut seen = 0usize;
    let mut at: Vec<u64> = Vec::new();
    for s in 0..140u64 {
        if s % 5 == 0 {
            lan.push(x, "192.168.1.20:4001");
        }
        tokio::time::sleep(secs(1)).await;
        let c = dials_with(&n, &x, "192.168.1.20:4001").len();
        if c > seen {
            at.push(s);
            seen = c;
        }
    }
    assert!(
        at.len() >= 3,
        "наборы по находке идут, а не замерли: {at:?}"
    );
    for w in at.windows(2) {
        // шаг опроса 1 с: настоящий промежуток не меньше 32 с, видимый не меньше 31
        assert!(w[1] - w[0] >= 31, "набор на тот же IP раньше срока: {at:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn lan_sighting_ignored_live_inactive_keyproblem() {
    let mut pre = Pre::new();
    let live = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let blocked = pre.solo_friend(vec![inv("5.6.7.9:4000")]);
    let broken = pre.solo_friend(vec![inv("5.6.7.10:4000")]);
    pre.store.delete(&broken).unwrap();
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let lan = FakeLan::new();
    n.engine.attach_lan(lan.clone()).unwrap();
    n.t.push_incoming(FakeConn::lonely(live, addr("5.6.7.8:4000"), false));
    n.engine.update_book(|b, s| b.block(s, &blocked)).unwrap();
    let guest = PairId::from_bytes([0x55; 16]);
    let peer = guest_peer(guest);
    n.engine
        .add_guest(
            guest,
            vec![addr("8.8.8.8:1")],
            Box::new(move || Some(peer.clone())),
        )
        .unwrap();
    tokio::time::sleep(secs(3)).await;
    assert!(n.engine.connection(&live).is_some());

    for (i, p) in [live, blocked, broken, guest, PairId::from_bytes([0x11; 16])]
        .into_iter()
        .enumerate()
    {
        lan.push(p, &format!("192.168.1.{}:4001", 30 + i));
    }
    tokio::time::sleep(secs(5)).await;
    assert!(
        n.engine.inner.lock().lan_seen.is_empty(),
        "ни одна находка не принята"
    );
    for i in 0..5 {
        assert!(
            n.t.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(_, a)| !a.contains(&addr(&format!("192.168.1.{}:4001", 30 + i)))),
            "набор по ненужной находке {i}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn lan_sighting_no_fast_window_no_reset() {
    let (mut n, x, lan) = dial_node();
    // быстрое окно запуска кончилось, наборы идут по ограничителю
    tokio::time::sleep(secs(200)).await;
    let _ = drain(&mut n.events).await;
    let book_addr = addr("5.6.7.8:4000");
    let now = tokio::time::Instant::now();
    let reknocks = n.t.reknock_count();
    let blocked_before = !n.engine.inner.lock().limiter.allow(book_addr, true, now);
    lan.push(x, "192.168.1.20:4001");
    tokio::time::sleep(secs(2)).await;
    {
        let st = n.engine.inner.lock();
        assert!(st.lan_seen.contains_key(&x), "находка принята");
        assert!(st.fast_global_until.is_none(), "быстрого окна нет");
        assert!(st.friends.get(&x).is_none_or(|r| r.fast_until.is_none()));
        assert!(!st.friends.get(&x).is_some_and(|r| r.want_addr_info));
    }
    assert_eq!(n.t.reknock_count(), reknocks, "повторного стука нет");
    let evs = drain(&mut n.events).await;
    assert!(!evs.contains(&EngineEvent::OwnAddrsChanged));
    // ограничитель не сброшен: адрес книги блокирован так же, как до находки
    let now = tokio::time::Instant::now();
    let after = !n.engine.inner.lock().limiter.allow(book_addr, true, now);
    assert_eq!(blocked_before, after);
}

#[tokio::test(start_paused = true)]
async fn lan_seen_expires() {
    let (n, x, lan) = node_with_lan();
    // набор висит (не удаётся и не кончается): запись живёт по сроку, а не по соединению
    lan.push(x, "192.168.1.20:4001");
    tokio::time::sleep(secs(3)).await;
    assert!(n.engine.inner.lock().lan_seen.contains_key(&x));
    tokio::time::sleep(secs(100)).await;
    assert!(
        n.engine.inner.lock().lan_seen.contains_key(&x),
        "срок 120 с"
    );
    tokio::time::sleep(secs(30)).await;
    assert!(n.engine.inner.lock().lan_seen.is_empty(), "срок вышел");
}

#[tokio::test(start_paused = true)]
async fn lan_sighting_not_persisted() {
    let (n, x, lan) = node_with_lan();
    let lan_addr = addr("192.168.1.20:4001");
    let book_before = n
        .engine
        .read_book(|b| b.get(&x).unwrap().known_addrs.clone());
    // набор по адресу из маяка удаётся
    let conn = FakeConn::lonely(x, lan_addr, true);
    let c = conn.clone();
    n.t.set_script(move |_, addrs| {
        if addrs.contains(&addr("192.168.1.20:4001")) {
            Action::Ok(c.clone(), secs(0))
        } else {
            Action::Fail(TransportError::TimedOut, secs(0))
        }
    });
    lan.push(x, "192.168.1.20:4001");
    // пока соединения нет, книга не меняется
    tokio::time::sleep(secs(1)).await;
    let during = n
        .engine
        .read_book(|b| b.get(&x).unwrap().known_addrs.clone());
    if n.engine.connection(&x).is_none() {
        assert!(during == book_before, "книга без изменений до соединения");
    }
    wait_until(|| n.engine.connection(&x).is_some()).await;
    // после соединения одна запись `Contact` с этим адресом
    let after = n
        .engine
        .read_book(|b| b.get(&x).unwrap().known_addrs.clone());
    let contacts: Vec<_> = after
        .iter()
        .filter(|k| k.addr == lan_addr && k.source == chervo_addr::AddrSource::Contact)
        .collect();
    assert_eq!(contacts.len(), 1);
    assert_eq!(after.len(), book_before.len() + 1);
    assert!(n.engine.inner.lock().lan_seen.is_empty(), "запись снята");
}

#[tokio::test(start_paused = true)]
async fn lan_status_event_once() {
    let (mut n, _x, lan) = node_with_lan();
    tokio::time::sleep(secs(5)).await;
    assert!(
        lan_events(&drain(&mut n.events).await).is_empty(),
        "состояние на момент подключения событием не объявляется"
    );
    lan.set_status(LanStatus::Announcing);
    tokio::time::sleep(secs(5)).await;
    assert_eq!(
        lan_events(&drain(&mut n.events).await),
        vec![LanStatus::Announcing]
    );
    tokio::time::sleep(secs(5)).await;
    assert!(lan_events(&drain(&mut n.events).await).is_empty());
    lan.set_status(LanStatus::PortBusy);
    tokio::time::sleep(secs(2)).await;
    lan.set_status(LanStatus::Listening);
    tokio::time::sleep(secs(2)).await;
    assert_eq!(
        lan_events(&drain(&mut n.events).await),
        vec![LanStatus::PortBusy, LanStatus::Listening]
    );
}

#[tokio::test(start_paused = true)]
async fn lan_shutdown_signalled() {
    let (n, _x, lan) = node_with_lan();
    assert_eq!(lan.shutdowns.load(Ordering::SeqCst), 0);
    n.engine.shutdown();
    assert!(lan.shutdowns.load(Ordering::SeqCst) >= 1);
}

#[tokio::test(start_paused = true)]
async fn lan_local_dual_listen() {
    // двойное гнездо: `local_addrs` = IPv4 и IPv6; порт для маяка берётся из записи IPv4
    for local in [
        vec![addr("0.0.0.0:4321"), addr("[::]:4321")],
        vec![addr("[::]:4321"), addr("0.0.0.0:4321")],
    ] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let t = FakeTransport::new();
        t.set_local(local.clone());
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            t,
            FakeProbe::new(Some("192.168.1.5")),
        );
        let lan = FakeLan::new();
        n.engine.attach_lan(lan.clone()).unwrap();
        tokio::time::sleep(secs(30)).await;
        let l = lan
            .last_local()
            .unwrap_or_else(|| panic!("{local:?}: None"));
        assert_eq!(l.own, "192.168.1.5".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(l.listen_port, 4321, "{local:?}");
    }
}
