#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Сквозные сетевые тесты слоя соединения (C4): настоящие `QuinnTransport` на 127.0.0.1,
//! приглашение целиком, одновременный набор, перезапуск, блокировка, смена маршрута.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{AddrSource, KnownAddr, RouteSources};
use chervo_connect::{
    AllowSet, Clock, ConnectConfig, Engine, EngineEvent, EngineEvents, InviteAddrs, InviteOutcome,
    RouteProbe, SystemClock,
};
use chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_identity::{IdentityError, KxPeer, ListKeyStore, PairId, PairKey, SecretStore};
use chervo_token::addr_flow::exchange_addr_info;
use chervo_token::{Token, decode};
use chervo_transport::{Connection, PeerAddr, PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use zeroize::Zeroizing;

// ------------------------------------------------------------------- помощники

#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl MemStore {
    fn pair_count(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .list
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = None;
        Ok(())
    }
}

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Arc<Self> {
        let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("chervo-engine-net-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Arc::new(Self(p))
    }

    fn file(&self) -> PathBuf {
        self.0.join("friends.chfl")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Probe(Mutex<RouteSources>);

impl Probe {
    fn new() -> Arc<Self> {
        let p = Arc::new(Self(Mutex::new(RouteSources::default())));
        p.set_v4("127.0.0.1");
        p
    }

    fn set_v4(&self, ip: &str) {
        self.0.lock().unwrap().v4 = Some(ip.parse::<Ipv4Addr>().unwrap());
    }
}

impl RouteProbe for Probe {
    fn probe(&self) -> RouteSources {
        *self.0.lock().unwrap()
    }

    fn source_for(&self, _target: SocketAddr) -> Option<std::net::IpAddr> {
        None
    }
}

fn quinn_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

fn engine_cfg() -> ConnectConfig {
    ConnectConfig {
        tick: Duration::from_millis(100),
        probe_interval: Duration::from_millis(200),
        fast_period: Duration::from_millis(300),
        per_ip_dials: 1000,
        addr_info_out_interval: Duration::from_secs(1),
        ..ConnectConfig::default()
    }
}

/// Транспорт на 127.0.0.1 (порт 0 или заданный) до запуска движка.
struct Bound {
    t: Arc<QuinnTransport>,
    allow: Arc<AllowSet>,
    addr: SocketAddr,
}

fn bind(port: u16) -> Bound {
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let t = Arc::new(
        QuinnTransport::bind(
            SocketAddr::from(([127, 0, 0, 1], port)),
            quinn_cfg(),
            filter,
        )
        .unwrap(),
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], t.local_addrs()[0].port()));
    Bound { t, allow, addr }
}

type Eng = Engine<QuinnTransport, MemStore>;

struct Node {
    engine: Eng,
    events: EngineEvents,
    t: Arc<QuinnTransport>,
    store: Arc<MemStore>,
    probe: Arc<Probe>,
    addr: SocketAddr,
    dir: Arc<TestDir>,
}

impl Node {
    fn new() -> Node {
        Self::start(bind(0), Arc::new(MemStore::default()), TestDir::new(), None)
    }

    /// Запуск движка; `book`: готовая книга (иначе открывается файл каталога).
    fn start(b: Bound, store: Arc<MemStore>, dir: Arc<TestDir>, book: Option<FriendBook>) -> Node {
        Self::start_cfg(b, store, dir, book, engine_cfg())
    }

    fn start_cfg(
        b: Bound,
        store: Arc<MemStore>,
        dir: Arc<TestDir>,
        book: Option<FriendBook>,
        cfg: ConnectConfig,
    ) -> Node {
        let book = book.unwrap_or_else(|| FriendBook::open(&dir.file(), &*store).unwrap());
        let probe = Probe::new();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let p: Arc<dyn RouteProbe> = probe.clone();
        let (engine, events) =
            Engine::start(b.t.clone(), b.allow, book, store.clone(), clock, p, cfg).unwrap();
        Node {
            engine,
            events,
            t: b.t,
            store,
            probe,
            addr: b.addr,
            dir,
        }
    }
}

/// Зеркальная дружба `x` и `y` на готовых книгах: пары у каждой стороны и адреса друг друга.
struct Mirror {
    pair_x: PairId,
    pair_y: PairId,
}

fn known(addr: SocketAddr) -> KnownAddr {
    KnownAddr {
        addr,
        source: AddrSource::Invite,
        last_seen_unix: SystemClock::new().now_unix(),
        short_lived: false,
        hint: false,
    }
}

struct Pre {
    store: Arc<MemStore>,
    dir: Arc<TestDir>,
    book: FriendBook,
}

fn pre() -> Pre {
    let store = Arc::new(MemStore::default());
    let dir = TestDir::new();
    let book = FriendBook::open(&dir.file(), &*store).unwrap();
    Pre { store, dir, book }
}

fn new_friend(theirs: &PairKey, ours: &PairKey, addr: Option<SocketAddr>) -> NewFriend {
    NewFriend {
        name: "friend".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: addr.map(known).into_iter().collect(),
        now_unix: SystemClock::new().now_unix(),
    }
}

/// Дружба между `x` и `y`: `addr_of_y` знает `x`, `addr_of_x` знает `y` (`None`: не знает).
fn befriend(
    x: &mut Pre,
    y: &mut Pre,
    x_knows_y: Option<SocketAddr>,
    y_knows_x: Option<SocketAddr>,
) -> Mirror {
    let (px, kx) = x
        .book
        .begin_pair(&*x.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (py, ky) = y
        .book
        .begin_pair(&*y.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    x.book
        .finish_pair(&*x.store, &px, new_friend(&ky, &kx, x_knows_y))
        .unwrap();
    y.book
        .finish_pair(&*y.store, &py, new_friend(&kx, &ky, y_knows_x))
        .unwrap();
    Mirror {
        pair_x: px,
        pair_y: py,
    }
}

fn run(p: Pre, b: Bound) -> Node {
    Node::start(b, p.store, p.dir, Some(p.book))
}

async fn wait_for(
    events: &mut EngineEvents,
    secs: u64,
    f: impl Fn(&EngineEvent) -> bool,
) -> Option<EngineEvent> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, events.recv()).await {
            Ok(Some(e)) if f(&e) => return Some(e),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

fn is_connected(e: &EngineEvent) -> bool {
    matches!(e, EngineEvent::Connected { .. })
}

fn is_sas(e: &EngineEvent) -> bool {
    matches!(e, EngineEvent::SasReady { .. })
}

fn is_finished(e: &EngineEvent) -> bool {
    matches!(e, EngineEvent::InviteFinished { .. })
}

fn outcome(e: Option<EngineEvent>) -> Option<InviteOutcome> {
    match e {
        Some(EngineEvent::InviteFinished { outcome, .. }) => Some(outcome),
        _ => None,
    }
}

/// Круг по живому соединению друга: ADDR_INFO по настоящему потоку (диспетчер движка отвечает).
async fn round_trip(engine: &Eng, pair: &PairId) -> bool {
    // сразу после одновременного набора запись может указывать на проигравшее (уже
    // закрытое) соединение: оно вот-вот заменится выигравшим, поэтому берём запись заново
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(conn) = engine.connection(pair) {
            let r = tokio::time::timeout(
                Duration::from_secs(5),
                exchange_addr_info(&conn, pair, None),
            )
            .await;
            if matches!(r, Ok(Ok(_))) {
                return true;
            }
        }
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Ждёт живое соединение с другом (опрос: события `Connected` могли накопиться раньше).
async fn wait_conn(engine: &Eng, pair: &PairId, secs: u64) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        if engine.connection(pair).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Ждёт `Connected` у обоих.
async fn both_connected(x: &mut Node, y: &mut Node, secs: u64) {
    assert!(
        wait_for(&mut x.events, secs, is_connected).await.is_some(),
        "first side not connected"
    );
    assert!(
        wait_for(&mut y.events, secs, is_connected).await.is_some(),
        "second side not connected"
    );
}

/// Приглашение A -> B до `Added` на обеих сторонах. Возвращает пары (у A, у B).
async fn invite(a: &mut Node, b: &mut Node, a_ok: bool, b_ok: bool) -> (PairId, PairId) {
    let (pa, text) = a
        .engine
        .create_invite(300, InviteAddrs::Manual(vec![a.addr]))
        .unwrap();
    let pb = b.engine.accept_invite(&text).unwrap();
    let Some(EngineEvent::SasReady { sas: sa, .. }) = wait_for(&mut a.events, 15, is_sas).await
    else {
        panic!("A: no SAS")
    };
    let Some(EngineEvent::SasReady { sas: sb, .. }) = wait_for(&mut b.events, 15, is_sas).await
    else {
        panic!("B: no SAS")
    };
    assert_eq!(sa.digits(), sb.digits());
    assert_eq!(sa.digits().chars().filter(char::is_ascii_digit).count(), 8);
    a.engine.confirm_sas(&pa, a_ok, "Борис").unwrap();
    b.engine.confirm_sas(&pb, b_ok, "Анна").unwrap();
    (pa, pb)
}

// ------------------------------------------------------------------------ тесты

#[tokio::test]
async fn engine_invite_then_friend_connect() {
    let (mut a, mut b) = (Node::new(), Node::new());
    let (pa, pb) = invite(&mut a, &mut b, true, true).await;
    assert_eq!(
        outcome(wait_for(&mut a.events, 15, is_finished).await),
        Some(InviteOutcome::Added)
    );
    assert_eq!(
        outcome(wait_for(&mut b.events, 15, is_finished).await),
        Some(InviteOutcome::Added)
    );
    // гость больше не принимается и не набирается: оба узла добавили друга и сняли гостя
    both_connected(&mut a, &mut b, 15).await;
    assert!(round_trip(&a.engine, &pa).await);
    assert!(round_trip(&b.engine, &pb).await);
    // книги: друг один, pending нет, один ключ пары
    for (n, p) in [(&a, pa), (&b, pb)] {
        assert!(n.engine.read_book(|bk| bk.get(&p).is_some()));
        assert_eq!(n.engine.read_book(|bk| bk.friends().len()), 1);
        assert_eq!(n.engine.read_book(|bk| bk.pending().len()), 0);
        assert_eq!(n.store.pair_count(), 1);
    }
    // у A единственный адрес B: Contact с гостевого соединения
    let known_a = a
        .engine
        .read_book(|bk| bk.get(&pa).unwrap().known_addrs.clone());
    assert!(known_a.iter().any(|k| k.source == AddrSource::Contact));
    let known_b = b
        .engine
        .read_book(|bk| bk.get(&pb).unwrap().known_addrs.clone());
    assert!(
        known_b
            .iter()
            .any(|k| k.source == AddrSource::Invite && k.addr == a.addr)
    );
    // и спустя паузу соединения не рвались (гостевое закрыто, дружеское живо)
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(round_trip(&a.engine, &pa).await);
}

#[tokio::test]
async fn engine_invite_declined_nothing_saved() {
    for (a_ok, b_ok) in [(true, false), (false, true), (false, false)] {
        let (mut a, mut b) = (Node::new(), Node::new());
        let _ = invite(&mut a, &mut b, a_ok, b_ok).await;
        for n in [&mut a, &mut b] {
            assert_eq!(
                outcome(wait_for(&mut n.events, 15, is_finished).await),
                Some(InviteOutcome::Declined),
                "{a_ok} {b_ok}"
            );
            assert_eq!(n.engine.read_book(|bk| bk.friends().len()), 0);
            assert_eq!(n.engine.read_book(|bk| bk.pending().len()), 0);
            assert_eq!(n.store.pair_count(), 0, "key left behind");
        }
        // и на диске ничего нет
        assert!(
            FriendBook::open(&a.dir.file(), &*a.store)
                .unwrap()
                .friends()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn engine_simultaneous_both_dial_one_conn() {
    for _ in 0..3 {
        let (mut x, mut y) = (pre(), pre());
        let (bx, by) = (bind(0), bind(0));
        let m = befriend(&mut x, &mut y, Some(by.addr), Some(bx.addr));
        let (mut nx, mut ny) = (run(x, bx), run(y, by));
        both_connected(&mut nx, &mut ny, 15).await;
        // после улёгшихся наборов у каждой стороны одно живое соединение, оно работает
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(round_trip(&nx.engine, &m.pair_x).await);
        assert!(round_trip(&ny.engine, &m.pair_y).await);
        let id_x = nx.engine.connection(&m.pair_x).unwrap().conn_id();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            nx.engine.connection(&m.pair_x).unwrap().conn_id(),
            id_x,
            "connection replaced after settling"
        );
    }
}

#[tokio::test]
async fn engine_reconnect_after_peer_restart() {
    let (mut x, mut y) = (pre(), pre());
    let (bx, by) = (bind(0), bind(0));
    let (x_addr, y_addr) = (bx.addr, by.addr);
    let m = befriend(&mut x, &mut y, Some(y_addr), Some(x_addr));
    let mut nx = run(x, bx);
    let mut ny = run(y, by);
    both_connected(&mut nx, &mut ny, 15).await;
    // B (y) перезапускается на том же порту с теми же ключами и книгой с диска
    let (store, dir) = (ny.store.clone(), ny.dir.clone());
    ny.engine.shutdown();
    ny.t.shutdown();
    drop(ny);
    assert!(
        wait_for(&mut nx.events, 15, |e| matches!(
            e,
            EngineEvent::Disconnected { .. }
        ))
        .await
        .is_some(),
        "A did not notice the restart"
    );
    let mut rebound = None;
    for _ in 0..50 {
        let allow = AllowSet::new();
        let filter: Arc<dyn PeerFilter> = allow.clone();
        match QuinnTransport::bind(y_addr, quinn_cfg(), filter) {
            Ok(t) => {
                rebound = Some(Bound {
                    t: Arc::new(t),
                    allow,
                    addr: y_addr,
                });
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut ny = Node::start(rebound.expect("port not freed"), store, dir, None);
    nx.engine.connect_now(&m.pair_x).unwrap();
    assert!(
        wait_for(&mut nx.events, 15, is_connected).await.is_some(),
        "A not reconnected"
    );
    assert!(
        wait_for(&mut ny.events, 15, is_connected).await.is_some(),
        "B not reconnected"
    );
    assert!(round_trip(&nx.engine, &m.pair_x).await);
}

#[tokio::test]
async fn engine_block_closes_and_stops_dialing() {
    let (mut x, mut y) = (pre(), pre());
    let (bx, by) = (bind(0), bind(0));
    let m = befriend(&mut x, &mut y, Some(by.addr), Some(bx.addr));
    let (mut nx, mut ny) = (run(x, bx), run(y, by));
    both_connected(&mut nx, &mut ny, 15).await;
    nx.engine
        .update_book(|bk, st| bk.block(st, &m.pair_x))
        .unwrap();
    assert!(nx.engine.connection(&m.pair_x).is_none());
    assert!(
        wait_for(&mut ny.events, 15, |e| matches!(
            e,
            EngineEvent::Disconnected { .. }
        ))
        .await
        .is_some(),
        "friend still connected after block"
    );
    // заблокированный друг не набирается и не принимается; вторая сторона не дозванивается
    assert!(nx.engine.connect_now(&m.pair_x).is_err());
    // исходящий набор из быстрого окна мог снять снимок пар до блокировки: он кончается не
    // позже `auth_deadline`, поэтому снимок статистики берётся после него (+1 с), а не сразу
    tokio::time::sleep(quinn_cfg().auth_deadline + Duration::from_secs(1)).await;
    for n in [&mut nx, &mut ny] {
        while wait_for(&mut n.events, 0, |_| true).await.is_some() {}
    }
    let stats = nx.t.stats();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(nx.engine.connection(&m.pair_x).is_none());
    assert!(ny.engine.connection(&m.pair_y).is_none());
    // допуск: ни одного `Connected` ни у одной стороны, соединений нет
    assert!(
        wait_for(&mut nx.events, 0, is_connected).await.is_none(),
        "blocked friend connected (A)"
    );
    assert!(
        wait_for(&mut ny.events, 0, is_connected).await.is_none(),
        "blocked friend connected (B)"
    );
    // `auth_ok` растёт только при допуске реестром
    assert_eq!(
        nx.t.stats().auth_ok,
        stats.auth_ok,
        "blocked friend authenticated"
    );
    // разблокировка возвращает связь
    nx.engine
        .update_book(|bk, st| bk.unblock(st, &m.pair_x))
        .unwrap();
    nx.engine.connect_now(&m.pair_x).unwrap();
    ny.engine.connect_now(&m.pair_y).unwrap();
    assert!(
        wait_conn(&nx.engine, &m.pair_x, 20).await,
        "not reconnected after unblock"
    );
    assert!(round_trip(&nx.engine, &m.pair_x).await);
}

#[tokio::test]
async fn engine_three_no_cross_addresses() {
    // A дружит с B и C; B и C друг друга не знают
    let (mut a, mut b, mut c) = (pre(), pre(), pre());
    let (ba, bb, bc) = (bind(0), bind(0), bind(0));
    let (a_addr, b_addr, c_addr) = (ba.addr, bb.addr, bc.addr);
    let mab = befriend(&mut a, &mut b, Some(b_addr), Some(a_addr));
    let mac = befriend(&mut a, &mut c, Some(c_addr), Some(a_addr));
    let (mut na, mut nb, mut nc) = (run(a, ba), run(b, bb), run(c, bc));
    for _ in 0..2 {
        assert!(wait_for(&mut na.events, 15, is_connected).await.is_some());
    }
    assert!(wait_for(&mut nb.events, 15, is_connected).await.is_some());
    assert!(wait_for(&mut nc.events, 15, is_connected).await.is_some());
    // обмены ADDR_INFO в обе стороны
    assert!(round_trip(&na.engine, &mab.pair_x).await);
    assert!(round_trip(&na.engine, &mac.pair_x).await);
    assert!(round_trip(&nb.engine, &mab.pair_y).await);
    assert!(round_trip(&nc.engine, &mac.pair_y).await);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let all = |n: &Node| -> Vec<SocketAddr> {
        n.engine.read_book(|bk| {
            bk.friends()
                .iter()
                .flat_map(|f| f.known_addrs.iter().map(|k| k.addr))
                .collect()
        })
    };
    let (in_b, in_c) = (all(&nb), all(&nc));
    assert!(!in_b.iter().any(|x| x.port() == c_addr.port()));
    assert!(!in_c.iter().any(|x| x.port() == b_addr.port()));
    // а у A нет ни адреса B у C, ни наоборот (адреса только свои)
    assert!(in_b.iter().all(|x| x.port() == a_addr.port()));
    assert!(in_c.iter().all(|x| x.port() == a_addr.port()));
    assert_eq!(nb.engine.read_book(|bk| bk.friends().len()), 1);
    assert_eq!(nc.engine.read_book(|bk| bk.friends().len()), 1);
}

#[tokio::test]
async fn engine_probe_change_reknocks_and_keeps_conn() {
    let (mut x, mut y) = (pre(), pre());
    let (bx, by) = (bind(0), bind(0));
    let m = befriend(&mut x, &mut y, Some(by.addr), Some(bx.addr));
    let (mut nx, mut ny) = (run(x, bx), run(y, by));
    both_connected(&mut nx, &mut ny, 15).await;
    // оба звонили одновременно: даём улечься замене соединения, затем запоминаем номер
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = nx.t.stats().reknock_runs;
    let id = nx.engine.connection(&m.pair_x).unwrap().conn_id();
    // сменился исходящий адрес маршрута: повторный стук, соединение продолжается
    nx.probe.set_v4("10.20.30.40");
    assert!(
        wait_for(&mut nx.events, 10, |e| matches!(
            e,
            EngineEvent::OwnAddrsChanged
        ))
        .await
        .is_some(),
        "change not noticed"
    );
    // серия стуков идёт около трёх секунд и учитывается по её окончании
    let end = tokio::time::Instant::now() + Duration::from_secs(10);
    while nx.t.stats().reknock_runs == before && tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(nx.t.stats().reknock_runs, before + 1);
    assert_eq!(nx.engine.connection(&m.pair_x).unwrap().conn_id(), id);
    assert!(round_trip(&nx.engine, &m.pair_x).await);
    assert!(round_trip(&ny.engine, &m.pair_y).await);
}

struct AllowAll;

impl PeerFilter for AllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

/// Ревью 13, L2: держатель токена соединяется и молчит. Пригласивший освобождает сессию по
/// сроку M1 (здесь 2 с), приглашение живёт, настоящий приглашённый затем проходит целиком.
#[tokio::test]
async fn engine_silent_token_holder_dropped_then_real_invitee_succeeds() {
    let cfg = ConnectConfig {
        invite_m1_deadline: Duration::from_secs(2),
        ..engine_cfg()
    };
    let mut a = Node::start_cfg(
        bind(0),
        Arc::new(MemStore::default()),
        TestDir::new(),
        None,
        cfg,
    );
    let mut b = Node::new();
    let (pa, text) = a
        .engine
        .create_invite(300, InviteAddrs::Manual(vec![a.addr]))
        .unwrap();
    // «держатель токена»: те же гостевые ключи, но по соединению ничего не отправляется
    let Token::Invite(tok) = decode(&text).unwrap() else {
        panic!("not an invite")
    };
    let pc = PairId::generate().unwrap();
    let filter: Arc<dyn PeerFilter> = Arc::new(AllowAll);
    let c =
        QuinnTransport::bind(SocketAddr::from(([127, 0, 0, 1], 0)), quinn_cfg(), filter).unwrap();
    c.set_peers(vec![KxPeer::new(
        pc,
        tok.guest_secret().unwrap().into_kx(),
        tok.inviter_x(),
    )])
    .unwrap();
    let silent = c
        .connect(&PeerAddr {
            pair: pc,
            addrs: vec![a.addr],
        })
        .await
        .unwrap();
    // до срока M1 соединение держится
    assert!(
        tokio::time::timeout(Duration::from_millis(1000), silent.closed())
            .await
            .is_err(),
        "dropped before the M1 deadline"
    );
    // после срока M1 (но задолго до срока сессии в 300 с) пригласивший его закрывает
    tokio::time::timeout(Duration::from_secs(5), silent.closed())
        .await
        .expect("silent holder not dropped after the M1 deadline");
    // приглашение живо, настоящий приглашённый проходит
    assert_eq!(a.engine.read_book(|bk| bk.pending().len()), 1);
    let pb = b.engine.accept_invite(&text).unwrap();
    let Some(EngineEvent::SasReady { sas: sa, .. }) = wait_for(&mut a.events, 15, is_sas).await
    else {
        panic!("A: no SAS")
    };
    let Some(EngineEvent::SasReady { sas: sb, .. }) = wait_for(&mut b.events, 15, is_sas).await
    else {
        panic!("B: no SAS")
    };
    assert_eq!(sa.digits(), sb.digits());
    a.engine.confirm_sas(&pa, true, "Борис").unwrap();
    b.engine.confirm_sas(&pb, true, "Анна").unwrap();
    assert_eq!(
        outcome(wait_for(&mut a.events, 15, is_finished).await),
        Some(InviteOutcome::Added)
    );
    assert_eq!(
        outcome(wait_for(&mut b.events, 15, is_finished).await),
        Some(InviteOutcome::Added)
    );
}
