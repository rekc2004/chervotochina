#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Сквозные тесты поиска в LAN (этап 13в): настоящие `QuinnTransport` на 127.0.0.1, у друзей
//! в книгах нет ни одного адреса; вместо сети маяки носит ссылка в памяти на `chervo_lan::LanCore`
//! (петля разрешена, источник 127.0.0.1). Остальной путь настоящий: подсказка, стук, QUIC,
//! Noise KK, `Contact` в книге.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_addr::{AddrSource, LanFound, LanLink, LanPeer, LanStatus, RouteSources};
use chervo_connect::{
    AllowSet, Clock, ConnectConfig, Engine, EngineEvent, EngineEvents, PathKind, RouteProbe,
    SystemClock,
};
use chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_identity::{IdentityError, ListKeyStore, PairId, PairKey, SecretStore};
use chervo_lan::{CoreConfig, LanCore};
use chervo_transport::PeerFilter;
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use zeroize::Zeroizing;

// ------------------------------------------------------------------- помощники

#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
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
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "chervo-lan-net-{}-{n}-{nanos:x}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
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

/// Маршрут частный (иначе движок не передаст ссылке точку входа); сам транспорт на петле.
struct Probe(Ipv4Addr);

impl RouteProbe for Probe {
    fn probe(&self) -> RouteSources {
        RouteSources {
            v4: Some(self.0),
            v6: None,
        }
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

type Eng = Engine<QuinnTransport, MemStore>;

struct Node {
    engine: Eng,
    events: EngineEvents,
    _t: Arc<QuinnTransport>,
    _dir: Arc<TestDir>,
}

struct Pre {
    store: Arc<MemStore>,
    dir: Arc<TestDir>,
    book: FriendBook,
}

fn pre() -> Pre {
    let store = Arc::new(MemStore::default());
    let dir = TestDir::new();
    let book = FriendBook::open_unanchored(&dir.file(), &*store).unwrap();
    Pre { store, dir, book }
}

fn new_friend(theirs: &PairKey, ours: &PairKey) -> NewFriend {
    NewFriend {
        name: "friend".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        // ни одного адреса: найти друга можно только через поиск в LAN
        addrs: Vec::new(),
        now_unix: SystemClock::new().now_unix(),
    }
}

/// Зеркальная дружба без адресов: (пара у `x`, пара у `y`).
fn befriend(x: &mut Pre, y: &mut Pre) -> (PairId, PairId) {
    let (px, kx) = x
        .book
        .begin_pair(&*x.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (py, ky) = y
        .book
        .begin_pair(&*y.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    x.book
        .finish_pair(&*x.store, &px, new_friend(&ky, &kx))
        .unwrap();
    y.book
        .finish_pair(&*y.store, &py, new_friend(&kx, &ky))
        .unwrap();
    (px, py)
}

fn start(p: Pre, route: Ipv4Addr) -> Node {
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let t = Arc::new(
        QuinnTransport::bind(SocketAddr::from(([127, 0, 0, 1], 0)), quinn_cfg(), filter).unwrap(),
    );
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(Probe(route));
    let (engine, events) = Engine::start(
        t.clone(),
        allow,
        p.book,
        p.store.clone(),
        clock,
        probe,
        engine_cfg(),
    )
    .unwrap();
    Node {
        engine,
        events,
        _t: t,
        _dir: p.dir,
    }
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

// ----------------------------------------------------- ссылка в памяти на LanCore

fn mono() -> Duration {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed()
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Ссылка поиска в LAN без сети: маяки из `LanCore` одной стороны отдаются `LanCore` другой.
struct MemLan {
    core: Mutex<LanCore>,
    peer: Mutex<Weak<MemLan>>,
    stop: AtomicBool,
}

impl MemLan {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            core: Mutex::new(LanCore::new(CoreConfig {
                allow_loopback: true,
            })),
            peer: Mutex::new(Weak::new()),
            stop: AtomicBool::new(false),
        })
    }

    /// Две соединённые ссылки; потоки носят маяки, пока ссылки не остановлены.
    fn pair() -> (Arc<Self>, Arc<Self>) {
        let (a, b) = (Self::new(), Self::new());
        *a.peer.lock().unwrap() = Arc::downgrade(&b);
        *b.peer.lock().unwrap() = Arc::downgrade(&a);
        for l in [&a, &b] {
            let weak = Arc::downgrade(l);
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(50));
                    let Some(me) = weak.upgrade() else { return };
                    if me.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let beacon = me.core.lock().unwrap().poll_send(mono(), unix());
                    let peer = me.peer.lock().unwrap().upgrade();
                    if let (Some(b), Some(p)) = (beacon, peer) {
                        // источник: 127.0.0.1 (так подписан маяк)
                        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
                        p.core.lock().unwrap().on_datagram(src, &b, mono(), unix());
                    }
                }
            });
        }
        (a, b)
    }

    fn found_count(&self) -> u64 {
        self.core.lock().unwrap().stats().found
    }

    fn beacons_out(&self) -> u64 {
        self.core.lock().unwrap().stats().beacons_out
    }
}

impl LanLink for MemLan {
    fn set_local(&self, local: Option<SocketAddrV4>) {
        // точка входа в петле: сам транспорт слушает 127.0.0.1
        let l = local.map(|l| SocketAddrV4::new(Ipv4Addr::LOCALHOST, l.port()));
        self.core.lock().unwrap().set_local(l, mono());
    }

    fn set_peers(&self, peers: Vec<LanPeer>) {
        self.core.lock().unwrap().set_peers(peers);
    }

    fn set_wanted(&self, wanted: Vec<PairId>) {
        self.core.lock().unwrap().set_wanted(wanted);
    }

    fn trigger(&self) {
        self.core.lock().unwrap().trigger(mono());
    }

    fn take_found(&self) -> Vec<LanFound> {
        self.core.lock().unwrap().take_found()
    }

    fn status(&self) -> LanStatus {
        LanStatus::Running
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

// ------------------------------------------------------------------------ тесты

#[tokio::test]
async fn lan_net_empty_books_connect() {
    let (mut x, mut y) = (pre(), pre());
    let (px, py) = befriend(&mut x, &mut y);
    let mut a = start(x, Ipv4Addr::new(10, 9, 8, 1));
    let mut b = start(y, Ipv4Addr::new(10, 9, 8, 2));
    // до поиска в LAN ни одного адреса: набирать некуда
    assert!(
        a.engine
            .read_book(|bk| bk.get(&px).unwrap().known_addrs.is_empty())
    );
    let (la, lb) = MemLan::pair();
    a.engine.attach_lan(la.clone()).unwrap();
    b.engine.attach_lan(lb.clone()).unwrap();
    let is_conn = |e: &EngineEvent| matches!(e, EngineEvent::Connected { .. });
    let ea = wait_for(&mut a.events, 15, is_conn).await;
    let eb = wait_for(&mut b.events, 15, is_conn).await;
    let (
        Some(EngineEvent::Connected { path: pa, .. }),
        Some(EngineEvent::Connected { path: pb, .. }),
    ) = (ea, eb)
    else {
        panic!(
            "not connected: a found {} b found {}",
            la.found_count(),
            lb.found_count()
        )
    };
    assert_eq!(pa, PathKind::Lan);
    assert_eq!(pb, PathKind::Lan);
    assert!(a.engine.connection(&px).is_some());
    assert!(b.engine.connection(&py).is_some());
    // после KK у каждой стороны в книге Contact другого, и только он
    for (n, p) in [(&a, px), (&b, py)] {
        let book = n
            .engine
            .read_book(|bk| bk.get(&p).unwrap().known_addrs.clone());
        assert!(!book.is_empty());
        assert!(
            book.iter()
                .all(|k| k.source == AddrSource::Contact && !k.hint)
        );
        assert!(book.iter().all(|k| k.addr.ip().is_loopback()));
    }
    assert!(la.beacons_out() >= 1 && lb.beacons_out() >= 1);
    a.engine.shutdown();
    b.engine.shutdown();
}

#[tokio::test]
async fn lan_net_wrong_pair_no_connect() {
    // два движка не друзья: у каждого свой друг с чужими ключами
    let (mut x, mut y) = (pre(), pre());
    let (mut x2, mut y2) = (pre(), pre());
    let (px, _) = befriend(&mut x, &mut x2);
    let (py, _) = befriend(&mut y, &mut y2);
    let mut a = start(x, Ipv4Addr::new(10, 9, 8, 1));
    let mut b = start(y, Ipv4Addr::new(10, 9, 8, 2));
    let (la, lb) = MemLan::pair();
    a.engine.attach_lan(la.clone()).unwrap();
    b.engine.attach_lan(lb.clone()).unwrap();
    let is_conn = |e: &EngineEvent| matches!(e, EngineEvent::Connected { .. });
    assert!(wait_for(&mut a.events, 20, is_conn).await.is_none());
    assert!(wait_for(&mut b.events, 1, is_conn).await.is_none());
    // маяки ходили, но ни один слот чужого не открылся: подсказок не было, наборов не было
    assert!(la.beacons_out() >= 1 && lb.beacons_out() >= 1);
    assert_eq!(la.found_count(), 0);
    assert_eq!(lb.found_count(), 0);
    assert!(a.engine.connection(&px).is_none());
    assert!(b.engine.connection(&py).is_none());
    assert!(
        a.engine
            .read_book(|bk| bk.get(&px).unwrap().known_addrs.is_empty())
    );
    a.engine.shutdown();
    b.engine.shutdown();
}
