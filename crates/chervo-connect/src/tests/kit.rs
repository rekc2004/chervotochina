//! Помощники тестов: скриптуемый поддельный транспорт, соединения в памяти, часы, хранилище
//! и узел (движок с поддельными частями). Сокетов нет: адреса только как значения.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{AddrSource, KnownAddr, RouteSources};
use chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_identity::{
    IdentityError, KxPeer, KxPublicKey, ListKeyStore, PairId, PairKey, SecretStore, create,
};
use chervo_transport::{
    Connection, DuplicatePairError, EventSource, ManagedTransport, PeerAddr, RecvStream,
    SendStream, Transport, TransportError, TransportEvent,
};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::{AllowSet, Clock, ConnectConfig, Engine, EngineEvent, EngineEvents, RouteProbe};

pub const BASE_UNIX: u64 = 1_800_000_000;

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ------------------------------------------------------------------ хранилище

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl MemStore {
    pub fn pair_count(&self) -> usize {
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

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("chervo-connect-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn file(&self) -> PathBuf {
        self.0.join("friends.chfl")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ----------------------------------------------------------------- часы и проба

/// Секунды Unix идут вместе с приостановленным временем tokio.
pub struct TestClock {
    skew: AtomicU64,
    start: Instant,
}

impl TestClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            skew: AtomicU64::new(0),
            start: Instant::now(),
        })
    }

    /// Часы уходят вперёд на `secs` секунд (скачок часов пользователя).
    pub fn skew(&self, secs: u64) {
        self.skew.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        BASE_UNIX
            + self.skew.load(Ordering::SeqCst)
            + Instant::now()
                .saturating_duration_since(self.start)
                .as_secs()
    }
}

pub struct FakeProbe {
    sources: Mutex<RouteSources>,
    /// Адрес-источник на пути к цели (`source_for`); цели нет в таблице: `None`.
    path: Mutex<HashMap<SocketAddr, IpAddr>>,
    source_calls: AtomicUsize,
}

impl FakeProbe {
    pub fn new(v4: Option<&str>) -> Arc<Self> {
        let p = Arc::new(Self {
            sources: Mutex::new(RouteSources::default()),
            path: Mutex::new(HashMap::new()),
            source_calls: AtomicUsize::new(0),
        });
        p.set_v4(v4);
        p
    }

    /// Что вернёт `source_for(target)`.
    pub fn set_source(&self, target: &str, src: Option<&str>) {
        let t: SocketAddr = target.parse().unwrap();
        let mut m = self.path.lock().unwrap();
        match src {
            Some(s) => {
                m.insert(t, s.parse().unwrap());
            }
            None => {
                m.remove(&t);
            }
        }
    }

    /// Сколько раз вызывали `source_for`.
    pub fn source_calls(&self) -> usize {
        self.source_calls.load(Ordering::SeqCst)
    }

    pub fn set_v4(&self, v4: Option<&str>) {
        self.sources.lock().unwrap().v4 = v4.map(|s| s.parse().unwrap());
    }

    pub fn set_v6(&self, v6: Option<&str>) {
        self.sources.lock().unwrap().v6 = v6.map(|s| s.parse().unwrap());
    }
}

impl RouteProbe for FakeProbe {
    fn probe(&self) -> RouteSources {
        *self.sources.lock().unwrap()
    }

    fn source_for(&self, target: SocketAddr) -> Option<IpAddr> {
        self.source_calls.fetch_add(1, Ordering::SeqCst);
        self.path.lock().unwrap().get(&target).copied()
    }
}

// --------------------------------------------------------------------- потоки

pub struct FakeTx(Option<mpsc::UnboundedSender<Vec<u8>>>);

pub struct FakeRx {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cur: Vec<u8>,
    pos: usize,
}

fn chan() -> (FakeTx, FakeRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        FakeTx(Some(tx)),
        FakeRx {
            rx,
            cur: Vec::new(),
            pos: 0,
        },
    )
}

impl SendStream for FakeTx {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send {
        let r = match &self.0 {
            Some(tx) => tx.send(buf.to_vec()).map_err(|_| TransportError::Closed),
            None => Err(TransportError::Closed),
        };
        std::future::ready(r)
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        self.0 = None;
        Ok(())
    }
}

impl RecvStream for FakeRx {
    #[allow(clippy::manual_async_fn)]
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, TransportError>> + Send {
        async move {
            if self.pos >= self.cur.len() {
                match self.rx.recv().await {
                    Some(c) => {
                        self.cur = c;
                        self.pos = 0;
                    }
                    None => return Ok(None),
                }
            }
            let n = (self.cur.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
            self.pos += n;
            Ok(Some(n))
        }
    }
}

// ----------------------------------------------------------------- соединение

type StreamPair = (FakeTx, FakeRx);

static CONN_ID: AtomicU64 = AtomicU64::new(1);

async fn wait_true(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

pub struct ConnInner {
    pair: PairId,
    remote: Mutex<SocketAddr>,
    id: u64,
    initiator: bool,
    closed: Arc<watch::Sender<bool>>,
    outbox: mpsc::UnboundedSender<StreamPair>,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamPair>>,
    pub opened: AtomicUsize,
    pub accepted: AtomicUsize,
    peer: Mutex<Option<FakeConn>>,
}

#[derive(Clone)]
pub struct FakeConn(pub Arc<ConnInner>);

impl FakeConn {
    /// Два конца одного соединения. `a` видит собеседника как `pair_a` по адресу `remote_a`.
    pub fn pair(
        pair_a: PairId,
        remote_a: SocketAddr,
        pair_b: PairId,
        remote_b: SocketAddr,
        a_initiator: bool,
    ) -> (FakeConn, FakeConn) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let closed = Arc::new(watch::channel(false).0);
        let a = FakeConn(Arc::new(ConnInner {
            pair: pair_a,
            remote: Mutex::new(remote_a),
            id: CONN_ID.fetch_add(1, Ordering::SeqCst),
            initiator: a_initiator,
            closed: closed.clone(),
            outbox: b_tx,
            inbox: tokio::sync::Mutex::new(a_rx),
            opened: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            peer: Mutex::new(None),
        }));
        let b = FakeConn(Arc::new(ConnInner {
            pair: pair_b,
            remote: Mutex::new(remote_b),
            id: CONN_ID.fetch_add(1, Ordering::SeqCst),
            initiator: !a_initiator,
            closed,
            outbox: a_tx,
            inbox: tokio::sync::Mutex::new(b_rx),
            opened: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            peer: Mutex::new(None),
        }));
        (a, b)
    }

    /// Соединение без живого собеседника; противоположный конец доступен через `peer()`
    /// (тест играет за собеседника или молчит).
    pub fn lonely(pair: PairId, remote: SocketAddr, initiator: bool) -> FakeConn {
        let (a, b) = Self::pair(
            pair,
            remote,
            PairId::from_bytes([0xEE; 16]),
            addr("198.51.100.1:1"),
            initiator,
        );
        *a.0.peer.lock().unwrap() = Some(b);
        a
    }

    pub fn peer(&self) -> FakeConn {
        self.0.peer.lock().unwrap().clone().unwrap()
    }

    pub fn is_closed(&self) -> bool {
        *self.0.closed.borrow()
    }

    /// Собеседник сменил адрес посреди соединения (как после NAT-перепривязки).
    pub fn set_remote(&self, remote: SocketAddr) {
        *self.0.remote.lock().unwrap() = remote;
    }

    pub fn opened(&self) -> usize {
        self.0.opened.load(Ordering::SeqCst)
    }

    pub fn accepted(&self) -> usize {
        self.0.accepted.load(Ordering::SeqCst)
    }
}

impl Connection for FakeConn {
    type Tx = FakeTx;
    type Rx = FakeRx;

    fn remote_pair(&self) -> PairId {
        self.0.pair
    }

    fn remote_addr(&self) -> SocketAddr {
        *self.0.remote.lock().unwrap()
    }

    fn open_bi(&self) -> impl Future<Output = Result<(FakeTx, FakeRx), TransportError>> + Send {
        let this = self.0.clone();
        async move {
            if *this.closed.borrow() {
                return Err(TransportError::Closed);
            }
            let (a_tx, b_rx) = chan();
            let (b_tx, a_rx) = chan();
            this.outbox
                .send((b_tx, b_rx))
                .map_err(|_| TransportError::Closed)?;
            this.opened.fetch_add(1, Ordering::SeqCst);
            Ok((a_tx, a_rx))
        }
    }

    fn accept_bi(&self) -> impl Future<Output = Result<(FakeTx, FakeRx), TransportError>> + Send {
        let this = self.0.clone();
        async move {
            let mut inbox = this.inbox.lock().await;
            tokio::select! {
                s = inbox.recv() => match s {
                    Some(s) => {
                        this.accepted.fetch_add(1, Ordering::SeqCst);
                        Ok(s)
                    }
                    None => Err(TransportError::Closed),
                },
                () = wait_true(this.closed.subscribe()) => Err(TransportError::Closed),
            }
        }
    }

    fn close(&self) {
        self.0.closed.send_replace(true);
    }

    fn conn_id(&self) -> u64 {
        self.0.id
    }

    fn is_initiator(&self) -> bool {
        self.0.initiator
    }

    fn closed(&self) -> impl Future<Output = ()> + Send {
        let rx = self.0.closed.subscribe();
        wait_true(rx)
    }
}

// ------------------------------------------------------------------ транспорт

pub enum Action {
    Fail(TransportError, Duration),
    Ok(FakeConn, Duration),
    Hang,
}

type Script = Box<dyn FnMut(&PairId, &[SocketAddr]) -> Action + Send>;

pub struct Shared {
    local: Mutex<Vec<SocketAddr>>,
    pub calls: Mutex<Vec<(PairId, Vec<SocketAddr>)>>,
    script: Mutex<Script>,
    cur_pair: Mutex<HashMap<PairId, usize>>,
    pub max_pair: AtomicUsize,
    cur_total: AtomicUsize,
    pub max_total: AtomicUsize,
    pub peers_calls: Mutex<Vec<Vec<(PairId, KxPublicKey, KxPublicKey)>>>,
    pub dup_error: AtomicBool,
    pub reknocks: AtomicUsize,
    incoming_tx: mpsc::UnboundedSender<FakeConn>,
    incoming_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<FakeConn>>,
    pub events_tx: broadcast::Sender<TransportEvent>,
}

pub struct FakeTransport {
    s: Arc<Shared>,
}

impl Deref for FakeTransport {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.s
    }
}

impl FakeTransport {
    pub fn new() -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            s: Arc::new(Shared {
                local: Mutex::new(vec![addr("0.0.0.0:4000")]),
                calls: Mutex::new(Vec::new()),
                script: Mutex::new(Box::new(|_, _| Action::Hang)),
                cur_pair: Mutex::new(HashMap::new()),
                max_pair: AtomicUsize::new(0),
                cur_total: AtomicUsize::new(0),
                max_total: AtomicUsize::new(0),
                peers_calls: Mutex::new(Vec::new()),
                dup_error: AtomicBool::new(false),
                reknocks: AtomicUsize::new(0),
                incoming_tx,
                incoming_rx: tokio::sync::Mutex::new(incoming_rx),
                events_tx: broadcast::channel(64).0,
            }),
        })
    }

    pub fn set_script(&self, f: impl FnMut(&PairId, &[SocketAddr]) -> Action + Send + 'static) {
        *self.s.script.lock().unwrap() = Box::new(f);
    }

    pub fn set_local(&self, v: Vec<SocketAddr>) {
        *self.s.local.lock().unwrap() = v;
    }

    /// Входящее соединение (как из `accept`).
    pub fn push_incoming(&self, c: FakeConn) {
        self.s.incoming_tx.send(c).unwrap();
    }

    pub fn call_count(&self) -> usize {
        self.s.calls.lock().unwrap().len()
    }

    pub fn calls_for(&self, pair: &PairId) -> Vec<Vec<SocketAddr>> {
        self.s
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == pair)
            .map(|(_, a)| a.clone())
            .collect()
    }

    pub fn last_peers(&self) -> Vec<PairId> {
        self.s
            .peers_calls
            .lock()
            .unwrap()
            .last()
            .map(|v| v.iter().map(|(p, _, _)| *p).collect())
            .unwrap_or_default()
    }

    pub fn peers_call_count(&self) -> usize {
        self.s.peers_calls.lock().unwrap().len()
    }

    pub fn reknock_count(&self) -> usize {
        self.s.reknocks.load(Ordering::SeqCst)
    }

    /// Событие транспорта для движка (например, `RemoteAddrChanged`).
    pub fn emit(&self, e: TransportEvent) {
        let _ = self.s.events_tx.send(e);
    }
}

struct DialGuard(Arc<Shared>, PairId);

impl Drop for DialGuard {
    fn drop(&mut self) {
        self.0.cur_total.fetch_sub(1, Ordering::SeqCst);
        let mut m = self.0.cur_pair.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
        }
    }
}

impl Transport for FakeTransport {
    type Conn = FakeConn;

    fn local_addrs(&self) -> Vec<SocketAddr> {
        self.s.local.lock().unwrap().clone()
    }

    fn connect(
        &self,
        peer: &PeerAddr,
    ) -> impl Future<Output = Result<FakeConn, TransportError>> + Send {
        let s = self.s.clone();
        let pair = peer.pair;
        let addrs = peer.addrs.clone();
        async move {
            s.calls.lock().unwrap().push((pair, addrs.clone()));
            let total = s.cur_total.fetch_add(1, Ordering::SeqCst) + 1;
            s.max_total.fetch_max(total, Ordering::SeqCst);
            {
                let mut m = s.cur_pair.lock().unwrap();
                let n = m.entry(pair).or_insert(0);
                *n += 1;
                s.max_pair.fetch_max(*n, Ordering::SeqCst);
            }
            let _guard = DialGuard(s.clone(), pair);
            let action = (s.script.lock().unwrap())(&pair, &addrs);
            match action {
                Action::Fail(e, d) => {
                    tokio::time::sleep(d).await;
                    Err(e)
                }
                Action::Ok(c, d) => {
                    tokio::time::sleep(d).await;
                    Ok(c)
                }
                Action::Hang => std::future::pending().await,
            }
        }
    }

    fn accept(&self) -> impl Future<Output = Result<FakeConn, TransportError>> + Send {
        let s = self.s.clone();
        async move {
            let mut rx = s.incoming_rx.lock().await;
            rx.recv().await.ok_or(TransportError::Closed)
        }
    }
}

pub struct FakeEvents(broadcast::Receiver<TransportEvent>);

impl EventSource for FakeEvents {
    #[allow(clippy::manual_async_fn)]
    fn recv(&mut self) -> impl Future<Output = Option<TransportEvent>> + Send {
        async move {
            match self.0.recv().await {
                Ok(e) => Some(e),
                Err(broadcast::error::RecvError::Lagged(_)) => Some(TransportEvent::Lagged),
                Err(broadcast::error::RecvError::Closed) => None,
            }
        }
    }
}

impl ManagedTransport for FakeTransport {
    type Events = FakeEvents;

    fn set_peers(&self, peers: Vec<KxPeer>) -> Result<(), DuplicatePairError> {
        if self.s.dup_error.load(Ordering::SeqCst) {
            return Err(DuplicatePairError);
        }
        self.s.peers_calls.lock().unwrap().push(
            peers
                .iter()
                .map(|p| (p.pair(), p.ours_public(), p.theirs()))
                .collect(),
        );
        Ok(())
    }

    fn reknock(&self) {
        self.s.reknocks.fetch_add(1, Ordering::SeqCst);
    }

    fn subscribe(&self) -> FakeEvents {
        FakeEvents(self.s.events_tx.subscribe())
    }
}

// ----------------------------------------------------------- книга и узел

pub fn known(a: &str, source: AddrSource, hint: bool) -> KnownAddr {
    let a = addr(a);
    KnownAddr {
        addr: a,
        source,
        last_seen_unix: BASE_UNIX,
        short_lived: a.is_ipv6(),
        hint,
    }
}

/// Адрес приглашения (постоянный, не подсказка).
pub fn inv(a: &str) -> KnownAddr {
    known(a, AddrSource::Invite, false)
}

/// Книга и хранилище до запуска движка.
pub struct Pre {
    pub dir: TestDir,
    pub store: Arc<MemStore>,
    pub book: FriendBook,
}

fn new_friend(theirs: &PairKey, ours: &PairKey, name: &str, addrs: Vec<KnownAddr>) -> NewFriend {
    NewFriend {
        name: name.to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs,
        now_unix: BASE_UNIX,
    }
}

impl Pre {
    pub fn new() -> Self {
        let dir = TestDir::new();
        let store = Arc::new(MemStore::default());
        let book = FriendBook::open(&dir.file(), &*store).unwrap();
        Self { dir, store, book }
    }

    /// Друг с произвольными ключами другой стороны (самой стороны нет).
    pub fn solo_friend(&mut self, addrs: Vec<KnownAddr>) -> PairId {
        let (pair, ours) = self
            .book
            .begin_pair(&*self.store, PendingRole::Inviter, u64::MAX)
            .unwrap();
        let other = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
        self.book
            .finish_pair(
                &*self.store,
                &pair,
                new_friend(&other, &ours, "friend", addrs),
            )
            .unwrap();
        pair
    }
}

/// Зеркальная дружба двух сторон: (пара у `a`, пара у `b`).
pub fn befriend(
    a: &mut Pre,
    b: &mut Pre,
    a_knows_b: Vec<KnownAddr>,
    b_knows_a: Vec<KnownAddr>,
) -> (PairId, PairId) {
    let (pa, ka) = a
        .book
        .begin_pair(&*a.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (pb, kb) = b
        .book
        .begin_pair(&*b.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    a.book
        .finish_pair(&*a.store, &pa, new_friend(&kb, &ka, "friend", a_knows_b))
        .unwrap();
    b.book
        .finish_pair(&*b.store, &pb, new_friend(&ka, &kb, "friend", b_knows_a))
        .unwrap();
    (pa, pb)
}

pub struct Node {
    pub engine: Engine<FakeTransport, MemStore>,
    pub events: EngineEvents,
    pub t: Arc<FakeTransport>,
    pub store: Arc<MemStore>,
    pub clock: Arc<TestClock>,
    pub probe: Arc<FakeProbe>,
    pub allow: Arc<AllowSet>,
    _dir: TestDir,
}

impl Node {
    pub fn start(pre: Pre, cfg: ConnectConfig) -> Node {
        Self::start_with(
            pre,
            cfg,
            FakeTransport::new(),
            FakeProbe::new(Some("192.168.1.5")),
        )
    }

    pub fn start_with(
        pre: Pre,
        cfg: ConnectConfig,
        t: Arc<FakeTransport>,
        probe: Arc<FakeProbe>,
    ) -> Node {
        let clock = TestClock::new();
        let allow = AllowSet::new();
        let c: Arc<dyn Clock> = clock.clone();
        let p: Arc<dyn RouteProbe> = probe.clone();
        let (engine, events) = Engine::start(
            t.clone(),
            allow.clone(),
            pre.book,
            pre.store.clone(),
            c,
            p,
            cfg,
        )
        .unwrap();
        Node {
            engine,
            events,
            t,
            store: pre.store,
            clock,
            probe,
            allow,
            _dir: pre.dir,
        }
    }
}

/// Ждёт событие, подходящее под условие, не дольше `max`.
pub async fn wait_event(
    events: &mut EngineEvents,
    max: Duration,
    f: impl Fn(&EngineEvent) -> bool,
) -> Option<EngineEvent> {
    let deadline = Instant::now() + max;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, events.recv()).await {
            Ok(Some(e)) if f(&e) => return Some(e),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

/// Все события, доступные сразу.
pub async fn drain(events: &mut EngineEvents) -> Vec<EngineEvent> {
    let mut out = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::ZERO, events.recv()).await {
        out.push(e);
    }
    out
}

/// Соединённая пара узлов `a` и `b` (друзья друг для друга): `a` звонит `b`, `b` не звонит.
/// Возвращает хранилище созданных соединений (концы `a` и `b`).
pub fn link_nodes(
    a: &Node,
    pair_a: PairId,
    a_sees_b_at: &str,
    b: &Node,
    pair_b: PairId,
    b_sees_a_at: &str,
) -> Arc<Mutex<Vec<(FakeConn, FakeConn)>>> {
    let links: Arc<Mutex<Vec<(FakeConn, FakeConn)>>> = Arc::new(Mutex::new(Vec::new()));
    let (l, bt) = (links.clone(), b.t.clone());
    let (ra, rb) = (addr(a_sees_b_at), addr(b_sees_a_at));
    a.t.set_script(move |pair, _| {
        if *pair != pair_a {
            return Action::Fail(TransportError::TimedOut, Duration::ZERO);
        }
        let (ca, cb) = FakeConn::pair(pair_a, ra, pair_b, rb, true);
        l.lock().unwrap().push((ca.clone(), cb.clone()));
        bt.push_incoming(cb);
        Action::Ok(ca, Duration::ZERO)
    });
    b.t.set_script(|_, _| Action::Hang);
    links
}

/// Друг с произвольными ключами другой стороны; для `update_book`.
pub fn add_solo_friend(
    book: &mut FriendBook,
    store: &MemStore,
    addrs: Vec<KnownAddr>,
) -> Result<PairId, chervo_friends::FriendsError> {
    let (pair, ours) = book.begin_pair(store, PendingRole::Inviter, u64::MAX)?;
    let other = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    book.finish_pair(store, &pair, new_friend(&other, &ours, "friend", addrs))?;
    Ok(pair)
}

/// Наблюдение друга без живого соединения (отключённый друг): «с моей стороны вы выглядите
/// как `observed`», друг на `via`. Идёт напрямую в `observe` активного друга, мимо проверки
/// живого соединения `apply_peer_info`; отметки `reporter_up` нет, наблюдение не текущее.
pub fn apply_obs(n: &Node, pair: PairId, via: &str, observed: &str) {
    let unix = n.clock.now_unix();
    let mut st = n.engine.inner.lock();
    if st.book.is_active(&pair) {
        let _ = st.own.observe(pair, addr(via), addr(observed), unix);
    }
}

/// То же через `apply_peer_info` от имени соединения `conn_id`.
pub fn apply_obs_on(n: &Node, pair: PairId, conn_id: u64, via: &str, observed: &str) {
    let now = Instant::now();
    let unix = n.clock.now_unix();
    let mut st = n.engine.inner.lock();
    n.engine.inner.apply_peer_info(
        &mut st,
        pair,
        conn_id,
        chervo_token::addr_flow::PeerAddrInfo {
            observed_me: addr(observed),
            via: addr(via),
            update: None,
        },
        now,
        unix,
    );
}

/// Наблюдение по живому соединению друга (его `conn_id` берётся из движка).
pub fn apply_obs_live(n: &Node, pair: PairId, via: &str, observed: &str) {
    let id = n.engine.connection(&pair).map_or(0, |c| c.conn_id());
    apply_obs_on(n, pair, id, via, observed);
}
