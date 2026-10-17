//! Помощники тестов X2/X3: соединения в памяти, поддельный транспорт под настоящим движком
//! (`chervo_connect::Engine`), узлы с `Transfers`, поддельный отправитель и подмены точек
//! писателя. Сокетов нет.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{AddrSource, KnownAddr, RouteSources};
use chervo_connect::{AllowSet, Clock, ConnectConfig, Engine, EngineEvents, RouteProbe};
use chervo_friends::{FriendBook, NewFriend, PendingRole, Permission};
use chervo_identity::{IdentityError, KxPeer, ListKeyStore, PairId, PairKey, SecretStore, create};
use chervo_transport::{
    Connection, DuplicatePairError, EventSource, ManagedTransport, PeerAddr, RecvStream,
    SendStream, Transport, TransportError, TransportEvent,
};
use tokio::sync::{broadcast, mpsc, watch};
use zeroize::Zeroizing;

use crate::shared::{Hook, HookPoint};
use crate::{
    AskAlways, CompletedFile, GeneratedNames, Message, PlaceError, Placed, Placement, SourceFile,
    TransferConfig, TransferEvent, TransferEvents, TransferKey, Transfers, encode, read_message,
};

pub const BASE_UNIX: u64 = 1_800_000_000;

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

// ------------------------------------------------------------------ хранилище

#[derive(Default)]
pub struct MemStore {
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

/// Каталог в temp, удаляется целиком при уничтожении (только каталоги самих тестов).
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Arc<Self> {
        let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("chervo-xfer-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Arc::new(Self(p))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn file(&self) -> PathBuf {
        self.0.join("friends.chfl")
    }

    /// Имена прямых потомков (для проверки, что лишнего нет).
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ----------------------------------------------------------------- часы и проба

pub struct TestClock;

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        BASE_UNIX
    }
}

pub struct FakeProbe(Mutex<RouteSources>);

impl FakeProbe {
    pub fn new() -> Arc<Self> {
        let s = RouteSources {
            v4: Some("192.168.1.5".parse().unwrap()),
            ..RouteSources::default()
        };
        Arc::new(Self(Mutex::new(s)))
    }
}

impl RouteProbe for FakeProbe {
    fn probe(&self) -> RouteSources {
        *self.0.lock().unwrap()
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
    remote: SocketAddr,
    id: u64,
    initiator: bool,
    closed: Arc<watch::Sender<bool>>,
    outbox: mpsc::UnboundedSender<StreamPair>,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamPair>>,
    peer: Mutex<Option<FakeConn>>,
}

#[derive(Clone)]
pub struct FakeConn(pub Arc<ConnInner>);

impl FakeConn {
    /// Два конца одного соединения. `a` видит собеседника как `pair_a`.
    pub fn pair(
        pair_a: PairId,
        remote_a: SocketAddr,
        pair_b: PairId,
        remote_b: SocketAddr,
    ) -> (FakeConn, FakeConn) {
        Self::pair_ids(pair_a, remote_a, pair_b, remote_b, None)
    }

    /// То же с заданными номерами концов (`None`: из счётчика). Нужно, чтобы сыграть
    /// повторное использование номера (так вёл себя адрес в памяти у прежнего адаптера quinn).
    pub fn pair_ids(
        pair_a: PairId,
        remote_a: SocketAddr,
        pair_b: PairId,
        remote_b: SocketAddr,
        ids: Option<(u64, u64)>,
    ) -> (FakeConn, FakeConn) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let closed = Arc::new(watch::channel(false).0);
        let mk = |pair, remote, outbox, inbox, id: Option<u64>| {
            FakeConn(Arc::new(ConnInner {
                pair,
                remote,
                id: id.unwrap_or_else(|| CONN_ID.fetch_add(1, Ordering::SeqCst)),
                initiator: false,
                closed: closed.clone(),
                outbox,
                inbox: tokio::sync::Mutex::new(inbox),
                peer: Mutex::new(None),
            }))
        };
        let a = mk(pair_a, remote_a, b_tx, a_rx, ids.map(|i| i.0));
        let b = mk(pair_b, remote_b, a_tx, b_rx, ids.map(|i| i.1));
        (a, b)
    }

    /// Соединение без живого собеседника; противоположный конец через `peer()` (тест играет
    /// за собеседника).
    pub fn lonely(pair: PairId) -> FakeConn {
        let (a, b) = Self::pair(
            pair,
            addr("198.51.100.2:1"),
            PairId::from_bytes([0xEE; 16]),
            addr("198.51.100.1:1"),
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
}

impl Connection for FakeConn {
    type Tx = FakeTx;
    type Rx = FakeRx;

    fn remote_pair(&self) -> PairId {
        self.0.pair
    }

    fn remote_addr(&self) -> SocketAddr {
        self.0.remote
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
            Ok((a_tx, a_rx))
        }
    }

    fn accept_bi(&self) -> impl Future<Output = Result<(FakeTx, FakeRx), TransportError>> + Send {
        let this = self.0.clone();
        async move {
            let mut inbox = this.inbox.lock().await;
            tokio::select! {
                s = inbox.recv() => s.ok_or(TransportError::Closed),
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
        wait_true(self.0.closed.subscribe())
    }
}

// ------------------------------------------------------------------- транспорт

pub struct FakeTransport {
    incoming_tx: mpsc::UnboundedSender<FakeConn>,
    incoming_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<FakeConn>>,
    events_tx: broadcast::Sender<TransportEvent>,
}

impl FakeTransport {
    pub fn new() -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            incoming_tx,
            incoming_rx: tokio::sync::Mutex::new(incoming_rx),
            events_tx: broadcast::channel(64).0,
        })
    }

    pub fn push_incoming(&self, c: FakeConn) {
        self.incoming_tx.send(c).unwrap();
    }
}

impl Transport for FakeTransport {
    type Conn = FakeConn;

    fn local_addrs(&self) -> Vec<SocketAddr> {
        vec![addr("0.0.0.0:4000")]
    }

    fn connect(
        &self,
        _peer: &PeerAddr,
    ) -> impl Future<Output = Result<FakeConn, TransportError>> + Send {
        std::future::pending()
    }

    #[allow(clippy::manual_async_fn)]
    fn accept(&self) -> impl Future<Output = Result<FakeConn, TransportError>> + Send {
        async move {
            let mut rx = self.incoming_rx.lock().await;
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

    fn set_peers(&self, _peers: Vec<KxPeer>) -> Result<(), DuplicatePairError> {
        Ok(())
    }

    fn reknock(&self) {}

    fn subscribe(&self) -> FakeEvents {
        FakeEvents(self.events_tx.subscribe())
    }
}

// ----------------------------------------------------------- книга и узлы

fn new_friend(theirs: &PairKey, ours: &PairKey, name: &str) -> NewFriend {
    NewFriend {
        name: name.to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: vec![KnownAddr {
            addr: addr("198.51.100.9:4000"),
            source: AddrSource::Invite,
            last_seen_unix: BASE_UNIX,
            short_lived: false,
            hint: false,
        }],
        now_unix: BASE_UNIX,
    }
}

/// Книга и хранилище до запуска движка.
pub struct Pre {
    pub dir: Arc<TestDir>,
    pub store: Arc<MemStore>,
    pub book: FriendBook,
}

impl Pre {
    pub fn new() -> Self {
        let dir = TestDir::new();
        let store = Arc::new(MemStore::default());
        let book = FriendBook::open(&dir.file(), &*store).unwrap();
        Self { dir, store, book }
    }

    /// Друг с произвольными ключами другой стороны (самой стороны нет).
    pub fn solo_friend(&mut self) -> PairId {
        let (pair, ours) = self
            .book
            .begin_pair(&*self.store, PendingRole::Inviter, u64::MAX)
            .unwrap();
        let other = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
        self.book
            .finish_pair(&*self.store, &pair, new_friend(&other, &ours, "friend"))
            .unwrap();
        pair
    }
}

/// Зеркальная дружба двух сторон: (пара у `a`, пара у `b`).
pub fn befriend(a: &mut Pre, b: &mut Pre) -> (PairId, PairId) {
    let (pa, ka) = a
        .book
        .begin_pair(&*a.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (pb, kb) = b
        .book
        .begin_pair(&*b.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    a.book
        .finish_pair(&*a.store, &pa, new_friend(&kb, &ka, "friend"))
        .unwrap();
    b.book
        .finish_pair(&*b.store, &pb, new_friend(&ka, &kb, "friend"))
        .unwrap();
    (pa, pb)
}

pub type TEngine = Engine<FakeTransport, MemStore>;

pub struct Node {
    pub engine: Arc<TEngine>,
    pub events: EngineEvents,
    pub t: Arc<FakeTransport>,
    _dir: Arc<TestDir>,
}

impl Node {
    pub fn start(pre: Pre) -> Node {
        let t = FakeTransport::new();
        let c: Arc<dyn Clock> = Arc::new(TestClock);
        let p: Arc<dyn RouteProbe> = FakeProbe::new();
        let (engine, events) = Engine::start(
            t.clone(),
            AllowSet::new(),
            pre.book,
            pre.store.clone(),
            c,
            p,
            ConnectConfig::default(),
        )
        .unwrap();
        Node {
            engine: Arc::new(engine),
            events,
            t,
            _dir: pre.dir,
        }
    }
}

// --------------------------------------------------------- подмены писателя

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ev {
    Write(u32, u32, crate::BlockHash),
    Written(u32, u32),
    Synced(u32),
    StateWrite(Vec<u8>),
    Manifest(u32),
    FinalVerify(u32),
    BeforePlace(u32),
    HashBlock(u32, u32),
}

type Handler = Box<dyn FnMut(&Ev) -> io::Result<()> + Send>;

/// Журнал точек писателя и необязательный обработчик, который может вернуть ошибку или
/// вмешаться в файлы.
#[derive(Default)]
pub struct TestHook {
    pub log: Mutex<Vec<Ev>>,
    handler: Mutex<Option<Handler>>,
}

impl TestHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set(&self, h: impl FnMut(&Ev) -> io::Result<()> + Send + 'static) {
        *self.handler.lock().unwrap() = Some(Box::new(h));
    }

    pub fn clear(&self) {
        *self.handler.lock().unwrap() = None;
    }

    pub fn events(&self) -> Vec<Ev> {
        self.log.lock().unwrap().clone()
    }
}

impl Hook for TestHook {
    fn at(&self, p: HookPoint<'_>) -> io::Result<()> {
        let ev = match p {
            HookPoint::Write { file, block, data } => {
                Ev::Write(file, block, crate::leaf_hash(block, data))
            }
            HookPoint::Written { file, block } => Ev::Written(file, block),
            HookPoint::Synced { file } => Ev::Synced(file),
            HookPoint::StateWrite { bytes } => Ev::StateWrite(bytes.to_vec()),
            HookPoint::Manifest { file } => Ev::Manifest(file),
            HookPoint::FinalVerify { file } => Ev::FinalVerify(file),
            HookPoint::BeforePlace { file } => Ev::BeforePlace(file),
            HookPoint::HashBlock { file, block } => Ev::HashBlock(file, block),
        };
        self.log.lock().unwrap().push(ev.clone());
        match self.handler.lock().unwrap().as_mut() {
            Some(h) => h(&ev),
            None => Ok(()),
        }
    }
}

/// `Placement` с журналом: перед размещением сверяет корень временного файла на диске.
pub struct PlaceSpy {
    pub inner: GeneratedNames,
    pub calls: Mutex<Vec<(u32, bool)>>,
    /// Отказывать в размещении (проверка PlaceFailed).
    pub fail: std::sync::atomic::AtomicBool,
}

impl Placement for PlaceSpy {
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        let ok = crate::fsio::disk_root(f.temp_path(), f.size).is_ok_and(|r| r == f.root);
        self.calls.lock().unwrap().push((f.index, ok));
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlaceError::Refused);
        }
        self.inner.place(f)
    }
}

// ------------------------------------------------------------------------ узел передач

pub struct Peer {
    pub node: Node,
    pub tr: Transfers<TEngine>,
    pub ev: TransferEvents,
    pub partial: Arc<TestDir>,
    pub dest: Arc<TestDir>,
    pub hook: Arc<TestHook>,
    pub spy: Arc<PlaceSpy>,
    pub cfg: TransferConfig,
}

pub fn small_cfg(partial: &Path) -> TransferConfig {
    let mut c = TransferConfig::new(partial.to_path_buf());
    c.progress_interval = Duration::from_millis(5);
    c.checkpoint_interval = Duration::from_millis(50);
    c
}

impl Peer {
    pub fn start(
        node: Node,
        partial: Arc<TestDir>,
        dest: Arc<TestDir>,
        cfg: TransferConfig,
    ) -> Peer {
        let inbox = node
            .engine
            .stream_inbox(&[crate::STREAM_TRANSFER_CTL, crate::STREAM_TRANSFER_DATA])
            .unwrap();
        let hook = TestHook::new();
        let spy = Arc::new(PlaceSpy {
            inner: GeneratedNames {
                dest_dir: dest.path().to_path_buf(),
            },
            calls: Mutex::new(Vec::new()),
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let (tr, ev) = Transfers::start_with(
            node.engine.clone(),
            inbox,
            Arc::new(AskAlways),
            spy.clone(),
            cfg.clone(),
            Some(hook.clone()),
            Duration::from_millis(200),
        )
        .unwrap();
        Peer {
            node,
            tr,
            ev,
            partial,
            dest,
            hook,
            spy,
            cfg,
        }
    }

    /// Останавливает передачи и запускает заново на тех же каталогах (как перезапуск
    /// программы; движок и соединения остаются).
    pub async fn restart(&mut self) {
        self.tr.shutdown();
        self.tr.wait_stopped().await;
        let inbox = self
            .node
            .engine
            .stream_inbox(&[crate::STREAM_TRANSFER_CTL, crate::STREAM_TRANSFER_DATA])
            .unwrap();
        self.hook.log.lock().unwrap().clear();
        self.hook.clear();
        self.spy.calls.lock().unwrap().clear();
        let (tr, ev) = Transfers::start_with(
            self.node.engine.clone(),
            inbox,
            Arc::new(AskAlways),
            self.spy.clone(),
            self.cfg.clone(),
            Some(self.hook.clone()),
            Duration::from_millis(200),
        )
        .unwrap();
        self.tr = tr;
        self.ev = ev;
    }
}

/// Заслонка: на нужном событии писателя останавливает его поток, пока тест не отпустит.
pub struct Gate {
    reached: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
}

impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: std::sync::atomic::AtomicBool::new(false),
            release: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Вызывается из обработчика: при первом срабатывании ждёт `release`.
    pub fn hold(&self) {
        if !self.reached.swap(true, Ordering::SeqCst) {
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    pub async fn wait_reached(&self) {
        for _ in 0..3000 {
            if self.reached.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("gate not reached");
    }

    pub fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }
}

/// Остановка на `n`-м событии `Written` (примерно середина передачи).
pub fn gate_after_written(hook: &TestHook, n: usize) -> Arc<Gate> {
    let gate = Gate::new();
    let g = gate.clone();
    let mut count = 0usize;
    hook.set(move |ev| {
        if matches!(ev, Ev::Written(..)) {
            count += 1;
            if count == n {
                g.hold();
            }
        }
        Ok(())
    });
    gate
}

/// Два узла-друга с передачами и их соединение в памяти.
pub struct Rig {
    pub a: Peer,
    pub b: Peer,
    pub pa: PairId,
    pub pb: PairId,
    /// Текущее соединение (концы у A и B).
    pub cur: (FakeConn, FakeConn),
}

impl Rig {
    pub async fn new() -> Rig {
        Self::with(|_| {}, |_| {}).await
    }

    pub async fn with(
        fa: impl FnOnce(&mut TransferConfig),
        fb: impl FnOnce(&mut TransferConfig),
    ) -> Rig {
        let mut pre_a = Pre::new();
        let mut pre_b = Pre::new();
        let (pa, pb) = befriend(&mut pre_a, &mut pre_b);
        let (na, nb) = (Node::start(pre_a), Node::start(pre_b));
        let (da, db) = (TestDir::new(), TestDir::new());
        let (dest_a, dest_b) = (TestDir::new(), TestDir::new());
        let (mut ca, mut cb) = (small_cfg(da.path()), small_cfg(db.path()));
        fa(&mut ca);
        fb(&mut cb);
        let a = Peer::start(na, da, dest_a, ca);
        let b = Peer::start(nb, db, dest_b, cb);
        let (ca, cb) = (FakeConn::lonely(pa), FakeConn::lonely(pb));
        let mut rig = Rig {
            a,
            b,
            pa,
            pb,
            cur: (ca, cb),
        };
        rig.cur = rig.link().await;
        rig
    }

    /// Новое соединение между узлами; ждёт, пока оба движка его приняли.
    pub async fn link(&self) -> (FakeConn, FakeConn) {
        self.link_ids(None).await
    }

    /// `link` с заданными номерами концов (A, B).
    pub async fn link_ids(&self, ids: Option<(u64, u64)>) -> (FakeConn, FakeConn) {
        let (ca, cb) = FakeConn::pair_ids(
            self.pa,
            addr("198.51.100.20:4000"),
            self.pb,
            addr("198.51.100.10:4000"),
            ids,
        );
        self.a.node.t.push_incoming(ca.clone());
        self.b.node.t.push_incoming(cb.clone());
        for _ in 0..500 {
            let ok_a = self
                .a
                .node
                .engine
                .connection(&self.pa)
                .is_some_and(|c| c.conn_id() == ca.conn_id());
            let ok_b = self
                .b
                .node
                .engine
                .connection(&self.pb)
                .is_some_and(|c| c.conn_id() == cb.conn_id());
            if ok_a && ok_b {
                return (ca, cb);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("connection was not accepted");
    }

    /// Закрывает текущее соединение, ждёт, пока оба движка его сняли, и ставит новое с заданными
    /// номерами концов.
    pub async fn relink_ids(&mut self, ids: (u64, u64)) {
        self.cur.0.close();
        for _ in 0..500 {
            if self.a.node.engine.connection(&self.pa).is_none()
                && self.b.node.engine.connection(&self.pb).is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.cur = self.link_ids(Some(ids)).await;
    }
}

// --------------------------------------------------------------------- данные

/// Псевдослучайные байты (xorshift64*), одни и те же для одного зерна.
pub fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let take = (n - out.len()).min(8);
        out.extend_from_slice(&v[..take]);
    }
    out
}

pub fn write_src(dir: &Path, name: &str, data: &[u8]) -> SourceFile {
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    SourceFile {
        path,
        name: name.to_owned(),
    }
}

// ---------------------------------------------------------------------- события

pub async fn wait_ev(
    ev: &mut TransferEvents,
    secs: u64,
    f: impl Fn(&TransferEvent) -> bool,
) -> TransferEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ev.recv()).await {
            Ok(Some(e)) if f(&e) => return e,
            Ok(Some(_)) => {}
            _ => panic!("timed out waiting for event"),
        }
    }
}

/// Ждёт событие; `None` по истечении срока.
pub async fn try_ev(
    ev: &mut TransferEvents,
    ms: u64,
    f: impl Fn(&TransferEvent) -> bool,
) -> Option<TransferEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ev.recv()).await {
            Ok(Some(e)) if f(&e) => return Some(e),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

/// Все события, доступные сразу.
pub async fn drain(ev: &mut TransferEvents) -> Vec<TransferEvent> {
    let mut out = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::ZERO, ev.recv()).await {
        out.push(e);
    }
    out
}

pub fn is_completed(key: TransferKey) -> impl Fn(&TransferEvent) -> bool {
    move |e| matches!(e, TransferEvent::Completed { key: k } if *k == key)
}

pub fn is_offer() -> impl Fn(&TransferEvent) -> bool {
    |e| matches!(e, TransferEvent::OfferReceived { .. })
}

pub fn key_of(e: &TransferEvent) -> TransferKey {
    match e {
        TransferEvent::OfferReceived { key }
        | TransferEvent::OfferAnswered { key, .. }
        | TransferEvent::Started { key }
        | TransferEvent::Progress { key, .. }
        | TransferEvent::Verifying { key }
        | TransferEvent::Preparing { key, .. }
        | TransferEvent::FileReceived { key, .. }
        | TransferEvent::FileDelivered { key, .. }
        | TransferEvent::FileFailed { key, .. }
        | TransferEvent::Paused { key, .. }
        | TransferEvent::Resumed { key }
        | TransferEvent::Completed { key }
        | TransferEvent::Cancelled { key, .. }
        | TransferEvent::Failed { key, .. } => *key,
    }
}

/// Итоговые файлы в каталоге назначения: имя -> содержимое.
pub fn placed_files(dest: &TestDir) -> Vec<(String, Vec<u8>)> {
    dest.list()
        .into_iter()
        .map(|n| {
            let d = std::fs::read(dest.path().join(&n)).unwrap();
            (n, d)
        })
        .collect()
}

// -------------------------------------------------------------- провод (враждебный узел)

pub async fn send_frame(tx: &mut FakeTx, m: &Message) {
    let mut out = Vec::new();
    encode(m, &mut out).unwrap();
    tx.write_all(&out).await.unwrap();
}

pub async fn recv_frame(rx: &mut FakeRx, secs: u64) -> Option<Message> {
    let mut buf = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(secs),
        read_message(rx, &mut buf, Duration::from_secs(secs)),
    )
    .await
    .ok()?
    .ok()?
}

pub fn ok_or_panic<T>(x: Option<T>) -> T {
    x.expect("expected a value")
}

/// Права друга для `Permission::AutoAccept` (проверка «всегда спрашивать»).
pub fn auto_accept() -> Permission {
    Permission::AutoAccept(chervo_friends::AutoAcceptLimits {
        max_total_bytes: 1 << 30,
        max_files: 100,
    })
}
