//! Узел: одна потокобезопасная точка входа для оболочек (GUI, CLI) (этап 18а,
//! решение D1). Ключи в хранилище ОС, список друзей с якорем против отката, транспорт quinn,
//! движок соединений, передачи, безопасный приём; UPnP только по согласию пользователя, сверка
//! часов только по кнопке. Поведение берётся из прежних этапов, своих правил тут нет.
//!
//! Все публичные методы синхронные и могут блокироваться (например, до 12 с на Secret Service):
//! оболочка вызывает их из своего рабочего потока, не из потока интерфейса. Фоновая среда
//! tokio живёт в отдельном потоке узла.

mod core;
mod error;
mod events;
mod folder;
mod friends;
mod network;
mod profile;
mod runtime;
mod settings;
mod store;
mod testing;
#[cfg(test)]
mod tests;
pub mod texts;
mod transfers;
mod views;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::PortMapper;
use chervo_connect::{
    AllowSet, Clock, ConnectConfig, Engine, EngineEvents, RouteProbe, SystemClock, SystemProbe,
};
use chervo_friends::FriendBook;
use chervo_identity::EpochStore;
use chervo_receive::{ReceiveConfig, ReceivePlacement, ReceivePolicy, ReceiveRoot};
use chervo_transfer::{
    STREAM_TRANSFER_CTL, STREAM_TRANSFER_DATA, TransferConfig, TransferEvents, Transfers,
};
use chervo_transport::PeerFilter;
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use chervo_upnp::{UpnpMapper, UpnpSettings};
use tokio::runtime::Handle;

pub use chervo_addr::{MapStatus, NatView};
pub use chervo_connect::{ConnectError, InviteOutcome, NoDirectPath, PathKind};
pub use chervo_friends::{FriendsError, TrustConfirmation};
pub use chervo_receive::{ReceiveLimits, RootError};
pub use chervo_timesync::SyncError;
pub use chervo_transfer::{FailReason, PauseReason, Side, TransferError, TransferState};
pub use chervo_upnp::UpnpError;

pub use self::error::NodeError;
pub use self::events::{NodeEvent, NodeEvents};
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub use self::settings::fuzz_settings;
#[doc(hidden)]
pub use self::store::KeyBackend;
pub use self::store::KeyStoreKind;
#[doc(hidden)]
pub use self::testing::TestOpen;
pub use self::views::{
    AddrToken, ClockProposal, ClockSync, DiagnosisView, FileKind, FriendRef, FriendStatus,
    FriendView, IncomingOffer, InviteRef, NodeWarning, OfferFile, RevocationText, RouterCandidate,
    RouterView, SasView, SettingsView, SpaceView, TransferRef, TransferResult, TransferView,
};

use self::core::{Core, Eng, LiveConfig, Registry, lock, pump};
use self::events::EventSink;
use self::profile::InstanceLock;
use self::runtime::RtThread;
use self::settings::Settings;
use self::store::NodeStore;
use crate::HardenReport;

/// Настройки запуска. `Debug` без путей и портов (путь содержит имя пользователя, этап 17, B3).
#[derive(Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// Каталог данных; `None`: каталог профиля пользователя (абсолютные переменные окружения).
    pub data_dir: Option<PathBuf>,
    pub receive_limits: ReceiveLimits,
    /// Порт вместо хранимого в настройках (тесты, ручная проверка).
    pub port_override: Option<u16>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("receive_limits", &self.receive_limits)
            .finish_non_exhaustive()
    }
}

/// Предел вставленного текста (приглашение, токен адреса, текст отзыва), байт. Длиннее:
/// `InputTooLong` до любого разбора (инвариант 5).
pub(crate) const MAX_INPUT_BYTES: usize = 4096;
/// Предел ожидания снятия проброса при выходе.
const RELEASE_BOUND: Duration = Duration::from_secs(8);
/// Срок остановки передач при `Drop` без `shutdown`.
const DROP_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    Normal,
    AcceptOlder,
    StartOver,
}

/// Откуда берётся хранилище ключей. В продукте только `Os`; `Given` строит одна функция
/// `testing.rs`.
pub(crate) enum StoreSource {
    Os,
    Given(Arc<dyn KeyBackend>),
}

/// Запущенный узел. Не клонируется. `Send + Sync`.
pub struct Node {
    pub(crate) core: Arc<Core>,
    rt: Mutex<Option<RtThread>>,
    stopped: AtomicBool,
    /// Замок единственного экземпляра: последним в списке полей, снимается после остановки.
    _lock: InstanceLock,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Node(..)")
    }
}

fn map_bind(e: &std::io::Error) -> NodeError {
    use std::io::ErrorKind::{AddrInUse, AddrNotAvailable, PermissionDenied};
    match e.kind() {
        AddrInUse | AddrNotAvailable | PermissionDenied => NodeError::PortInUse,
        _ => NodeError::Io,
    }
}

/// Случайный порт из динамического диапазона (не криптография: порт открыт и так).
fn random_port() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let span = u64::from(u16::MAX) - 49_152 + 1;
    49_152 + u16::try_from(r % span).unwrap_or(0)
}

/// Свободный (на момент проверки) UDP-порт для нового узла.
fn pick_port() -> u16 {
    for _ in 0..32 {
        let p = random_port();
        if UdpSocket::bind((Ipv4Addr::UNSPECIFIED, p)).is_ok() {
            return p;
        }
    }
    random_port()
}

/// Настройки движка соединений из настроек узла. Здесь же (и только здесь) позже подключается
/// параметр поиска в локальной сети из этапа 13в.
fn connect_config(s: &Settings) -> ConnectConfig {
    ConnectConfig {
        manual_forward: s.manual_forward,
        ..ConnectConfig::default()
    }
}

fn open_store(src: StoreSource) -> Result<Arc<NodeStore>, NodeError> {
    match src {
        StoreSource::Os => {
            let os = chervo_identity::OsKeyStore::open().map_err(|_| NodeError::KeyStoreLocked)?;
            let backend: Arc<dyn KeyBackend> = Arc::new(os);
            Ok(Arc::new(NodeStore::new(backend, KeyStoreKind::of_os())))
        }
        StoreSource::Given(b) => Ok(Arc::new(NodeStore::new(b, KeyStoreKind::Test))),
    }
}

fn receive_config(root: &Path, limits: ReceiveLimits, s: &Settings) -> ReceiveConfig {
    let mut rc = ReceiveConfig::new(root.to_path_buf());
    rc.limits = limits;
    rc.min_free_percent = s.min_free_percent;
    rc.allow_shared_root = s.shared_root_confirmed;
    rc
}

impl Node {
    /// Первый запуск (или явная смена папки приёма после `ReceiveRoot`-ошибки при запуске):
    /// проверяет папку приёма (`ReceiveRoot::open`: вне профиля Windows нужно
    /// `confirm_shared_root`) и записывает настройки. Порт выбирается случайно в 49152..=65535
    /// один раз и дальше не меняется. Ключей не создаёт.
    ///
    /// Если настройки уже есть и читаются, заменяются только папка приёма и подтверждение:
    /// прежняя основная папка остаётся в списке дополнительных (недокачанные там передачи не
    /// теряются). Испорченный файл настроек остаётся как есть (`SettingsCorrupt`).
    pub fn first_run_setup(
        cfg: &NodeConfig,
        h: &HardenReport,
        root: &Path,
        confirm_shared_root: bool,
    ) -> Result<(), NodeError> {
        let _ = h;
        let dir = profile::resolve_data_dir(cfg.data_dir.as_deref())?;
        let _lock = InstanceLock::acquire(&dir)?;
        let mut rc = ReceiveConfig::new(root.to_path_buf());
        rc.limits = cfg.receive_limits;
        rc.allow_shared_root = confirm_shared_root;
        ReceiveRoot::open(&rc).map_err(NodeError::ReceiveRoot)?;
        let new = match settings::load(&dir)? {
            None => Settings::new(
                cfg.port_override
                    .filter(|p| *p != 0)
                    .unwrap_or_else(pick_port),
                root.to_path_buf(),
                confirm_shared_root,
            ),
            Some(mut s) => {
                settings::replace_root(&mut s, root, confirm_shared_root);
                s
            }
        };
        settings::save(&dir, &new)
    }

    pub fn open(cfg: NodeConfig, h: &HardenReport) -> Result<(Node, NodeEvents), NodeError> {
        open_node(cfg, h, OpenMode::Normal, StoreSource::Os)
    }

    /// Явный выбор пользователя после `RolledBack`: принять старый список.
    pub fn open_accept_older(
        cfg: NodeConfig,
        h: &HardenReport,
    ) -> Result<(Node, NodeEvents), NodeError> {
        open_node(cfg, h, OpenMode::AcceptOlder, StoreSource::Os)
    }

    /// Явный выбор пользователя после `KeysLost` (или нечитаемого списка): начать заново. Старый
    /// файл сохраняется как `friends.chfl.unreadable-<t>`.
    pub fn open_start_over(
        cfg: NodeConfig,
        h: &HardenReport,
    ) -> Result<(Node, NodeEvents), NodeError> {
        open_node(cfg, h, OpenMode::StartOver, StoreSource::Os)
    }

    /// Явный выбор пользователя после `SettingsCorrupt`: убрать файл настроек в сторону
    /// (`settings.v1.bad-<t>`). Дальше запуск начнётся как первый (`FirstRun`).
    pub fn reset_settings(cfg: &NodeConfig, h: &HardenReport) -> Result<(), NodeError> {
        let _ = h;
        let dir = profile::resolve_data_dir(cfg.data_dir.as_deref())?;
        let _lock = InstanceLock::acquire(&dir)?;
        settings::set_aside(&dir, profile::now_unix())
    }

    /// Только по нажатию кнопки (Linux): просит Secret Service разблокировать коллекцию (рабочий
    /// стол может показать окно пароля). `wait` ограничивается 1..=300 с. Другие ОС:
    /// `Unsupported`.
    pub fn request_unlock(cfg: &NodeConfig, wait: Duration) -> Result<(), NodeError> {
        let _ = cfg;
        #[cfg(target_os = "linux")]
        {
            let os = chervo_identity::OsKeyStore::open().map_err(|_| NodeError::KeyStoreLocked)?;
            os.request_unlock(wait)
                .map_err(|_| NodeError::KeyStoreLocked)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = wait;
            Err(NodeError::Unsupported)
        }
    }

    /// Будильник: вызывается после каждого события (GUI просит перерисовку). Он выполняется на
    /// фоновом потоке узла: должен быть быстрым и не вызывать методы `Node` (взаимная
    /// блокировка).
    pub fn set_waker(&self, w: Box<dyn Fn() + Send + Sync>) {
        self.core.sink.set_waker(w);
    }

    /// Упорядоченная остановка: передачи, движок, транспорт, снятие проброса (до 8 с), затем
    /// фоновая среда и замок. Не дольше `deadline` на передачи плюс 8 с на проброс.
    pub fn shutdown(self, deadline: Duration) {
        self.stop(deadline);
    }

    fn stop(&self, deadline: Duration) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let core = self.core.clone();
        let _ = runtime::run(&self.core.rt, async move {
            core.transfers.shutdown();
            let _ = tokio::time::timeout(deadline, core.transfers.wait_stopped()).await;
            core.engine.shutdown();
            core.transport.shutdown();
        });
        // проброс снимается явно: движок сам `release` при выходе не вызывает
        let mapper = lock(&self.core.mapper).take();
        if let Some(m) = mapper {
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::Builder::new()
                .name("chervo-release".to_owned())
                .spawn(move || {
                    m.release();
                    let _ = tx.send(());
                });
            if worker.is_ok() {
                let _ = rx.recv_timeout(RELEASE_BOUND);
            }
        }
        self.core.sink.emit(NodeEvent::Stopped);
        if let Some(mut rt) = lock(&self.rt).take() {
            rt.stop();
        }
    }

    pub(crate) fn enter(&self) -> tokio::runtime::EnterGuard<'_> {
        self.core.rt.enter()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop(DROP_DEADLINE);
    }
}

/// Общий путь запуска (`open*` и тестовый вход).
pub(crate) fn open_node(
    cfg: NodeConfig,
    h: &HardenReport,
    mode: OpenMode,
    src: StoreSource,
) -> Result<(Node, NodeEvents), NodeError> {
    // доказательство, что укрепление процесса выполнено до загрузки ключей
    let _ = h;
    let dir = profile::resolve_data_dir(cfg.data_dir.as_deref())?;
    let lock_guard = InstanceLock::acquire(&dir)?;
    let st = settings::load(&dir)?.ok_or(NodeError::FirstRun)?;
    let store = open_store(src)?;

    let path = profile::friends_path(&dir);
    let anchor: Arc<dyn EpochStore> = store.clone();
    let book = match mode {
        OpenMode::Normal => FriendBook::open_anchored(&path, &*store, anchor),
        OpenMode::AcceptOlder => FriendBook::accept_older(&path, &*store, anchor),
        OpenMode::StartOver => {
            FriendBook::start_over_anchored(&path, &*store, anchor, profile::now_unix())
        }
    }
    .map_err(NodeError::from)?;

    // папка приёма проверяется до запуска сети: плохая папка не должна оставлять открытый порт
    let rcfg = receive_config(&st.receive_root, cfg.receive_limits, &st);
    let root = ReceiveRoot::open(&rcfg).map_err(NodeError::ReceiveRoot)?;

    let (sink, node_events) = EventSink::channel();
    let rt = RtThread::start()?;
    let built = {
        let _g = rt.handle.enter();
        let parts = Parts {
            dir,
            settings: st,
            store,
            book,
            rcfg,
            root,
            sink,
            handle: rt.handle.clone(),
        };
        build_core(&cfg, parts)
    };
    let (core, events, tevents, warnings) = match built {
        Ok(v) => v,
        Err(e) => {
            let mut rt = rt;
            rt.stop();
            return Err(e);
        }
    };
    for w in warnings {
        core.warn(w);
    }
    drop(rt.handle.spawn(pump(core.clone(), events, tevents)));
    let node = Node {
        core,
        rt: Mutex::new(Some(rt)),
        stopped: AtomicBool::new(false),
        _lock: lock_guard,
    };
    Ok((node, node_events))
}

/// Всё, что готово к запуску сети.
struct Parts {
    dir: PathBuf,
    settings: Settings,
    store: Arc<NodeStore>,
    book: FriendBook,
    rcfg: ReceiveConfig,
    root: ReceiveRoot,
    sink: Arc<EventSink>,
    handle: Handle,
}

type Built = (Arc<Core>, EngineEvents, TransferEvents, Vec<NodeWarning>);

/// Запуск сети внутри фоновой среды (вызывается под `Handle::enter`): транспорт, часы, движок,
/// проброс (только если есть разрешённый роутер), передачи, известные папки приёма.
fn build_core(cfg: &NodeConfig, p: Parts) -> Result<Built, NodeError> {
    let Parts {
        dir,
        settings: st,
        store,
        book,
        rcfg,
        root,
        sink,
        handle,
    } = p;
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let port = cfg.port_override.unwrap_or(st.port);
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .map_err(|e| map_bind(&e))?;
    let transport = Arc::new(
        QuinnTransport::from_socket(sock, QuinnConfig::default(), filter)
            .map_err(|_| NodeError::Io)?,
    );
    // поправка часов, сохранённая кнопкой «Сверить часы», действует и на часы движка, и на стук
    let clock = Arc::new(SystemClock::new());
    clock
        .set_offset_ms(st.clock_offset_ms)
        .map_err(|_| NodeError::SettingsCorrupt)?;
    transport
        .set_clock_offset(st.clock_offset_ms)
        .map_err(|_| NodeError::SettingsCorrupt)?;
    let probe = Arc::new(SystemProbe);
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let probe_dyn: Arc<dyn RouteProbe> = probe.clone();
    let (engine, events) = Engine::start(
        transport.clone(),
        allow,
        book,
        store.clone(),
        clock_dyn,
        probe_dyn,
        connect_config(&st),
    )
    .map_err(NodeError::from)?;
    let engine: Arc<Eng> = Arc::new(engine);

    // проброс: ни одного пакета, пока пользователь не разрешил хотя бы один роутер
    let mapper = if st.routers.is_empty() {
        None
    } else {
        let m = Arc::new(UpnpMapper::new(UpnpSettings {
            routers: st.routers.clone(),
        }));
        let dynamic: Arc<dyn PortMapper> = m.clone();
        engine.attach_mapper(dynamic).map_err(NodeError::from)?;
        Some(m)
    };

    let inbox = engine
        .stream_inbox(&[STREAM_TRANSFER_CTL, STREAM_TRANSFER_DATA])
        .map_err(NodeError::from)?;
    let placement = Arc::new(ReceivePlacement::new(root.clone(), &rcfg));
    let policy = Arc::new(ReceivePolicy::new(root.clone(), &rcfg));
    let mut tcfg = TransferConfig::new(root.partial_dir().to_path_buf());
    tcfg.progress_interval = Duration::from_millis(500);
    // `offer_relink_grace` и остальное: значения по умолчанию этапа 14б (2 минуты)
    let (transfers, tevents) = Transfers::start(
        engine.clone(),
        inbox,
        policy.clone(),
        placement.clone(),
        tcfg,
    )
    .map_err(NodeError::from)?;

    // папки, куда принимались отдельные предложения: иначе их недокачанные передачи не найдутся
    // после перезапуска (SECURITY_REVIEW разд. 8)
    let mut warnings = Vec::new();
    for extra in &st.extra_roots {
        let mut c = rcfg.clone();
        c.root = extra.clone();
        match ReceiveRoot::open(&c) {
            Ok(r) => placement.add_known_root(r),
            Err(_) => {
                if !warnings.contains(&NodeWarning::RootUnavailable) {
                    warnings.push(NodeWarning::RootUnavailable);
                }
            }
        }
    }

    let live = LiveConfig {
        port_setting: st.port,
        receive_root: st.receive_root.clone(),
        min_free_percent: st.min_free_percent,
        manual_forward: st.manual_forward,
    };
    let core = Arc::new(Core {
        rt: handle,
        dir,
        engine,
        transport,
        store,
        clock,
        probe,
        transfers,
        placement,
        policy,
        rcfg,
        root,
        sink,
        settings: Mutex::new(st),
        live,
        reg: Mutex::new(Registry::default()),
        mapper: Mutex::new(mapper),
    });
    Ok((core, events, tevents, warnings))
}
