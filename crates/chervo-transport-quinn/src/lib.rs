//! Адаптер транспорта на quinn: одно UDP-гнездо для приёма и звонков, одноразовый ключ TLS 1.3
//! на каждое соединение, аутентификация Noise KK (`chervo-identity`), привязанная к экспортёру
//! TLS, без метки пары в сети, с лимитами до аутентификации и одинаковым отказом.
//! Спецификация: `docs/specs/stage-09-transport.md`.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod client;
mod conn;
#[cfg(any(test, feature = "fuzzing"))]
mod fuzz_entry;
mod knock;
mod limits;
mod registry;
mod server;
mod tls;

#[cfg(test)]
mod tests;

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chervo_identity::{KxPeer, PairId};
use chervo_transport::{
    EventSource, ManagedTransport, PeerAddr, PeerFilter, Transport, TransportError,
};
use quinn::Runtime;
use tokio::sync::{Semaphore, broadcast, mpsc};

pub use chervo_transport::{DuplicatePairError, TransportEvent};
pub use conn::{QuinnConn, QuinnRecv, QuinnSend};
/// Этап 17, B6/C04, S1 L6: только для фаззинга (`fuzz/`, вне рабочего пространства) и тестов,
/// не для продукта: в продуктовой сборке (без свойства `fuzzing`) этих функций нет.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub use fuzz_entry::{fuzz_knock_admits, fuzz_knock_ready};
pub use knock::window_at;

use knock::{KnockSocket, KnockState};
use limits::{Counters, IpLimiter, KkGate, PreauthKeys, PreauthPairs};
use registry::Registry;

pub const ALPN: &[u8] = b"chervo/1";
pub const SERVER_NAME: &str = "chervo.invalid";
pub const EKM_LABEL: &[u8] = b"EXPERIMENTAL-chervotochina-conn-kk-v1";
pub const EKM_CONTEXT: &[u8] = b"";
/// Любой отказ и обычное закрытие; причина всегда пустая.
pub const CLOSE_REFUSED: u32 = 0;
/// Только аутентифицированному собеседнику.
pub const CLOSE_DUPLICATE: u32 = 1;
/// Длина окна «стука», секунд.
pub const KNOCK_WINDOW_SECS: u64 = 30;
/// Принимаются окна `w-1..=w+1`.
pub const KNOCK_ACCEPT_SPAN: u64 = 1;
/// Окна `w±2..=w±10` держатся как «подсказка»: верный стук в них не допускается, но отмечается.
pub const KNOCK_HINT_SPAN: u64 = 10;

/// Предел модуля поправки часов: 7 суток (как `max_abs_offset` в `chervo-timesync`).
pub const MAX_CLOCK_OFFSET_MS: i64 = 7 * 24 * 3600 * 1000;

/// Поправка часов вне `±MAX_CLOCK_OFFSET_MS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockOffsetError;

impl std::fmt::Display for ClockOffsetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("clock offset out of range (max 7 days)")
    }
}

impl std::error::Error for ClockOffsetError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuinnConfig {
    /// От `Incoming` (вызываемый) или от `connect` (звонящий) до конца KK.
    pub auth_deadline: Duration,
    /// Рукопожатий за окно с одного ключа лимитера.
    pub per_ip_max: u32,
    /// Окно лимитера; ключ: IPv4 целиком, IPv6 по /64, v4-mapped как IPv4.
    pub per_ip_window: Duration,
    /// Размер карты лимитера; при переполнении вытесняется давний ключ.
    pub limiter_capacity: usize,
    /// Соединений в работе до конца KK (семафор).
    pub max_preauth: usize,
    /// Срок от приёма QUIC (`Incoming`) до полного `msg1`; не больше `auth_deadline` (при
    /// использовании ограничивается им). Позже: единый отказ, как у остальных. По умолчанию 5 с:
    /// больше `KK_ATTEMPT_CAP` (3 с) плюс шаг гонки адресов, чтобы честный второй адрес звонящего
    /// не обрезался, пока первый молчит.
    pub msg1_deadline: Duration,
    /// Незавершённых (до конца KK) соединений на один ключ лимитера (IPv4 целиком, IPv6 по
    /// /64); не меньше 1. Сверх предела: молчание, как при занятом семафоре.
    pub max_preauth_per_key: usize,
    /// Незавершённых (до конца KK) соединений на одну пару допуска (пару, чей верный стук открыл
    /// допуск адреса); не меньше 1. Друг со многими ключами лимитера не занимает все места
    /// (этап 17, S2, L3). Сверх предела: молчание, как при занятом семафоре.
    pub max_preauth_per_pair: usize,
    /// Срок от отправки `msg2` до `msg3` и EOF; не больше `auth_deadline`. Друг с верным `msg1`,
    /// молчащий дальше, освобождает место через это время, а не через `auth_deadline`.
    pub msg3_deadline: Duration,
    /// Одновременных переборов KK; при использовании ограничивается `[1, max_preauth]`.
    pub max_kk_trials: usize,
    /// Кандидатов в секунду (глобально).
    pub kk_budget_per_sec: u32,
    /// Кандидатов в ведре; не меньше 1 и не меньше числа пар в `set_peers`.
    pub kk_budget_burst: u32,
    pub max_incoming: usize,
    pub incoming_buffer: u64,
    pub incoming_buffer_total: u64,
    /// Окно соединения до KK.
    pub preauth_receive_window: u32,
    /// Окно приёма одного потока (оба конца, с первого пакета). Пока идёт KK его ограничивает
    /// малое окно соединения; после KK действует оно и окно соединения ниже.
    pub stream_receive_window: u32,
    /// Окно приёма соединения после KK (заменяет `preauth_receive_window`): предел того, что
    /// недоверенный, но аутентифицированный друг может заставить нас держать в памяти.
    pub post_auth_receive_window: u32,
    /// Окно отправки соединения (оба конца, с первого пакета).
    pub send_window: u64,
    /// Потоков после KK (однонаправленных всегда 0, датаграммы выключены).
    pub post_auth_bidi: u32,
    pub idle_timeout: Duration,
    pub keep_alive: Duration,
    /// Готовых соединений в очереди `accept`; переполнено: закрыть новое.
    pub accept_queue: usize,
    pub addr_poll: Duration,
    /// До верного стука адрес не получает ни одного пакета; звонящий стучит перед QUIC.
    /// `false` только в тестах (сырые клиенты, проверяющие слой после стука).
    pub knock_required: bool,
    /// Жизнь допуска после верного стука.
    pub knock_admit_ttl: Duration,
    /// Подтверждённых `Incoming` на один допуск.
    pub knock_admit_attempts: u32,
    /// Пауза между стуком и первым пакетом QUIC.
    pub knock_lead: Duration,
    /// Досылка стука в моменты `resend`, `3*resend` после первого.
    pub knock_resend_after: Duration,
    /// Размер таблицы допуска (адресов); одна пара занимает не больше восьмой части.
    pub admit_capacity: usize,
    /// Записей кэша виденных стуков на одну пару (страховка памяти; сверх этого ещё
    /// не больше 32 nonce на пару и окно).
    pub replay_capacity: usize,
    /// Гонка адресов в одном `connect`: адрес `i` стартует через `i * connect_stagger`.
    pub connect_stagger: Duration,
    /// Не больше стольких различных адресов на один `connect` (остальные отбрасываются).
    pub max_race: usize,
}

/// Нижняя граница окон: размер окна соединения до KK по умолчанию.
const MIN_WINDOW: u32 = 64 * 1024;

impl QuinnConfig {
    /// Действующий срок до `msg1`: не больше срока всей аутентификации.
    pub(crate) fn msg1_deadline_eff(&self) -> Duration {
        self.msg1_deadline.min(self.auth_deadline)
    }

    /// Окна согласованы: `MIN_WINDOW <= stream_receive_window <= post_auth_receive_window`,
    /// `send_window >= MIN_WINDOW` и все представимы в `VarInt`.
    pub(crate) fn windows_valid(&self) -> bool {
        self.stream_receive_window >= MIN_WINDOW
            && self.stream_receive_window <= self.post_auth_receive_window
            && self.send_window >= u64::from(MIN_WINDOW)
            && quinn::VarInt::from_u64(self.send_window).is_ok()
    }
}

impl Default for QuinnConfig {
    fn default() -> Self {
        Self {
            auth_deadline: Duration::from_secs(10),
            per_ip_max: 5,
            per_ip_window: Duration::from_secs(10),
            limiter_capacity: 4096,
            max_preauth: 32,
            msg1_deadline: Duration::from_secs(5),
            max_preauth_per_key: 2,
            max_preauth_per_pair: 4,
            msg3_deadline: Duration::from_secs(3),
            max_kk_trials: 1,
            kk_budget_per_sec: 2000,
            kk_budget_burst: 2000,
            max_incoming: 128,
            incoming_buffer: 16 * 1024,
            incoming_buffer_total: 1024 * 1024,
            preauth_receive_window: 64 * 1024,
            stream_receive_window: 4 * 1024 * 1024,
            post_auth_receive_window: 16 * 1024 * 1024,
            send_window: 16 * 1024 * 1024,
            post_auth_bidi: 16,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            accept_queue: 16,
            addr_poll: Duration::from_secs(1),
            knock_required: true,
            knock_admit_ttl: Duration::from_secs(10),
            knock_admit_attempts: 2,
            knock_lead: Duration::from_millis(30),
            knock_resend_after: Duration::from_secs(1),
            admit_capacity: 1024,
            replay_capacity: 4096,
            connect_stagger: Duration::from_millis(250),
            max_race: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    pub retry_sent: u64,
    pub ignored_rate: u64,
    pub ignored_busy: u64,
    /// Звонки и ответы, прошедшие KK и допущенные реестром (победитель или проигравший дубль).
    pub auth_ok: u64,
    /// KK прошёл, но тройки уже нет в текущем наборе пар (`promote` -> `NotAllowed`).
    pub auth_not_admitted: u64,
    pub auth_failed: u64,
    pub auth_timeout: u64,
    pub duplicates_closed: u64,
    pub queue_full: u64,
    /// Запущенные переборы (замыкание начало работу).
    pub kk_trials: u64,
    /// Сумма списанных токенов (стоимость после ограничения burst).
    pub kk_candidates: u64,
    /// Максимум одновременно идущих переборов.
    pub kk_trials_peak: u64,
    /// Отказы ворот: бюджет или дедлайн до старта перебора.
    pub kk_denied: u64,
    /// Допуски по верному стуку.
    pub knock_ok: u64,
    /// Стук с известным `id`, но неверным тегом.
    pub knock_bad: u64,
    /// Повторный стук (nonce уже виден).
    pub knock_replay: u64,
    /// Верный стук в окне «подсказки» (часы расходятся).
    pub knock_skewed: u64,
    /// Принятые гнездом записи недопущенных адресов (не переданы quinn).
    pub dropped_unadmitted: u64,
    /// Переполнение таблицы допуска или кэша повторов.
    pub admit_full: u64,
    /// Подтверждённый `Incoming` без допуска или сверх числа попыток.
    pub admit_exhausted: u64,
    /// Попытки звонка, на которые не пришло ни одного пакета.
    pub connect_silent: u64,
    /// Живые соединения, закрытые из-за `set_peers` без их тройки.
    pub removed_closed: u64,
    /// Серии повторных стуков (`reknock`), реально запущенные (с объединением вызовов).
    pub reknock_runs: u64,
    /// Установленные соединения гонки, закрытые отказом до KK (проиграли первому).
    pub race_losers: u64,
}

/// Только тесты: детерминированная гонка между концом KK и `promote`.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct PromoteHook {
    /// Соединение дошло до `promote` и ждёт.
    pub(crate) reached: Arc<tokio::sync::Notify>,
    /// Разрешение продолжить.
    pub(crate) proceed: Arc<tokio::sync::Notify>,
}

/// Только тесты: пауза `set_peers` после смены ключей стука и до смены реестра.
#[cfg(test)]
pub(crate) struct SetPeersHook {
    /// Вызов дошёл до паузы.
    pub(crate) reached: std::sync::mpsc::Sender<()>,
    /// Разрешение продолжить.
    pub(crate) proceed: std::sync::mpsc::Receiver<()>,
}

pub(crate) struct Inner {
    pub(crate) cfg: QuinnConfig,
    pub(crate) filter: Arc<dyn PeerFilter>,
    pub(crate) endpoint: quinn::Endpoint,
    pub(crate) peers: Mutex<Arc<Vec<KxPeer>>>,
    /// Крюк тестов гонки: пауза между концом KK и `promote`.
    #[cfg(test)]
    pub(crate) promote_hook: Mutex<Option<PromoteHook>>,
    pub(crate) events: broadcast::Sender<TransportEvent>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) knock: Arc<KnockState>,
    pub(crate) limiter: Mutex<IpLimiter>,
    pub(crate) preauth: Arc<Semaphore>,
    /// Незавершённые соединения по ключу лимитера (`max_preauth_per_key`).
    pub(crate) preauth_keys: Arc<PreauthKeys>,
    /// Незавершённые соединения по паре допуска (`max_preauth_per_pair`).
    pub(crate) preauth_pairs: Arc<PreauthPairs>,
    /// Один замок на всю смену набора пар: ворота, ключи стука и реестр меняются под ним
    /// вместе, параллельные `set_peers` не перемешиваются.
    pub(crate) peers_update: Mutex<()>,
    /// Крюк тестов: пауза внутри `set_peers` между ключами стука и реестром (срабатывает один раз).
    #[cfg(test)]
    pub(crate) set_peers_hook: Mutex<Option<SetPeersHook>>,
    pub(crate) gate: KkGate,
    pub(crate) registry: Registry,
    /// Пары с идущим исходящим звонком (не больше одного на пару).
    pub(crate) dialing: Mutex<std::collections::HashSet<PairId>>,
    /// Объединение повторных стуков: (серия идёт, нужен ещё один прогон).
    pub(crate) reknock: Mutex<(bool, bool)>,
    pub(crate) queue_tx: mpsc::Sender<QuinnConn>,
    queue_rx: tokio::sync::Mutex<mpsc::Receiver<QuinnConn>>,
    pub(crate) client_quic: Arc<quinn::crypto::rustls::QuicClientConfig>,
    pub(crate) client_transport: Arc<quinn::TransportConfig>,
    /// Runtime, захваченный в `from_socket`: фоновые задачи (повторные стуки) создаются
    /// из любого потока, в том числе вне контекста tokio.
    pub(crate) rt: tokio::runtime::Handle,
}

impl Inner {
    /// Только тесты: если задан крюк, сообщить о подходе к `promote` и ждать разрешения.
    #[cfg(test)]
    pub(crate) async fn test_pause_before_promote(&self) {
        let hook = self
            .promote_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(h) = hook {
            h.reached.notify_one();
            h.proceed.notified().await;
        }
    }

    /// Только тесты: если задан крюк, сообщить о подходе к реестру и ждать разрешения.
    #[cfg(test)]
    pub(crate) fn test_pause_in_set_peers(&self) {
        let hook = self
            .set_peers_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = hook {
            let _ = h.reached.send(());
            let _ = h.proceed.recv_timeout(Duration::from_secs(10));
        }
    }

    pub(crate) fn peers_snapshot(&self) -> Arc<Vec<KxPeer>> {
        self.peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub struct QuinnTransport {
    inner: Arc<Inner>,
}

impl fmt::Debug for QuinnTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QuinnTransport(..)")
    }
}

impl QuinnTransport {
    /// Требует работающий tokio runtime. Одно гнездо для приёма и звонков.
    pub fn bind(
        addr: SocketAddr,
        cfg: QuinnConfig,
        filter: Arc<dyn PeerFilter>,
    ) -> Result<Self, TransportError> {
        let sock = std::net::UdpSocket::bind(addr).map_err(|_| TransportError::Io)?;
        Self::from_socket(sock, cfg, filter)
    }

    pub fn from_socket(
        sock: std::net::UdpSocket,
        cfg: QuinnConfig,
        filter: Arc<dyn PeerFilter>,
    ) -> Result<Self, TransportError> {
        let rt = tokio::runtime::Handle::try_current().map_err(|_| TransportError::Io)?;
        if !cfg.windows_valid() {
            return Err(TransportError::Io);
        }
        sock.set_nonblocking(true).map_err(|_| TransportError::Io)?;
        let base = tls::base_server_config(&cfg).map_err(|_| TransportError::Io)?;
        let counters = Arc::new(Counters::default());
        let (events, _) = broadcast::channel(64);
        let raw = quinn::TokioRuntime
            .wrap_udp_socket(sock)
            .map_err(|_| TransportError::Io)?;
        let knock = KnockState::new(
            &cfg,
            counters.clone(),
            filter.clone(),
            events.clone(),
            raw.clone(),
        );
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(base),
            Arc::new(KnockSocket::new(raw, knock.clone())),
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| TransportError::Io)?;
        let client_quic = tls::client_quic().map_err(|_| TransportError::Io)?;
        let client_transport =
            tls::pre_auth_transport(&cfg, tls::Role::Client).map_err(|_| TransportError::Io)?;
        let (queue_tx, queue_rx) = mpsc::channel(cfg.accept_queue.max(1));
        let inner = Arc::new(Inner {
            limiter: Mutex::new(IpLimiter::new(
                cfg.per_ip_max,
                cfg.per_ip_window,
                cfg.limiter_capacity,
            )),
            preauth: Arc::new(Semaphore::new(cfg.max_preauth.max(1))),
            preauth_keys: PreauthKeys::new(cfg.max_preauth_per_key),
            preauth_pairs: PreauthPairs::new(cfg.max_preauth_per_pair),
            peers_update: Mutex::new(()),
            #[cfg(test)]
            set_peers_hook: Mutex::new(None),
            gate: KkGate::new(&cfg, counters.clone()),
            registry: Registry::default(),
            dialing: Mutex::new(std::collections::HashSet::new()),
            reknock: Mutex::new((false, false)),
            peers: Mutex::new(Arc::new(Vec::new())),
            #[cfg(test)]
            promote_hook: Mutex::new(None),
            cfg,
            filter,
            endpoint,
            events,
            counters,
            knock,
            queue_tx,
            queue_rx: tokio::sync::Mutex::new(queue_rx),
            client_quic,
            client_transport,
            rt,
        });
        let looped = inner.clone();
        tokio::spawn(async move {
            while let Some(incoming) = looped.endpoint.accept().await {
                server::admit(&looped, incoming);
            }
        });
        Ok(Self { inner })
    }

    /// Атомарная замена набора пар. Ёмкость бюджета перебора не меньше числа пар
    /// (`kk_budget_burst` меньше этого числа поднимается, иначе стоимость обрезалась бы).
    ///
    /// Ворота, ключи стука и реестр меняются под одним замком (`peers_update`): вызов,
    /// вернувшийся после удаления друга, не оставляет ему ни стука, ни записи в наборе.
    ///
    /// Живые соединения, чьей тройки `(пара, наш X25519, X25519 собеседника)` нет в новом
    /// наборе, закрываются отказом с пустой причиной (событие `PeerRemoved`, счётчик
    /// `removed_closed`). Порядок замков: реестр, затем набор пар; соединения закрываются
    /// после снятия замков.
    ///
    /// `PairId` в наборе уникален: повтор отвергается целиком (`DuplicatePairError`), прежний
    /// набор остаётся. Иначе тройка соединения, найденная по `PairId`, могла бы оказаться
    /// не той записью, с которой прошёл KK (гость записался бы как друг).
    pub fn set_peers(&self, peers: Vec<KxPeer>) -> Result<(), DuplicatePairError> {
        let mut seen = std::collections::HashSet::with_capacity(peers.len());
        if !peers.iter().all(|p| seen.insert(p.pair())) {
            return Err(DuplicatePairError);
        }
        let removed = {
            // Весь набор меняется под одним замком: ни один вызов не видит и не оставляет
            // ключи стука одного набора рядом с реестром другого. Закрытие соединений и
            // события идут после снятия замка.
            let _update = self
                .inner
                .peers_update
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.inner.gate.set_min_burst(peers.len());
            self.inner.knock.set_peers(&peers);
            #[cfg(test)]
            self.inner.test_pause_in_set_peers();
            self.inner.registry.replace_peers(&self.inner.peers, peers)
        };
        for (pair, conn) in removed {
            conn::refuse(&conn);
            self.inner
                .counters
                .removed_closed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = self.inner.events.send(TransportEvent::PeerRemoved { pair });
        }
        Ok(())
    }

    /// Стук по каждому живому соединению с того же гнезда (тот же порт): вызывать после
    /// смены собственного адреса, когда гнездо остаётся; проброс порта и порт прослушивания
    /// не меняются. `rebind` нужен только когда само гнездо должно смениться.
    pub fn reknock(&self) {
        client::reknock_live(&self.inner);
    }

    pub fn rebind(&self, sock: std::net::UdpSocket) -> Result<(), TransportError> {
        sock.set_nonblocking(true).map_err(|_| TransportError::Io)?;
        let raw = quinn::TokioRuntime
            .wrap_udp_socket(sock)
            .map_err(|_| TransportError::Io)?;
        let wrapped = Arc::new(KnockSocket::new(raw.clone(), self.inner.knock.clone()));
        self.inner
            .endpoint
            .rebind_abstract(wrapped)
            .map_err(|_| TransportError::Io)?;
        self.inner.knock.set_tx(raw);
        client::reknock_live(&self.inner);
        Ok(())
    }

    /// Поправка часов (мс) к системному времени для стука; задаётся только отсюда
    /// (значение из кнопки «синхронизировать время»), сама никогда не меняется.
    /// Не больше `MAX_CLOCK_OFFSET_MS` по модулю, иначе ошибка и прежняя поправка.
    pub fn set_clock_offset(&self, offset_ms: i64) -> Result<(), ClockOffsetError> {
        if offset_ms.unsigned_abs() > MAX_CLOCK_OFFSET_MS.unsigned_abs() {
            return Err(ClockOffsetError);
        }
        self.inner.knock.set_offset(offset_ms);
        Ok(())
    }

    pub fn clock_offset_ms(&self) -> i64 {
        self.inner.knock.offset()
    }

    pub fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.inner.events.subscribe()
    }

    pub fn stats(&self) -> TransportStats {
        self.inner.counters.snapshot()
    }

    pub fn shutdown(&self) {
        // Обычное закрытие: тот же код и пустая причина, что у отказа.
        conn::close_endpoint(&self.inner.endpoint);
    }
}

impl Drop for QuinnTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Подписка на события `QuinnTransport` для `ManagedTransport`.
pub struct QuinnEvents(broadcast::Receiver<TransportEvent>);

impl fmt::Debug for QuinnEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QuinnEvents(..)")
    }
}

impl EventSource for QuinnEvents {
    async fn recv(&mut self) -> Option<TransportEvent> {
        match self.0.recv().await {
            Ok(e) => Some(e),
            Err(broadcast::error::RecvError::Lagged(_)) => Some(TransportEvent::Lagged),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

impl ManagedTransport for QuinnTransport {
    type Events = QuinnEvents;

    fn set_peers(&self, peers: Vec<KxPeer>) -> Result<(), DuplicatePairError> {
        QuinnTransport::set_peers(self, peers)
    }

    fn reknock(&self) {
        QuinnTransport::reknock(self);
    }

    fn subscribe(&self) -> Self::Events {
        QuinnEvents(self.inner.events.subscribe())
    }
}

impl Transport for QuinnTransport {
    type Conn = QuinnConn;

    fn local_addrs(&self) -> Vec<SocketAddr> {
        self.inner.endpoint.local_addr().into_iter().collect()
    }

    fn connect(
        &self,
        peer: &PeerAddr,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send {
        let inner = self.inner.clone();
        let peer = peer.clone();
        async move { client::connect(&inner, &peer).await }
    }

    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send {
        let inner = self.inner.clone();
        async move {
            inner
                .queue_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(TransportError::Closed)
        }
    }
}
