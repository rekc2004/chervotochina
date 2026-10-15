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
use chervo_transport::{PeerAddr, PeerFilter, Transport, TransportError};
use tokio::sync::{Semaphore, broadcast, mpsc};

pub use conn::{QuinnConn, QuinnRecv, QuinnSend};

use limits::{Counters, IpLimiter, KkGate};
use registry::Registry;

pub const ALPN: &[u8] = b"chervo/1";
pub const SERVER_NAME: &str = "chervo.invalid";
pub const EKM_LABEL: &[u8] = b"EXPERIMENTAL-chervotochina-conn-kk-v1";
pub const EKM_CONTEXT: &[u8] = b"";
/// Любой отказ и обычное закрытие; причина всегда пустая.
pub const CLOSE_REFUSED: u32 = 0;
/// Только аутентифицированному собеседнику.
pub const CLOSE_DUPLICATE: u32 = 1;

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
    /// Одновременных переборов KK; при использовании ограничивается `[1, max_preauth]`.
    pub max_kk_trials: usize,
    /// Кандидатов в секунду (глобально).
    pub kk_budget_per_sec: u32,
    /// Кандидатов в ведре; при использовании не меньше 1.
    pub kk_budget_burst: u32,
    pub max_incoming: usize,
    pub incoming_buffer: u64,
    pub incoming_buffer_total: u64,
    /// Окно соединения до KK.
    pub preauth_receive_window: u32,
    /// Потоков после KK (однонаправленных всегда 0, датаграммы выключены).
    pub post_auth_bidi: u32,
    pub idle_timeout: Duration,
    pub keep_alive: Duration,
    /// Готовых соединений в очереди `accept`; переполнено: закрыть новое.
    pub accept_queue: usize,
    pub addr_poll: Duration,
}

impl Default for QuinnConfig {
    fn default() -> Self {
        Self {
            auth_deadline: Duration::from_secs(10),
            per_ip_max: 5,
            per_ip_window: Duration::from_secs(10),
            limiter_capacity: 4096,
            max_preauth: 32,
            max_kk_trials: 1,
            kk_budget_per_sec: 2000,
            kk_budget_burst: 2000,
            max_incoming: 128,
            incoming_buffer: 16 * 1024,
            incoming_buffer_total: 1024 * 1024,
            preauth_receive_window: 64 * 1024,
            post_auth_bidi: 16,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            accept_queue: 16,
            addr_poll: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportEvent {
    RemoteAddrChanged { pair: PairId },
    ConnectionReplaced { pair: PairId },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    pub retry_sent: u64,
    pub ignored_rate: u64,
    pub ignored_busy: u64,
    pub auth_ok: u64,
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
}

pub(crate) struct Inner {
    pub(crate) cfg: QuinnConfig,
    pub(crate) filter: Arc<dyn PeerFilter>,
    pub(crate) endpoint: quinn::Endpoint,
    peers: Mutex<Arc<Vec<KxPeer>>>,
    pub(crate) events: broadcast::Sender<TransportEvent>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) limiter: Mutex<IpLimiter>,
    pub(crate) preauth: Arc<Semaphore>,
    pub(crate) gate: KkGate,
    pub(crate) registry: Registry,
    pub(crate) queue_tx: mpsc::Sender<QuinnConn>,
    queue_rx: tokio::sync::Mutex<mpsc::Receiver<QuinnConn>>,
    pub(crate) client_quic: Arc<quinn::crypto::rustls::QuicClientConfig>,
    pub(crate) client_transport: Arc<quinn::TransportConfig>,
}

impl Inner {
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
        sock.set_nonblocking(true).map_err(|_| TransportError::Io)?;
        let base = tls::base_server_config(&cfg).map_err(|_| TransportError::Io)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(base),
            sock,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| TransportError::Io)?;
        let client_quic = tls::client_quic().map_err(|_| TransportError::Io)?;
        let client_transport = tls::pre_auth_transport(&cfg, tls::Role::Client);
        let counters = Arc::new(Counters::default());
        let (queue_tx, queue_rx) = mpsc::channel(cfg.accept_queue.max(1));
        let (events, _) = broadcast::channel(64);
        let inner = Arc::new(Inner {
            limiter: Mutex::new(IpLimiter::new(
                cfg.per_ip_max,
                cfg.per_ip_window,
                cfg.limiter_capacity,
            )),
            preauth: Arc::new(Semaphore::new(cfg.max_preauth.max(1))),
            gate: KkGate::new(&cfg, counters.clone()),
            registry: Registry::default(),
            peers: Mutex::new(Arc::new(Vec::new())),
            cfg,
            filter,
            endpoint,
            events,
            counters,
            queue_tx,
            queue_rx: tokio::sync::Mutex::new(queue_rx),
            client_quic,
            client_transport,
        });
        let looped = inner.clone();
        tokio::spawn(async move {
            while let Some(incoming) = looped.endpoint.accept().await {
                server::admit(&looped, incoming);
            }
        });
        Ok(Self { inner })
    }

    /// Атомарная замена набора пар.
    pub fn set_peers(&self, peers: Vec<KxPeer>) {
        *self
            .inner
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(peers);
    }

    pub fn rebind(&self, sock: std::net::UdpSocket) -> Result<(), TransportError> {
        sock.set_nonblocking(true).map_err(|_| TransportError::Io)?;
        self.inner
            .endpoint
            .rebind(sock)
            .map_err(|_| TransportError::Io)
    }

    pub fn events(&self) -> broadcast::Receiver<TransportEvent> {
        self.inner.events.subscribe()
    }

    pub fn stats(&self) -> TransportStats {
        self.inner.counters.snapshot()
    }

    pub fn shutdown(&self) {
        self.inner
            .endpoint
            .close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
    }
}

impl Drop for QuinnTransport {
    fn drop(&mut self) {
        self.shutdown();
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
