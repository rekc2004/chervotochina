//! Общие помощники модульных тестов: ключи, сырые клиенты и серверы.
//! Никакого вывода в stdout: печатающие тесты лежат в `tests/`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_identity::{
    IdentityError, KxPeer, KxPublicKey, PairId, PublicKey, SecretStore, create, load,
};
use chervo_transport::{PeerAddr, PeerFilter};
use zeroize::Zeroizing;

use crate::tls::{Role, client_config, client_quic, ephemeral_server_config, pre_auth_transport};
use crate::{QuinnConfig, QuinnTransport};

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
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

pub struct AllowAll;

impl PeerFilter for AllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

#[derive(Default)]
pub struct BlockSet(pub Mutex<HashSet<PairId>>);

impl PeerFilter for BlockSet {
    fn is_allowed(&self, pair: &PairId) -> bool {
        !self.0.lock().unwrap().contains(pair)
    }
}

/// Одна сторона пары: хранилище позволяет получать независимые копии `KxPeer`.
pub struct Side {
    pair: PairId,
    store: MemStore,
    public: PublicKey,
    pub kx_public: KxPublicKey,
}

impl Side {
    fn new(pair: PairId) -> Self {
        let store = MemStore::default();
        let key = create(&store, &pair).unwrap();
        let public = key.public_key();
        let kx_public = key.kx_public();
        Self {
            pair,
            store,
            public,
            kx_public,
        }
    }

    pub fn peer(&self, theirs: KxPublicKey) -> KxPeer {
        self.peer_as(self.pair, theirs)
    }

    /// Те же секреты, но под другим идентификатором пары.
    pub fn peer_as(&self, pair: PairId, theirs: KxPublicKey) -> KxPeer {
        let key = load(&self.store, &self.pair, &self.public).unwrap();
        KxPeer::new(pair, key.into_kx(), theirs)
    }
}

/// Пара друзей: ключи A и B, с возможностью многократно получать `KxPeer` каждой стороны.
pub struct Keys {
    pub pid: PairId,
    pub a: Side,
    pub b: Side,
}

impl Keys {
    pub fn new() -> Self {
        let pid = PairId::generate().unwrap();
        Self {
            pid,
            a: Side::new(pid),
            b: Side::new(pid),
        }
    }

    /// `KxPeer` стороны A (знает публичный ключ B).
    pub fn peer_a(&self) -> KxPeer {
        self.a.peer(self.b.kx_public)
    }

    pub fn peer_b(&self) -> KxPeer {
        self.b.peer(self.a.kx_public)
    }
}

/// Ключи «незнакомца», выдающего себя за пару `pid`: свои секреты, чужой публичный ключ друга.
pub fn stranger_peer(pid: PairId, theirs: KxPublicKey) -> KxPeer {
    Side::new(pid).peer(theirs)
}

pub fn lo() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub fn test_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

pub fn bind(cfg: QuinnConfig, peers: Vec<KxPeer>) -> QuinnTransport {
    bind_with(cfg, peers, Arc::new(AllowAll))
}

pub fn bind_with(
    cfg: QuinnConfig,
    peers: Vec<KxPeer>,
    filter: Arc<dyn PeerFilter>,
) -> QuinnTransport {
    let t = QuinnTransport::bind(lo(), cfg, filter).unwrap();
    t.set_peers(peers);
    t
}

pub fn addr_of(t: &QuinnTransport) -> SocketAddr {
    use chervo_transport::Transport;
    let a = t.local_addrs();
    SocketAddr::new("127.0.0.1".parse().unwrap(), a[0].port())
}

pub fn peer_addr(pair: PairId, t: &QuinnTransport) -> PeerAddr {
    PeerAddr {
        pair,
        addrs: vec![addr_of(t)],
    }
}

// ---------------------------------------------------------------------------------------------
// Сырые клиенты и серверы
// ---------------------------------------------------------------------------------------------

/// Эндпоинт клиента без серверной части.
pub fn raw_endpoint() -> quinn::Endpoint {
    let sock = std::net::UdpSocket::bind(lo()).unwrap();
    sock.set_nonblocking(true).unwrap();
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap()
}

pub fn raw_client_cfg() -> quinn::ClientConfig {
    let quic = client_quic().unwrap();
    let transport = pre_auth_transport(&QuinnConfig::default(), Role::Client).unwrap();
    client_config(&quic, &transport)
}

/// TLS-рукопожатие нашим клиентским конфигом, без KK.
pub async fn raw_tls(
    ep: &quinn::Endpoint,
    addr: SocketAddr,
) -> Result<quinn::Connection, quinn::ConnectionError> {
    ep.connect_with(raw_client_cfg(), addr, crate::SERVER_NAME)
        .unwrap()
        .await
}

/// Эндпоинт сервера: закрытый базовый конфиг; соединения принимает `serve_one`.
pub fn server_endpoint(cfg: &QuinnConfig) -> quinn::Endpoint {
    let sock = std::net::UdpSocket::bind(lo()).unwrap();
    sock.set_nonblocking(true).unwrap();
    let base = crate::tls::base_server_config(cfg).unwrap();
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(base),
        sock,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap()
}

pub fn ep_addr(ep: &quinn::Endpoint) -> SocketAddr {
    SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        ep.local_addr().unwrap().port(),
    )
}

/// Принять одно входящее с одноразовым ключом (после Retry) и вернуть соединение.
pub async fn serve_one(ep: &quinn::Endpoint, cfg: &QuinnConfig) -> quinn::Connection {
    loop {
        let incoming = ep.accept().await.unwrap();
        if !incoming.remote_address_validated() {
            incoming.retry().unwrap();
            continue;
        }
        let sc = ephemeral_server_config(cfg).unwrap();
        return incoming.accept_with(sc).unwrap().await.unwrap();
    }
}

/// Что увидел сырой клиент при чтении потока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// Конец потока.
    Eof,
    /// Закрытие приложением: код и признак пустой причины.
    AppClosed { code: u64, reason_empty: bool },
    /// Иное закрытие или сброс.
    Other,
    /// Ничего не пришло за отведённое время.
    Timeout,
}

pub fn app_closed(e: &quinn::ConnectionError) -> Seen {
    match e {
        quinn::ConnectionError::ApplicationClosed(ac) => Seen::AppClosed {
            code: ac.error_code.into_inner(),
            reason_empty: ac.reason.is_empty(),
        },
        _ => Seen::Other,
    }
}

/// Читает всё, что придёт, до конца/ошибки/времени. Возвращает прочитанные байты и причину остановки.
pub async fn drain(rx: &mut quinn::RecvStream, limit: Duration) -> (Vec<u8>, Seen) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let fut = async {
        loop {
            match rx.read(&mut buf).await {
                Ok(Some(n)) => out.extend_from_slice(&buf[..n]),
                Ok(None) => return Seen::Eof,
                Err(quinn::ReadError::ConnectionLost(e)) => return app_closed(&e),
                Err(_) => return Seen::Other,
            }
        }
    };
    let seen = match tokio::time::timeout(limit, fut).await {
        Ok(s) => s,
        Err(_) => Seen::Timeout,
    };
    (out, seen)
}

/// Ждёт закрытия соединения и сообщает вид закрытия.
pub async fn wait_closed(conn: &quinn::Connection, limit: Duration) -> Seen {
    match tokio::time::timeout(limit, conn.closed()).await {
        Ok(e) => app_closed(&e),
        Err(_) => Seen::Timeout,
    }
}

pub const REFUSED: Seen = Seen::AppClosed {
    code: crate::CLOSE_REFUSED as u64,
    reason_empty: true,
};

/// Сырой звонящий после отправки `msg1`.
pub struct Raw {
    pub conn: quinn::Connection,
    pub tx: quinn::SendStream,
    pub rx: quinn::RecvStream,
    pub init: chervo_identity::KkInitiator,
    pub msg1: [u8; chervo_identity::KK_MSG1_LEN],
}

/// TLS, первый поток, `msg1` от настоящего `KxPeer` (поток не закрывается).
pub async fn raw_start(ep: &quinn::Endpoint, addr: SocketAddr, kx: &KxPeer) -> Raw {
    let conn = raw_tls(ep, addr).await.unwrap();
    let b = crate::conn::binding(&conn).unwrap();
    let (init, msg1) = chervo_identity::kk_initiate(kx, &b).unwrap();
    let (mut tx, rx) = conn.open_bi().await.unwrap();
    tx.write_all(&msg1).await.unwrap();
    Raw {
        conn,
        tx,
        rx,
        init,
        msg1,
    }
}

/// Случайные байты (ring).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut b).unwrap();
    b
}

/// `msg1` незнакомца: вид 1 и случайные байты.
pub fn random_msg1() -> [u8; chervo_identity::KK_MSG1_LEN] {
    let mut m: [u8; chervo_identity::KK_MSG1_LEN] = random_bytes();
    m[0] = chervo_identity::KK_KIND_V1;
    m
}

pub async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Кадры от собеседника, по которым видна причина отказа (до закрытия соединения).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frames {
    pub stop_sending: u64,
    pub reset_stream: u64,
    pub stream: u64,
}

/// Принятые кадры по статистике соединения (на уровне пакетов, не потоков).
pub fn frames(conn: &quinn::Connection) -> Frames {
    let f = conn.stats().frame_rx;
    Frames {
        stop_sending: f.stop_sending,
        reset_stream: f.reset_stream,
        stream: f.stream,
    }
}

/// После `msg2`: из потока больше ничего, соединение закрыто отказом, а STOP_SENDING и
/// RESET_STREAM от вызываемого не приходили.
pub async fn expect_refused_after_msg2(rx: &mut quinn::RecvStream, conn: &quinn::Connection) {
    let (bytes, _) = drain(rx, Duration::from_secs(4)).await;
    assert!(bytes.is_empty(), "после msg2 пришли лишние байты");
    assert_eq!(wait_closed(conn, Duration::from_secs(4)).await, REFUSED);
    let f = frames(conn);
    assert_eq!(f.stop_sending, 0, "STOP_SENDING от вызываемого: {f:?}");
    assert_eq!(f.reset_stream, 0, "RESET_STREAM от вызываемого: {f:?}");
}

/// Полное рукопожатие сырым звонящим.
pub async fn raw_full(
    ep: &quinn::Endpoint,
    addr: std::net::SocketAddr,
    kx: &chervo_identity::KxPeer,
) -> (quinn::Connection, [u8; 49]) {
    let mut raw = raw_start(ep, addr, kx).await;
    let mut m2 = [0u8; chervo_identity::KK_MSG2_LEN];
    raw.rx.read_exact(&mut m2).await.unwrap();
    let m3 = raw.init.finish(&m2).unwrap();
    raw.tx.write_all(&m3).await.unwrap();
    raw.tx.finish().unwrap();
    (raw.conn, raw.msg1)
}
