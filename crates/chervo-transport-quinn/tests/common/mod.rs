#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_identity::{IdentityError, KxPeer, PairId, SecretStore, create};
use chervo_transport::{
    Connection, PeerAddr, PeerFilter, RecvStream, SendStream, Transport, TransportError,
};
use chervo_transport_quinn::{QuinnConfig, QuinnConn, QuinnTransport};
use zeroize::Zeroizing;

/// Хранилище в памяти (копия из тестов chervo-identity).
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

/// Фильтр с изменяемым набором запрещённых пар.
#[derive(Default)]
pub struct BlockSet(pub Mutex<HashSet<PairId>>);

impl PeerFilter for BlockSet {
    fn is_allowed(&self, pair: &PairId) -> bool {
        !self.0.lock().unwrap().contains(pair)
    }
}

/// Конфиг для тестов: короткие дедлайны, лимитер по IP не мешает.
pub fn test_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

/// Одна пара с двух сторон: (вид стороны A, вид стороны B).
pub fn make_pair() -> (KxPeer, KxPeer) {
    make_pair_with(PairId::generate().unwrap())
}

pub fn make_pair_with(pid: PairId) -> (KxPeer, KxPeer) {
    let (sa, sb) = (MemStore::default(), MemStore::default());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    (
        KxPeer::new(pid, ka.into_kx(), pb),
        KxPeer::new(pid, kb.into_kx(), pa),
    )
}

pub fn lo() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub fn bind(cfg: QuinnConfig, peers: Vec<KxPeer>) -> QuinnTransport {
    let t = QuinnTransport::bind(lo(), cfg, Arc::new(AllowAll)).unwrap();
    t.set_peers(peers).unwrap();
    t
}

pub fn addr_of(t: &QuinnTransport) -> SocketAddr {
    let a = t.local_addrs();
    assert_eq!(a.len(), 1);
    SocketAddr::new("127.0.0.1".parse().unwrap(), a[0].port())
}

pub fn peer_addr(pair: PairId, t: &QuinnTransport) -> PeerAddr {
    PeerAddr {
        pair,
        addrs: vec![addr_of(t)],
    }
}

/// Эхо-сервер: на каждом принятом соединении на каждом потоке возвращает всё прочитанное.
pub fn spawn_echo(t: Arc<QuinnTransport>) {
    tokio::spawn(async move {
        while let Ok(conn) = t.accept().await {
            tokio::spawn(echo_conn(conn));
        }
    });
}

pub async fn echo_conn(conn: QuinnConn) {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(Some(n)) = rx.read(&mut buf).await {
                if tx.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
            let _ = tx.finish();
        });
    }
}

/// Отправить данные, закрыть сторону и прочитать всё до конца.
pub async fn roundtrip(conn: &QuinnConn, data: &[u8]) -> Result<Vec<u8>, TransportError> {
    let (mut tx, mut rx) = conn.open_bi().await?;
    let writer = async {
        tx.write_all(data).await?;
        tx.finish()
    };
    let reader = async {
        let mut out = Vec::with_capacity(data.len());
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = rx.read(&mut buf).await? {
            out.extend_from_slice(&buf[..n]);
        }
        Ok::<_, TransportError>(out)
    };
    let (w, r) = tokio::join!(writer, reader);
    w?;
    r
}

pub fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
        .collect()
}

/// Незнакомец, выдающий себя за пару `pid`: свои секреты.
pub fn stranger_peer(pid: PairId) -> KxPeer {
    make_pair_with(pid).0
}

pub fn median<T: Ord + Copy>(v: &mut [T]) -> T {
    v.sort();
    v[v.len() / 2]
}
