//! Инструмент стенда netns (только инструмент, не продукт): отправитель для строк DOS1-DOS3
//! `tools/netns/stage17.sh` (контракт KNOCKFLOOD в заголовке этого файла стенда). Один
//! исполняемый файл, режимы:
//!   --mode garbage|knock48 --target IP:PORT --src-net A.B.C --sources N --pps P --secs S
//!     шлёт UDP с A.B.C.0..N-1 (каждый источник на своём адресе) суммарно P датаграмм/с в
//!     течение S секунд: garbage — случайная длина 1..1200, knock48 — случайные 48 байт.
//!     Ключи не нужны. В конце печатает `sent=<n>`.
//!   --mode idle-tls --target IP:PORT --book-dir D --label L --conns N --secs S
//!     друг (каталог книги D, созданный node16, метка друга L) шлёт верный стук, заканчивает
//!     QUIC+TLS и затем молчит (без msg1) в каждом из N соединений. На каждое соединение, когда
//!     собеседник его закрывает, печатает `conn=<k> closed_ms=<ms>`; в конце —
//!     `opened=<n> closed=<m> max_closed_ms=<ms>`.
//!   --mode invite-hold --target IP:PORT --invite FILE --conns N --secs S
//!     держатель приглашения (текст файла) открывает N сессий к пригласившему и держит их
//!     незавершёнными (без решения SAS). `--target` только для совместимости командной строки:
//!     адреса для звонка берутся из самого приглашения. В конце печатает `opened=<n>`.
//! Выход 0 после S секунд. Что-то другое — INCONCLUSIVE для строки стенда, никогда не PASS.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_connect::{AllowSet, ConnectConfig, Engine, SystemClock, SystemProbe};
use chervo_friends::FriendBook;
use chervo_identity::{IdentityError, KxPeer, PairId, SecretStore};
use chervo_transport::PeerFilter;
use chervo_transport_quinn::{ALPN, QuinnConfig, QuinnTransport, SERVER_NAME, window_at};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use zeroize::Zeroizing;

type Res<T> = Result<T, String>;

// ---------------------------------------------------------------- разбор командной строки

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn req(args: &[String], name: &str) -> Res<String> {
    arg(args, name).ok_or_else(|| format!("нужен {name}"))
}

fn req_num<T: std::str::FromStr>(args: &[String], name: &str) -> Res<T> {
    req(args, name)?
        .parse()
        .map_err(|_| format!("{name}: не число"))
}

// ---------------------------------------------------------------- быстрый ГСЧ шума (не криптография)

fn next_rand(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn fill_rand(state: &mut u64, buf: &mut [u8]) {
    for b in buf {
        *b = (next_rand(state) >> 24) as u8;
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

// ---------------------------------------------------------------- garbage / knock48

fn parse_src_net(s: &str) -> Res<(u8, u8, u8)> {
    let p: Vec<&str> = s.split('.').collect();
    if p.len() != 3 {
        return Err("--src-net: нужны три октета A.B.C".to_owned());
    }
    let o = |i: usize| {
        p[i].parse::<u8>()
            .map_err(|_| "--src-net: не число".to_owned())
    };
    Ok((o(0)?, o(1)?, o(2)?))
}

fn bind_sources(net: (u8, u8, u8), n: u32) -> Res<Vec<UdpSocket>> {
    let mut out = Vec::new();
    for i in 0..n {
        let last = u8::try_from(i).map_err(|_| "--sources: не больше 256".to_owned())?;
        let ip = IpAddr::V4(Ipv4Addr::new(net.0, net.1, net.2, last));
        let s = UdpSocket::bind(SocketAddr::new(ip, 0)).map_err(|e| format!("bind {ip}: {e}"))?;
        out.push(s);
    }
    if out.is_empty() {
        return Err("--sources: требуется хотя бы один".to_owned());
    }
    Ok(out)
}

/// `garbage`: случайная длина 1..1200; `knock48`: ровно 48 случайных байт. Темп `pps` суммарно
/// по всем источникам, тики по 20 мс. Возвращает число отправленных датаграмм.
fn flood(target: SocketAddr, socks: &[UdpSocket], pps: u32, secs: u64, knock48: bool) -> u64 {
    let tick = Duration::from_millis(20);
    let per_tick = ((f64::from(pps) * tick.as_secs_f64()).round() as u64).max(1);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut sent = 0u64;
    let mut idx = 0usize;
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    while Instant::now() < deadline {
        let tick_start = Instant::now();
        for _ in 0..per_tick {
            if Instant::now() >= deadline {
                break;
            }
            let Some(sock) = socks.get(idx % socks.len()) else {
                break;
            };
            idx = idx.wrapping_add(1);
            let len = if knock48 {
                48
            } else {
                1 + usize::try_from(next_rand(&mut rng) % 1200).unwrap_or(0)
            };
            let mut buf = vec![0u8; len];
            fill_rand(&mut rng, &mut buf);
            let _ = sock.send_to(&buf, target);
            sent += 1;
        }
        let elapsed = tick_start.elapsed();
        if elapsed < tick {
            std::thread::sleep(tick - elapsed);
        }
    }
    sent
}

fn run_flood(args: &[String], knock48: bool) -> Res<()> {
    let target: SocketAddr = req(args, "--target")?
        .parse()
        .map_err(|_| "--target".to_owned())?;
    let net = parse_src_net(&req(args, "--src-net")?)?;
    let sources: u32 = req_num(args, "--sources")?;
    let pps: u32 = req_num(args, "--pps")?;
    let secs: u64 = req_num(args, "--secs")?;
    let socks = bind_sources(net, sources)?;
    let sent = flood(target, &socks, pps, secs, knock48);
    println!("sent={sent}");
    Ok(())
}

// ---------------------------------------------------------------- хранилище ключей книги (чтение)

struct FileStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            lock: Mutex::new(()),
        }
    }

    fn pair_path(&self, pair: &PairId) -> PathBuf {
        self.dir.join(format!("pair-{}", hex(pair.as_bytes())))
    }

    fn list_path(&self) -> PathBuf {
        self.dir.join("list-key")
    }
}

fn read_opt(p: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
    match std::fs::read(p) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(IdentityError::StorageUnavailable),
    }
}

fn write_atomic_bytes(p: &Path, data: &[u8]) -> Result<(), IdentityError> {
    let mut tmp = p.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, data).map_err(|_| IdentityError::StorageUnavailable)?;
    std::fs::rename(&tmp, p).map_err(|_| IdentityError::StorageUnavailable)
}

fn remove_opt(p: &Path) -> Result<(), IdentityError> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IdentityError::StorageUnavailable),
    }
}

impl SecretStore for FileStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        read_opt(&self.pair_path(pair))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic_bytes(&self.pair_path(pair), blob)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        remove_opt(&self.pair_path(pair))
    }
}

impl chervo_identity::ListKeyStore for FileStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        read_opt(&self.list_path())
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic_bytes(&self.list_path(), key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        remove_opt(&self.list_path())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex_pair(s: &str) -> Option<PairId> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(PairId::from_bytes(out))
}

/// Метка -> пара, из `BOOKDIR/labels` (как пишет node16).
fn label_pair(book_dir: &Path, label: &str) -> Option<PairId> {
    let text = std::fs::read_to_string(book_dir.join("labels")).ok()?;
    text.lines().find_map(|line| {
        let (h, l) = line.split_once(' ')?;
        (l == label).then(|| unhex_pair(h)).flatten()
    })
}

/// `KxPeer` друга с данной меткой, читая книгу друзей `book_dir` (создана node16).
fn load_friend(book_dir: &Path, label: &str) -> Res<KxPeer> {
    let pair = label_pair(book_dir, label).ok_or_else(|| "label: не найдена в книге".to_owned())?;
    let store = FileStore::new(book_dir.join("keys"));
    let book = FriendBook::open_unanchored(&book_dir.join("friends.chfl"), &store)
        .map_err(|e| format!("книга: {e}"))?;
    let (peers, _bad) = book
        .kx_peers(&store)
        .map_err(|e| format!("kx_peers: {e}"))?;
    peers
        .into_iter()
        .find(|p| p.pair() == pair)
        .ok_or_else(|| "label: друг неактивен или ключ недоступен".to_owned())
}

// ---------------------------------------------------------------- idle-tls: клиентский TLS без KK

/// Повтор клиентского верификатора `chervo_transport_quinn::tls::RpkVerifier` (голые публичные
/// ключи, RFC 7250): дублируется здесь намеренно, инструмент не входит в продукт и не меняет его.
struct RpkVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl RpkVerifier {
    fn new() -> Self {
        Self {
            algs: provider().signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for RpkVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RpkVerifier")
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl ServerCertVerifier for RpkVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn idle_client_config() -> Res<quinn::ClientConfig> {
    let mut cc = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RpkVerifier::new()))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];
    cc.enable_sni = false;
    cc.enable_early_data = false;
    let quic = QuicClientConfig::try_from(Arc::new(cc)).map_err(|e| format!("quic tls: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// Общие для всех `idle_conn` счётчики итога.
#[derive(Clone)]
struct IdleCounters {
    opened: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    max_ms: Arc<AtomicU64>,
}

/// Одно соединение: стук, QUIC+TLS, затем тишина (ни одного потока, значит ни одного msg1).
async fn idle_conn(
    k: usize,
    target: SocketAddr,
    keys: Arc<chervo_identity::KnockKeys>,
    cfg: quinn::ClientConfig,
    hold: Duration,
    c: IdleCounters,
) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    if let Ok(k0) = keys.make(window_at(now_ms())) {
        let _ = sock.send_to(&k0, target);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let Some(runtime) = quinn::default_runtime() else {
        return;
    };
    let Ok(endpoint) = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, runtime)
    else {
        return;
    };
    let Ok(connecting) = endpoint.connect_with(cfg, target, SERVER_NAME) else {
        return;
    };
    let Ok(Ok(conn)) = tokio::time::timeout(hold, connecting).await else {
        return;
    };
    c.opened.fetch_add(1, Ordering::Relaxed);
    let t0 = Instant::now();
    let _ = tokio::time::timeout(hold, conn.closed()).await;
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    println!("conn={k} closed_ms={ms}");
    c.closed.fetch_add(1, Ordering::Relaxed);
    c.max_ms.fetch_max(ms, Ordering::Relaxed);
}

async fn run_idle_tls(args: &[String]) -> Res<()> {
    let target: SocketAddr = req(args, "--target")?
        .parse()
        .map_err(|_| "--target".to_owned())?;
    let book_dir = PathBuf::from(req(args, "--book-dir")?);
    let label = req(args, "--label")?;
    let conns: usize = req_num(args, "--conns")?;
    let secs: u64 = req_num(args, "--secs")?;
    let friend = load_friend(&book_dir, &label)?;
    let keys = Arc::new(
        friend
            .knock_keys()
            .map_err(|e| format!("knock_keys: {e}"))?,
    );
    let cfg = idle_client_config()?;
    let hold = Duration::from_secs(secs.max(1));
    let c = IdleCounters {
        opened: Arc::new(AtomicUsize::new(0)),
        closed: Arc::new(AtomicUsize::new(0)),
        max_ms: Arc::new(AtomicU64::new(0)),
    };
    let mut tasks = Vec::new();
    for k in 0..conns {
        tasks.push(tokio::spawn(idle_conn(
            k,
            target,
            keys.clone(),
            cfg.clone(),
            hold,
            c.clone(),
        )));
    }
    for t in tasks {
        let _ = t.await;
    }
    println!(
        "opened={} closed={} max_closed_ms={}",
        c.opened.load(Ordering::Relaxed),
        c.closed.load(Ordering::Relaxed),
        c.max_ms.load(Ordering::Relaxed)
    );
    Ok(())
}

// ---------------------------------------------------------------- invite-hold: сессии без решения SAS

/// Хранилище в памяти: нужно только на время держания сессий, без диска.
#[derive(Default)]
struct MemStore {
    pairs: Mutex<std::collections::HashMap<PairId, Vec<u8>>>,
    list: Mutex<Option<Vec<u8>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pair)
            .cloned()
            .map(Zeroizing::new))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(*pair, blob.to_vec());
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(pair);
        Ok(())
    }
}

impl chervo_identity::ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map(Zeroizing::new))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *self.list.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.to_vec());
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *self.list.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }
}

/// Пустая книга друзей, живущая только в процессе: путь нужен `FriendBook::open_unanchored`/сохранению,
/// но вне книги держателю приглашения ничего не нужно хранить навсегда.
fn scratch_book_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "chervo-knockflood-{}-{nanos:x}.chfl",
        std::process::id()
    ))
}

async fn run_invite_hold(args: &[String]) -> Res<()> {
    // `--target` обязателен для совместимости с контрактом стенда; адреса звонка берутся из
    // приглашения, не из этого аргумента.
    let _target: SocketAddr = req(args, "--target")?
        .parse()
        .map_err(|_| "--target".to_owned())?;
    let invite_path = PathBuf::from(req(args, "--invite")?);
    let conns: usize = req_num(args, "--conns")?;
    let secs: u64 = req_num(args, "--secs")?;
    let text = std::fs::read_to_string(&invite_path).map_err(|e| format!("--invite: {e}"))?;

    let store = Arc::new(MemStore::default());
    let book_path = scratch_book_path();
    let book =
        FriendBook::open_unanchored(&book_path, &*store).map_err(|e| format!("книга: {e}"))?;
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let transport = QuinnTransport::bind(
        SocketAddr::from(([0, 0, 0, 0], 0)),
        QuinnConfig::default(),
        filter,
    )
    .map(Arc::new)
    .map_err(|e| format!("bind: {e}"))?;
    let clock: Arc<dyn chervo_connect::Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn chervo_connect::RouteProbe> = Arc::new(SystemProbe);
    let (engine, _events) = Engine::start(
        transport.clone(),
        allow,
        book,
        store,
        clock,
        probe,
        ConnectConfig::default(),
    )
    .map_err(|e| format!("engine: {e}"))?;

    let mut opened = 0usize;
    for _ in 0..conns {
        if engine.accept_invite(text.trim()).is_ok() {
            opened += 1;
        }
    }
    println!("opened={opened}");
    tokio::time::sleep(Duration::from_secs(secs.max(1))).await;
    engine.shutdown();
    transport.shutdown();
    let _ = std::fs::remove_file(&book_path);
    Ok(())
}

// ---------------------------------------------------------------- точка входа

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = arg(&args, "--mode").unwrap_or_default();
    let r: Res<()> = match mode.as_str() {
        "garbage" => run_flood(&args, false),
        "knock48" => run_flood(&args, true),
        "idle-tls" => run_idle_tls(&args).await,
        "invite-hold" => run_invite_hold(&args).await,
        _ => Err("--mode: garbage|knock48|idle-tls|invite-hold".to_owned()),
    };
    if let Err(e) = r {
        eprintln!("knockflood: {e}");
        std::process::exit(2);
    }
}
