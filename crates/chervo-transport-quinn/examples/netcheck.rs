//! Инструмент стенда netns (только инструмент, не продукт): повтор G1 и G12 на адаптере.
//!
//! Подкоманды:
//!   keygen  --dir D
//!   listen  --dir D --listen ADDR
//!   connect --dir D --to ADDR [--pair N] [--bytes N] [--duration S] [--idle-s S] [--change-addr-at S]
//!
//! Печатает только строки `EVENT <имя> key=value` без IP, ключей, PairId и экспортёра.
//! Файловое хранилище секретов здесь допустимо только как часть инструмента: файлы 0600
//! в каталоге стенда вне репозитория.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chervo_identity::{
    IdentityError, KxPeer, KxPublicKey, PairId, PublicKey, SecretStore, create, load,
};
use chervo_transport::{Connection, PeerAddr, PeerFilter, RecvStream, SendStream, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnConn, QuinnTransport, TransportEvent};
use zeroize::Zeroizing;

type Res<T> = Result<T, String>;

fn ev(name: &str, kv: &str) {
    if kv.is_empty() {
        println!("EVENT {name}");
    } else {
        println!("EVENT {name} {kv}");
    }
}

// ---------------------------------------------------------------- файловое хранилище

struct FileStore(PathBuf);

impl FileStore {
    fn path(&self, pair: &PairId) -> PathBuf {
        self.0.join(pair.account_name())
    }
}

impl SecretStore for FileStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        match fs::read(self.path(pair)) {
            Ok(b) => Ok(Some(Zeroizing::new(b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(IdentityError::StorageUnavailable),
        }
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        let p = self.path(pair);
        fs::write(&p, blob).map_err(|_| IdentityError::StorageUnavailable)?;
        private(&p).map_err(|_| IdentityError::StorageUnavailable)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        match fs::remove_file(self.path(pair)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(IdentityError::StorageUnavailable),
        }
    }
}

#[cfg(unix)]
fn private(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn private(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

fn write_private(p: &Path, text: &str) -> Res<()> {
    fs::write(p, text).map_err(|e| format!("write: {e}"))?;
    private(p).map_err(|e| format!("chmod: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "hex".to_string()))
        .collect()
}

fn read_text(dir: &Path, name: &str) -> Res<String> {
    fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"))
}

// ---------------------------------------------------------------- ключи

const PAIRS: u8 = 2;

fn keygen(dir: &Path) -> Res<()> {
    fs::create_dir_all(dir.join("side-a")).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("side-b")).map_err(|e| e.to_string())?;
    let (sa, sb) = (FileStore(dir.join("side-a")), FileStore(dir.join("side-b")));
    let mut needles = Vec::new();
    for n in 1..=PAIRS {
        let pid = PairId::generate().map_err(|e| e.to_string())?;
        let ka = create(&sa, &pid).map_err(|e| e.to_string())?;
        let kb = create(&sb, &pid).map_err(|e| e.to_string())?;
        let files = [
            (format!("pair{n}.id"), hex(pid.as_bytes())),
            (format!("pair{n}.a.pub"), hex(&ka.public_key().to_bytes())),
            (format!("pair{n}.b.pub"), hex(&kb.public_key().to_bytes())),
            (format!("pair{n}.a.kx"), hex(&ka.kx_public().to_bytes())),
            (format!("pair{n}.b.kx"), hex(&kb.kx_public().to_bytes())),
        ];
        for (name, val) in &files {
            write_private(&dir.join(name), val)?;
            let label = name.replace('.', "_");
            needles.push(format!("{label} hex {val}"));
        }
    }
    needles.push("server_name str chervo.invalid".to_string());
    write_private(&dir.join("needles.txt"), &needles.join("\n"))?;
    ev("keygen_ok", &format!("pairs={PAIRS}"));
    Ok(())
}

/// `KxPeer` стороны `side` ('a' или 'b') для пары `n`.
fn load_peer(dir: &Path, side: char, n: u8) -> Res<KxPeer> {
    let other = if side == 'a' { 'b' } else { 'a' };
    let pid_bytes: [u8; 16] = unhex(&read_text(dir, &format!("pair{n}.id"))?)?
        .try_into()
        .map_err(|_| "pair id".to_string())?;
    let pid = PairId::from_bytes(pid_bytes);
    let public =
        PublicKey::try_from_slice(&unhex(&read_text(dir, &format!("pair{n}.{side}.pub"))?)?)
            .map_err(|e| e.to_string())?;
    let theirs =
        KxPublicKey::try_from_slice(&unhex(&read_text(dir, &format!("pair{n}.{other}.kx"))?)?)
            .map_err(|e| e.to_string())?;
    let store = FileStore(dir.join(format!("side-{side}")));
    let key = load(&store, &pid, &public).map_err(|e| e.to_string())?;
    Ok(KxPeer::new(pid, key.into_kx(), theirs))
}

fn pair_id(dir: &Path, n: u8) -> Res<PairId> {
    let b: [u8; 16] = unhex(&read_text(dir, &format!("pair{n}.id"))?)?
        .try_into()
        .map_err(|_| "pair id".to_string())?;
    Ok(PairId::from_bytes(b))
}

struct AllowAll;

impl PeerFilter for AllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

// ---------------------------------------------------------------- сервер

async fn echo(conn: QuinnConn) {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(Some(n)) = rx.read(&mut buf).await {
                let Some(chunk) = buf.get(..n) else { return };
                if tx.write_all(chunk).await.is_err() {
                    return;
                }
            }
            let _ = tx.finish();
        });
    }
}

async fn listen(dir: &Path, addr: SocketAddr) -> Res<()> {
    let t = QuinnTransport::bind(addr, QuinnConfig::default(), Arc::new(AllowAll))
        .map_err(|e| e.to_string())?;
    let mut peers = Vec::new();
    for n in 1..=PAIRS {
        peers.push(load_peer(dir, 'b', n)?);
    }
    t.set_peers(peers);
    ev("bound", "");
    let mut events = t.events();
    tokio::spawn(async move {
        let mut n = 0u32;
        while let Ok(e) = events.recv().await {
            if let TransportEvent::RemoteAddrChanged { .. } = e {
                n += 1;
                ev("addr_changed", &format!("n={n}"));
            }
        }
    });
    while let Ok(conn) = t.accept().await {
        ev("auth_ok", "side=s");
        tokio::spawn(echo(conn));
    }
    Ok(())
}

// ---------------------------------------------------------------- клиент

struct Opts {
    to: SocketAddr,
    pair: u8,
    bytes: usize,
    duration_s: u64,
    idle_s: u64,
    change_addr_at: Option<u64>,
}

fn pattern(off: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((off + i as u64).wrapping_mul(31).wrapping_add(7) % 251) as u8;
    }
}

/// Одна двунаправленная передача: блоки `bytes` каждые 200 мс в течение `duration_s`, эхо сверяется.
async fn app_phase(conn: &QuinnConn, o: &Opts) -> Result<(u64, bool), String> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let total_ms = o.duration_s * 1000;
    let reader = tokio::spawn(async move {
        let mut got = 0u64;
        let mut eq = true;
        let mut buf = vec![0u8; 64 * 1024];
        let mut want = vec![0u8; 64 * 1024];
        while let Ok(Some(n)) = rx.read(&mut buf).await {
            let (Some(b), Some(w)) = (buf.get(..n), want.get_mut(..n)) else {
                return (got, false);
            };
            pattern(got, w);
            if b != &*w {
                eq = false;
            }
            got += n as u64;
        }
        (got, eq)
    });
    let started = Instant::now();
    let mut sent = 0u64;
    let mut chunk = vec![0u8; o.bytes.max(1)];
    while started.elapsed().as_millis() < u128::from(total_ms) {
        pattern(sent, &mut chunk);
        tx.write_all(&chunk).await.map_err(|e| e.to_string())?;
        sent += chunk.len() as u64;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tx.finish().map_err(|e| e.to_string())?;
    let (got, eq) = tokio::time::timeout(Duration::from_secs(20), reader)
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok((got, eq && got == sent))
}

async fn probe(conn: &QuinnConn) -> bool {
    let fut = async {
        let (mut tx, mut rx) = conn.open_bi().await.ok()?;
        tx.write_all(b"ping-after-idle").await.ok()?;
        tx.finish().ok()?;
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        while let Some(n) = rx.read(&mut buf).await.ok()? {
            out.extend_from_slice(buf.get(..n)?);
        }
        Some(out == b"ping-after-idle")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(10), fut).await,
        Ok(Some(true))
    )
}

async fn client(dir: &Path, o: Opts) -> Res<()> {
    let t = QuinnTransport::bind(
        "0.0.0.0:0".parse().map_err(|_| "addr".to_string())?,
        QuinnConfig::default(),
        Arc::new(AllowAll),
    )
    .map_err(|e| e.to_string())?;
    t.set_peers(vec![load_peer(dir, 'a', o.pair)?]);
    let pid = pair_id(dir, o.pair)?;
    let started = Instant::now();
    if let Some(s) = o.change_addr_at {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(s)).await;
            ev(
                "addr_change_mark",
                &format!("t={}", started.elapsed().as_millis()),
            );
        });
    }
    let conn = match t
        .connect(&PeerAddr {
            pair: pid,
            addrs: vec![o.to],
        })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            ev("client_result", &format!("err kind={e:?}"));
            return Ok(());
        }
    };
    ev("auth_ok", "side=c");
    match app_phase(&conn, &o).await {
        Ok((n, eq)) => {
            ev("app_ok", &format!("bytes={n} echo_eq={}", u8::from(eq)));
            if o.idle_s > 0 {
                tokio::time::sleep(Duration::from_secs(o.idle_s)).await;
                let alive = conn.open_bi().await.is_ok();
                let ok = probe(&conn).await;
                ev(
                    "after_idle",
                    &format!("conn_alive={} probe_ok={}", u8::from(alive), u8::from(ok)),
                );
            }
            ev(
                "client_result",
                if eq { "ok" } else { "err kind=EchoMismatch" },
            );
        }
        Err(_) => ev("client_result", "err kind=Closed"),
    }
    conn.close();
    tokio::time::sleep(Duration::from_millis(200)).await;
    t.shutdown();
    Ok(())
}

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

fn num<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> Res<T> {
    match arg(args, name) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|_| format!("{name}: не число")),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r: Res<()> = async {
        let cmd = args.first().map(String::as_str).unwrap_or("");
        let dir = PathBuf::from(req(&args, "--dir")?);
        match cmd {
            "keygen" => keygen(&dir),
            "listen" => {
                let a: SocketAddr = req(&args, "--listen")?
                    .parse()
                    .map_err(|_| "--listen".to_string())?;
                listen(&dir, a).await
            }
            "connect" => {
                let o = Opts {
                    to: req(&args, "--to")?
                        .parse()
                        .map_err(|_| "--to".to_string())?,
                    pair: num(&args, "--pair", 1u8)?,
                    bytes: num(&args, "--bytes", 65536usize)?,
                    duration_s: num(&args, "--duration", 5u64)?,
                    idle_s: num(&args, "--idle-s", 0u64)?,
                    change_addr_at: match arg(&args, "--change-addr-at") {
                        Some(v) => Some(v.parse().map_err(|_| "--change-addr-at".to_string())?),
                        None => None,
                    },
                };
                client(&dir, o).await
            }
            _ => Err("команда: keygen|listen|connect".into()),
        }
    }
    .await;
    if let Err(e) = r {
        eprintln!("ERROR {e}");
        std::process::exit(2);
    }
}
