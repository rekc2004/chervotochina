//! Общая обвязка сервера, клиента, MITM и flood поверх трейтов транспорта (A и B).
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, sleep, timeout};

use crate::auth::{CallerCfg, Conn, PairSet, Stats, callee_auth, caller_auth, Mode};
use crate::ev;
use crate::keys::{rand16, rand32};
use crate::util::{BoxErr, hex, q};

pub trait Incoming: Send + 'static {
    type C: Conn;
    fn peer(&self) -> SocketAddr;
    fn validated(&self) -> bool;
    fn retry(self);
    fn ignore(self);
    fn accept(self) -> impl Future<Output = Result<Self::C, BoxErr>> + Send;
}

pub trait ServerNet: Send + Sync + 'static {
    type I: Incoming;
    fn next(&self) -> impl Future<Output = Option<Self::I>> + Send;
}

pub trait ClientNet: Send + Sync + 'static {
    type C: Conn;
    fn connect(
        &self,
        to: SocketAddr,
        id: Option<[u8; 32]>,
    ) -> impl Future<Output = Result<Self::C, BoxErr>> + Send;
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}

// ---------------------------------------------------------------- сервер

pub struct ServerOpts {
    /// (рукопожатий, окно): None = без лимита и без Retry.
    pub limit: Option<(usize, Duration)>,
    pub bad_auth2: bool,
    pub pairs: Arc<PairSet>,
}

struct Limiter {
    max: usize,
    window: Duration,
    seen: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl Limiter {
    /// true, если рукопожатие разрешено (и учтено).
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let Ok(mut m) = self.seen.lock() else {
            return false;
        };
        let q = m.entry(ip).or_default();
        while let Some(&f) = q.front() {
            if now.duration_since(f) > self.window {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= self.max {
            return false;
        }
        q.push_back(now);
        true
    }
}

pub async fn run_server<N: ServerNet>(net: Arc<N>, o: ServerOpts) {
    let limiter = o.limit.map(|(max, window)| Limiter { max, window, seen: Mutex::new(HashMap::new()) });
    let n = Arc::new(AtomicU64::new(0));
    while let Some(inc) = net.next().await {
        let peer = inc.peer();
        let validated = inc.validated();
        let action = match &limiter {
            None => "accept",
            Some(_) if !validated => "retry",
            Some(l) if l.allow(peer.ip()) => "accept",
            Some(_) => "ignore",
        };
        ev!("incoming", "peer={peer} validated={} action={action}", u8::from(validated));
        match action {
            "retry" => inc.retry(),
            "ignore" => inc.ignore(),
            _ => {
                let id = n.fetch_add(1, Ordering::Relaxed) + 1;
                let pairs = o.pairs.clone();
                let bad2 = o.bad_auth2;
                tokio::spawn(async move { handle(inc, id, peer, pairs, bad2).await });
            }
        }
    }
}

async fn handle<I: Incoming>(inc: I, n: u64, peer: SocketAddr, pairs: Arc<PairSet>, bad2: bool) {
    let conn = match inc.accept().await {
        Ok(c) => c,
        Err(e) => {
            ev!("hs_fail", "peer={peer} conn={n} err=\"{}\"", q(&e.to_string()));
            return;
        }
    };
    ev!("hs_done", "peer={peer} conn={n}");
    let mut ekm = [0u8; 32];
    if let Err(e) = conn.ekm(&mut ekm) {
        ev!("ekm_error", "side=s conn={n} err=\"{}\"", q(&e.to_string()));
        conn.close(1);
        return;
    }
    ev!("ekm", "side=s conn={n} ekm={}", hex(&ekm));
    ev!("peer_identity", "{} conn={n}", if conn.peer_identity() { "some" } else { "none" });
    match callee_auth(&conn, &pairs, &ekm, bad2).await {
        Err(f) => {
            ev!("auth_fail", "side=s conn={n} reason={} app_bytes_read=0", f.reason());
            conn.close(1);
            let _ = timeout(Duration::from_secs(1), conn.wait_closed()).await;
        }
        Ok(_) => {
            ev!("auth_ok", "side=s conn={n}");
            while let Ok(Ok((s, r))) = timeout(Duration::from_secs(150), conn.accept_bi()).await {
                tokio::spawn(echo(s, r, n));
            }
            ev!("conn_end", "conn={n}");
        }
    }
}

async fn echo<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(mut s: S, mut r: R, n: u64) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(k) => {
                let Some(chunk) = buf.get(..k) else { break };
                if s.write_all(chunk).await.is_err() {
                    break;
                }
                total += k as u64;
            }
            Err(_) => break,
        }
    }
    let _ = s.shutdown().await;
    ev!("app_served", "conn={n} bytes={total}");
}

// ---------------------------------------------------------------- клиент

pub struct ClientOpts {
    pub to: SocketAddr,
    pub id: Option<[u8; 32]>,
    pub pairs: Arc<PairSet>,
    pub pair_idx: usize,
    pub mode: Mode,
    pub bytes: usize,
    pub duration_s: u64,
    pub chunk_ms: u64,
    pub idle_s: u64,
    pub repeat: u32,
    pub change_addr_at: Option<u64>,
}

fn pattern(off: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((off + i as u64).wrapping_mul(31).wrapping_add(7) % 251) as u8;
    }
}

fn result(kind: &str, err: &str, recv: u64, sent: u64) {
    ev!("client_result", "{kind} err=\"{}\" app_bytes_received={recv} app_bytes_sent={sent}", q(err));
}

pub async fn run_client<N: ClientNet>(net: &N, o: &ClientOpts) {
    if let Some(s) = o.change_addr_at {
        tokio::spawn(async move {
            sleep(Duration::from_secs(s)).await;
            ev!("addr_change_mark");
        });
    }
    for k in 1..=o.repeat.max(1) {
        attempt(net, o, k).await;
    }
    net.shutdown().await;
}

async fn connect_to<N: ClientNet>(net: &N, o: &ClientOpts) -> Result<N::C, BoxErr> {
    match timeout(Duration::from_secs(20), net.connect(o.to, o.id)).await {
        Ok(r) => r,
        Err(_) => Err("connect timeout 20s".into()),
    }
}

async fn attempt<N: ClientNet>(net: &N, o: &ClientOpts, k: u32) {
    let t0 = Instant::now();
    ev!("attempt_start", "n={k}");
    let (Some(pair), Some(other)) = (o.pairs.0.get(o.pair_idx), o.pairs.0.get(1 - o.pair_idx.min(1))) else {
        result("hs_error", "нет пары", 0, 0);
        return;
    };
    // other-conn: сначала соседнее соединение, берём его EKM.
    let mut ekm_override = None;
    let mut decoy = None;
    if o.mode == Mode::OtherConn {
        match connect_to(net, o).await {
            Ok(c) => {
                let mut e = [0u8; 32];
                if c.ekm(&mut e).is_ok() {
                    ev!("ekm", "side=c conn=0 ekm={}", hex(&e));
                    ekm_override = Some(e);
                    let cfg = CallerCfg { mode: Mode::Ok, pair, other, ekm_override: None, random_pair: [0; 16] };
                    let mut st = Stats::default();
                    let r = caller_auth(&c, &cfg, &e, &mut st).await;
                    ev!("decoy", "auth={}", if r.is_ok() { "ok" } else { "fail" });
                }
                decoy = Some(c);
            }
            Err(e) => {
                result("hs_error", &format!("decoy: {e}"), 0, 0);
                return;
            }
        }
    }
    let conn = match connect_to(net, o).await {
        Ok(c) => c,
        Err(e) => {
            result("hs_error", &e.to_string(), 0, 0);
            return;
        }
    };
    ev!("hs_done", "peer={} conn={k}", o.to);
    let mut ekm = [0u8; 32];
    if let Err(e) = conn.ekm(&mut ekm) {
        result("hs_error", &format!("ekm: {e}"), 0, 0);
        return;
    }
    ev!("ekm", "side=c conn={k} ekm={}", hex(&ekm));
    ev!("peer_identity", "{} conn={k}", if conn.peer_identity() { "some" } else { "none" });
    let random_pair = rand16().unwrap_or([0xee; 16]);
    let cfg = CallerCfg { mode: o.mode, pair, other, ekm_override, random_pair };
    let mut st = Stats::default();
    if let Err(f) = caller_auth(&conn, &cfg, &ekm, &mut st).await {
        ev!("auth_fail", "side=c conn={k} reason={} app_bytes_sent={}", f.reason(), st.app_sent);
        conn.close(1);
        let _ = timeout(Duration::from_secs(1), conn.wait_closed()).await;
        let detail = match &f {
            crate::auth::AuthFail::Closed(s) => s.clone(),
            other => other.reason().to_string(),
        };
        result("closed", &detail, 0, st.app_sent);
        if let Some(d) = decoy {
            d.close(0);
        }
        return;
    }
    ev!("auth_ok", "side=c conn={k} dur_ms={}", t0.elapsed().as_millis());
    let sent = Arc::new(AtomicU64::new(0));
    let recvd = Arc::new(AtomicU64::new(0));
    let r = app_phase(&conn, o, sent.clone(), recvd.clone()).await;
    let (s_n, r_n) = (sent.load(Ordering::Relaxed), recvd.load(Ordering::Relaxed));
    match r {
        Ok(eq) => {
            ev!("app_ok", "bytes={r_n} echo_eq={}", u8::from(eq && r_n == s_n));
            if o.idle_s > 0 {
                sleep(Duration::from_secs(o.idle_s)).await;
                let alive = timeout(Duration::from_millis(10), conn.wait_closed()).await.is_err();
                let probe = probe(&conn).await;
                ev!("after_idle", "conn_alive={} probe_ok={}", u8::from(alive), u8::from(probe));
            }
            result(if eq && r_n == s_n { "ok" } else { "closed" }, "", r_n, s_n);
        }
        Err(e) => {
            ev!("app_error", "err=\"{}\"", q(&e));
            result("closed", &e, r_n, s_n);
        }
    }
    conn.close(0);
    if let Some(d) = decoy {
        d.close(0);
    }
}

async fn probe<C: Conn>(conn: &C) -> bool {
    let fut = async {
        let (mut s, mut r) = conn.open_bi().await.ok()?;
        s.write_all(b"ping-after-idle").await.ok()?;
        s.shutdown().await.ok()?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.ok()?;
        Some(out == b"ping-after-idle")
    };
    matches!(timeout(Duration::from_secs(10), fut).await, Ok(Some(true)))
}

async fn app_phase<C: Conn>(
    conn: &C,
    o: &ClientOpts,
    sent: Arc<AtomicU64>,
    recvd: Arc<AtomicU64>,
) -> Result<bool, String> {
    let (mut s, mut r) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let rc = recvd.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        let mut exp = vec![0u8; 64 * 1024];
        let mut off = 0u64;
        let mut eq = true;
        loop {
            match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    pattern(off, exp.get_mut(..n).unwrap_or(&mut []));
                    if buf.get(..n) != exp.get(..n) {
                        eq = false;
                    }
                    off += n as u64;
                    rc.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(eq)
    });
    let mut off = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    let end = Instant::now() + Duration::from_secs(o.duration_s);
    let mut remaining = o.bytes as u64;
    loop {
        let n = if o.duration_s > 0 {
            if Instant::now() >= end {
                break;
            }
            buf.len()
        } else {
            if remaining == 0 {
                break;
            }
            usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len())
        };
        let Some(chunk) = buf.get_mut(..n) else { break };
        pattern(off, chunk);
        s.write_all(chunk).await.map_err(|e| e.to_string())?;
        off += n as u64;
        remaining = remaining.saturating_sub(n as u64);
        sent.fetch_add(n as u64, Ordering::Relaxed);
        if o.duration_s > 0 {
            sleep(Duration::from_millis(o.chunk_ms)).await;
        }
    }
    s.shutdown().await.map_err(|e| e.to_string())?;
    match timeout(Duration::from_secs(60), reader).await {
        Err(_) => Err("echo timeout".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(r)) => r,
    }
}

// ---------------------------------------------------------------- MITM

pub async fn run_mitm<S: ServerNet, K: ClientNet>(
    srv: Arc<S>,
    cli: Arc<K>,
    upstream: SocketAddr,
    upstream_id: Option<[u8; 32]>,
) {
    let n = AtomicU64::new(0);
    while let Some(inc) = srv.next().await {
        let id = n.fetch_add(1, Ordering::Relaxed) + 1;
        let peer = inc.peer();
        ev!("incoming", "peer={peer} validated={} action=accept", u8::from(inc.validated()));
        let cli = cli.clone();
        tokio::spawn(async move {
            let down = match inc.accept().await {
                Ok(c) => c,
                Err(e) => {
                    ev!("hs_fail", "peer={peer} conn={id} err=\"{}\"", q(&e.to_string()));
                    return;
                }
            };
            ev!("hs_done", "peer={peer} conn={id}");
            let up = match cli.connect(upstream, upstream_id).await {
                Ok(c) => c,
                Err(e) => {
                    ev!("mitm_upstream_error", "err=\"{}\"", q(&e.to_string()));
                    down.close(1);
                    return;
                }
            };
            let (mut e1, mut e2) = ([0u8; 32], [0u8; 32]);
            if down.ekm(&mut e1).is_ok() {
                ev!("ekm", "side=md conn={id} ekm={}", hex(&e1));
            }
            if up.ekm(&mut e2).is_ok() {
                ev!("ekm", "side=mu conn={id} ekm={}", hex(&e2));
            }
            let up = Arc::new(up);
            let down = Arc::new(down);
            loop {
                tokio::select! {
                    d = down.accept_bi() => {
                        let Ok((ds, dr)) = d else { break };
                        let Ok((us, ur)) = up.open_bi().await else { break };
                        tokio::spawn(pump(dr, us));
                        tokio::spawn(pump(ur, ds));
                    }
                    _ = up.wait_closed() => break,
                }
            }
            down.close(1);
            up.close(1);
            sleep(Duration::from_millis(500)).await;
            ev!("mitm_end", "conn={id}");
        });
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Some(c) = buf.get(..n) else { break };
                if w.write_all(c).await.is_err() {
                    return;
                }
            }
        }
    }
    let _ = w.shutdown().await;
}

// ---------------------------------------------------------------- flood

pub struct FloodOpts {
    pub to: SocketAddr,
    pub id: Option<[u8; 32]>,
    pub srcs: Vec<IpAddr>,
    pub rate: u32,
    pub duration_s: u64,
}

#[derive(Default)]
struct FloodCnt {
    attempts: AtomicU64,
    connected: AtomicU64,
    failed: AtomicU64,
    skipped: AtomicU64,
    inflight: AtomicU64,
}

pub async fn run_flood<N, F, Fut>(make: F, o: &FloodOpts)
where
    N: ClientNet,
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = Result<N, BoxErr>>,
{
    let cnt = Arc::new(FloodCnt::default());
    let mut loops = Vec::new();
    for ip in &o.srcs {
        let net = match make(*ip).await {
            Ok(n) => Arc::new(n),
            Err(e) => {
                ev!("flood_error", "src={ip} err=\"{}\"", q(&e.to_string()));
                continue;
            }
        };
        let (to, id, rate, dur) = (o.to, o.id, o.rate.max(1), o.duration_s);
        let cnt = cnt.clone();
        loops.push(tokio::spawn(async move {
            let end = Instant::now() + Duration::from_secs(dur);
            let mut tick = tokio::time::interval(Duration::from_micros(1_000_000 / u64::from(rate)));
            while Instant::now() < end {
                tick.tick().await;
                if cnt.inflight.load(Ordering::Relaxed) >= 300 {
                    cnt.skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                cnt.attempts.fetch_add(1, Ordering::Relaxed);
                cnt.inflight.fetch_add(1, Ordering::Relaxed);
                let (net, cnt) = (net.clone(), cnt.clone());
                tokio::spawn(async move {
                    flood_one(&*net, to, id, &cnt).await;
                    cnt.inflight.fetch_sub(1, Ordering::Relaxed);
                });
            }
            net
        }));
    }
    let mut nets = Vec::new();
    for l in loops {
        if let Ok(n) = l.await {
            nets.push(n);
        }
    }
    sleep(Duration::from_secs(6)).await;
    for n in nets {
        n.shutdown().await;
    }
    ev!(
        "flood_done",
        "attempts={} connected={} failed={} skipped={}",
        cnt.attempts.load(Ordering::Relaxed),
        cnt.connected.load(Ordering::Relaxed),
        cnt.failed.load(Ordering::Relaxed),
        cnt.skipped.load(Ordering::Relaxed)
    );
}

async fn flood_one<N: ClientNet>(net: &N, to: SocketAddr, id: Option<[u8; 32]>, cnt: &FloodCnt) {
    let Ok(Ok(conn)) = timeout(Duration::from_secs(5), net.connect(to, id)).await else {
        cnt.failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    cnt.connected.fetch_add(1, Ordering::Relaxed);
    let mut junk = Vec::with_capacity(82);
    junk.extend_from_slice(&[1, 1]);
    junk.extend_from_slice(&rand16().unwrap_or([7; 16]));
    junk.extend_from_slice(&rand32().unwrap_or([9; 32]));
    junk.extend_from_slice(&rand32().unwrap_or([9; 32]));
    if let Ok((mut s, _r)) = conn.open_bi().await {
        let _ = s.write_all(&junk).await;
        let _ = s.shutdown().await;
        let _ = timeout(Duration::from_secs(2), conn.wait_closed()).await;
    }
    conn.close(0);
}
