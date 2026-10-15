//! Этап 8: замеры G4-G8, только вариант B (quinn 0.11.12 + rustls 0.23.46). Одноразовый код.
//! Подкоманды: keygen, recv, send, hello, punch, reflect, natprobe, rdv, upnp.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, VarInt};
use rustls::pki_types::CertificateDer;
use tokio::time::{Instant, sleep, timeout};

use spike::auth::{CallerCfg, Conn, EKM_CONTEXT, EKM_LABEL, Mode, PairSet, Stats, callee_auth, caller_auth};
use spike::tlsb::{self, SERVER_NAME};
use spike::util::{Args, BoxErr, err, hex, init_clock, q, unhex};
use spike::xfer::{self, RecvState, SendOpts, Served};
use spike::{ev, keys, natp};

/// Адаптер quinn для `auth::Conn` (копия из spike-b.rs).
#[derive(Clone)]
struct ConnB(Connection);

impl Conn for ConnB {
    type S = SendStream;
    type R = RecvStream;
    async fn open_bi(&self) -> Result<(SendStream, RecvStream), BoxErr> {
        Ok(self.0.open_bi().await?)
    }
    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), BoxErr> {
        Ok(self.0.accept_bi().await?)
    }
    fn ekm(&self, out: &mut [u8; 32]) -> Result<(), BoxErr> {
        self.0
            .export_keying_material(out, EKM_LABEL, EKM_CONTEXT)
            .map_err(|e| err(format!("export_keying_material: {e:?}")))
    }
    fn close(&self, code: u32) {
        self.0.close(VarInt::from_u32(code), b"");
    }
    async fn wait_closed(&self) -> String {
        format!("{}", self.0.closed().await)
    }
    fn peer_identity(&self) -> bool {
        self.0.peer_identity().is_some()
    }
    fn server_spki(&self) -> Option<Vec<u8>> {
        let id = self.0.peer_identity()?;
        let certs = id.downcast::<Vec<CertificateDer<'static>>>().ok()?;
        certs.first().map(|c| c.as_ref().to_vec())
    }
}

fn sock(a: &Args, key: &str) -> Result<SocketAddr, BoxErr> {
    a.req(key)?.parse().map_err(|e| err(format!("--{key}: {e}")))
}

fn parse_addrs(s: &str) -> Result<Vec<SocketAddr>, BoxErr> {
    s.split(',')
        .map(|x| x.trim().parse::<SocketAddr>().map_err(|e| err(format!("адрес {x}: {e}"))))
        .collect()
}

fn dir_of(a: &Args) -> Result<PathBuf, BoxErr> {
    Ok(PathBuf::from(a.get("pairs").or(a.get("dir")).ok_or_else(|| err("нужен --pairs/--dir"))?))
}

fn epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn pair_idx(a: &Args) -> Result<usize, BoxErr> {
    let n: usize = a.num("pair", 1usize)?;
    Ok(n.saturating_sub(1).min(1))
}

fn transport_from(a: &Args) -> Result<Arc<quinn::TransportConfig>, BoxErr> {
    xfer::transport(
        a.get("win").unwrap_or("W0"),
        a.get("cc").unwrap_or("cubic"),
        a.num("idle-s", 0u64)?,
        a.num("keepalive-s", 0u64)?,
    )
}

/// Звонящий: соединение и аутентификация (AUTH1/AUTH2 из спайка этапа 7 без изменений).
async fn caller_conn(
    ep: &Endpoint,
    cc: &quinn::ClientConfig,
    pairs: &PairSet,
    idx: usize,
    to: SocketAddr,
) -> Result<Connection, BoxErr> {
    let t0 = Instant::now();
    let conn = ep.connect_with(cc.clone(), to, SERVER_NAME)?.await?;
    let hs = t0.elapsed();
    let b = ConnB(conn.clone());
    let mut e = [0u8; 32];
    b.ekm(&mut e)?;
    let (Some(pair), Some(other)) = (pairs.0.get(idx), pairs.0.get(1 - idx.min(1))) else {
        return Err(err("нет ключей пары"));
    };
    let cfg = CallerCfg { mode: Mode::Ok, pair, other, ekm_override: None, random_pair: [0u8; 16] };
    let mut st = Stats::default();
    let t1 = Instant::now();
    if let Err(f) = caller_auth(&b, &cfg, &e, &mut st).await {
        conn.close(VarInt::from_u32(1), b"");
        return Err(err(format!("auth: {}", f.reason())));
    }
    ev!("auth_ok", "side=c to={to} hs_ms={} auth_ms={}", hs.as_millis(), t1.elapsed().as_millis());
    Ok(conn)
}

/// Вызываемый: новый ключ сервера на каждое входящее, затем аутентификация.
async fn callee_conn(inc: quinn::Incoming, tc: Arc<quinn::TransportConfig>, pairs: &PairSet) -> Result<Connection, BoxErr> {
    let (sc, spki) = xfer::fresh_server_config(tc)?;
    let peer = inc.remote_address();
    ev!("server_spki_issued", "peer={peer} spki={}", hex(&spki));
    let t0 = Instant::now();
    let conn = timeout(Duration::from_secs(10), inc.accept_with(Arc::new(sc))?)
        .await
        .map_err(|_| err("handshake: тайм-аут"))??;
    let b = ConnB(conn.clone());
    let mut e = [0u8; 32];
    b.ekm(&mut e)?;
    match callee_auth(&b, pairs, &e, false).await {
        Ok(_) => {
            ev!("auth_ok", "side=s peer={peer} dur_ms={}", t0.elapsed().as_millis());
            Ok(conn)
        }
        Err(f) => {
            conn.close(VarInt::from_u32(1), b"");
            ev!("auth_fail", "peer={peer} reason={}", f.reason());
            Err(err(format!("auth: {}", f.reason())))
        }
    }
}

// ---------------------------------------------------------------- recv

async fn cmd_recv(a: &Args) -> Result<(), BoxErr> {
    let pairs = Arc::new(keys::load_pairs(&dir_of(a)?)?);
    let listen = sock(a, "listen")?;
    let out_dir = PathBuf::from(a.req("out-dir")?);
    std::fs::create_dir_all(&out_dir)?;
    let max_bytes: u64 = a.num("max-bytes", 0u64)?;
    if max_bytes == 0 {
        return Err(err("нужен --max-bytes > 0"));
    }
    let tc = transport_from(a)?;
    let (base, _) = xfer::fresh_server_config(tc.clone())?;
    let ep = Endpoint::server(base, listen)?;
    ev!("bound", "id=- listen={listen}");
    let st = Arc::new(RecvState::new(&out_dir, max_bytes));
    let finished = Arc::new(AtomicBool::new(false));
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        if finished.load(Ordering::SeqCst) {
            break;
        }
        let inc = tokio::select! {
            i = ep.accept() => i,
            () = sleep(Duration::from_millis(100)) => continue,
        };
        let Some(inc) = inc else { break };
        if live.fetch_add(1, Ordering::SeqCst) >= 64 {
            live.fetch_sub(1, Ordering::SeqCst);
            inc.ignore();
            continue;
        }
        let (pairs, tc, st, finished, live) = (pairs.clone(), tc.clone(), st.clone(), finished.clone(), live.clone());
        tokio::spawn(async move {
            if let Ok(conn) = callee_conn(inc, tc, &pairs).await {
                match xfer::serve_conn(conn, st).await {
                    Served::Done(n) => {
                        ev!("recv_done", "bytes={n}");
                        finished.store(true, Ordering::SeqCst);
                    }
                    Served::Rejected(why) => ev!("serve_rejected", "why={}", q(&why)),
                    Served::Hello | Served::Dropped => {}
                }
            }
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
    sleep(Duration::from_millis(300)).await;
    ep.close(VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(1), ep.wait_idle()).await;
    Ok(())
}

// ---------------------------------------------------------------- send, hello

fn client_endpoint(local: SocketAddr, a: &Args) -> Result<(Endpoint, quinn::ClientConfig), BoxErr> {
    let ep = Endpoint::client(local)?;
    let cc = xfer::client_config(transport_from(a)?)?;
    Ok((ep, cc))
}

async fn cmd_send(a: &Args) -> Result<(), BoxErr> {
    let pairs = Arc::new(keys::load_pairs(&dir_of(a)?)?);
    let addrs = parse_addrs(a.req("connect")?)?;
    let local: SocketAddr = match a.get("local") {
        Some(l) => l.parse().map_err(|e| err(format!("--local: {e}")))?,
        None => "0.0.0.0:0".parse().map_err(|e| err(format!("{e}")))?,
    };
    let idx = pair_idx(a)?;
    let (ep, cc) = client_endpoint(local, a)?;
    ev!("bound", "id=- local={local}");
    let o = SendOpts {
        addrs,
        file: PathBuf::from(a.req("file")?),
        streams: a.num("streams", 1u8)?,
        reconnect_deadline: Duration::from_secs(a.num("reconnect-deadline-s", 60u64)?),
        attempt: Duration::from_secs(3),
        test_abort_after: None,
    };
    let dial = |to: SocketAddr| {
        let (ep, cc, pairs) = (ep.clone(), cc.clone(), pairs.clone());
        async move { caller_conn(&ep, &cc, &pairs, idx, to).await }
    };
    let rep = xfer::send_file(dial, &o).await;
    ep.close(VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(1), ep.wait_idle()).await;
    let rep = rep?;
    ev!(
        "send_result",
        "ok=1 size={} app_bytes_sent={} conns={} first_resume_from={} max_resume_from={}",
        rep.size,
        rep.app_bytes_sent,
        rep.conns,
        rep.first_resume_from,
        rep.max_resume_from
    );
    Ok(())
}

async fn cmd_hello(a: &Args) -> Result<(), BoxErr> {
    let pairs = keys::load_pairs(&dir_of(a)?)?;
    let to = sock(a, "connect")?;
    let local = sock(a, "local")?;
    let (ep, cc) = client_endpoint(local, a)?;
    let conn = timeout(Duration::from_secs(10), caller_conn(&ep, &cc, &pairs, pair_idx(a)?, to))
        .await
        .map_err(|_| err("hello: тайм-аут соединения"))??;
    let seen = xfer::hello(&conn).await?;
    ev!("observed_by_peer", "addr={seen}");
    conn.close(VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(1), ep.wait_idle()).await;
    Ok(())
}

// ---------------------------------------------------------------- punch

type Found = Arc<Mutex<Vec<(&'static str, u128)>>>;

async fn cmd_punch(a: &Args) -> Result<(), BoxErr> {
    let pairs = Arc::new(keys::load_pairs(&dir_of(a)?)?);
    let local = sock(a, "local")?;
    let idx = pair_idx(a)?;
    let mode = a.req("mode")?.to_string();
    let interval = Duration::from_secs(a.num("interval-s", 5u64)?);
    let attempt = Duration::from_secs(a.num("attempt-s", if mode == "sync" { 15u64 } else { 10u64 })?);
    let deadline = Duration::from_secs(a.num("deadline-s", 40u64)?);
    let us = std::net::UdpSocket::bind(local)?;
    let start = Instant::now();
    ev!("punch_start", "epoch_ms={} mode={mode}", epoch_ms());
    let mut peer: Option<SocketAddr> = a.get("peer").map(|p| p.parse()).transpose().map_err(|e| err(format!("--peer: {e}")))?;
    let mut t_ref = start;
    if mode == "sync" {
        let rdv = sock(a, "rdv")?;
        let tag = unhex(a.req("tag")?)?;
        let tag = <[u8; 16]>::try_from(tag.as_slice()).map_err(|_| err("--tag: нужно 32 hex-символа"))?;
        let side: u8 = a.num("side", 1u8)?;
        let us2 = us.try_clone()?;
        let (p, delay) = tokio::task::spawn_blocking(move || natp::rdv_register_blocking(&us2, rdv, tag, side, deadline))
            .await
            .map_err(|e| err(format!("join: {e}")))??;
        ev!("punch_go", "epoch_ms={} peer={p} delay_ms={delay}", epoch_ms());
        sleep(Duration::from_millis(u64::from(delay))).await;
        peer = Some(p);
        t_ref = Instant::now();
        ev!("punch_attempt_start", "epoch_ms={}", epoch_ms());
    } else if mode != "periodic" {
        return Err(err("--mode: periodic|sync"));
    }
    let peer = peer.ok_or_else(|| err("нужен --peer"))?;
    us.set_nonblocking(true)?;
    let tc = xfer::transport("W0", "cubic", 0, 0)?;
    let (base, _) = xfer::fresh_server_config(tc.clone())?;
    let ep = Endpoint::new(EndpointConfig::default(), Some(base), us, Arc::new(quinn::TokioRuntime))?;
    let cc = {
        let qc = QuicClientConfig::try_from(tlsb::client_tls()?).map_err(|e| err(format!("QuicClientConfig: {e}")))?;
        let mut c = quinn::ClientConfig::new(Arc::new(qc));
        c.transport_config(tc.clone());
        c
    };
    ev!("bound", "id=- local={local}");
    let found: Found = Arc::new(Mutex::new(Vec::new()));
    // приём входящих (вызываемый)
    {
        let (ep, found, pairs, tc) = (ep.clone(), found.clone(), pairs.clone(), tc.clone());
        tokio::spawn(async move {
            while let Some(inc) = ep.accept().await {
                let (found, pairs, tc) = (found.clone(), pairs.clone(), tc.clone());
                tokio::spawn(async move {
                    if let Ok(c) = callee_conn(inc, tc, &pairs).await {
                        if let Ok(mut g) = found.lock() {
                            g.push(("in", t_ref.elapsed().as_millis()));
                        }
                        // держим соединение, пока процесс жив
                        c.closed().await;
                    }
                });
            }
        });
    }
    // исходящие попытки (звонящий)
    let running = Arc::new(AtomicUsize::new(0));
    let launch = {
        let (ep, cc, pairs, found, running) = (ep.clone(), cc.clone(), pairs.clone(), found.clone(), running.clone());
        move || {
            if running.fetch_add(1, Ordering::SeqCst) >= 2 {
                running.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            let (ep, cc, pairs, found, running) = (ep.clone(), cc.clone(), pairs.clone(), found.clone(), running.clone());
            ev!("punch_attempt", "to={peer} epoch_ms={}", epoch_ms());
            tokio::spawn(async move {
                if let Ok(Ok(c)) = timeout(attempt, caller_conn(&ep, &cc, &pairs, idx, peer)).await {
                    if let Ok(mut g) = found.lock() {
                        g.push(("out", t_ref.elapsed().as_millis()));
                    }
                    c.closed().await;
                }
                running.fetch_sub(1, Ordering::SeqCst);
            });
        }
    };
    let overall = if mode == "sync" { attempt + Duration::from_secs(1) } else { deadline };
    let mut next_launch = t_ref;
    let mut first_seen: Option<Instant> = None;
    loop {
        let now = Instant::now();
        if first_seen.is_none() {
            let any = found.lock().map(|g| !g.is_empty()).unwrap_or(false);
            if any {
                first_seen = Some(now);
            }
        }
        if let Some(f) = first_seen {
            if now.duration_since(f) >= Duration::from_millis(1500) {
                break;
            }
        } else {
            if now.duration_since(t_ref) >= overall {
                ev!("punch_fail", "reason=deadline");
                ep.close(VarInt::from_u32(0), b"");
                return Err(err("punch: дедлайн"));
            }
            if now >= next_launch && (mode == "periodic" || next_launch == t_ref) {
                launch();
                next_launch = if mode == "periodic" { now + interval } else { now + Duration::from_secs(3600) };
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
    let g = found.lock().map(|g| g.clone()).unwrap_or_default();
    let has = |d: &str| g.iter().any(|x| x.0 == d);
    let dir = match (has("out"), has("in")) {
        (true, true) => "both",
        (true, false) => "out",
        _ => "in",
    };
    let ms = g.iter().map(|x| x.1).min().unwrap_or(0);
    ev!("punch_ok", "dir={dir} ms={ms} epoch_ms={}", epoch_ms());
    ep.close(VarInt::from_u32(0), b"");
    let _ = timeout(Duration::from_secs(1), ep.wait_idle()).await;
    Ok(())
}

// ---------------------------------------------------------------- upnp

fn cmd_upnp(op: &str, a: &Args) -> Result<(), BoxErr> {
    use igd_next::{PortMappingProtocol, SearchOptions, search_gateway};
    let internal = sock(a, "internal")?;
    let mut so = SearchOptions::default();
    so.bind_addr = SocketAddr::new(internal.ip(), 0);
    so.timeout = Some(Duration::from_secs(5));
    so.single_search_timeout = Some(Duration::from_secs(2));
    let gw = match search_gateway(so) {
        Ok(g) => g,
        Err(e) => {
            ev!("upnp_error", "op=search msg={}", q(&format!("{e}")));
            return Err(err("upnp: шлюз не найден"));
        }
    };
    ev!("upnp_gateway", "addr={}", gw.addr);
    match gw.get_external_ip() {
        Ok(ip) => ev!("upnp_ext_ip", "ip={ip}"),
        Err(e) => ev!("upnp_error", "op=get_external_ip msg={}", q(&format!("{e}"))),
    }
    let ext_port: u16 = a.num("ext-port", 0u16)?;
    match op {
        "info" => {
            for i in 0..16u32 {
                match gw.get_generic_port_mapping_entry(i) {
                    Ok(e) => ev!(
                        "upnp_entry",
                        "idx={i} ext_port={} proto={:?} internal={}:{} lease={} enabled={}",
                        e.external_port,
                        e.protocol,
                        e.internal_client,
                        e.internal_port,
                        e.lease_duration,
                        e.enabled
                    ),
                    Err(_) => break,
                }
            }
        }
        "map" => {
            let lease: u32 = a.num("lease", 120u32)?;
            match gw.add_port(PortMappingProtocol::UDP, ext_port, internal, lease, "chervo-spike8") {
                Ok(()) => ev!("upnp_mapped", "ext_port={ext_port} internal={internal} lease={lease}"),
                Err(e) => {
                    ev!("upnp_error", "op=add_port msg={}", q(&format!("{e}")));
                    return Err(err("upnp: add_port отказ"));
                }
            }
            let hold: u64 = a.num("hold-s", 0u64)?;
            if hold > 0 {
                std::thread::sleep(Duration::from_secs(hold));
            }
        }
        "unmap" => match gw.remove_port(PortMappingProtocol::UDP, ext_port) {
            Ok(()) => ev!("upnp_unmapped", "ext_port={ext_port}"),
            Err(e) => {
                ev!("upnp_error", "op=remove_port msg={}", q(&format!("{e}")));
                return Err(err("upnp: remove_port отказ"));
            }
        },
        other => return Err(err(format!("upnp: неизвестная операция {other}"))),
    }
    Ok(())
}

// ---------------------------------------------------------------- main

async fn run() -> Result<(), BoxErr> {
    init_clock();
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    let mut upnp_op = String::new();
    if argv.first().map(String::as_str) == Some("upnp") && argv.len() > 1 {
        upnp_op = argv.remove(1);
    }
    let a = Args::parse(&argv, &[])?;
    match a.cmd.as_str() {
        "keygen" => {
            let dir = dir_of(&a)?;
            let needles = keys::keygen_pairs(&dir)?;
            keys::write_needles(&dir, &needles)?;
            println!("keygen ok: {}", dir.display());
        }
        "recv" => cmd_recv(&a).await?,
        "send" => cmd_send(&a).await?,
        "hello" => cmd_hello(&a).await?,
        "punch" => cmd_punch(&a).await?,
        "reflect" => {
            let b = parse_addrs(a.req("bind")?)?;
            let Ok(b3) = <[SocketAddr; 3]>::try_from(b) else {
                return Err(err("--bind: нужно ровно три адреса (R1a,R1b,R2)"));
            };
            natp::reflect(b3).await?;
        }
        "natprobe" => {
            let r = natp::probe(sock(&a, "local")?, sock(&a, "r1a")?, sock(&a, "r1b")?, sock(&a, "r2")?).await?;
            let f = |x: Option<SocketAddr>| x.map_or("-".to_string(), |s| s.to_string());
            ev!(
                "nat_probe",
                "mapping={} filtering={} ext={} ext_r1b={} ext_r2={} r1b_reply={} r2_reply={}",
                r.mapping,
                r.filtering,
                f(r.ext_r1a),
                f(r.ext_r1b),
                f(r.ext_r2),
                u8::from(r.r1b_reply),
                u8::from(r.r2_reply)
            );
        }
        "rdv" => natp::rdv_serve(sock(&a, "listen")?).await?,
        "upnp" => {
            let op = upnp_op.clone();
            tokio::task::spawn_blocking(move || cmd_upnp(&op, &a))
                .await
                .map_err(|e| err(format!("join: {e}")))??;
        }
        other => return Err(err(format!("неизвестная подкоманда {other}"))),
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("ERROR {}", q(&e.to_string()));
        std::process::exit(2);
    }
}
