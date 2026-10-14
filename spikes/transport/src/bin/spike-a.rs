//! Вариант A: iroh 1.3.0 (Minimal, без relay и address lookup).
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{
    Connection, Incoming, RecvStream, SendStream, VarInt, presets,
};
#[cfg(not(feature = "iroh-portmapper"))]
use iroh::endpoint::PortmapperConfig;
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, TransportAddr};

use spike::auth::{Conn, EKM_CONTEXT, EKM_LABEL, Mode};
use spike::harness::{self, ClientNet, ClientOpts, FloodOpts, Incoming as Inc, ServerNet, ServerOpts};
use spike::keys;
use spike::util::{Args, BoxErr, err, hex, init_clock, q, unhex32};
use spike::ev;

const ALPN: &[u8] = b"chervo-spike/1";

#[derive(Clone)]
struct ConnA(Connection);

impl Conn for ConnA {
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
}

struct IncA(Incoming);

impl Inc for IncA {
    type C = ConnA;
    fn peer(&self) -> SocketAddr {
        match self.0.remote_addr() {
            iroh::endpoint::IncomingAddr::Ip(a) => a,
            _ => SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }
    fn validated(&self) -> bool {
        self.0.remote_addr_validated()
    }
    fn retry(self) {
        let _ = self.0.retry();
    }
    fn ignore(self) {
        self.0.ignore();
    }
    async fn accept(self) -> Result<ConnA, BoxErr> {
        let acc = self.0.accept()?;
        Ok(ConnA(acc.await?))
    }
}

struct ServerA(Endpoint);

impl ServerNet for ServerA {
    type I = IncA;
    async fn next(&self) -> Option<IncA> {
        self.0.accept().await.map(IncA)
    }
}

struct ClientA(Endpoint);

impl ClientNet for ClientA {
    type C = ConnA;
    async fn connect(&self, to: SocketAddr, id: Option<[u8; 32]>) -> Result<ConnA, BoxErr> {
        let id = id.ok_or_else(|| err("для варианта A нужен id сервера (--id)"))?;
        let pk = PublicKey::from_bytes(&id)?;
        let addr = EndpointAddr::new(pk).with_addrs([TransportAddr::Ip(to)]);
        Ok(ConnA(self.0.connect(addr, ALPN).await?))
    }
    async fn shutdown(&self) {
        self.0.close().await;
    }
}

fn base_builder() -> iroh::endpoint::Builder {
    let b = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![ALPN.to_vec()])
        .max_tls_tickets(0);
    #[cfg(not(feature = "iroh-portmapper"))]
    let b = b.portmapper_config(PortmapperConfig::Disabled);
    b
}

fn parse_addrs(s: &str) -> Result<Vec<SocketAddr>, BoxErr> {
    s.split(',')
        .map(|a| a.trim().parse::<SocketAddr>().map_err(|e| err(format!("адрес {a}: {e}"))))
        .collect()
}

async fn bind_listen(listen: &str, seed: [u8; 32]) -> Result<Endpoint, BoxErr> {
    let mut b = base_builder().secret_key(SecretKey::from_bytes(&seed)).clear_ip_transports();
    for a in parse_addrs(listen)? {
        b = b.bind_addr(a)?;
    }
    let ep = b.bind().await?;
    ev!("bound", "id={}", hex(ep.id().as_bytes()));
    Ok(ep)
}

async fn bind_client(src: Option<IpAddr>, seed: Option<[u8; 32]>) -> Result<Endpoint, BoxErr> {
    let mut b = base_builder();
    if let Some(s) = seed {
        b = b.secret_key(SecretKey::from_bytes(&s));
    }
    if let Some(ip) = src {
        b = b.clear_ip_transports().bind_addr(SocketAddr::new(ip, 0))?;
    }
    let ep = b.bind().await?;
    ev!("bound", "id={}", hex(ep.id().as_bytes()));
    Ok(ep)
}

fn dir_of(a: &Args) -> Result<PathBuf, BoxErr> {
    Ok(PathBuf::from(a.get("pairs").or(a.get("dir")).ok_or_else(|| err("нужен --pairs/--dir"))?))
}

fn id_arg(a: &Args, dir: &PathBuf, key: &str, file: &str) -> Result<Option<[u8; 32]>, BoxErr> {
    match a.get(key) {
        Some(h) => Ok(Some(unhex32(h)?)),
        None => match keys::read_text(dir, file) {
            Ok(h) => Ok(Some(unhex32(&h)?)),
            Err(_) => Ok(None),
        },
    }
}

async fn run() -> Result<(), BoxErr> {
    init_clock();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = Args::parse(&argv, &["no-limit", "bad-auth2"])?;
    match a.cmd.as_str() {
        "keygen" => {
            let dir = dir_of(&a)?;
            let mut needles = keys::keygen_pairs(&dir)?;
            for name in ["server_ep", "client_ep", "mitm_ep"] {
                let seed = keys::ensure_seed(&dir, &format!("{name}.key"))?;
                let id = hex(SecretKey::from_bytes(&seed).public().as_bytes());
                keys::write_text(&dir, &format!("{name}.id"), &id)?;
                needles.push(format!("{name}_id hex {id}"));
            }
            needles.push("sni_iroh str iroh.invalid".into());
            keys::write_needles(&dir, &needles)?;
            println!("keygen ok: {}", dir.display());
        }
        "server" => {
            let dir = dir_of(&a)?;
            let pairs = Arc::new(keys::load_pairs(&dir)?);
            let seed = keys::load_seed(&dir, "server_ep.key")?;
            let ep = bind_listen(a.req("listen")?, seed).await?;
            let limit = if a.flag("no-limit") {
                None
            } else {
                Some((a.num("limit-per-ip", 5usize)?, Duration::from_secs(a.num("window-s", 10u64)?)))
            };
            let opts = ServerOpts { limit, bad_auth2: a.flag("bad-auth2"), pairs };
            harness::run_server(Arc::new(ServerA(ep)), opts).await;
        }
        "client" => {
            let dir = dir_of(&a)?;
            let pairs = Arc::new(keys::load_pairs(&dir)?);
            let seed = keys::load_seed(&dir, "client_ep.key").ok();
            let ep = bind_client(None, seed).await?;
            let pair_n: usize = a.num("pair", 1usize)?;
            let mode = Mode::parse(a.get("mode").unwrap_or("ok")).ok_or_else(|| err("неизвестный --mode"))?;
            let o = ClientOpts {
                to: a.req("connect")?.parse().map_err(|e| err(format!("--connect: {e}")))?,
                id: id_arg(&a, &dir, "id", "server_ep.id")?,
                pairs,
                pair_idx: pair_n.saturating_sub(1).min(1),
                mode,
                bytes: a.num("bytes", 0usize)?,
                duration_s: a.num("duration", 0u64)?,
                chunk_ms: a.num("chunk-ms", 100u64)?,
                idle_s: a.num("idle-s", 0u64)?,
                repeat: a.num("repeat", 1u32)?,
                change_addr_at: a.get("change-addr-at").and_then(|v| v.parse().ok()),
            };
            harness::run_client(&ClientA(ep), &o).await;
        }
        "mitm" => {
            let dir = dir_of(&a)?;
            let seed = keys::load_seed(&dir, "mitm_ep.key")?;
            let srv = bind_listen(a.req("listen")?, seed).await?;
            let up = bind_client(None, None).await?;
            let to: SocketAddr = a.req("upstream")?.parse().map_err(|e| err(format!("--upstream: {e}")))?;
            let uid = id_arg(&a, &dir, "upstream-id", "server_ep.id")?;
            harness::run_mitm(Arc::new(ServerA(srv)), Arc::new(ClientA(up)), to, uid).await;
        }
        "flood" => {
            let dir = dir_of(&a)?;
            let srcs: Result<Vec<IpAddr>, BoxErr> = a
                .req("src")?
                .split(',')
                .map(|s| s.trim().parse::<IpAddr>().map_err(|e| err(format!("--src: {e}"))))
                .collect();
            let o = FloodOpts {
                to: a.req("target")?.parse().map_err(|e| err(format!("--target: {e}")))?,
                id: id_arg(&a, &dir, "id", "server_ep.id")?,
                srcs: srcs?,
                rate: a.num("rate", 20u32)?,
                duration_s: a.num("duration", 30u64)?,
            };
            harness::run_flood(|ip| async move { Ok(ClientA(bind_client(Some(ip), None).await?)) }, &o).await;
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
