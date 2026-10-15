//! Вариант B: quinn 0.11.12 + rustls 0.23.46. Одноразовый ключ сервера на каждое входящее
//! (`Incoming::accept_with`), клиент без пиннинга с проверкой подписи рукопожатия.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::pki_types::CertificateDer;

use spike::auth::{Conn, EKM_CONTEXT, EKM_LABEL, Mode};
use spike::ev;
use spike::harness::{self, ClientNet, ClientOpts, FloodOpts, Incoming as Inc, ServerNet, ServerOpts};
use spike::keys;
use spike::tlsb::{self, SERVER_NAME};
use spike::util::{Args, BoxErr, err, hex, init_clock, q};

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

/// Настройки транспорта: как у A (keep-alive 5 с, простой по умолчанию 30 с).
fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    Arc::new(t)
}

/// Одноразовый серверный конфиг quinn: новый ключ Ed25519, новый rustls-конфиг.
fn fresh_server_config(mismatch: bool) -> Result<(quinn::ServerConfig, Vec<u8>), BoxErr> {
    let issued = tlsb::ephemeral_server(mismatch)?;
    let qc = QuicServerConfig::try_from(issued.cfg).map_err(|e| err(format!("QuicServerConfig: {e}")))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qc));
    sc.transport_config(transport());
    Ok((sc, issued.spki))
}

struct IncB {
    inc: quinn::Incoming,
    mismatch: bool,
}

impl Inc for IncB {
    type C = ConnB;
    fn peer(&self) -> SocketAddr {
        self.inc.remote_address()
    }
    fn validated(&self) -> bool {
        self.inc.remote_address_validated()
    }
    fn retry(self) {
        let _ = self.inc.retry();
    }
    fn ignore(self) {
        self.inc.ignore();
    }
    async fn accept(self) -> Result<ConnB, BoxErr> {
        let peer = self.inc.remote_address();
        let (sc, spki) = fresh_server_config(self.mismatch)?;
        ev!("server_spki_issued", "peer={peer} spki={}", hex(&spki));
        let connecting = self.inc.accept_with(Arc::new(sc))?;
        Ok(ConnB(connecting.await?))
    }
}

struct ServerB {
    eps: Vec<Endpoint>,
    mismatch: bool,
}

impl ServerNet for ServerB {
    type I = IncB;
    async fn next(&self) -> Option<IncB> {
        let inc = match self.eps.as_slice() {
            [a] => a.accept().await,
            [a, b] => {
                tokio::select! {
                    x = a.accept() => x,
                    y = b.accept() => y,
                }
            }
            _ => None,
        };
        inc.map(|inc| IncB { inc, mismatch: self.mismatch })
    }
}

struct ClientB {
    ep: Endpoint,
    cfg: quinn::ClientConfig,
}

fn client_config() -> Result<quinn::ClientConfig, BoxErr> {
    let qc = QuicClientConfig::try_from(tlsb::client_tls()?).map_err(|e| err(format!("QuicClientConfig: {e}")))?;
    let mut cc = quinn::ClientConfig::new(Arc::new(qc));
    cc.transport_config(transport());
    Ok(cc)
}

impl ClientNet for ClientB {
    type C = ConnB;
    async fn connect(&self, to: SocketAddr, _id: Option<[u8; 32]>) -> Result<ConnB, BoxErr> {
        let c = self.ep.connect_with(self.cfg.clone(), to, SERVER_NAME)?.await?;
        Ok(ConnB(c))
    }
    async fn shutdown(&self) {
        self.ep.close(VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_secs(2), self.ep.wait_idle()).await;
    }
}

fn parse_addrs(s: &str) -> Result<Vec<SocketAddr>, BoxErr> {
    s.split(',')
        .map(|a| a.trim().parse::<SocketAddr>().map_err(|e| err(format!("адрес {a}: {e}"))))
        .collect()
}

fn unspecified_for(to: SocketAddr) -> SocketAddr {
    if to.is_ipv6() { SocketAddr::from(([0u16; 8], 0)) } else { SocketAddr::from(([0, 0, 0, 0], 0)) }
}

fn bind_listen(listen: &str, mismatch: bool) -> Result<ServerB, BoxErr> {
    let mut eps = Vec::new();
    for a in parse_addrs(listen)? {
        // Серверный конфиг сокета нужен только для приёма; каждое входящее идёт через accept_with с новым ключом.
        let (base, _) = fresh_server_config(mismatch)?;
        eps.push(Endpoint::server(base, a)?);
    }
    if eps.is_empty() || eps.len() > 2 {
        return Err(err("--listen: нужен один или два адреса"));
    }
    ev!("bound", "id=-");
    Ok(ServerB { eps, mismatch })
}

fn bind_client(addr: SocketAddr) -> Result<ClientB, BoxErr> {
    let ep = Endpoint::client(addr)?;
    ev!("bound", "id=-");
    Ok(ClientB { ep, cfg: client_config()? })
}

fn dir_of(a: &Args) -> Result<PathBuf, BoxErr> {
    Ok(PathBuf::from(a.get("pairs").or(a.get("dir")).ok_or_else(|| err("нужен --pairs/--dir"))?))
}

fn sock(a: &Args, key: &str) -> Result<SocketAddr, BoxErr> {
    a.req(key)?.parse().map_err(|e| err(format!("--{key}: {e}")))
}

async fn zrtt(to: SocketAddr, local: SocketAddr) -> Result<(), BoxErr> {
    let cl = bind_client(local)?;
    let c1 = cl.ep.connect_with(cl.cfg.clone(), to, SERVER_NAME)?.await?;
    ev!("zrtt_first", "done");
    c1.close(VarInt::from_u32(0), b"");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let connecting = cl.ep.connect_with(cl.cfg.clone(), to, SERVER_NAME)?;
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            let ok = accepted.await;
            ev!("zero_rtt", "{}", if ok { "accepted" } else { "refused" });
            conn.close(VarInt::from_u32(0), b"");
        }
        Err(connecting) => {
            ev!("zero_rtt", "refused why=no_0rtt_keys");
            let conn = connecting.await?;
            conn.close(VarInt::from_u32(0), b"");
        }
    }
    cl.shutdown().await;
    Ok(())
}

async fn run() -> Result<(), BoxErr> {
    init_clock();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = Args::parse(&argv, &["no-limit", "bad-auth2", "tls-key-mismatch"])?;
    match a.cmd.as_str() {
        "keygen" => {
            let dir = dir_of(&a)?;
            let mut needles = keys::keygen_pairs(&dir)?;
            needles.push("sni_b str chervo.invalid".into());
            keys::write_needles(&dir, &needles)?;
            println!("keygen ok: {}", dir.display());
        }
        "server" => {
            let dir = dir_of(&a)?;
            let pairs = Arc::new(keys::load_pairs(&dir)?);
            let srv = bind_listen(a.req("listen")?, a.flag("tls-key-mismatch"))?;
            let limit = if a.flag("no-limit") {
                None
            } else {
                Some((a.num("limit-per-ip", 5usize)?, Duration::from_secs(a.num("window-s", 10u64)?)))
            };
            let opts = ServerOpts { limit, bad_auth2: a.flag("bad-auth2"), pairs };
            harness::run_server(Arc::new(srv), opts).await;
        }
        "client" => {
            let dir = dir_of(&a)?;
            let pairs = Arc::new(keys::load_pairs(&dir)?);
            let to = sock(&a, "connect")?;
            let cl = bind_client(unspecified_for(to))?;
            let pair_n: usize = a.num("pair", 1usize)?;
            let mode = Mode::parse(a.get("mode").unwrap_or("ok")).ok_or_else(|| err("неизвестный --mode"))?;
            let o = ClientOpts {
                to,
                id: None,
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
            harness::run_client(&cl, &o).await;
        }
        "zrtt" => {
            let to = sock(&a, "connect")?;
            zrtt(to, unspecified_for(to)).await?;
        }
        "mitm" => {
            let srv = bind_listen(a.req("listen")?, false)?;
            let to = sock(&a, "upstream")?;
            let up = bind_client(unspecified_for(to))?;
            harness::run_mitm(Arc::new(srv), Arc::new(up), to, None).await;
        }
        "flood" => {
            let srcs: Result<Vec<IpAddr>, BoxErr> = a
                .req("src")?
                .split(',')
                .map(|s| s.trim().parse::<IpAddr>().map_err(|e| err(format!("--src: {e}"))))
                .collect();
            let o = FloodOpts {
                to: sock(&a, "target")?,
                id: None,
                srcs: srcs?,
                rate: a.num("rate", 20u32)?,
                duration_s: a.num("duration", 30u64)?,
            };
            harness::run_flood(|ip| async move { bind_client(SocketAddr::new(ip, 0)) }, &o).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Полное рукопожатие по loopback: экспортёры совпадают, ключи сервера у двух соединений разные.
    #[tokio::test]
    async fn b_loopback_ekm_equal_and_server_keys_differ() {
        let srv = match bind_listen("127.0.0.1:0", false) {
            Ok(s) => s,
            Err(e) => panic!("bind: {e}"),
        };
        let addr = srv.eps[0].local_addr().expect("addr");
        let srv = Arc::new(srv);
        let s2 = srv.clone();
        let server = tokio::spawn(async move {
            let mut out = Vec::new();
            for _ in 0..2 {
                let Some(inc) = s2.next().await else { break };
                let Ok(c) = inc.accept().await else { break };
                let mut e = [0u8; 32];
                let _ = c.ekm(&mut e);
                out.push((e, c.peer_identity()));
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            out
        });
        let cl = bind_client(unspecified_for(addr)).expect("client");
        let mut seen = Vec::new();
        for _ in 0..2 {
            let c = cl.connect(addr, None).await.expect("connect");
            let mut e = [0u8; 32];
            c.ekm(&mut e).expect("ekm");
            seen.push((e, c.server_spki().expect("spki")));
        }
        let srv_out = server.await.expect("server task");
        assert_eq!(srv_out.len(), 2);
        assert_eq!(srv_out[0].0, seen[0].0);
        assert_eq!(srv_out[1].0, seen[1].0);
        assert_ne!(seen[0].0, seen[1].0);
        assert_ne!(seen[0].1, seen[1].1);
        assert!(!srv_out[0].1, "сертификат клиента не запрашивался");
    }
}
