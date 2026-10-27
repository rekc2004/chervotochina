//! Поддельный IGD на петле (часть U2): потоки std, SSDP по unicast, записанный журнал.
//!
//! Роутеры живут на 127.0.0.2, 127.0.0.3, ...; клиент привязан к 127.0.0.1 (`OWN`). Если
//! адреса 127.0.0.N недоступны для привязки, `Lab::new` возвращает `None`, а `skip()`
//! роняет тест (на Linux и Windows сбой привязки это ошибка, а не молчаливый зачёт). На
//! macOS без алиасов эти тесты помечены `ignore` (`cfg_attr`) и не запускаются.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chervo_addr::MapRequest;

use crate::mapper::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings};
use crate::net::Net;

pub const OWN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const PORT: u16 = 40123;
pub const WAN: &str = "93.184.216.34";
pub const UDN: &str = "uuid:fake-router-1";
pub const SVC_V1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
pub const SVC_V2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
pub const CTL: &str = "/ctl/IPConn";

#[derive(Clone)]
pub struct Req {
    pub is_post: bool,
    pub path: String,
    pub peer: Ipv4Addr,
    pub head: String,
    pub body: String,
    pub action: String,
    pub args: HashMap<String, String>,
}

impl Req {
    pub fn arg(&self, k: &str) -> Option<&str> {
        self.args.get(k).map(String::as_str)
    }
}

pub enum Reply {
    /// 200 с этим телом.
    Body(String),
    /// 500 с ошибкой UPnP.
    Fault(u16),
    Status(u16),
    Redirect(String),
    Raw(Vec<u8>),
    /// Принять запрос и молчать.
    Stall,
    /// Правдоподобное начало ответа, затем по одному байту в 300 мс.
    Drip,
    /// Ответ без Content-Length и без конца: n байт тела.
    BigBody(usize),
    /// Заголовки длиннее 8 КиБ.
    HugeHead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ext: u16,
    pub internal_port: u16,
    pub client: String,
    pub desc: String,
    pub lease: u32,
}

#[derive(Clone, Copy)]
pub enum LeaseMode {
    Honor,
    /// Роутер молча делает аренду бессрочной.
    Permanent,
    /// Роутер ограничивает аренду.
    Cap(u32),
}

pub type Hook = Arc<dyn Fn(&Req, &mut Inner) -> Option<Reply> + Send + Sync>;

pub struct Cfg {
    pub udn: String,
    pub wan: String,
    /// (тип службы, путь управления)
    pub services: Vec<(String, String)>,
    /// Хост в `LOCATION` вместо настоящего.
    pub location_ip: Option<String>,
    pub description: Option<String>,
    pub advertise: bool,
    pub only_permanent: bool,
    pub lease_mode: LeaseMode,
    /// Внешние порты, занятые другим клиентом (ответ 718).
    pub taken: Vec<u16>,
    pub hook: Option<Hook>,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            udn: UDN.to_owned(),
            wan: WAN.to_owned(),
            services: vec![(SVC_V1.to_owned(), CTL.to_owned())],
            location_ip: None,
            description: None,
            advertise: true,
            only_permanent: false,
            lease_mode: LeaseMode::Honor,
            taken: Vec::new(),
            hook: None,
        }
    }
}

#[derive(Default)]
pub struct State {
    pub table: Vec<Entry>,
    pub log: Vec<Req>,
    pub connections: usize,
}

pub struct Inner {
    pub cfg: Cfg,
    pub state: State,
}

pub struct Router {
    pub ip: Ipv4Addr,
    pub addr: SocketAddrV4,
    pub inner: Arc<Mutex<Inner>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Router {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Router {
    pub fn start(ip: Ipv4Addr, cfg: Cfg) -> Option<Router> {
        let listener = TcpListener::bind((ip, 0)).ok()?;
        listener.set_nonblocking(true).ok()?;
        let addr = match listener.local_addr().ok()? {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => return None,
        };
        let inner = Arc::new(Mutex::new(Inner {
            cfg,
            state: State::default(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let (i2, s2) = (Arc::clone(&inner), Arc::clone(&stop));
        thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, peer)) => {
                        lock(&i2).state.connections += 1;
                        let i3 = Arc::clone(&i2);
                        thread::spawn(move || {
                            if s.set_nonblocking(false).is_ok() {
                                serve(s, peer, &i3);
                            }
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Some(Router {
            ip,
            addr,
            inner,
            stop,
        })
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut lock(&self.inner))
    }

    pub fn location(&self) -> String {
        let host = self.with(|i| i.cfg.location_ip.clone());
        format!(
            "http://{}:{}/desc.xml",
            host.unwrap_or_else(|| self.ip.to_string()),
            self.addr.port()
        )
    }

    /// Журнал запросов: `GET` для описаний, имя действия для SOAP.
    pub fn actions(&self) -> Vec<String> {
        self.with(|i| {
            i.state
                .log
                .iter()
                .map(|r| {
                    if r.is_post {
                        r.action.clone()
                    } else {
                        "GET".to_owned()
                    }
                })
                .collect()
        })
    }

    pub fn count(&self, action: &str) -> usize {
        self.actions().iter().filter(|a| *a == action).count()
    }

    pub fn soap_count(&self) -> usize {
        self.with(|i| i.state.log.iter().filter(|r| r.is_post).count())
    }

    pub fn connections(&self) -> usize {
        self.with(|i| i.state.connections)
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.with(|i| i.state.table.clone())
    }

    pub fn put_entry(&self, e: Entry) {
        self.with(|i| i.state.table.push(e));
    }

    pub fn requests(&self, action: &str) -> Vec<Req> {
        self.with(|i| {
            i.state
                .log
                .iter()
                .filter(|r| r.is_post && r.action == action)
                .cloned()
                .collect()
        })
    }
}

const ARG_NAMES: [&str; 8] = [
    "NewRemoteHost",
    "NewExternalPort",
    "NewProtocol",
    "NewInternalPort",
    "NewInternalClient",
    "NewEnabled",
    "NewPortMappingDescription",
    "NewLeaseDuration",
];

fn tag_value(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_owned())
}

fn read_request(s: &mut TcpStream) -> Option<(String, String)> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let cl = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + cl {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + cl]).into_owned();
    Some((head, body))
}

fn serve(mut s: TcpStream, peer: SocketAddr, inner: &Arc<Mutex<Inner>>) {
    let Some((head, body)) = read_request(&mut s) else {
        return;
    };
    let first = head.lines().next().unwrap_or_default().to_owned();
    let mut parts = first.split(' ');
    let is_post = parts.next() == Some("POST");
    let path = parts.next().unwrap_or_default().to_owned();
    let action = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("soapaction:"))
        .and_then(|l| l.split_once('#'))
        .map(|(_, a)| a.trim_end_matches('"').trim().to_owned())
        .unwrap_or_default();
    let args = ARG_NAMES
        .iter()
        .filter_map(|n| tag_value(&body, n).map(|v| ((*n).to_owned(), v)))
        .collect();
    let peer_ip = match peer {
        SocketAddr::V4(a) => *a.ip(),
        SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let req = Req {
        is_post,
        path,
        peer: peer_ip,
        head,
        body,
        action,
        args,
    };
    let reply = {
        let mut g = lock(inner);
        g.state.log.push(req.clone());
        let hook = g.cfg.hook.clone();
        match hook.and_then(|h| h(&req, &mut g)) {
            Some(r) => r,
            None => default_reply(&mut g, &req),
        }
    };
    write_reply(&mut s, reply);
}

fn http_resp(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.0 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

pub fn fault_body(code: u16) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
    )
}

pub fn soap_ok(urn: &str, action: &str, inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action}Response xmlns:u=\"{urn}\">{inner}</u:{action}Response></s:Body></s:Envelope>"
    )
}

fn write_reply(s: &mut TcpStream, r: Reply) {
    match r {
        Reply::Body(b) => {
            let _ = s.write_all(&http_resp(200, &b));
        }
        Reply::Fault(code) => {
            let _ = s.write_all(&http_resp(500, &fault_body(code)));
        }
        Reply::Status(code) => {
            let _ = s.write_all(&http_resp(code, ""));
        }
        Reply::Redirect(loc) => {
            let _ = s.write_all(
                format!("HTTP/1.0 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
        }
        Reply::Raw(b) => {
            let _ = s.write_all(&b);
        }
        Reply::Stall => thread::sleep(Duration::from_secs(4)),
        Reply::Drip => {
            let _ = s.write_all(b"HTTP/1.0 200 OK\r\nX-Slow: ");
            for _ in 0..40 {
                if s.write_all(b"a").is_err() {
                    return;
                }
                let _ = s.flush();
                thread::sleep(Duration::from_millis(300));
            }
        }
        Reply::BigBody(n) => {
            let _ = s.write_all(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n<a>");
            let block = [b'x'; 4096];
            let mut left = n;
            while left > 0 {
                let k = left.min(block.len());
                if s.write_all(&block[..k]).is_err() {
                    return;
                }
                left -= k;
            }
        }
        Reply::HugeHead => {
            let mut v = b"HTTP/1.0 200 OK\r\n".to_vec();
            for _ in 0..400 {
                v.extend_from_slice(
                    b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
                );
            }
            v.extend_from_slice(b"\r\n<a></a>");
            let _ = s.write_all(&v);
        }
    }
    let _ = s.flush();
}

pub fn description_xml(cfg: &Cfg) -> String {
    let services: String = cfg
        .services
        .iter()
        .map(|(urn, path)| {
            format!(
                "<service><serviceType>{urn}</serviceType><serviceId>urn:upnp-org:serviceId:IPConn1</serviceId><controlURL>{path}</controlURL></service>"
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>fake</friendlyName><UDN>{}</UDN><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList>{services}</serviceList></device></deviceList></device></deviceList></device></root>",
        cfg.udn
    )
}

fn default_reply(g: &mut Inner, req: &Req) -> Reply {
    if !req.is_post {
        if req.path == "/desc.xml" {
            return Reply::Body(
                g.cfg
                    .description
                    .clone()
                    .unwrap_or_else(|| description_xml(&g.cfg)),
            );
        }
        return Reply::Status(404);
    }
    let Some((urn, _)) = g.cfg.services.iter().find(|(_, p)| *p == req.path).cloned() else {
        return Reply::Status(404);
    };
    let act = req.action.as_str();
    let num = |k: &str| req.arg(k).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let ext = u16::try_from(num("NewExternalPort")).unwrap_or(0);
    match act {
        "GetExternalIPAddress" => Reply::Body(soap_ok(
            &urn,
            act,
            &format!("<NewExternalIPAddress>{}</NewExternalIPAddress>", g.cfg.wan),
        )),
        "AddPortMapping" | "AddAnyPortMapping" => {
            let lease = num("NewLeaseDuration");
            if g.cfg.only_permanent && lease != 0 {
                return Reply::Fault(725);
            }
            let client = req.arg("NewInternalClient").unwrap_or_default().to_owned();
            let conflict = g.cfg.taken.contains(&ext)
                || g.state
                    .table
                    .iter()
                    .any(|e| e.ext == ext && e.client != client);
            let mut ext_final = ext;
            if conflict {
                if act == "AddPortMapping" {
                    return Reply::Fault(718);
                }
                ext_final = 50555;
            }
            let stored = match g.cfg.lease_mode {
                LeaseMode::Honor => lease,
                LeaseMode::Permanent => 0,
                LeaseMode::Cap(c) if lease == 0 || lease > c => c,
                LeaseMode::Cap(_) => lease,
            };
            g.state.table.retain(|e| e.ext != ext_final);
            g.state.table.push(Entry {
                ext: ext_final,
                internal_port: u16::try_from(num("NewInternalPort")).unwrap_or(0),
                client,
                desc: req
                    .arg("NewPortMappingDescription")
                    .unwrap_or_default()
                    .to_owned(),
                lease: stored,
            });
            let inner = if act == "AddAnyPortMapping" {
                format!("<NewReservedPort>{ext_final}</NewReservedPort>")
            } else {
                String::new()
            };
            Reply::Body(soap_ok(&urn, act, &inner))
        }
        "GetSpecificPortMappingEntry" => match g.state.table.iter().find(|e| e.ext == ext) {
            Some(e) => Reply::Body(soap_ok(
                &urn,
                act,
                &format!(
                    "<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>",
                    e.internal_port, e.client, e.desc, e.lease
                ),
            )),
            None => Reply::Fault(714),
        },
        "DeletePortMapping" => {
            let before = g.state.table.len();
            g.state.table.retain(|e| e.ext != ext);
            if g.state.table.len() == before {
                Reply::Fault(714)
            } else {
                Reply::Body(soap_ok(&urn, act, ""))
            }
        }
        _ => Reply::Fault(401),
    }
}

/// SSDP-сервер: отвечает на каждый M-SEARCH от имени всех объявленных роутеров, каждый ответ
/// уходит с сокета, привязанного к адресу роутера.
pub struct Ssdp {
    pub addr: SocketAddrV4,
    datagrams: Arc<AtomicUsize>,
    adverts: Arc<Mutex<Vec<(UdpSocket, String)>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Ssdp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Ssdp {
    pub fn start() -> Option<Ssdp> {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .ok()?;
        let addr = match sock.local_addr().ok()? {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => return None,
        };
        let datagrams = Arc::new(AtomicUsize::new(0));
        let adverts: Arc<Mutex<Vec<(UdpSocket, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (d2, a2, s2) = (
            Arc::clone(&datagrams),
            Arc::clone(&adverts),
            Arc::clone(&stop),
        );
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !s2.load(Ordering::SeqCst) {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                d2.fetch_add(1, Ordering::SeqCst);
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                let st = text
                    .lines()
                    .find_map(|l| l.strip_prefix("ST: "))
                    .unwrap_or_default()
                    .to_owned();
                for (s, loc) in lock(&a2).iter() {
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nLOCATION: {loc}\r\nSERVER: fake\r\nST: {st}\r\nUSN: uuid:x::{st}\r\n\r\n"
                    );
                    let _ = s.send_to(reply.as_bytes(), src);
                }
            }
        });
        Some(Ssdp {
            addr,
            datagrams,
            adverts,
            stop,
        })
    }

    pub fn advertise(&self, ip: Ipv4Addr, location: String) {
        if let Ok(s) = UdpSocket::bind((ip, 0)) {
            lock(&self.adverts).push((s, location));
        }
    }

    pub fn count(&self) -> usize {
        self.datagrams.load(Ordering::SeqCst)
    }
}

pub struct Lab {
    pub ssdp: Ssdp,
    pub routers: Vec<Router>,
}

impl Lab {
    pub fn new(cfgs: Vec<Cfg>) -> Option<Lab> {
        let ssdp = Ssdp::start()?;
        let mut routers = Vec::new();
        for (i, cfg) in cfgs.into_iter().enumerate() {
            let ip = Ipv4Addr::new(127, 0, 0, u8::try_from(2 + i).ok()?);
            let adv = cfg.advertise;
            let r = Router::start(ip, cfg)?;
            if adv {
                ssdp.advertise(ip, r.location());
            }
            routers.push(r);
        }
        Some(Lab { ssdp, routers })
    }

    pub fn r(&self) -> &Router {
        &self.routers[0]
    }

    pub fn net(&self) -> Net {
        Net {
            ssdp_target: self.ssdp.addr,
            allow_loopback: true,
            http_deadline: Duration::from_millis(1000),
            discovery_window: Duration::from_millis(500),
            max_refresh: Duration::from_secs(10),
        }
    }

    pub fn mapper(&self, settings: UpnpSettings) -> UpnpMapper {
        UpnpMapper::with_net(settings, self.net())
    }
}

/// Привязка 127.0.0.N не удалась: тест падает, а не проходит вхолостую.
pub fn skip() -> ! {
    panic!("cannot bind 127.0.0.N (macOS needs lo0 aliases: such tests are ignored there)");
}

pub fn rid(udn: &str) -> RouterId {
    RouterId::from_setting(udn).unwrap()
}

pub fn allow(udn: &str, permanent_ok: bool) -> UpnpSettings {
    UpnpSettings {
        routers: vec![AllowedRouter {
            id: rid(udn),
            permanent_ok,
        }],
    }
}

pub fn req_for(port: u16) -> MapRequest {
    MapRequest {
        internal: SocketAddrV4::new(OWN, port),
    }
}

pub fn req() -> MapRequest {
    req_for(PORT)
}
