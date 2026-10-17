//! Fuzz-смоук на stable без зависимостей: ГПСЧ xorshift64* с фиксированным зерном.
//! Свойство: ни одной паники; каждый принятый результат удовлетворяет инвариантам
//! (набор символов пути, тот же хост, ASCII значения в пределах, пределы глубины и числа).
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug).

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use chervo_addr::{AddrClass, classify};

use super::target;
use crate::desc::parse_description;
use crate::error::ScanError;
use crate::http::parse_response as http_response;
use crate::limits::{
    BODY_MAX, HTTP_HEAD_MAX, MAX_RESPONDERS, MAX_SERVICES, PATH_MAX, UDN_MAX, VALUE_MAX,
    XML_MAX_DEPTH, XML_MAX_ELEMENTS,
};
use crate::scan::{Event, scan, value};
use crate::soap::{Fault, parse_add_any, parse_external_ip, parse_fault, parse_specific};
use crate::ssdp::{Responder, SsdpPolicy, parse_response as ssdp_response, select};
use crate::url::{parse_location, parse_port};

struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

const TOKENS: [&[u8]; 16] = [
    b"<!",
    b"&",
    b"<?",
    b"<![CDATA[",
    b"&#",
    b"\xff",
    b"\x00",
    b"</",
    b">",
    b"\"",
    b"'",
    b"<!--",
    b"%",
    b"]]>",
    b"&amp;",
    b"\r\n\r\n",
];

/// Случайная мутация образца: несколько операций подряд.
fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    for _ in 0..=rng.below(3) {
        match rng.below(10) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                if let Some(b) = v.get_mut(i) {
                    *b ^= 1 << rng.below(8);
                }
            }
            1 => {
                let i = rng.below(v.len() + 1);
                let n = 1 + rng.below(4);
                let extra = rng.bytes(n);
                v.splice(i..i, extra);
            }
            2 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            3 => {
                let n = rng.below(v.len() + 1);
                v.truncate(n);
            }
            4 if !v.is_empty() => {
                let i = rng.below(v.len());
                let b = rng.next() as u8;
                if let Some(x) = v.get_mut(i) {
                    *x = b;
                }
            }
            // вставка опасной лексемы
            5 | 6 => {
                let i = rng.below(v.len() + 1);
                let t = TOKENS[rng.below(TOKENS.len())];
                v.splice(i..i, t.iter().copied());
            }
            // глубокая вложенность
            7 => {
                let i = rng.below(v.len() + 1);
                let n = 1 + rng.below(40);
                let open: Vec<u8> = b"<a>".iter().copied().cycle().take(3 * n).collect();
                v.splice(i..i, open);
            }
            // дубликат участка сразу после него
            8 if !v.is_empty() => {
                let i = rng.below(v.len());
                let len = 1 + rng.below(200.min(v.len() - i));
                let chunk: Vec<u8> = v[i..i + len].to_vec();
                let times = 1 + rng.below(3);
                for _ in 0..times {
                    v.splice(i + len..i + len, chunk.iter().copied());
                }
            }
            // много копий участка (рост числа элементов)
            9 if !v.is_empty() => {
                let i = rng.below(v.len());
                let len = 1 + rng.below(40.min(v.len() - i));
                let chunk: Vec<u8> = v[i..i + len].to_vec();
                let times = 1 + rng.below(60);
                for _ in 0..times {
                    v.splice(i + len..i + len, chunk.iter().copied());
                }
            }
            _ => {}
        }
        v.truncate(BODY_MAX + 200);
    }
    v
}

/// Случайная последовательность лексем, похожая на XML.
fn xmlish(rng: &mut XorShift) -> Vec<u8> {
    const FR: [&str; 14] = [
        "<a>",
        "</a>",
        "<b x=\"1\">",
        "</b>",
        "<c/>",
        "text",
        " ",
        "&amp;",
        "&lt;",
        "<s:a>",
        "</s:a>",
        "<root>",
        "</root>",
        "<?xml version=\"1.0\"?>",
    ];
    let n = rng.below(60);
    let mut v = Vec::new();
    for _ in 0..n {
        v.extend_from_slice(FR[rng.below(FR.len())].as_bytes());
    }
    v
}

fn random_input(rng: &mut XorShift) -> Vec<u8> {
    match rng.below(3) {
        0 => {
            let n = rng.below(300);
            rng.bytes(n)
        }
        _ => xmlish(rng),
    }
}

fn path_ok(p: &str) {
    assert!(p.starts_with('/') && p.len() <= PATH_MAX, "path shape");
    assert!(
        p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/!$'()*+,;=:@%".contains(&b)),
        "path charset"
    );
    let lower = p.to_ascii_lowercase();
    for bad in ["%00", "%2f", "%5c"] {
        assert!(!lower.contains(bad), "forbidden percent");
    }
    for seg in lower.split('/') {
        let norm = seg.replace("%2e", ".");
        assert!(norm != "." && norm != "..", "dot segment");
    }
}

// ----- образцы -----

const IGD1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

fn svc(kind: &str, ctl: &str) -> String {
    format!("<service><serviceType>{kind}</serviceType><controlURL>{ctl}</controlURL></service>")
}

fn desc_sample() -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><URLBase>http://192.168.1.1:5000/</URLBase><device><deviceType>{IGD1}</deviceType><UDN>uuid:abc-123</UDN><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><serviceList>{}{}{}</serviceList></device></deviceList></device></deviceList></device></root>",
        svc("urn:schemas-upnp-org:service:WANPPPConnection:1", "/ppp"),
        svc("urn:schemas-upnp-org:service:WANIPConnection:1", "ctl/ip1"),
        svc("urn:schemas-upnp-org:service:WANIPConnection:2", "http://192.168.1.1:5000/ip2"),
    )
    .into_bytes()
}

fn soap_resp(action: &str, fields: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action}Response xmlns:u=\"urn:x\">{fields}</u:{action}Response></s:Body></s:Envelope>"
    )
    .into_bytes()
}

fn soap_samples() -> Vec<Vec<u8>> {
    vec![
        soap_resp(
            "GetExternalIPAddress",
            "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>",
        ),
        soap_resp("AddAnyPortMapping", "<NewReservedPort>50001</NewReservedPort>"),
        soap_resp(
            "GetSpecificPortMappingEntry",
            "<NewInternalPort>4455</NewInternalPort><NewInternalClient>192.168.1.10</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>",
        ),
        b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"x\"><s:Body><s:Fault><faultcode>s:Client</faultcode><detail><UPnPError xmlns=\"y\"><errorCode>718</errorCode><errorDescription>c</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>".to_vec(),
    ]
}

const ST1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const OWN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

fn ssdp_sample() -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {ST1}\r\nUSN: uuid:abc::{ST1}\r\nEXT:\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n")
        .into_bytes()
}

fn http_samples() -> Vec<Vec<u8>> {
    let body = soap_samples()[0].clone();
    let mut with_len = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    with_len.extend_from_slice(&body);
    let mut no_len = b"HTTP/1.1 500 Internal Server Error\r\nServer: x\r\n\r\n".to_vec();
    no_len.extend_from_slice(&soap_samples()[3]);
    vec![with_len, no_len]
}

// ----- цели -----

#[test]
fn fuzz_smoke_scan() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x1234_5678_9ABC_DEF0);
    let samples = [
        desc_sample(),
        soap_samples().remove(2),
        soap_samples().remove(3),
    ];
    let mut ok = 0u64;
    for i in 0..n {
        let input = match rng.below(4) {
            0 => random_input(&mut rng),
            _ => {
                let s = &samples[rng.below(samples.len())];
                mutate(&mut rng, s)
            }
        };
        let mut stack: Vec<String> = Vec::new();
        let mut starts = 0usize;
        let mut sound = true;
        let r = scan(&input, |e| {
            match e {
                Event::Start { name } => {
                    starts += 1;
                    sound &= !name.is_empty() && name.is_ascii();
                    stack.push(name.to_owned());
                    sound &= stack.len() <= XML_MAX_DEPTH;
                }
                Event::End { name } => {
                    sound &= stack.pop().as_deref() == Some(name);
                }
                Event::Text { raw } => {
                    sound &= !raw.is_empty() && !raw.contains(&b'<') && !stack.is_empty();
                }
            }
            Ok::<(), ScanError>(())
        });
        if r.is_ok() {
            ok += 1;
            assert!(sound, "iteration {i}: unbalanced events");
            assert!(stack.is_empty() && (1..=XML_MAX_ELEMENTS).contains(&starts));
            assert!(input.len() <= BODY_MAX);
            assert!(!input.windows(2).any(|w| w == b"<!"), "accepted <!");
            let body = input
                .strip_prefix(&[0xEF, 0xBB, 0xBF][..])
                .unwrap_or(&input);
            assert!(
                !body
                    .iter()
                    .any(|&c| matches!(c, 0..=8 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F)),
                "accepted control byte"
            );
        }
        // значение: принятое всегда печатный ASCII в пределах
        let cut = rng.below(input.len() + 1);
        if let Ok(v) = value(&input[..cut]) {
            assert!(v.len() <= VALUE_MAX && v.bytes().all(|b| (0x20..=0x7E).contains(&b)));
        }
    }
    println!("fuzz_smoke_scan: iterations={n} accepted={ok}");
}

#[test]
fn fuzz_smoke_desc() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x0DE5_C0DE_1234_5678);
    let sample = desc_sample();
    let t = target();
    let mut ok = 0u64;
    // образец сам принимается
    assert_eq!(parse_description(&sample, &t).unwrap().services.len(), 3);
    for _ in 0..n {
        let input = match rng.below(5) {
            0 => random_input(&mut rng),
            _ => mutate(&mut rng, &sample),
        };
        if let Ok(d) = parse_description(&input, &t) {
            ok += 1;
            assert!((1..=MAX_SERVICES).contains(&d.services.len()));
            let udn = d.udn.as_str();
            assert!(udn.starts_with("uuid:") && udn.len() <= UDN_MAX);
            assert!(
                udn.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-:._".contains(&b))
            );
            for w in d.services.windows(2) {
                assert!(w[0].kind <= w[1].kind, "order");
                assert!(w[0] != w[1], "duplicate");
            }
            for s in &d.services {
                path_ok(s.control.as_str());
            }
        }
    }
    println!("fuzz_smoke_desc: iterations={n} accepted={ok}");
}

#[test]
fn fuzz_smoke_soap() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x50A9_0000_DEAD_BEEF);
    let samples = soap_samples();
    let mut ok = 0u64;
    for _ in 0..n {
        let input = match rng.below(5) {
            0 => random_input(&mut rng),
            _ => {
                let s = &samples[rng.below(samples.len())];
                mutate(&mut rng, s)
            }
        };
        if let Ok(Some(ip)) = parse_external_ip(&input) {
            ok += 1;
            // строгий разбор: обратная печать даёт каноническую запись
            let again: Ipv4Addr = ip.to_string().parse().unwrap();
            assert_eq!(again, ip);
        }
        if let Ok(p) = parse_add_any(&input) {
            ok += 1;
            assert_ne!(p, 0);
        }
        if let Ok(e) = parse_specific(&input) {
            ok += 1;
            assert!(e.internal_port != 0 && e.lease <= 604_800);
        }
        if let Fault::Upnp(c) = parse_fault(&input) {
            ok += 1;
            assert!(c <= 9999);
        }
    }
    println!("fuzz_smoke_soap: iterations={n} accepted={ok}");
}

#[test]
fn fuzz_smoke_ssdp() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x5555_0000_AAAA_1111);
    let sample = ssdp_sample();
    let src = SocketAddrV4::new(SRC, 1900);
    let mut ok = 0u64;
    let mut pool: Vec<Responder> = Vec::new();
    for i in 0..n {
        let input = match rng.below(5) {
            0 => random_input(&mut rng),
            _ => mutate(&mut rng, &sample),
        };
        if let Ok(r) = ssdp_response(&input, src, OWN, SsdpPolicy::STRICT) {
            ok += 1;
            assert_eq!(r.ip, SRC);
            assert_eq!(*r.target.gw.addr().ip(), SRC, "location host != responder");
            assert_eq!(classify(IpAddr::V4(r.ip)), AddrClass::Private);
            assert_ne!(r.ip, OWN);
            path_ok(r.target.path.as_str());
            if pool.len() < 20 {
                pool.push(r);
            }
        }
        // произвольные строки как LOCATION
        let s = String::from_utf8_lossy(&mutate(&mut rng, b"http://192.168.1.1:5000/a/b.xml"))
            .into_owned();
        if let Ok(t) = parse_location(&s, SRC) {
            assert_eq!(*t.gw.addr().ip(), SRC);
            assert!(t.gw.addr().port() != 0);
            path_ok(t.path.as_str());
        }
        let _ = parse_port(&s);
        if i % 1000 == 0 {
            let out = select(pool.clone());
            assert!(out.len() <= MAX_RESPONDERS);
        }
    }
    println!("fuzz_smoke_ssdp: iterations={n} accepted={ok}");
}

#[test]
fn fuzz_smoke_http() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0xB0DE_0000_7777_3333);
    let samples = http_samples();
    let mut ok = 0u64;
    for _ in 0..n {
        let input = match rng.below(5) {
            0 => random_input(&mut rng),
            _ => {
                let s = &samples[rng.below(samples.len())];
                mutate(&mut rng, s)
            }
        };
        if let Ok(r) = http_response(&input) {
            ok += 1;
            assert!(r.status == 200 || r.status == 500);
            assert!(r.body.len() <= BODY_MAX);
            let end = input
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("terminator")
                + 4;
            assert!(end <= HTTP_HEAD_MAX);
            let head = String::from_utf8_lossy(&input[..end]).to_ascii_lowercase();
            assert!(!head.contains("transfer-encoding"), "accepted chunked");
        }
    }
    println!("fuzz_smoke_http: iterations={n} accepted={ok}");
}
