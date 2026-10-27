use std::net::{Ipv4Addr, SocketAddrV4};

use super::ip;
use crate::error::{SsdpError, UrlError};
use crate::ssdp::{
    Responder, SEARCH_TARGETS, ST_IGD_V1, ST_IGD_V2, SsdpPolicy, msearch, parse_response, select,
};

const OWN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

fn src(ip: Ipv4Addr) -> SocketAddrV4 {
    SocketAddrV4::new(ip, 1900)
}

fn response(extra: &str, st: &str, location: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {st}\r\nUSN: uuid:abc::{st}\r\nEXT:\r\nSERVER: Linux UPnP/1.1 miniupnpd/2.3\r\nLOCATION: {location}\r\n{extra}\r\n"
    )
}

fn good() -> String {
    response("", ST_IGD_V1, "http://192.168.1.1:5000/rootDesc.xml")
}

fn parse(s: &str) -> Result<Responder, SsdpError> {
    parse_response(s.as_bytes(), src(ROUTER), OWN, SsdpPolicy::STRICT)
}

#[test]
fn ssdp_msearch_exact_bytes() {
    assert_eq!(
        msearch(ST_IGD_V1),
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
            .to_vec()
    );
    assert_eq!(
        msearch(ST_IGD_V2),
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n"
            .to_vec()
    );
    assert_eq!(SEARCH_TARGETS, [ST_IGD_V1, ST_IGD_V2]);
    // влезает в одну датаграмму
    assert!(msearch(ST_IGD_V1).len() < 200);
}

#[test]
fn ssdp_response_ok() {
    let r = parse(&good()).unwrap();
    assert_eq!(r.ip, ROUTER);
    assert_eq!(r.target.gw.addr(), SocketAddrV4::new(ROUTER, 5000));
    assert_eq!(r.target.path.as_str(), "/rootDesc.xml");
    // версия 2, имена заголовков без учёта регистра, без `OK`, без завершающей пустой строки
    let s = "HTTP/1.1 200\r\nst: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nlocation: http://192.168.1.1/d.xml";
    assert_eq!(parse(s).unwrap().target.gw.addr().port(), 80);
    // ровно 20 заголовков
    let filler: String = (0..14).map(|i| format!("X-{i}: v\r\n")).collect();
    parse(&response(&filler, ST_IGD_V1, "http://192.168.1.1/d")).unwrap();
}

#[test]
fn ssdp_wrong_status() {
    for first in [
        "HTTP/1.1 404 Not Found",
        "HTTP/1.1 2000 OK",
        "HTTP/1.1 20 OK",
        "HTTP/1.0 200 OK",
        "HTTP/1.1  200 OK",
        "NOTIFY * HTTP/1.1",
        "M-SEARCH * HTTP/1.1",
        "",
        "200 OK",
    ] {
        let s = good().replacen("HTTP/1.1 200 OK", first, 1);
        assert_eq!(parse(&s).unwrap_err(), SsdpError::BadStatus, "{first:?}");
    }
    assert_eq!(parse("").unwrap_err(), SsdpError::BadStatus);
}

#[test]
fn ssdp_two_locations_rejected() {
    let s = response(
        "Location: http://192.168.1.1:5000/other.xml\r\n",
        ST_IGD_V1,
        "http://192.168.1.1:5000/rootDesc.xml",
    );
    assert_eq!(parse(&s).unwrap_err(), SsdpError::DuplicateLocation);
    // нет LOCATION
    let s = good().replace("LOCATION", "X-LOCATION");
    assert_eq!(parse(&s).unwrap_err(), SsdpError::MissingLocation);
}

#[test]
fn ssdp_st_mismatch() {
    let s = response("", "upnp:rootdevice", "http://192.168.1.1:5000/d");
    assert_eq!(parse(&s).unwrap_err(), SsdpError::StMismatch);
    let s = response(
        "",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:3",
        "http://192.168.1.1:5000/d",
    );
    assert_eq!(parse(&s).unwrap_err(), SsdpError::StMismatch);
    let s = good().replace("ST:", "X-ST:");
    assert_eq!(parse(&s).unwrap_err(), SsdpError::MissingSt);
    let s = response(
        &format!("ST: {ST_IGD_V1}\r\n"),
        ST_IGD_V1,
        "http://192.168.1.1:5000/d",
    );
    assert_eq!(parse(&s).unwrap_err(), SsdpError::DuplicateSt);
}

#[test]
fn ssdp_oversize() {
    let pad = |total: usize| {
        let base = good();
        // дополнить заголовком X-P до нужной общей длины
        let head = base.strip_suffix("\r\n").unwrap();
        let fixed = head.len() + "X-P: \r\n\r\n".len();
        format!("{head}X-P: {}\r\n\r\n", "a".repeat(total - fixed))
    };
    let ok = pad(1472);
    assert_eq!(ok.len(), 1472);
    parse(&ok).unwrap();
    let big = pad(1473);
    assert_eq!(big.len(), 1473);
    assert_eq!(parse(&big).unwrap_err(), SsdpError::Oversize);
}

#[test]
fn ssdp_non_ascii_header() {
    let mut s = good().into_bytes();
    s.splice(20..20, [0xC3, 0xA9]);
    let r = parse_response(&s, src(ROUTER), OWN, SsdpPolicy::STRICT);
    assert_eq!(r.unwrap_err(), SsdpError::NonAscii);
    for bad in ["\t", "\0", "\x7f", "é"] {
        let s = good().replace("max-age=120", &format!("max-age={bad}"));
        assert_eq!(parse(&s).unwrap_err(), SsdpError::NonAscii, "{bad:?}");
    }
    // одиночные CR и LF
    for bad in ["\n", "\r"] {
        let s = good().replace("max-age=120", &format!("max-age=1{bad}20"));
        assert_eq!(parse(&s).unwrap_err(), SsdpError::BadHeader, "{bad:?}");
    }
}

#[test]
fn ssdp_obs_fold_rejected() {
    let s = response(" continued\r\n", ST_IGD_V1, "http://192.168.1.1:5000/d");
    assert_eq!(parse(&s).unwrap_err(), SsdpError::ObsFold);
    // нет двоеточия, пустое имя, имя с пробелом
    for line in ["no colon\r\n", ": value\r\n", "bad name: v\r\n"] {
        let s = response(line, ST_IGD_V1, "http://192.168.1.1:5000/d");
        assert_eq!(parse(&s).unwrap_err(), SsdpError::BadHeader, "{line:?}");
    }
    // 21 заголовок: отказ
    let filler: String = (0..15).map(|i| format!("X-{i}: v\r\n")).collect();
    let s = response(&filler, ST_IGD_V1, "http://192.168.1.1:5000/d");
    assert_eq!(parse(&s).unwrap_err(), SsdpError::TooManyHeaders);
    // данные после пустой строки
    let s = format!("{}tail", good());
    assert_eq!(parse(&s).unwrap_err(), SsdpError::Trailing);
}

#[test]
fn ssdp_responder_public_or_self_rejected() {
    let p = |a: Ipv4Addr, loc: &str| {
        let s = response("", ST_IGD_V1, loc);
        parse_response(s.as_bytes(), src(a), OWN, SsdpPolicy::STRICT)
    };
    assert_eq!(
        p(ip(8, 8, 8, 8), "http://8.8.8.8/d").unwrap_err(),
        SsdpError::BadSource
    );
    assert_eq!(
        p(ip(100, 64, 1, 1), "http://100.64.1.1/d").unwrap_err(),
        SsdpError::BadSource
    );
    assert_eq!(
        p(ip(169, 254, 1, 1), "http://169.254.1.1/d").unwrap_err(),
        SsdpError::BadSource
    );
    assert_eq!(
        p(ip(127, 0, 0, 1), "http://127.0.0.1/d").unwrap_err(),
        SsdpError::BadSource
    );
    assert_eq!(
        p(ip(224, 0, 0, 1), "http://224.0.0.1/d").unwrap_err(),
        SsdpError::BadSource
    );
    assert_eq!(
        p(OWN, "http://192.168.1.10/d").unwrap_err(),
        SsdpError::SelfSource
    );
    // LOCATION указывает не на ответившего
    assert_eq!(
        p(ROUTER, "http://192.168.1.99/d").unwrap_err(),
        SsdpError::Location(UrlError::HostMismatch)
    );
    assert_eq!(
        p(ROUTER, "http://evil.example/d").unwrap_err(),
        SsdpError::Location(UrlError::Host)
    );
    p(ip(10, 0, 0, 1), "http://10.0.0.1:80/d").unwrap();
    p(ip(172, 16, 5, 5), "http://172.16.5.5/d").unwrap();
}

#[test]
fn ssdp_loopback_only_in_test_policy() {
    let lo = ip(127, 0, 0, 1);
    let own = ip(127, 0, 0, 2);
    let s = response("", ST_IGD_V1, "http://127.0.0.1:5000/d");
    let strict = parse_response(s.as_bytes(), src(lo), own, SsdpPolicy::STRICT);
    assert_eq!(strict.unwrap_err(), SsdpError::BadSource);
    let test = SsdpPolicy {
        allow_loopback: true,
    };
    assert_eq!(
        parse_response(s.as_bytes(), src(lo), own, test).unwrap().ip,
        lo
    );
    // публичный адрес политика loopback не открывает
    let s = response("", ST_IGD_V1, "http://8.8.8.8/d");
    let r = parse_response(s.as_bytes(), src(ip(8, 8, 8, 8)), own, test);
    assert_eq!(r.unwrap_err(), SsdpError::BadSource);
}

#[test]
fn ssdp_select_conflicting_location_is_ambiguous() {
    let r = |ip: Ipv4Addr, path: &str| {
        let s = response("", ST_IGD_V1, &format!("http://{ip}:5000{path}"));
        parse_response(s.as_bytes(), src(ip), OWN, SsdpPolicy::STRICT).unwrap()
    };
    let a = ip(192, 168, 1, 1);
    let b = ip(192, 168, 1, 2);
    // один IP, два разных LOCATION: итог неоднозначный (ред. 2), IP в список не попадает
    let out = select(vec![r(a, "/x"), r(b, "/y"), r(a, "/z")]);
    assert!(out.ambiguous);
    assert_eq!(out.responders.iter().map(|x| x.ip).collect::<Vec<_>>(), [b]);
    // порядок не важен: поддельная датаграмма после настоящей тоже даёт неоднозначность
    assert!(select(vec![r(a, "/z"), r(a, "/x")]).ambiguous);
    assert!(select(vec![r(a, "/x"), r(b, "/y"), r(a, "/z")]).ambiguous);
    // повтор одного и того же сводится к одному, порядок прихода сохраняется
    let out = select(vec![r(b, "/y"), r(a, "/x"), r(b, "/y")]);
    assert!(!out.ambiguous);
    assert_eq!(
        out.responders.iter().map(|x| x.ip).collect::<Vec<_>>(),
        [b, a]
    );
    // ровно 8 IP: не неоднозначно
    let eight: Vec<Responder> = (1..=8).map(|i| r(ip(192, 168, 2, i), "/d")).collect();
    let out = select(eight);
    assert!(!out.ambiguous);
    assert_eq!(out.responders.len(), 8);
    // больше 8 IP: неоднозначно, в списке не более 8
    let many: Vec<Responder> = (1..=12).map(|i| r(ip(192, 168, 2, i), "/d")).collect();
    let out = select(many);
    assert!(out.ambiguous);
    assert_eq!(out.responders.len(), 8);
    assert_eq!(out.responders[7].ip, ip(192, 168, 2, 8));
    let out = select(Vec::new());
    assert!(!out.ambiguous && out.responders.is_empty());
}
