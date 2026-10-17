use std::net::{Ipv4Addr, SocketAddrV4};

use super::{ip, target};
use crate::error::UrlError;
use crate::url::{check_urlbase, control_url, parse_ipv4, parse_location, parse_port};

const R: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

fn loc(v: &str) -> Result<(SocketAddrV4, String), UrlError> {
    parse_location(v, R).map(|t| (t.gw.addr(), t.path.as_str().to_owned()))
}

#[test]
fn location_rules() {
    let (a, p) = loc("http://192.168.1.1:5000/rootDesc.xml").unwrap();
    assert_eq!(a, SocketAddrV4::new(R, 5000));
    assert_eq!(p, "/rootDesc.xml");
    // порт по умолчанию 80, схема без учёта регистра
    let (a, p) = loc("HtTp://192.168.1.1/x").unwrap();
    assert_eq!(a, SocketAddrV4::new(R, 80));
    assert_eq!(p, "/x");
    // допустимые знаки пути
    loc("http://192.168.1.1/a-b._~/!$'()*+,;=:@%41").unwrap();

    let bad = |v: &str, e: UrlError| assert_eq!(loc(v).unwrap_err(), e, "{v}");
    bad("http://router.local/x", UrlError::Host);
    bad("http://[::1]/x", UrlError::Authority);
    bad("http://[fe80::1]:80/x", UrlError::Authority);
    bad("http://user@192.168.1.1/x", UrlError::Authority);
    bad("http://user:pw@192.168.1.1/x", UrlError::Authority);
    bad("https://192.168.1.1/x", UrlError::Scheme);
    bad("ftp://192.168.1.1/x", UrlError::Scheme);
    bad("//192.168.1.1/x", UrlError::Scheme);
    bad("/x", UrlError::Scheme);
    bad("", UrlError::Scheme);
    bad("http:/192.168.1.1/x", UrlError::Scheme);
    bad("http://192.168.1.1:0/x", UrlError::Port);
    bad("http://192.168.1.1:65536/x", UrlError::Port);
    bad("http://192.168.1.1:123456/x", UrlError::Port);
    bad("http://192.168.1.1:/x", UrlError::Port);
    bad("http://192.168.1.1:80a/x", UrlError::Port);
    bad("http://192.168.1.1:80:80/x", UrlError::Port);
    bad("http://192.168.1.1", UrlError::NoPath);
    bad("http://192.168.1.1:5000", UrlError::NoPath);
    bad("http://192.168.1.1/a/../b", UrlError::DotSegment);
    bad("http://192.168.1.1/..", UrlError::DotSegment);
    bad("http://192.168.1.1/a/./b", UrlError::DotSegment);
    bad("http://192.168.1.1/a/%2e%2E/b", UrlError::DotSegment);
    bad("http://192.168.1.1/a%00b", UrlError::Percent);
    bad("http://192.168.1.1/a%2fb", UrlError::Percent);
    bad("http://192.168.1.1/a%2Fb", UrlError::Percent);
    bad("http://192.168.1.1/a%5cb", UrlError::Percent);
    bad("http://192.168.1.1/a%5Cb", UrlError::Percent);
    bad("http://192.168.1.1/a%zz", UrlError::Percent);
    bad("http://192.168.1.1/a%2", UrlError::Percent);
    bad("http://192.168.1.1/a%", UrlError::Percent);
    bad("http://192.168.1.1/a?b=c", UrlError::PathChar);
    bad("http://192.168.1.1/a#b", UrlError::PathChar);
    bad("http://192.168.1.1/a b", UrlError::PathChar);
    bad("http://192.168.1.1/a\\b", UrlError::PathChar);
    bad("http://192.168.1.1/é", UrlError::PathChar);
    bad("http://192.168.1.1/a\"b", UrlError::PathChar);
    // IPv4: лидирующий ноль, 256, число частей
    bad("http://192.168.01.1/x", UrlError::Host);
    bad("http://192.168.1.256/x", UrlError::Host);
    bad("http://192.168.1/x", UrlError::Host);
    bad("http://192.168.1.1.1/x", UrlError::Host);
    bad("http://192.168.1.1./x", UrlError::Host);
    bad("http://192.168.1.1 /x", UrlError::Host);
    bad("http://0xc0.168.1.1/x", UrlError::Host);
    bad("http://3232235777/x", UrlError::Host);
    // длина пути: 256 допустимо, 257 нет
    let path = |n: usize| format!("http://192.168.1.1/{}", "a".repeat(n - 1));
    loc(&path(256)).unwrap();
    bad(&path(257), UrlError::TooLong);
}

#[test]
fn location_host_must_equal_responder() {
    assert_eq!(
        parse_location("http://192.168.1.2/x", R).unwrap_err(),
        UrlError::HostMismatch
    );
    assert_eq!(
        parse_location("http://10.0.0.1:80/x", R).unwrap_err(),
        UrlError::HostMismatch
    );
    parse_location("http://192.168.1.2/x", ip(192, 168, 1, 2)).unwrap();
}

#[test]
fn control_url_relative_absolute_and_full() {
    let t = target(); // 192.168.1.1:5000
    let c = |v: &str| control_url(v, &t).map(|p| p.as_str().to_owned());
    assert_eq!(c("/ctl/IPConn").unwrap(), "/ctl/IPConn");
    assert_eq!(c("ctl/IPConn").unwrap(), "/ctl/IPConn");
    assert_eq!(c("http://192.168.1.1:5000/ctl").unwrap(), "/ctl");
    assert_eq!(c("HTTP://192.168.1.1:5000/ctl/x").unwrap(), "/ctl/x");
    // пустое, схема в «относительной» ссылке, правила пути
    assert_eq!(c("").unwrap_err(), UrlError::Empty);
    assert_eq!(c("ftp://x/y").unwrap_err(), UrlError::Scheme);
    assert_eq!(
        c("https://192.168.1.1:5000/ctl").unwrap_err(),
        UrlError::Scheme
    );
    assert_eq!(c("/a/../b").unwrap_err(), UrlError::DotSegment);
    assert_eq!(c("../b").unwrap_err(), UrlError::DotSegment);
    assert_eq!(c("/a?b").unwrap_err(), UrlError::PathChar);
    assert_eq!(c("/a%00").unwrap_err(), UrlError::Percent);
    assert_eq!(c("http://192.168.1.1:5000").unwrap_err(), UrlError::NoPath);
}

#[test]
fn control_url_other_host_or_port_rejected() {
    let t = target();
    let c = |v: &str| control_url(v, &t).unwrap_err();
    assert_eq!(c("http://192.168.1.2:5000/ctl"), UrlError::HostMismatch);
    assert_eq!(c("http://192.168.1.1:5001/ctl"), UrlError::HostMismatch);
    // порт по умолчанию 80 не равен 5000
    assert_eq!(c("http://192.168.1.1/ctl"), UrlError::HostMismatch);
    assert_eq!(c("http://router/ctl"), UrlError::Host);
    assert_eq!(c("http://u@192.168.1.1:5000/ctl"), UrlError::Authority);
}

#[test]
fn urlbase_other_host_rejected() {
    let t = target();
    check_urlbase("http://192.168.1.1:5000/", &t).unwrap();
    check_urlbase("http://192.168.1.1:5000", &t).unwrap();
    assert_eq!(
        check_urlbase("http://192.168.1.2:5000/", &t).unwrap_err(),
        UrlError::HostMismatch
    );
    assert_eq!(
        check_urlbase("http://192.168.1.1:5001/", &t).unwrap_err(),
        UrlError::HostMismatch
    );
    assert_eq!(
        check_urlbase("http://192.168.1.1/", &t).unwrap_err(),
        UrlError::HostMismatch
    );
    assert_eq!(check_urlbase("", &t).unwrap_err(), UrlError::Scheme);
    assert_eq!(
        check_urlbase("http://host:5000/", &t).unwrap_err(),
        UrlError::Host
    );
}

#[test]
fn ipv4_and_port_strict() {
    assert_eq!(parse_ipv4("0.0.0.0"), Some(ip(0, 0, 0, 0)));
    assert_eq!(parse_ipv4("255.255.255.255"), Some(ip(255, 255, 255, 255)));
    for s in [
        "",
        "1.2.3",
        "1.2.3.4.5",
        "01.2.3.4",
        "1.2.3.04",
        "256.1.1.1",
        "1.2.3.-4",
        " 1.2.3.4",
        "1.2.3.4 ",
        "1..3.4",
        "a.b.c.d",
        "1.2.3.4a",
        "1.2.3.+4",
        "0000.1.1.1",
        "١.2.3.4",
    ] {
        assert_eq!(parse_ipv4(s), None, "{s:?}");
    }
    assert_eq!(parse_port("1"), Some(1));
    assert_eq!(parse_port("65535"), Some(65535));
    for s in ["", "0", "00000", "65536", "123456", "-1", "+1", "1a", " 1"] {
        assert_eq!(parse_port(s), None, "{s:?}");
    }
}
