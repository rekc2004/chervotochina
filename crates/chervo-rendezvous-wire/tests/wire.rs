#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Протокол эха (этап 13д, Р1): кругообороты, отказы по каждому полю, XOR.

use chervo_rendezvous_wire::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn nonce() -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    for (i, b) in n.iter_mut().enumerate() {
        *b = 0xA5 ^ (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    Nonce(n)
}

fn v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 40_123)
}

fn v6() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
        51_999,
    )
}

#[test]
fn echo_request_roundtrip() {
    let n = nonce();
    let b = encode_echo_request(&n);
    assert_eq!(b.len(), 64);
    assert_eq!(&b[0..4], b"CHRV");
    assert_eq!(b[4], 1);
    assert_eq!(b[5], T_ECHO_REQUEST);
    assert_eq!(&b[6..8], &[0, 0]);
    assert_eq!(&b[8..24], &n.0);
    assert!(b[24..].iter().all(|x| *x == 0));
    assert_eq!(parse_request(&b), Ok(Request::Echo(n)));
}

#[test]
fn reach_request_roundtrip() {
    let n = nonce();
    let b = encode_reach_request(&n, 45_901);
    assert_eq!(b[5], T_REACH_REQUEST);
    assert_eq!(&b[24..26], &45_901u16.to_be_bytes());
    assert!(b[26..].iter().all(|x| *x == 0));
    assert_eq!(
        parse_request(&b),
        Ok(Request::Reach {
            nonce: n,
            target_port: 45_901
        })
    );
}

#[test]
fn echo_response_roundtrip_v4() {
    let n = nonce();
    let b = encode_echo_response(&n, v4(), 45_901);
    assert_eq!(b.len(), 48);
    assert_eq!(b[24], 4);
    assert_eq!(
        parse_response(&b, &n),
        Ok(Response {
            observed: v4(),
            reach_port: 45_901,
            reach: false
        })
    );
    // без проверки: порт 0
    let b = encode_echo_response(&n, v4(), 0);
    assert_eq!(parse_response(&b, &n).unwrap().reach_port, 0);
}

#[test]
fn echo_response_roundtrip_v6() {
    let n = nonce();
    let b = encode_echo_response(&n, v6(), 45_901);
    assert_eq!(b[24], 6);
    assert_eq!(
        parse_response(&b, &n),
        Ok(Response {
            observed: v6(),
            reach_port: 45_901,
            reach: false
        })
    );
}

#[test]
fn reach_response_roundtrip() {
    let n = nonce();
    for addr in [v4(), v6()] {
        let b = encode_reach_response(&n, addr);
        assert_eq!(b[5], T_REACH_RESPONSE);
        assert_eq!(&b[44..46], &[0, 0]);
        assert_eq!(
            parse_response(&b, &n),
            Ok(Response {
                observed: addr,
                reach_port: 0,
                reach: true
            })
        );
    }
}

#[test]
fn mapped_v6_encoded_as_v4() {
    let n = nonce();
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(203, 0, 113, 77).to_ipv6_mapped()),
        40_123,
    );
    let b = encode_echo_response(&n, mapped, 0);
    assert_eq!(b[24], 4, "семейство 4");
    assert_eq!(
        b,
        encode_echo_response(&n, v4(), 0),
        "те же байты, что у IPv4"
    );
    assert_eq!(parse_response(&b, &n).unwrap().observed, v4());
}

#[test]
fn response_shorter_than_request() {
    const { assert!(RESPONSE_LEN < REQUEST_LEN) };
    assert!(encode_echo_response(&nonce(), v4(), 1).len() < encode_echo_request(&nonce()).len());
    assert!(encode_reach_response(&nonce(), v6()).len() < encode_reach_request(&nonce(), 1).len());
}

#[test]
fn xor_hides_plain_address() {
    let n = nonce();
    let b = encode_echo_response(&n, v4(), 0);
    let plain_ip = [203u8, 0, 113, 77];
    assert!(
        !b.windows(4).any(|w| w == plain_ip),
        "IPv4 открытым текстом"
    );
    assert!(
        !b.windows(2).any(|w| w == 40_123u16.to_be_bytes()),
        "порт открытым текстом"
    );
    let b6 = encode_echo_response(&n, v6(), 0);
    let plain6 = match v6().ip() {
        IpAddr::V6(a) => a.octets(),
        IpAddr::V4(_) => unreachable!(),
    };
    assert!(
        !b6.windows(8).any(|w| w == &plain6[0..8]),
        "IPv6 открытым текстом"
    );
}

#[test]
fn request_rejects_each_field() {
    let n = nonce();
    let echo = encode_echo_request(&n);
    let reach = encode_reach_request(&n, 45_901);
    // длины
    for len in [0usize, 63, 65] {
        let v = vec![0u8; len];
        assert_eq!(parse_request(&v), Err(WireError::Length), "длина {len}");
    }
    let mut longer = echo.to_vec();
    longer.push(0);
    assert_eq!(parse_request(&longer), Err(WireError::Length));
    assert_eq!(parse_request(&echo[..63]), Err(WireError::Length));
    for base in [echo, reach] {
        let mut b = base;
        b[0] ^= 1;
        assert_eq!(parse_request(&b), Err(WireError::Magic));
        for ver in [0u8, 2] {
            let mut b = base;
            b[4] = ver;
            assert_eq!(parse_request(&b), Err(WireError::Version), "версия {ver}");
        }
        for ty in [0u8, 2, 4, 5, 0x10, 0x7F, 0xFF] {
            let mut b = base;
            b[5] = ty;
            assert_eq!(parse_request(&b), Err(WireError::Type), "тип {ty}");
        }
        for at in [6usize, 7] {
            let mut b = base;
            b[at] = 1;
            assert_eq!(parse_request(&b), Err(WireError::Flags), "флаги {at}");
        }
        let mut b = base;
        b[63] = 1;
        assert_eq!(parse_request(&b), Err(WireError::Padding));
    }
    let mut b = echo;
    b[24] = 1;
    assert_eq!(
        parse_request(&b),
        Err(WireError::Padding),
        "эхо: хвост с 24"
    );
    let mut b = reach;
    b[26] = 1;
    assert_eq!(
        parse_request(&b),
        Err(WireError::Padding),
        "проверка: хвост с 26"
    );
    // целевой порт 0
    assert_eq!(
        parse_request(&encode_reach_request(&n, 0)),
        Err(WireError::Port)
    );
}

#[test]
fn response_rejects_each_field() {
    let n = nonce();
    let ok = encode_echo_response(&n, v4(), 45_901);
    assert!(parse_response(&ok, &n).is_ok());
    // длины
    for len in [0usize, 47, 49, 64] {
        assert_eq!(
            parse_response(&vec![0u8; len], &n),
            Err(WireError::Length),
            "длина {len}"
        );
    }
    // заголовок
    let mut b = ok;
    b[1] ^= 1;
    assert_eq!(parse_response(&b, &n), Err(WireError::Magic));
    let mut b = ok;
    b[4] = 2;
    assert_eq!(parse_response(&b, &n), Err(WireError::Version));
    for ty in [T_ECHO_REQUEST, T_REACH_REQUEST, 0, 5] {
        let mut b = ok;
        b[5] = ty;
        assert_eq!(parse_response(&b, &n), Err(WireError::Type), "тип {ty}");
    }
    let mut b = ok;
    b[7] = 1;
    assert_eq!(parse_response(&b, &n), Err(WireError::Flags));
    // чужой nonce (один бит)
    let mut other = n;
    other.0[15] ^= 1;
    assert_eq!(parse_response(&ok, &other), Err(WireError::Nonce));
    // семейство
    for fam in [0u8, 5, 7, 255] {
        let mut b = ok;
        b[24] = fam;
        assert_eq!(
            parse_response(&b, &n),
            Err(WireError::Family),
            "семейство {fam}"
        );
    }
    // порт 0 (после XOR)
    let zero_port = SocketAddr::new(v4().ip(), 0);
    assert_eq!(
        parse_response(&encode_echo_response(&n, zero_port, 0), &n),
        Err(WireError::Port)
    );
    // недопустимые адреса
    for ip in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
    ] {
        let a = SocketAddr::new(IpAddr::V4(ip), 4000);
        assert_eq!(
            parse_response(&encode_echo_response(&n, a, 0), &n),
            Err(WireError::Address),
            "{ip}"
        );
    }
    for ip in [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
    ] {
        let a = SocketAddr::new(IpAddr::V6(ip), 4000);
        assert_eq!(
            parse_response(&encode_echo_response(&n, a, 0), &n),
            Err(WireError::Address),
            "{ip}"
        );
    }
    // ненулевой хвост: байт 25, пустая часть адреса v4, хвост 46..48
    for at in [25usize, 32, 43, 46, 47] {
        let mut b = ok;
        b[at] = 1;
        assert_eq!(parse_response(&b, &n), Err(WireError::Padding), "байт {at}");
    }
    // у ответа проверки порт проверки обязан быть 0
    let mut b = encode_reach_response(&n, v4());
    b[45] = 1;
    assert_eq!(parse_response(&b, &n), Err(WireError::Padding));
    // `::ffff:a.b.c.d` в семействе 6 не принимается
    let mut b = encode_echo_response(&n, v6(), 0);
    let mapped = Ipv4Addr::new(203, 0, 113, 77).to_ipv6_mapped().octets();
    for i in 0..16 {
        b[28 + i] = mapped[i] ^ n.0[i];
    }
    assert_eq!(parse_response(&b, &n), Err(WireError::Address));
}

#[test]
fn debug_hides_nonce() {
    let n = nonce();
    let s = format!("{n:?} {:?}", Request::Echo(n));
    assert_eq!(s, "Nonce(..) Echo(Nonce(..))");
}
