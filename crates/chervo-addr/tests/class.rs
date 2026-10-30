//! Таблицы классификации: первый и последний адрес каждого диапазона и обе соседние точки.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use chervo_addr::AddrClass::{
    Benchmark, Broadcast, Documentation, Global, LinkLocal, Loopback, Multicast, Private, Reserved,
    Shared, Unspecified, V4Mapped,
};
use chervo_addr::{
    AddrClass, classify, is_eui64, normalize, update_allowed, v6_egress_ok, v6_peer_ok,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn check(table: &[(&str, AddrClass)]) {
    for (s, want) in table {
        assert_eq!(classify(ip(s)), *want, "{s}");
    }
}

#[test]
fn classify_v4_table() {
    check(&[
        // 0.0.0.0/32 и 0.0.0.0/8
        ("0.0.0.0", Unspecified),
        ("0.0.0.1", Reserved),
        ("0.255.255.255", Reserved),
        ("1.0.0.0", Global),
        // 10/8
        ("9.255.255.255", Global),
        ("10.0.0.0", Private),
        ("10.255.255.255", Private),
        ("11.0.0.0", Global),
        // 100.64/10
        ("100.63.255.255", Global),
        ("100.64.0.0", Shared),
        ("100.127.255.255", Shared),
        ("100.128.0.0", Global),
        // 127/8
        ("126.255.255.255", Global),
        ("127.0.0.0", Loopback),
        ("127.255.255.255", Loopback),
        ("128.0.0.0", Global),
        // 169.254/16
        ("169.253.255.255", Global),
        ("169.254.0.0", LinkLocal),
        ("169.254.255.255", LinkLocal),
        ("169.255.0.0", Global),
        // 172.16/12
        ("172.15.255.255", Global),
        ("172.16.0.0", Private),
        ("172.31.255.255", Private),
        ("172.32.0.0", Global),
        // 192.0.0/24, 192.0.2/24
        ("191.255.255.255", Global),
        ("192.0.0.0", Reserved),
        ("192.0.0.255", Reserved),
        ("192.0.1.0", Global),
        ("192.0.1.255", Global),
        ("192.0.2.0", Documentation),
        ("192.0.2.255", Documentation),
        ("192.0.3.0", Global),
        // 192.88.99/24
        ("192.88.98.255", Global),
        ("192.88.99.0", Reserved),
        ("192.88.99.255", Reserved),
        ("192.88.100.0", Global),
        // 192.168/16
        ("192.167.255.255", Global),
        ("192.168.0.0", Private),
        ("192.168.255.255", Private),
        ("192.169.0.0", Global),
        // 198.18/15
        ("198.17.255.255", Global),
        ("198.18.0.0", Benchmark),
        ("198.19.255.255", Benchmark),
        ("198.20.0.0", Global),
        // 198.51.100/24
        ("198.51.99.255", Global),
        ("198.51.100.0", Documentation),
        ("198.51.100.255", Documentation),
        ("198.51.101.0", Global),
        // 203.0.113/24
        ("203.0.112.255", Global),
        ("203.0.113.0", Documentation),
        ("203.0.113.255", Documentation),
        ("203.0.114.0", Global),
        // 224/4, 240/4, 255.255.255.255/32
        ("223.255.255.255", Global),
        ("224.0.0.0", Multicast),
        ("239.255.255.255", Multicast),
        ("240.0.0.0", Reserved),
        ("255.255.255.254", Reserved),
        ("255.255.255.255", Broadcast),
        // типичные глобальные
        ("8.8.8.8", Global),
        ("1.1.1.1", Global),
    ]);
}

#[test]
fn classify_v6_table() {
    check(&[
        // ::/128, ::1/128, ::/96
        ("::", Unspecified),
        ("::1", Loopback),
        ("::2", Reserved),
        ("::fffe:ffff", Reserved),
        ("::ffff:0:0", V4Mapped),
        ("::ffff:ffff:ffff", V4Mapped),
        ("::1:0:0", Reserved),
        ("0:0:0:0:1::", Reserved),
        // 64:ff9b::/96 и 64:ff9b:1::/48
        ("64:ff9b::", Reserved),
        ("64:ff9b::ffff:ffff", Reserved),
        ("64:ff9b:1::", Reserved),
        ("64:ff9b:1:ffff:ffff:ffff:ffff:ffff", Reserved),
        // 100::/64
        ("100::", Reserved),
        ("100::ffff:ffff:ffff:ffff", Reserved),
        ("100:0:0:1::", Reserved),
        // ff00::/8
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("ff00::", Multicast),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Multicast),
        // fe80::/10
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("fe80::", LinkLocal),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", LinkLocal),
        // fec0::/10
        ("fec0::", Reserved),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", Reserved),
        // fc00::/7
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("fc00::", Private),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Private),
        ("fe00::", Reserved),
        // 2001:db8::/32
        ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("2001:db8::", Documentation),
        ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", Documentation),
        ("2001:db9::", Global),
        // 3fff::/20
        ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("3fff::", Documentation),
        ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", Documentation),
        ("3fff:1000::", Global),
        // 2001::/23
        ("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("2001::", Reserved),
        ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("2001:200::", Global),
        // 2002::/16
        ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("2002::", Reserved),
        ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("2003::", Global),
        // 2000::/3 и всё остальное
        ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Reserved),
        ("2000::", Global),
        ("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("4000::", Reserved),
        ("2606:4700::1111", Global),
    ]);
}

#[test]
fn eui64_detection() {
    let yes: Ipv6Addr = "2606:4700::211:22ff:fe33:4455".parse().unwrap();
    assert!(is_eui64(&yes));
    let no: Ipv6Addr = "2606:4700::211:22ff:fd33:4455".parse().unwrap();
    assert!(!is_eui64(&no));
    let half1: Ipv6Addr = "2606:4700::211:22ff:ff33:4455".parse().unwrap();
    assert!(!is_eui64(&half1));
    let half2: Ipv6Addr = "2606:4700::211:2200:fe33:4455".parse().unwrap();
    assert!(!is_eui64(&half2));
    let plain: Ipv6Addr = "2606:4700::1".parse().unwrap();
    assert!(!is_eui64(&plain));
}

#[test]
fn normalize_v4_mapped() {
    let m: SocketAddr = "[::ffff:8.8.8.8]:443".parse().unwrap();
    assert_eq!(normalize(m), "8.8.8.8:443".parse::<SocketAddr>().unwrap());
    let v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
    assert_eq!(normalize(v6), v6);
    let v4: SocketAddr = "8.8.8.8:443".parse().unwrap();
    assert_eq!(normalize(v4), v4);
    // IPv4-совместимый (не mapped) не меняется
    let compat: SocketAddr = "[::8.8.8.8]:443".parse().unwrap();
    assert_eq!(normalize(compat), compat);
}

#[test]
fn update_allowed_only_global_and_private() {
    for s in [
        "8.8.8.8",
        "10.1.2.3",
        "192.168.1.1",
        "2606:4700::1",
        "fd00::1",
    ] {
        assert!(update_allowed(ip(s)), "{s}");
    }
    for s in [
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "240.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "::",
        "::1",
        "fe80::1",
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "ff02::1",
    ] {
        assert!(!update_allowed(ip(s)), "{s}");
    }
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// Факт, на который опирается канон адреса: `SocketAddrV6` сравнивается по всем четырём полям.
#[test]
fn std_v6_eq_includes_flowinfo() {
    let ip = v6("2606:4700::1");
    let a = SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 0));
    let b = SocketAddr::V6(SocketAddrV6::new(ip, 443, 7, 0));
    let c = SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 3));
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_eq!(a, SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 0)));
}

#[test]
fn normalize_v6_zeroes_flowinfo_and_scope() {
    let ip = v6("2606:4700::1");
    let dirty = SocketAddr::V6(SocketAddrV6::new(ip, 443, 7, 3));
    let clean = SocketAddr::V6(SocketAddrV6::new(ip, 443, 0, 0));
    let n = normalize(dirty);
    assert_eq!(n, clean);
    let SocketAddr::V6(n6) = n else {
        panic!("не IPv6")
    };
    assert_eq!((n6.flowinfo(), n6.scope_id()), (0, 0));
    // link-local со scope id тоже обнуляется (набирать его всё равно нельзя)
    let ll = SocketAddr::V6(SocketAddrV6::new(v6("fe80::1"), 5, 9, 3));
    assert_eq!(
        normalize(ll),
        SocketAddr::V6(SocketAddrV6::new(v6("fe80::1"), 5, 0, 0))
    );
}

#[test]
fn normalize_v4_mapped_to_v4_keeps_port() {
    let m = SocketAddr::V6(SocketAddrV6::new(v6("::ffff:1.2.3.4"), 9999, 7, 3));
    assert_eq!(normalize(m), "1.2.3.4:9999".parse::<SocketAddr>().unwrap());
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

#[test]
fn normalize_idempotent() {
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..10_000u32 {
        let mut o = [0u8; 16];
        for ch in o.chunks_mut(8) {
            ch.copy_from_slice(&xorshift(&mut s).to_le_bytes());
        }
        // каждый пятый: v4-mapped
        if i % 5 == 0 {
            o[..10].fill(0);
            o[10] = 0xff;
            o[11] = 0xff;
        }
        let r = xorshift(&mut s);
        let a = if i % 7 == 0 {
            SocketAddr::new(IpAddr::from([o[0], o[1], o[2], o[3]]), r as u16)
        } else {
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(o),
                r as u16,
                (r >> 16) as u32,
                (r >> 40) as u32,
            ))
        };
        let once = normalize(a);
        assert_eq!(normalize(once), once);
        if let SocketAddr::V6(v) = once {
            assert_eq!((v.flowinfo(), v.scope_id()), (0, 0));
            assert!(v.ip().to_ipv4_mapped().is_none());
        }
    }
}

#[test]
fn v6_peer_ok_table() {
    for ok in [
        "2606:4700::1",
        "2000::1",
        "3ffe::1",
        // EUI-64 как адрес друга принимается
        "2606:4700::211:22ff:fe33:4455",
        // ULA
        "fc00::1",
        "fd00::1",
        "::1",
    ] {
        assert!(v6_peer_ok(&v6(ok)), "{ok}");
    }
    for bad in [
        // link-local, site-local
        "fe80::1",
        "febf::1",
        "fec0::1",
        // Teredo и всё 2001::/23, 6to4
        "2001::1",
        "2001:0:4136:e378::1",
        "2001:1ff::1",
        "2002::1",
        "2002:0102:0304::1",
        // NAT64
        "64:ff9b::1",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        // v4-compatible, неуказанный, v4-mapped
        "::1.2.3.4",
        "::",
        "::ffff:1.2.3.4",
        // 100::/64
        "100::1",
        // документация
        "2001:db8::1",
        "3fff::1",
        "3fff:fff:ffff::1",
        // multicast
        "ff02::1",
        "ff00::1",
        // вне 2000::/3
        "1000::1",
        "4000::1",
        "8000::1",
        "e000::1",
    ] {
        assert!(!v6_peer_ok(&v6(bad)), "{bad}");
    }
}

#[test]
fn v6_egress_ok_table() {
    assert!(!v6_egress_ok(None));
    assert!(v6_egress_ok(Some(v6("2606:4700::7"))));
    // ULA за NAT66
    assert!(v6_egress_ok(Some(v6("fd00::7"))));
    // EUI-64 как свой исходящий источник допускается (решение владельца В1 = а)
    assert!(v6_egress_ok(Some(v6("2606:4700::211:22ff:fe33:4455"))));
    for bad in [
        "fe80::1",
        "2001:0:4136:e378::1",
        "2002:0102:0304::1",
        "2001:db8::1",
        "3fff::1",
        "64:ff9b::1",
        "::1",
        "::",
        "ff02::1",
    ] {
        assert!(!v6_egress_ok(Some(v6(bad))), "{bad}");
    }
}
