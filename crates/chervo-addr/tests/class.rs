//! Таблицы классификации: первый и последний адрес каждого диапазона и обе соседние точки.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use chervo_addr::AddrClass::{
    Benchmark, Broadcast, Documentation, Global, LinkLocal, Loopback, Multicast, Private, Reserved,
    Shared, Unspecified, V4Mapped,
};
use chervo_addr::{AddrClass, classify, is_eui64, normalize, update_allowed};

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
