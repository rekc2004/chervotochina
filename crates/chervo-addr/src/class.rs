//! Классификация адресов по собственным таблицам префиксов (без нестабильного std).
//!
//! Таблицы выписаны по памяти из реестра специального назначения IANA (RFC 6890 и
//! дополнения); у каждого диапазона указан RFC, чтобы сверить таблицу с реестром.
//! Побеждает первое совпадение в порядке записи; порядок задан спецификацией этапа 12.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddrClass {
    Global,
    Private,
    Shared,
    Loopback,
    LinkLocal,
    Unspecified,
    Multicast,
    Broadcast,
    Documentation,
    Benchmark,
    V4Mapped,
    Reserved,
}

use AddrClass::{
    Benchmark, Broadcast, Documentation, Global, LinkLocal, Loopback, Multicast, Private, Reserved,
    Shared, Unspecified, V4Mapped,
};

/// IPv4: (сеть, длина префикса, класс). Первое совпадение выигрывает.
const V4_TABLE: &[(Ipv4Addr, u8, AddrClass)] = &[
    // RFC 1122 s3.2.1.3 "this host on this network"; RFC 6890
    (Ipv4Addr::new(0, 0, 0, 0), 32, Unspecified),
    // RFC 1122 s3.2.1.3 "this network"; RFC 6890
    (Ipv4Addr::new(0, 0, 0, 0), 8, Reserved),
    // RFC 1918 private use
    (Ipv4Addr::new(10, 0, 0, 0), 8, Private),
    // RFC 6598 shared address space (CGNAT)
    (Ipv4Addr::new(100, 64, 0, 0), 10, Shared),
    // RFC 1122 s3.2.1.3 loopback; RFC 6890
    (Ipv4Addr::new(127, 0, 0, 0), 8, Loopback),
    // RFC 3927 link-local
    (Ipv4Addr::new(169, 254, 0, 0), 16, LinkLocal),
    // RFC 1918 private use
    (Ipv4Addr::new(172, 16, 0, 0), 12, Private),
    // RFC 6890 IETF protocol assignments (RFC 5736 and others)
    (Ipv4Addr::new(192, 0, 0, 0), 24, Reserved),
    // RFC 5737 TEST-NET-1
    (Ipv4Addr::new(192, 0, 2, 0), 24, Documentation),
    // RFC 3068 6to4 relay anycast (deprecated by RFC 7526), kept reserved
    (Ipv4Addr::new(192, 88, 99, 0), 24, Reserved),
    // RFC 1918 private use
    (Ipv4Addr::new(192, 168, 0, 0), 16, Private),
    // RFC 2544 benchmarking; RFC 6890
    (Ipv4Addr::new(198, 18, 0, 0), 15, Benchmark),
    // RFC 5737 TEST-NET-2
    (Ipv4Addr::new(198, 51, 100, 0), 24, Documentation),
    // RFC 5737 TEST-NET-3
    (Ipv4Addr::new(203, 0, 113, 0), 24, Documentation),
    // RFC 5771 multicast (former class D)
    (Ipv4Addr::new(224, 0, 0, 0), 4, Multicast),
    // RFC 919 limited broadcast; RFC 8190
    (Ipv4Addr::new(255, 255, 255, 255), 32, Broadcast),
    // RFC 1112 s4 reserved (former class E); RFC 6890
    (Ipv4Addr::new(240, 0, 0, 0), 4, Reserved),
];

/// IPv6: (сеть, длина префикса, класс). Первое совпадение выигрывает.
const V6_TABLE: &[(Ipv6Addr, u8, AddrClass)] = &[
    // RFC 4291 s2.5.2 unspecified address
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128, Unspecified),
    // RFC 4291 s2.5.3 loopback address
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128, Loopback),
    // RFC 4291 s2.5.5.2 IPv4-mapped addresses
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96, V4Mapped),
    // RFC 4291 s2.5.5.1 IPv4-compatible (deprecated), kept reserved
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 96, Reserved),
    // RFC 6052 NAT64 well-known prefix
    (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96, Reserved),
    // RFC 8215 local-use NAT64 prefix
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48, Reserved),
    // RFC 6666 discard-only prefix
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64, Reserved),
    // RFC 4291 s2.7 multicast
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, Multicast),
    // RFC 4291 s2.5.6 link-local unicast
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, LinkLocal),
    // RFC 3879 site-local (deprecated), kept reserved
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10, Reserved),
    // RFC 4193 unique local addresses (ULA)
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7, Private),
    // RFC 3849 documentation prefix
    (
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        32,
        Documentation,
    ),
    // RFC 9637 documentation prefix (large)
    (
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        20,
        Documentation,
    ),
    // RFC 6890 / RFC 2928 IETF protocol assignments (Teredo, ORCHID, benchmarking inside)
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23, Reserved),
    // RFC 3056 6to4
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16, Reserved),
    // RFC 4291 / RFC 3587 global unicast space
    (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3, Global),
];

fn in_v4(ip: u32, net: Ipv4Addr, len: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(len)))
        .unwrap_or(0);
    ip & mask == u32::from(net) & mask
}

fn in_v6(ip: u128, net: Ipv6Addr, len: u8) -> bool {
    let mask = u128::MAX
        .checked_shl(128u32.saturating_sub(u32::from(len)))
        .unwrap_or(0);
    ip & mask == u128::from(net) & mask
}

/// Класс адреса по таблицам выше; всё, чего нет в таблице IPv4, считается глобальным,
/// всё, чего нет в таблице IPv6, зарезервированным.
pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(a) => {
            let v = u32::from(a);
            V4_TABLE
                .iter()
                .find(|(net, len, _)| in_v4(v, *net, *len))
                .map_or(Global, |(_, _, c)| *c)
        }
        IpAddr::V6(a) => {
            let v = u128::from(a);
            V6_TABLE
                .iter()
                .find(|(net, len, _)| in_v6(v, *net, *len))
                .map_or(Reserved, |(_, _, c)| *c)
        }
    }
}

/// Адрес с идентификатором интерфейса EUI-64 (байты 11 и 12 равны `ff fe`): выдаёт MAC.
pub fn is_eui64(ip: &Ipv6Addr) -> bool {
    let o = ip.octets();
    o.get(11) == Some(&0xff) && o.get(12) == Some(&0xfe)
}

/// IPv6 вида `::ffff:a.b.c.d` становится IPv4 с тем же портом; остальное без изменений.
pub fn normalize(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        SocketAddr::V4(_) => a,
    }
}

/// В токене обновления допустимы только глобальные и частные (RFC 1918, ULA) адреса.
pub fn update_allowed(ip: IpAddr) -> bool {
    matches!(classify(ip), Global | Private)
}
