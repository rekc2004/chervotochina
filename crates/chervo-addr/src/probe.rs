//! Единственный сокетный код крейта. Определяет адрес-источник по маршруту: UDP-сокет
//! `connect` к адресу документации и чтение `local_addr`. Для UDP `connect` не отправляет
//! ни одного пакета (проверка захватом трафика отложена на этап 16). Данные не посылаются
//! никогда: третьи лица не опрашиваются.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use crate::class::{AddrClass, classify, normalize};

/// 192.0.2.1:9 (TEST-NET-1, RFC 5737).
pub const PROBE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
/// [2001:db8::1]:9 (RFC 3849).
pub const PROBE_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    9,
);

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteSources {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl fmt::Debug for RouteSources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RouteSources(..)")
    }
}

fn source_for(bind: SocketAddr, target: SocketAddr) -> Option<IpAddr> {
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(target).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    match classify(ip) {
        AddrClass::Unspecified | AddrClass::Loopback => None,
        _ => Some(ip),
    }
}

/// Адрес-источник на маршруте к `target` (после `normalize`): bind неуказанного адреса его
/// семейства, UDP `connect`, `local_addr`. Петлевой, неуказанный адрес и любая ошибка дают
/// `None`. Ничего не отправляет.
pub fn route_source_for(target: SocketAddr) -> Option<IpAddr> {
    let target = normalize(target);
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    source_for(bind, target)
}

/// bind `0.0.0.0:0` / `[::]:0`, `connect(PROBE_*)`, `local_addr().ip()`. Любая ошибка
/// даёт `None` для этого семейства; неуказанный и петлевой результат тоже `None`.
pub fn probe_route_sources() -> RouteSources {
    let v4 = match source_for(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        PROBE_V4,
    ) {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    };
    let v6 = match source_for(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        PROBE_V6,
    ) {
        Some(IpAddr::V6(a)) => Some(a),
        _ => None,
    };
    RouteSources { v4, v6 }
}
