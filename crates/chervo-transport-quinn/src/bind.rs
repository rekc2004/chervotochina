//! Двойное гнездо приёма: один UDP-сокет `[::]:port` с `IPV6_V6ONLY = 0` (IPv4 приходит как
//! v4-mapped) и запасной путь на `0.0.0.0:port`, если ОС двойного гнезда не даёт.
//! Единственный пользователь `socket2` в крейте. Спецификация: `docs/specs/stage-13g-ipv6.md`.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};

/// Семейства, которыми пользуется гнездо транспорта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenMode {
    /// Только IPv4 (`0.0.0.0` или конкретный адрес IPv4).
    V4Only,
    /// Только IPv6 (`IPV6_V6ONLY = 1` либо конкретный адрес IPv6).
    V6Only,
    /// `[::]` с `IPV6_V6ONLY = 0`: IPv4 и IPv6 одним гнездом.
    DualStack,
}

/// Ошибка `bind_listen`; без адресов и текстов ОС.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// Порт занят (или нет прав на него): запасного пути нет.
    PortInUse,
    /// Любая иная ошибка ввода-вывода.
    Io,
}

/// Почему двойное гнездо не получилось.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DualFail {
    /// ОС не даёт двойного гнезда: идти на запасной путь IPv4.
    Unavailable,
    /// Порт занят хотя бы одной половиной: запасного пути нет.
    PortInUse,
}

/// Режим готового гнезда по факту: адрес IPv4 это `V4Only`; неуказанный IPv6 с
/// `IPV6_V6ONLY = 0` это `DualStack`; прочий IPv6 это `V6Only`.
pub(crate) fn mode_of(sock: &UdpSocket) -> ListenMode {
    match sock.local_addr() {
        Ok(SocketAddr::V4(_)) | Err(_) => ListenMode::V4Only,
        Ok(SocketAddr::V6(a)) => {
            if a.ip().is_unspecified() && matches!(SockRef::from(sock).only_v6(), Ok(false)) {
                ListenMode::DualStack
            } else {
                ListenMode::V6Only
            }
        }
    }
}

fn dual(port: u16) -> Result<UdpSocket, DualFail> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| DualFail::Unavailable)?;
    s.set_only_v6(false).map_err(|_| DualFail::Unavailable)?;
    let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    s.bind(&SockAddr::from(any)).map_err(|e| match e.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => DualFail::PortInUse,
        _ => DualFail::Unavailable,
    })?;
    // обратное чтение: гнездо действительно двойное
    if !matches!(s.only_v6(), Ok(false)) {
        return Err(DualFail::Unavailable);
    }
    Ok(s.into())
}

/// Выбор по результату двойного гнезда (без ОС, для тестов): двойное готово; ОС его не даёт,
/// тогда `v4()`; порт занят, тогда `PortInUse` без запасного пути.
pub(crate) fn choose(
    dual: Result<UdpSocket, DualFail>,
    v4: impl FnOnce() -> io::Result<UdpSocket>,
) -> Result<(UdpSocket, ListenMode), BindError> {
    match dual {
        Ok(s) => Ok((s, ListenMode::DualStack)),
        Err(DualFail::PortInUse) => Err(BindError::PortInUse),
        Err(DualFail::Unavailable) => match v4() {
            Ok(s) => Ok((s, ListenMode::V4Only)),
            Err(e) => Err(match e.kind() {
                io::ErrorKind::AddrInUse
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::PermissionDenied => BindError::PortInUse,
                _ => BindError::Io,
            }),
        },
    }
}

/// `[::]:port`, `IPV6_V6ONLY = 0` до `bind`, обратное чтение; запасной путь `0.0.0.0:port`
/// только если ОС двойного гнезда не даёт (не при занятом порте).
pub fn bind_listen(port: u16) -> Result<(UdpSocket, ListenMode), BindError> {
    choose(dual(port), || {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
    })
}
