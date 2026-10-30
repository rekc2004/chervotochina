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

/// Попыток при `port = 0`: чужой держатель мог занять выбранный ОС порт между шагами.
const MAX_EPHEMERAL_TRIES: usize = 8;

/// Ошибка `bind` двойного или IPv6-пробного гнезда: занято (или нет прав) или иное.
fn busy_or_unavailable(kind: io::ErrorKind) -> DualFail {
    match kind {
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => DualFail::PortInUse,
        _ => DualFail::Unavailable,
    }
}

/// Создание и `bind` двойного гнезда `[::]:p` (`IPV6_V6ONLY = 0` до `bind`, обратное чтение).
fn open_dual(port: u16) -> Result<UdpSocket, DualFail> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| DualFail::Unavailable)?;
    s.set_only_v6(false).map_err(|_| DualFail::Unavailable)?;
    let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    s.bind(&SockAddr::from(any))
        .map_err(|e| busy_or_unavailable(e.kind()))?;
    // обратное чтение: гнездо действительно двойное
    if !matches!(s.only_v6(), Ok(false)) {
        return Err(DualFail::Unavailable);
    }
    Ok(s.into())
}

/// Пробный захват IPv6-половины: `[::]:p` с `IPV6_V6ONLY = 1`.
fn open_probe6(port: u16) -> Result<Socket, DualFail> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| DualFail::Unavailable)?;
    s.set_only_v6(true).map_err(|_| DualFail::Unavailable)?;
    let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    s.bind(&SockAddr::from(any))
        .map_err(|e| busy_or_unavailable(e.kind()))?;
    Ok(s)
}

/// Одна попытка: пробные захваты обеих половин порта, затем двойное гнездо. Пробы живут только
/// здесь и закрыты на любом пути выхода (они локальные значения).
fn dual_once(port: u16) -> Result<UdpSocket, DualFail> {
    // 1. IPv4-половина; при `port = 0` это же выбор порта
    let g4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).map_err(|e| match e.kind() {
        io::ErrorKind::AddrNotAvailable => DualFail::PortInUse,
        k => busy_or_unavailable(k),
    })?;
    let p = g4.local_addr().map_err(|_| DualFail::Unavailable)?.port();
    // 2. IPv6-половина
    let g6 = open_probe6(p)?;
    // 3. двойное гнездо, пока пробы открыты
    match open_dual(p) {
        // ОС не закрепляет половины за двойным гнездом: пробы свободны для двойного
        Ok(d) => {
            drop(g4);
            drop(g6);
            Ok(d)
        }
        // ОС закрепляет половины: конфликт с нашими пробами, повтор без них
        Err(DualFail::PortInUse) => {
            drop(g4);
            drop(g6);
            open_dual(p)
        }
        Err(DualFail::Unavailable) => Err(DualFail::Unavailable),
    }
}

fn dual(port: u16) -> Result<UdpSocket, DualFail> {
    let tries = if port == 0 { MAX_EPHEMERAL_TRIES } else { 1 };
    for _ in 0..tries {
        match dual_once(port) {
            Err(DualFail::PortInUse) => {}
            other => return other,
        }
    }
    Err(DualFail::PortInUse)
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
