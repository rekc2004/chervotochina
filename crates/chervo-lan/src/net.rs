//! Единственный сокетный код крейта (этап 13в, L3).
//!
//! Приём: сокет UDP IPv4 с `SO_REUSEADDR` (без `SO_REUSEPORT`), на unix привязан к
//! `(LAN_GROUP, LAN_PORT)`, на Windows к `(0.0.0.0, LAN_PORT)`; вход в группу на интерфейсе
//! с нашим адресом. Отправка (только в режиме «сообщать»): сокет с адресом `(own, 0)`,
//! `IP_MULTICAST_IF = own`, TTL 1, петля выключена; назначение только `(LAN_GROUP, LAN_PORT)`.
//! Вход в группу 224.0.0.1 отчётов IGMP не вызывает, режим «только слушать» ничего не шлёт.
//! Ничего не печатается и не пишется в журнал.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::limits::{LAN_GROUP, LAN_PORT, READ_TIMEOUT};

/// Откуда и куда: продукт (группа) или тест на петле (юникаст).
#[derive(Clone, Copy)]
pub(crate) enum Route {
    Product,
    /// Только под `test` и `test-net`: приём на `(bind, port)` без группы, отправка на `target`.
    #[cfg(any(test, feature = "test-net"))]
    Test {
        bind: Ipv4Addr,
        port: u16,
        target: SocketAddrV4,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// Порт занят другой программой.
    Busy,
    Other,
}

/// Итог одного ожидания датаграммы.
pub(crate) enum Recv {
    /// `len` байт в буфере от `src`.
    Data { len: usize, src: SocketAddr },
    /// Срок ожидания вышел.
    Idle,
    /// Датаграмма длиннее буфера (Windows сообщает об этом ошибкой): отброшена.
    Oversize,
    /// Прочая ошибка приёма.
    Error,
}

pub(crate) struct Sockets {
    listen: UdpSocket,
    send: Option<UdpSocket>,
    send_ip: Ipv4Addr,
    target: SocketAddrV4,
}

fn is_busy(k: ErrorKind) -> bool {
    matches!(k, ErrorKind::AddrInUse)
}

fn open_listen(own: Ipv4Addr, route: Route) -> Result<UdpSocket, OpenError> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| OpenError::Other)?;
    let bind_to = match route {
        Route::Product => {
            sock.set_reuse_address(true).map_err(|_| OpenError::Other)?;
            if cfg!(windows) {
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LAN_PORT)
            } else {
                SocketAddrV4::new(LAN_GROUP, LAN_PORT)
            }
        }
        // в тесте общий доступ к порту не включается: занятый порт виден одинаково на всех ОС
        #[cfg(any(test, feature = "test-net"))]
        Route::Test { bind, port, .. } => SocketAddrV4::new(bind, port),
    };
    sock.bind(&SockAddr::from(bind_to)).map_err(|e| {
        if is_busy(e.kind()) {
            OpenError::Busy
        } else {
            OpenError::Other
        }
    })?;
    if matches!(route, Route::Product) {
        sock.join_multicast_v4(&LAN_GROUP, &own)
            .map_err(|_| OpenError::Other)?;
    }
    Ok(UdpSocket::from(sock))
}

fn open_send(own: Ipv4Addr, route: Route) -> Result<UdpSocket, OpenError> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| OpenError::Other)?;
    // в тесте адрес маршрута может быть выдуманным (частный, которого на машине нет): тогда
    // отправитель привязывается к адресу приёма на петле, а запечатывается адресом привязки
    let from = match route {
        Route::Product => own,
        #[cfg(any(test, feature = "test-net"))]
        Route::Test { bind, .. } if !own.is_loopback() => bind,
        #[cfg(any(test, feature = "test-net"))]
        Route::Test { .. } => own,
    };
    sock.bind(&SockAddr::from(SocketAddrV4::new(from, 0)))
        .map_err(|_| OpenError::Other)?;
    if matches!(route, Route::Product) {
        sock.set_multicast_if_v4(&own)
            .map_err(|_| OpenError::Other)?;
        sock.set_multicast_ttl_v4(1).map_err(|_| OpenError::Other)?;
        sock.set_multicast_loop_v4(false)
            .map_err(|_| OpenError::Other)?;
    }
    Ok(UdpSocket::from(sock))
}

impl Sockets {
    /// Открыть приём и, если `want_send`, отправку. Адрес отправки: `own`.
    pub(crate) fn open(own: Ipv4Addr, want_send: bool, route: Route) -> Result<Self, OpenError> {
        let listen = open_listen(own, route)?;
        let send = if want_send {
            Some(open_send(own, route)?)
        } else {
            None
        };
        let target = match route {
            Route::Product => SocketAddrV4::new(LAN_GROUP, LAN_PORT),
            #[cfg(any(test, feature = "test-net"))]
            Route::Test { target, .. } => target,
        };
        Ok(Self {
            listen,
            send,
            send_ip: own,
            target,
        })
    }

    /// Адрес, которым запечатываются слоты: адрес привязки сокета отправки.
    pub(crate) fn send_ip(&self) -> Ipv4Addr {
        self.send
            .as_ref()
            .and_then(|s| match s.local_addr() {
                Ok(SocketAddr::V4(a)) => Some(*a.ip()),
                _ => None,
            })
            .unwrap_or(self.send_ip)
    }

    pub(crate) fn can_send(&self) -> bool {
        self.send.is_some()
    }

    /// Отправка одной датаграммы на назначение; без сокета отправки (режим «слушать») ничего не
    /// делает и сообщает об ошибке.
    pub(crate) fn send(&self, d: &[u8]) -> bool {
        let Some(s) = self.send.as_ref() else {
            return false;
        };
        matches!(s.send_to(d, SocketAddr::V4(self.target)), Ok(n) if n == d.len())
    }

    /// Ждать датаграмму не дольше `wait` (от 1 мс до `READ_TIMEOUT`).
    pub(crate) fn recv(&self, buf: &mut [u8], wait: Duration) -> Recv {
        let wait = wait.clamp(Duration::from_millis(1), READ_TIMEOUT);
        if self.listen.set_read_timeout(Some(wait)).is_err() {
            return Recv::Error;
        }
        match self.listen.recv_from(buf) {
            Ok((len, src)) => Recv::Data { len, src },
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Recv::Idle,
            // Windows: WSAEMSGSIZE (10040), датаграмма не поместилась в буфер
            Err(e) if cfg!(windows) && e.raw_os_error() == Some(10040) => Recv::Oversize,
            Err(_) => Recv::Error,
        }
    }
}
