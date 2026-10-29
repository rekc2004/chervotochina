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
    /// Интерфейсы, на которых приём вошёл в группу (в тесте: все заданные).
    members: Vec<Ipv4Addr>,
    /// Сокет отправки на каждый интерфейс: запрошенный адрес и сокет.
    sends: Vec<(Ipv4Addr, UdpSocket)>,
    target: SocketAddrV4,
}

fn is_busy(k: ErrorKind) -> bool {
    matches!(k, ErrorKind::AddrInUse)
}

/// Один сокет приёма на все интерфейсы: привязка как в продукте или в тесте, без входа в группу.
fn open_listen(route: Route) -> Result<Socket, OpenError> {
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
    Ok(sock)
}

fn open_send(own: Ipv4Addr, route: Route) -> Result<UdpSocket, OpenError> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| OpenError::Other)?;
    // в тесте адрес интерфейса может быть выдуманным (частный, которого на машине нет): тогда
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
    /// Открыть приём на интерфейсах `members` и, если `want_send`, отправку с каждого из них.
    /// Интерфейс, на котором не удался вход в группу (или открытие сокета отправки), отбрасывается;
    /// не осталось ни одного: ошибка.
    pub(crate) fn open(
        members: &[Ipv4Addr],
        want_send: bool,
        route: Route,
    ) -> Result<Self, OpenError> {
        let listen = open_listen(route)?;
        let mut joined: Vec<Ipv4Addr> = Vec::new();
        for m in members {
            let ok = match route {
                Route::Product => listen.join_multicast_v4(&LAN_GROUP, m).is_ok(),
                #[cfg(any(test, feature = "test-net"))]
                Route::Test { .. } => true,
            };
            if ok && !joined.contains(m) {
                joined.push(*m);
            }
        }
        let mut sends: Vec<(Ipv4Addr, UdpSocket)> = Vec::new();
        let mut kept: Vec<Ipv4Addr> = Vec::new();
        for m in joined {
            if want_send {
                match open_send(m, route) {
                    Ok(s) => sends.push((m, s)),
                    Err(_) => continue,
                }
            }
            kept.push(m);
        }
        if kept.is_empty() {
            return Err(OpenError::Other);
        }
        let target = match route {
            Route::Product => SocketAddrV4::new(LAN_GROUP, LAN_PORT),
            #[cfg(any(test, feature = "test-net"))]
            Route::Test { target, .. } => target,
        };
        Ok(Self {
            listen: UdpSocket::from(listen),
            members: kept,
            sends,
            target,
        })
    }

    /// Интерфейсы, на которых идёт поиск.
    pub(crate) fn members(&self) -> Vec<Ipv4Addr> {
        self.members.clone()
    }

    /// Адреса, которыми запечатываются слоты: адрес привязки каждого сокета отправки.
    pub(crate) fn send_ips(&self) -> Vec<Ipv4Addr> {
        self.sends
            .iter()
            .map(|(m, s)| match s.local_addr() {
                Ok(SocketAddr::V4(a)) => *a.ip(),
                _ => *m,
            })
            .collect()
    }

    pub(crate) fn can_send(&self) -> bool {
        !self.sends.is_empty()
    }

    /// Отправка одной датаграммы сокетом номер `i` на назначение; без такого сокета (режим
    /// «слушать») ничего не делает и сообщает об ошибке.
    pub(crate) fn send(&self, i: usize, d: &[u8]) -> bool {
        let Some((_, s)) = self.sends.get(i) else {
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
