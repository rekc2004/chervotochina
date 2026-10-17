//! Единственный сокетный код крейта (этап 13а, решение 4).
//!
//! Назначения только два: адрес SSDP (`Net::ssdp_target`) и `GatewayAddr`, тип которого
//! строится только после проверки, что хост адреса равен адресу ответившего. Всё блокирующее,
//! с явными сроками. SSDP уходит с TTL 1 с адреса `own_ip`; TCP к шлюзу тоже с TTL 1 (установка
//! до `connect`) и с привязкой к `own_ip`: хост не в локальной сети рукопожатия не завершит.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::NetError;
use crate::limits::{
    BODY_MAX, DISCOVERY_WINDOW, HTTP_DEADLINE, HTTP_HEAD_MAX, MAX_REFRESH, SSDP_MAX_DGRAMS,
    SSDP_RECV_BUF,
};
use crate::ssdp::{Responder, SEARCH_TARGETS, SsdpPolicy, msearch, parse_response, select};
use crate::url::GatewayAddr;

/// Повторная отправка запросов SSDP.
const RESEND_AFTER: Duration = Duration::from_millis(300);

/// Параметры сети. Рабочие значения даёт `Net::production`; другие строят только тесты.
#[derive(Clone, Copy)]
pub(crate) struct Net {
    pub(crate) ssdp_target: SocketAddrV4,
    pub(crate) allow_loopback: bool,
    pub(crate) http_deadline: Duration,
    pub(crate) discovery_window: Duration,
    /// Общий срок одного `refresh` (рабочее значение `MAX_REFRESH`).
    pub(crate) max_refresh: Duration,
}

impl Net {
    pub(crate) fn production() -> Self {
        Net {
            ssdp_target: SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900),
            allow_loopback: false,
            http_deadline: HTTP_DEADLINE,
            discovery_window: DISCOVERY_WINDOW,
            max_refresh: MAX_REFRESH,
        }
    }

    pub(crate) fn policy(&self) -> SsdpPolicy {
        SsdpPolicy {
            allow_loopback: self.allow_loopback,
        }
    }
}

fn is_timeout(k: ErrorKind) -> bool {
    matches!(k, ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Оставшееся время до срока; ноль и меньше это `Timeout`.
fn remaining(deadline: Instant) -> Result<Duration, NetError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(NetError::Timeout)
}

impl Net {
    /// Поиск шлюзов: M-SEARCH (две цели, каждая в момент 0 и через 300 мс) и сбор ответов
    /// в течение окна. Принимаются только ответы, прошедшие `parse_response` (источник из
    /// частной сети, не мы, `LOCATION` указывает на ответившего).
    pub(crate) fn discover(
        &self,
        own_ip: Ipv4Addr,
        overall: Instant,
    ) -> Result<Vec<Responder>, NetError> {
        let start = Instant::now();
        let end = overall.min(start + self.discovery_window);
        let resend_at = start + RESEND_AFTER;

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|_| NetError::Io)?;
        sock.bind(&SockAddr::from(SocketAddrV4::new(own_ip, 0)))
            .map_err(|_| NetError::Io)?;
        if self.ssdp_target.ip().is_multicast() {
            sock.set_multicast_if_v4(&own_ip)
                .map_err(|_| NetError::Io)?;
            sock.set_multicast_ttl_v4(1).map_err(|_| NetError::Io)?;
            sock.set_multicast_loop_v4(false)
                .map_err(|_| NetError::Io)?;
        }
        let sock = UdpSocket::from(sock);

        let datagrams: Vec<Vec<u8>> = SEARCH_TARGETS.iter().map(|st| msearch(st)).collect();
        let send_round = |sock: &UdpSocket| -> bool {
            let mut ok = false;
            for d in &datagrams {
                ok |= sock.send_to(d, SocketAddr::V4(self.ssdp_target)).is_ok();
            }
            ok
        };
        if !send_round(&sock) {
            return Err(NetError::Io);
        }

        let mut resent = false;
        let mut received = 0usize;
        let mut errors = 0usize;
        let mut found: Vec<Responder> = Vec::new();
        let mut buf = [0u8; SSDP_RECV_BUF];
        loop {
            let now = Instant::now();
            if now >= end {
                break;
            }
            if !resent && now >= resend_at {
                send_round(&sock);
                resent = true;
                continue;
            }
            let stop = if resent { end } else { end.min(resend_at) };
            let wait = stop.saturating_duration_since(now);
            if wait.is_zero() || sock.set_read_timeout(Some(wait)).is_err() {
                break;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(src))) => {
                    received += 1;
                    if received > SSDP_MAX_DGRAMS {
                        break;
                    }
                    // датаграмма, заполнившая буфер, могла быть обрезана
                    if n >= buf.len() {
                        continue;
                    }
                    let Some(data) = buf.get(..n) else { continue };
                    if let Ok(r) = parse_response(data, src, own_ip, self.policy()) {
                        found.push(r);
                    }
                }
                Ok(_) => {}
                Err(e) if is_timeout(e.kind()) => {}
                Err(_) => {
                    errors += 1;
                    if errors > SSDP_MAX_DGRAMS {
                        break;
                    }
                }
            }
        }
        Ok(select(found))
    }

    /// Один запрос HTTP: соединение, запись и чтение укладываются в один срок
    /// `min(now + http_deadline, overall)`. Перед каждым чтением таймаут заново ставится по
    /// остатку срока (медленная отдача по байту не продлевает срок). Читает до EOF, но не
    /// больше головы и тела вместе плюс один байт (тогда `TooLarge`).
    pub(crate) fn http(
        &self,
        gw: &GatewayAddr,
        own_ip: Ipv4Addr,
        request: &[u8],
        overall: Instant,
    ) -> Result<Vec<u8>, NetError> {
        let deadline = overall.min(Instant::now() + self.http_deadline);
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|_| NetError::Io)?;
        // TTL 1 до connect: SYN не пройдёт дальше первого маршрутизатора
        sock.set_ttl_v4(1).map_err(|_| NetError::Io)?;
        sock.bind(&SockAddr::from(SocketAddrV4::new(own_ip, 0)))
            .map_err(|_| NetError::Io)?;
        sock.connect_timeout(&SockAddr::from(gw.addr()), remaining(deadline)?)
            .map_err(|e| {
                if is_timeout(e.kind()) {
                    NetError::Timeout
                } else {
                    NetError::Io
                }
            })?;
        let mut stream = TcpStream::from(sock);

        let mut sent = 0usize;
        while sent < request.len() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| NetError::Io)?;
            let rest = request.get(sent..).unwrap_or_default();
            match stream.write(rest) {
                Ok(0) => return Err(NetError::Io),
                Ok(n) => sent += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if is_timeout(e.kind()) => return Err(NetError::Timeout),
                Err(_) => return Err(NetError::Io),
            }
        }

        let cap = HTTP_HEAD_MAX + BODY_MAX + 1;
        let mut out: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let left = remaining(deadline)?.min(self.http_deadline);
            stream
                .set_read_timeout(Some(left))
                .map_err(|_| NetError::Io)?;
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    if out.len() >= cap {
                        return Err(NetError::TooLarge);
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if is_timeout(e.kind()) => return Err(NetError::Timeout),
                Err(_) => return Err(NetError::Io),
            }
        }
        Ok(out)
    }
}
