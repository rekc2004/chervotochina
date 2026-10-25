//! The only socket code of the crate (spec D12 and section 5, driver).
//!
//! Production: a send socket bound to `(own_ip, 0)` with the multicast interface set to
//! `own_ip`, TTL 1 and loopback off; a receive socket with address reuse, bound to the group
//! (Unix) or to the wildcard (Windows, where binding to a multicast address is refused),
//! joined to the group on `own_ip`. The only destination of a production send is
//! `LAN_GROUP_V4:LAN_PORT`. Tests use a unicast mode (bind on loopback, explicit targets).

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::limits::{LAN_GROUP_V4, LAN_PORT, SOCKET_RECV_BUF};

/// Opening or configuring a socket failed. No text: the reason is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetError;

enum Mode {
    Multicast,
    /// Tests only (manual): the real group with multicast loopback on, so that two links on
    /// one host hear each other.
    #[cfg(test)]
    MulticastLive,
    /// Tests only: bind on loopback without joining, send to the listed targets.
    #[cfg(test)]
    Unicast {
        bind: SocketAddrV4,
        targets: Vec<SocketAddrV4>,
    },
}

/// Network parameters. Production code uses `Net::production()` only.
pub(crate) struct Net {
    mode: Mode,
}

impl Net {
    pub(crate) fn production() -> Self {
        Self {
            mode: Mode::Multicast,
        }
    }

    #[cfg(test)]
    pub(crate) fn multicast_live() -> Self {
        Self {
            mode: Mode::MulticastLive,
        }
    }

    #[cfg(test)]
    pub(crate) fn unicast(bind: SocketAddrV4, targets: Vec<SocketAddrV4>) -> Self {
        Self {
            mode: Mode::Unicast { bind, targets },
        }
    }

    /// Opens both sockets for `own_ip`; any failure closes everything opened so far.
    pub(crate) fn open(&self, own_ip: Ipv4Addr) -> Result<Sockets, NetError> {
        match &self.mode {
            Mode::Multicast => open_multicast(own_ip, false),
            #[cfg(test)]
            Mode::MulticastLive => open_multicast(own_ip, true),
            #[cfg(test)]
            Mode::Unicast { bind, targets } => open_unicast(*bind, targets),
        }
    }
}

/// What one receive attempt produced.
pub(crate) enum Recv {
    /// `n` bytes from the source. `n == buf.len()` means "possibly longer": the caller treats
    /// it as a wrong length.
    Data(usize, SocketAddr),
    Timeout,
    /// The datagram was larger than the buffer and the OS reported an error (Windows).
    Oversize,
    Error,
}

/// Both sockets and the fixed list of send destinations.
pub(crate) struct Sockets {
    send: UdpSocket,
    recv: UdpSocket,
    targets: Vec<SocketAddr>,
}

impl Sockets {
    /// Sends the datagram to every fixed destination; true if at least one send succeeded.
    pub(crate) fn send(&self, beacon: &[u8]) -> bool {
        let mut ok = false;
        for t in &self.targets {
            ok |= self.send.send_to(beacon, *t).is_ok();
        }
        ok
    }

    pub(crate) fn recv(&self, buf: &mut [u8], timeout: Duration) -> Recv {
        if self
            .recv
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .is_err()
        {
            return Recv::Error;
        }
        match self.recv.recv_from(buf) {
            Ok((n, src)) => Recv::Data(n, src),
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Recv::Timeout,
                _ if cfg!(windows) && e.raw_os_error() == Some(10040) => Recv::Oversize,
                _ => Recv::Error,
            },
        }
    }
}

fn new_udp() -> Result<Socket, NetError> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|_| NetError)
}

fn open_multicast(own_ip: Ipv4Addr, loopback: bool) -> Result<Sockets, NetError> {
    // receive socket: reuse, bind, join, buffer, timeout (D12 order)
    let rx = new_udp()?;
    rx.set_reuse_address(true).map_err(|_| NetError)?;
    // Unix: bound to the group, so unicast to the port is not delivered. Windows refuses a
    // multicast bind address and uses the wildcard.
    let bind_ip = if cfg!(windows) {
        Ipv4Addr::UNSPECIFIED
    } else {
        LAN_GROUP_V4
    };
    rx.bind(&SockAddr::from(SocketAddrV4::new(bind_ip, LAN_PORT)))
        .map_err(|_| NetError)?;
    rx.join_multicast_v4(&LAN_GROUP_V4, &own_ip)
        .map_err(|_| NetError)?;
    rx.set_recv_buffer_size(SOCKET_RECV_BUF)
        .map_err(|_| NetError)?;

    // send socket: own address, multicast interface, TTL 1, no loopback
    let tx = new_udp()?;
    tx.bind(&SockAddr::from(SocketAddrV4::new(own_ip, 0)))
        .map_err(|_| NetError)?;
    tx.set_multicast_if_v4(&own_ip).map_err(|_| NetError)?;
    tx.set_multicast_ttl_v4(1).map_err(|_| NetError)?;
    tx.set_multicast_loop_v4(false).map_err(|_| NetError)?;
    if loopback {
        // tests only: production always passes false
        tx.set_multicast_loop_v4(true).map_err(|_| NetError)?;
    }

    Ok(Sockets {
        send: UdpSocket::from(tx),
        recv: UdpSocket::from(rx),
        targets: vec![SocketAddr::V4(SocketAddrV4::new(LAN_GROUP_V4, LAN_PORT))],
    })
}

#[cfg(test)]
fn open_unicast(bind: SocketAddrV4, targets: &[SocketAddrV4]) -> Result<Sockets, NetError> {
    let rx = new_udp()?;
    rx.bind(&SockAddr::from(bind)).map_err(|_| NetError)?;
    let tx = new_udp()?;
    tx.bind(&SockAddr::from(SocketAddrV4::new(*bind.ip(), 0)))
        .map_err(|_| NetError)?;
    Ok(Sockets {
        send: UdpSocket::from(tx),
        recv: UdpSocket::from(rx),
        targets: targets.iter().map(|t| SocketAddr::V4(*t)).collect(),
    })
}
