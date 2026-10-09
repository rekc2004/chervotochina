//! Установка прямого соединения: типы путей и заглушка. Relay-варианта нет и не будет.

use std::fmt;
use std::future::Future;

use chervo_transport::{PeerAddr, Transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Lan,
    Ipv6,
    PortMapped,
    SimultaneousOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoDirectPath {
    BothBehindCgnat,
    SymmetricNat,
    UdpBlocked,
    NoIpv6,
    NoKnownAddress,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    NoDirectPath(NoDirectPath),
    NotImplemented,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDirectPath(reason) => write!(f, "no direct path: {reason:?}"),
            Self::NotImplemented => f.write_str("not implemented"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Заглушка: всегда `NotImplemented`.
pub fn connect_direct<T: Transport>(
    _transport: &T,
    _peer: &PeerAddr,
) -> impl Future<Output = Result<(T::Conn, PathKind), ConnectError>> + Send {
    std::future::ready(Err(ConnectError::NotImplemented))
}
