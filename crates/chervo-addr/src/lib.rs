//! Книга адресов: типы записей. Логики пока нет.

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSource {
    Interface,
    Lan,
    PortMapping,
    Invite,
    AddressUpdate,
    ObservedByFriend,
}

/// Без Debug: адреса не печатаются через derive.
#[derive(Clone, PartialEq, Eq)]
pub struct KnownAddr {
    pub addr: SocketAddr,
    pub source: AddrSource,
    pub last_seen_unix: u64,
    pub short_lived: bool,
}
