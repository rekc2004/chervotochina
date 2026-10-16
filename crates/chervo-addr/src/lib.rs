//! Адреса: классификация, собственные адреса и набор для публикации (этап 12, часть A1).
//! Спецификация: `docs/specs/stage-12-addr.md`.
//!
//! Часов, фоновых задач и отправки данных в крейте нет: время передаёт вызывающий
//! (`now_unix`, секунды UTC с поправкой). Сокетный код только в `probe`.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod class;
mod own;
mod probe;

use std::net::SocketAddr;

pub use class::{AddrClass, classify, is_eui64, normalize, update_allowed};
pub use own::{
    GatewayInfo, LocalSnapshot, MAX_OBSERVATIONS, MAX_UPDATE_ADDRS, NatView, OBSERVED_TTL_SECS,
    ObserveOutcome, ObserveReject, OwnAddrs, PublishCtx, PublishSet, UpdateAddr,
};
pub use probe::{PROBE_V4, PROBE_V6, RouteSources, probe_route_sources};

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
