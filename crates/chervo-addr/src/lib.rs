//! Адреса: классификация, собственные адреса и набор для публикации (этап 12, части A1 и A4).
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

mod book;
mod class;
mod mapper;
mod own;
mod probe;

use std::net::SocketAddr;

pub use book::{
    CONTACT_REFRESH_SECS, CONTACT_TTL_SECS, Findability, HINT_TTL_SECS, MAX_CONTACT_ADDRS,
    NEED_TOKEN_TEXT, NO_PUBLIC_ADDR_TEXT, PRIVATE_TTL_SECS, SHORT_LIVED_TTL_SECS, findability,
    from_invite, merge_update, note_contact, prune, usable, usable_entries,
};
pub use class::{AddrClass, classify, is_eui64, normalize, update_allowed};
pub use mapper::{MapReport, MapRequest, MapStatus, PortMapper};
pub use own::{
    GatewayInfo, LocalSnapshot, MAX_OBSERVATIONS, MAX_REPORTERS_UP, MAX_UPDATE_ADDRS, NatView,
    OBSERVED_TTL_SECS, ObserveOutcome, ObserveReject, OwnAddrs, PublishCtx, PublishSet, UpdateAddr,
};
pub use probe::{PROBE_V4, PROBE_V6, RouteSources, probe_route_sources, route_source_for};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSource {
    Interface,
    Lan,
    PortMapping,
    Invite,
    AddressUpdate,
    ObservedByFriend,
    /// Адрес, с которого друг подключился по проверенному соединению.
    Contact,
}

/// Без Debug: адреса не печатаются через derive.
#[derive(Clone, PartialEq, Eq)]
pub struct KnownAddr {
    pub addr: SocketAddr,
    pub source: AddrSource,
    pub last_seen_unix: u64,
    pub short_lived: bool,
    /// Отправитель пометил адрес как «так меня видят» (непроверенная подсказка).
    pub hint: bool,
}
