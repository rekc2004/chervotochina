//! LAN discovery (stage 13v, spec `docs/specs/stage-13v-lan.md`).
//!
//! Friends in one home network find each other's current private address without a token and
//! without a third party. Every minute a fixed-size beacon (557 bytes) goes to a link-local
//! multicast group. It carries no key, no name, no stable identifier and no port in clear:
//! 16 slots, each `id || sealed port || tag`, real slots for friends we currently miss and
//! random fillers for the rest. A friend recognises its slot by the pair key, learns our
//! address, and only then the usual knock + QUIC + Noise KK path decides about trust.
//!
//! Layout: `limits` (constants), `wire` (format, pure), `core` (`LanCore`, pure state
//! machine), `net` (the only socket code), `link` (`LanDiscovery`, thread).
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod core;
#[cfg(any(test, feature = "fuzzing"))]
mod fuzz_entry;
mod limits;
mod link;
mod net;
mod wire;

#[cfg(test)]
mod tests;

pub use chervo_addr::{LanFound, LanLink, LanPeer, LanStatus};

pub use crate::core::{CoreConfig, LanCore, LanStats, lan_epoch};
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub use crate::fuzz_entry::{fuzz_beacon, fuzz_lan_ready};
pub use crate::limits::{BEACON_LEN, LAN_EPOCH_SECS, LAN_GROUP_V4, LAN_PORT, LAN_SLOTS};
pub use crate::link::LanDiscovery;
