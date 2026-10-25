//! Limits and constants of LAN discovery (stage 13v, spec sections 1, 3, 7). All values are
//! fixed by the specification. The group and the port come from S0 (IANA registries checked
//! 2026-10-25).

use std::net::Ipv4Addr;
use std::time::Duration;

/// Multicast group (RFC 2365 IPv4 Local Scope, 239.255.0.0/16; no IANA assignment).
pub const LAN_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 112, 47);
/// UDP port (IANA 47101-47556 range, unassigned).
pub const LAN_PORT: u16 = 47131;

/// Beacon length: version 1 + nonce 12 + 16 slots of 34.
pub const BEACON_LEN: usize = 557;
/// Slots in every beacon.
pub const LAN_SLOTS: usize = 16;
/// Epoch length in seconds.
pub const LAN_EPOCH_SECS: u64 = 60;
/// Wire format version.
pub(crate) const BEACON_VERSION: u8 = 1;

/// Global budget: bucket size and refill period (50 per second).
pub(crate) const GLOBAL_BURST: u32 = 100;
pub(crate) const GLOBAL_PERIOD: Duration = Duration::from_millis(20);
/// Per-source budget: bucket size and refill period (one token per 6 s, 10 per minute).
pub(crate) const SOURCE_BURST: u32 = 10;
pub(crate) const SOURCE_PERIOD: Duration = Duration::from_secs(6);
/// Entries of the per-source table (the least recently used is evicted).
pub(crate) const SOURCE_MAP_MAX: usize = 256;
/// AEAD opens per datagram.
pub(crate) const MAX_OPENS: u32 = 2;
/// The same (pair, address) is reported at most once in this time.
pub(crate) const FOUND_REPEAT: Duration = Duration::from_secs(10);
/// Entries of the found throttle table.
pub(crate) const FOUND_MAP_MAX: usize = 256;

/// Mean beacon interval and the jitter around it (uniform, plus and minus).
pub(crate) const BEACON_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const BEACON_JITTER_MS: u32 = 10_000;
/// Burst offsets after attach, a new local endpoint, a user action.
pub(crate) const BURST_OFFSETS: [Duration; 3] = [
    Duration::from_secs(0),
    Duration::from_secs(1),
    Duration::from_secs(3),
];
/// At most this many beacons in any rolling window.
pub(crate) const SEND_CAP: usize = 8;
pub(crate) const SEND_CAP_WINDOW: Duration = Duration::from_secs(60);

/// Driver: longest wait, minimal wait, pause when the global budget is empty, retry after a
/// failed socket open, receive buffer.
pub(crate) const MAX_WAIT: Duration = Duration::from_millis(200);
pub(crate) const MIN_WAIT: Duration = Duration::from_millis(5);
pub(crate) const BUDGET_PAUSE: Duration = Duration::from_millis(100);
pub(crate) const REOPEN_AFTER: Duration = Duration::from_secs(30);
pub(crate) const SOCKET_RECV_BUF: usize = 64 * 1024;
/// Bounded wait for the thread on shutdown.
pub(crate) const JOIN_WAIT: Duration = Duration::from_secs(1);
