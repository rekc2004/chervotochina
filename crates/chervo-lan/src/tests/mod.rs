#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Tests of the pure core, the unicast loopback sockets, the guards and the fuzz smoke.

mod core;
mod fuzz;
mod net;
mod src_guard;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use chervo_identity::{LAN_ID_LEN, LAN_NONCE_LEN, LAN_SLOT_LEN, LanKeys, PairId};

use crate::core::{CoreConfig, LanCore, lan_epoch};
use crate::fuzz_entry::{FIX_UNIX, PairFixture, RECV_LOCAL, SEND_LOCAL};
use crate::limits::BEACON_LEN;

pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub fn pair() -> PairFixture {
    PairFixture::new().unwrap()
}

/// A sending core of side `b` with the given endpoint, wanting `wanted`.
pub fn sender(fx: &PairFixture, local: SocketAddrV4, wanted: Vec<PairId>) -> LanCore {
    let mut c = LanCore::new(CoreConfig::default());
    c.set_local(Some(local), Duration::ZERO);
    c.set_peers(vec![fx.peer_b().unwrap()]);
    c.set_wanted(wanted);
    c
}

/// Like `sender`, but accepting loopback (for sockets on 127.0.0.1).
pub fn sender_lo(fx: &PairFixture, local: SocketAddrV4, wanted: Vec<PairId>) -> LanCore {
    let mut c = LanCore::new(CoreConfig {
        allow_loopback: true,
    });
    c.set_local(Some(local), Duration::ZERO);
    c.set_peers(vec![fx.peer_b().unwrap()]);
    c.set_wanted(wanted);
    c
}

/// A sending core with several pairs at once.
pub fn multi_sender(fxs: &[PairFixture], wanted: Vec<PairId>) -> LanCore {
    let mut c = LanCore::new(CoreConfig::default());
    c.set_local(Some(SEND_LOCAL), Duration::ZERO);
    c.set_peers(fxs.iter().map(|f| f.peer_b().unwrap()).collect());
    c.set_wanted(wanted);
    c
}

/// Forces one beacon now (trigger, then poll).
pub fn force_beacon(core: &mut LanCore, now: Duration, unix: u64) -> [u8; BEACON_LEN] {
    core.trigger(now);
    core.poll_send(now, unix).expect("a beacon was due")
}

/// A fresh sender's beacon at `unix` for the fixture pair, from `local`.
pub fn beacon_from(fx: &PairFixture, local: SocketAddrV4, unix: u64) -> [u8; BEACON_LEN] {
    let mut c = sender(fx, local, vec![fx.pair]);
    c.poll_send(Duration::ZERO, unix).unwrap()
}

pub fn slots(b: &[u8]) -> Vec<&[u8]> {
    b[1 + LAN_NONCE_LEN..]
        .as_chunks::<LAN_SLOT_LEN>()
        .0
        .iter()
        .map(|c| c.as_slice())
        .collect()
}

pub fn ids(b: &[u8]) -> Vec<[u8; LAN_ID_LEN]> {
    slots(b)
        .into_iter()
        .map(|s| s[..LAN_ID_LEN].try_into().unwrap())
        .collect()
}

pub fn nonce_of(b: &[u8]) -> [u8; LAN_NONCE_LEN] {
    b[1..1 + LAN_NONCE_LEN].try_into().unwrap()
}

/// Ports of all slots of `b` that open with `keys` (sealed for source `src`).
pub fn opened(keys: &LanKeys, b: &[u8], unix: u64, src: Ipv4Addr) -> Vec<u16> {
    let e = lan_epoch(unix);
    let n = nonce_of(b);
    slots(b)
        .into_iter()
        .filter_map(|s| keys.open_slot(e, &n, std::net::IpAddr::V4(src), s))
        .collect()
}

pub fn src(a: SocketAddrV4) -> SocketAddr {
    SocketAddr::V4(a)
}

pub fn recv_core(fx: &PairFixture) -> LanCore {
    fx.receiver().unwrap()
}

pub const UNIX: u64 = FIX_UNIX;
pub const RECV: SocketAddrV4 = RECV_LOCAL;
pub const SEND: SocketAddrV4 = SEND_LOCAL;
