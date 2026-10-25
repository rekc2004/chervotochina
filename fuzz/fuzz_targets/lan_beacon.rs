#![no_main]
//! LAN discovery beacon from an unauthenticated multicast source (stage 13v). Same entry point
//! and property as `fuzz_smoke_beacon` (`crates/chervo-lan/src/tests/fuzz.rs`), through the
//! wrapper `chervo_lan::fuzz_beacon` (crate feature `fuzzing`, enabled in `fuzz/Cargo.toml`): any
//! datagram other than the one real beacon of the other side of this entry point's own secret
//! fixture pair must never produce a found item. A fuzzer-supplied input matching that
//! secret-derived 557-byte beacon (nonce, sealed port, tags) is not reachable in practice.
//!
//! The fixture uses two DISTINCT pair keys (an equal key is refused by `lan_keys` and would leave
//! the table empty), and `fuzz_lan_ready` runs a positive control (the real beacon of the other
//! side is found exactly once). The assertion below makes a vacuous run a crash, not a pass.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(
        chervo_lan::fuzz_lan_ready(),
        "LAN beacon fuzz fixture is not ready (no key pair or failed positive control)"
    );
    assert!(
        !chervo_lan::fuzz_beacon(data),
        "LAN beacon datagram produced a found item: {} bytes",
        data.len()
    );
});
