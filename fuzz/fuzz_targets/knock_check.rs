#![no_main]
//! Knock datagram from an unauthenticated UDP source. Same entry point and property as
//! `fuzz_smoke_knock_never_admits` (`crates/chervo-transport-quinn/src/tests/fuzz.rs`), through
//! the stage 17 (B6) wrapper `chervo_transport_quinn::fuzz_knock_admits` (crate feature `fuzzing`,
//! enabled in `fuzz/Cargo.toml`): any datagram other than the one real knock the other side of this
//! entry point's own fixture pair makes for the current window must never admit. A fuzzer-supplied
//! input matching that secret-derived 48-byte knock bit-for-bit is not reachable in practice.
//!
//! S1 M3: the fixture uses two DISTINCT pair keys (an equal key is refused by `knock_keys` and left the
//! table empty), and `fuzz_knock_ready` runs a positive control (a real knock of the other side admits,
//! the table holds exactly one key). The assertion below makes a vacuous run a crash, not a pass.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(
        chervo_transport_quinn::fuzz_knock_ready(),
        "knock fuzz fixture is not ready (empty key table or failed positive control)"
    );
    assert!(
        !chervo_transport_quinn::fuzz_knock_admits(data),
        "knock datagram admitted the source: {} bytes",
        data.len()
    );
});
