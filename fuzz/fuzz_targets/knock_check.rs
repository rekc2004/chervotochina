#![no_main]
//! Knock datagram from an unauthenticated UDP source. Same entry point and property as
//! `fuzz_smoke_knock_never_admits` (`crates/chervo-transport-quinn/src/tests/fuzz.rs`), through
//! the stage 17 (B6) wrapper `chervo_transport_quinn::fuzz_knock_admits`: any datagram other than
//! the one real knock this entry point's own fixture key makes for the current window must never
//! admit. A fuzzer-supplied input matching that secret-derived 48-byte knock bit-for-bit is not
//! reachable in practice.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(
        !chervo_transport_quinn::fuzz_knock_admits(data),
        "knock datagram admitted the source: {} bytes",
        data.len()
    );
});
