#![no_main]
//! IGD device description XML from the LAN. Same entry point as `fuzz_smoke_desc`
//! (`crates/chervo-upnp/src/tests/fuzz.rs`), reached through the stage 17 (B6) `#[doc(hidden)]`
//! wrapper `chervo_upnp::fuzz_desc`. Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_upnp::fuzz_desc(data);
});
