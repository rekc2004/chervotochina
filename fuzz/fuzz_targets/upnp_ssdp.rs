#![no_main]
//! SSDP discovery reply from the LAN. Same entry point as `fuzz_smoke_ssdp`
//! (`crates/chervo-upnp/src/tests/fuzz.rs`), through the stage 17 (B6) wrapper
//! `chervo_upnp::fuzz_ssdp`. Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_upnp::fuzz_ssdp(data);
});
