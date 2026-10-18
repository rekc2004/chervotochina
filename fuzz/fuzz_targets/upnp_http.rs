#![no_main]
//! HTTP response framing for UPnP SOAP replies. Same entry point as `fuzz_smoke_http`
//! (`crates/chervo-upnp/src/tests/fuzz.rs`), through the stage 17 (B6) wrapper
//! `chervo_upnp::fuzz_http`. Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_upnp::fuzz_http(data);
});
