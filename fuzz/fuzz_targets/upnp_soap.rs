#![no_main]
//! SOAP response/fault bodies from a router. Same entry point as `fuzz_smoke_soap`
//! (`crates/chervo-upnp/src/tests/fuzz.rs`), through the stage 17 (B6) wrapper
//! `chervo_upnp::fuzz_soap`. Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_upnp::fuzz_soap(data);
});
