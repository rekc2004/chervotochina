#![no_main]
//! `LOCATION` URL and port text from SSDP/description. Same entry point as `fuzz_smoke_ssdp`'s
//! URL checks (`crates/chervo-upnp/src/tests/fuzz.rs`), through the stage 17 (B6) wrapper
//! `chervo_upnp::fuzz_url`. Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_upnp::fuzz_url(data);
});
