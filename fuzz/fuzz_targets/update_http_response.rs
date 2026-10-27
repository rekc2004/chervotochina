#![no_main]
//! HTTP response and `Location` parser of the update notice (stage 19d). Same entry point as
//! `fuzz_smoke_update_http` (`crates/chervo-update-check/src/tests/fuzz_smoke.rs`), through the
//! `fuzzing` feature wrapper `chervo_update_check::fuzz_http_response`. Properties: no panic; the body is
//! never longer than the limit; `Location` host comes from the embedded list; no more than
//! `MAX_HEADER_BYTES + 4 + limit + 1` bytes are read.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_update_check::fuzz_http_response(data);
});
