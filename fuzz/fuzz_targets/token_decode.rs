#![no_main]
//! Token text decoder (invite CHV1, revocation CHR1, address update CHA1) and the invite decision
//! message. Same entry points as `crates/chervo-token/tests/fuzz_smoke.rs` (decode, decode_decision).
//! Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = chervo_token::decode(&text);
    let _ = chervo_token::decode_decision(data);
});
