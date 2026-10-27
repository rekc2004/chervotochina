#![no_main]
//! Node settings file parser (`chervo_core::fuzz_settings`, stage 18a, `node/settings.rs`).
//! Input: the file bytes. Properties: no panic; a file the parser accepts is written back and read
//! again into the same settings, and a second write gives the same text (parse after write and
//! write after parse are idempotent). The entry point asserts both itself, so a violation is a crash.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chervo_core::fuzz_settings(data);
});
