#![no_main]
//! LAN beacon datagram (stage 13v). Same entry point as `fuzz_smoke_beacon`
//! (`crates/chervo-lan/src/tests/fuzz.rs`), through the doc(hidden) wrapper
//! `chervo_lan::fuzz_beacon` (feature `fuzzing`): the parser against a table of three test pairs.
//! Property: no panic on any input. The pair keys are random per process, so a random input never
//! opens a slot; the target covers length, header, source and slot-table paths.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chervo_lan::fuzz_beacon(data);
});
