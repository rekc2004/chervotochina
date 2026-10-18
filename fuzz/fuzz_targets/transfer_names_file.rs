#![no_main]
//! `.names` state file (`crates/chervo-transfer/src/state.rs`): bytes read back from disk, not
//! the `UntrustedName` text itself (see `transfer_names.rs` for that). Same entry point as
//! `fuzz_smoke_names`, through the stage 17 (B6) re-export `chervo_transfer::decode_names`.
//! Property: no panic on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chervo_transfer::decode_names(data);
});
