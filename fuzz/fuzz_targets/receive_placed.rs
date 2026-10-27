#![no_main]
//! `.placed` journal (`crates/chervo-receive/src/journal.rs`): the append-only log of name
//! candidates tried for each index. Same entry point as `parse_placed`, through the stage 17
//! (B6) re-export `chervo_receive::parse_placed`. Property: no panic; a returned `k` is always
//! in `1..=999` (`MAX_K`), the function never claims more valid bytes than it was given.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (last, valid) = chervo_receive::parse_placed(data);
    assert!(valid <= data.len());
    for k in last.values() {
        assert!((1..=999).contains(k), "k out of range: {k}");
    }
});
