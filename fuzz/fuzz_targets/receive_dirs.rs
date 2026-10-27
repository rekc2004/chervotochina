#![no_main]
//! `.dirs` journal (`crates/chervo-receive/src/journal.rs`): bytes read back from the receive
//! folder. Same entry point as `read_dirs`'s pure body, through the stage 17 (B6) re-export
//! `chervo_receive::decode_dirs`. Key, digest and count are fixed (only the untrusted bytes
//! vary): the journal is never trusted to bind itself to the right transfer, so a mismatch
//! there is as uninteresting as any other rejection. Property: no panic on any input.

use chervo_identity::PairId;
use chervo_transfer::{TransferId, TransferKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = TransferKey {
        pair: PairId::from_bytes([0x11; 16]),
        id: TransferId([0x22; 16]),
    };
    let digest = [0x33u8; 32];
    for count in [0usize, 1, 3] {
        let _ = chervo_receive::decode_dirs(data, &key, &digest, count);
    }
});
