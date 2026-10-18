#![no_main]
//! Receive-state file. Same entry points and property as `fuzz_smoke_state`:
//! an accepted state re-encodes into the same bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(state) = chervo_transfer::decode_state(data) {
        assert_eq!(
            chervo_transfer::encode_state(&state),
            data,
            "accepted state is not canonical"
        );
    }
});
