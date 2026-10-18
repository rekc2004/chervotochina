#![no_main]
//! Signed address update, binary path. Same entry point and property as `fuzz_smoke_addr_update`:
//! an accepted binary has length 83..=235 and re-encodes into a text that `decode` accepts.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if chervo_token::decode_addr_update_bin(data).is_ok() {
        assert!((83..=235).contains(&data.len()));
        let text = chervo_token::encode_addr_update_bytes(data);
        assert!(chervo_token::decode(&text).is_ok());
    }
});
