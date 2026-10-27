#![no_main]
//! Minisign public key file parser (stage 19a). Same entry point as
//! `crates/chervo-update/tests/fuzz_smoke.rs`. Properties: no panic; for `Ok` the minisign key
//! string produced from the parsed key is contained in the input.

use chervo_update::{KeyRole, KeySet, pubkey_line};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(keys) = KeySet::from_pubkey_files(&[(KeyRole::Primary, data)]) {
        let list = keys.list();
        assert_eq!(list.len(), 1);
        let line = pubkey_line(list[0].1, &list[0].2);
        let text = String::from_utf8_lossy(data);
        assert!(text.contains(&line));
    }
});
