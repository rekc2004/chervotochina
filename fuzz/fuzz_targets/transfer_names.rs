#![no_main]
//! Untrusted file names from the wire. `decode_names` (the `names` state file) is crate-private, so only
//! the public constructor is reachable from here; see fuzz/README.md. Property: no panic, an accepted
//! name is non-empty, has no NUL and fits MAX_NAME_BYTES.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if chervo_transfer::UntrustedName::new(&text).is_ok() {
        assert!(!text.is_empty());
        assert!(!text.contains('\0'));
        assert!(text.len() <= chervo_transfer::MAX_NAME_BYTES);
    }
});
