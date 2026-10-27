#![no_main]
//! Release manifest parser (stage 19a). Same entry point as
//! `crates/chervo-update/tests/fuzz_smoke.rs`. Properties: no panic; for `Ok` the canonical
//! form equals the input byte for byte.

use chervo_update::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Manifest::parse(data) {
        assert_eq!(m.to_canonical_bytes(), data);
    }
});
