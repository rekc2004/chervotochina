#![no_main]
//! Minisign signature file parser and `verify_manifest` (stage 19a). Same entry point as
//! `crates/chervo-update/tests/fuzz_smoke.rs`. The key below is a TEST key (fixed seed, public
//! half only); nobody holds a signature for the manifest below that is not in the corpus.
//! Properties: no panic; for `Ok` the verified manifest equals the fixed manifest.

use chervo_update::{KeyRole, KeySet, Manifest, verify_manifest};
use libfuzzer_sys::fuzz_target;

const TEST_PUB: &[u8] = b"untrusted comment: minisign public key (test)\n\
RWQBAgMEBQYHCCFS+NGbeR0kRTJC4V8uq2y3z/p7al7TAJeWDgaYgdsS\n";

const MANIFEST: &[u8] = b"chervo-release-manifest 1\n\
version 1.2.3\n\
commit abababababababababababababababababababab\n\
artifact any 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 5 hello.txt\n";

fuzz_target!(|data: &[u8]| {
    let keys = KeySet::from_pubkey_files(&[(KeyRole::Primary, TEST_PUB)]).expect("test key");
    if let Ok(vm) = verify_manifest(&keys, MANIFEST, data) {
        assert_eq!(
            Some(vm.manifest().clone()),
            Manifest::parse(MANIFEST).ok()
        );
    }
});
