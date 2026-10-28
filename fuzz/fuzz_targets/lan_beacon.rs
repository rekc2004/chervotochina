#![no_main]
//! LAN beacon datagram (stage 13v). Same entry point as `fuzz_smoke_beacon`
//! (`crates/chervo-lan/src/tests/fuzz.rs`), through the doc(hidden) wrappers
//! `chervo_lan::fuzz_beacon_ports` / `fuzz_valid_beacon` (feature `fuzzing`): the parser against a
//! table of three test pairs with FIXED keys, so the corpus file `valid-3-pairs` (a real datagram)
//! reaches `open`. Properties: no panic on any input; every slot that opens carries exactly the
//! port that was sealed (a mutated byte never yields another port); at most three sightings.
//! Like `knock_check`, a vacuous run is a crash: the first call asserts that the valid datagram
//! opens all three slots.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    static READY: std::sync::Once = std::sync::Once::new();
    READY.call_once(|| {
        let ports = chervo_lan::fuzz_beacon_ports(&chervo_lan::fuzz_valid_beacon());
        assert_eq!(ports, vec![chervo_lan::FUZZ_PORT; chervo_lan::FUZZ_PAIRS]);
    });
    let ports = chervo_lan::fuzz_beacon_ports(data);
    assert!(ports.len() <= chervo_lan::FUZZ_PAIRS);
    assert!(ports.iter().all(|p| *p == chervo_lan::FUZZ_PORT));
});
