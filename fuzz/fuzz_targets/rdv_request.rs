#![no_main]
//! Echo server request parser (`chervo_rendezvous_wire::parse_request`, stage 13d). Input: the
//! datagram bytes. Same properties as `fuzz_smoke_request` in `crates/chervo-rendezvous-wire/tests`:
//! no panic; an accepted request is exactly 64 bytes and encodes back to the SAME bytes (one canonical
//! form); an echo or reach request is told apart only by the type byte.

use chervo_rendezvous_wire::{Request, encode_echo_request, encode_reach_request, parse_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = parse_request(data) {
        assert_eq!(data.len(), 64);
        let again = match req {
            Request::Echo(n) => encode_echo_request(&n),
            Request::Reach { nonce, target_port } => {
                assert_ne!(target_port, 0);
                encode_reach_request(&nonce, target_port)
            }
        };
        assert_eq!(&again[..], data, "accepted request is not canonical");
    }
});
