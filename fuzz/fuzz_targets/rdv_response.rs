#![no_main]
//! Echo server response parser (`chervo_rendezvous_wire::parse_response`, stage 13d). Input: the
//! datagram bytes. The expected nonce is taken from the datagram itself (bytes 8..24) so that the
//! nonce check can pass and the later fields are reached; a second call with a flipped nonce must be
//! refused. Properties (as `fuzz_smoke_response`): no panic; an accepted response is 48 bytes, has a
//! non-zero port and encodes back to the SAME bytes.

use chervo_rendezvous_wire::{
    Nonce, WireError, encode_echo_response, encode_reach_response, parse_response,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut n = [0u8; 16];
    if let Some(s) = data.get(8..24) {
        n.copy_from_slice(s);
    }
    let nonce = Nonce(n);
    if let Ok(r) = parse_response(data, &nonce) {
        assert_eq!(data.len(), 48);
        assert_ne!(r.observed.port(), 0);
        let again = if r.reach {
            encode_reach_response(&nonce, r.observed)
        } else {
            encode_echo_response(&nonce, r.observed, r.reach_port)
        };
        assert_eq!(&again[..], data, "accepted response is not canonical");
        let mut other = n;
        other[0] ^= 0x80;
        assert_eq!(
            parse_response(data, &Nonce(other)),
            Err(WireError::Nonce),
            "response accepted with a different nonce"
        );
    }
});
