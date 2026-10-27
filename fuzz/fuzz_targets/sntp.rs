#![no_main]
//! SNTP reply parser (`chervo_timesync::parse_response`). Input: the reply bytes. The expected
//! originate timestamp is taken from the reply itself (bytes 24..32) so that the check can pass and
//! the later fields are reached; t1/t4 come from bytes 8..16 and 16..24 when present. Second call with
//! a flipped origin must be refused. Property: no panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let word = |at: usize| -> u64 {
        data.get(at..at + 8)
            .map(|s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
            .unwrap_or(0)
    };
    let mut origin = [0u8; 8];
    if let Some(s) = data.get(24..32) {
        origin.copy_from_slice(s);
    }
    let _ = chervo_timesync::parse_response(data, origin, word(8), word(16));
    let mut other = origin;
    other[0] ^= 0x80;
    if chervo_timesync::parse_response(data, other, word(8), word(16)).is_ok() {
        panic!("reply accepted with a different origin");
    }
});
