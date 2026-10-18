#![no_main]
//! Transfer message body codec. Same entry point and property as `fuzz_smoke_codec`:
//! an accepted body re-encodes into exactly `len(u32 BE) || body`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = chervo_transfer::decode_message(data) {
        let mut again = Vec::new();
        chervo_transfer::encode(&msg, &mut again).expect("accepted message must encode");
        let mut want = (data.len() as u32).to_be_bytes().to_vec();
        want.extend_from_slice(data);
        assert_eq!(again, want, "accepted body is not canonical");
    }
});
