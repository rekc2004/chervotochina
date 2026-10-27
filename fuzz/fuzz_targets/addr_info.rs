#![no_main]
//! ADDR_INFO frame. Same entry point and properties as `fuzz_smoke_addr_info`:
//! an accepted frame has length 11..=258 and a non-zero observed port.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((observed, _update)) = chervo_token::addr_flow::decode_addr_info(data) {
        assert!((11..=258).contains(&data.len()));
        assert_ne!(observed.port(), 0);
    }
});
