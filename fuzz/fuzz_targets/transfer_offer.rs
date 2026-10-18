#![no_main]
//! Offer assembly (OFFER_HEAD + OFFER_FILES chunks). Same entry points as `fuzz_smoke_offer_assembly`.
//! Input: 16 header bytes (file_count u32, total_size u64, offer_bytes u32, big-endian), then entries
//! `size u64 | name_len u8 | name`. Property: no panic; an accepted offer agrees with its header exactly.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let file_count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let total_size = u64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);
    let offer_bytes = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let Ok(mut asm) = chervo_transfer::OfferAssembler::new(file_count, total_size, offer_bytes)
    else {
        return;
    };
    let mut rest = &data[16..];
    let mut failed = false;
    while rest.len() >= 9 {
        let size = u64::from_be_bytes([
            rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
        ]);
        let len = usize::from(rest[8]);
        let end = (9 + len).min(rest.len());
        let name = String::from_utf8_lossy(&rest[9..end]).into_owned();
        rest = &rest[end..];
        let Ok(name) = chervo_transfer::UntrustedName::new(&name) else {
            continue;
        };
        let entry = chervo_transfer::OfferedFile { name, size };
        if asm.push(vec![entry]).is_err() {
            failed = true;
            break;
        }
    }
    let result = asm.finish();
    if failed {
        assert!(result.is_err(), "finish accepted after a push error");
    } else if let Ok(files) = result {
        assert_eq!(files.len() as u32, file_count);
        assert_eq!(
            files.iter().map(|f| 10 + f.name.len() as u64).sum::<u64>(),
            u64::from(offer_bytes)
        );
        assert_eq!(files.iter().map(|f| f.size).sum::<u64>(), total_size);
    }
});
