//! Редакция вывода внутренних типов состояния (этап 17, B3, решение 1c): `RecvState` и
//! `NamesFile` не печатают ни имён, ни `PairId`, ни идентификатора передачи, ни суммы. Здесь
//! нельзя печатать (охрана `src_guard` проверяет только `src/` без `src/tests`, но правило то
//! же): только сравнения.

use chervo_identity::PairId;

use crate::state::{RecvState, decode_names, encode_names};
use crate::{TransferId, UntrustedName};

#[test]
fn recv_state_and_names_file_debug_hide_everything() {
    let pair = PairId::from_bytes([0xC3; 16]);
    let id = TransferId([0x5E; 16]);
    let state = RecvState {
        pair,
        id,
        created_unix: 1_700_000_000,
        last_progress_unix: 1_700_000_999,
        total_size: 123_456_789,
        names_sum: [0x77; 32],
        files: Vec::new(),
    };
    let names = [
        UntrustedName::new("STATEMARK-one.txt").unwrap(),
        UntrustedName::new("STATEMARKDIR/STATEMARK-two.bin").unwrap(),
    ];
    let (bytes, _sum) = encode_names(&pair, &id, &names);
    let file = decode_names(&bytes).unwrap();

    for text in [
        format!("{state:?}"),
        format!("{state:#?}"),
        format!("{file:?}"),
        format!("{file:#?}"),
    ] {
        assert!(!text.contains("STATEMARK"), "{text}");
        assert!(
            !text.contains("1700000000") && !text.contains("123456789"),
            "{text}"
        );
        // байты PairId и идентификатора передачи в десятичной и hex-записи
        assert!(!text.contains("195, 195"), "{text}");
        assert!(!text.contains("94, 94"), "{text}");
        assert!(!text.to_lowercase().contains("c3c3c3"), "{text}");
        assert!(!text.to_lowercase().contains("5e5e5e"), "{text}");
        assert!(!text.contains("119, 119"), "{text}");
        assert!(text.ends_with("(..)"), "{text}");
    }
}
