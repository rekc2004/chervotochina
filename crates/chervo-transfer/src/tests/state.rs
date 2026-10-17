use chervo_identity::PairId;

use crate::hash::sha256;
use crate::state::{FileStatus, Progress, RecvState, StateFile};
use crate::{
    BlockHash, FileRoot, Layout, MAX_STATE_LEN, StateError, TransferId, UntrustedName,
    decode_state, encode_hashes, encode_state, file_root, layout, leaf_hash, parse_hashes,
    state_dir_name,
};

const MIB: u64 = 1 << 20;

fn file(name: &str, size: u64, status: FileStatus) -> StateFile {
    StateFile {
        name: UntrustedName::new(name).unwrap(),
        size,
        status,
    }
}

fn progress(size: u64, bitmap: Vec<u8>) -> FileStatus {
    FileStatus::InProgress(Progress {
        layout: layout(size).unwrap(),
        root: FileRoot([5; 32]),
        bitmap,
    })
}

/// Состояние с файлами во всех статусах; сумма размеров согласована с `total_size`.
fn sample() -> RecvState {
    let sizes = [3 * MIB + 1, 10, 0, 7, 2 * MIB];
    RecvState {
        pair: PairId::from_bytes([1; 16]),
        id: TransferId([2; 16]),
        created_unix: 1_700_000_000,
        last_progress_unix: 1_700_000_500,
        total_size: sizes.iter().sum(),
        files: vec![
            file(
                "a/in progress.bin",
                sizes[0],
                progress(sizes[0], vec![0b0000_0101]),
            ),
            file("waiting", sizes[1], FileStatus::Waiting),
            file("empty", sizes[2], progress(sizes[2], vec![])),
            file(
                "verified",
                sizes[3],
                FileStatus::Verified(FileRoot([6; 32])),
            ),
            file("placed", sizes[4], FileStatus::Placed(FileRoot([7; 32]))),
        ],
    }
}

/// Пересчёт контрольной суммы после правки тела: чтобы проверка дошла до разбора полей.
fn reseal(mut b: Vec<u8>) -> Vec<u8> {
    let n = b.len() - 32;
    b.truncate(n);
    let sum = sha256(&[&b]);
    b.extend_from_slice(&sum);
    b
}

#[test]
fn state_roundtrip() {
    let s = sample();
    let b = encode_state(&s);
    let back = decode_state(&b).unwrap();
    assert!(back == s);
    assert_eq!(encode_state(&back), b);
    // Состояние с Failed.
    let mut s2 = sample();
    s2.files[1].status = FileStatus::Failed;
    assert!(decode_state(&encode_state(&s2)).unwrap() == s2);
    assert_eq!(format!("{s:?}"), "RecvState(..)");
}

#[test]
fn state_checksum_mismatch_rejected() {
    let b = encode_state(&sample());
    // Любой перевёрнутый бит в любом байте.
    for i in 0..b.len() {
        let mut x = b.clone();
        x[i] ^= 0x01;
        assert!(decode_state(&x).is_err(), "byte {i}");
    }
    let mut x = b.clone();
    x[20] ^= 0x80;
    assert_eq!(decode_state(&x).err(), Some(StateError::BadChecksum));
    // Верная сумма при чужой магии: отдельная ошибка.
    let mut x = b.clone();
    x[0] ^= 1;
    assert_eq!(decode_state(&reseal(x)).err(), Some(StateError::BadMagic));
}

#[test]
fn state_truncated_rejected() {
    let b = encode_state(&sample());
    for n in 0..b.len() {
        assert!(decode_state(&b[..n]).is_err(), "prefix {n}");
    }
    // Лишний байт в конце.
    let mut x = b.clone();
    x.push(0);
    assert!(decode_state(&x).is_err());
    // Усечённое тело с пересчитанной суммой: Malformed, не паника.
    let mut x = b[..b.len() - 32 - 3].to_vec();
    let sum = sha256(&[&x]);
    x.extend_from_slice(&sum);
    assert_eq!(decode_state(&x).err(), Some(StateError::Malformed));
    // Лишние байты перед суммой.
    let mut x = b[..b.len() - 32].to_vec();
    x.push(9);
    let sum = sha256(&[&x]);
    x.extend_from_slice(&sum);
    assert_eq!(decode_state(&x).err(), Some(StateError::Malformed));
}

#[test]
fn state_len_cap() {
    let big = vec![0u8; MAX_STATE_LEN as usize + 1];
    assert_eq!(decode_state(&big).err(), Some(StateError::TooLong));
    // Ровно предел проходит проверку длины и падает уже на сумме.
    let edge = vec![0u8; MAX_STATE_LEN as usize];
    assert_eq!(decode_state(&edge).err(), Some(StateError::BadChecksum));
    assert_eq!(decode_state(&[]).err(), Some(StateError::Truncated));
}

#[test]
fn state_bitmap_high_bits_rejected() {
    // 3 блока: допустимы биты 0..=2, бит 3 и выше запрещены.
    let size = 2 * MIB + 1;
    let mut s = sample();
    s.total_size = s.total_size - s.files[0].size + size;
    s.files[0].size = size;
    s.files[0].status = progress(size, vec![0b0000_0111]);
    assert!(decode_state(&encode_state(&s)).is_ok());
    for bad in [0b0000_1000u8, 0b1000_0000, 0b1111_1111] {
        s.files[0].status = progress(size, vec![bad]);
        assert_eq!(
            decode_state(&encode_state(&s)).err(),
            Some(StateError::Malformed),
            "{bad:#b}"
        );
    }
    // Карта неверной длины.
    s.files[0].status = progress(size, vec![1, 0]);
    assert_eq!(
        decode_state(&encode_state(&s)).err(),
        Some(StateError::Malformed)
    );
    // Блоков кратно 8: все биты байта допустимы.
    let size = 8 * MIB;
    let mut s = sample();
    s.total_size = s.total_size - s.files[0].size + size;
    s.files[0].size = size;
    s.files[0].status = progress(size, vec![0xFF]);
    assert!(decode_state(&encode_state(&s)).is_ok());
}

#[test]
fn state_inprogress_cap() {
    let make = |n: usize| {
        let files: Vec<_> = (0..n)
            .map(|i| file(&format!("f{i}"), 1, progress(1, vec![0])))
            .collect();
        RecvState {
            pair: PairId::from_bytes([1; 16]),
            id: TransferId([2; 16]),
            created_unix: 1,
            last_progress_unix: 2,
            total_size: n as u64,
            files,
        }
    };
    assert!(decode_state(&encode_state(&make(8))).is_ok());
    assert_eq!(
        decode_state(&encode_state(&make(9))).err(),
        Some(StateError::Malformed)
    );
    // Без InProgress файлов может быть сколько угодно (до границ предложения).
    let mut many = make(100);
    for f in &mut many.files {
        f.status = FileStatus::Waiting;
    }
    assert!(decode_state(&encode_state(&many)).is_ok());
}

#[test]
fn state_nothing_trusted() {
    let base = sample();
    let bad = |mutate: &dyn Fn(&mut RecvState)| {
        let mut s = base.clone();
        mutate(&mut s);
        decode_state(&encode_state(&s)).err()
    };
    // Раскладка в файле обязана совпасть с пересчитанной по размеру.
    assert_eq!(
        bad(&|s| {
            s.files[0].status = FileStatus::InProgress(Progress {
                layout: Layout {
                    block_size: 1 << 21,
                    block_count: 2,
                },
                root: FileRoot([5; 32]),
                bitmap: vec![0],
            })
        }),
        Some(StateError::Malformed)
    );
    // Сумма размеров, число файлов, размер файла сверх предела.
    assert_eq!(bad(&|s| s.total_size += 1), Some(StateError::Malformed));
    assert_eq!(bad(&|s| s.files.clear()), Some(StateError::Malformed));
    assert_eq!(
        bad(&|s| {
            s.files[1].size = (1 << 40) + 1;
            s.total_size = s.files.iter().map(|f| f.size).sum();
        }),
        Some(StateError::Malformed)
    );
    assert_eq!(
        bad(&|s| s.total_size = (1 << 44) + 1),
        Some(StateError::Malformed)
    );
    // Неизвестный статус и NUL в имени (правка байтов с пересчётом суммы).
    let b = encode_state(&base);
    let pos = b
        .windows(7)
        .position(|w| w == b"waiting")
        .expect("имя в файле");
    let mut x = b.clone();
    x[pos + 7] = 9;
    assert_eq!(decode_state(&reseal(x)).err(), Some(StateError::Malformed));
    let mut x = b.clone();
    x[pos] = 0;
    assert_eq!(decode_state(&reseal(x)).err(), Some(StateError::Malformed));
}

#[test]
fn state_dir_name_is_32_hex() {
    let p = PairId::from_bytes([1; 16]);
    let a = state_dir_name(&p, &TransferId([2; 16]));
    assert_eq!(a.len(), 32);
    assert!(
        a.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    );
    assert_ne!(a, state_dir_name(&p, &TransferId([3; 16])));
    assert_ne!(
        a,
        state_dir_name(&PairId::from_bytes([9; 16]), &TransferId([2; 16]))
    );
    assert_eq!(a, state_dir_name(&p, &TransferId([2; 16])));
}

#[test]
fn hashes_file_mismatch_clears_progress() {
    let size = 3 * MIB + 1;
    let l = layout(size).unwrap();
    let leaves: Vec<BlockHash> = (0..l.block_count)
        .map(|i| leaf_hash(i, &[i as u8; 16]))
        .collect();
    let root = file_root(size, l, &leaves).unwrap();
    let raw = encode_hashes(&leaves);
    assert_eq!(raw.len(), l.block_count as usize * 32);
    assert_eq!(parse_hashes(&raw, size, l, &root).unwrap(), leaves);

    // Один перевёрнутый бит: корень не воспроизводится.
    let mut bad = raw.clone();
    bad[40] ^= 1;
    assert_eq!(
        parse_hashes(&bad, size, l, &root).err(),
        Some(StateError::HashMismatch)
    );
    // Чужой корень.
    assert_eq!(
        parse_hashes(&raw, size, l, &FileRoot([0; 32])).err(),
        Some(StateError::HashMismatch)
    );
    // Неверная длина, чужая раскладка.
    for n in [0, raw.len() - 1, raw.len() - 32] {
        assert_eq!(
            parse_hashes(&raw[..n], size, l, &root).err(),
            Some(StateError::Malformed)
        );
    }
    let mut long = raw.clone();
    long.push(0);
    assert_eq!(
        parse_hashes(&long, size, l, &root).err(),
        Some(StateError::Malformed)
    );
    let other = Layout {
        block_size: 1 << 21,
        block_count: 2,
    };
    assert_eq!(
        parse_hashes(&raw, size, other, &root).err(),
        Some(StateError::Malformed)
    );

    // Прогресс такого файла сбрасывается; остальные файлы не затронуты.
    let mut s = sample();
    assert!(matches!(s.files[0].status, FileStatus::InProgress(_)));
    assert!(s.clear_progress(0));
    assert!(matches!(s.files[0].status, FileStatus::Waiting));
    assert!(!s.clear_progress(0), "уже не в процессе");
    assert!(!s.clear_progress(3), "Verified не трогаем");
    assert!(!s.clear_progress(99));
    assert!(matches!(s.files[3].status, FileStatus::Verified(_)));
}
