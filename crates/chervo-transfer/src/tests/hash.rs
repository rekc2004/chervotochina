use ring::digest::{SHA256, digest};

use crate::hash::sha256;
use crate::{
    BlockHash, Layout, MAX_BLOCKS, ProtocolError, block_len, file_root, layout, leaf_hash,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn sha256_known_answer() {
    assert_eq!(
        hex(&sha256(&[b"abc"])),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(&[b"a", b"bc"])),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Прямой вызов ring даёт то же самое.
    assert_eq!(digest(&SHA256, b"abc").as_ref(), &sha256(&[b"abc"])[..]);
}

#[test]
fn layout_table() {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    let l = |size| layout(size).unwrap();
    let t = |bs: u32, bc: u32| Layout {
        block_size: bs,
        block_count: bc,
    };
    assert_eq!(l(0), t(1 << 20, 0));
    assert_eq!(l(1), t(1 << 20, 1));
    assert_eq!(l(MIB), t(1 << 20, 1));
    assert_eq!(l(MIB + 1), t(1 << 20, 2));
    assert_eq!(l(64 * GIB), t(1 << 20, 65_536));
    // 64 ГиБ + 1 байт: окно 1 МиБ уже мало, блок растёт до 2 МиБ.
    assert_eq!(l(64 * GIB + 1), t(1 << 21, 32_769));
    assert_eq!(l(100 * GIB), t(1 << 21, 51_200));
    assert_eq!(l(1 << 40), t(1 << 24, 65_536));
    assert!(matches!(
        layout((1 << 40) + 1),
        Err(ProtocolError::TooLarge)
    ));
    assert!(matches!(layout(u64::MAX), Err(ProtocolError::TooLarge)));

    // Вокруг каждой степени двойки: блоков не больше 65536, блок в границах,
    // длины блоков складываются ровно в размер файла.
    let mut sizes = vec![0u64, 1, 2, 65_535, 65_536, 65_537, 123_456_789];
    for p in 0..=40u32 {
        for d in [-2i64, -1, 0, 1, 2] {
            let v = (1i128 << p) + i128::from(d);
            if (0..=(1i128 << 40)).contains(&v) {
                sizes.push(v as u64);
            }
        }
    }
    for size in sizes {
        let lay = l(size);
        assert!(lay.block_count <= MAX_BLOCKS, "size {size}");
        assert!((1 << 20..=1 << 24).contains(&lay.block_size), "size {size}");
        assert!(lay.block_size.is_power_of_two());
        assert_eq!(
            u64::from(lay.block_count),
            size.div_ceil(u64::from(lay.block_size))
        );
        // Сумма длин: для больших файлов проверяем первый, последний и граничные блоки.
        if lay.block_count > 0 {
            let last = lay.block_count - 1;
            let full = u64::from(last) * u64::from(lay.block_size);
            let tail = u64::from(block_len(size, lay, last).unwrap());
            assert_eq!(full + tail, size, "size {size}");
            assert!(tail >= 1 && tail <= u64::from(lay.block_size));
            assert_eq!(
                block_len(size, lay, 0).unwrap() as u64,
                size.min(u64::from(lay.block_size))
            );
        }
        assert_eq!(block_len(size, lay, lay.block_count), None);
        assert_eq!(block_len(size, lay, u32::MAX), None);
    }
    // block_len не доверяет раскладке: рассогласованная раскладка даёт None, а не панику.
    let bad = t(1 << 20, 10);
    assert_eq!(block_len(5, bad, 3), None);
    assert_eq!(block_len(5, t(u32::MAX, u32::MAX), u32::MAX - 1), None);
}

#[test]
fn leaf_binds_index_and_len() {
    let data = [1u8, 2, 3, 4];
    let a = leaf_hash(0, &data);
    assert_ne!(a, leaf_hash(1, &data), "индекс входит в хэш");
    assert_ne!(
        leaf_hash(0, &data),
        leaf_hash(0, &[1, 2, 3, 4, 0]),
        "длина и содержимое входят в хэш"
    );
    assert_ne!(leaf_hash(0, &[]), leaf_hash(0, &[0]));
    assert_eq!(a, leaf_hash(0, &data));
    // Индекс и длина не смешиваются с данными: сдвиг границы меняет хэш.
    assert_ne!(leaf_hash(0, &[0, 0, 0, 1, 7]), leaf_hash(1, &[7]));
}

fn leaves(n: u8) -> Vec<BlockHash> {
    (0..n).map(|i| leaf_hash(u32::from(i), &[i; 10])).collect()
}

#[test]
fn root_binds_size_layout_order() {
    let l = Layout {
        block_size: 1 << 20,
        block_count: 3,
    };
    let size = 2 * (1u64 << 20) + 5;
    let lv = leaves(3);
    let root = file_root(size, l, &lv).unwrap();
    assert_eq!(root, file_root(size, l, &lv).unwrap());
    let mut swapped = lv.clone();
    swapped.swap(0, 2);
    assert_ne!(root, file_root(size, l, &swapped).unwrap(), "порядок");
    assert_ne!(root, file_root(size + 1, l, &lv).unwrap(), "размер");
    let l2 = Layout {
        block_size: 1 << 21,
        ..l
    };
    assert_ne!(root, file_root(size, l2, &lv).unwrap(), "размер блока");
    let mut changed = lv.clone();
    changed[1] = leaf_hash(1, &[0xFF; 10]);
    assert_ne!(root, file_root(size, l, &changed).unwrap(), "хэш блока");
    // Число хэшей обязано совпасть с раскладкой.
    for n in [0u8, 2, 4] {
        assert!(matches!(
            file_root(size, l, &leaves(n)),
            Err(ProtocolError::Malformed)
        ));
    }
    // Пустой файл: 0 блоков, корень определён.
    let l0 = layout(0).unwrap();
    assert!(file_root(0, l0, &[]).is_ok());
    assert_ne!(
        file_root(0, l0, &[]).unwrap(),
        file_root(1, layout(1).unwrap(), &[leaf_hash(0, &[0])]).unwrap()
    );
}

#[test]
fn root_matches_independent_computation() {
    let size = 3 * (1u64 << 20) - 7;
    let l = layout(size).unwrap();
    assert_eq!(l.block_count, 3);
    // Содержимое: три блока по раскладке.
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut lv = Vec::new();
    let mut manual_leaves: Vec<u8> = Vec::new();
    for i in 0..l.block_count {
        let start = i as usize * l.block_size as usize;
        let len = block_len(size, l, i).unwrap() as usize;
        let chunk = &data[start..start + len];
        lv.push(leaf_hash(i, chunk));
        // Независимая сборка буфера листа.
        let mut buf = b"chervo-xfer-v1-block\0".to_vec();
        buf.extend_from_slice(&i.to_be_bytes());
        buf.extend_from_slice(&(len as u32).to_be_bytes());
        buf.extend_from_slice(chunk);
        let want = digest(&SHA256, &buf);
        assert_eq!(lv[i as usize].0.as_slice(), want.as_ref());
        manual_leaves.extend_from_slice(want.as_ref());
    }
    let mut buf = b"chervo-xfer-v1-file\0".to_vec();
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&l.block_size.to_be_bytes());
    buf.extend_from_slice(&l.block_count.to_be_bytes());
    buf.extend_from_slice(&manual_leaves);
    let want = digest(&SHA256, &buf);
    let got = file_root(size, l, &lv).unwrap();
    assert_eq!(got.0.as_slice(), want.as_ref());
}
