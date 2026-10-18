#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout
)]
//! Fuzz-смоук журналов приёма (этап 17, B3, C10): `.dirs` и `.placed` на stable, без внешних
//! пакетов. ГПСЧ xorshift64*; число итераций `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в
//! release, 2 000 в debug), зерно `CHERVO_FUZZ_SEED` (по умолчанию фиксированное).
//!
//! Свойства: ни одной паники; принятый `.dirs` перекодируется в те же байты и принят только
//! для своего ключа, плана и числа каталогов; `parse_placed` берёт только годный префикс
//! записей по 8 байт, и `PlacedLog::open` обрезает файл до него.

use std::fs;
use std::path::{Path, PathBuf};

use chervo_identity::PairId;
use chervo_transfer::{TransferId, TransferKey};

use super::{
    DIRS_MAGIC, MAX_K, PlacedLog, REC_LEN, check_of, dirs_path, parse_placed, placed_path,
    plan_digest, read_dirs, sha256, write_dirs,
};

const HEX: &str = "0123456789abcdef0123456789abcdef";

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Зерно цели: без `CHERVO_FUZZ_SEED` ровно `default`; с ней splitmix64 от `seed ^ default`.
/// Пустое значение считается незаданным, неразборное вызывает панику.
fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Одна случайная мутация: переворот бита, вставка, удаление, обрезка, замена байта.
fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(5) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() + 1);
            let len = 1 + rng.below(4);
            for (k, b) in rng.bytes(len).into_iter().enumerate() {
                v.insert(i + k, b);
            }
        }
        2 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        3 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}

/// Пересчитывает контрольную сумму `.dirs` после правки тела: проверки структуры не прячутся
/// за суммой.
fn reseal(mut raw: Vec<u8>) -> Vec<u8> {
    if raw.len() < 32 {
        return raw;
    }
    let n = raw.len() - 32;
    raw.truncate(n);
    let sum = sha256(&[&raw]);
    raw.extend_from_slice(&sum);
    raw
}

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("chervo-jfuzz-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key(n: u8) -> TransferKey {
    TransferKey {
        pair: PairId::from_bytes([n; 16]),
        id: TransferId([n.wrapping_add(100); 16]),
    }
}

#[test]
fn fuzz_smoke_journal() {
    let n = fuzz_iters();
    let mut rng = XorShift(fuzz_seed(0x6A0B_17A1_D1F5_0017).max(1));
    let tmp = Dir::new();
    let (dir, other) = (tmp.path().join("a"), tmp.path().join("b"));
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&other).unwrap();

    let k = key(7);
    let names = ["фото", "docs", "a b"];
    let digest = plan_digest(&names);
    let ks: Vec<(u16, u64)> = vec![(1, 11), (2, 0xDEAD_BEEF), (MAX_K, u64::MAX)];
    write_dirs(&dir, HEX, &k, &digest, &ks).unwrap();
    let valid = fs::read(dirs_path(&dir, HEX)).unwrap();
    assert_eq!(read_dirs(&dir, HEX, &k, &digest, 3), Some(ks.clone()));

    // отрицательные контроли: чужой ключ, чужой план, чужое число каталогов
    assert_eq!(read_dirs(&dir, HEX, &key(8), &digest, 3), None);
    assert_eq!(read_dirs(&dir, HEX, &k, &plan_digest(&["x"]), 3), None);
    assert_eq!(read_dirs(&dir, HEX, &k, &digest, 2), None);
    assert_eq!(read_dirs(&dir, HEX, &k, &digest, 4), None);

    // валидный `.placed` для мутаций
    let mut valid_placed = Vec::new();
    for i in 0..6u32 {
        let kk = 1 + (i as u16 * 37) % MAX_K;
        valid_placed.extend_from_slice(&i.to_be_bytes());
        valid_placed.extend_from_slice(&kk.to_be_bytes());
        valid_placed.extend_from_slice(&check_of(i, kk).to_be_bytes());
    }
    assert_eq!(parse_placed(&valid_placed).1, valid_placed.len());

    let (mut dirs_ok, mut placed_ended_by_eof, mut logs_opened) = (0u64, 0u64, 0u64);
    for i in 0..n {
        // ---- `.dirs`
        let input = match rng.below(5) {
            0 => {
                let len = rng.below(300);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &valid),
            2 => reseal(mutate(&mut rng, &valid)),
            3 => {
                let once = mutate(&mut rng, &valid);
                reseal(mutate(&mut rng, &once))
            }
            _ => {
                // хвост и длина числа каталогов с пересчитанной суммой
                let mut v = valid[..valid.len() - 32].to_vec();
                if rng.below(2) == 0 {
                    let cut = rng.below(v.len() + 1);
                    v.truncate(cut);
                } else {
                    let extra = 1 + rng.below(12);
                    v.extend(rng.bytes(extra));
                }
                v.extend_from_slice(&[0u8; 32]);
                reseal(v)
            }
        };
        fs::write(dirs_path(&dir, HEX), &input).unwrap();
        // чужое число каталогов проверяется на каждой четвёртой: чтение файла дорогое
        let counts: Vec<usize> = if i % 4 == 0 {
            vec![3, rng.below(6)]
        } else {
            vec![3]
        };
        for count in counts {
            if let Some(got) = read_dirs(&dir, HEX, &k, &digest, count) {
                dirs_ok += 1;
                assert_eq!(got.len(), count, "итерация {i}: число каталогов");
                assert!(
                    got.iter().all(|(kk, _)| (1..=MAX_K).contains(kk)),
                    "итерация {i}: k вне 1..=MAX_K"
                );
                // принятый журнал канонический: запись даёт те же байты
                write_dirs(&other, HEX, &k, &digest, &got).unwrap();
                let again = fs::read(dirs_path(&other, HEX)).unwrap();
                assert_eq!(again, input, "итерация {i}: .dirs не канонический");
                // и подходит только своему ключу, плану и числу
                assert_eq!(read_dirs(&dir, HEX, &key(9), &digest, count), None);
                assert_eq!(read_dirs(&dir, HEX, &k, &plan_digest(&["z"]), count), None);
                assert_eq!(read_dirs(&dir, HEX, &k, &digest, count + 1), None);
            }
        }
        // заголовок и магия: журнал с другой магией никогда не принимается
        if input.len() >= 8 && input[..8] != *DIRS_MAGIC {
            assert_eq!(read_dirs(&dir, HEX, &k, &digest, 3), None);
        }

        // ---- `.placed`
        let raw = match rng.below(4) {
            0 => {
                let len = rng.below(100);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &valid_placed),
            2 => {
                let once = mutate(&mut rng, &valid_placed);
                mutate(&mut rng, &once)
            }
            _ => {
                // годные записи с мусорным хвостом
                let mut v = valid_placed.clone();
                let extra = rng.below(20);
                v.extend(rng.bytes(extra));
                v
            }
        };
        let (last, valid_len) = parse_placed(&raw);
        assert!(
            valid_len <= raw.len(),
            "итерация {i}: префикс длиннее ввода"
        );
        assert_eq!(valid_len % REC_LEN, 0, "итерация {i}: префикс не кратен 8");
        let mut expect = std::collections::HashMap::new();
        for rec in raw[..valid_len].as_chunks::<REC_LEN>().0 {
            let index = u32::from_be_bytes(rec[..4].try_into().unwrap());
            let kk = u16::from_be_bytes(rec[4..6].try_into().unwrap());
            let chk = u16::from_be_bytes(rec[6..8].try_into().unwrap());
            assert!((1..=MAX_K).contains(&kk), "итерация {i}: k в префиксе");
            assert_eq!(chk, check_of(index, kk), "итерация {i}: сумма в префиксе");
            expect.insert(index, kk);
        }
        assert_eq!(
            last, expect,
            "итерация {i}: последняя годная запись индекса"
        );
        if let Some(rec) = raw.get(valid_len..valid_len + REC_LEN) {
            // первая негодная запись заканчивает разбор
            let index = u32::from_be_bytes(rec[..4].try_into().unwrap());
            let kk = u16::from_be_bytes(rec[4..6].try_into().unwrap());
            let chk = u16::from_be_bytes(rec[6..8].try_into().unwrap());
            assert!(
                !(1..=MAX_K).contains(&kk) || chk != check_of(index, kk),
                "итерация {i}: годная запись после обрыва"
            );
        } else {
            placed_ended_by_eof += 1;
        }

        // каждый 64-й: настоящий файл `.placed`; открытие обрезает до годного префикса
        if i % 64 == 0 {
            fs::write(placed_path(&dir, HEX), &raw).unwrap();
            let mut log = PlacedLog::open(&dir, HEX).unwrap();
            logs_opened += 1;
            assert_eq!(
                fs::metadata(placed_path(&dir, HEX)).unwrap().len(),
                valid_len as u64,
                "итерация {i}: файл не обрезан до годного префикса"
            );
            for (index, kk) in &expect {
                assert_eq!(log.last(*index), Some(*kk));
            }
            log.append(4_000_000, 5).unwrap();
            drop(log);
            let again = PlacedLog::open(&dir, HEX).unwrap();
            assert_eq!(again.last(4_000_000), Some(5));
        }
    }
    println!(
        "fuzz_smoke_journal: iterations={n} dirs_accepted={dirs_ok} \
         placed_ended_by_eof={placed_ended_by_eof} logs_opened={logs_opened}"
    );
    // контроль: нетронутый журнал по-прежнему читается
    fs::write(dirs_path(&dir, HEX), &valid).unwrap();
    assert_eq!(read_dirs(&dir, HEX, &k, &digest, 3), Some(ks));
}
