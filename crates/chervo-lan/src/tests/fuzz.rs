//! Fuzz-смоук разбора датаграммы: ни одной паники; случайный ввод даёт 0 находок; изменённый
//! байт верной датаграммы никогда не даёт другой порт или другой адрес. Число итераций:
//! `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug); тест печатает его.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};

use chervo_identity::{LAN_HDR, PairId};

use super::build;
use super::{OWN, PORT, SRC, W, fixture, sock};
use crate::limits::DGRAM_LEN;
use crate::wire::{SrcPolicy, parse};

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
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn fuzz_iters() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) {
            2_000
        } else {
            20_000
        })
}

#[test]
fn fuzz_smoke_beacon() {
    let mut fx = fixture(3);
    let valid = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    let orig: HashSet<(PairId, SocketAddrV4)> =
        parse(&valid, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT)
            .iter()
            .map(|s| (s.pair, s.addr))
            .collect();
    assert_eq!(orig.len(), 3);

    let n = fuzz_iters();
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let (mut random_in, mut mutated, mut kept) = (0u64, 0u64, 0u64);
    for _ in 0..n {
        match rng.below(5) {
            // случайные байты любой длины
            0 => {
                let len = rng.below(700);
                let v = rng.bytes(len);
                assert!(parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT).is_empty());
                crate::fuzz_beacon(&v);
                random_in += 1;
            }
            // верная длина и заголовок, остальное случайно
            1 => {
                let mut v = rng.bytes(DGRAM_LEN);
                v[..2].copy_from_slice(&LAN_HDR);
                assert!(parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT).is_empty());
                crate::fuzz_beacon(&v);
                random_in += 1;
            }
            // верный маяк с чужого частного адреса: AAD не сходится
            2 => {
                let ip = Ipv4Addr::new(10, rng.byte(), rng.byte(), rng.byte());
                if ip != SRC && ip != OWN {
                    let f = parse(&valid, sock(ip), &[OWN], &t, SrcPolicy::PRODUCT);
                    assert!(f.is_empty(), "{ip}");
                }
            }
            // мутации верной датаграммы
            _ => {
                let mut v = valid.to_vec();
                for _ in 0..=rng.below(4) {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
                if rng.below(4) == 0 {
                    let len = rng.below(DGRAM_LEN + 40);
                    v.resize(len, rng.byte());
                }
                mutated += 1;
                let f = parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT);
                for s in &f {
                    assert!(orig.contains(&(s.pair, s.addr)), "другой порт или адрес");
                }
                kept += u64::try_from(f.len()).unwrap();
                crate::fuzz_beacon(&v);
            }
        }
    }
    println!(
        "fuzz_smoke_beacon: iterations {n}, random {random_in}, mutated {mutated}, sightings kept {kept}"
    );
}

// ---------------------------------------------------------------- корпус fuzz-цели

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/lan_beacon")
}

/// Ключи пар у fuzz-цели фиксированные: таблица и верная датаграмма собираются из одних и тех же
/// секретов при каждом запуске, поэтому корпус с настоящей датаграммой доходит до `open`.
#[test]
fn fuzz_keys_are_fixed_and_valid_beacon_opens() {
    let a = crate::testkit::fixed_peer_duo(0).unwrap();
    let b = crate::testkit::fixed_peer_duo(0).unwrap();
    assert_eq!(
        a.1.lan_keys().unwrap().send_id(1000),
        b.1.lan_keys().unwrap().send_id(1000)
    );
    assert_ne!(
        a.1.lan_keys().unwrap().send_id(1000),
        crate::testkit::fixed_peer_duo(1)
            .unwrap()
            .1
            .lan_keys()
            .unwrap()
            .send_id(1000)
    );
    let d = crate::fuzz_valid_beacon();
    assert_eq!(d.len(), DGRAM_LEN);
    assert_eq!(
        crate::fuzz_beacon_ports(&d),
        vec![crate::FUZZ_PORT; crate::FUZZ_PAIRS]
    );
    // один изменённый байт слота: слот пропадает, порт никогда не другой
    for at in [14usize, 14 + 26 + 9, 14 + 5 * 26 + 25, 429] {
        let mut x = d.clone();
        x[at] ^= 0x40;
        for p in crate::fuzz_beacon_ports(&x) {
            assert_eq!(p, crate::FUZZ_PORT);
        }
    }
}

/// Файлы корпуса `fuzz/corpus/lan_beacon/` остаются настоящими датаграммами текущего формата и
/// ключей: сломается формат или метки, тест напомнит пересоздать корпус (`--ignored fuzz_corpus_write`).
#[test]
fn fuzz_corpus_seed_opens() {
    let valid = std::fs::read(corpus_dir().join("valid-3-pairs")).unwrap();
    assert_eq!(valid.len(), DGRAM_LEN);
    assert_eq!(
        crate::fuzz_beacon_ports(&valid),
        vec![crate::FUZZ_PORT; crate::FUZZ_PAIRS]
    );
    let flipped = std::fs::read(corpus_dir().join("flipped-slot")).unwrap();
    assert_eq!(flipped.len(), DGRAM_LEN);
    assert!(crate::fuzz_beacon_ports(&flipped).len() < crate::FUZZ_PAIRS);
}

/// Создание файлов корпуса. Запускается вручную: `cargo test -p chervo-lan fuzz_corpus_write -- --ignored`.
#[test]
#[ignore = "пишет файлы корпуса в fuzz/corpus/lan_beacon"]
fn fuzz_corpus_write() {
    let dir = corpus_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let valid = crate::fuzz_valid_beacon();
    assert_eq!(crate::fuzz_beacon_ports(&valid).len(), crate::FUZZ_PAIRS);
    std::fs::write(dir.join("valid-3-pairs"), &valid).unwrap();
    // испорчен байт первого настоящего слота (метка не найдётся или не откроется)
    let mut flipped = valid.clone();
    for at in 14..14 + 26 * 16 {
        let mut x = valid.clone();
        x[at] ^= 0x01;
        if crate::fuzz_beacon_ports(&x).len() < crate::FUZZ_PAIRS {
            flipped = x;
            break;
        }
    }
    assert_ne!(flipped, valid);
    std::fs::write(dir.join("flipped-slot"), &flipped).unwrap();
}
