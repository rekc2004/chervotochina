#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout
)]
//! Fuzz-смоук разбора ответа SNTP на stable (этап 17, B3): `parse_response` на случайных и
//! мутированных пакетах. ГПСЧ xorshift64*; число итераций `CHERVO_FUZZ_ITERS` (по умолчанию
//! 20 000 в release, 2 000 в debug), зерно `CHERVO_FUZZ_SEED`.
//!
//! Свойства: ни одной паники; `Ok` ровно тогда, когда заголовок допустим по правилам (длина
//! 48..=1024, LI != 3, версия 3 или 4, режим 4, страта 1..=15, задержка и дисперсия корня не
//! больше секунды, «originate» равен нашему nonce, время отправки сервера не ноль); у
//! правильно построенного пакета поправка совпадает с заложенной до 2 мс.

use chervo_timesync::parse_response;

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

fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(6) {
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
        4 => {
            // длина вокруг границ 48 и 1024
            let target = [0usize, 1, 47, 48, 49, 1023, 1024, 1025, 2048][rng.below(9)];
            v.resize(target, 0xAB);
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}

/// Независимая запись правил допуска заголовка.
fn expected_ok(buf: &[u8], origin: [u8; 8]) -> bool {
    if buf.len() < 48 || buf.len() > 1024 {
        return false;
    }
    let li = buf[0] >> 6;
    let vn = (buf[0] >> 3) & 7;
    let mode = buf[0] & 7;
    if li == 3 || (vn != 3 && vn != 4) || mode != 4 {
        return false;
    }
    if !(1..=15).contains(&buf[1]) {
        return false;
    }
    let be32 = |at: usize| u32::from_be_bytes(buf[at..at + 4].try_into().unwrap());
    if be32(4) > 0x1_0000 || be32(8) > 0x1_0000 {
        return false;
    }
    if buf[24..32] != origin {
        return false;
    }
    buf[40..48] != [0u8; 8]
}

/// Мс в формат NTP 32.32 (дробь секунды).
fn ms_to_fixed(ms: i64) -> u64 {
    ((i128::from(ms) << 32) / 1000) as i64 as u64
}

/// Правильно построенный ответ: часы сервера впереди наших на `off_ms`, задержка сети `delay_ms`
/// туда-обратно, обработка на сервере `proc_ms`.
fn build(origin: [u8; 8], t1: u64, off_ms: i64, delay_ms: i64, proc_ms: i64) -> (Vec<u8>, u64) {
    let t2 = t1
        .wrapping_add(ms_to_fixed(off_ms))
        .wrapping_add(ms_to_fixed(delay_ms / 2));
    let t3 = t2.wrapping_add(ms_to_fixed(proc_ms));
    let t4 = t1
        .wrapping_add(ms_to_fixed(delay_ms))
        .wrapping_add(ms_to_fixed(proc_ms));
    let mut p = vec![0u8; 48];
    p[0] = 0x24; // LI 0, VN 4, mode 4
    p[1] = 2;
    p[24..32].copy_from_slice(&origin);
    p[32..40].copy_from_slice(&t2.to_be_bytes());
    p[40..48].copy_from_slice(&t3.to_be_bytes());
    (p, t4)
}

#[test]
fn fuzz_smoke_sntp() {
    let n = fuzz_iters();
    let mut rng = XorShift(fuzz_seed(0x5A7B_0DE5_00C0_FFEE).max(1));
    let (mut accepted, mut constructed) = (0u64, 0u64);
    for i in 0..n {
        let origin: [u8; 8] = rng.bytes(8).try_into().unwrap();
        let t1 = rng.next();
        let t4 = t1.wrapping_add(rng.next() >> 20);
        let off = (rng.next() % 4_000_000) as i64 - 2_000_000;
        let delay = (rng.next() % 2_000) as i64;
        let proc_ms = (rng.next() % 50) as i64;
        let (good, good_t4) = build(origin, t1, off, delay, proc_ms);

        // правильный пакет принимается, поправка совпадает с заложенной
        let got = parse_response(&good, origin, t1, good_t4)
            .unwrap_or_else(|()| panic!("итерация {i}: годный пакет отвергнут"));
        assert!(
            (got - off).abs() <= 2,
            "итерация {i}: поправка {got} мс, заложено {off} мс"
        );
        constructed += 1;

        let input = match rng.below(5) {
            0 => {
                let len = rng.below(1200);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &good),
            2 => {
                let once = mutate(&mut rng, &good);
                mutate(&mut rng, &once)
            }
            3 => {
                // годный заголовок с мусором в остальном
                let len = 48 + rng.below(40);
                let mut v = rng.bytes(len);
                v[0] = [0x23, 0x24, 0x1B, 0x1C, 0xE4, 0x25][rng.below(6)];
                v[1] = rng.below(18) as u8;
                v[24..32].copy_from_slice(&origin);
                v
            }
            _ => {
                // годный пакет с чужим nonce
                let mut v = good.clone();
                let at = 24 + rng.below(8);
                v[at] ^= 1 << rng.below(8);
                v
            }
        };
        let res = parse_response(&input, origin, t1, t4);
        let want = expected_ok(&input, origin);
        assert_eq!(
            res.is_ok(),
            want,
            "итерация {i}: разбор и независимые правила расходятся ({} байт, голова {:02x?})",
            input.len(),
            &input[..input.len().min(8)]
        );
        if res.is_ok() {
            accepted += 1;
        }
        // чужой nonce никогда не принимается
        let mut other = origin;
        other[rng.below(8)] ^= 1 << rng.below(8);
        assert_eq!(
            parse_response(&input, other, t1, t4).is_ok(),
            expected_ok(&input, other),
            "итерация {i}: чужой nonce"
        );
    }
    println!("fuzz_smoke_sntp: iterations={n} accepted={accepted} constructed_ok={constructed}");
}
