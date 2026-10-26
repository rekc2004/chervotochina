#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout
)]
//! Fuzz-смоук разбора файла настроек на stable (этап 18а): `fuzz_settings` на случайных и
//! мутированных файлах. ГПСЧ xorshift64*; число итераций `CHERVO_FUZZ_ITERS` (по умолчанию
//! 1 000 000 в release, 20 000 в debug), зерно `CHERVO_FUZZ_SEED`.
//!
//! Свойства: ни одной паники; принятый файл записывается и читается обратно в те же настройки
//! (`parse` после `write` даёт то же), а вторая запись даёт тот же текст (идемпотентность). Обе
//! проверки внутри `fuzz_settings` (он же цель libFuzzer `settings`).

use chervo_core::fuzz_settings;

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
        20_000
    } else {
        1_000_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn fuzz_seed(default: u64) -> u64 {
    match std::env::var("CHERVO_FUZZ_SEED") {
        Ok(raw) if !raw.trim().is_empty() => {
            let n: u64 = raw.trim().parse().expect("CHERVO_FUZZ_SEED");
            let mut z = (n ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            (z ^ (z >> 31)) | 1
        }
        _ => default,
    }
}

#[cfg(windows)]
const ROOT: &str = "C:\\data\\recv";
#[cfg(not(windows))]
const ROOT: &str = "/data/recv";

const KEYS: [&str; 11] = [
    "port",
    "receive_root",
    "shared_root_confirmed",
    "extra_root",
    "min_free_percent",
    "invite_ttl_secs",
    "manual_forward",
    "upnp_router",
    "clock_offset_ms",
    "clock_offset_at",
    "ntp_server",
];

const VALUES: [&str; 22] = [
    "0",
    "1",
    "10",
    "50000",
    "65535",
    "65536",
    "-1",
    "-0",
    "604800000",
    "-604800001",
    "900",
    "86400",
    "uuid:6f1c0a2e-0000-4000-8000-000000000001;1",
    "uuid:x;0",
    "ntp.example.org",
    "a b",
    "",
    "00",
    "+7",
    "ROOT",
    "rel/path",
    "99999999999999999999999",
];

fn valid_file() -> Vec<u8> {
    format!(
        "chervo-settings 1\nport=50000\nreceive_root={ROOT}\nshared_root_confirmed=1\n\
         extra_root={ROOT}2\nmin_free_percent=10\ninvite_ttl_secs=900\nmanual_forward=50000\n\
         upnp_router=uuid:6f1c0a2e-0000-4000-8000-000000000001;1\nclock_offset_ms=-5\n\
         clock_offset_at=1700000000\nntp_server=ntp.example.org\n"
    )
    .into_bytes()
}

fn structured(rng: &mut XorShift) -> Vec<u8> {
    let mut s = String::from("chervo-settings 1\n");
    if rng.below(8) != 0 {
        s.push_str(&format!("port={}\n", 1 + rng.below(65535)));
    }
    if rng.below(8) != 0 {
        s.push_str(&format!("receive_root={ROOT}\n"));
    }
    for _ in 0..rng.below(8) {
        let key = KEYS[rng.below(KEYS.len())];
        let v = VALUES[rng.below(VALUES.len())];
        let v = if v == "ROOT" { ROOT } else { v };
        s.push_str(&format!("{key}={v}\n"));
    }
    s.into_bytes()
}

fn mutate(rng: &mut XorShift, mut b: Vec<u8>) -> Vec<u8> {
    for _ in 0..1 + rng.below(4) {
        if b.is_empty() {
            b.push(rng.next() as u8);
            continue;
        }
        let at = rng.below(b.len());
        match rng.below(6) {
            0 => b[at] = rng.next() as u8,
            1 => b[at] ^= 1 << rng.below(8),
            2 => {
                b.remove(at);
            }
            3 => b.insert(at, rng.next() as u8),
            4 => b.truncate(at),
            _ => {
                let end = (at + rng.below(40)).min(b.len());
                let chunk = b[at..end].to_vec();
                b.splice(at..at, chunk);
            }
        }
    }
    b
}

#[test]
fn settings_parser_survives_noise() {
    let iters = fuzz_iters();
    let mut rng = XorShift(fuzz_seed(0x5E77_1465_0000_0001));
    let base = valid_file();
    assert!(fuzz_settings(&base), "рабочий файл не принят");
    let (mut accepted, mut total) = (0u64, 0u64);
    for i in 0..iters {
        let input = match i % 4 {
            0 => {
                let n = rng.below(300);
                rng.bytes(n)
            }
            1 => mutate(&mut rng, base.clone()),
            2 => structured(&mut rng),
            _ => {
                let s = structured(&mut rng);
                mutate(&mut rng, s)
            }
        };
        total += 1;
        if fuzz_settings(&input) {
            accepted += 1;
        }
    }
    println!("settings fuzz: iterations={total} accepted={accepted}");
    // проверка не пуста: часть входов принимается (иначе свойство записи/чтения не проверялось)
    assert!(
        accepted * 1000 >= total || total < 1000,
        "принято слишком мало: {accepted} из {total}"
    );
    assert!(accepted > 0);
}
