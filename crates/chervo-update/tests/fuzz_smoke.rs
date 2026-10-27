//! Дымовой фаззинг разбора ключей, подписей и манифеста: xorshift64*, без внешних пакетов.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000); зерно: `CHERVO_FUZZ_SEED`.
//! Свойства: нет паники; для `Ok` манифеста каноничная запись равна входу; для `Ok` ключа
//! строка `pubkey_line` входит в файл; случайные подписи не проходят `verify_manifest`.
//! Ключ ТЕСТОВЫЙ (зерно в коде).

mod common;

use chervo_update::{KeyRole, KeySet, Manifest, pubkey_line, verify_manifest};
use common::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

fn iterations() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Зерно ГПСЧ цели. Без `CHERVO_FUZZ_SEED` ровно `default`. С ней у каждой цели своё зерно
/// (splitmix64 от `seed ^ default`). Неразборное значение вызывает панику.
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

const B64_ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/// Мутирует копию входа: переворот бита, замена, вставка, удаление, усечение.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.byte();
            }
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.byte());
            }
            3 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            4 if !v.is_empty() => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            5 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = b"\r\n \t=/+A0"[rng.below(9)];
            }
            _ => {}
        }
    }
    v
}

fn random_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let n = rng.below(max + 1);
    (0..n).map(|_| rng.byte()).collect()
}

fn random_b64(rng: &mut Rng, n: usize) -> String {
    (0..n)
        .map(|_| B64_ALPHA[rng.below(B64_ALPHA.len())] as char)
        .collect()
}

#[test]
fn fuzz_smoke_update_pubkey() {
    let n = iterations();
    println!(
        "fuzz_smoke_update_pubkey: os={} iterations={n}",
        std::env::consts::OS
    );
    let mut rng = Rng(fuzz_seed(0xA11C_E0F0_0D5E_ED01));
    let valid = pubkey_file(&test_key(11), key_id(11));
    let mut oks = 0u64;
    for i in 0..n {
        let input = match i % 4 {
            0 => random_bytes(&mut rng, 1100),
            1 | 2 => mutate(&mut rng, &valid),
            _ => format!(
                "untrusted comment: t\n{}\n",
                random_b64(&mut rng, 52 + (i as usize % 8))
            )
            .into_bytes(),
        };
        if let Ok(ks) = KeySet::from_pubkey_files(&[(KeyRole::Primary, &input)]) {
            oks += 1;
            let list = ks.list();
            assert_eq!(list.len(), 1);
            let line = pubkey_line(list[0].1, &list[0].2);
            let text = String::from_utf8_lossy(&input);
            assert!(
                text.contains(&line),
                "Ok-ключ не совпал с входом: {input:?}"
            );
        }
    }
    println!("fuzz_smoke_update_pubkey: ok-inputs={oks}");
}

#[test]
fn fuzz_smoke_update_minisig() {
    // проверка подписи дорога в debug-сборке: итераций меньше, чем у разбора текста
    let n = (iterations() / 10).max(200);
    println!(
        "fuzz_smoke_update_minisig: os={} iterations={n}",
        std::env::consts::OS
    );
    let mut rng = Rng(fuzz_seed(0xA11C_E0F0_0D5E_ED02));
    let sk = test_key(12);
    let id = key_id(12);
    let ks = KeySet::from_pubkey_files(&[(KeyRole::Primary, &pubkey_file(&sk, id))]).unwrap();
    let manifest = sample_manifest_bytes();
    let valid = sign(&sk, id, &manifest, "chervo-release 1.2.3");
    verify_manifest(&ks, &manifest, &valid).expect("образец подписан верно");
    let mut id_raw = b"ED".to_vec();
    id_raw.extend_from_slice(&id);
    for i in 0..n {
        match i % 5 {
            // мутации настоящего файла подписи: паники нет, а при Ok манифест тот же
            0..=1 => {
                let input = mutate(&mut rng, &valid);
                if let Ok(vm) = verify_manifest(&ks, &manifest, &input) {
                    assert_eq!(vm.manifest().to_canonical_bytes(), manifest);
                }
            }
            // настоящая подпись при изменённом манифесте не проходит
            2 => {
                let bad = mutate(&mut rng, &manifest);
                if bad != manifest {
                    assert!(verify_manifest(&ks, &bad, &valid).is_err());
                }
            }
            // случайные, но структурно верные подпись и глобальная подпись с верным key_id
            3 => {
                let mut raw = id_raw.clone();
                raw.extend((0..64).map(|_| rng.byte()));
                let global: Vec<u8> = (0..64).map(|_| rng.byte()).collect();
                let file = format!(
                    "untrusted comment: r\n{}\ntrusted comment: r\n{}\n",
                    b64(&raw),
                    b64(&global)
                );
                assert!(verify_manifest(&ks, &manifest, file.as_bytes()).is_err());
            }
            // полностью случайные байты и случайный base64
            _ => {
                let input = if rng.below(2) == 0 {
                    random_bytes(&mut rng, 4200)
                } else {
                    format!(
                        "untrusted comment: r\n{}\ntrusted comment: r\n{}\n",
                        random_b64(&mut rng, 100),
                        random_b64(&mut rng, 88)
                    )
                    .into_bytes()
                };
                assert!(verify_manifest(&ks, &manifest, &input).is_err());
            }
        }
    }
}

fn random_manifest_text(rng: &mut Rng) -> Vec<u8> {
    let targets = [
        "linux-x86_64",
        "macos-aarch64",
        "any",
        "bsd",
        "windows-x86_64",
    ];
    let mut s = String::from("chervo-release-manifest 1\n");
    s.push_str(&format!(
        "version {}.{}.{}\n",
        rng.below(3),
        rng.below(300),
        rng.below(3)
    ));
    s.push_str(&format!(
        "commit {}\n",
        "0123456789abcdef".repeat(3)[..40].to_owned()
    ));
    for k in 0..=rng.below(5) {
        let sha: String = (0..64)
            .map(|_| b"0123456789abcdef"[rng.below(16)] as char)
            .collect();
        s.push_str(&format!(
            "artifact {} {} {} f{}-{}\n",
            targets[rng.below(targets.len())],
            sha,
            rng.next() % 100_000,
            k,
            rng.below(10)
        ));
    }
    s.into_bytes()
}

#[test]
fn fuzz_smoke_update_manifest() {
    let n = iterations();
    println!(
        "fuzz_smoke_update_manifest: os={} iterations={n}",
        std::env::consts::OS
    );
    let mut rng = Rng(fuzz_seed(0xA11C_E0F0_0D5E_ED03));
    let valid = sample_manifest_bytes();
    let mut oks = 0u64;
    for i in 0..n {
        let input = match i % 4 {
            0 => random_bytes(&mut rng, 300),
            1 => mutate(&mut rng, &valid),
            2 => random_manifest_text(&mut rng),
            _ => {
                let t = random_manifest_text(&mut rng);
                mutate(&mut rng, &t)
            }
        };
        if let Ok(m) = Manifest::parse(&input) {
            oks += 1;
            assert_eq!(m.to_canonical_bytes(), input, "каноническая запись != вход");
            assert!(!m.artifacts.is_empty() && m.artifacts.len() <= 32);
        }
    }
    println!("fuzz_smoke_update_manifest: ok-inputs={oks}");
    assert!(oks > 0, "ни один образец не разобрался: генератор сломан");
}
