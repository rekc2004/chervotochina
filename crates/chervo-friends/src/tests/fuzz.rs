//! Fuzz-смоук кодека открытого текста и файла: ни одной паники; каждый `Ok` разбора
//! кодируется обратно в те же байты. Число итераций: `CHERVO_FUZZ_ITERS`.
//! Тест печатает число итераций (приёмка читает его с `--nocapture`).
#![allow(clippy::print_stdout)]

use super::kit::*;
use crate::plain::{decode, encode};
use crate::vault::{open, seal};

#[test]
fn fuzz_smoke_vault_plain() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x9E37_79B9_7F4A_7C15);
    let sample = sample();
    let valid = encode(&sample).unwrap().to_vec();
    let key = [0x17u8; 32];
    let file = seal(&key, &sample).unwrap();
    let mut ok_plain = 0u64;
    let mut ok_file = 0u64;
    for _ in 0..n {
        // открытый текст
        let input = match rng.below(3) {
            0 => {
                let len = rng.below(400);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &valid),
        };
        if let Ok(d) = decode(&input) {
            ok_plain += 1;
            assert_eq!(encode(&d).unwrap().to_vec(), input, "Ok не канонический");
        }
        // файл целиком
        let f = match rng.below(3) {
            0 => {
                let len = rng.below(300);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &file),
        };
        if open(&key, &f).is_ok() {
            ok_file += 1;
            assert_eq!(f, file, "изменённый файл принят");
        }
    }
    println!(
        "fuzz_smoke_vault_plain: итераций {n}, открытый текст принят {ok_plain}, файл принят {ok_file}"
    );
}
