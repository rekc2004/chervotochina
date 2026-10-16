//! Fuzz-смоук кодека открытого текста и файла: ни одной паники; каждый `Ok` разбора
//! v2 кодируется обратно в те же байты, v1 переходит в v2 и дальше канонично. Число итераций: `CHERVO_FUZZ_ITERS`.
//! Тест печатает число итераций (приёмка читает его с `--nocapture`).
#![allow(clippy::print_stdout)]

use super::kit::*;
use super::plain::v1_blob;
use crate::plain::{decode, encode};
use crate::vault::{open, seal};

#[test]
fn fuzz_smoke_vault_plain() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x9E37_79B9_7F4A_7C15);
    let sample = sample();
    let valid = encode(&sample).unwrap().to_vec();
    let mut old = friend(3);
    old.name = "abc".into();
    let valid_v1 = v1_blob(&old);
    assert!(decode(&valid_v1).is_ok());
    let key = [0x17u8; 32];
    let file = seal(&key, &sample).unwrap();
    let mut ok_plain = 0u64;
    let mut ok_v1 = 0u64;
    let mut ok_file = 0u64;
    for _ in 0..n {
        // открытый текст
        let input = match rng.below(4) {
            0 => {
                let len = rng.below(400);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &valid_v1),
            _ => mutate(&mut rng, &valid),
        };
        if let Ok(d) = decode(&input) {
            ok_plain += 1;
            let again = encode(&d).unwrap().to_vec();
            if input.first() == Some(&1) {
                // v1: запись даёт v2, и тот канонически читается обратно
                ok_v1 += 1;
                assert_eq!(again.first(), Some(&2));
                assert_eq!(encode(&decode(&again).unwrap()).unwrap().to_vec(), again);
            } else {
                assert_eq!(again, input, "Ok не канонический");
            }
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
        "fuzz_smoke_vault_plain: итераций {n}, открытый текст принят {ok_plain} (из них v1 {ok_v1}), файл принят {ok_file}"
    );
}
