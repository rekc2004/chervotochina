//! Fuzz-смоук на stable без зависимостей: ГПСЧ xorshift64* с фиксированным зерном.
//! Свойство: ни одной паники; каждый `Ok` после `decode` перекодируется в тот же канонический текст.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug).

mod common;

use chervo_token::{
    InviteeSession, M1_LEN, RevocationReason, Token, decode, decode_addr_update_bin,
    decode_decision, encode_addr_update_bytes, encode_invite_bytes, encode_revocation_bytes,
    issue_addr_update, issue_invite, issue_revocation,
};
use common::*;

const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Каноническая форма введённого текста: без пробельных символов, заглавные.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Свойство перекодирования для принятого текста.
fn check_canonical(input: &str, token: &Token) {
    let norm = normalize(input);
    let bytes = b32_decode(&norm[4..]);
    let again = match token {
        Token::Invite(_) => encode_invite_bytes(&bytes),
        Token::Revocation(_) => encode_revocation_bytes(&bytes),
        Token::AddrUpdate(_) => encode_addr_update_bytes(&bytes),
        _ => panic!("неизвестный вид"),
    };
    assert_eq!(again, norm, "принятый текст не канонический");
}

#[test]
fn fuzz_smoke_decode() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x1234_5678_9ABC_DEF0);
    let a = key();
    let (_p, invite) = issue_invite(&draft(900), &a).unwrap();
    let revocation = issue_revocation(&a, RevocationReason::Rekey, 77).unwrap();
    let inv_bytes = text_bytes(&invite);
    let rev_bytes = text_bytes(&revocation);
    let mut ok = 0u64;
    for i in 0..n {
        let (input, from_bytes): (String, bool) = match rng.below(6) {
            // случайные байты как строка
            0 => {
                let len = rng.below(64);
                (String::from_utf8_lossy(&rng.bytes(len)).into_owned(), false)
            }
            // случайная строка base32 с префиксом
            1 => {
                let prefix = ["CHV1", "CHR1", "chv1", "XXXX"][rng.below(4)];
                let len = rng.below(600);
                let body: String = (0..len).map(|_| ALPHA[rng.below(32)] as char).collect();
                (format!("{prefix}{body}"), false)
            }
            // мутации двоичного приглашения
            2 | 3 => {
                let m = mutate(&mut rng, &inv_bytes);
                (encode_invite_bytes(&m), true)
            }
            // мутации двоичного отзыва
            4 => {
                let m = mutate(&mut rng, &rev_bytes);
                (encode_revocation_bytes(&m), true)
            }
            // текстовые мутации и немутированные образцы
            _ => {
                let src = if rng.below(2) == 0 {
                    &invite
                } else {
                    &revocation
                };
                let mut t = src.clone().into_bytes();
                if rng.below(3) != 0 {
                    t = mutate(&mut rng, &t);
                }
                let s = String::from_utf8_lossy(&t).into_owned();
                (s, false)
            }
        };
        let _ = from_bytes;
        // итерация 0 всегда подаёт исходный образец приглашения
        let input = if i == 0 { invite.clone() } else { input };
        if let Ok(tok) = decode(&input) {
            ok += 1;
            check_canonical(&input, &tok);
        }
        if i % 7919 == 0 {
            // немутированные образцы всегда принимаются
            assert!(decode(&invite).is_ok());
            assert!(decode(&revocation).is_ok());
        }
    }
    assert!(ok > 0, "ни одного принятого образца");
    println!("fuzz_smoke_decode: итераций {n}, принято {ok}");
}

#[test]
fn fuzz_smoke_m1() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0xDEAD_BEEF_0BAD_F00D);
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let mut valid = h.m1.to_vec();
    let mut ok = 0u64;
    let mut rejected = 0u64;
    for _ in 0..n {
        let input = match rng.below(4) {
            0 => rng.bytes(M1_LEN),
            1 => {
                let len = rng.below(500);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &valid),
        };
        match h.pending.on_m1(&input) {
            Ok(_) => {
                // только точная копия валидного M1; приглашение потрачено, начинаем заново
                assert_eq!(input, valid);
                ok += 1;
                h = honest();
                h.pending.begin_session(1_000_100).unwrap();
                valid = h.m1.to_vec();
            }
            Err(_) => rejected += 1,
        }
    }
    // после всех отказов состояние живо: настоящий M1 ещё принимается
    assert!(h.pending.on_m1(&h.m1).is_ok());
    println!("fuzz_smoke_m1: итераций {n}, принято {ok}, отказов {rejected}");
}

#[test]
fn fuzz_smoke_m2() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x0F0F_1234_5678_9ABC);
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let (m2, _sas, _keys) = h.pending.on_m1(&h.m1).unwrap();
    let token = invite_of(&h.text);
    let mut ok = 0u64;
    for _ in 0..n {
        let input = match rng.below(3) {
            0 => rng.bytes(34),
            1 => {
                let len = rng.below(100);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &m2),
        };
        // решение: ни паники на любом вводе
        let _ = decode_decision(&input);
        let (s, _m1) = InviteeSession::start(&token, &h.b_key).unwrap();
        if s.on_m2(&input).is_ok() {
            assert_eq!(input, m2.to_vec());
            ok += 1;
        }
    }
    println!("fuzz_smoke_m2: итераций {n}, принято {ok}");
}

#[test]
fn fuzz_smoke_revocation() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0xA5A5_5A5A_C3C3_3C3C);
    let k = key();
    let good = text_bytes(&issue_revocation(&k, RevocationReason::Removed, 9).unwrap());
    let mut ok = 0u64;
    for i in 0..n {
        let drawn = match rng.below(3) {
            0 => {
                let len = rng.below(200);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &good),
        };
        // итерация 0 всегда подаёт исходный образец: принятый вход гарантирован
        let input = if i == 0 { good.clone() } else { drawn };
        let text = encode_revocation_bytes(&input);
        if let Ok(tok) = decode(&text) {
            ok += 1;
            assert!(matches!(tok, Token::Revocation(_)));
            check_canonical(&text, &tok);
            assert_eq!(input, good);
        }
    }
    assert!(n == 0 || ok > 0, "ни одного принятого образца");
    println!("fuzz_smoke_revocation: итераций {n}, принято {ok}");
}

// ---------- токен обновления адреса и ADDR_INFO ----------

fn fuzz_set() -> chervo_addr::PublishSet {
    let mut o = chervo_addr::OwnAddrs::new();
    o.set_local(chervo_addr::LocalSnapshot {
        route: chervo_addr::RouteSources {
            v4: Some("192.168.1.2".parse().unwrap()),
            v6: Some("2606:4700::7".parse().unwrap()),
        },
        listen: vec![
            "0.0.0.0:4000".parse().unwrap(),
            "[::]:4001".parse().unwrap(),
        ],
    });
    o.observe(
        chervo_identity::PairId::from_bytes([1; 16]),
        "8.8.8.8:5000".parse().unwrap(),
        "9.9.9.9:6000".parse().unwrap(),
        1_000,
    );
    o.publishable(chervo_addr::PublishCtx { include_lan: true }, 1_000)
}

#[test]
fn fuzz_smoke_addr_update() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(0x5EED_ADD2_0123_4567);
    let (a, b) = (key(), key());
    let (pa, pb) = (a.public_key(), b.public_key());
    let good = issue_addr_update(&a, &pb, 42, &fuzz_set())
        .unwrap()
        .bytes()
        .to_vec();
    let good_text = encode_addr_update_bytes(&good);
    let mut ok_bin = 0u64;
    let mut ok_text = 0u64;
    let mut verified = 0u64;
    for i in 0..n {
        // двоичный путь
        let m = match rng.below(4) {
            0 => {
                let len = rng.below(300);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, &good),
        };
        let m = if i == 0 { good.clone() } else { m };
        if let Ok(signed) = decode_addr_update_bin(&m) {
            ok_bin += 1;
            assert!((83..=235).contains(&m.len()));
            if signed.verify(&pa, &pb).is_ok() {
                verified += 1;
                assert_eq!(m, good, "подпись приняла изменённые байты");
            }
            // принятые байты перекодируются в принятый текст
            assert!(decode(&encode_addr_update_bytes(&m)).is_ok());
        }
        // текстовый путь
        let text = match rng.below(5) {
            0 => {
                let len = rng.below(600);
                let body: String = (0..len).map(|_| ALPHA[rng.below(32)] as char).collect();
                format!("CHA1{body}")
            }
            1 => {
                let len = rng.below(64);
                String::from_utf8_lossy(&rng.bytes(len)).into_owned()
            }
            2 => {
                let mut t = good_text.clone().into_bytes();
                t = mutate(&mut rng, &t);
                String::from_utf8_lossy(&t).into_owned()
            }
            _ => encode_addr_update_bytes(&mutate(&mut rng, &good)),
        };
        let text = if i == 0 { good_text.clone() } else { text };
        if let Ok(tok) = decode(&text) {
            ok_text += 1;
            assert!(matches!(tok, Token::AddrUpdate(_)));
            check_canonical(&text, &tok);
        }
        if i % 7919 == 0 {
            assert!(decode(&good_text).is_ok());
        }
    }
    assert!(n == 0 || (ok_bin > 0 && ok_text > 0 && verified > 0));
    println!(
        "fuzz_smoke_addr_update: итераций {n}, принято двоичных {ok_bin}, текстов {ok_text}, подпись сошлась {verified}"
    );
}

#[test]
fn fuzz_smoke_addr_info() {
    use chervo_token::addr_flow::{decode_addr_info, encode_addr_info};
    let n = fuzz_iters();
    let mut rng = XorShift::new(0xADD2_F00D_BEEF_0042);
    let (a, b) = (key(), key());
    let upd = issue_addr_update(&a, &b.public_key(), 7, &fuzz_set()).unwrap();
    let frames = [
        encode_addr_info("8.8.8.8:443".parse().unwrap(), None).unwrap(),
        encode_addr_info("8.8.8.8:443".parse().unwrap(), Some(&upd)).unwrap(),
        encode_addr_info("[2606:4700::1]:443".parse().unwrap(), Some(&upd)).unwrap(),
    ];
    let (pa, pb) = (a.public_key(), b.public_key());
    let mut ok = 0u64;
    for i in 0..n {
        let src = &frames[rng.below(frames.len())];
        let m = match rng.below(4) {
            0 => {
                let len = rng.below(300);
                rng.bytes(len)
            }
            _ => mutate(&mut rng, src),
        };
        let m = if i == 0 { frames[1].clone() } else { m };
        if let Ok((obs, update)) = decode_addr_info(&m) {
            ok += 1;
            assert!((11..=258).contains(&m.len()));
            assert_ne!(obs.port(), 0);
            if let Some(u) = update {
                let _ = u.verify(&pa, &pb);
            }
        }
    }
    assert!(n == 0 || ok > 0);
    println!("fuzz_smoke_addr_info: итераций {n}, принято {ok}");
}
