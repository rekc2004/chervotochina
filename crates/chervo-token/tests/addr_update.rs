//! Токен обновления адреса (`CHA1…`): выпуск, разбор, проверка подписи, границы.
//! Наборы `PublishSet` строятся только через `OwnAddrs`; нестандартные двоичные записи
//! собираются вручную независимым построителем.

mod common;

use std::net::SocketAddr;

use chervo_addr::{LocalSnapshot, OwnAddrs, PublishCtx, PublishSet, RouteSources, UpdateAddr};
use chervo_identity::{PairId, PairKey, PublicKey, SignDomain};
use chervo_token::{
    ADDR_UPDATE_MAX_LEN, ADDR_UPDATE_MIN_LEN, FLAG_HINT, FLAG_SHORT_LIVED, MAX_TOKEN_TEXT_LEN,
    SignedAddrUpdate, Token, TokenError, decode, decode_addr_update_bin, encode_addr_update_bytes,
    encode_invite_bytes, issue_addr_update,
};
use common::*;

const NOW: u64 = 1_000_000;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn snapshot(v4: Option<&str>, v6: Option<&str>, listen: &[&str]) -> LocalSnapshot {
    LocalSnapshot {
        route: RouteSources {
            v4: v4.map(|s| s.parse().unwrap()),
            v6: v6.map(|s| s.parse().unwrap()),
        },
        listen: listen.iter().map(|s| sa(s)).collect(),
    }
}

/// Одна запись: белый IPv4, флаги 0.
fn simple_set() -> PublishSet {
    let mut o = OwnAddrs::new();
    o.set_local(snapshot(Some("8.8.4.4"), None, &["0.0.0.0:4000"]));
    o.publishable(PublishCtx::default(), NOW)
}

/// Три записи: подсказка (hint), глобальный IPv6 (short_lived), частный IPv4.
fn rich_set() -> PublishSet {
    let mut o = OwnAddrs::new();
    o.set_local(snapshot(
        Some("192.168.1.2"),
        Some("2606:4700::7"),
        &["0.0.0.0:4000", "[::]:4001"],
    ));
    o.observe(
        PairId::from_bytes([1; 16]),
        sa("8.8.8.8:5000"),
        sa("9.9.9.9:6000"),
        NOW,
    );
    o.publishable(
        PublishCtx {
            include_lan: true,
            path_source: None,
        },
        NOW,
    )
}

fn empty_set() -> PublishSet {
    OwnAddrs::new().publishable(PublishCtx::default(), NOW)
}

fn as_tuple(a: &UpdateAddr) -> (SocketAddr, bool, bool) {
    (a.addr, a.short_lived, a.hint)
}

fn pub_of(k: &PairKey) -> PublicKey {
    k.public_key()
}

fn addr_token(text: &str) -> SignedAddrUpdate {
    match decode(text) {
        Ok(Token::AddrUpdate(s)) => s,
        Ok(_) => panic!("не токен обновления"),
        Err(e) => panic!("decode: {e}"),
    }
}

// ---------- независимый построитель ----------

/// Запись `[семейство][IP][порт][флаги]`.
fn ent(addr: &str, flags: u8) -> Vec<u8> {
    let mut v = enc_addr(&sa(addr));
    v.push(flags);
    v
}

/// Тело без подписи: `[1][3][seq][n]` и записи; `n` задаётся отдельно от числа записей.
fn body_raw(seq: u64, n: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![1u8, 3u8];
    b.extend_from_slice(&seq.to_be_bytes());
    b.push(n);
    for e in entries {
        b.extend_from_slice(e);
    }
    b
}

fn body_of(seq: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    body_raw(seq, u8::try_from(entries.len()).unwrap(), entries)
}

/// Тело и нулевая подпись: годится для проверок разбора без подписи.
fn unsigned(body: &[u8]) -> Vec<u8> {
    let mut b = body.to_vec();
    b.extend_from_slice(&[0u8; 64]);
    b
}

/// Тело и подпись `signer` в домене `domain` для получателя `recipient`.
fn sign_raw(body: &[u8], signer: &PairKey, recipient: &PublicKey, domain: SignDomain) -> Vec<u8> {
    let mut msg = signer.public_key().to_bytes().to_vec();
    msg.extend_from_slice(&recipient.to_bytes());
    msg.extend_from_slice(body);
    let sig = signer.sign(domain, &msg).unwrap();
    let mut b = body.to_vec();
    b.extend_from_slice(&sig);
    b
}

fn good_entries() -> Vec<Vec<u8>> {
    vec![ent("8.8.8.8:4000", 0)]
}

fn bin_err(b: &[u8]) -> Option<TokenError> {
    decode_addr_update_bin(b).err()
}

fn text_err(b: &[u8]) -> Option<TokenError> {
    decode_err(&encode_addr_update_bytes(b))
}

/// Ошибка и в двоичном, и в текстовом разборе, одинаковая.
fn both_err(b: &[u8]) -> Option<TokenError> {
    let e = bin_err(b);
    assert_eq!(e, text_err(b), "двоичный и текстовый разбор расходятся");
    e
}

// ---------- тесты ----------

#[test]
fn addr_update_roundtrip() {
    let (a, b) = (key(), key());
    let set = rich_set();
    assert_eq!(set.as_slice().len(), 3);
    let issued = issue_addr_update(&a, &pub_of(&b), 77, &set).unwrap();
    assert_eq!(issued.seq(), 77);
    let text = issued.text();
    assert!(text.starts_with("CHA1"));
    let upd = addr_token(&text).verify(&pub_of(&a), &pub_of(&b)).unwrap();
    assert_eq!(upd.seq(), 77);
    let got: Vec<_> = upd.addrs().iter().map(as_tuple).collect();
    let want: Vec<_> = set.as_slice().iter().map(as_tuple).collect();
    assert_eq!(got, want);
    // флаги переданы: hint у первого, short_lived у второго
    assert_eq!(got.first().map(|g| g.2), Some(true));
    assert_eq!(got.get(1).map(|g| g.1), Some(true));
    // минимальный размер: одна запись IPv4
    let one = issue_addr_update(&a, &pub_of(&b), 1, &simple_set()).unwrap();
    assert_eq!(one.bytes().len(), ADDR_UPDATE_MIN_LEN);
}

#[test]
fn addr_update_bin_equals_text_payload() {
    let (a, b) = (key(), key());
    let issued = issue_addr_update(&a, &pub_of(&b), 5, &rich_set()).unwrap();
    assert_eq!(text_bytes(&issued.text()), issued.bytes());
    let from_bin = decode_addr_update_bin(issued.bytes())
        .unwrap()
        .verify(&pub_of(&a), &pub_of(&b))
        .unwrap();
    let from_text = addr_token(&issued.text())
        .verify(&pub_of(&a), &pub_of(&b))
        .unwrap();
    assert_eq!(from_bin.seq(), from_text.seq());
    assert_eq!(
        from_bin.addrs().iter().map(as_tuple).collect::<Vec<_>>(),
        from_text.addrs().iter().map(as_tuple).collect::<Vec<_>>()
    );
}

#[test]
fn addr_update_text_whitespace_and_case() {
    let (a, b) = (key(), key());
    let text = issue_addr_update(&a, &pub_of(&b), 9, &rich_set())
        .unwrap()
        .text();
    let lower = text.to_ascii_lowercase();
    let mut spaced = String::new();
    for (i, c) in text.chars().enumerate() {
        spaced.push(c);
        match i % 11 {
            3 => spaced.push(' '),
            7 => spaced.push('\n'),
            9 => spaced.push_str("\t\r"),
            _ => {}
        }
    }
    for variant in [lower, spaced, format!("  {text}\n"), format!("\n{text}  ")] {
        let upd = addr_token(&variant)
            .verify(&pub_of(&a), &pub_of(&b))
            .unwrap();
        assert_eq!(upd.seq(), 9);
    }
    // длина проверяется до всего остального
    let long = format!("{text}{}", " ".repeat(MAX_TOKEN_TEXT_LEN));
    assert_eq!(decode_err(&long), Some(TokenError::TooLong));
}

#[test]
fn addr_update_foreign_pair_rejected() {
    let (a, b) = (key(), key());
    let (c, d) = (key(), key());
    let issued = issue_addr_update(&a, &pub_of(&b), 3, &simple_set()).unwrap();
    let signed = addr_token(&issued.text());
    assert!(signed.verify(&pub_of(&a), &pub_of(&b)).is_ok());
    // ключи совсем другой пары
    assert_eq!(
        signed.verify(&pub_of(&c), &pub_of(&d)).err(),
        Some(TokenError::BadSignature)
    );
    // подписант верный, получатель чужой; и наоборот
    assert_eq!(
        signed.verify(&pub_of(&a), &pub_of(&d)).err(),
        Some(TokenError::BadSignature)
    );
    assert_eq!(
        signed.verify(&pub_of(&c), &pub_of(&b)).err(),
        Some(TokenError::BadSignature)
    );
}

#[test]
fn addr_update_wrong_recipient_rejected() {
    // один подписант (его ключ повторно в двух парах), разные получатели
    let a = key();
    let (b1, b2) = (key(), key());
    let for_b1 = issue_addr_update(&a, &pub_of(&b1), 3, &simple_set()).unwrap();
    let signed = addr_token(&for_b1.text());
    assert!(signed.verify(&pub_of(&a), &pub_of(&b1)).is_ok());
    assert_eq!(
        signed.verify(&pub_of(&a), &pub_of(&b2)).err(),
        Some(TokenError::BadSignature)
    );
}

#[test]
fn addr_update_swapped_roles_rejected() {
    let (a, b) = (key(), key());
    let signed = addr_token(
        &issue_addr_update(&a, &pub_of(&b), 3, &simple_set())
            .unwrap()
            .text(),
    );
    assert_eq!(
        signed.verify(&pub_of(&b), &pub_of(&a)).err(),
        Some(TokenError::BadSignature)
    );
    // токен, выпущенный в обратную сторону, подходит только обратной паре ролей
    let back = addr_token(
        &issue_addr_update(&b, &pub_of(&a), 3, &simple_set())
            .unwrap()
            .text(),
    );
    assert!(back.verify(&pub_of(&b), &pub_of(&a)).is_ok());
    assert!(back.verify(&pub_of(&a), &pub_of(&b)).is_err());
}

#[test]
fn addr_update_any_byte_flip_rejected() {
    let (a, b) = (key(), key());
    let issued = issue_addr_update(&a, &pub_of(&b), 3, &rich_set()).unwrap();
    let good = issued.bytes().to_vec();
    for i in 0..good.len() {
        for mask in [1u8 << (i % 8), 0xFF] {
            let mut m = good.clone();
            m[i] ^= mask;
            let rejected = match decode_addr_update_bin(&m) {
                Err(_) => true,
                Ok(s) => s.verify(&pub_of(&a), &pub_of(&b)).is_err(),
            };
            assert!(rejected, "байт {i}, маска {mask:#x} принят");
        }
    }
}

#[test]
fn addr_update_every_truncation_rejected() {
    let (a, b) = (key(), key());
    let good = issue_addr_update(&a, &pub_of(&b), 3, &rich_set())
        .unwrap()
        .bytes()
        .to_vec();
    for len in 0..good.len() {
        assert!(bin_err(&good[..len]).is_some(), "двоичный префикс {len}");
        assert!(text_err(&good[..len]).is_some(), "текстовый префикс {len}");
    }
    // текст, обрезанный по символам, тоже не принимается
    let text = encode_addr_update_bytes(&good);
    for len in 4..text.len() {
        assert!(decode_err(&text[..len]).is_some(), "текст {len}");
    }
}

#[test]
fn addr_update_trailing_bytes_rejected() {
    let (a, b) = (key(), key());
    let good = issue_addr_update(&a, &pub_of(&b), 3, &simple_set())
        .unwrap()
        .bytes()
        .to_vec();
    for extra in [1usize, 2, 7, 8, 20, 64] {
        let mut m = good.clone();
        m.extend(std::iter::repeat_n(0u8, extra));
        assert_eq!(both_err(&m), Some(TokenError::Malformed), "+{extra}");
        let mut m = good.clone();
        m.extend(std::iter::repeat_n(0xA5u8, extra));
        assert_eq!(both_err(&m), Some(TokenError::Malformed), "+{extra} (A5)");
    }
}

#[test]
fn addr_update_every_wrong_length() {
    for n in 1..=8usize {
        let entries: Vec<Vec<u8>> = (0..n)
            .map(|i| ent(&format!("8.8.8.{}:4000", i + 1), 0))
            .collect();
        let full = unsigned(&body_of(1, &entries));
        assert_eq!(full.len(), 75 + 8 * n);
        assert!(decode_addr_update_bin(&full).is_ok());
        for len in 0..=300usize {
            let mut m = full.clone();
            m.resize(len, 0);
            let r = bin_err(&m);
            if len == full.len() {
                assert!(r.is_none(), "n={n}");
            } else {
                assert_eq!(r, Some(TokenError::Malformed), "n={n} len={len}");
            }
        }
    }
}

#[test]
fn addr_update_count_rules() {
    // n = 0 при допустимой общей длине
    let mut z = body_raw(1, 0, &[]);
    z.resize(ADDR_UPDATE_MIN_LEN - 64, 0);
    assert_eq!(both_err(&unsigned(&z)), Some(TokenError::Malformed));
    // n = 9 при девяти записях
    let nine: Vec<Vec<u8>> = (0..9)
        .map(|i| ent(&format!("8.8.8.{}:4000", i + 1), 0))
        .collect();
    assert_eq!(
        both_err(&unsigned(&body_of(1, &nine))),
        Some(TokenError::Malformed)
    );
    // n = 255
    let mut big = body_raw(1, 255, &good_entries());
    big.resize(100, 0);
    assert_eq!(both_err(&unsigned(&big)), Some(TokenError::Malformed));
    // n больше числа записей
    assert_eq!(
        both_err(&unsigned(&body_raw(1, 2, &good_entries()))),
        Some(TokenError::Malformed)
    );
    // n меньше числа записей
    let two = vec![ent("8.8.8.8:4000", 0), ent("8.8.4.4:4000", 0)];
    assert_eq!(
        both_err(&unsigned(&body_raw(1, 1, &two))),
        Some(TokenError::Malformed)
    );
    // ровно восемь IPv6 допустимы, девять нет
    let v6 = |i: usize| ent(&format!("[2606:4700::{}]:4000", i + 1), 0);
    let eight: Vec<Vec<u8>> = (0..8).map(v6).collect();
    assert!(decode_addr_update_bin(&unsigned(&body_of(1, &eight))).is_ok());
}

#[test]
fn addr_update_addr_rules() {
    let unsigned_of = |e: Vec<u8>| unsigned(&body_of(1, &[e]));
    // порт 0
    assert_eq!(
        both_err(&unsigned_of(ent("8.8.8.8:0", 0))),
        Some(TokenError::BadAddress)
    );
    // неизвестное семейство
    let mut bad_family = ent("8.8.8.8:4000", 0);
    bad_family[0] = 5;
    assert_eq!(
        both_err(&unsigned_of(bad_family)),
        Some(TokenError::Malformed)
    );
    // каждый отвергаемый класс
    for s in [
        "127.0.0.1:1",
        "169.254.1.1:1",
        "100.64.0.1:1",
        "192.0.2.1:1",
        "198.18.0.1:1",
        "240.0.0.1:1",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "0.0.0.0:1",
        "0.1.2.3:1",
        "[::]:1",
        "[::1]:1",
        "[fe80::1]:1",
        "[ff02::1]:1",
        "[2001:db8::1]:1",
        "[::ffff:8.8.8.8]:1",
        "[2002::1]:1",
    ] {
        assert_eq!(
            both_err(&unsigned_of(ent(s, 0))),
            Some(TokenError::BadAddress),
            "{s}"
        );
    }
    // повтор
    let dup = vec![ent("8.8.8.8:4000", 0), ent("8.8.8.8:4000", FLAG_HINT)];
    assert_eq!(
        both_err(&unsigned(&body_of(1, &dup))),
        Some(TokenError::BadAddress)
    );
    // тот же IP на другом порту не повтор
    let not_dup = vec![ent("8.8.8.8:4000", 0), ent("8.8.8.8:4001", 0)];
    assert_eq!(both_err(&unsigned(&body_of(1, &not_dup))), None);
    // частные и глобальные принимаются
    for s in [
        "8.8.8.8:1",
        "10.0.0.1:1",
        "192.168.1.1:65535",
        "[2606:4700::1]:1",
        "[fd00::1]:1",
    ] {
        assert_eq!(both_err(&unsigned_of(ent(s, 0))), None, "{s}");
    }
}

#[test]
fn addr_update_flag_rules() {
    let unsigned_of = |e: Vec<u8>| unsigned(&body_of(1, &[e]));
    for bit in 2..8u8 {
        let flags = 1u8 << bit;
        for s in ["8.8.8.8:1", "[2606:4700::1]:1"] {
            assert_eq!(
                both_err(&unsigned_of(ent(s, flags))),
                Some(TokenError::Malformed),
                "{s} флаги {flags:#x}"
            );
            assert_eq!(
                both_err(&unsigned_of(ent(s, flags | FLAG_HINT))),
                Some(TokenError::Malformed)
            );
        }
    }
    // short_lived на IPv4
    assert_eq!(
        both_err(&unsigned_of(ent("8.8.8.8:1", FLAG_SHORT_LIVED))),
        Some(TokenError::Malformed)
    );
    assert_eq!(
        both_err(&unsigned_of(ent("8.8.8.8:1", FLAG_SHORT_LIVED | FLAG_HINT))),
        Some(TokenError::Malformed)
    );
    // допустимые сочетания
    assert_eq!(both_err(&unsigned_of(ent("8.8.8.8:1", FLAG_HINT))), None);
    for f in [0, FLAG_SHORT_LIVED, FLAG_HINT, FLAG_SHORT_LIVED | FLAG_HINT] {
        assert_eq!(both_err(&unsigned_of(ent("[2606:4700::1]:1", f))), None);
    }
    // флаги проверяются раньше порта и класса адреса
    assert_eq!(
        both_err(&unsigned_of(ent("127.0.0.1:0", 0x80))),
        Some(TokenError::Malformed)
    );
}

#[test]
fn addr_update_seq_zero_rejected() {
    let b = unsigned(&body_of(0, &good_entries()));
    assert_eq!(both_err(&b), Some(TokenError::Malformed));
    let (a, c) = (key(), key());
    assert_eq!(
        issue_addr_update(&a, &pub_of(&c), 0, &simple_set()).err(),
        Some(TokenError::Malformed)
    );
    // seq = 1 и u64::MAX допустимы
    for seq in [1u64, u64::MAX] {
        assert_eq!(both_err(&unsigned(&body_of(seq, &good_entries()))), None);
    }
}

#[test]
fn addr_update_other_domain_rejected() {
    let (a, b) = (key(), key());
    let body = body_of(4, &good_entries());
    let ok = sign_raw(&body, &a, &pub_of(&b), SignDomain::AddressUpdate);
    assert!(
        decode_addr_update_bin(&ok)
            .unwrap()
            .verify(&pub_of(&a), &pub_of(&b))
            .is_ok()
    );
    for d in [
        SignDomain::Invite,
        SignDomain::KeyRevocation,
        SignDomain::InviteAccept,
    ] {
        let wrong = sign_raw(&body, &a, &pub_of(&b), d);
        let parsed = decode_addr_update_bin(&wrong).unwrap();
        assert_eq!(
            parsed.verify(&pub_of(&a), &pub_of(&b)).err(),
            Some(TokenError::BadSignature),
            "{d:?}"
        );
    }
    // подпись одного тела без ключей получателя не подходит
    let mut no_keys = body.clone();
    no_keys.extend_from_slice(&a.sign(SignDomain::AddressUpdate, &body).unwrap());
    assert_eq!(
        decode_addr_update_bin(&no_keys)
            .unwrap()
            .verify(&pub_of(&a), &pub_of(&b))
            .err(),
        Some(TokenError::BadSignature)
    );
}

#[test]
fn addr_update_prefix_kind_mismatch() {
    let (a, b) = (key(), key());
    let good = issue_addr_update(&a, &pub_of(&b), 3, &simple_set())
        .unwrap()
        .bytes()
        .to_vec();
    // CHA1 и вид 1
    let mut as_invite_kind = good.clone();
    as_invite_kind[1] = 1;
    assert_eq!(text_err(&as_invite_kind), Some(TokenError::BadKind));
    assert_eq!(bin_err(&as_invite_kind), Some(TokenError::BadKind));
    // CHA1 и вид 2
    let mut as_rev_kind = good.clone();
    as_rev_kind[1] = 2;
    assert_eq!(text_err(&as_rev_kind), Some(TokenError::BadKind));
    // CHV1 и вид 3; CHR1 и вид 3
    assert_eq!(
        decode_err(&encode_invite_bytes(&good)),
        Some(TokenError::BadKind)
    );
    assert_eq!(
        decode_err(&chervo_token::encode_revocation_bytes(&good)),
        Some(TokenError::BadKind)
    );
    // чужие префиксы
    let rest = &encode_addr_update_bytes(&good)[4..];
    for p in ["CHA2", "CHA0", "CHAA", "CHB1", "cha"] {
        assert_eq!(
            decode_err(&format!("{p}{rest}")),
            Some(TokenError::BadPrefix),
            "{p}"
        );
    }
}

#[test]
fn addr_update_unknown_version() {
    let (a, b) = (key(), key());
    let mut m = issue_addr_update(&a, &pub_of(&b), 3, &simple_set())
        .unwrap()
        .bytes()
        .to_vec();
    for v in [0u8, 2, 0xFF] {
        m[0] = v;
        assert_eq!(both_err(&m), Some(TokenError::UnsupportedVersion), "v{v}");
    }
}

#[test]
fn addr_update_max_size() {
    let (a, b) = (key(), key());
    let v6: Vec<Vec<u8>> = (0..8)
        .map(|i| ent(&format!("[2606:4700::{}]:4000", i + 1), FLAG_SHORT_LIVED))
        .collect();
    let signed = sign_raw(
        &body_of(11, &v6),
        &a,
        &pub_of(&b),
        SignDomain::AddressUpdate,
    );
    assert_eq!(signed.len(), ADDR_UPDATE_MAX_LEN);
    assert_eq!(signed.len(), 235);
    let text = encode_addr_update_bytes(&signed);
    assert!(text.len() <= 2048);
    assert_eq!(text.len(), 380);
    let upd = addr_token(&text).verify(&pub_of(&a), &pub_of(&b)).unwrap();
    assert_eq!(upd.seq(), 11);
    assert_eq!(upd.addrs().len(), 8);
    assert!(upd.addrs().iter().all(|u| u.short_lived && !u.hint));
    // на байт длиннее предела
    let mut over = signed.clone();
    over.push(0);
    assert_eq!(both_err(&over), Some(TokenError::Malformed));
}

#[test]
fn issue_addr_update_rules() {
    let (a, b) = (key(), key());
    // seq 0
    assert_eq!(
        issue_addr_update(&a, &pub_of(&b), 0, &simple_set()).err(),
        Some(TokenError::Malformed)
    );
    // пустой набор
    assert_eq!(
        issue_addr_update(&a, &pub_of(&b), 1, &empty_set()).err(),
        Some(TokenError::BadAddress)
    );
    // получатель = подписант
    assert_eq!(
        issue_addr_update(&a, &pub_of(&a), 1, &simple_set()).err(),
        Some(TokenError::BadKey)
    );
    // порядок: сначала seq, затем набор, затем ключ
    assert_eq!(
        issue_addr_update(&a, &pub_of(&a), 0, &empty_set()).err(),
        Some(TokenError::Malformed)
    );
    // нормальный выпуск разбирается и проверяется
    let issued = issue_addr_update(&a, &pub_of(&b), u64::MAX, &rich_set()).unwrap();
    assert_eq!(issued.seq(), u64::MAX);
    assert!(issued.bytes().len() >= ADDR_UPDATE_MIN_LEN);
    assert!(issued.bytes().len() <= ADDR_UPDATE_MAX_LEN);
    // два выпуска с одним seq дают проверяемые токены (подпись Ed25519 детерминирована)
    let again = issue_addr_update(&a, &pub_of(&b), u64::MAX, &rich_set()).unwrap();
    assert!(
        decode_addr_update_bin(again.bytes())
            .unwrap()
            .verify(&pub_of(&a), &pub_of(&b))
            .is_ok()
    );
}

#[test]
fn addr_update_debug_is_redacted() {
    let (a, b) = (key(), key());
    let issued = issue_addr_update(&a, &pub_of(&b), 3, &rich_set()).unwrap();
    let signed = addr_token(&issued.text());
    let upd = signed.verify(&pub_of(&a), &pub_of(&b)).unwrap();
    assert_eq!(format!("{issued:?}"), "IssuedAddrUpdate(..)");
    assert_eq!(format!("{signed:?}"), "SignedAddrUpdate(..)");
    assert_eq!(format!("{upd:?}"), "AddrUpdate(..)");
    assert_eq!(format!("{:?}", rich_set()), "PublishSet(..)");
}
