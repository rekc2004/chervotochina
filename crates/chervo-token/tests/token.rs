mod common;

use chervo_identity::{
    GuestSecret, KK_PROLOGUE_TAG, KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_TAG_LABEL, SignDomain,
};
use chervo_token::{
    CLOCK_TOLERANCE_SECS, COMMIT_TAG, InviteDraft, MAX_TOKEN_TEXT_LEN, SAS_TAG, TOKEN_HASH_TAG,
    TokenError, decode, encode_invite_bytes, encode_revocation_bytes, issue_invite,
};
use common::*;

fn good() -> (chervo_identity::PairKey, String, Vec<u8>) {
    let k = key();
    let (_p, text) = issue_invite(&draft(900), &k).unwrap();
    let bytes = text_bytes(&text);
    (k, text, bytes)
}

#[test]
fn invite_roundtrip() {
    let k = key();
    let d = InviteDraft {
        issued_at: 5_000,
        ttl_secs: 600,
        addrs: vec![addr("203.0.113.7:4455"), addr("[2001:db8::1]:9999")],
    };
    let (pending, text) = issue_invite(&d, &k).unwrap();
    let t = invite_of(&text);
    assert_eq!(t.issued_at(), 5_000);
    assert_eq!(t.expires_at(), 5_600);
    assert_eq!(pending.expires_at(), 5_600);
    assert_eq!(t.inviter_ed(), k.public_key());
    assert_eq!(t.inviter_x(), k.kx_public());
    assert_eq!(t.addrs(), d.addrs.as_slice());
    let g = t.guest_secret().unwrap();
    assert_eq!(g.public(), pending.guest_public());
    assert_ne!(g.public(), k.kx_public());
    // два токена одного ключа различны (случайные g и r_A)
    let (_p2, text2) = issue_invite(&d, &k).unwrap();
    assert_ne!(text, text2);
}

#[test]
fn invite_text_canonical() {
    let (_k, text, bytes) = good();
    assert!(text.starts_with("CHV1"));
    assert!(
        text[4..]
            .bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
    );
    assert!(!text.contains('='));
    assert_eq!(text, encode_invite_bytes(&bytes));
    assert_eq!(b32_encode(&bytes), text[4..]);
    assert_eq!(bytes.len(), 218);
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], 1);
}

#[test]
fn invite_text_whitespace_and_case() {
    let (k, text, _) = good();
    let mut messy = String::new();
    for (i, c) in text.chars().enumerate() {
        if i % 7 == 0 {
            messy.push(['\n', ' ', '\t', '\r'][(i / 7) % 4]);
        }
        messy.push(if i % 2 == 0 {
            c.to_ascii_lowercase()
        } else {
            c
        });
    }
    let t = invite_of(&messy);
    assert_eq!(t.inviter_ed(), k.public_key());
    let t0 = invite_of(&text);
    assert_eq!(
        t.guest_secret().unwrap().public(),
        t0.guest_secret().unwrap().public()
    );
    // пробельные символы внутри префикса тоже удаляются
    assert!(decode(&format!(" c h\nv1{}", &text[4..])).is_ok());
}

#[test]
fn invite_any_byte_flip_rejected() {
    let (_k, _t, bytes) = good();
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= mask;
            assert!(
                decode(&encode_invite_bytes(&b)).is_err(),
                "байт {i} маска {mask:#x} принят"
            );
        }
    }
}

#[test]
fn invite_every_truncation_rejected() {
    let (_k, text, bytes) = good();
    for n in 0..bytes.len() {
        assert!(
            decode(&encode_invite_bytes(&bytes[..n])).is_err(),
            "обрезка до {n} принята"
        );
    }
    // обрезка текста по символам
    for n in 0..text.len() {
        assert!(decode(&text[..n]).is_err(), "обрезка текста до {n} принята");
    }
}

#[test]
fn invite_trailing_bytes_rejected() {
    let (_k, _t, bytes) = good();
    for extra in 1..=70usize {
        let mut b = bytes.clone();
        b.extend(std::iter::repeat_n(0u8, extra));
        assert!(
            matches!(decode(&encode_invite_bytes(&b)), Err(TokenError::Malformed)),
            "лишние {extra} байт"
        );
    }
}

#[test]
fn invite_bad_base32() {
    let (_k, text, bytes) = good();
    for bad in ['0', '1', '8', '9', '=', '-', '!', '\0', '\u{7f}'] {
        let t = format!("{text}{bad}");
        assert_eq!(decode_err(&t), Some(TokenError::BadEncoding), "{bad:?}");
        let mid = format!("{}{bad}{}", &text[..20], &text[21..]);
        assert_eq!(decode_err(&mid), Some(TokenError::BadEncoding), "{bad:?}");
    }
    // длина по модулю 8 из {1, 3, 6}
    let n = text.len() - 4;
    for extra in 1..=8usize {
        let t = format!("{text}{}", "A".repeat(extra));
        let m = (n + extra) % 8;
        if matches!(m, 1 | 3 | 6) {
            assert_eq!(decode_err(&t), Some(TokenError::BadEncoding), "mod {m}");
        }
    }
    for cut in 1..=8usize {
        let t = &text[..text.len() - cut];
        let m = (n - cut) % 8;
        if matches!(m, 1 | 3 | 6) {
            assert_eq!(decode_err(t), Some(TokenError::BadEncoding), "mod {m}");
        }
    }
    // ненулевые хвостовые биты: у 218 байт один неиспользуемый бит
    let unused = (5 - (bytes.len() * 8) % 5) % 5;
    assert!(unused > 0);
    let last = text.as_bytes()[text.len() - 1];
    let v = if last.is_ascii_uppercase() {
        usize::from(last - b'A')
    } else {
        usize::from(last - b'2') + 26
    };
    assert_eq!(v & ((1 << unused) - 1), 0, "канонический хвост нулевой");
    let v2 = v | 1;
    let sym = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[v2] as char;
    let t = format!("{}{sym}", &text[..text.len() - 1]);
    assert_eq!(decode_err(&t), Some(TokenError::BadEncoding));
    // не-ASCII
    assert_eq!(
        decode_err(&format!("{text}Я")),
        Some(TokenError::BadEncoding)
    );
}

#[test]
fn invite_wrong_prefix() {
    let (_k, text, _) = good();
    let rest = &text[4..];
    for p in ["CHV2", "CHX1", "XHV1", "CHV0", "ABCD", "chv", "CH", "C", ""] {
        assert_eq!(
            decode_err(&format!("{p}{rest}")),
            Some(TokenError::BadPrefix),
            "{p:?}"
        );
    }
    assert_eq!(decode_err(""), Some(TokenError::BadPrefix));
    assert_eq!(decode_err("   "), Some(TokenError::BadPrefix));
}

#[test]
fn invite_kind_mismatch() {
    let (_k, text, bytes) = good();
    assert_eq!(
        decode_err(&format!("CHR1{}", &text[4..])),
        Some(TokenError::BadKind)
    );
    let r =
        chervo_token::issue_revocation(&key(), chervo_token::RevocationReason::Removed, 1).unwrap();
    assert_eq!(
        decode_err(&format!("CHV1{}", &r[4..])),
        Some(TokenError::BadKind)
    );
    let mut b = bytes.clone();
    b[1] = 0;
    assert_eq!(
        decode_err(&encode_invite_bytes(&b)),
        Some(TokenError::BadKind)
    );
    b[1] = 3;
    assert_eq!(
        decode_err(&encode_invite_bytes(&b)),
        Some(TokenError::BadKind)
    );
    assert_eq!(
        decode_err(&encode_revocation_bytes(&bytes)),
        Some(TokenError::BadKind)
    );
}

#[test]
fn invite_unknown_version() {
    let (_k, _t, bytes) = good();
    for v in [0u8, 2, 3, 0x80, 0xFF] {
        let mut b = bytes.clone();
        b[0] = v;
        assert_eq!(
            decode_err(&encode_invite_bytes(&b)),
            Some(TokenError::UnsupportedVersion),
            "версия {v}"
        );
    }
    // меньше двух байт
    assert_eq!(decode_err("CHV1"), Some(TokenError::Malformed));
    assert_eq!(
        decode_err(&encode_invite_bytes(&[1])),
        Some(TokenError::Malformed)
    );
}

#[test]
fn invite_too_long_text() {
    let ok_len = format!("CHV1{}", "A".repeat(MAX_TOKEN_TEXT_LEN - 4));
    assert_eq!(ok_len.len(), MAX_TOKEN_TEXT_LEN);
    assert!(!matches!(decode_err(&ok_len), Some(TokenError::TooLong)));
    let long = format!("{ok_len}A");
    assert_eq!(decode_err(&long), Some(TokenError::TooLong));
    // длина проверяется раньше всего прочего, в том числе раньше проверки ASCII
    assert_eq!(
        decode_err(&"Я".repeat(MAX_TOKEN_TEXT_LEN)),
        Some(TokenError::TooLong)
    );
    assert_eq!(
        decode_err(&" ".repeat(MAX_TOKEN_TEXT_LEN + 1)),
        Some(TokenError::TooLong)
    );
}

#[test]
fn invite_bad_signature() {
    let a = key();
    let other = key();
    let f = fields(&a);
    // подпись чужого ключа над тем же телом
    let bytes = signed(&f, &other, SignDomain::Invite);
    assert_eq!(decode_err(&text_of(&bytes)), Some(TokenError::BadSignature));
    // положительный контроль: своя подпись принимается
    let ok = signed(&f, &a, SignDomain::Invite);
    assert!(decode(&text_of(&ok)).is_ok());
}

#[test]
fn invite_other_domain_signature_rejected() {
    let a = key();
    let f = fields(&a);
    for d in [
        SignDomain::InviteAccept,
        SignDomain::KeyRevocation,
        SignDomain::AddressUpdate,
    ] {
        let bytes = signed(&f, &a, d);
        assert_eq!(
            decode_err(&text_of(&bytes)),
            Some(TokenError::BadSignature),
            "{d:?}"
        );
    }
}

#[test]
fn invite_bad_keys() {
    let a = key();
    let sign = |f: &Fields| text_of(&signed(f, &a, SignDomain::Invite));
    // малый порядок X (ноль и единица)
    for bad in [[0u8; 32], {
        let mut v = [0u8; 32];
        v[0] = 1;
        v
    }] {
        let mut f = fields(&a);
        f.a_x = bad;
        assert_eq!(decode_err(&sign(&f)), Some(TokenError::BadKey));
    }
    // невалидный Ed: единичная точка (слабая) и не-точка
    let mut weak = [0u8; 32];
    weak[0] = 1;
    for bad in [weak, [0xFFu8; 32], [0u8; 32]] {
        let mut f = fields(&a);
        f.a_ed = bad;
        assert_eq!(decode_err(&sign(&f)), Some(TokenError::BadKey));
    }
    // G == A_x
    let mut f = fields(&a);
    let g = GuestSecret::generate().unwrap();
    f.g = *g.to_token_bytes();
    f.a_x = g.public().to_bytes();
    assert_eq!(decode_err(&sign(&f)), Some(TokenError::BadKey));
    // контроль: обычные поля проходят
    assert!(decode(&sign(&fields(&a))).is_ok());
}

#[test]
fn invite_addr_rules() {
    let a = key();
    let bad_sets: Vec<(&str, Vec<std::net::SocketAddr>)> = vec![
        ("порт 0", vec![addr("203.0.113.7:0")]),
        ("0.0.0.0", vec![addr("0.0.0.0:4455")]),
        ("::", vec![addr("[::]:4455")]),
        ("multicast v4", vec![addr("224.0.0.1:4455")]),
        ("multicast v6", vec![addr("[ff02::1]:4455")]),
        ("broadcast", vec![addr("255.255.255.255:4455")]),
        ("v4-mapped", vec![addr("[::ffff:1.2.3.4]:4455")]),
        (
            "дубликат",
            vec![addr("203.0.113.7:4455"), addr("203.0.113.7:4455")],
        ),
    ];
    for (name, set) in &bad_sets {
        // выпуск
        let d = InviteDraft {
            issued_at: 1,
            ttl_secs: 900,
            addrs: set.clone(),
        };
        assert_eq!(
            issue_invite(&d, &a).err(),
            Some(TokenError::BadAddress),
            "выпуск: {name}"
        );
        // разбор подписанного токена с теми же адресами
        let f = with_addrs(fields(&a), set);
        assert_eq!(
            decode_err(&text_of(&signed(&f, &a, SignDomain::Invite))),
            Some(TokenError::BadAddress),
            "разбор: {name}"
        );
    }
    // 0 и 9 адресов
    let d0 = InviteDraft {
        issued_at: 1,
        ttl_secs: 900,
        addrs: vec![],
    };
    assert_eq!(issue_invite(&d0, &a).err(), Some(TokenError::BadAddress));
    let nine: Vec<_> = (1..=9)
        .map(|i| addr(&format!("203.0.113.{i}:4455")))
        .collect();
    let d9 = InviteDraft {
        issued_at: 1,
        ttl_secs: 900,
        addrs: nine.clone(),
    };
    assert_eq!(issue_invite(&d9, &a).err(), Some(TokenError::BadAddress));
    let f0 = with_addrs(fields(&a), &[]);
    assert_eq!(
        decode_err(&text_of(&signed(&f0, &a, SignDomain::Invite))),
        Some(TokenError::Malformed)
    );
    let f9 = with_addrs(fields(&a), &nine);
    assert_eq!(
        decode_err(&text_of(&signed(&f9, &a, SignDomain::Invite))),
        Some(TokenError::Malformed)
    );
    // неизвестное семейство
    let mut fx = fields(&a);
    fx.addr_bytes = vec![vec![5, 1, 2, 3, 4, 0x11, 0x5B]];
    assert_eq!(
        decode_err(&text_of(&signed(&fx, &a, SignDomain::Invite))),
        Some(TokenError::BadAddress)
    );
    // допустимые: loopback, частные, link-local, глобальный v6
    let fine = [
        addr("127.0.0.1:1"),
        addr("192.168.1.5:65535"),
        addr("169.254.1.1:7"),
        addr("[fe80::1]:7"),
        addr("[2001:db8::1]:7"),
        addr("203.0.113.7:7"),
        addr("203.0.113.7:8"),
        addr("[::1]:7"),
    ];
    let d = InviteDraft {
        issued_at: 1,
        ttl_secs: 900,
        addrs: fine.to_vec(),
    };
    let (_p, text) = issue_invite(&d, &a).unwrap();
    assert_eq!(invite_of(&text).addrs(), fine.as_slice());
}

#[test]
fn invite_ttl_rules() {
    let a = key();
    for ttl in [0u64, 1, 59, 86_401, u64::MAX] {
        assert_eq!(
            issue_invite(&draft(ttl), &a).err(),
            Some(TokenError::BadTtl),
            "ttl {ttl}"
        );
    }
    for ttl in [60u64, 61, 900, 86_399, 86_400] {
        assert!(issue_invite(&draft(ttl), &a).is_ok(), "ttl {ttl}");
    }
    // переполнение issued_at + ttl
    let d = InviteDraft {
        issued_at: u64::MAX - 10,
        ttl_secs: 60,
        addrs: vec![addr("203.0.113.7:4455")],
    };
    assert_eq!(issue_invite(&d, &a).err(), Some(TokenError::BadTtl));
    // разбор
    let cases: [(u64, u64, bool); 8] = [
        (1000, 1060, true),
        (1000, 1059, false),
        (1000, 1000, false),
        (1000, 900, false),
        (1000, 1000 + 86_400, true),
        (1000, 1001 + 86_400, false),
        (0, 60, true),
        (u64::MAX - 10, u64::MAX, false),
    ];
    for (issued, expires, ok) in cases {
        let mut f = fields(&a);
        f.issued = issued;
        f.expires = expires;
        let r = decode_err(&text_of(&signed(&f, &a, SignDomain::Invite)));
        if ok {
            assert_eq!(r, None, "{issued}..{expires}");
        } else {
            assert_eq!(r, Some(TokenError::BadTtl), "{issued}..{expires}");
        }
    }
}

#[test]
fn invite_check_time() {
    let a = key();
    let d = InviteDraft {
        issued_at: 10_000,
        ttl_secs: 900,
        addrs: vec![addr("203.0.113.7:4455")],
    };
    let (_p, text) = issue_invite(&d, &a).unwrap();
    let t = invite_of(&text);
    let tol = CLOCK_TOLERANCE_SECS;
    assert_eq!(tol, 600);
    assert_eq!(t.check_time(10_000 - tol), Ok(()));
    assert_eq!(t.check_time(10_000 - tol - 1), Err(TokenError::NotYetValid));
    assert_eq!(t.check_time(10_900 + tol), Ok(()));
    assert_eq!(t.check_time(10_900 + tol + 1), Err(TokenError::Expired));
    assert_eq!(t.check_time(10_500), Ok(()));
    // крайние значения без паники
    assert_eq!(t.check_time(0), Err(TokenError::NotYetValid));
    assert_eq!(t.check_time(u64::MAX), Err(TokenError::Expired));
}

#[test]
fn invite_max_size_fits_limit() {
    let a = key();
    let addrs: Vec<_> = (1..=8u16)
        .map(|i| addr(&format!("[2001:db8:{i:x}::1]:{}", 4000 + i)))
        .collect();
    let d = InviteDraft {
        issued_at: 1,
        ttl_secs: 900,
        addrs: addrs.clone(),
    };
    let (_p, text) = issue_invite(&d, &a).unwrap();
    assert_eq!(text_bytes(&text).len(), 147 + 8 * 19 + 64);
    assert!(text.len() <= MAX_TOKEN_TEXT_LEN, "длина {}", text.len());
    assert_eq!(invite_of(&text).addrs(), addrs.as_slice());
    // минимум
    let (_p, small) = issue_invite(&draft(900), &a).unwrap();
    assert_eq!(text_bytes(&small).len(), 218);
}

#[test]
fn tags_distinct_from_identity_tags() {
    let mut ours: Vec<(&str, &[u8])> = vec![
        ("hash", TOKEN_HASH_TAG),
        ("commit", COMMIT_TAG),
        ("sas", SAS_TAG),
    ];
    let mut theirs: Vec<(&str, &[u8])> = vec![
        ("kk", KK_PROLOGUE_TAG),
        ("knock-kdf", KNOCK_KDF_LABEL),
        ("knock-id", KNOCK_ID_LABEL),
        ("knock-tag", KNOCK_TAG_LABEL),
    ];
    let domains: Vec<&[u8]> = SignDomain::ALL.iter().map(|d| d.tag()).collect();
    for d in &domains {
        theirs.push(("domain", d));
    }
    // между собой и с тегами identity: не равны и не префиксы
    let all: Vec<(&str, &[u8])> = ours.drain(..).chain(theirs.drain(..)).collect();
    for (i, (na, a)) in all.iter().enumerate() {
        assert_eq!(a.iter().filter(|b| **b == 0).count(), 1, "{na}");
        assert_eq!(a.last(), Some(&0));
        for (j, (nb, b)) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "{na} == {nb}");
                assert!(!b.starts_with(a), "{na} префикс {nb}");
            }
        }
    }
}
