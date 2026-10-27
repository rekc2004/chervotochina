mod common;

use chervo_identity::SignDomain;
use chervo_token::{
    RevocationReason, Token, TokenError, decode, encode_revocation_bytes, issue_revocation,
};
use common::*;

fn notice(text: &str) -> chervo_token::RevocationNotice {
    match decode(text) {
        Ok(Token::Revocation(n)) => n,
        Ok(_) => panic!("не отзыв"),
        Err(e) => panic!("decode: {e}"),
    }
}

/// Тело отзыва из частей.
fn rev_body(issued: u64, ed: &[u8; 32], x: &[u8; 32], reason: u8) -> Vec<u8> {
    let mut b = vec![1u8, 2u8];
    b.extend_from_slice(&issued.to_be_bytes());
    b.extend_from_slice(ed);
    b.extend_from_slice(x);
    b.push(reason);
    b
}

#[test]
fn revocation_roundtrip() {
    let k = key();
    for (reason, byte) in [
        (RevocationReason::Rekey, 1u8),
        (RevocationReason::Removed, 2u8),
    ] {
        let text = issue_revocation(&k, reason, 123_456).unwrap();
        assert!(text.starts_with("CHR1"));
        let bytes = text_bytes(&text);
        assert_eq!(bytes.len(), 139);
        assert_eq!(bytes[74], byte);
        assert_eq!(text, encode_revocation_bytes(&bytes));
        let n = notice(&text);
        assert_eq!(n.revoked_ed, k.public_key());
        assert_eq!(n.revoked_x, k.kx_public());
        assert_eq!(n.reason, reason);
        assert_eq!(n.issued_at, 123_456);
        assert_eq!(format!("{n:?}"), "RevocationNotice(..)");
    }
}

#[test]
fn revocation_bad_signature() {
    let k = key();
    let text = issue_revocation(&k, RevocationReason::Removed, 1).unwrap();
    let bytes = text_bytes(&text);
    // изменение подписи
    for i in 75..139 {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert_eq!(
            decode(&encode_revocation_bytes(&b)).err(),
            Some(TokenError::BadSignature),
            "байт {i}"
        );
    }
    // любой байт отзыва: ошибка
    for i in 0..139 {
        let mut b = bytes.clone();
        b[i] ^= 0x80;
        assert!(decode(&encode_revocation_bytes(&b)).is_err(), "байт {i}");
    }
    // чужой ключ подписывает отзыв чужого ключа
    let other = key();
    let body = rev_body(1, &k.public_key().to_bytes(), &k.kx_public().to_bytes(), 2);
    let mut forged = body.clone();
    forged.extend_from_slice(&other.sign(SignDomain::KeyRevocation, &body).unwrap());
    assert_eq!(
        decode(&encode_revocation_bytes(&forged)).err(),
        Some(TokenError::BadSignature)
    );
    // длина
    for n in 0..bytes.len() {
        assert!(decode(&encode_revocation_bytes(&bytes[..n])).is_err());
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        decode(&encode_revocation_bytes(&long)).err(),
        Some(TokenError::Malformed)
    );
}

#[test]
fn revocation_other_domain() {
    let k = key();
    let body = rev_body(1, &k.public_key().to_bytes(), &k.kx_public().to_bytes(), 1);
    for d in [
        SignDomain::Invite,
        SignDomain::InviteAccept,
        SignDomain::AddressUpdate,
    ] {
        let mut b = body.clone();
        b.extend_from_slice(&k.sign(d, &body).unwrap());
        assert_eq!(
            decode(&encode_revocation_bytes(&b)).err(),
            Some(TokenError::BadSignature),
            "{d:?}"
        );
    }
    // контроль: свой домен проходит
    let mut b = body.clone();
    b.extend_from_slice(&k.sign(SignDomain::KeyRevocation, &body).unwrap());
    assert!(decode(&encode_revocation_bytes(&b)).is_ok());
}

#[test]
fn revocation_bad_reason() {
    let k = key();
    for reason in [0u8, 3, 4, 0x80, 0xFF] {
        let body = rev_body(
            1,
            &k.public_key().to_bytes(),
            &k.kx_public().to_bytes(),
            reason,
        );
        let mut b = body.clone();
        // подпись корректна: проверяется именно значение причины
        b.extend_from_slice(&k.sign(SignDomain::KeyRevocation, &body).unwrap());
        assert_eq!(
            decode(&encode_revocation_bytes(&b)).err(),
            Some(TokenError::Malformed),
            "reason {reason}"
        );
    }
    // плохие ключи при корректной подписи
    let mut weak = [0u8; 32];
    weak[0] = 1;
    let body = rev_body(1, &k.public_key().to_bytes(), &weak, 1);
    let mut b = body.clone();
    b.extend_from_slice(&k.sign(SignDomain::KeyRevocation, &body).unwrap());
    assert_eq!(
        decode(&encode_revocation_bytes(&b)).err(),
        Some(TokenError::BadKey)
    );
    let body = rev_body(1, &weak, &k.kx_public().to_bytes(), 1);
    let mut b = body.clone();
    b.extend_from_slice(&k.sign(SignDomain::KeyRevocation, &body).unwrap());
    assert_eq!(
        decode(&encode_revocation_bytes(&b)).err(),
        Some(TokenError::BadKey)
    );
}
