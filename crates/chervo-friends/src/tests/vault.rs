use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

use super::kit::*;
use crate::vault::{open, seal};
use crate::{BookData, FILE_MAGIC, FILE_VERSION, FriendsError, MAX_FILE_BYTES};

const KEY: [u8; 32] = [0x42; 32];

#[test]
fn vault_roundtrip() {
    let data = sample();
    let file = seal(&KEY, &data).unwrap();
    assert_eq!(&file[..4], FILE_MAGIC);
    assert_eq!(file[4], FILE_VERSION);
    let back = open(&KEY, &file).unwrap();
    assert!(same(&data, &back));
    // пустая книга
    let empty = seal(&KEY, &BookData::default()).unwrap();
    let back = open(&KEY, &empty).unwrap();
    assert!(back.friends.is_empty() && back.pending.is_empty());
    // в файле нет открытых имён и адресов
    let name = data.friends[0].name.as_bytes();
    assert!(!file.windows(name.len()).any(|w| w == name));
}

#[test]
fn vault_wrong_key_rejected() {
    let file = seal(&KEY, &sample()).unwrap();
    for other in [[0x43u8; 32], [0u8; 32], {
        let mut k = KEY;
        k[31] ^= 1;
        k
    }] {
        assert_eq!(open(&other, &file).err(), Some(FriendsError::Corrupt));
    }
}

#[test]
fn vault_any_byte_flip_rejected() {
    let file = seal(&KEY, &sample()).unwrap();
    for i in 0..file.len() {
        for mask in [0x01u8, 0x80] {
            let mut f = file.clone();
            f[i] ^= mask;
            assert!(open(&KEY, &f).is_err(), "байт {i} маска {mask:#x} принят");
        }
    }
}

#[test]
fn vault_every_truncation_rejected() {
    let file = seal(&KEY, &sample()).unwrap();
    for n in 0..file.len() {
        assert!(open(&KEY, &file[..n]).is_err(), "обрезка до {n} принята");
    }
    let mut longer = file.clone();
    longer.push(0);
    assert!(open(&KEY, &longer).is_err());
    // предел размера
    let big = vec![0u8; MAX_FILE_BYTES + 1];
    assert_eq!(open(&KEY, &big).err(), Some(FriendsError::Corrupt));
    assert_eq!(open(&KEY, &[]).err(), Some(FriendsError::Corrupt));
    assert_eq!(open(&KEY, &[0u8; 32]).err(), Some(FriendsError::Corrupt));
}

/// Заголовок входит в AAD: подмена версии или магии не проходит, даже когда шифртекст цел.
#[test]
fn vault_header_bound_by_aad() {
    let file = seal(&KEY, &sample()).unwrap();
    // версия и магия, как есть
    let mut f = file.clone();
    f[4] = 2;
    assert_eq!(open(&KEY, &f).err(), Some(FriendsError::UnsupportedVersion));
    f[4] = 0;
    assert_eq!(open(&KEY, &f).err(), Some(FriendsError::UnsupportedVersion));
    for i in 0..4 {
        let mut f = file.clone();
        f[i] ^= 0x20;
        assert_eq!(open(&KEY, &f).err(), Some(FriendsError::Corrupt));
    }
    // шифртекст сделан с другим AAD, но заголовок в файле нормальный
    let nonce: [u8; 12] = file[5..17].try_into().unwrap();
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &KEY).unwrap());
    let mut plain = file[17..].to_vec();
    let n = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&file[..5]),
            &mut plain,
        )
        .unwrap()
        .len();
    plain.truncate(n);
    for other_aad in [
        b"CHFX\x01".to_vec(),
        b"CHFL\x02".to_vec(),
        b"CHFL".to_vec(),
        vec![],
    ] {
        let mut body = plain.clone();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(other_aad.as_slice()),
            &mut body,
        )
        .unwrap();
        let mut forged = file[..17].to_vec();
        forged.extend_from_slice(&body);
        assert_eq!(open(&KEY, &forged).err(), Some(FriendsError::Corrupt));
    }
    // контроль: тот же приём с правильным AAD принимается
    let mut body = plain.clone();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&file[..5]),
        &mut body,
    )
    .unwrap();
    let mut ok = file[..17].to_vec();
    ok.extend_from_slice(&body);
    assert!(open(&KEY, &ok).is_ok());
}

#[test]
fn vault_nonce_fresh() {
    let data = sample();
    let mut nonces = std::collections::HashSet::new();
    let mut bodies = std::collections::HashSet::new();
    for _ in 0..64 {
        let f = seal(&KEY, &data).unwrap();
        nonces.insert(f[5..17].to_vec());
        bodies.insert(f[17..].to_vec());
    }
    assert_eq!(nonces.len(), 64);
    assert_eq!(bodies.len(), 64);
}
