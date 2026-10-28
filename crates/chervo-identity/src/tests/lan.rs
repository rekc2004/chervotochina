//! Тесты L1: ключи и слоты маяка (`lan.rs`).

use std::net::Ipv4Addr;

use crate::{
    KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_TAG_LABEL, KxPeer, LAN_AEADKEY_LABEL, LAN_HDR,
    LAN_ID_LABEL, LAN_IDKEY_LABEL, LAN_KDF_LABEL, LAN_NONCE_LEN, LAN_PAD_LABEL, LAN_SLOT_LEN,
    LanKeys, PairId, PairKey, lan_pad_id,
};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 7);
const NONCE: [u8; LAN_NONCE_LEN] = [7; LAN_NONCE_LEN];
const W: u64 = 56_789_012;

fn kx_pair(a: u8, b: u8) -> (crate::PairKx, crate::PairKx) {
    let ka = PairKey::from_secrets(&[a; 32], &[a.wrapping_add(100); 32]);
    let kb = PairKey::from_secrets(&[b; 32], &[b.wrapping_add(100); 32]);
    (ka.into_kx(), kb.into_kx())
}

/// Одна пара с двух сторон: (ключи A, ключи B).
fn pair_keys(i: u8) -> (LanKeys, LanKeys) {
    let (a, b) = kx_pair(i, i.wrapping_add(50));
    let (pa, pb) = (a.public(), b.public());
    let id = PairId::from_bytes([i; 16]);
    (
        KxPeer::new(id, a, pb).lan_keys().unwrap(),
        KxPeer::new(id, b, pa).lan_keys().unwrap(),
    )
}

#[test]
fn lan_keys_directional() {
    let (a, b) = pair_keys(1);
    assert_eq!(a.send_id(W), b.recv_id(W));
    assert_eq!(b.send_id(W), a.recv_id(W));
    assert_ne!(a.send_id(W), a.recv_id(W));
    assert_ne!(a.send_id(W), a.send_id(W + 1), "метка меняется по окнам");
    // чужая пара даёт другие метки
    let (c, _) = pair_keys(9);
    assert_ne!(a.send_id(W), c.send_id(W));
}

#[test]
fn lan_seal_open_roundtrip() {
    let (a, b) = pair_keys(2);
    for port in [1u16, 443, 40_000, 65_535] {
        let slot = a.seal(W, &NONCE, SRC, port).unwrap();
        assert_eq!(slot.len(), LAN_SLOT_LEN);
        assert_eq!(slot[..8], a.send_id(W));
        assert_eq!(b.open(W, &NONCE, SRC, &slot), Some(port));
        // слот в обратную сторону: свой слот отправителю не открывается
        assert_eq!(a.open(W, &NONCE, SRC, &slot), None);
    }
    // порт не виден в слоте открытым текстом
    let slot = a.seal(W, &NONCE, SRC, 0x1234).unwrap();
    assert_ne!(slot[8..10], [0x12, 0x34]);
}

#[test]
fn lan_open_rejects_other_src_ip() {
    let (a, b) = pair_keys(3);
    let slot = a.seal(W, &NONCE, SRC, 5000).unwrap();
    assert_eq!(b.open(W, &NONCE, SRC, &slot), Some(5000));
    assert_eq!(
        b.open(W, &NONCE, Ipv4Addr::new(192, 168, 50, 8), &slot),
        None
    );
    assert_eq!(b.open(W, &NONCE, Ipv4Addr::new(10, 0, 0, 7), &slot), None);
}

#[test]
fn lan_open_rejects_other_window() {
    let (a, b) = pair_keys(4);
    let slot = a.seal(W, &NONCE, SRC, 5000).unwrap();
    for w in [W - 1, W + 1, W + 2, 0, u64::MAX] {
        assert_eq!(b.open(w, &NONCE, SRC, &slot), None, "окно {w}");
    }
}

#[test]
fn lan_open_rejects_other_nonce() {
    let (a, b) = pair_keys(5);
    let slot = a.seal(W, &NONCE, SRC, 5000).unwrap();
    assert_eq!(b.open(W, &[8; LAN_NONCE_LEN], SRC, &slot), None);
    assert_eq!(b.open(W, &[0; LAN_NONCE_LEN], SRC, &slot), None);
}

#[test]
fn lan_open_rejects_every_bit_flip() {
    let (a, b) = pair_keys(6);
    let slot = a.seal(W, &NONCE, SRC, 5000).unwrap();
    // каждый бит слота: 26 * 8
    for i in 0..LAN_SLOT_LEN {
        for bit in 0..8 {
            let mut s = slot;
            s[i] ^= 1 << bit;
            assert_eq!(b.open(W, &NONCE, SRC, &s), None, "слот: байт {i} бит {bit}");
        }
    }
    // каждый бит nonce
    for i in 0..LAN_NONCE_LEN {
        for bit in 0..8 {
            let mut n = NONCE;
            n[i] ^= 1 << bit;
            assert_eq!(b.open(W, &n, SRC, &slot), None, "nonce: байт {i} бит {bit}");
        }
    }
    // каждый бит адреса источника (он в AAD)
    let oct = SRC.octets();
    for i in 0..4 {
        for bit in 0..8 {
            let mut o = oct;
            o[i] ^= 1 << bit;
            assert_eq!(b.open(W, &NONCE, Ipv4Addr::from(o), &slot), None);
        }
    }
    // заголовок: он не часть слота, а константа в AAD; слот, собранный при другом заголовке,
    // не открывается. Проверяется через сторонний AAD: слот другого окна не подходит (см. выше),
    // а заголовок отсекается разборщиком датаграмм (chervo-lan, wire_bad_header).
    assert_eq!(LAN_HDR, [0x01, 0x00]);
    // длина
    assert_eq!(b.open(W, &NONCE, SRC, &slot[..LAN_SLOT_LEN - 1]), None);
    let mut longer = slot.to_vec();
    longer.push(0);
    assert_eq!(b.open(W, &NONCE, SRC, &longer), None);
    assert_eq!(b.open(W, &NONCE, SRC, &[]), None);
    // исходный слот по-прежнему открывается
    assert_eq!(b.open(W, &NONCE, SRC, &slot), Some(5000));
}

#[test]
fn lan_seal_port_zero_rejected() {
    let (a, _) = pair_keys(7);
    assert_eq!(
        a.seal(W, &NONCE, SRC, 0),
        Err(crate::IdentityError::AuthFailed)
    );
}

#[test]
fn lan_open_port_zero_rejected() {
    // Слот с портом 0 собираем вручную теми же ключами: `seal` его не выпускает.
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    let (a, b) = pair_keys(8);
    let id = a.send_id(W);
    let mut aad = Vec::new();
    aad.extend_from_slice(&LAN_HDR);
    aad.extend_from_slice(&W.to_be_bytes());
    aad.extend_from_slice(&SRC.octets());
    aad.extend_from_slice(&id);
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, a.test_send_aead().as_slice()).unwrap(),
    );
    let mut ct = [0u8, 0u8];
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(NONCE),
            Aad::from(aad.as_slice()),
            &mut ct,
        )
        .unwrap();
    let mut slot = Vec::new();
    slot.extend_from_slice(&id);
    slot.extend_from_slice(&ct);
    slot.extend_from_slice(tag.as_ref());
    assert_eq!(slot.len(), LAN_SLOT_LEN);
    // тот же слот с портом != 0 открылся бы: проверяем, что отказ именно из-за нуля
    assert_eq!(b.open(W, &NONCE, SRC, &slot), None);
    let ok = a.seal(W, &NONCE, SRC, 1).unwrap();
    assert_eq!(b.open(W, &NONCE, SRC, &ok), Some(1));
}

#[test]
fn lan_keys_equal_pubkeys_rejected() {
    // ключ друга равен нашему: отражение
    let ka = PairKey::from_secrets(&[3; 32], &[103; 32]);
    let kb = PairKey::from_secrets(&[3; 32], &[103; 32]);
    let pb = kb.kx_public();
    let peer = KxPeer::new(PairId::from_bytes([1; 16]), ka.into_kx(), pb);
    assert_eq!(
        peer.lan_keys().err(),
        Some(crate::IdentityError::AuthFailed)
    );
}

#[test]
fn lan_labels_distinct_from_knock() {
    let all: [&[u8]; 8] = [
        LAN_KDF_LABEL,
        LAN_IDKEY_LABEL,
        LAN_AEADKEY_LABEL,
        LAN_ID_LABEL,
        LAN_PAD_LABEL,
        KNOCK_KDF_LABEL,
        KNOCK_ID_LABEL,
        KNOCK_TAG_LABEL,
    ];
    for (i, x) in all.iter().enumerate() {
        assert!(x.starts_with(b"chervotochina/v1/"));
        assert_eq!(x.last(), Some(&0u8), "метка оканчивается нулевым байтом");
        for y in all.iter().skip(i + 1) {
            assert_ne!(x, y);
        }
    }
    // ключ направления маяка не равен ключу стука той же пары (разные метки KDF)
    let (a, _) = pair_keys(1);
    let (ka, kb) = kx_pair(1, 51);
    let peer = KxPeer::new(PairId::from_bytes([1; 16]), ka, kb.public());
    let kn = peer.knock_keys().unwrap();
    assert_ne!(kn.recv_id(W)[..8], a.recv_id(W));
}

/// Золотой вектор: фиксированные секреты, окно, nonce, адрес, порт -> фиксированные 26 байт.
/// Значение получено этой реализацией и сверено независимым расчётом на Python
/// (`cryptography`: X25519 и ChaCha20-Poly1305, `hashlib.blake2s` с ключом).
#[test]
fn lan_golden_vector() {
    let (ka, kb) = kx_pair(1, 2);
    let (pa, pb) = (ka.public(), kb.public());
    let id = PairId::from_bytes([0; 16]);
    let a = KxPeer::new(id, ka, pb).lan_keys().unwrap();
    let b = KxPeer::new(id, kb, pa).lan_keys().unwrap();
    let nonce = [0x42u8; LAN_NONCE_LEN];
    let slot = a
        .seal(1_000_000, &nonce, Ipv4Addr::new(192, 168, 1, 10), 45_000)
        .unwrap();
    assert_eq!(hex(&slot), GOLDEN_SLOT);
    assert_eq!(
        b.open(1_000_000, &nonce, Ipv4Addr::new(192, 168, 1, 10), &slot),
        Some(45_000)
    );
}

const GOLDEN_SLOT: &str = "d72078edb7a845fcb38ed9683c71a66313f92acd93962911abd4";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn lan_keys_debug_redacted() {
    let (a, _) = pair_keys(1);
    assert_eq!(format!("{a:?}"), "LanKeys(..)");
    assert_eq!(format!("{a:#?}"), "LanKeys(..)");
}

/// Метка пустого слота: постоянна внутри окна, меняется с окном, ключом и номером; значение
/// сверено независимым расчётом на Python (`hashlib.blake2s` с ключом).
#[test]
fn lan_pad_id_stable_and_golden() {
    let r = [7u8; 32];
    let id = lan_pad_id(&r, 1_000_000, 3).unwrap();
    assert_eq!(hex(&id), "2a7b05fd695a9826");
    assert_eq!(id, lan_pad_id(&r, 1_000_000, 3).unwrap());
    assert_ne!(id, lan_pad_id(&r, 1_000_001, 3).unwrap(), "другое окно");
    assert_ne!(id, lan_pad_id(&r, 1_000_000, 4).unwrap(), "другой номер");
    assert_ne!(
        id,
        lan_pad_id(&[8u8; 32], 1_000_000, 3).unwrap(),
        "другой ключ R"
    );
}
