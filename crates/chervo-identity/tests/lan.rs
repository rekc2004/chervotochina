mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chervo_identity::{
    IdentityError, KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_TAG_LABEL, KxPeer, LAN_AAD_LABEL,
    LAN_ID_KEY_LABEL, LAN_ID_LABEL, LAN_NONCE_LEN, LAN_SEAL_KEY_LABEL, LAN_SLOT_LEN, LanKeys,
    PairId, create,
};
use common::MemStore;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 12));
const NONCE: [u8; LAN_NONCE_LEN] = [7; LAN_NONCE_LEN];

fn keys_and_knock() -> (LanKeys, LanKeys, chervo_identity::KnockKeys) {
    let pid = PairId::generate().unwrap();
    let (sa, sb) = (MemStore::new(), MemStore::new());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    let a = KxPeer::new(pid, ka.into_kx(), pb);
    let b = KxPeer::new(pid, kb.into_kx(), pa);
    let knock_a = a.knock_keys().unwrap();
    (a.lan_keys().unwrap(), b.lan_keys().unwrap(), knock_a)
}

/// Одна пара с двух сторон: (ключи A, ключи B).
fn pair_keys() -> (LanKeys, LanKeys) {
    let (a, b, _) = keys_and_knock();
    (a, b)
}

#[test]
fn lan_keys_directional() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(5, &NONCE, IP, 41_234).unwrap();
    assert_eq!(slot.len(), LAN_SLOT_LEN);
    assert_eq!(b.open_slot(5, &NONCE, IP, &slot), Some(41_234));
    // метка в ячейке A равна recv_id(e) стороны B
    assert_eq!(slot[..16], b.recv_id(5)[..]);
    // и обратно
    let back = b.seal_slot(5, &NONCE, IP, 40_001).unwrap();
    assert_eq!(a.open_slot(5, &NONCE, IP, &back), Some(40_001));
    // направления независимы
    assert_ne!(slot[..16], back[..16]);
    // отражение: своя ячейка самому себе не открывается
    assert_eq!(a.open_slot(5, &NONCE, IP, &slot), None);
    assert_ne!(slot[..16], a.recv_id(5)[..]);
}

#[test]
fn lan_ids_independent_of_knock() {
    let (a, b, knock_a) = keys_and_knock();
    for n in [0u64, 1, 5, 28_000_000, u64::MAX] {
        let lan_a = a.recv_id(n);
        let lan_b = b.recv_id(n);
        assert_ne!(lan_a, knock_a.recv_id(n), "эпоха {n}");
        let sent = a.seal_slot(n, &NONCE, IP, 1).unwrap();
        assert_ne!(sent[..16], lan_a[..]);
        assert_ne!(lan_a, lan_b);
        // и метка отправителя (ячейка A) не равна id стука A→B, который B ждёт как recv_id
        let knock_sent = knock_a.make(n).unwrap();
        assert_ne!(sent[..16], knock_sent[..16]);
    }
    for (i, x) in [
        LAN_ID_KEY_LABEL,
        LAN_SEAL_KEY_LABEL,
        LAN_ID_LABEL,
        LAN_AAD_LABEL,
        KNOCK_KDF_LABEL,
        KNOCK_ID_LABEL,
        KNOCK_TAG_LABEL,
    ]
    .iter()
    .enumerate()
    {
        for (j, y) in [
            LAN_ID_KEY_LABEL,
            LAN_SEAL_KEY_LABEL,
            LAN_ID_LABEL,
            LAN_AAD_LABEL,
            KNOCK_KDF_LABEL,
            KNOCK_ID_LABEL,
            KNOCK_TAG_LABEL,
        ]
        .iter()
        .enumerate()
        {
            if i != j {
                assert_ne!(x, y);
                assert!(!y.starts_with(x), "метка {i} префикс метки {j}");
            }
        }
    }
}

#[test]
fn lan_id_changes_per_epoch() {
    let (a, b) = pair_keys();
    let mut seen = std::collections::HashSet::new();
    for e in 0..200u64 {
        assert!(seen.insert(b.recv_id(e)), "повтор метки в эпохе {e}");
        // детерминирована внутри эпохи
        assert_eq!(b.recv_id(e), b.recv_id(e));
        let s1 = a.seal_slot(e, &NONCE, IP, 9).unwrap();
        let s2 = a.seal_slot(e, &[9; LAN_NONCE_LEN], IP, 9).unwrap();
        assert_eq!(s1[..16], s2[..16], "метка не зависит от nonce");
        assert_ne!(s1[16..], s2[16..], "шифртекст и тег зависят от nonce");
    }
}

#[test]
fn lan_slot_rejects_other_ip() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(11, &NONCE, IP, 5000).unwrap();
    let other = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 13));
    assert_eq!(b.open_slot(11, &NONCE, other, &slot), None);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(b.open_slot(11, &NONCE, v6, &slot), None);
    assert_eq!(b.open_slot(11, &NONCE, IP, &slot), Some(5000));
}

#[test]
fn lan_slot_rejects_other_epoch() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(11, &NONCE, IP, 5000).unwrap();
    for e in [0u64, 10, 12, 13, u64::MAX] {
        assert_eq!(b.open_slot(e, &NONCE, IP, &slot), None, "эпоха {e}");
    }
}

#[test]
fn lan_slot_rejects_other_nonce() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(11, &NONCE, IP, 5000).unwrap();
    let mut other = NONCE;
    other[0] ^= 1;
    assert_eq!(b.open_slot(11, &other, IP, &slot), None);
    for i in 0..LAN_NONCE_LEN * 8 {
        let mut n = NONCE;
        n[i / 8] ^= 1 << (i % 8);
        assert_eq!(b.open_slot(11, &n, IP, &slot), None, "бит nonce {i}");
    }
}

#[test]
fn lan_slot_rejects_every_flipped_bit() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(77, &NONCE, IP, 41_234).unwrap();
    assert_eq!(b.open_slot(77, &NONCE, IP, &slot), Some(41_234));
    for i in 0..LAN_SLOT_LEN * 8 {
        let mut x = slot;
        x[i / 8] ^= 1 << (i % 8);
        assert_eq!(b.open_slot(77, &NONCE, IP, &x), None, "бит {i}");
    }
}

#[test]
fn lan_slot_rejects_wrong_len() {
    let (a, b) = pair_keys();
    let slot = a.seal_slot(3, &NONCE, IP, 80).unwrap();
    for n in [0usize, 1, 16, 18, 33, 35, 68] {
        let mut v = slot.to_vec();
        v.resize(n, 0);
        assert_eq!(b.open_slot(3, &NONCE, IP, &v), None, "длина {n}");
    }
    assert_eq!(b.open_slot(3, &NONCE, IP, &slot[..33]), None);
    let mut long = slot.to_vec();
    long.push(0);
    assert_eq!(b.open_slot(3, &NONCE, IP, &long), None);
}

#[test]
fn lan_slot_rejects_other_pair() {
    let (a, _b) = pair_keys();
    let (_c, d) = pair_keys();
    let slot = a.seal_slot(1, &NONCE, IP, 80).unwrap();
    assert_eq!(d.open_slot(1, &NONCE, IP, &slot), None);
}

#[test]
fn lan_slot_port_zero_rejected() {
    let (a, _b) = pair_keys();
    assert_eq!(
        a.seal_slot(1, &NONCE, IP, 0).err(),
        Some(IdentityError::AuthFailed)
    );
}

#[test]
fn lan_slot_v4_mapped_equals_v4() {
    let (a, b) = pair_keys();
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 77, 12).to_ipv6_mapped());
    // запечатано v4-mapped — открывается как v4, и наоборот
    let s1 = a.seal_slot(9, &NONCE, mapped, 6000).unwrap();
    assert_eq!(b.open_slot(9, &NONCE, IP, &s1), Some(6000));
    let s2 = a.seal_slot(9, &NONCE, IP, 6000).unwrap();
    assert_eq!(b.open_slot(9, &NONCE, mapped, &s2), Some(6000));
    assert_eq!(s1, s2, "одинаковые входы дают одинаковую ячейку");
    // чистый v6 с теми же 4 младшими байтами — другой адрес
    let v6 = IpAddr::V6("2001:db8::c0a8:4d0c".parse().unwrap());
    assert_eq!(b.open_slot(9, &NONCE, v6, &s1), None);
}

#[test]
fn lan_keys_equal_key_rejected() {
    let pid = PairId::generate().unwrap();
    let s = MemStore::new();
    let k = create(&s, &pid).unwrap();
    let own = k.kx_public();
    let peer = KxPeer::new(pid, k.into_kx(), own);
    assert_eq!(peer.lan_keys().err(), Some(IdentityError::AuthFailed));
}

#[test]
fn lan_keys_debug_redacted() {
    let (a, _b) = pair_keys();
    assert_eq!(format!("{a:?}"), "LanKeys(..)");
    assert_eq!(format!("{a:#?}"), "LanKeys(..)");
}
