mod common;

use chervo_identity::{
    IdentityError, KK_PROLOGUE_TAG, KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_LEN, KNOCK_TAG_LABEL,
    KnockKeys, KxPeer, PairId, SignDomain, create,
};
use common::MemStore;

/// Одна пара с двух сторон: (ключи A, ключи B).
fn pair_keys() -> (KnockKeys, KnockKeys) {
    let pid = PairId::generate().unwrap();
    let (sa, sb) = (MemStore::new(), MemStore::new());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    let a = KxPeer::new(pid, ka.into_kx(), pb).knock_keys().unwrap();
    let b = KxPeer::new(pid, kb.into_kx(), pa).knock_keys().unwrap();
    (a, b)
}

#[test]
fn knock_roundtrip() {
    let (a, b) = pair_keys();
    let k = a.make(77).unwrap();
    assert_eq!(k.len(), KNOCK_LEN);
    assert!(b.verify(77, &k));
    // и обратно
    let k2 = b.make(77).unwrap();
    assert!(a.verify(77, &k2));
    // id совпадает с таблицей вызываемого
    assert_eq!(&k[..16], &b.recv_id(77)[..]);
}

#[test]
fn knock_fresh_nonce() {
    let (a, _b) = pair_keys();
    let k1 = a.make(5).unwrap();
    let k2 = a.make(5).unwrap();
    assert_eq!(k1[..16], k2[..16], "id детерминирован в окне");
    assert_ne!(k1[16..32], k2[16..32], "nonce различен");
    assert_ne!(k1[32..], k2[32..], "tag различен");
}

#[test]
fn knock_directional() {
    let (a, b) = pair_keys();
    let k = a.make(9).unwrap();
    assert!(b.verify(9, &k));
    assert!(!a.verify(9, &k), "свой стук, отражённый себе, не проходит");
    // send != recv: id своего стука не равен нашему recv_id
    assert_ne!(k[..16], a.recv_id(9)[..]);
}

#[test]
fn knock_wrong_window() {
    let (a, b) = pair_keys();
    let k = a.make(100).unwrap();
    assert!(b.verify(100, &k));
    assert!(!b.verify(99, &k));
    assert!(!b.verify(101, &k));
    assert!(!b.verify(0, &k));
}

#[test]
fn knock_other_pair() {
    let (a, _b) = pair_keys();
    let (_c, d) = pair_keys();
    let k = a.make(1).unwrap();
    assert!(!d.verify(1, &k));
}

#[test]
fn knock_all_bit_flips() {
    let (a, b) = pair_keys();
    let k = a.make(42).unwrap();
    assert!(b.verify(42, &k));
    for i in 0..KNOCK_LEN * 8 {
        let mut x = k;
        x[i / 8] ^= 1 << (i % 8);
        assert!(!b.verify(42, &x), "бит {i}");
    }
}

#[test]
fn knock_wrong_lengths() {
    let (a, b) = pair_keys();
    let k = a.make(3).unwrap();
    for n in 0..=100usize {
        if n == KNOCK_LEN {
            continue;
        }
        let mut v = k.to_vec();
        v.resize(n, 0);
        assert!(!b.verify(3, &v), "длина {n}");
    }
}

#[test]
fn knock_self_key_rejected() {
    let pid = PairId::generate().unwrap();
    let s = MemStore::new();
    let k = create(&s, &pid).unwrap();
    let own = k.kx_public();
    let peer = KxPeer::new(pid, k.into_kx(), own);
    assert_eq!(peer.knock_keys().err(), Some(IdentityError::AuthFailed));
}

#[test]
fn knock_labels_distinct() {
    let mut all: Vec<&[u8]> = vec![
        KNOCK_KDF_LABEL,
        KNOCK_ID_LABEL,
        KNOCK_TAG_LABEL,
        KK_PROLOGUE_TAG,
    ];
    for d in SignDomain::ALL {
        all.push(d.tag());
    }
    for (i, x) in all.iter().enumerate() {
        for (j, y) in all.iter().enumerate() {
            if i != j {
                assert_ne!(x, y);
                assert!(!y.starts_with(x), "метка {i} префикс метки {j}");
            }
        }
    }
}

#[test]
fn knock_debug_redacted() {
    let (a, _b) = pair_keys();
    assert_eq!(format!("{a:?}"), "KnockKeys(..)");
    assert_eq!(format!("{a:#?}"), "KnockKeys(..)");
}
