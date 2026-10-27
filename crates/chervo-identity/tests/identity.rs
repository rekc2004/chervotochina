mod common;

use chervo_identity::{
    ACCOUNT_PREFIX, ChannelBinding, DEFAULT_SERVICE, GuestSecret, IdentityError, KEY_BLOB_LEN,
    KK_PROLOGUE_TAG, KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_TAG_LABEL, KxPeer, KxPublicKey,
    LIST_KEY_ACCOUNT, LIST_KEY_LEN, ListKeyStore, PairId, PairKey, PairKx, PublicKey, SecretStore,
    SignDomain, UnavailableKeyStore, create, load, rekey,
};
use common::{FailingStore, FixedStore, LossyStore, MemStore};
use zeroize::{ZeroizeOnDrop, Zeroizing};

fn pair() -> PairId {
    PairId::generate().unwrap()
}

fn fresh() -> (MemStore, PairId, PairKey) {
    let s = MemStore::new();
    let p = pair();
    let k = create(&s, &p).unwrap();
    (s, p, k)
}

fn some_public() -> PublicKey {
    let (_, _, k) = fresh();
    k.public_key()
}

// ---------- гостевой секрет приглашения ----------

#[test]
fn guest_generate_public_valid() {
    let g = GuestSecret::generate().unwrap();
    let p = g.public();
    assert!(KxPublicKey::try_from_slice(&p.to_bytes()).is_ok());
    assert_ne!(
        g.public(),
        GuestSecret::generate().unwrap().public(),
        "два секрета не совпадают"
    );
}

#[test]
fn guest_from_bytes_roundtrip() {
    let g = GuestSecret::generate().unwrap();
    let bytes = g.to_token_bytes();
    let back = GuestSecret::from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(back.public(), g.public());
    assert_eq!(*back.to_token_bytes(), *bytes);
}

#[test]
fn guest_from_bytes_bad_len() {
    for n in [0usize, 1, 31, 33, 64] {
        assert_eq!(
            GuestSecret::from_bytes(&vec![7u8; n]).err(),
            Some(IdentityError::InvalidGuestSecret),
            "длина {n}"
        );
    }
    assert!(GuestSecret::from_bytes(&[7u8; 32]).is_ok());
}

#[test]
fn guest_debug_redacted() {
    let g = GuestSecret::from_bytes(&[0xAB; 32]).unwrap();
    assert_eq!(format!("{g:?}"), "GuestSecret(..)");
    assert_eq!(
        IdentityError::InvalidGuestSecret.to_string(),
        "invalid invite secret"
    );
    fn z<T: ZeroizeOnDrop>() {}
    z::<GuestSecret>();
}

#[test]
fn sign_domains_pairwise_not_prefix() {
    let mut all: Vec<&[u8]> = SignDomain::ALL.iter().map(|d| d.tag()).collect();
    assert_eq!(all.len(), 4);
    all.push(KK_PROLOGUE_TAG);
    all.push(KNOCK_KDF_LABEL);
    all.push(KNOCK_ID_LABEL);
    all.push(KNOCK_TAG_LABEL);
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "теги {i} и {j} равны");
                assert!(!b.starts_with(a), "тег {i} префикс тега {j}");
            }
        }
    }
}

#[test]
fn invite_accept_domain_separated() {
    assert_eq!(
        SignDomain::InviteAccept.tag(),
        b"chervotochina/v1/invite-accept\0"
    );
    let (_, _, k) = fresh();
    let pk = k.public_key();
    let msg = b"payload";
    let a = k.sign(SignDomain::InviteAccept, msg).unwrap();
    let i = k.sign(SignDomain::Invite, msg).unwrap();
    assert!(pk.verify(SignDomain::InviteAccept, msg, &a).is_ok());
    assert!(pk.verify(SignDomain::Invite, msg, &i).is_ok());
    assert_eq!(
        pk.verify(SignDomain::Invite, msg, &a),
        Err(IdentityError::BadSignature)
    );
    assert_eq!(
        pk.verify(SignDomain::InviteAccept, msg, &i),
        Err(IdentityError::BadSignature)
    );
}

// ---------- ключ списка друзей ----------

#[test]
fn unavailable_list_key_store() {
    assert_eq!(
        UnavailableKeyStore.read_list_key().err(),
        Some(IdentityError::NotImplemented)
    );
    assert_eq!(
        UnavailableKeyStore.write_list_key(&[0; LIST_KEY_LEN]),
        Err(IdentityError::NotImplemented)
    );
    assert_eq!(
        UnavailableKeyStore.delete_list_key(),
        Err(IdentityError::NotImplemented)
    );
    assert_eq!(LIST_KEY_ACCOUNT, "friends-key-v1");
    assert!(!LIST_KEY_ACCOUNT.starts_with(ACCOUNT_PREFIX));
    assert_eq!(LIST_KEY_LEN, 32);
}

// ---------- позитивные ----------

#[test]
fn pair_id_generate_distinct() {
    assert_ne!(pair(), pair());
}

#[test]
fn account_name_format() {
    let name = PairId::from_bytes([0xAB; 16]).account_name();
    assert!(name.starts_with(ACCOUNT_PREFIX));
    assert_eq!(name.len(), 40);
    assert_eq!(name, format!("pair-v1-{}", "ab".repeat(16)));
    let tail = &name[ACCOUNT_PREFIX.len()..];
    assert!(tail.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    let name0 = PairId::from_bytes([0; 16]).account_name();
    assert_eq!(name0.len(), 40);
}

#[test]
fn create_then_load_same_key() {
    let (s, p, k) = fresh();
    let expected = k.public_key();
    let loaded = load(&s, &p, &expected).unwrap();
    assert_eq!(loaded.public_key(), expected);
    let sig = k.sign(SignDomain::Invite, b"m").unwrap();
    assert!(
        loaded
            .public_key()
            .verify(SignDomain::Invite, b"m", &sig)
            .is_ok()
    );
    assert_eq!(s.raw(&p).unwrap().len(), KEY_BLOB_LEN);
}

#[test]
fn rekey_replaces_key() {
    let (s, p, k) = fresh();
    let old = k.public_key();
    let new = rekey(&s, &p).unwrap().public_key();
    assert_ne!(old, new);
    assert_eq!(load(&s, &p, &old).unwrap_err(), IdentityError::KeyMismatch);
    assert!(load(&s, &p, &new).is_ok());
}

#[test]
fn sign_verify_roundtrip() {
    let (_, _, k) = fresh();
    for d in SignDomain::ALL {
        let sig = k.sign(*d, b"hello").unwrap();
        assert_eq!(k.public_key().verify(*d, b"hello", &sig), Ok(()));
    }
}

#[test]
fn public_key_roundtrip() {
    let (_, _, k) = fresh();
    let pk = k.public_key();
    assert_eq!(PublicKey::try_from_slice(&pk.to_bytes()).unwrap(), pk);
}

#[test]
fn delete_missing_is_ok() {
    let s = MemStore::new();
    assert_eq!(s.delete(&pair()), Ok(()));
}

#[test]
fn pair_key_debug_redacted() {
    let (_, _, k) = fresh();
    assert_eq!(format!("{k:?}"), "PairKey(..)");
}

#[test]
fn public_debug_redacted() {
    let pk = some_public();
    assert_eq!(format!("{pk:?}"), "PublicKey(..)");
    assert_eq!(format!("{:?}", pair()), "PairId(..)");
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        // Без демона/доступа к хранилищу ОС экземпляр не создать: тогда проверяем лишь ошибку.
        match chervo_identity::OsKeyStore::open_with_service("chervotochina-test-debug") {
            Ok(s) => assert_eq!(format!("{s:?}"), "OsKeyStore(..)"),
            Err(e) => assert_eq!(e, IdentityError::StorageUnavailable),
        }
    }
}

#[test]
fn error_display_fixed_strings() {
    let all = [
        (IdentityError::NotImplemented, "not implemented"),
        (IdentityError::StorageUnavailable, "key storage unavailable"),
        (
            IdentityError::StorageLocked,
            "key storage locked or access denied",
        ),
        (
            IdentityError::StorageInconsistent,
            "key storage inconsistent",
        ),
        (IdentityError::KeyMissing, "pair key missing"),
        (IdentityError::KeyAlreadyExists, "pair key already exists"),
        (
            IdentityError::KeyMismatch,
            "pair key does not match expected public key",
        ),
        (IdentityError::CorruptKey, "stored key is corrupt"),
        (
            IdentityError::UnsupportedKeyVersion,
            "unsupported stored key version",
        ),
        (
            IdentityError::RandomUnavailable,
            "os random source unavailable",
        ),
        (IdentityError::InvalidPublicKey, "invalid public key"),
        (IdentityError::BadSignature, "bad signature"),
        (IdentityError::SigningFailed, "signing failed"),
        (
            IdentityError::InvalidKxPublicKey,
            "invalid key-exchange public key",
        ),
        (
            IdentityError::AuthFailed,
            "connection authentication failed",
        ),
        (IdentityError::InvalidGuestSecret, "invalid invite secret"),
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
    }
}

#[test]
fn create_then_load_same_kx() {
    let (s, p, k) = fresh();
    let kx = k.kx_public();
    let loaded = load(&s, &p, &k.public_key()).unwrap();
    assert_eq!(loaded.kx_public(), kx);
    let raw = s.raw(&p).unwrap();
    assert_eq!(raw.len(), KEY_BLOB_LEN);
    assert_eq!(raw[0], 2);
    assert_eq!(&raw[97..129], kx.to_bytes().as_slice());
    assert_eq!(&raw[33..65], k.public_key().to_bytes().as_slice());
}

#[test]
fn rekey_replaces_kx() {
    let (s, p, k) = fresh();
    let old = k.kx_public();
    let new = rekey(&s, &p).unwrap();
    assert_ne!(old, new.kx_public());
    assert_eq!(s.raw(&p).unwrap()[97..129], new.kx_public().to_bytes());
}

#[test]
fn kx_public_roundtrip() {
    let (_, _, k) = fresh();
    let kx = k.kx_public();
    assert_eq!(KxPublicKey::try_from_slice(&kx.to_bytes()).unwrap(), kx);
}

#[test]
fn into_kx_keeps_public() {
    let (_, _, k) = fresh();
    let kx = k.kx_public();
    assert_eq!(k.into_kx().public(), kx);
}

#[test]
fn kx_debug_redacted() {
    let (_, _, k) = fresh();
    let (_, _, other) = fresh();
    let theirs = other.kx_public();
    assert_eq!(format!("{theirs:?}"), "KxPublicKey(..)");
    let kx = k.into_kx();
    assert_eq!(format!("{kx:?}"), "PairKx(..)");
    let peer = KxPeer::new(pair(), kx, theirs);
    assert_eq!(format!("{peer:?}"), "KxPeer(..)");
    let binding = ChannelBinding::from_bytes([3; 32]);
    assert_eq!(format!("{binding:?}"), "ChannelBinding(..)");
    let (init, _msg1) = chervo_identity::kk_initiate(&peer, &binding).unwrap();
    assert_eq!(format!("{init:?}"), "KkInitiator(..)");
    // вызываемый: тот же набор ключей с другой стороны
    let (_, _, a) = fresh();
    let (_, _, b) = fresh();
    let (pa, pb) = (a.kx_public(), b.kx_public());
    let caller = KxPeer::new(pair(), a.into_kx(), pb);
    let callee = KxPeer::new(caller.pair(), b.into_kx(), pa);
    let (_, m1) = chervo_identity::kk_initiate(&caller, &binding).unwrap();
    let (resp, _) = chervo_identity::kk_respond(&[&callee], &binding, &m1).unwrap();
    assert_eq!(format!("{resp:?}"), "KkResponder(..)");
}

#[test]
fn prologue_tag_distinct_from_sign_domains() {
    assert_eq!(KK_PROLOGUE_TAG.iter().filter(|b| **b == 0).count(), 1);
    assert_eq!(KK_PROLOGUE_TAG.last(), Some(&0));
    for d in SignDomain::ALL {
        let t = d.tag();
        assert_ne!(KK_PROLOGUE_TAG, t);
        assert!(!KK_PROLOGUE_TAG.starts_with(t), "тег домена префикс KK");
        assert!(!t.starts_with(KK_PROLOGUE_TAG), "KK префикс тега домена");
    }
}

#[test]
fn domain_tags_prefix_free() {
    let tags: Vec<&[u8]> = SignDomain::ALL.iter().map(|d| d.tag()).collect();
    assert_eq!(tags.len(), 4);
    for (i, a) in tags.iter().enumerate() {
        assert_eq!(a.iter().filter(|b| **b == 0).count(), 1);
        assert_eq!(a.last(), Some(&0));
        assert_ne!(a.first(), Some(&0x20));
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert!(!b.starts_with(a), "один тег префикс другого");
            }
        }
    }
}

#[test]
fn secret_types_zeroize_on_drop() {
    fn f<T: ZeroizeOnDrop>() {}
    f::<PairKey>();
    f::<PairKx>();
    f::<x25519_dalek::StaticSecret>();
    f::<ed25519_dalek::SigningKey>();
    f::<Zeroizing<Vec<u8>>>();
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn has_word(text: &str, word: &str) -> bool {
    let b = text.as_bytes();
    let is_w = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    text.match_indices(word).any(|(i, _)| {
        let before = i == 0 || !is_w(b[i - 1]);
        let after = b.get(i + word.len()).is_none_or(|c| !is_w(*c));
        before && after
    })
}

#[test]
fn src_has_no_io_or_default_store() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src, &mut files);
    assert!(!files.is_empty());
    let substrings = [
        "std::fs",
        "File",
        "OpenOptions",
        "set_var",
        "env::var",
        "print!",
        "println!",
        "eprint",
        "dbg!",
        "stdout",
        "stderr",
        "log::",
        "tracing",
        "Command",
        "set_default_store",
        "get_default_store",
        "mock",
        "Entry::new(",
        "keyring::",
        ".sign(",
        "generate_keypair",
        "fixed_ephemeral",
        "risky",
        "dangerously",
        "to_scalar_bytes",
        ".to_scalar(",
        "StaticSecret::random",
    ];
    for f in files {
        let mut text = std::fs::read_to_string(&f).unwrap();
        // Имена lint-атрибутов `clippy::print_stdout`/`print_stderr` содержат "stdout"/"stderr".
        text = text
            .replace("clippy::print_stdout", "")
            .replace("clippy::print_stderr", "");
        for s in substrings {
            assert!(!text.contains(s), "{}: найдено {s:?}", f.display());
        }
        assert!(!has_word(&text, "fs"), "{}: найдено слово fs", f.display());
    }
}

// ---------- негативные ----------

#[test]
fn load_missing_is_key_missing() {
    let s = MemStore::new();
    let e = load(&s, &pair(), &some_public()).unwrap_err();
    assert_eq!(e, IdentityError::KeyMissing);
    assert!(s.is_empty());
}

#[test]
fn create_refuses_existing_record() {
    let (s, p, _) = fresh();
    let before = s.raw(&p);
    assert_eq!(create(&s, &p).unwrap_err(), IdentityError::KeyAlreadyExists);
    assert_eq!(s.raw(&p), before);
    // испорченная запись тоже не перезаписывается
    let s2 = MemStore::with_raw(&p, vec![9, 9, 9]);
    assert_eq!(
        create(&s2, &p).unwrap_err(),
        IdentityError::KeyAlreadyExists
    );
    assert_eq!(s2.raw(&p), Some(vec![9, 9, 9]));
}

#[test]
fn load_expected_mismatch_rejected() {
    let (s, p, _) = fresh();
    assert_eq!(
        load(&s, &p, &some_public()).unwrap_err(),
        IdentityError::KeyMismatch
    );
}

#[test]
fn locked_store_not_missing() {
    let s = FailingStore(IdentityError::StorageLocked);
    let p = pair();
    assert_eq!(
        load(&s, &p, &some_public()).unwrap_err(),
        IdentityError::StorageLocked
    );
    assert_eq!(create(&s, &p).unwrap_err(), IdentityError::StorageLocked);
    assert_eq!(rekey(&s, &p).unwrap_err(), IdentityError::StorageLocked);
}

#[test]
fn failing_store_propagates() {
    let s = FailingStore(IdentityError::StorageUnavailable);
    let p = pair();
    assert_eq!(
        load(&s, &p, &some_public()).unwrap_err(),
        IdentityError::StorageUnavailable
    );
    assert_eq!(
        create(&s, &p).unwrap_err(),
        IdentityError::StorageUnavailable
    );
    assert_eq!(
        rekey(&s, &p).unwrap_err(),
        IdentityError::StorageUnavailable
    );
}

#[test]
fn lossy_store_detected() {
    assert_eq!(
        create(&LossyStore, &pair()).unwrap_err(),
        IdentityError::StorageInconsistent
    );
}

#[test]
fn rekey_missing_is_key_missing() {
    let s = MemStore::new();
    assert_eq!(rekey(&s, &pair()).unwrap_err(), IdentityError::KeyMissing);
    assert!(s.is_empty());
}

#[test]
fn delete_then_load_is_key_missing() {
    let (s, p, k) = fresh();
    s.delete(&p).unwrap();
    assert_eq!(
        load(&s, &p, &k.public_key()).unwrap_err(),
        IdentityError::KeyMissing
    );
}

#[test]
fn unavailable_store_fails_closed() {
    let p = pair();
    let s = UnavailableKeyStore;
    assert_eq!(s.read(&p).unwrap_err(), IdentityError::NotImplemented);
    assert_eq!(s.write(&p, b"x"), Err(IdentityError::NotImplemented));
    assert_eq!(s.delete(&p), Err(IdentityError::NotImplemented));
    assert_eq!(create(&s, &p).unwrap_err(), IdentityError::NotImplemented);
    assert_eq!(
        load(&s, &p, &some_public()).unwrap_err(),
        IdentityError::NotImplemented
    );
    assert_eq!(rekey(&s, &p).unwrap_err(), IdentityError::NotImplemented);
}

fn load_fixed(blob: Vec<u8>) -> IdentityError {
    load(&FixedStore(blob), &pair(), &some_public()).unwrap_err()
}

#[test]
fn blob_empty_rejected() {
    assert_eq!(load_fixed(Vec::new()), IdentityError::CorruptKey);
}

#[test]
fn blob_wrong_length_rejected() {
    for len in [128usize, 130, 65, 1 << 20] {
        let mut b = vec![0x5A; len];
        b[0] = 2;
        assert_eq!(load_fixed(b), IdentityError::CorruptKey, "len {len}");
    }
}

#[test]
fn blob_unknown_version_rejected() {
    for v in [0x00u8, 0x01, 0x03, 0xFF] {
        for len in [129usize, 65, 10] {
            let mut b = vec![0x5A; len];
            b[0] = v;
            assert_eq!(
                load_fixed(b),
                IdentityError::UnsupportedKeyVersion,
                "v {v} len {len}"
            );
        }
    }
}

#[test]
fn blob_public_part_mismatch_rejected() {
    let (s, p, k) = fresh();
    let mut b = s.raw(&p).unwrap();
    b[40] ^= 1;
    assert_eq!(
        load(&FixedStore(b), &p, &k.public_key()).unwrap_err(),
        IdentityError::CorruptKey
    );
}

#[test]
fn blob_seed_bit_flip_rejected() {
    let (s, p, k) = fresh();
    let mut b = s.raw(&p).unwrap();
    b[5] ^= 1;
    assert_eq!(
        load(&FixedStore(b), &p, &k.public_key()).unwrap_err(),
        IdentityError::CorruptKey
    );
}

#[test]
fn blob_kx_secret_bit_flip_rejected() {
    let (s, p, k) = fresh();
    let mut b = s.raw(&p).unwrap();
    b[70] ^= 1;
    assert_eq!(
        load(&FixedStore(b), &p, &k.public_key()).unwrap_err(),
        IdentityError::CorruptKey
    );
}

#[test]
fn blob_kx_public_mismatch_rejected() {
    let (s, p, k) = fresh();
    let mut b = s.raw(&p).unwrap();
    b[100] ^= 1;
    assert_eq!(
        load(&FixedStore(b), &p, &k.public_key()).unwrap_err(),
        IdentityError::CorruptKey
    );
}

#[test]
fn v1_record_not_migrated() {
    let p = pair();
    let seed = [0x42u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let mut v1 = vec![1u8];
    v1.extend_from_slice(&seed);
    v1.extend_from_slice(&public);
    assert_eq!(v1.len(), 65);
    let s = MemStore::with_raw(&p, v1.clone());
    let expected = PublicKey::try_from_slice(&public).unwrap();
    assert_eq!(
        load(&s, &p, &expected).unwrap_err(),
        IdentityError::UnsupportedKeyVersion
    );
    assert_eq!(s.raw(&p), Some(v1.clone()));
    assert_eq!(create(&s, &p).unwrap_err(), IdentityError::KeyAlreadyExists);
    assert_eq!(s.raw(&p), Some(v1));
    let new = rekey(&s, &p).unwrap();
    let raw = s.raw(&p).unwrap();
    assert_eq!(raw.len(), 129);
    assert_eq!(raw[0], 2);
    assert!(load(&s, &p, &new.public_key()).is_ok());
}

#[test]
fn corrupt_blob_not_overwritten() {
    let (s, p, k) = fresh();
    let mut b = s.raw(&p).unwrap();
    b[5] ^= 1;
    let s2 = MemStore::with_raw(&p, b.clone());
    assert_eq!(
        load(&s2, &p, &k.public_key()).unwrap_err(),
        IdentityError::CorruptKey
    );
    assert_eq!(s2.raw(&p), Some(b));
}

#[test]
fn blob_exhaustive_lengths_and_versions() {
    for len in 0..=260usize {
        let mut b = vec![0x5A; len];
        if let Some(f) = b.first_mut() {
            *f = 2;
        }
        assert_eq!(load_fixed(b), IdentityError::CorruptKey, "len {len}");
    }
    for v in 0..=255u8 {
        let mut b = vec![0x5A; 129];
        b[0] = v;
        let want = if v == 2 {
            IdentityError::CorruptKey
        } else {
            IdentityError::UnsupportedKeyVersion
        };
        assert_eq!(load_fixed(b), want, "version {v}");
    }
}

#[test]
fn public_key_rejects_wrong_length() {
    for len in [0usize, 31, 33] {
        assert_eq!(
            PublicKey::try_from_slice(&vec![1u8; len]).unwrap_err(),
            IdentityError::InvalidPublicKey,
            "len {len}"
        );
    }
}

#[test]
fn public_key_rejects_weak() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut minus_one = [0xFFu8; 32];
    minus_one[0] = 0xEC;
    minus_one[31] = 0x7F;
    let mut identity_sign = identity;
    identity_sign[31] = 0x80;
    // y = 0: точка порядка 4 (x^2 = -1 имеет корень), оба знака x
    let order4 = [0u8; 32];
    let mut order4_sign = order4;
    order4_sign[31] = 0x80;
    for k in [order4, order4_sign] {
        // контроль: ключ раскладывается в точку и dalek считает её слабой
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&k).unwrap();
        assert!(vk.is_weak());
    }
    for k in [identity, minus_one, identity_sign, order4, order4_sign] {
        assert_eq!(
            PublicKey::try_from_slice(&k).unwrap_err(),
            IdentityError::InvalidPublicKey
        );
    }
}

#[test]
fn public_key_rejects_noncanonical() {
    let mut control = false;
    for k in 0..=18u8 {
        for sign in [0u8, 0x80] {
            // y = p + k, p = 2^255 - 19: байты ED, FF*30, 7F плюс k в младшем байте
            let mut b = [0xFFu8; 32];
            b[0] = 0xED + k;
            b[31] = 0x7F | sign;
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&b)
                && !vk.is_weak()
            {
                control = true;
            }
            assert_eq!(
                PublicKey::try_from_slice(&b).unwrap_err(),
                IdentityError::InvalidPublicKey,
                "k {k} sign {sign}"
            );
        }
    }
    assert!(control, "нет положительного контроля");
}

#[test]
fn kx_public_rejects_wrong_length() {
    for len in [0usize, 31, 33] {
        assert_eq!(
            KxPublicKey::try_from_slice(&vec![9u8; len]).unwrap_err(),
            IdentityError::InvalidKxPublicKey,
            "len {len}"
        );
    }
}

#[test]
fn kx_public_rejects_small_order() {
    for (i, t) in curve25519_dalek::constants::EIGHT_TORSION
        .iter()
        .enumerate()
    {
        let b = t.to_montgomery().to_bytes();
        assert_eq!(
            KxPublicKey::try_from_slice(&b).unwrap_err(),
            IdentityError::InvalidKxPublicKey,
            "torsion {i}"
        );
    }
}

#[test]
fn kx_public_rejects_mixed_order() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    // положительный контроль: чистая точка основной подгруппы принимается
    let clean = ED25519_BASEPOINT_POINT;
    assert!(clean.is_torsion_free());
    assert!(KxPublicKey::try_from_slice(&clean.to_montgomery().to_bytes()).is_ok());
    // P + T (T порядка 2, 4 и 8): каноническая кодировка, не малый порядок, но не чистая
    for (i, t) in EIGHT_TORSION.iter().enumerate().skip(1) {
        let mixed = clean + t;
        assert!(!mixed.is_small_order(), "точка {i} малого порядка");
        assert!(!mixed.is_torsion_free(), "точка {i} чистая");
        assert_eq!(
            KxPublicKey::try_from_slice(&mixed.to_montgomery().to_bytes()).unwrap_err(),
            IdentityError::InvalidKxPublicKey,
            "P + T[{i}]"
        );
    }
}

fn le_u(u: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&u.to_le_bytes());
    b
}

#[test]
fn kx_public_rejects_twist() {
    // u = p - 1 = -1
    let mut minus_one = [0xFFu8; 32];
    minus_one[0] = 0xEC;
    minus_one[31] = 0x7F;
    assert!(
        curve25519_dalek::montgomery::MontgomeryPoint(minus_one)
            .to_edwards(0)
            .is_none()
    );
    assert_eq!(
        KxPublicKey::try_from_slice(&minus_one).unwrap_err(),
        IdentityError::InvalidKxPublicKey
    );
    // первое u >= 2 на кривой кручения
    let mut found = None;
    for u in 2..1000u64 {
        let b = le_u(u);
        if curve25519_dalek::montgomery::MontgomeryPoint(b)
            .to_edwards(0)
            .is_none()
        {
            found = Some(b);
            break;
        }
    }
    let b = found.expect("нет точки кручения среди первых u");
    assert_eq!(
        KxPublicKey::try_from_slice(&b).unwrap_err(),
        IdentityError::InvalidKxPublicKey
    );
}

#[test]
fn kx_public_rejects_noncanonical() {
    // положительный контроль: базовая точка и настоящий ключ принимаются
    let (_, _, k) = fresh();
    let mut base = [0u8; 32];
    base[0] = 9;
    assert!(
        KxPublicKey::try_from_slice(&base).is_ok(),
        "нет положительного контроля"
    );
    assert!(
        KxPublicKey::try_from_slice(&k.kx_public().to_bytes()).is_ok(),
        "нет положительного контроля"
    );
    // u = p + k, k = 0..=18: байты ED+k, FF*30, 7F
    for k in 0..=18u8 {
        let mut b = [0xFFu8; 32];
        b[0] = 0xED + k;
        b[31] = 0x7F;
        assert_eq!(
            KxPublicKey::try_from_slice(&b).unwrap_err(),
            IdentityError::InvalidKxPublicKey,
            "k {k}"
        );
    }
    // базовая точка с выставленным старшим битом
    let mut high = base;
    high[31] |= 0x80;
    assert_eq!(
        KxPublicKey::try_from_slice(&high).unwrap_err(),
        IdentityError::InvalidKxPublicKey
    );
}

#[test]
fn verify_rejects_other_domain() {
    let (_, _, k) = fresh();
    let sig = k.sign(SignDomain::Invite, b"m").unwrap();
    for d in SignDomain::ALL {
        if *d != SignDomain::Invite {
            assert_eq!(
                k.public_key().verify(*d, b"m", &sig).unwrap_err(),
                IdentityError::BadSignature
            );
        }
    }
}

#[test]
fn verify_rejects_modified_message() {
    let (_, _, k) = fresh();
    let sig = k.sign(SignDomain::Invite, b"message").unwrap();
    assert_eq!(
        k.public_key()
            .verify(SignDomain::Invite, b"messagE", &sig)
            .unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn verify_rejects_modified_signature() {
    let (_, _, k) = fresh();
    let sig = k.sign(SignDomain::Invite, b"m").unwrap();
    for i in [0usize, 31, 32, 63] {
        let mut bad = sig;
        bad[i] ^= 1;
        assert_eq!(
            k.public_key()
                .verify(SignDomain::Invite, b"m", &bad)
                .unwrap_err(),
            IdentityError::BadSignature,
            "byte {i}"
        );
    }
}

#[test]
fn verify_rejects_other_key() {
    let (_, _, k) = fresh();
    let sig = k.sign(SignDomain::Invite, b"m").unwrap();
    assert_eq!(
        some_public()
            .verify(SignDomain::Invite, b"m", &sig)
            .unwrap_err(),
        IdentityError::BadSignature
    );
}

#[test]
fn verify_rejects_wrong_sig_length() {
    let (_, _, k) = fresh();
    let sig = k.sign(SignDomain::Invite, b"m").unwrap();
    let mut long = sig.to_vec();
    long.push(0);
    for bad in [Vec::new(), sig[..63].to_vec(), long] {
        assert_eq!(
            k.public_key()
                .verify(SignDomain::Invite, b"m", &bad)
                .unwrap_err(),
            IdentityError::BadSignature
        );
    }
}

// ---------- ручной тест хранилища ОС ----------

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
#[test]
#[ignore = "трогает реальное хранилище ОС; запускает владелец вручную"]
fn os_store_roundtrip_manual() {
    use chervo_identity::OsKeyStore;

    struct Guard {
        service: String,
        pair: PairId,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Ok(s) = OsKeyStore::open_with_service(&self.service) {
                let _ = s.delete(&self.pair);
            }
        }
    }

    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let service = format!("chervotochina-test-{hex}");
    assert_ne!(service, DEFAULT_SERVICE);
    let p = pair();
    let _guard = Guard {
        service: service.clone(),
        pair: p,
    };

    let first = OsKeyStore::open_with_service(&service).unwrap();
    let key = create(&first, &p).unwrap();
    let expected = key.public_key();
    let kx = key.kx_public();

    let second = OsKeyStore::open_with_service(&service).unwrap();
    let loaded = load(&second, &p, &expected).unwrap();
    assert_eq!(loaded.public_key(), expected);
    assert_eq!(loaded.kx_public(), kx);

    let new = rekey(&second, &p).unwrap().public_key();
    assert_ne!(new, expected);
    assert_eq!(
        load(&first, &p, &expected).unwrap_err(),
        IdentityError::KeyMismatch
    );
    assert!(load(&first, &p, &new).is_ok());

    second.delete(&p).unwrap();
    assert_eq!(
        load(&first, &p, &new).unwrap_err(),
        IdentityError::KeyMissing
    );
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
#[test]
#[ignore = "трогает реальное хранилище ОС; запускает владелец вручную"]
fn os_list_key_roundtrip_manual() {
    use chervo_identity::OsKeyStore;

    struct Guard(String);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Ok(s) = OsKeyStore::open_with_service(&self.0) {
                let _ = s.delete_list_key();
            }
        }
    }

    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let service = format!("chervotochina-test-{hex}");
    assert_ne!(service, DEFAULT_SERVICE);
    let _guard = Guard(service.clone());

    let first = OsKeyStore::open_with_service(&service).unwrap();
    assert!(first.read_list_key().unwrap().is_none());
    first.write_list_key(&[0x5A; LIST_KEY_LEN]).unwrap();
    let second = OsKeyStore::open_with_service(&service).unwrap();
    assert_eq!(
        second.read_list_key().unwrap().unwrap().as_slice(),
        &[0x5A; LIST_KEY_LEN]
    );
    second.write_list_key(&[0x33; LIST_KEY_LEN]).unwrap();
    assert_eq!(
        first.read_list_key().unwrap().unwrap().as_slice(),
        &[0x33; LIST_KEY_LEN]
    );
    second.delete_list_key().unwrap();
    assert!(first.read_list_key().unwrap().is_none());
    second.delete_list_key().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "трогает реальное хранилище ОС; запускает владелец вручную"]
fn os_epoch_roundtrip_manual() {
    use chervo_identity::{EpochStore, OsKeyStore};

    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let service = format!("chervotochina-test-{hex}");
    assert_ne!(service, DEFAULT_SERVICE);

    let first = OsKeyStore::open_with_service(&service).unwrap();
    assert!(first.read_epoch().unwrap().is_none());
    first.write_epoch(0x0102_0304_0506_0708).unwrap();
    let second = OsKeyStore::open_with_service(&service).unwrap();
    assert_eq!(second.read_epoch().unwrap(), Some(0x0102_0304_0506_0708));
    second.write_epoch(5).unwrap();
    assert_eq!(first.read_epoch().unwrap(), Some(5));
}

/// M1, этап 17a: запись тремя методами старого клиента Secret Service. Без очистки:
/// читает `ss_migration_read_new` на итоговом коммите.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "трогает реальное хранилище ОС; запускает владелец вручную"]
fn ss_migration_write_old() {
    use chervo_identity::{EpochStore, OsKeyStore};

    let store = OsKeyStore::open_with_service("chervotochina-migration-17a").unwrap();
    let mut blob = vec![2u8];
    blob.extend_from_slice(&[0x11; 128]);
    store.write(&PairId::from_bytes([0x17; 16]), &blob).unwrap();
    store.write_list_key(&[0x5A; LIST_KEY_LEN]).unwrap();
    store.write_epoch(0x1717).unwrap();
}

/// M1, этап 17a: чтение новым клиентом записей, созданных `ss_migration_write_old` старым
/// клиентом (запущенным на коммите B0). Побайтное совпадение, затем удаление и повторное чтение.
/// Запись эпохи удалить нельзя (в `EpochStore` нет удаления): она остаётся, это 8 байт без секрета.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "трогает реальное хранилище ОС; запускает владелец вручную"]
fn ss_migration_read_new() {
    use chervo_identity::{EpochStore, OsKeyStore};

    let store = OsKeyStore::open_with_service("chervotochina-migration-17a").unwrap();
    let pair = PairId::from_bytes([0x17; 16]);
    let mut blob = vec![2u8];
    blob.extend_from_slice(&[0x11; 128]);

    assert_eq!(store.read(&pair).unwrap().unwrap().as_slice(), &blob[..]);
    assert_eq!(
        store.read_list_key().unwrap().unwrap().as_slice(),
        &[0x5A; LIST_KEY_LEN]
    );
    assert_eq!(store.read_epoch().unwrap(), Some(0x1717));

    store.delete(&pair).unwrap();
    store.delete_list_key().unwrap();
    assert!(store.read(&pair).unwrap().is_none());
    assert!(store.read_list_key().unwrap().is_none());
}
