mod common;

use chervo_identity::{
    ACCOUNT_PREFIX, DEFAULT_SERVICE, DeviceId, IdentityError, KEY_BLOB_LEN, PairId, PairKey,
    PublicKey, SecretStore, SignDomain, UnavailableKeyStore, create, load, rekey,
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

// ---------- заглушка DeviceId ----------

#[test]
fn device_id_roundtrip() {
    assert_eq!(DeviceId::from_bytes([7; 32]).as_bytes(), &[7; 32]);
}

#[test]
fn debug_does_not_leak_key() {
    assert_eq!(
        format!("{:?}", DeviceId::from_bytes([0xAB; 32])),
        "DeviceId(..)"
    );
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
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
    }
}

#[test]
fn domain_tags_prefix_free() {
    let tags: Vec<&[u8]> = SignDomain::ALL.iter().map(|d| d.tag()).collect();
    assert_eq!(tags.len(), 3);
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
    ];
    for f in files {
        let mut text = std::fs::read_to_string(&f).unwrap();
        // Имена lint-атрибутов `clippy::print_stdout`/`print_stderr` содержат "stdout"/"stderr".
        text = text.replace("print_stdout", "").replace("print_stderr", "");
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
    for len in [64usize, 66, 1 << 20] {
        let mut b = vec![0x5A; len];
        b[0] = 1;
        assert_eq!(load_fixed(b), IdentityError::CorruptKey, "len {len}");
    }
}

#[test]
fn blob_unknown_version_rejected() {
    for v in [0x00u8, 0x02, 0xFF] {
        for len in [65usize, 10] {
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
    for len in 0..=130usize {
        let mut b = vec![0x5A; len];
        if let Some(f) = b.first_mut() {
            *f = 1;
        }
        assert_eq!(load_fixed(b), IdentityError::CorruptKey, "len {len}");
    }
    for v in 0..=255u8 {
        let mut b = vec![0x5A; 65];
        b[0] = v;
        let want = if v == 1 {
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
    for k in [identity, minus_one, identity_sign] {
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

    let second = OsKeyStore::open_with_service(&service).unwrap();
    assert_eq!(load(&second, &p, &expected).unwrap().public_key(), expected);

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
