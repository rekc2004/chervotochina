#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Тесты `update.rs` (этап 19г-1): таблица решений и сверка файлов выпуска. Подписи делает
//! ТЕСТОВЫЙ ключ из фиксированного зерна; к ключам релизов он отношения не имеет.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};

use super::*;

// ТЕСТОВЫЙ ключ из зерна (не ключ релизов).
const SEED: [u8; 32] = [0x42; 32];
const KEY_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// SHA-256 от байтов `hello`, `world`.
const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const WORLD_SHA256: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn v(major: u32, minor: u32, patch: u32) -> Version {
    Version {
        major,
        minor,
        patch,
    }
}

// ---------------------------------------------------------------------------- решения

const E: UpdateConsent = UpdateConsent::Enabled;

#[test]
fn update_decide_table() {
    use Decision::{Deny, Permit, RecordOnly};
    const DAY: u64 = UPDATE_CHECK_INTERVAL_SECS;
    const MIN: u64 = MANUAL_CHECK_FLOOR_SECS;
    let rows: Vec<(&str, UpdateConsent, u64, u64, bool, Decision)> = vec![
        // согласия нет или отказ: всегда Deny
        (
            "not asked bg",
            UpdateConsent::NotAsked,
            0,
            DAY * 9,
            false,
            Deny,
        ),
        (
            "not asked manual",
            UpdateConsent::NotAsked,
            0,
            DAY * 9,
            true,
            Deny,
        ),
        (
            "disabled bg",
            UpdateConsent::Disabled,
            0,
            DAY * 9,
            false,
            Deny,
        ),
        (
            "disabled manual",
            UpdateConsent::Disabled,
            1,
            DAY * 9,
            true,
            Deny,
        ),
        // фон
        ("bg never checked", E, 0, 1_700_000_000, false, Permit),
        ("bg never checked now=0", E, 0, 0, false, Deny),
        ("bg 86399 s", E, 1000, 1000 + DAY - 1, false, Deny),
        ("bg 86400 s", E, 1000, 1000 + DAY, false, Permit),
        ("bg same second", E, 1000, 1000, false, Deny),
        ("bg clock back", E, 1000, 999, false, RecordOnly),
        ("bg clock back now=0", E, 1000, 0, false, Deny),
        ("bg last=MAX", E, u64::MAX, 5, false, RecordOnly),
        ("bg last=MAX now=MAX", E, u64::MAX, u64::MAX, false, Deny),
        ("bg now=MAX", E, 1000, u64::MAX, false, Permit),
        // кнопка
        ("manual 59 s", E, 1000, 1000 + MIN - 1, true, Deny),
        ("manual 60 s", E, 1000, 1000 + MIN, true, Permit),
        ("manual same second", E, 1000, 1000, true, Deny),
        ("manual clock back", E, 1000, 999, true, Permit),
        ("manual never checked", E, 0, 1_700_000_000, true, Permit),
        ("manual last=MAX", E, u64::MAX, 5, true, Permit),
        ("manual now=0 last=0", E, 0, 0, true, Deny),
        (
            "manual now=0 last=1000 (clock back to 0)",
            E,
            1000,
            0,
            true,
            Deny,
        ),
        (
            "bg now=0 last=MAX (clock back to 0)",
            E,
            u64::MAX,
            0,
            false,
            Deny,
        ),
        ("manual now=0 last=MAX", E, u64::MAX, 0, true, Deny),
        ("manual now=MAX", E, 1000, u64::MAX, true, Permit),
        // кнопка работает и внутри суток после фонового запроса
        ("manual after bg 1 h", E, 5000, 5000 + 3600, true, Permit),
    ];
    assert!(rows.len() >= 14);
    for (name, consent, last, now, manual, want) in rows {
        assert_eq!(decide(consent, last, now, manual), want, "{name}");
    }
}

#[test]
fn permit_issue_is_internal_only() {
    // `check_latest` тратит разрешение: после вызова значения нет (проверка типом: передача по значению)
    let p = UpdateCheckPermit::issue();
    assert!(format!("{p:?}").contains("UpdateCheckPermit"));
}

// ---------------------------------------------------------------------------- сверка файлов

fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (c.get(1).copied().map_or(0, u32::from) << 8)
            | c.get(2).copied().map_or(0, u32::from);
        let ch = |s: u32| ALPHABET[((n >> s) & 63) as usize] as char;
        out.push(ch(18));
        out.push(ch(12));
        out.push(if c.len() > 1 { ch(6) } else { '=' });
        out.push(if c.len() > 2 { ch(0) } else { '=' });
    }
    out
}

fn pubkey_file(sk: &SigningKey) -> Vec<u8> {
    let mut raw = b"Ed".to_vec();
    raw.extend_from_slice(&KEY_ID);
    raw.extend_from_slice(&sk.verifying_key().to_bytes());
    format!("untrusted comment: test\n{}\n", b64(&raw)).into_bytes()
}

fn sign(sk: &SigningKey, manifest: &[u8]) -> Vec<u8> {
    let sig = sk.sign(Blake2b512::digest(manifest).as_slice()).to_bytes();
    let mut raw = b"ED".to_vec();
    raw.extend_from_slice(&KEY_ID);
    raw.extend_from_slice(&sig);
    // комментарий с bidi-символом: наружу он не выходит
    let trusted = "chervo-release test \u{202E}evil";
    let mut gm = sig.to_vec();
    gm.extend_from_slice(trusted.as_bytes());
    let global = sk.sign(&gm).to_bytes();
    format!(
        "untrusted comment: sig\n{}\ntrusted comment: {trusted}\n{}\n",
        b64(&raw),
        b64(&global)
    )
    .into_bytes()
}

fn keyset() -> Result<KeySet, UpdateError> {
    let sk = SigningKey::from_bytes(&SEED);
    KeySet::from_pubkey_files(&[(KeyRole::Primary, &pubkey_file(&sk))])
}

struct Fx {
    dir: PathBuf,
    manifest: PathBuf,
    sig: PathBuf,
}

impl Fx {
    /// Каталог с подписанным списком: `hello.txt` (any), `world.bin` (windows-x86_64).
    fn new(tag: &str, version: &str) -> Fx {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("chervo-core-upd-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let text = format!(
            "chervo-release-manifest 1\nversion {version}\ncommit {}\n\
             artifact any {HELLO_SHA256} 5 hello.txt\n\
             artifact windows-x86_64 {WORLD_SHA256} 5 world.bin\n",
            "ab".repeat(20)
        );
        let fx = Fx {
            manifest: dir.join("chervo-release.txt"),
            sig: dir.join("chervo-release.txt.minisig"),
            dir,
        };
        fx.put_signed(text.as_bytes());
        fx
    }

    fn put_signed(&self, manifest: &[u8]) {
        let sk = SigningKey::from_bytes(&SEED);
        std::fs::write(&self.manifest, manifest).unwrap();
        std::fs::write(&self.sig, sign(&sk, manifest)).unwrap();
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn run(
        &self,
        running: Version,
        target: Option<Target>,
        files: &[PathBuf],
        allow: bool,
    ) -> Result<ReleaseCheck, UpdateError> {
        verify_release_files_with(
            keyset(),
            Some(running),
            target,
            &self.manifest,
            &self.sig,
            files,
            allow,
        )
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn verdict(name: &str, target: Target, freshness: Freshness) -> Result<FileVerdict, UpdateError> {
    Ok(FileVerdict {
        name: name.to_owned(),
        target,
        freshness,
    })
}

#[test]
fn verify_files_ok_newer_same_older() {
    let fx = Fx::new("ok", "1.0.0");
    let hello = fx.file("renamed (1).txt", b"hello");
    let files = std::slice::from_ref(&hello);
    let tgt = Some(Target::LinuxX86_64);

    let newer = fx.run(v(0, 9, 0), tgt, files, false).unwrap();
    assert_eq!(newer.version, v(1, 0, 0));
    assert_eq!(newer.signer.role, KeyRole::Primary);
    assert_eq!(newer.signer.key_id, KeyId(KEY_ID));
    // имя берётся из подписанного списка, не с диска
    assert_eq!(
        newer.files,
        vec![verdict("hello.txt", Target::Any, Freshness::Newer)]
    );
    let same = fx.run(v(1, 0, 0), tgt, files, false).unwrap();
    assert_eq!(
        same.files,
        vec![verdict("hello.txt", Target::Any, Freshness::Same)]
    );
    // откат: без флага ошибка, с флагом особый итог
    let older = fx.run(v(2, 0, 0), tgt, files, false).unwrap();
    assert_eq!(
        older.files,
        vec![Err(UpdateError::Downgrade {
            running: v(2, 0, 0),
            offered: v(1, 0, 0)
        })]
    );
    let allowed = fx.run(v(2, 0, 0), tgt, files, true).unwrap();
    assert_eq!(
        allowed.files,
        vec![verdict("hello.txt", Target::Any, Freshness::OlderAllowed)]
    );
}

#[test]
fn verify_files_no_keys_reads_nothing() {
    // ни списка, ни подписи, ни файла на диске нет: ошибка ключей раньше любого чтения
    let missing = Path::new("/nonexistent/chervo/none.txt");
    let r = verify_release_files_with(
        Err(UpdateError::NoTrustedKeys),
        running_version(),
        Target::current(),
        missing,
        missing,
        &[missing.to_path_buf()],
        false,
    );
    assert_eq!(r, Err(UpdateError::NoTrustedKeys));
    // и без версии программы чтение тоже не начинается
    let r = verify_release_files_with(keyset(), None, None, missing, missing, &[], false);
    assert_eq!(r, Err(UpdateError::Io(std::io::ErrorKind::InvalidData)));
    // а с ключами и несуществующим списком это уже Io
    let r = verify_release_files_with(
        keyset(),
        Some(v(1, 0, 0)),
        None,
        missing,
        missing,
        &[],
        false,
    );
    assert!(matches!(r, Err(UpdateError::Io(_))), "{r:?}");
}

#[test]
fn verify_files_manifest_oversize() {
    let fx = Fx::new("mbig", "1.0.0");
    // ровно предел проходит чтение (дальше разбор скажет своё), предел плюс байт нет
    std::fs::write(&fx.manifest, vec![b'a'; MAX_MANIFEST_LEN + 1]).unwrap();
    let r = fx.run(v(1, 0, 0), None, &[], false);
    assert_eq!(r, Err(UpdateError::TooLarge));
    std::fs::write(&fx.manifest, vec![b'a'; MAX_MANIFEST_LEN]).unwrap();
    let r = fx.run(v(1, 0, 0), None, &[], false);
    assert_ne!(r, Err(UpdateError::TooLarge));
}

#[test]
fn verify_files_sig_oversize() {
    let fx = Fx::new("sbig", "1.0.0");
    std::fs::write(&fx.sig, vec![b'a'; MAX_MINISIG_LEN + 1]).unwrap();
    let r = fx.run(v(1, 0, 0), None, &[], false);
    assert_eq!(r, Err(UpdateError::TooLarge));
}

#[test]
fn verify_files_mixed_results() {
    let fx = Fx::new("mixed", "1.0.0");
    let hello = fx.file("a.txt", b"hello");
    let world = fx.file("b.bin", b"world");
    let other = fx.file("c.txt", b"abc");
    let gone = fx.dir.join("gone.txt");
    let files = [hello.clone(), world, other, gone];
    let r = fx
        .run(v(1, 0, 0), Some(Target::LinuxX86_64), &files, false)
        .unwrap();
    assert_eq!(r.files.len(), 4, "по одному итогу на файл, в порядке ввода");
    assert_eq!(
        r.files[0],
        verdict("hello.txt", Target::Any, Freshness::Same)
    );
    assert_eq!(
        r.files[1],
        Err(UpdateError::WrongTarget {
            expected: Some(Target::LinuxX86_64),
            found: Target::WindowsX86_64
        })
    );
    assert_eq!(r.files[2], Err(UpdateError::NotInManifest));
    assert_eq!(
        r.files[3],
        Err(UpdateError::Io(std::io::ErrorKind::NotFound))
    );
    // та же цель, что в списке: файл подходит
    let on_win = fx
        .run(v(1, 0, 0), Some(Target::WindowsX86_64), &files[1..2], false)
        .unwrap();
    assert_eq!(
        on_win.files,
        vec![verdict("world.bin", Target::WindowsX86_64, Freshness::Same)]
    );
    // откат: без флага и с флагом, в одном порядке
    let down = fx
        .run(v(3, 0, 0), None, std::slice::from_ref(&hello), false)
        .unwrap();
    assert!(matches!(down.files[0], Err(UpdateError::Downgrade { .. })));
    let allowed = fx
        .run(v(3, 0, 0), None, std::slice::from_ref(&hello), true)
        .unwrap();
    assert_eq!(
        allowed.files[0],
        verdict("hello.txt", Target::Any, Freshness::OlderAllowed)
    );
}

#[test]
fn verify_files_bad_signature_whole_err() {
    let fx = Fx::new("bad", "1.0.0");
    let hello = fx.file("a.txt", b"hello");
    // список изменён после подписи
    let mut text = std::fs::read(&fx.manifest).unwrap();
    text.extend_from_slice(b"artifact any 00 1 x\n");
    std::fs::write(&fx.manifest, &text).unwrap();
    let r = fx.run(v(1, 0, 0), None, std::slice::from_ref(&hello), false);
    assert_eq!(r, Err(UpdateError::BadSignature));
    // файл подписи мусор
    let fx = Fx::new("bad2", "1.0.0");
    std::fs::write(&fx.sig, b"garbage\n").unwrap();
    let r = fx.run(v(1, 0, 0), None, &[], false);
    assert!(r.is_err());
    // подпись чужим ключом
    let fx = Fx::new("bad3", "1.0.0");
    let other = SigningKey::from_bytes(&[0x43; 32]);
    let manifest = std::fs::read(&fx.manifest).unwrap();
    std::fs::write(&fx.sig, sign(&other, &manifest)).unwrap();
    let r = fx.run(v(1, 0, 0), None, &[], false);
    assert_eq!(r, Err(UpdateError::BadSignature));
}

#[test]
fn verify_files_not_regular_is_io_not_blocking() {
    let fx = Fx::new("dirs", "1.0.0");
    // каталог вместо файла: Io без чтения
    let r = fx.run(v(1, 0, 0), None, std::slice::from_ref(&fx.dir), false);
    assert_eq!(
        r.unwrap().files,
        vec![Err(UpdateError::Io(std::io::ErrorKind::InvalidInput))]
    );
    // каталог вместо списка
    let r = verify_release_files_with(
        keyset(),
        Some(v(1, 0, 0)),
        None,
        &fx.dir,
        &fx.sig,
        &[],
        false,
    );
    assert_eq!(r, Err(UpdateError::Io(std::io::ErrorKind::InvalidInput)));
}

#[test]
fn embedded_keys_agree_with_keyset() {
    match (embedded_keys(), KeySet::embedded()) {
        (Ok(a), Ok(k)) => assert_eq!(a, embedded_of(&k)),
        (Err(a), Err(b)) => assert_eq!(a, b),
        _ => panic!("embedded_keys и KeySet::embedded разошлись"),
    }
}

#[test]
fn running_version_is_the_crate_version() {
    assert_eq!(
        running_version().map(|v| v.to_string()),
        Some(crate::VERSION.to_owned())
    );
}
