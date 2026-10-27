//! Команды проверки выпусков: `verify-release` и `release-keys`. Только чтение, без сети.
//!
//! Ключи передаются параметром: в программе это вшитые ключи (`KeySet::embedded()`), в тестах
//! подставляется тестовый набор. Пути к ключам из командной строки или окружения не читаются.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chervo_update::{
    Freshness, KeyRole, KeySet, MAX_MANIFEST_LEN, MAX_MINISIG_LEN, Target, UpdateError, Version,
    check_artifact_path, pubkey_line, verify_manifest,
};

const USAGE_VERIFY: &str =
    "использование: chervo verify-release <манифест> <подпись> <файл>... [--allow-downgrade]";
const USAGE_KEYS: &str = "использование: chervo release-keys";

/// Короткий код ошибки для строки `FAIL <код>`: имя варианта без данных.
fn code(e: &UpdateError) -> String {
    format!("{e:?}")
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect()
}

/// Читает файл не больше `max` байт; больше значит `TooLarge`.
fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, UpdateError> {
    let io = |e: std::io::Error| UpdateError::Io(e.kind());
    let file = std::fs::File::open(path).map_err(io)?;
    let mut buf = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(io)?;
    if buf.len() > max {
        return Err(UpdateError::TooLarge);
    }
    Ok(buf)
}

/// `chervo verify-release <манифест> <подпись> <файл>... [--allow-downgrade]`.
/// Коды: 0 все файлы прошли; 1 хоть один не прошёл или манифест не прошёл; 2 ошибка использования.
pub(crate) fn verify_release(
    args: &[OsString],
    keys: Result<KeySet, UpdateError>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut allow_downgrade = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for a in args {
        match a.to_str() {
            Some("--allow-downgrade") => allow_downgrade = true,
            Some(s) if s.starts_with("--") => {
                let _ = writeln!(err, "chervo: неизвестный параметр\n{USAGE_VERIFY}");
                return 2;
            }
            _ => paths.push(PathBuf::from(a)),
        }
    }
    if paths.len() < 3 {
        let _ = writeln!(err, "{USAGE_VERIFY}");
        return 2;
    }
    let Ok(running) = Version::from_str(chervo_core::VERSION) else {
        let _ = writeln!(err, "chervo: внутренняя ошибка: версия программы неверна");
        return 2;
    };
    let target = Target::current();
    let files = &paths[2..];

    // Манифест не прошёл: одна строка FAIL на каждый файл с кодом причины.
    let verified = keys.and_then(|keys| {
        let manifest = read_capped(&paths[0], MAX_MANIFEST_LEN)?;
        let sig = read_capped(&paths[1], MAX_MINISIG_LEN)?;
        verify_manifest(&keys, &manifest, &sig)
    });
    let vm = match verified {
        Ok(vm) => vm,
        Err(e) => {
            for _ in files {
                let _ = writeln!(out, "FAIL {}", code(&e));
            }
            let _ = writeln!(err, "манифест не прошёл проверку: {e}");
            return 1;
        }
    };

    let mut all_ok = true;
    for path in files {
        match check_artifact_path(&vm, path, running, target, allow_downgrade) {
            Ok(c) => {
                let word = match c.freshness {
                    Freshness::Newer => "newer",
                    Freshness::Same => "same",
                    Freshness::OlderAllowed => "older-allowed",
                };
                let _ = writeln!(out, "OK {} {} {word}", c.artifact.name, c.version);
                if c.freshness == Freshness::OlderAllowed {
                    let _ = writeln!(
                        err,
                        "предупреждение: версия {} старее запущенной {running}; откат разрешён флагом --allow-downgrade",
                        c.version
                    );
                }
            }
            Err(e) => {
                all_ok = false;
                let _ = writeln!(out, "FAIL {}", code(&e));
                let _ = writeln!(err, "{}: {e}", path.display());
            }
        }
    }
    u8::from(!all_ok)
}

/// `chervo release-keys`: роль, key_id и строка публичного ключа для сверки с README.
/// Коды: 0 ключи есть; 1 ключи не вшиты или набор неверен; 2 ошибка использования.
pub(crate) fn release_keys(
    args: &[OsString],
    keys: Result<KeySet, UpdateError>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if !args.is_empty() {
        let _ = writeln!(err, "{USAGE_KEYS}");
        return 2;
    }
    match keys {
        Ok(keys) => {
            for (role, id, pk) in keys.list() {
                let role = match role {
                    KeyRole::Primary => "primary",
                    KeyRole::Backup => "backup",
                };
                let _ = writeln!(out, "{role} {id} {}", pubkey_line(id, &pk));
            }
            0
        }
        Err(UpdateError::NoTrustedKeys) => {
            let _ = writeln!(out, "ключи владельца не вшиты");
            1
        }
        Err(e) => {
            let _ = writeln!(out, "вшитые ключи неверны: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::{Blake2b512, Digest};
    use ed25519_dalek::{Signer, SigningKey};

    // ТЕСТОВЫЙ ключ из фиксированного зерна; к ключам релизов отношения не имеет.
    const SEED: [u8; 32] = [0x42; 32];
    const KEY_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    /// SHA-256 от байтов `hello`.
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
        let trusted = "chervo-release test";
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

    struct Fixture {
        dir: PathBuf,
        manifest: PathBuf,
        sig: PathBuf,
        file: PathBuf,
        keys: Vec<u8>,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let dir =
                std::env::temp_dir().join(format!("chervo-cli-test-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let sk = SigningKey::from_bytes(&SEED);
            let manifest_text = format!(
                "chervo-release-manifest 1\nversion 1.0.0\ncommit {}\nartifact any {HELLO_SHA256} 5 hello.txt\n",
                "ab".repeat(20)
            );
            let f = Fixture {
                manifest: dir.join("chervo-release.txt"),
                sig: dir.join("chervo-release.txt.minisig"),
                file: dir.join("renamed (1).txt"),
                keys: pubkey_file(&sk),
                dir,
            };
            std::fs::write(&f.manifest, manifest_text.as_bytes()).unwrap();
            std::fs::write(&f.sig, sign(&sk, manifest_text.as_bytes())).unwrap();
            std::fs::write(&f.file, b"hello").unwrap();
            f
        }

        fn keyset(&self) -> Result<KeySet, UpdateError> {
            KeySet::from_pubkey_files(&[(KeyRole::Primary, &self.keys)])
        }

        fn run(&self, extra: &[&Path]) -> (u8, String, String) {
            let mut args: Vec<OsString> =
                vec![self.manifest.clone().into(), self.sig.clone().into()];
            args.extend(extra.iter().map(|p| OsString::from(*p)));
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let rc = verify_release(&args, self.keyset(), &mut out, &mut err);
            (
                rc,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn verify_release_ok() {
        let f = Fixture::new("ok");
        // файл переименован браузером: ищется по хэшу
        let (rc, out, err) = f.run(&[&f.file]);
        assert_eq!(
            (rc, out.as_str()),
            (0, "OK hello.txt 1.0.0 newer\n"),
            "{err}"
        );
    }

    #[test]
    fn verify_release_tampered_exit1() {
        let f = Fixture::new("tampered");
        // изменённый файл: нет в манифесте; хороший файл рядом всё равно проходит
        let bad = f.dir.join("bad.bin");
        std::fs::write(&bad, b"hellO").unwrap();
        let (rc, out, _) = f.run(&[&f.file, &bad]);
        assert_eq!(rc, 1);
        assert_eq!(out, "OK hello.txt 1.0.0 newer\nFAIL NotInManifest\n");

        // изменённый манифест: подпись не сходится, на каждый файл по строке FAIL
        let mut m = std::fs::read(&f.manifest).unwrap();
        m[26] ^= 1;
        std::fs::write(&f.manifest, &m).unwrap();
        let (rc, out, _) = f.run(&[&f.file, &bad]);
        assert_eq!(rc, 1);
        assert_eq!(out, "FAIL BadSignature\nFAIL BadSignature\n");

        // подпись другим ключом (key_id тот же): тоже отказ
        let other = SigningKey::from_bytes(&[0x43; 32]);
        std::fs::write(&f.sig, sign(&other, &m)).unwrap();
        let (rc, out, _) = f.run(&[&f.file]);
        assert_eq!((rc, out.as_str()), (1, "FAIL BadSignature\n"));

        // нет файла манифеста
        std::fs::remove_file(&f.manifest).unwrap();
        let (rc, out, _) = f.run(&[&f.file]);
        assert_eq!((rc, out.as_str()), (1, "FAIL Io\n"));
    }

    #[test]
    fn verify_release_without_keys_fails_closed() {
        let f = Fixture::new("nokeys");
        let args: Vec<OsString> = vec![
            f.manifest.clone().into(),
            f.sig.clone().into(),
            f.file.clone().into(),
        ];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = verify_release(&args, Err(UpdateError::NoTrustedKeys), &mut out, &mut err);
        assert_eq!(rc, 1);
        assert_eq!(String::from_utf8(out).unwrap(), "FAIL NoTrustedKeys\n");
    }

    #[test]
    fn verify_release_usage_codes() {
        let f = Fixture::new("usage");
        let run = |args: &[&str]| {
            let args: Vec<OsString> = args.iter().map(OsString::from).collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            verify_release(&args, f.keyset(), &mut out, &mut err)
        };
        assert_eq!(run(&[]), 2);
        assert_eq!(run(&["a", "b"]), 2);
        assert_eq!(run(&["a", "b", "--allow-downgrade"]), 2);
        assert_eq!(run(&["a", "b", "c", "--nope"]), 2);
    }

    #[test]
    fn release_keys_lists_and_placeholder() {
        let f = Fixture::new("keys");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(release_keys(&[], f.keyset(), &mut out, &mut err), 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("primary 0807060504030201 RW"), "{text}");
        assert_eq!(
            text.trim_end().split(' ').next_back().map(str::len),
            Some(56)
        );

        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            release_keys(&[], Err(UpdateError::NoTrustedKeys), &mut out, &mut err),
            1
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "ключи владельца не вшиты\n"
        );
    }
}
