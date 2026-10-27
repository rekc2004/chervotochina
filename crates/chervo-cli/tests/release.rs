//! Команды проверки выпусков через настоящий бинарь `chervo` и вшитые ключи.
//! Положительный и подделанный случаи с тестовым ключом живут в модульных тестах
//! `src/release.rs` (вшитые ключи подменить нельзя, это и есть смысл вшивания).

use std::path::PathBuf;
use std::process::{Command, Output};

fn chervo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chervo"))
        .args(args)
        .output()
        .expect("run chervo")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Пока владелец не вшил ключи, набор пуст; когда вшил, тесты проверяют другую ветку.
fn keys_embedded() -> bool {
    chervo_update::KeySet::embedded().is_ok()
}

#[test]
fn verify_release_usage_exit2() {
    for args in [
        &["verify-release"][..],
        &["verify-release", "a", "b"],
        &["verify-release", "a", "b", "--allow-downgrade"],
        &["verify-release", "a", "b", "c", "--bogus"],
        &["release-keys", "extra"],
    ] {
        let out = chervo(args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn release_keys_placeholder_exit1() {
    let out = chervo(&["release-keys"]);
    if keys_embedded() {
        // ключи вшиты: два ключа, по строке на каждый
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            text(&out.stdout).lines().count(),
            2,
            "{}",
            text(&out.stdout)
        );
    } else {
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(text(&out.stdout), "ключи владельца не вшиты\n");
    }
}

#[test]
fn verify_release_without_valid_keys_or_files_exit1() {
    let dir: PathBuf = std::env::temp_dir().join(format!("chervo-cli-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let m = dir.join("m.txt");
    let s = dir.join("m.txt.minisig");
    let f = dir.join("f.bin");
    for p in [&m, &s, &f] {
        std::fs::write(p, b"junk").unwrap();
    }
    let out = chervo(&[
        "verify-release",
        m.to_str().unwrap(),
        s.to_str().unwrap(),
        f.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    if keys_embedded() {
        assert_eq!(stdout, "FAIL MalformedSignature\n");
    } else {
        assert_eq!(stdout, "FAIL NoTrustedKeys\n");
    }
    assert!(!stdout.contains("junk"));
}
