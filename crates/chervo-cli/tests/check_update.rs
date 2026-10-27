//! `chervo check-update` через настоящий бинарь. Сети в этих тестах нет: ключи владельца в
//! репозитории пока не вшиты (пустые файлы), поэтому запрос не делается вовсе.

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

#[test]
fn check_update_usage_exit2() {
    for args in [
        &["check-update", "extra"][..],
        &["check-update", "--help"],
        &["check-update", ""],
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

/// Пока владелец не вшил ключи: сообщение «не вшиты», код 1 и ни слова о запросе (сети нет).
/// Когда вшил, этот тест пропускается: настоящий запрос в сеть из тестов не делается.
#[test]
fn check_update_no_keys_exit1() {
    if chervo_update::KeySet::embedded().is_ok() {
        eprintln!("ключи вшиты: тест «без ключей» пропущен, чтобы не ходить в сеть");
        return;
    }
    let out = chervo(&["check-update"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("не вшиты"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "о запросе в сеть не сообщаем: его нет"
    );
}
