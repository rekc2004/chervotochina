//! Охрана «в продукте нет подставного хранилища ключей» (этап 18а, A1.4). Узлу хранилище
//! подставляет одна точка входа, предназначенная для тестов; она живёт в
//! `chervo-core/src/node/testing.rs` и больше нигде в `crates/*/src` (продуктовые крейты, в том
//! числе будущий `chervo-gui`) не должна встречаться. Тесты и примеры (`tests/`, `examples/`)
//! её вызывать могут.
//!
//! Текстовый разбор без `cargo`, шаблон `anchored_only.rs`.

use std::fs;
use std::path::{Path, PathBuf};

const NAME: &str = "open_with_store_for_tests";
/// Единственный разрешённый файл (путь от `crates/`, с косой чертой).
const ALLOWED: &str = "chervo-core/src/node/testing.rs";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn sources() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for e in fs::read_dir(root().join("crates")).unwrap() {
        let src = e.unwrap().path().join("src");
        if src.is_dir() {
            walk(&src, &mut files);
        }
    }
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root().join("crates"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, fs::read_to_string(&p).unwrap())
        })
        .collect()
}

/// Файлы, где встречается имя точки входа, кроме разрешённого.
fn violations(files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(rel, text)| rel != ALLOWED && text.contains(NAME))
        .map(|(rel, _)| rel.clone())
        .collect()
}

#[test]
fn guard_sees_violations() {
    let files = vec![
        ("chervo-gui/src/main.rs".to_owned(), format!("x.{NAME}(c);")),
        (ALLOWED.to_owned(), format!("pub fn {NAME}()")),
        ("chervo-core/src/lib.rs".to_owned(), "mod node;".to_owned()),
    ];
    assert_eq!(violations(&files), ["chervo-gui/src/main.rs"]);
}

#[test]
fn test_entry_point_lives_only_in_testing_rs() {
    let files = sources();
    assert!(files.len() >= 100, "просканировано файлов: {}", files.len());
    let bad = violations(&files);
    assert!(
        bad.is_empty(),
        "подставное хранилище в продуктовом коде: {bad:?}"
    );
    // положительный контроль: точка входа на месте
    let testing = files.iter().find(|(rel, _)| rel == ALLOWED).unwrap();
    assert!(testing.1.contains(&format!("pub fn {NAME}")));
}

/// Продуктовый вход использует только хранилище ОС, а подстановка недостижима из `open*`.
#[test]
fn product_open_uses_the_os_store_only() {
    let node = sources()
        .into_iter()
        .find(|(rel, _)| rel == "chervo-core/src/node/mod.rs")
        .unwrap()
        .1;
    assert!(node.contains("StoreSource::Os"));
    assert!(node.contains("OsKeyStore::open()"));
    // в продуктовых входах (`open`, `open_accept_older`, `open_start_over`) нет `Given`
    for entry in [
        "pub fn open(",
        "pub fn open_accept_older(",
        "pub fn open_start_over(",
    ] {
        let at = node.find(entry).unwrap();
        let body = &node[at..];
        let end = body.find("\n    }\n").unwrap();
        assert!(!body[..end].contains("StoreSource::Given"), "{entry}");
    }
    // файлового хранилища и подделки ключей в продуктовом коде ядра нет
    for (rel, text) in sources()
        .iter()
        .filter(|(r, _)| r.starts_with("chervo-core/src/"))
    {
        for banned in [
            "MemStore",
            "FileStore",
            "impl SecretStore for",
            "impl ListKeyStore for",
        ] {
            let allowed_wrapper = rel.ends_with("node/store.rs");
            assert!(
                allowed_wrapper || !text.contains(banned),
                "{rel}: `{banned}` в продуктовом коде ядра"
            );
        }
    }
}
