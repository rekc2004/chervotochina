//! Охрана «продукт открывает книгу друзей только с якорем» (этап 17, S1 M2): в `src/` продуктовых
//! крейтов нет вызовов `*_unanchored` (кроме их определения). Они доступны для тестов и
//! примеров; без якоря откат файла друзей не обнаруживается.
//!
//! Текстовый разбор без `cargo`. Файлы в каталогах `tests/`, `tests.rs`, `fuzz_tests.rs` и
//! всё после первого `#[cfg(test)] mod ...` (модуль тестов в конце файла) не считается
//! продуктовым кодом.

use std::fs;
use std::path::{Path, PathBuf};

const BANNED: [&str; 2] = ["open_unanchored", "start_over_unanchored"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(dir: &Path, skip_tests_dir: bool, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if skip_tests_dir && p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            walk(&p, skip_tests_dir, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let name = p.file_name().unwrap().to_string_lossy();
            if !skip_tests_dir || (name != "tests.rs" && name != "fuzz_tests.rs") {
                out.push(p);
            }
        }
    }
}

fn crate_dirs(sub: &str, skip_tests_dir: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for e in fs::read_dir(root().join("crates")).unwrap() {
        let d = e.unwrap().path().join(sub);
        if d.is_dir() {
            walk(&d, skip_tests_dir, &mut files);
        }
    }
    files
}

/// Строки кода с вызовом запрещённого имени (не комментарий, не определение `fn`).
fn violations(text: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n");
    let product = match text.find("\n#[cfg(test)]\nmod ") {
        Some(i) => &text[..i],
        None => &text,
    };
    product
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| !l.contains("fn open_unanchored") && !l.contains("fn start_over_unanchored"))
        .filter(|l| BANNED.iter().any(|b| l.contains(b)))
        .map(str::to_owned)
        .collect()
}

#[test]
fn guard_sees_violations() {
    assert_eq!(
        violations("fn f() {\n    FriendBook::open_unanchored(p, s);\n}\n").len(),
        1
    );
    assert_eq!(
        violations("x\nFriendBook::start_over_unanchored(p, k, 0);\n").len(),
        1
    );
    // определение, комментарий и тестовый хвост не считаются
    assert!(violations("pub fn open_unanchored<S>(p: &Path) {}\n").is_empty());
    assert!(violations("// FriendBook::open_unanchored(p, s)\n").is_empty());
    assert!(
        violations(
            "fn a() {}\n#[cfg(test)]\nmod t { fn x() { FriendBook::open_unanchored(p, s); } }\n"
        )
        .is_empty()
    );
}

#[test]
fn product_src_never_calls_unanchored() {
    let srcs = crate_dirs("src", true);
    assert!(srcs.len() >= 100, "просканировано файлов: {}", srcs.len());
    for p in &srcs {
        let bad = violations(&fs::read_to_string(p).unwrap());
        assert!(
            bad.is_empty(),
            "{}: вызов *_unanchored в продуктовом коде: {bad:?}",
            p.display()
        );
    }
}

/// Положительный контроль: определения на месте, а тесты и примеры их вызывают (то есть имя
/// действительно то, которым пользуются, и охрана не пуста из-за опечатки в имени).
#[test]
fn unanchored_names_exist_and_are_used_by_tests_and_examples() {
    let book = fs::read_to_string(root().join("crates/chervo-friends/src/book.rs")).unwrap();
    assert!(book.contains("pub fn open_unanchored"));
    assert!(book.contains("pub fn start_over_unanchored"));
    assert!(book.contains("pub fn open_anchored"));
    let mut users = 0;
    for sub in ["tests", "examples"] {
        for p in crate_dirs(sub, false) {
            if fs::read_to_string(&p)
                .unwrap()
                .contains("FriendBook::open_unanchored(")
            {
                users += 1;
            }
        }
    }
    assert!(users >= 5, "ожидались вызовы в тестах и примерах: {users}");
}
