//! Охрана «ядро запускает другую программу ровно в одном месте» (этап 18б, Н7): запуск
//! проводника для «Открыть папку приёма» живёт в `src/node/open_folder.rs`, и только там есть
//! `Command::new`. Оболочек (`cmd`, `sh`, `bash`, `powershell`) и склейки аргументов в запуске
//! нет. Тестовые модули (`src/node/tests.rs`, `src/update_tests.rs`) охраной не проверяются.
//! Текстовый разбор без `cargo`.

use std::fs;
use std::path::{Path, PathBuf};

const ALLOWED: &str = "src/node/open_folder.rs";
const SKIPPED: [&str; 2] = ["src/node/tests.rs", "src/update_tests.rs"];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Метка в списке строк: блок `#[cfg(test)] ... { ... }` не закрылся (скобки в строках сбили счёт).
/// Страж на неё падает, а не молча пропускает остаток файла.
const UNBALANCED: &str = "<<незакрытый блок #[cfg(test)]>>";

/// Строки кода без строк-комментариев и без ТЕЛА блока `#[cfg(test)] mod x { ... }` (или другого
/// элемента с телом). `#[cfg(test)] mod tests;` и `#[cfg(test)] use ...;` без тела концом файла
/// не считаются: код после них остаётся под охраной. Скобки считаются по тексту строк.
fn product_code(text: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if !line.trim_start().starts_with("#[cfg(test)]") {
            out.push(line.to_owned());
            i += 1;
            continue;
        }
        // первая строка после атрибутов, где есть `{` или `;`
        let mut j = i + 1;
        let mut header = None;
        while j < lines.len() {
            let t = lines[j];
            let (open, semi) = (t.find('{'), t.find(';'));
            if open.is_some() && semi.is_none_or(|s| open.is_some_and(|o| o < s)) {
                header = Some(j);
                break;
            }
            if semi.is_some() {
                break;
            }
            j += 1;
        }
        let Some(start) = header else {
            // элемент без тела (`mod tests;`): строки остаются под охраной
            out.push(line.to_owned());
            i += 1;
            continue;
        };
        let mut depth: i32 = 0;
        let mut k = start;
        let mut closed = false;
        while k < lines.len() {
            for c in lines[k].chars() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            k += 1;
            if depth <= 0 {
                closed = true;
                break;
            }
        }
        if !closed {
            out.push(UNBALANCED.to_owned());
        }
        i = k;
    }
    out.into_iter()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

fn sources() -> Vec<(String, Vec<String>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let out: Vec<_> = files
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(root)
                .expect("under crate dir")
                .to_string_lossy()
                .replace('\\', "/");
            if SKIPPED.contains(&rel.as_str()) {
                return None;
            }
            let text = fs::read_to_string(&p).expect("read source");
            Some((rel, product_code(&text)))
        })
        .collect();
    assert!(out.len() >= 10, "исходники не найдены: {}", out.len());
    out
}

/// Слово `word` целиком (границы: не буква, не цифра, не `_`).
fn has_word(line: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(word).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

fn violations(files: &[(String, Vec<String>)]) -> Vec<String> {
    let mut bad = Vec::new();
    let mut allowed_seen = 0;
    for (name, lines) in files {
        for l in lines {
            if l == UNBALANCED {
                bad.push(format!("{name}: {UNBALANCED}"));
                continue;
            }
            // любое упоминание модуля `process` (в том числе `use std::process::{Command as X}`,
            // `use std::process as p`, `use std::{process, ..}`) и самого запуска вне разрешённого
            // файла; `process::id()` это не запуск, но запрещён так же: он здесь не нужен
            // `rustix::process` (запрет дампов, владелец каталога) процессов не запускает
            let spawns = l.contains("Command::new")
                || has_word(&l.replace("rustix::process", "rustix"), "process");
            if name == ALLOWED {
                if l.contains("Command::new(") {
                    allowed_seen += 1;
                }
                for shell in [
                    "\"cmd",
                    "\"sh\"",
                    "\"bash",
                    "\"powershell",
                    "\"-c\"",
                    "\"/c\"",
                ] {
                    if l.contains(shell) {
                        bad.push(format!("{name}: оболочка {shell}: {}", l.trim()));
                    }
                }
                // один аргумент, без форматирования строки запуска
                if l.contains("Command::new(format!") || l.contains(".args(") {
                    bad.push(format!("{name}: склейка аргументов: {}", l.trim()));
                }
            } else if spawns || l.contains("std::process::Stdio") {
                bad.push(format!("{name}: {}", l.trim()));
            }
        }
    }
    if allowed_seen != 1 {
        bad.push(format!(
            "{ALLOWED}: Command::new встречается {allowed_seen} раз, нужно 1"
        ));
    }
    bad
}

#[test]
fn only_open_folder_starts_a_process() {
    let bad = violations(&sources());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn control_guard_can_fail() {
    let ok = vec![(
        ALLOWED.to_owned(),
        vec!["let c = Command::new(program).arg(dir);".to_owned()],
    )];
    assert!(violations(&ok).is_empty());
    let other = vec![
        ok[0].clone(),
        (
            "src/node/x.rs".to_owned(),
            vec!["std::process::Command::new(\"ls\");".to_owned()],
        ),
    ];
    assert!(!violations(&other).is_empty());
    let shell = vec![(
        ALLOWED.to_owned(),
        vec!["let c = Command::new(\"cmd\").arg(\"/c\");".to_owned()],
    )];
    assert!(!violations(&shell).is_empty());
    let two = vec![(
        ALLOWED.to_owned(),
        vec!["Command::new(a);".to_owned(), "Command::new(b);".to_owned()],
    )];
    assert!(!violations(&two).is_empty());
    // комментарий и тестовый модуль не считаются
    let commented = vec![
        ok[0].clone(),
        (
            "src/node/y.rs".to_owned(),
            product_code(
                "// Command::new(x)\nfn a() {}\n#[cfg(test)]\nmod t { fn b() { Command::new(c); } }\n",
            ),
        ),
    ];
    assert!(violations(&commented).is_empty());
    // `#[cfg(test)] mod tests;` без тела концом файла не считается: код после него проверяется
    let after_decl = vec![
        ok[0].clone(),
        (
            "src/node/mod.rs".to_owned(),
            product_code(
                "#[cfg(test)]\nmod tests;\nfn later() { std::process::Command::new(\"x\"); }\n",
            ),
        ),
    ];
    assert!(!violations(&after_decl).is_empty());
    // а тело `#[cfg(test)] mod tests { ... }` пропускается, и код после него тоже виден
    let after_body = vec![
        ok[0].clone(),
        (
            "src/node/z.rs".to_owned(),
            product_code(
                "#[cfg(test)]\nmod tests {\n    fn t() { Command::new(a); }\n}\nfn later() { Command::new(b); }\n",
            ),
        ),
    ];
    assert_eq!(violations(&after_body).len(), 1);
    // незакрытый блок не прячет остаток молча
    let open = vec![
        ok[0].clone(),
        (
            "src/node/w.rs".to_owned(),
            product_code("#[cfg(test)]\nmod tests {\n    let s = \"{\";\n"),
        ),
    ];
    assert!(!violations(&open).is_empty());
    // псевдоним `Command` и `use std::process as p` вне разрешённого файла
    for alias in [
        "use std::process::{Command as X};",
        "use std::process as p;",
        "use std::{fs, process};",
        "let x = process::Command::new(a);",
    ] {
        let aliased = vec![
            ok[0].clone(),
            ("src/node/v.rs".to_owned(), vec![alias.to_owned()]),
        ];
        assert!(!violations(&aliased).is_empty(), "{alias}");
    }
    // имя `harden_process` слово `process` не содержит
    let harden = vec![
        ok[0].clone(),
        (
            "src/harden.rs".to_owned(),
            vec!["pub fn harden_process() {}".to_owned()],
        ),
    ];
    assert!(violations(&harden).is_empty());
}
