//! Общее для охранных тестов: обход `src/` и строки кода без комментариев. Текстовый разбор без
//! `cargo`, как у охран в `chervo-core/tests`.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// (путь от корня крейта с `/`, текст с `\n`) для каждого файла под `src/`.
pub fn src_files() -> Vec<(String, String)> {
    let root = crate_dir();
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    assert!(!files.is_empty(), "src/ пуст: охрана ничего не проверяет");
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("under crate dir")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&p)
                .expect("read source")
                .replace("\r\n", "\n");
            (rel, text)
        })
        .collect()
}

/// Код без строк-комментариев и без хвостовых `// ...`. Упоминание в комментарии не считается.
pub fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| match l.find(" //") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Файлы `files`, чей код содержит любой из `needles`: `(файл, номер строки, строка)`.
pub fn hits(files: &[(String, String)], needles: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, text) in files {
        for (i, line) in code(text).lines().enumerate() {
            if needles.iter().any(|n| line.contains(n)) {
                out.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    out
}
