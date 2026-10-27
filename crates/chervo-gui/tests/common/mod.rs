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
///
/// `//` внутри строкового литерала (в том числе растянутого на несколько строк) комментарием не
/// считается: `"https://x"` остаётся целиком. Блочные комментарии и сырые строки не разбираются.
pub fn code(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_string = false;
    for line in text.lines() {
        if !in_string && line.trim_start().starts_with("//") {
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let mut kept = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if in_string {
                kept.push(c);
                if c == '\\' && i + 1 < chars.len() {
                    kept.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == '"' {
                    in_string = false;
                }
                i += 1;
                continue;
            }
            match c {
                '"' => {
                    in_string = true;
                    kept.push(c);
                }
                // символьный литерал ('"', '\'', '\n'); `'a` без закрывающей кавычки это время жизни
                '\'' => {
                    let lit_len = if chars.get(i + 1) == Some(&'\\') {
                        chars[i + 2..]
                            .iter()
                            .position(|x| *x == '\'')
                            .map(|p| p + 3)
                    } else if chars.get(i + 2) == Some(&'\'') {
                        Some(3)
                    } else {
                        None
                    };
                    let n = lit_len.unwrap_or(1);
                    kept.extend(&chars[i..i + n]);
                    i += n;
                    continue;
                }
                '/' if chars.get(i + 1) == Some(&'/') => break,
                _ => kept.push(c),
            }
            i += 1;
        }
        out.push(kept.trim_end().to_owned());
    }
    out.join("\n")
}

/// Строка, внутри которой (по отступам) лежит строка `idx`: ближайшая выше строка с меньшим
/// отступом и `=>`, то есть заголовок ветки `match`. `None`, если такой нет.
pub fn enclosing_arm<'a>(lines: &[&'a str], idx: usize) -> Option<&'a str> {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut cur = indent(lines.get(idx)?);
    for l in lines[..idx].iter().rev() {
        if l.trim().is_empty() {
            continue;
        }
        let ind = indent(l);
        if ind < cur {
            if l.contains("=>") {
                return Some(l);
            }
            cur = ind;
        }
    }
    None
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
