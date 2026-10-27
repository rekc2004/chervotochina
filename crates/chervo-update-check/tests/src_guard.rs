//! Страж исходников: в `src/` (кроме тестового модуля `src/tests/`) нет запуска процессов,
//! чтения окружения и файлов, UDP, чужих HTTP-клиентов и печати; соединение открывается в одном
//! месте; `Cargo.toml` перечисляет ровно разрешённые зависимости. Сети в `chervo-update` нет
//! (его страж в силе), она только здесь.

use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "std::process",
    "Command",
    "std::env::var",
    "fs::",
    "UdpSocket",
    "reqwest",
    "hyper",
    "ureq",
    "println!",
    "eprintln!",
    "print!(",
    "dbg!",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            // тестовый модуль собирается только при cfg(test)
            if path.file_name().and_then(|n| n.to_str()) != Some("tests") {
                rs_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn src_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    assert!(files.len() >= 4, "ожидались исходники крейта: {files:?}");
    let mut connects = 0;
    for f in &files {
        let text = std::fs::read_to_string(f)
            .expect("read")
            .replace("\r\n", "\n");
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{} содержит запрещённое `{needle}`",
                f.display()
            );
        }
        connects += text.matches("TcpStream::connect").count();
        // тестовые модули только в lib.rs и только через `mod tests;` (каталог исключён выше)
        if f.file_name().and_then(|n| n.to_str()) != Some("lib.rs") {
            assert!(
                !text.contains("#[cfg(test)]"),
                "{}: тестовый код вне src/tests",
                f.display()
            );
        }
    }
    assert_eq!(connects, 1, "TcpStream::connect* должен быть в одном месте");

    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("Cargo.toml")
        .replace("\r\n", "\n");
    let mut section = String::new();
    let mut deps: Vec<String> = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.to_owned();
            assert!(
                !section.contains("dependencies")
                    || section == "[dependencies]"
                    || section == "[dev-dependencies]",
                "лишний раздел зависимостей: {section}"
            );
            continue;
        }
        if section == "[dependencies]" && !t.is_empty() && !t.starts_with('#') {
            let name = t.split(['=', '.', ' ']).next().unwrap_or("").to_owned();
            deps.push(name);
        }
    }
    deps.sort();
    assert_eq!(deps, ["chervo-update", "rustls", "webpki-roots"]);
}
