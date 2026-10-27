//! Страж исходников: `src/` (кроме `src/bin/`) не ходит в сеть, не пишет на диск и не
//! запускает процессы; `Cargo.toml` перечисляет ровно разрешённые зависимости.
//! Сеть уведомления о версии (19д) живёт в другом крейте; этот страж остаётся в силе.

use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "std::net",
    "TcpStream",
    "UdpSocket",
    "std::process",
    "Command",
    "reqwest",
    "ureq",
    "hyper",
    "fs::write",
    "rename",
    "set_permissions",
    "remove_file",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            // `src/bin/` это инструменты сборки, в программу проверки они не входят
            if path.file_name().and_then(|n| n.to_str()) != Some("bin") {
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
    assert!(files.len() >= 6, "ожидались исходники крейта: {files:?}");
    for f in files {
        let text = std::fs::read_to_string(&f)
            .expect("read")
            .replace("\r\n", "\n");
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{} содержит запрещённое `{needle}`",
                f.display()
            );
        }
    }

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
                !section.contains("dependencies") || section == "[dependencies]",
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
    assert_eq!(deps, ["blake2", "ed25519-dalek", "ring"]);
}
