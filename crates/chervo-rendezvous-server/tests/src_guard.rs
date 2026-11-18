#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Охрана исходников эхо-сервера (этап 13д, Р4): ничего не пишется на диск, нет журналов, процессов,
//! TCP, DNS и асинхронной среды; ровно два места отправки (ответ эха и ответ проверки); печать только
//! в `main.rs` и только строкой старта, строкой счётчиков и подсказкой `USAGE` (плюс фиксированный
//! текст `BIND_FAILED` при отказе привязки: адресов в нём нет).

use std::fs;
use std::path::Path;

/// Исходники производственного кода: `src/*.rs`, без каталога `src/tests`.
fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // комментарии и перечень lint-ов в атрибутах не код: слова в них не считаются
        let text: String = fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.contains("clippy::"))
            .map(|l| format!("{l}\n"))
            .collect();
        out.push((name, text));
    }
    out.sort();
    out
}

/// Код без тестового модуля `#[cfg(test)] mod tests { .. }` внутри файла (он стоит в конце файла).
fn production_part(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

fn hits(src: &[(String, String)], needle: &str) -> Vec<String> {
    src.iter()
        .filter(|(_, t)| production_part(t).contains(needle))
        .map(|(n, _)| n.clone())
        .collect()
}

fn count(src: &[(String, String)], needle: &str) -> usize {
    src.iter()
        .map(|(_, t)| production_part(t).matches(needle).count())
        .sum()
}

const BANNED: [&str; 15] = [
    "fs::",
    "File::",
    "OpenOptions",
    "log::",
    "tracing",
    "process::Command",
    "TcpListener",
    "TcpStream",
    "to_socket_addrs",
    "tokio",
    "unsafe",
    "std::env::var",
    "dbg!",
    "stdout",
    "env::args(",
];

#[test]
fn src_guard() {
    let src = sources();
    let names: Vec<&str> = src.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        ["lib.rs", "main.rs", "limiter.rs", "args.rs"]
            .iter()
            .all(|n| names.contains(n)),
        "исходники не найдены: {names:?}"
    );
    for needle in BANNED {
        let files = hits(&src, needle);
        assert!(files.is_empty(), "{needle} найдено в {files:?}");
    }
    // println! (stdout) нигде; eprintln! отдельно ниже
    for (n, t) in &src {
        assert!(
            !production_part(t)
                .replace("eprintln!", "")
                .contains("println!"),
            "println! в {n}"
        );
    }
    // ровно два места отправки: ответ эха и ответ проверки
    assert_eq!(count(&src, "send_to("), 2, "send_to( должно быть ровно два");
    assert_eq!(count(&src, "send("), 0, "send( не нужен");
    // печать только в main.rs
    for needle in ["eprintln!", "eprint!", "print!", "stderr", "write!(io::"] {
        let files = hits(&src, needle);
        assert!(
            files.iter().all(|f| f == "main.rs"),
            "{needle} вне main.rs: {files:?}"
        );
    }
    // в main.rs каждая печать только start_line(, report_line(, USAGE или BIND_FAILED
    let main = &src.iter().find(|(n, _)| n == "main.rs").unwrap().1;
    let prints: Vec<&str> = main.lines().filter(|l| l.contains("eprintln!")).collect();
    assert!(prints.len() >= 4, "печатей в main.rs: {}", prints.len());
    for line in prints {
        if line.trim_start().starts_with("//") {
            continue;
        }
        assert!(
            ["start_line(", "report_line(", "USAGE", "BIND_FAILED"]
                .iter()
                .any(|a| line.contains(a)),
            "посторонняя печать: {line}"
        );
    }
}

#[test]
fn manifest_has_only_two_dependencies() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    let mut in_deps = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t.starts_with("[dependencies") || t.contains("dependencies]");
            continue;
        }
        if in_deps && !t.is_empty() && !t.starts_with('#') {
            names.push(t.split(['=', '.']).next().unwrap().trim().to_owned());
        }
    }
    names.sort();
    assert_eq!(names, ["chervo-addr", "chervo-rendezvous-wire"]);
    assert!(!manifest.contains("tokio"));
}

/// Контроль: охрана умеет находить нарушения (не пустая).
#[test]
fn control_guard_can_fail() {
    let bad = vec![(
        "x.rs".to_owned(),
        "fn f(s:&UdpSocket){ s.send_to(b, a); s.send_to(b, a); s.send_to(b, a); std::fs::write(p, b); }"
            .to_owned(),
    )];
    assert_eq!(count(&bad, "send_to("), 3);
    assert_eq!(hits(&bad, "fs::"), vec!["x.rs".to_owned()]);
}
