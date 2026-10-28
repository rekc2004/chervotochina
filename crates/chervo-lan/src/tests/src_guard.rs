//! Охрана исходников: сокеты и отправка только в `net.rs`; адрес группы и номер порта записаны
//! только в `limits.rs`; нет имён, процессов, DNS, tokio, журналов и небезопасного кода; в
//! `error.rs` нет `String`; манифест без tokio и без feature `all` у socket2.

use std::fs;
use std::path::{Path, PathBuf};

/// Исходники производственного кода (без `src/tests`).
fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        out.push((name, text));
    }
    out.sort();
    out
}

fn files_with(src: &[(String, String)], needle: &str) -> Vec<String> {
    src.iter()
        .filter(|(_, t)| t.contains(needle))
        .map(|(n, _)| n.clone())
        .collect()
}

#[test]
fn src_guard() {
    let src = sources();
    assert!(src.len() >= 10, "исходники не найдены: {}", src.len());
    assert!(src.iter().any(|(n, _)| n == "net.rs"));

    // сокеты и отправка: только net.rs
    for needle in [
        "UdpSocket",
        "TcpStream",
        "TcpListener",
        "Socket::new",
        "socket2",
        "send_to",
        "recv_from",
        "join_multicast",
        "set_multicast",
        "set_reuse",
    ] {
        let files = files_with(&src, needle);
        assert!(
            files.iter().all(|f| f == "net.rs"),
            "{needle} вне net.rs: {files:?}"
        );
    }
    // net.rs действительно содержит сокетный код (охрана не пустая)
    assert!(!files_with(&src, "Socket::new").is_empty());
    assert!(!files_with(&src, "send_to").is_empty());

    // запрещено везде
    for needle in [
        "lookup_host",
        "to_socket_addrs",
        "ToSocketAddrs",
        "Command",
        "std::process",
        "tokio",
        "unsafe",
        "hostname",
        "log::",
        "tracing",
        "mdns",
        "println!",
        "eprintln!",
        "dbg!",
    ] {
        let files = files_with(&src, needle);
        assert!(files.is_empty(), "{needle} найдено в {files:?}");
    }

    // адрес группы и номер порта записаны только в limits.rs (в обеих формах; пробелы не в счёт)
    let files = files_with(&src, "45817");
    assert_eq!(files, vec!["limits.rs".to_owned()], "45817 вне limits.rs");
    let squeezed: Vec<(String, String)> = src
        .iter()
        .map(|(n, t)| (n.clone(), t.split_whitespace().collect::<String>()))
        .collect();
    let files = files_with(&squeezed, "224,0,0,1");
    assert_eq!(
        files,
        vec!["limits.rs".to_owned()],
        "224,0,0,1 вне limits.rs"
    );
    // сокетный код берёт константы, а не свои числа
    let net = &src.iter().find(|(n, _)| n == "net.rs").unwrap().1;
    assert!(net.contains("LAN_GROUP") && net.contains("LAN_PORT"));

    // назначение отправки задано в одном месте: `target` из `Sockets::open`
    assert_eq!(
        net.matches("send_to(").count(),
        1,
        "отправка в одном месте net.rs"
    );

    // ошибки без текста
    let (_, errors) = src.iter().find(|(n, _)| n == "error.rs").unwrap();
    assert!(!errors.contains("String"), "String в error.rs");
}

#[test]
fn src_guard_manifest() {
    let m = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(!m.contains("tokio"));
    assert!(!m.contains("mdns") && !m.contains("hickory") && !m.contains("if-addrs"));
    let line = m
        .lines()
        .find(|l| l.trim_start().starts_with("socket2"))
        .expect("socket2 не подключён");
    assert!(line.contains("=0.6.5"), "версия socket2: {line}");
    assert!(line.contains("default-features = false"), "{line}");
    assert!(!line.contains("features = ["), "feature у socket2: {line}");
    assert!(!m.contains("\"all\""), "feature all");
}

// ----------------------------------------------------------------------------------------
// `tests/` и `examples/` крейта тоже под охраной «процессов и конечных точек».
// ----------------------------------------------------------------------------------------

const OUTSIDE_SRC_FORBIDDEN: [&str; 8] = [
    "Command::new",
    "process::Command",
    "tokio::net",
    "TcpStream",
    "TcpListener",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
];

fn forbidden_outside_src(text: &str) -> Vec<&'static str> {
    OUTSIDE_SRC_FORBIDDEN
        .into_iter()
        .filter(|w| text.contains(w))
        .collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn src_guard_tests_and_examples() {
    // охрана сама видит нарушения
    assert_eq!(
        forbidden_outside_src("let c = std::process::Command::new(\"x\");"),
        ["Command::new", "process::Command"]
    );
    assert!(forbidden_outside_src("let n = std::process::id();").is_empty());

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for d in ["tests", "examples", "src/tests"] {
        walk(&root.join(d), &mut files);
    }
    // сам файл охраны называет запретные слова в своих списках
    files.retain(|p| p.file_name().is_some_and(|n| n != "src_guard.rs"));
    assert!(files.len() >= 8, "найдено файлов: {}", files.len());
    assert!(
        files
            .iter()
            .any(|p| p.components().any(|c| c.as_os_str() == "examples")),
        "examples/ не просканирован"
    );
    for p in &files {
        let text = fs::read_to_string(p).unwrap().replace("\r\n", "\n");
        let bad = forbidden_outside_src(&text);
        assert!(bad.is_empty(), "{} содержит {bad:?}", p.display());
    }
}
