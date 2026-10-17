//! Охрана исходников (часть U2): сокеты только в `net.rs`, никаких имён, процессов, DNS,
//! HTTPS, tokio и небезопасного кода; `GatewayAddr` строится только в `url.rs`; адрес
//! multicast записан только в `limits.rs`; в `error.rs` нет полей `String`.

use std::fs;
use std::path::Path;

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
        out.push((name, fs::read_to_string(&path).unwrap()));
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
    assert!(src.len() >= 12, "исходники не найдены: {}", src.len());
    assert!(src.iter().any(|(n, _)| n == "net.rs"));

    // сокеты и отправка: только net.rs
    for needle in [
        "UdpSocket",
        "TcpStream",
        "TcpListener",
        "Socket::new",
        "send_to",
        "connect_timeout",
    ] {
        let files = files_with(&src, needle);
        assert!(
            files.iter().all(|f| f == "net.rs"),
            "{needle} вне net.rs: {files:?}"
        );
    }
    // net.rs действительно содержит сокетный код (охрана не пустая)
    assert!(!files_with(&src, "Socket::new").is_empty());

    // запрещено везде
    for needle in [
        "lookup_host",
        "to_socket_addrs",
        "ToSocketAddrs",
        "Command",
        "std::process",
        "tokio",
        "https",
        "unsafe",
    ] {
        let files = files_with(&src, needle);
        assert!(files.is_empty(), "{needle} найдено в {files:?}");
    }

    // адрес шлюза строится только в url.rs
    let files = files_with(&src, "GatewayAddr(");
    assert_eq!(files, vec!["url.rs".to_owned()], "GatewayAddr( вне url.rs");

    // адрес multicast записан только в limits.rs
    let files = files_with(&src, "239.255.255.250");
    assert_eq!(files, vec!["limits.rs".to_owned()]);

    // ошибки без текста
    let (_, errors) = src.iter().find(|(n, _)| n == "error.rs").unwrap();
    assert!(!errors.contains("String"), "String в error.rs");
}
