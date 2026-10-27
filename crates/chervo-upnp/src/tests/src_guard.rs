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

    // адрес multicast записан только в limits.rs, в обеих формах (строка и `Ipv4Addr::new`,
    // пробелы не в счёт); остальной код берёт константу `SSDP_ADDR`
    let files = files_with(&src, "239.255.255.250");
    assert_eq!(files, vec!["limits.rs".to_owned()]);
    let squeezed: Vec<(String, String)> = src
        .iter()
        .map(|(n, t)| (n.clone(), t.split_whitespace().collect::<String>()))
        .collect();
    let files = files_with(&squeezed, "239,255,255,250");
    assert_eq!(
        files,
        vec!["limits.rs".to_owned()],
        "239,255,255,250 вне limits.rs"
    );
    let files = files_with(&src, "SSDP_ADDR");
    assert!(
        files.contains(&"net.rs".to_owned()),
        "net.rs не берёт SSDP_ADDR"
    );

    // ошибки без текста
    let (_, errors) = src.iter().find(|(n, _)| n == "error.rs").unwrap();
    assert!(!errors.contains("String"), "String в error.rs");
}

// ----------------------------------------------------------------------------------------
// Этап 17, C15 (SEC-13 L4, 12 L5): `tests/` и `examples/` крейта тоже под охраной
// «конечных точек и процессов». Структурные правила выше остаются только для `src/`.
// ----------------------------------------------------------------------------------------

/// Слова, которым нечего делать в тестах и примерах: запуск процессов, сокеты tokio, TCP, DNS.
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

fn guard_walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            guard_walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn src_guard_tests_and_examples() {
    // охрана сама видит нарушения (иначе пустой список слов прошёл бы молча)
    assert_eq!(
        forbidden_outside_src("let c = std::process::Command::new(\"x\");"),
        ["Command::new", "process::Command"]
    );
    assert_eq!(
        forbidden_outside_src("use tokio::net::TcpStream;"),
        ["tokio::net", "TcpStream"]
    );
    assert!(forbidden_outside_src("let n = std::process::id();").is_empty());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for d in ["tests", "examples"] {
        guard_walk(&root.join(d), &mut files);
    }
    // сам файл охраны называет запретные слова в своих списках
    files.retain(|p| p.file_name().is_some_and(|n| n != "src_guard.rs"));
    assert!(
        files.len() >= MIN_OUTSIDE_FILES,
        "охрана tests/ и examples/ нашла только {} файлов",
        files.len()
    );
    assert!(
        files
            .iter()
            .any(|p| p.components().any(|c| c.as_os_str() == "examples")),
        "examples/ не просканирован"
    );
    for p in &files {
        // переводы строк Windows приводятся к LF
        let text = std::fs::read_to_string(p).unwrap().replace("\r\n", "\n");
        let bad = forbidden_outside_src(&text);
        assert!(bad.is_empty(), "{} содержит {bad:?}", p.display());
    }
}

const MIN_OUTSIDE_FILES: usize = 1;
