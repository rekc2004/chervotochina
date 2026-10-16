//! Защитные тесты: проба маршрута не падает; в исходниках нет отправки данных.

use std::fs;
use std::path::Path;

use chervo_addr::{PROBE_V4, PROBE_V6, probe_route_sources};

#[test]
fn probe_no_panic() {
    // любой результат допустим: сети в окружении может не быть
    let r = probe_route_sources();
    if let Some(a) = r.v4 {
        assert!(!a.is_unspecified() && !a.is_loopback());
    }
    if let Some(a) = r.v6 {
        assert!(!a.is_unspecified() && !a.is_loopback());
    }
    assert_eq!(PROBE_V4, "192.0.2.1:9".parse().unwrap());
    assert_eq!(PROBE_V6, "[2001:db8::1]:9".parse().unwrap());
}

#[test]
fn no_send_in_src() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = 0usize;
    let mut with_socket = Vec::new();
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        seen += 1;
        assert!(!text.contains(".send("), "{name}: .send(");
        assert!(!text.contains("send_to("), "{name}: send_to(");
        if text.contains("UdpSocket") {
            with_socket.push(name);
        }
    }
    assert!(seen >= 4, "исходники не найдены");
    assert_eq!(with_socket, vec!["probe.rs".to_owned()]);
}
