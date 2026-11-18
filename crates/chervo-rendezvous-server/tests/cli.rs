#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Бинарь `chervo-rendezvous`: коды выхода и строка старта (этап 13д, Р4).

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_chervo-rendezvous");

#[test]
fn bad_arguments_exit_2_with_usage() {
    for args in [&["--bogus"][..], &[][..], &["--listen", "nonsense"][..]] {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn bind_failure_exits_1_without_addresses() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let out = Command::new(BIN)
        .args(["--listen", &addr])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains(&addr), "адрес не печатается: {err}");
    assert!(out.stdout.is_empty());
}

#[test]
fn start_line_then_silence() {
    let mut child = Command::new(BIN)
        .args(["--listen", "127.0.0.1:0"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(line.starts_with("chervo-rendezvous "), "{line}");
    assert!(line.contains("listening on 127.0.0.1:"), "{line}");
}
