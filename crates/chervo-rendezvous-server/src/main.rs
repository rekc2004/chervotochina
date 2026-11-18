//! Бинарь `chervo-rendezvous`. В stderr идут только строка старта, строки счётчиков и подсказка
//! `USAGE` при ошибке аргументов; IP клиентов не печатаются нигде.
//!
//! Коды выхода: 2 — аргументы, 1 — привязка к адресу или порту.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::dbg_macro,
    clippy::todo
)]
// печать в stderr разрешена только здесь и только тремя видами строк (проверяет `tests/src_guard.rs`)
#![allow(clippy::print_stderr)]

mod args;

use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use chervo_rendezvous_server::{report_line, serve, start_line};

use args::USAGE;

/// Фиксированный текст при отказе привязки (без адресов).
const BIND_FAILED: &str =
    "chervo-rendezvous: cannot bind: check the address, the port and that nothing else uses them";

fn main() -> ExitCode {
    let Ok(cfg) = args::parse(std::env::args_os().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let version = env!("CARGO_PKG_VERSION");
    let stop = Arc::new(AtomicBool::new(false));
    let result = serve(
        cfg,
        stop,
        |addrs| eprintln!("{}", start_line(version, &addrs)),
        |c| eprintln!("{}", report_line(c)),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("{BIND_FAILED}");
            ExitCode::from(1)
        }
    }
}
