#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Тесты части U1 (разборщики без сокетов) и части U2 (поддельный IGD на петле).

mod desc;
mod fake_igd;
mod fuzz;
mod http;
mod igd;
mod scan;
mod soap;
mod src_guard;
mod ssdp;
mod texts;
mod url;

use std::net::Ipv4Addr;

use crate::url::{HttpTarget, parse_location};

pub fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

/// Типичный адрес описания домашнего роутера.
pub fn target() -> HttpTarget {
    parse_location("http://192.168.1.1:5000/rootDesc.xml", ip(192, 168, 1, 1)).unwrap()
}
