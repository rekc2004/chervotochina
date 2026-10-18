#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Тесты части C3: поддельный транспорт, приостановленное время.

mod addrinfo;
mod candidates;
mod diag;
mod engine;
mod fake_mapper;
mod fixes16a;
mod gateway;
mod inbox;
mod invite;
mod kit;
mod limiter;
mod manual_token;
mod publish;
mod src_guard;
mod texts;
mod watch;
mod x02a;
