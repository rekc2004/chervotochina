//! Поиск друзей в локальной сети: свой маяк (этап 13в, не mDNS).
//! Спецификация: `docs/specs/stage-13v-lan.md`.
//!
//! Часть L2 (этот вызов): чистые модули без сокетов и потоков. `limits` (пределы), `wire`
//! (формат датаграммы 430 байт: сборка и разбор), `table` (таблица меток `id -> пара, окно`),
//! `rate` (ограничение приёма до разбора), `texts` (тексты), `error`. Всё, что приходит из
//! сети, считается враждебным. Части L3 (`net`, `service`) добавит следующий вызов.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

// Модули `error`, `limits`, `rate`, `table`, `wire` пока не используются кодом продукта: их
// подключает служба (L3). После этого `allow(dead_code)` убрать.
#[allow(dead_code)]
mod error;
#[allow(dead_code)]
mod limits;
#[allow(dead_code)]
mod rate;
#[allow(dead_code)]
mod table;
#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
mod testkit;
mod texts;
#[allow(dead_code)]
mod wire;

#[cfg(test)]
mod tests;

pub use limits::LAN_PORT;
pub use texts::{
    MODE_ANNOUNCE_TEXT, MODE_LISTEN_TEXT, MODE_OFF_TEXT, STATUS_ANNOUNCING_TEXT,
    STATUS_FAILED_TEXT, STATUS_LISTENING_TEXT, STATUS_NO_PRIVATE_ROUTE_TEXT, STATUS_OFF_TEXT,
    STATUS_PORT_BUSY_TEXT, mode_text, status_text,
};

/// Только для фаззинга: разбор произвольных байт как датаграммы маяка против фиксированной
/// таблицы из трёх тестовых пар. Ничего не возвращает; паника здесь была бы найденной ошибкой.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_beacon(bytes: &[u8]) {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::OnceLock;

    static TABLE: OnceLock<table::IdTable> = OnceLock::new();
    let t = TABLE.get_or_init(|| testkit::fuzz_table(3));
    let own = Ipv4Addr::new(192, 168, 50, 1);
    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 50, 7), 45_000));
    let _ = wire::parse(bytes, src, own, t, wire::SrcPolicy::PRODUCT);
}
