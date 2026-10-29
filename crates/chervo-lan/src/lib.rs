//! Поиск друзей в локальной сети: свой маяк (этап 13в, не mDNS).
//! Спецификация: `docs/specs/stage-13v-lan.md`.
//!
//! Чистые модули без сокетов и потоков (L2): `limits` (пределы), `wire` (формат датаграммы
//! 430 байт: сборка и разбор), `table` (таблица меток `id -> пара, окно`), `rate` (ограничение
//! приёма до разбора), `texts` (тексты), `error`. Сокетный код (L3) только в `net`, служба
//! (один поток std, `LanBeacon`) в `service`. Всё, что приходит из сети, считается враждебным.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod error;
mod ifaces;
mod limits;
mod net;
mod rate;
mod service;
mod table;
// Тестовая оснастка, не код продукта: часть её полей нужна не каждой сборке.
#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
mod testkit;
mod texts;
mod wire;

#[cfg(test)]
mod tests;

pub use limits::LAN_PORT;
pub use service::LanBeacon;
#[cfg(any(test, feature = "test-net"))]
pub use service::TestNet;
pub use texts::{
    ADDRS_PREFIX_TEXT, MODE_ANNOUNCE_TEXT, MODE_LISTEN_TEXT, MODE_OFF_TEXT, STATUS_ANNOUNCING_TEXT,
    STATUS_FAILED_TEXT, STATUS_LISTENING_TEXT, STATUS_NO_PRIVATE_ROUTE_TEXT, STATUS_OFF_TEXT,
    STATUS_PORT_BUSY_TEXT, VPN_HINT_TEXT, mode_text, status_text,
};

/// Только для проверок вручную (`lan_probe ifaces`): набор интерфейсов для адреса по умолчанию
/// `default` по опросу маршрутов системы и число обращений к опросу. Пакетов не отправляет,
/// сокетов приёма и отправки не открывает.
#[doc(hidden)]
pub fn sweep_report(default: std::net::Ipv4Addr) -> (Vec<std::net::Ipv4Addr>, usize) {
    let mut calls = 0usize;
    let set = ifaces::select(
        default,
        &mut |a| {
            calls = calls.saturating_add(1);
            chervo_addr::route_source_for(std::net::SocketAddr::V4(a))
        },
        wire::SrcPolicy::PRODUCT,
        &|| false,
    );
    (set, calls)
}

/// Только для фаззинга: разбор произвольных байт как датаграммы маяка против фиксированной
/// таблицы из трёх тестовых пар. Ничего не возвращает; паника здесь была бы найденной ошибкой.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_beacon(bytes: &[u8]) {
    let _ = fuzz_beacon_ports(bytes);
}

/// Как `fuzz_beacon`, но возвращает порты найденных слотов. Ключи пар фиксированные, поэтому
/// корпус с настоящей датаграммой (`fuzz/corpus/lan_beacon/`) доходит до `open`.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_beacon_ports(bytes: &[u8]) -> Vec<u16> {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::OnceLock;

    static TABLE: OnceLock<table::IdTable> = OnceLock::new();
    let t = TABLE.get_or_init(|| testkit::fuzz_table(FUZZ_PAIRS));
    let own = Ipv4Addr::new(192, 168, 50, 1);
    let src = SocketAddr::V4(SocketAddrV4::new(FUZZ_SRC, 45_000));
    wire::parse(bytes, src, &[own], t, wire::SrcPolicy::PRODUCT)
        .iter()
        .map(|s| s.addr.port())
        .collect()
}

/// Число пар таблицы fuzz-цели, порт, который в них запечатан, и верная датаграмма от этих пар.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub const FUZZ_PAIRS: usize = 3;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub const FUZZ_PORT: u16 = testkit::FUZZ_PORT;
#[cfg(any(test, feature = "fuzzing"))]
const FUZZ_SRC: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 168, 50, 7);

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_valid_beacon() -> Vec<u8> {
    testkit::fuzz_datagram(FUZZ_PAIRS, FUZZ_SRC).unwrap_or_default()
}
