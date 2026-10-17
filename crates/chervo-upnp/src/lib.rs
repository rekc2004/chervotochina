//! Собственный минимальный клиент UPnP IGD (этап 13а).
//! Спецификация: `docs/specs/stage-13a-upnp.md`.
//!
//! Часть U1 (этот вызов): чистые разборщики без сокетов. Всё, что приходит из локальной
//! сети, считается враждебным: XML разбирает фиксированный сканер подмножества (`scan`),
//! без внешних библиотек XML и HTTP; в конструкциях `<!` (DTD, комментарии, CDATA), в
//! неизвестных сущностях и управляющих символах отказ; тело не больше 64 КиБ.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]
// Потребители разборщиков (сеть и жизненный цикл) появятся в части U2.
#![allow(dead_code)]

mod desc;
mod error;
mod http;
mod limits;
mod scan;
mod soap;
mod ssdp;
mod url;

#[cfg(test)]
mod tests;
