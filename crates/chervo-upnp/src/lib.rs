//! Собственный минимальный клиент UPnP IGD (этап 13а).
//! Спецификация: `docs/specs/stage-13a-upnp.md`.
//!
//! Часть U1: чистые разборщики без сокетов. Всё, что приходит из локальной сети, считается
//! враждебным: XML разбирает фиксированный сканер подмножества (`scan`), без внешних библиотек
//! XML и HTTP; в конструкциях `<!` (DTD, комментарии, CDATA), в неизвестных сущностях и
//! управляющих символах отказ; тело не больше 64 КиБ.
//!
//! Часть U2: сетевой слой (`net`, единственный сокетный код) и жизненный цикл проброса
//! (`mapper`). Крейт реализует `chervo_addr::PortMapper`; по умолчанию (пустой список
//! разрешённых роутеров) не отправляет ни одного пакета.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod desc;
mod error;
mod http;
mod limits;
mod mapper;
mod net;
mod scan;
mod soap;
mod ssdp;
mod texts;
mod url;

#[cfg(test)]
mod tests;

pub use error::UpnpError;
pub use mapper::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings};
pub use texts::{
    AMBIGUOUS_TEXT, CGNAT_UPNP_TEXT, DOUBLE_NAT_UPNP_TEXT, ENABLE_ON_ROUTER_TEXT,
    NEED_PERMANENT_TEXT, NOT_HOME_TEXT, REFUSED_TEXT, status_text,
};
