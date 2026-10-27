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

// ---------------------------------------------------------------------------------------------
// Этап 17, B6/C04: точки входа для фаззинга (libFuzzer в `fuzz/`, вне рабочего пространства) и
// для собственных fuzz-смоук тестов этого крейта. Поведение не меняется: это только публичные
// обёртки над уже существующими разборщиками `pub(crate)`. Внутренние типы наружу не выходят.
// ---------------------------------------------------------------------------------------------

/// Только для фаззинга: разбор описания устройства IGD произвольными байтами (`desc.rs`).
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_desc(bytes: &[u8]) {
    if let Ok(t) = url::parse_location(
        "http://192.168.1.1:5000/rootDesc.xml",
        std::net::Ipv4Addr::new(192, 168, 1, 1),
    ) {
        let _ = desc::parse_description(bytes, &t);
    }
}

/// Только для фаззинга: разбор HTTP-ответа произвольными байтами (`http.rs`).
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_http(bytes: &[u8]) {
    let _ = http::parse_response(bytes);
}

/// Только для фаззинга: разбор SSDP-ответа произвольными байтами (`ssdp.rs`).
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_ssdp(bytes: &[u8]) {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 1900);
    let own = Ipv4Addr::new(192, 168, 1, 10);
    let policy = ssdp::SsdpPolicy {
        allow_loopback: false,
    };
    let _ = ssdp::parse_response(bytes, src, own, policy);
}

/// Только для фаззинга: разбор тел SOAP произвольными байтами (`soap.rs`).
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_soap(bytes: &[u8]) {
    let _ = soap::parse_external_ip(bytes);
    let _ = soap::parse_add_any(bytes);
    let _ = soap::parse_specific(bytes);
    let _ = soap::parse_fault(bytes);
}

/// Только для фаззинга: разбор `LOCATION`/порта произвольным текстом (`url.rs`).
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_url(bytes: &[u8]) {
    if let Ok(s) = std::str::from_utf8(bytes) {
        let _ = url::parse_location(s, std::net::Ipv4Addr::new(192, 168, 1, 1));
        let _ = url::parse_port(s);
    }
}
