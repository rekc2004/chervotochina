//! Слой соединения (этап 13, часть C3: ядро движка).
//! Спецификация: `docs/specs/stage-13-connect.md`.
//!
//! Слой решает, по каким адресам, в каком порядке и как часто звонить каждому активному
//! другу (один исходящий звонок на пару), следит за собственными адресами, обменивается
//! ADDR_INFO и называет причину, когда прямого пути нет. Сокетов, DNS и обращений к третьим
//! лицам в крейте нет; транспорт приходит снаружи через `ManagedTransport`.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod addrinfo;
mod allow;
mod clock;
mod config;
mod diag;
mod dispatch;
mod engine;
mod gateway;
mod inbox;
mod invite;
mod lan;
mod limiter;
mod plan;
mod texts;
mod watch;

#[cfg(test)]
mod tests;

pub use allow::AllowSet;
pub use clock::{Clock, ClockRangeError, RouteProbe, SystemClock, SystemProbe};
pub use config::ConnectConfig;
pub use diag::{Diagnosis, NoDirectPath};
pub use engine::{ConnectError, Engine, EngineEvent, EngineEvents, InviteAddrs, InviteOutcome};
pub use inbox::{ConnHold, IncomingStream, StreamInbox};
pub use plan::PathKind;
pub use texts::{
    CGNAT_TEXT, DOUBLE_NAT_TEXT, LAN_DISCOVERY_TEXT, LAN_FIRST_RUN_TEXT, NO_IPV6_TEXT,
    NO_KNOWN_ADDRESS_TEXT, PEER_UNREACHABLE_INVITE_TEXT, REVOCATION_FAILED_TEXT,
    REVOCATION_NOT_SENT_TEXT, SYMMETRIC_TEXT, UDP_BLOCKED_TEXT, UNKNOWN_TEXT,
    revocation_error_text, user_text,
};
