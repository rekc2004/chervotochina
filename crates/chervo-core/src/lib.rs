//! Ядро без UI для оболочек (CLI, GUI, мобильные): готовый узел `Node` (этап 18а, решение D1).
//! Транспорт окончательный (quinn), поэтому узел не обобщён; обобщённым остаётся движок
//! `chervo-connect`, так что второй адаптер (TCP, U7) не потребует его переписывать.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod harden;
mod node;

pub use chervo_addr;
pub use chervo_connect;
pub use chervo_friends;
pub use chervo_identity;
pub use chervo_receive;
pub use chervo_token;
pub use chervo_transfer;
pub use chervo_transport;

pub use harden::{HardenReport, harden_process};
pub use node::*;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
