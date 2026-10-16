//! Список друзей: типы записей, кодек открытого текста и зашифрованный файл списка
//! (этап 11, части К3 и О1). Спецификация: `docs/specs/stage-11-invite.md`.
//!
//! Файл списка: `[CHFL][версия][nonce 12][ChaCha20-Poly1305: шифртекст || тег 16]`, ключ лежит
//! в хранилище ОС отдельной записью (`chervo_identity::LIST_KEY_ACCOUNT`). Файл считается
//! недоверенным: после порчи или подмены любой разбор строгий, паник нет.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod book;
mod error;
mod plain;
mod types;
pub mod vault;

#[cfg(test)]
mod tests;

pub use book::{FriendBook, KeyStatus, MIN_INBAND_UPDATE_INTERVAL_SECS, NewFriend};
pub use error::FriendsError;
pub use types::{
    AutoAcceptLimits, BookData, Friend, FriendState, PendingEntry, PendingRole, Permission,
};

pub const MAX_FRIENDS: usize = 1024;
pub const MAX_PENDING: usize = 64;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_ADDRS_PER_FRIEND: usize = 16;
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const FILE_MAGIC: &[u8; 4] = b"CHFL";
pub const FILE_VERSION: u8 = 0x01;
pub const KEY_LOST_TEXT: &str = "Ключ для этого друга пропал или изменён. Добавьте друга заново.";
