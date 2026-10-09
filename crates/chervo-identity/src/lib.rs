//! Идентичность: ключи Ed25519 пар друзей в хранилище ОС.
//!
//! Ключ создаётся только явно (`create`, `rekey`), никогда молча. Приватный ключ
//! не покидает хранилище ОС и память процесса: API не отдаёт seed и blob.
//! Спецификация: `docs/specs/stage-10.md`.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod error;
mod ids;
mod keys;
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
mod os;
mod store;

pub use error::IdentityError;
pub use ids::{DeviceId, PairId};
pub use keys::{PairKey, PublicKey, SignDomain};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub use os::OsKeyStore;
pub use store::{SecretStore, UnavailableKeyStore, create, load, rekey};

/// Версия формата записи ключа.
pub const KEY_BLOB_VERSION: u8 = 1;
/// Длина записи: `[версия][seed 32][публичный ключ 32]`.
pub const KEY_BLOB_LEN: usize = 65;
/// Имя сервиса в хранилище ОС.
pub const DEFAULT_SERVICE: &str = "chervotochina";
/// Префикс имени записи пары.
pub const ACCOUNT_PREFIX: &str = "pair-v1-";
