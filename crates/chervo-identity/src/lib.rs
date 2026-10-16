//! Идентичность: ключи Ed25519 и X25519 пар друзей в хранилище ОС, Noise KK.
//!
//! Ключ создаётся только явно (`create`, `rekey`), никогда молча. Приватный ключ
//! не покидает хранилище ОС и память процесса: API не отдаёт seed и blob.
//! Спецификации: `docs/specs/stage-10.md`, `docs/specs/stage-10b-kx.md`.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod error;
mod guest;
mod ids;
mod keys;
mod kk;
mod knock;
mod kx;
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
mod os;
mod store;

pub use error::IdentityError;
pub use guest::GuestSecret;
pub use ids::PairId;
pub use keys::{PairKey, PublicKey, SignDomain};
pub use kk::{
    BINDING_LEN, ChannelBinding, KK_KIND_V1, KK_MSG1_LEN, KK_MSG2_LEN, KK_MSG3_LEN,
    KK_PROLOGUE_TAG, KkInitiator, KkResponder, KxPeer, NOISE_PARAMS, kk_initiate, kk_respond,
};
pub use knock::{KNOCK_ID_LABEL, KNOCK_KDF_LABEL, KNOCK_LEN, KNOCK_TAG_LABEL, KnockKeys};
pub use kx::{KxPublicKey, PairKx};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub use os::OsKeyStore;
pub use store::{ListKeyStore, SecretStore, UnavailableKeyStore, create, load, rekey};

/// Версия формата записи ключа.
pub const KEY_BLOB_VERSION: u8 = 2;
/// Длина записи: `[версия][seed Ed25519 32][публичный Ed25519 32][секрет X25519 32][публичный X25519 32]`.
pub const KEY_BLOB_LEN: usize = 129;
/// Имя сервиса в хранилище ОС.
pub const DEFAULT_SERVICE: &str = "chervotochina";
/// Префикс имени записи пары.
pub const ACCOUNT_PREFIX: &str = "pair-v1-";
/// Имя записи ключа списка друзей (не начинается с `ACCOUNT_PREFIX`).
pub const LIST_KEY_ACCOUNT: &str = "friends-key-v1";
/// Длина ключа списка друзей, байт.
pub const LIST_KEY_LEN: usize = 32;
