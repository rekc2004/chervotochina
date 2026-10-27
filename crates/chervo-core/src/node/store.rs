//! Хранилище ключей узла. В продукте это только `OsKeyStore::open()`: файлового хранилища и
//! подделки в продуктовом коде нет. Обёртка нужна одному типу `Engine<QuinnTransport, NodeStore>`
//! и тестам (через тестовую точку входа в `testing.rs`).

use std::sync::Arc;

use chervo_identity::{EpochStore, IdentityError, ListKeyStore, PairId, SecretStore};
use zeroize::Zeroizing;

/// Что нужно узлу от хранилища: ключи пар, ключ списка друзей и якорь против отката.
/// Реализуется автоматически для любого типа с тремя трейтами. Только для тестов вне ядра:
/// продуктовый код получает хранилище из `OsKeyStore`.
#[doc(hidden)]
pub trait KeyBackend: SecretStore + ListKeyStore + EpochStore {}

impl<T: SecretStore + ListKeyStore + EpochStore> KeyBackend for T {}

/// Какое хранилище под узлом (для экрана настроек).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyStoreKind {
    /// Windows: Credential Manager.
    CredentialManager,
    /// macOS: связка ключей.
    Keychain,
    /// Linux: Secret Service.
    SecretService,
    /// Подставленное тестом (в продукте не бывает).
    Test,
}

impl KeyStoreKind {
    pub(crate) fn of_os() -> Self {
        if cfg!(windows) {
            Self::CredentialManager
        } else if cfg!(target_os = "macos") {
            Self::Keychain
        } else {
            Self::SecretService
        }
    }
}

/// Хранилище за общим указателем: один тип для движка и для якоря списка друзей.
pub(crate) struct NodeStore {
    inner: Arc<dyn KeyBackend>,
    kind: KeyStoreKind,
}

impl NodeStore {
    pub(crate) fn new(inner: Arc<dyn KeyBackend>, kind: KeyStoreKind) -> Self {
        Self { inner, kind }
    }

    pub(crate) fn kind(&self) -> KeyStoreKind {
        self.kind
    }
}

impl std::fmt::Debug for NodeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeStore(..)")
    }
}

impl SecretStore for NodeStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read(pair)
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.inner.write(pair, blob)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.inner.delete(pair)
    }
}

impl ListKeyStore for NodeStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read_list_key()
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.inner.write_list_key(key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        self.inner.delete_list_key()
    }
}

impl EpochStore for NodeStore {
    fn read_epoch(&self) -> Result<Option<u64>, IdentityError> {
        self.inner.read_epoch()
    }

    fn write_epoch(&self, epoch: u64) -> Result<(), IdentityError> {
        self.inner.write_epoch(epoch)
    }
}
