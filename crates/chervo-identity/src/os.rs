use std::fmt;
use std::sync::Arc;

use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use zeroize::{Zeroize, Zeroizing};

use crate::{DEFAULT_SERVICE, IdentityError, PairId, SecretStore};

/// Хранилище ОС: Credential Manager, login keychain, Secret Service.
/// Создаётся явным конструктором платформенного крейта, глобальное хранилище не используется.
pub struct OsKeyStore {
    store: Arc<CredentialStore>,
    service: String,
}

impl fmt::Debug for OsKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OsKeyStore(..)")
    }
}

#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let s = apple_native_keyring_store::keychain::Store::new()?;
    let s: Arc<CredentialStore> = s;
    Ok(s)
}

#[cfg(target_os = "windows")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let s = windows_native_keyring_store::Store::new()?;
    let s: Arc<CredentialStore> = s;
    Ok(s)
}

#[cfg(target_os = "linux")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    let s = zbus_secret_service_keyring_store::Store::new()?;
    let s: Arc<CredentialStore> = s;
    Ok(s)
}

/// Ошибки keyring в наши. Байты секрета в `BadEncoding`/`BadDataFormat` обнуляются,
/// текст ошибок keyring не передаётся дальше.
fn map_error(e: KeyringError) -> IdentityError {
    match e {
        KeyringError::NoStorageAccess(_) => IdentityError::StorageLocked,
        KeyringError::Ambiguous(_) => IdentityError::StorageInconsistent,
        KeyringError::BadEncoding(mut v) => {
            v.zeroize();
            IdentityError::StorageUnavailable
        }
        KeyringError::BadDataFormat(mut v, _) => {
            v.zeroize();
            IdentityError::StorageUnavailable
        }
        _ => IdentityError::StorageUnavailable,
    }
}

impl OsKeyStore {
    /// Хранилище ОС с сервисом `DEFAULT_SERVICE`.
    pub fn open() -> Result<Self, IdentityError> {
        Self::open_with_service(DEFAULT_SERVICE)
    }

    /// Свой сервис (для ручного теста). Пустое имя: `StorageUnavailable`.
    pub fn open_with_service(service: &str) -> Result<Self, IdentityError> {
        if service.is_empty() {
            return Err(IdentityError::StorageUnavailable);
        }
        let store = platform_store().map_err(map_error)?;
        Ok(Self {
            store,
            service: service.to_owned(),
        })
    }

    fn entry(&self, pair: &PairId) -> Result<Entry, IdentityError> {
        let account = pair.account_name();
        #[cfg(target_os = "windows")]
        let mods_map = std::collections::HashMap::from([("persistence", "Local")]);
        #[cfg(target_os = "windows")]
        let mods = Some(&mods_map);
        #[cfg(not(target_os = "windows"))]
        let mods = None;
        self.store
            .build(&self.service, &account, mods)
            .map_err(map_error)
    }
}

impl SecretStore for OsKeyStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        match self.entry(pair)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_error(e)),
        }
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.entry(pair)?.set_secret(blob).map_err(map_error)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        match self.entry(pair)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(map_error(e)),
        }
    }
}
