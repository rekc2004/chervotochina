use std::fmt;
use std::sync::Arc;

use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use zeroize::{Zeroize, Zeroizing};

use crate::{DEFAULT_SERVICE, IdentityError, LIST_KEY_ACCOUNT, ListKeyStore, PairId, SecretStore};

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
        self.entry_named(&pair.account_name())
    }

    fn entry_named(&self, account: &str) -> Result<Entry, IdentityError> {
        #[cfg(target_os = "windows")]
        let mods_map = std::collections::HashMap::from([("persistence", "Local")]);
        #[cfg(target_os = "windows")]
        let mods = Some(&mods_map);
        #[cfg(not(target_os = "windows"))]
        let mods = None;
        self.store
            .build(&self.service, account, mods)
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

impl ListKeyStore for OsKeyStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        match self.entry_named(LIST_KEY_ACCOUNT)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_error(e)),
        }
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.entry_named(LIST_KEY_ACCOUNT)?
            .set_secret(key)
            .map_err(map_error)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        match self.entry_named(LIST_KEY_ACCOUNT)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(map_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> keyring_core::error::PlatformError {
        Box::new(std::fmt::Error)
    }

    #[test]
    fn map_error_no_storage_access_is_locked() {
        assert_eq!(
            map_error(KeyringError::NoStorageAccess(platform())),
            IdentityError::StorageLocked
        );
    }

    #[test]
    fn map_error_ambiguous_is_inconsistent() {
        assert_eq!(
            map_error(KeyringError::Ambiguous(Vec::new())),
            IdentityError::StorageInconsistent
        );
    }

    #[test]
    fn map_error_other_kinds_are_unavailable() {
        assert_eq!(
            map_error(KeyringError::BadEncoding(vec![1])),
            IdentityError::StorageUnavailable
        );
        assert_eq!(
            map_error(KeyringError::BadDataFormat(vec![1], platform())),
            IdentityError::StorageUnavailable
        );
        assert_eq!(
            map_error(KeyringError::PlatformFailure(platform())),
            IdentityError::StorageUnavailable
        );
        assert_eq!(
            map_error(KeyringError::NoEntry),
            IdentityError::StorageUnavailable
        );
    }
}
