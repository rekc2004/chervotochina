use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::secret_service::{SsClient, Timeouts, UNLOCK_WAIT_MAX_SECS, UNLOCK_WAIT_MIN_SECS};
use crate::{
    DEFAULT_SERVICE, EPOCH_ACCOUNT, EpochStore, IdentityError, LIST_KEY_ACCOUNT, ListKeyStore,
    PairId, SecretStore,
};

/// Longest accepted service name, bytes.
const MAX_SERVICE_LEN: usize = 255;

/// Linux key store: Secret Service over D-Bus through our own minimal client
/// (`secret_service`, spec 17a). Entries are compatible with the previous client.
pub struct OsKeyStore {
    client: SsClient,
    service: String,
}

impl fmt::Debug for OsKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OsKeyStore(..)")
    }
}

impl OsKeyStore {
    /// Store with the service `DEFAULT_SERVICE`.
    pub fn open() -> Result<Self, IdentityError> {
        Self::open_with_service(DEFAULT_SERVICE)
    }

    /// Own service name (for a manual test). Empty, longer than 255 bytes or containing a
    /// NUL byte: `StorageUnavailable`. Connects to the session bus and opens a session; any
    /// failure is `StorageUnavailable`.
    pub fn open_with_service(service: &str) -> Result<Self, IdentityError> {
        Self::open_checked(service, Timeouts::PRODUCT)
    }

    fn open_checked(service: &str, timeouts: Timeouts) -> Result<Self, IdentityError> {
        check_service(service)?;
        Ok(Self {
            client: SsClient::connect_session(timeouts)?,
            service: service.to_owned(),
        })
    }

    /// Ask the Secret Service to unlock the default collection (may show the password dialog of
    /// the desktop). Explicit user action only (GUI): read, write and delete never call it and
    /// never unlock by themselves. `wait` is the time the user gets at the dialog, clamped to
    /// 1..=300 s. Blocks up to `wait + 2 s`. Success only if the collection is unlocked after
    /// the call; dismissed, timed out or still locked: `StorageLocked`; no Secret Service or no
    /// default collection: `StorageUnavailable`.
    pub fn request_unlock(&self, wait: Duration) -> Result<(), IdentityError> {
        self.client.request_unlock(clamp_unlock_wait(wait))
    }

    /// Store over a ready client (tests only).
    #[cfg(test)]
    pub(crate) fn from_client(client: SsClient, service: &str) -> Result<Self, IdentityError> {
        check_service(service)?;
        Ok(Self {
            client,
            service: service.to_owned(),
        })
    }

    fn read_account(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.client.get(&self.service, account)
    }

    fn write_account(&self, account: &str, secret: &[u8]) -> Result<(), IdentityError> {
        self.client.set(&self.service, account, secret)
    }

    fn delete_account(&self, account: &str) -> Result<(), IdentityError> {
        self.client.delete(&self.service, account)
    }
}

/// The wait at the unlock dialog is limited to 1..=300 s (spec D8).
pub(crate) fn clamp_unlock_wait(wait: Duration) -> Duration {
    wait.clamp(
        Duration::from_secs(UNLOCK_WAIT_MIN_SECS),
        Duration::from_secs(UNLOCK_WAIT_MAX_SECS),
    )
}

fn check_service(service: &str) -> Result<(), IdentityError> {
    if service.is_empty() || service.len() > MAX_SERVICE_LEN || service.contains('\0') {
        return Err(IdentityError::StorageUnavailable);
    }
    Ok(())
}

impl SecretStore for OsKeyStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.read_account(&pair.account_name())
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.write_account(&pair.account_name(), blob)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.delete_account(&pair.account_name())
    }
}

impl ListKeyStore for OsKeyStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.read_account(LIST_KEY_ACCOUNT)
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.write_account(LIST_KEY_ACCOUNT, key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        self.delete_account(LIST_KEY_ACCOUNT)
    }
}

impl EpochStore for OsKeyStore {
    fn read_epoch(&self) -> Result<Option<u64>, IdentityError> {
        match self.read_account(EPOCH_ACCOUNT)? {
            Some(secret) => {
                let bytes: [u8; 8] = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::StorageInconsistent)?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    fn write_epoch(&self, epoch: u64) -> Result<(), IdentityError> {
        self.write_account(EPOCH_ACCOUNT, &epoch.to_be_bytes())
    }
}
