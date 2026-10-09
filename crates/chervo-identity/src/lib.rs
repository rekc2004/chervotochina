//! Идентичность устройства: тип ключа и заглушка хранилища.
//! Заглушки закрыты по умолчанию: возвращают `NotImplemented`.

use std::fmt;

/// Публичный идентификатор устройства (32 байта).
///
/// Ключ не валидируется, проверка точки кривой появится с библиотекой в этапе 10.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Ключ не валидируется, проверка точки кривой появится с библиотекой в этапе 10.
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Байты ключа не выводятся.
impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceId(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    NotImplemented,
    StorageUnavailable,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotImplemented => "not implemented",
            Self::StorageUnavailable => "key storage unavailable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for IdentityError {}

pub trait SecretKeyStore {
    fn load_or_create(&self) -> Result<DeviceId, IdentityError>;
    fn delete(&self) -> Result<(), IdentityError>;
}

/// Заглушка хранилища: всегда `NotImplemented`.
pub struct UnavailableKeyStore;

impl SecretKeyStore for UnavailableKeyStore {
    fn load_or_create(&self) -> Result<DeviceId, IdentityError> {
        Err(IdentityError::NotImplemented)
    }

    fn delete(&self) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented)
    }
}
