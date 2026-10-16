use std::fmt;

/// Ошибки идентичности. Текст ошибок фиксированный, без байтов ввода.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    NotImplemented,
    StorageUnavailable,
    StorageLocked,
    StorageInconsistent,
    KeyMissing,
    KeyAlreadyExists,
    KeyMismatch,
    CorruptKey,
    UnsupportedKeyVersion,
    RandomUnavailable,
    InvalidPublicKey,
    BadSignature,
    SigningFailed,
    InvalidKxPublicKey,
    AuthFailed,
    InvalidGuestSecret,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotImplemented => "not implemented",
            Self::StorageUnavailable => "key storage unavailable",
            Self::StorageLocked => "key storage locked or access denied",
            Self::StorageInconsistent => "key storage inconsistent",
            Self::KeyMissing => "pair key missing",
            Self::KeyAlreadyExists => "pair key already exists",
            Self::KeyMismatch => "pair key does not match expected public key",
            Self::CorruptKey => "stored key is corrupt",
            Self::UnsupportedKeyVersion => "unsupported stored key version",
            Self::RandomUnavailable => "os random source unavailable",
            Self::InvalidPublicKey => "invalid public key",
            Self::BadSignature => "bad signature",
            Self::SigningFailed => "signing failed",
            Self::InvalidKxPublicKey => "invalid key-exchange public key",
            Self::AuthFailed => "connection authentication failed",
            Self::InvalidGuestSecret => "invalid invite secret",
        };
        f.write_str(text)
    }
}

impl std::error::Error for IdentityError {}
