use std::fmt;

/// Ошибки списка друзей. Текст фиксированный, без имён, адресов и ключей.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FriendsError {
    KeyStorageUnavailable,
    ListKeyMissing,
    Corrupt,
    UnsupportedVersion,
    Io,
    LimitExceeded,
    InvalidName,
    InvalidLimits,
    TrustRequired,
    UnknownPair,
    AlreadyExists,
    KeyMissingOrChanged,
    KeyNeedsDecision,
    RandomUnavailable,
    BadRevocation,
    StaleSeq,
    BadAddrUpdate,
    NoAddresses,
    SeqExhausted,
    RateLimited,
    NotActive,
    /// Список старше последнего изменения безопасности (якорь в хранилище ОС).
    RolledBack,
}

impl fmt::Display for FriendsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::KeyStorageUnavailable => "key storage unavailable",
            Self::ListKeyMissing => "friends list key missing",
            Self::Corrupt => "friends list is corrupt",
            Self::UnsupportedVersion => "unsupported friends list version",
            Self::Io => "friends list i/o error",
            Self::LimitExceeded => "friends list limit exceeded",
            Self::InvalidName => "invalid friend name",
            Self::InvalidLimits => "invalid auto-accept limits",
            Self::TrustRequired => "auto-accept needs the trust confirmation",
            Self::UnknownPair => "unknown pair",
            Self::AlreadyExists => "pair already exists",
            Self::KeyMissingOrChanged => "pair key missing or changed",
            Self::KeyNeedsDecision => "pair key needs a decision",
            Self::RandomUnavailable => "os random source unavailable",
            Self::BadRevocation => "bad revocation",
            Self::StaleSeq => "address update is stale",
            Self::BadAddrUpdate => "bad address update",
            Self::NoAddresses => "no addresses to publish",
            Self::SeqExhausted => "address update numbers exhausted",
            Self::RateLimited => "address update rate limited",
            Self::NotActive => "friend is not active",
            Self::RolledBack => "friends list is older than the last security change",
        };
        f.write_str(text)
    }
}

impl std::error::Error for FriendsError {}
