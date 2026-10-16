use std::fmt;

use chervo_transport::TransportError;

/// Ошибки разбора и выпуска токенов. Текст фиксированный, без байтов ввода.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenError {
    TooLong,
    BadEncoding,
    BadPrefix,
    UnsupportedVersion,
    BadKind,
    Malformed,
    BadAddress,
    BadTtl,
    BadKey,
    BadSignature,
    Expired,
    NotYetValid,
    RandomUnavailable,
    SigningFailed,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooLong => "token text too long",
            Self::BadEncoding => "token text has bad encoding",
            Self::BadPrefix => "token has unknown prefix",
            Self::UnsupportedVersion => "unsupported token version",
            Self::BadKind => "token kind does not match prefix",
            Self::Malformed => "malformed token",
            Self::BadAddress => "token has bad address",
            Self::BadTtl => "token has bad lifetime",
            Self::BadKey => "token has bad key",
            Self::BadSignature => "token signature is bad",
            Self::Expired => "token expired",
            Self::NotYetValid => "token not yet valid",
            Self::RandomUnavailable => "os random source unavailable",
            Self::SigningFailed => "signing failed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TokenError {}

/// Ошибки протокола приглашения (M1, M2, решение).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InviteError {
    Malformed,
    WrongToken,
    BadKey,
    BadSignature,
    CommitMismatch,
    Expired,
    TooManySessions,
    Used,
    NoSession,
    RandomUnavailable,
    SigningFailed,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Malformed => "malformed invite message",
            Self::WrongToken => "invite message for another token",
            Self::BadKey => "invite message has bad key",
            Self::BadSignature => "invite message signature is bad",
            Self::CommitMismatch => "invite commitment mismatch",
            Self::Expired => "invite expired",
            Self::TooManySessions => "too many invite sessions",
            Self::Used => "invite already used",
            Self::NoSession => "no invite session",
            Self::RandomUnavailable => "os random source unavailable",
            Self::SigningFailed => "signing failed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for InviteError {}

/// Ошибки обмена по соединению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowError {
    Transport(TransportError),
    Invite(InviteError),
    /// Поток закончился раньше фиксированной длины сообщения.
    Truncated,
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Transport(_) => "invite transport error",
            Self::Invite(_) => "invite protocol error",
            Self::Truncated => "invite message truncated",
        };
        f.write_str(text)
    }
}

impl std::error::Error for FlowError {}

impl From<TransportError> for FlowError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<InviteError> for FlowError {
    fn from(e: InviteError) -> Self {
        Self::Invite(e)
    }
}
