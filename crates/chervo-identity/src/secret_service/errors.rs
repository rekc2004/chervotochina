//! zbus errors into ours. Text and payload of zbus errors are never formatted, stored or passed on.

use std::io::ErrorKind;

use zbus::fdo;

use super::proto::{ERR_IS_LOCKED, ERR_NO_SESSION, ERR_NO_SUCH_OBJECT};
use crate::IdentityError;

/// Internal failure of one step of a job.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SsError {
    /// Final result.
    Id(IdentityError),
    /// Connection-level error or `NoSession`: drop the connection, restart the job once (D9).
    Reconnect,
    /// `org.freedesktop.Secret.Error.NoSuchObject` (meaning depends on the operation).
    NoSuchObject,
}

impl SsError {
    pub(super) const UNAVAILABLE: Self = Self::Id(IdentityError::StorageUnavailable);
    pub(super) const LOCKED: Self = Self::Id(IdentityError::StorageLocked);
    pub(super) const INCONSISTENT: Self = Self::Id(IdentityError::StorageInconsistent);
}

/// Error of a call on an established connection.
pub(super) fn map_call_error(e: &zbus::Error) -> SsError {
    match e {
        zbus::Error::InputOutput(io) => {
            if io.kind() == ErrorKind::TimedOut {
                // Call timeout: the peer is silent; do not repeat, the caller gets an answer.
                SsError::UNAVAILABLE
            } else {
                SsError::Reconnect
            }
        }
        zbus::Error::Connection(..) => SsError::Reconnect,
        zbus::Error::MethodError(name, _, _) => match name.as_str() {
            ERR_NO_SESSION => SsError::Reconnect,
            ERR_IS_LOCKED => SsError::LOCKED,
            ERR_NO_SUCH_OBJECT => SsError::NoSuchObject,
            _ => SsError::UNAVAILABLE,
        },
        zbus::Error::FDO(f) => match &**f {
            fdo::Error::AccessDenied(_) => SsError::LOCKED,
            fdo::Error::Disconnected(_) => SsError::Reconnect,
            // ServiceUnknown, NameHasNoOwner, NoReply, Timeout, TimedOut, NotSupported,
            // UnknownMethod/Object/Interface, Spawn*, everything else.
            _ => SsError::UNAVAILABLE,
        },
        _ => SsError::UNAVAILABLE,
    }
}
