//! События, состояния и ошибки публичного интерфейса передачи. В событиях только ключи и
//! числа: ни имён, ни путей, ни адресов.

use std::fmt;

use tokio::sync::broadcast;

use crate::names::TransferKey;

/// Роль участника передачи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    Disconnected,
    DiskFull,
    Io,
    Stalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFailure {
    SourceChanged,
    SourceUnreadable,
    Damaged,
    WriteError,
    PlaceFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    Declined,
    Expired,
    Busy,
    Limits,
    Protocol,
    PeerForgot,
    NotFriend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferEvent {
    OfferReceived {
        key: TransferKey,
    },
    OfferAnswered {
        key: TransferKey,
        accepted: bool,
    },
    Started {
        key: TransferKey,
    },
    Progress {
        key: TransferKey,
        done: u64,
        total: u64,
    },
    Verifying {
        key: TransferKey,
    },
    /// Отправитель хэширует файлы перед отдачей: `hashed` из `total` байт предложения.
    Preparing {
        key: TransferKey,
        hashed: u64,
        total: u64,
    },
    FileReceived {
        key: TransferKey,
        index: u32,
    },
    FileDelivered {
        key: TransferKey,
        index: u32,
    },
    FileFailed {
        key: TransferKey,
        index: u32,
        reason: FileFailure,
    },
    Paused {
        key: TransferKey,
        reason: PauseReason,
    },
    Resumed {
        key: TransferKey,
    },
    Completed {
        key: TransferKey,
    },
    Cancelled {
        key: TransferKey,
        by: Side,
    },
    Failed {
        key: TransferKey,
        reason: FailReason,
    },
}

/// Получатель событий (broadcast на 256 событий; отставание пропускается молча).
pub struct TransferEvents {
    rx: broadcast::Receiver<TransferEvent>,
}

impl TransferEvents {
    pub(crate) fn new(rx: broadcast::Receiver<TransferEvent>) -> Self {
        Self { rx }
    }

    /// `None`: передачи остановлены.
    pub async fn recv(&mut self) -> Option<TransferEvent> {
        loop {
            match self.rx.recv().await {
                Ok(e) => return Some(e),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl fmt::Debug for TransferEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransferEvents(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Отправитель ждёт ответа получателя.
    AwaitingAnswer,
    /// Получатель ждёт решения пользователя.
    AwaitingUser,
    Active,
    Paused(PauseReason),
    /// Завершена (только память отправителя до `resume_hold`).
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferStatus {
    pub side: Side,
    pub state: TransferState,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferError {
    NotFriend,
    Busy,
    BadName,
    TooLarge,
    TooManyFiles,
    NoSuchTransfer,
    WrongState,
    /// Также: нет живого соединения с другом, неверная настройка.
    Io,
    Shutdown,
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotFriend => "not an active friend",
            Self::Busy => "too many transfers",
            Self::BadName => "invalid file name",
            Self::TooLarge => "file or offer too large",
            Self::TooManyFiles => "too many files",
            Self::NoSuchTransfer => "no such transfer",
            Self::WrongState => "wrong state for this action",
            Self::Io => "i/o error or no connection",
            Self::Shutdown => "transfers stopped",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TransferError {}
