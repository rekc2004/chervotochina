//! Ошибки узла. `Display` и `Debug` фиксированные: ни путей, ни имён, ни адресов, ни ключей.
//! Русский текст для пользователя: `NodeError::user_text` (`texts.rs`).

use std::fmt;

use chervo_connect::ConnectError;
use chervo_friends::FriendsError;
use chervo_receive::RootError;
use chervo_timesync::SyncError;
use chervo_transfer::TransferError;
use chervo_upnp::UpnpError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeError {
    /// Файла настроек нет: первый запуск, нужен `Node::first_run_setup`.
    FirstRun,
    /// Каталог данных уже занят другим экземпляром программы.
    AlreadyRunning,
    /// Каталог данных не определить или он не абсолютный.
    DataDir,
    /// Файл настроек не разобрать (только сломанный файл; неверное значение в вызове это
    /// `InvalidValue`).
    SettingsCorrupt,
    /// Хранилище ключей ОС закрыто или недоступно (одна ошибка на оба случая, этап 11, Н1).
    KeyStoreLocked,
    /// Ключ списка друзей пропал: файл списка не прочитать (нужно «начать заново»).
    KeysLost,
    /// Список друзей старше последнего изменения безопасности (нужен явный выбор пользователя).
    RolledBack,
    /// Другой экземпляр уже изменил безопасность: перезапустите программу.
    StaleInstance,
    PortInUse,
    ReceiveRoot(RootError),
    /// Число имён, которые не получилось передать (не UTF-8 или слишком длинные).
    BadName(usize),
    /// Вставленный текст длиннее 4096 байт: до разбора не доходит.
    InputTooLong,
    Friends(FriendsError),
    Connect(ConnectError),
    Transfer(TransferError),
    Upnp(UpnpError),
    Clock(SyncError),
    Unsupported,
    Shutdown,
    Io,
    /// В выбранной папке приёма не хватает места (добавлено в 18а: без неё `accept_into` нечем
    /// ответить).
    NoSpace,
    /// Значение настройки вне допустимых границ (порт, процент, внешний порт).
    InvalidValue,
    /// Достигнут предел списка (папок приёма или разрешённых роутеров).
    LimitReached,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::FirstRun => "first run: no settings yet",
            Self::AlreadyRunning => "another instance is already running",
            Self::DataDir => "data directory is not usable",
            Self::SettingsCorrupt => "settings are corrupt or out of range",
            Self::KeyStoreLocked => "key storage locked or unavailable",
            Self::KeysLost => "friends list key is lost",
            Self::RolledBack => "friends list is older than the last security change",
            Self::StaleInstance => "friends list was changed by another instance",
            Self::PortInUse => "port is already in use",
            Self::ReceiveRoot(_) => "receive folder is not usable",
            Self::BadName(_) => "some file names cannot be sent",
            Self::InputTooLong => "pasted text is too long",
            Self::Friends(_) => "friends list error",
            Self::Connect(_) => "connection layer error",
            Self::Transfer(_) => "transfer error",
            Self::Upnp(_) => "port mapping error",
            Self::Clock(_) => "clock synchronisation error",
            Self::Unsupported => "not supported on this system",
            Self::Shutdown => "node is shut down",
            Self::Io => "i/o error",
            Self::NoSpace => "not enough free space",
            Self::InvalidValue => "setting value is out of range",
            Self::LimitReached => "list limit reached",
        };
        f.write_str(text)
    }
}

impl std::error::Error for NodeError {}

impl From<FriendsError> for NodeError {
    fn from(e: FriendsError) -> Self {
        match e {
            FriendsError::RolledBack => Self::RolledBack,
            FriendsError::StaleInstance => Self::StaleInstance,
            FriendsError::ListKeyMissing => Self::KeysLost,
            FriendsError::KeyStorageUnavailable => Self::KeyStoreLocked,
            other => Self::Friends(other),
        }
    }
}

impl From<ConnectError> for NodeError {
    fn from(e: ConnectError) -> Self {
        match e {
            ConnectError::Friends(f) => f.into(),
            ConnectError::Shutdown => Self::Shutdown,
            other => Self::Connect(other),
        }
    }
}

impl From<TransferError> for NodeError {
    fn from(e: TransferError) -> Self {
        match e {
            TransferError::Shutdown => Self::Shutdown,
            other => Self::Transfer(other),
        }
    }
}
