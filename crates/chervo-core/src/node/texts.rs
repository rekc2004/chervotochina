//! Русские тексты узла для пользователя: по одному на каждый вариант ошибки, предупреждения и
//! итога передачи, плюс тексты нижних слоёв, собранные в одном месте, чтобы оболочки (GUI,
//! CLI) брали их отсюда и не лезли в нижние крейты. В текстах нет путей, имён, адресов и
//! ключей: подстановки только числа.

use chervo_connect::ConnectError;
use chervo_friends::FriendsError;
use chervo_receive::RootError;
use chervo_transfer::{FailReason, TransferError};

use super::error::NodeError;
use super::views::{NodeWarning, TransferResult};

pub use chervo_connect::{
    CGNAT_TEXT, DOUBLE_NAT_TEXT, NO_IPV6_TEXT, NO_KNOWN_ADDRESS_TEXT, PEER_UNREACHABLE_INVITE_TEXT,
    REVOCATION_FAILED_TEXT, REVOCATION_NOT_SENT_TEXT, SYMMETRIC_TEXT, UDP_BLOCKED_TEXT,
    UNKNOWN_TEXT,
};
pub use chervo_friends::KEY_LOST_TEXT;
pub use chervo_receive::{
    ACTIVE_DOC_TEXT, ASK_FILE_TEXT, CHOOSE_OTHER_FOLDER_TEXT, DECEPTIVE_TEXT, DISK_IMAGE_TEXT,
    EXECUTABLE_TEXT, HOSTILE_DECLINED_TEXT, LONG_PATH_TEXT, NAME_CHANGED_TEXT, SHARED_ROOT_TEXT,
    SUSPICIOUS_NAME_TEXT, TRUST_QUESTION_TEXT, insufficient_space_text,
};
pub use chervo_transfer::{
    DAMAGED_TEXT, DECLINED_TEXT, DISCONNECTED_TEXT, DISK_FULL_TEXT, EXPIRED_TEXT,
    PEER_CANCELLED_TEXT, PEER_FORGOT_TEXT, PREPARING_TEXT, SOURCE_CHANGED_TEXT, STALLED_TEXT,
};
pub use chervo_upnp::{ENABLE_ON_ROUTER_TEXT, NEED_PERMANENT_TEXT, status_text as mapping_text};

pub const FIRST_RUN_TEXT: &str =
    "Это первый запуск: выберите папку для принимаемых файлов. Ключи хранятся в хранилище ОС.";
pub const ALREADY_RUNNING_TEXT: &str = "Программа уже запущена.";
pub const DATA_DIR_TEXT: &str = "Не удалось определить или создать папку данных программы.";
pub const SETTINGS_CORRUPT_TEXT: &str = "Файл настроек повреждён или содержит недопустимое значение. Можно сбросить настройки: копия файла сохранится.";
pub const KEY_STORE_LOCKED_TEXT: &str = "Хранилище ключей ОС закрыто или недоступно. Разблокируйте его или убедитесь, что оно работает, и повторите.";
pub const KEYS_LOST_TEXT: &str = "Ключ списка друзей пропал: список прочитать нельзя. Можно начать заново, друзей придётся добавить снова. Старый файл сохранится рядом.";
pub const ROLLED_BACK_TEXT: &str = "Список друзей старше последнего изменения безопасности: возможно, его подменили старой копией. Принять старый список можно только осознанно.";
pub const STALE_INSTANCE_TEXT: &str =
    "Другой экземпляр программы уже изменил список друзей. Перезапустите программу.";
pub const PORT_IN_USE_TEXT: &str = "Порт уже занят другой программой. Выберите другой порт.";
pub const ROOT_NOT_ABSOLUTE_TEXT: &str = "Путь к папке приёма должен быть полным.";
pub const ROOT_NOT_DIR_TEXT: &str = "Указанная папка приёма не найдена или это не папка.";
pub const ROOT_SHARED_TEXT: &str = SHARED_ROOT_TEXT;
pub const ROOT_OUTSIDE_PROFILE_TEXT: &str = "Папка лежит вне вашего профиля: права на неё могут быть шире. Подтвердите, что других пользователей на этом ПК нет.";
pub const ROOT_INSIDE_PARTIAL_TEXT: &str =
    "Папка приёма не может лежать внутри служебной папки программы.";
pub const ROOT_OTHER_TEXT: &str = "Папку приёма открыть не удалось.";
pub const BAD_NAME_TEXT: &str =
    "Часть имён файлов нельзя передать: они не в формате UTF-8 или слишком длинные.";
pub const INPUT_TOO_LONG_TEXT: &str = "Вставленный текст слишком длинный.";
pub const FRIENDS_TEXT: &str = "Не удалось изменить список друзей.";
pub const INVALID_NAME_TEXT: &str = "Недопустимое имя друга.";
pub const BAD_TOKEN_TEXT: &str = "Текст не распознан или не подходит ни одному другу.";
pub const NO_ADDRESS_TEXT: &str =
    "Нет адреса, который можно сообщить другу. Проверьте сеть или укажите адрес с пробросом порта.";
pub const UNKNOWN_ITEM_TEXT: &str = "Такого друга, приглашения или передачи нет.";
pub const NOT_ACTIVE_TEXT: &str = "Друг сейчас не активен: он заблокирован, удалён или отозван.";
pub const CONNECT_TEXT: &str = "Не удалось выполнить действие со связью.";
pub const TRANSFER_BUSY_TEXT: &str =
    "Слишком много передач одновременно или с этим другом уже идёт передача.";
pub const TRANSFER_TOO_BIG_TEXT: &str = "Файл или набор файлов слишком большой.";
pub const TRANSFER_TOO_MANY_TEXT: &str = "Слишком много файлов в одном предложении.";
pub const TRANSFER_NO_CONNECTION_TEXT: &str = "Нет живого соединения с другом или файл недоступен.";
pub const TRANSFER_WRONG_STATE_TEXT: &str = "Сейчас это действие недоступно для этой передачи.";
pub const TRANSFER_TEXT: &str = "Не удалось выполнить действие с передачей.";
pub const UPNP_NO_GATEWAY_TEXT: &str =
    "Роутер с поддержкой автоматического проброса в сети не найден.";
pub const UPNP_AMBIGUOUS_TEXT: &str = chervo_upnp::AMBIGUOUS_TEXT;
pub const UPNP_TEXT: &str = "Не удалось поговорить с роутером.";
pub const CLOCK_TEXT: &str =
    "Не удалось сверить часы: серверы времени не ответили или их ответы не согласуются.";
pub const UNSUPPORTED_TEXT: &str = "Эта возможность недоступна в вашей системе.";
pub const SHUTDOWN_TEXT: &str = "Программа завершает работу.";
pub const IO_TEXT: &str = "Ошибка чтения или записи.";
pub const NO_SPACE_TEXT: &str = "В выбранной папке не хватает места.";
pub const INVALID_VALUE_TEXT: &str = "Недопустимое значение настройки: оно вне разрешённых границ.";
pub const LIMIT_REACHED_TEXT: &str =
    "Достигнут предел списка: уберите ненужную папку приёма или роутер и повторите.";

pub const ANCHOR_NOT_UPDATED_TEXT: &str =
    "Сохранено, но счётчик защиты от отката не обновлён. Перезапустите программу.";
pub const ROOT_UNAVAILABLE_TEXT: &str = "Одна из дополнительных папок приёма недоступна. Недокачанные там передачи не продолжатся, пока папка не вернётся.";
pub const SETTINGS_NOT_SAVED_TEXT: &str = "Действие выполнено, но настройки записать не удалось.";

pub const RESULT_COMPLETED_TEXT: &str = "Передача завершена.";
pub const RESULT_PROTOCOL_TEXT: &str = "Передача прервана из-за ошибки обмена с другом.";
pub const RESULT_BUSY_TEXT: &str = "Друг сейчас занят другой передачей. Попробуйте позже.";
pub const RESULT_LIMITS_TEXT: &str =
    "Предложение не подошло под ограничения приёма (число файлов, размер или имена).";
pub const RESULT_NOT_FRIEND_TEXT: &str = "Друг не признал это соединение. Добавьте друга заново.";
pub const RESULT_CANCELLED_BY_US_TEXT: &str = "Вы отменили передачу.";

fn root_text(e: RootError) -> &'static str {
    match e {
        RootError::NotAbsolute => ROOT_NOT_ABSOLUTE_TEXT,
        RootError::NotDir => ROOT_NOT_DIR_TEXT,
        RootError::Shared | RootError::PartialNotPrivate => ROOT_SHARED_TEXT,
        RootError::InsidePartial => ROOT_INSIDE_PARTIAL_TEXT,
        RootError::OutsideProfile => ROOT_OUTSIDE_PROFILE_TEXT,
        _ => ROOT_OTHER_TEXT,
    }
}

fn friends_text(e: FriendsError) -> &'static str {
    match e {
        FriendsError::InvalidName => INVALID_NAME_TEXT,
        FriendsError::BadRevocation | FriendsError::BadAddrUpdate => BAD_TOKEN_TEXT,
        FriendsError::UnknownPair => UNKNOWN_ITEM_TEXT,
        FriendsError::NotActive => NOT_ACTIVE_TEXT,
        FriendsError::KeyMissingOrChanged | FriendsError::KeyNeedsDecision => KEY_LOST_TEXT,
        FriendsError::NoAddresses => NO_ADDRESS_TEXT,
        FriendsError::Io => REVOCATION_NOT_SENT_TEXT,
        _ => FRIENDS_TEXT,
    }
}

fn connect_text(e: ConnectError) -> &'static str {
    match e {
        ConnectError::NoAddresses => NO_ADDRESS_TEXT,
        ConnectError::UnknownPair => UNKNOWN_ITEM_TEXT,
        ConnectError::NotActive => NOT_ACTIVE_TEXT,
        ConnectError::Token(_) | ConnectError::Invite(_) => BAD_TOKEN_TEXT,
        _ => CONNECT_TEXT,
    }
}

fn transfer_text(e: TransferError) -> &'static str {
    match e {
        TransferError::NotFriend => NOT_ACTIVE_TEXT,
        TransferError::Busy => TRANSFER_BUSY_TEXT,
        TransferError::BadName => BAD_NAME_TEXT,
        TransferError::TooLarge => TRANSFER_TOO_BIG_TEXT,
        TransferError::TooManyFiles => TRANSFER_TOO_MANY_TEXT,
        TransferError::NoSuchTransfer => UNKNOWN_ITEM_TEXT,
        TransferError::WrongState => TRANSFER_WRONG_STATE_TEXT,
        TransferError::Io => TRANSFER_NO_CONNECTION_TEXT,
        _ => TRANSFER_TEXT,
    }
}

impl NodeError {
    /// Русский текст для пользователя (фиксированный, без путей, имён и адресов).
    pub fn user_text(&self) -> &'static str {
        match *self {
            Self::FirstRun => FIRST_RUN_TEXT,
            Self::AlreadyRunning => ALREADY_RUNNING_TEXT,
            Self::DataDir => DATA_DIR_TEXT,
            Self::SettingsCorrupt => SETTINGS_CORRUPT_TEXT,
            Self::KeyStoreLocked => KEY_STORE_LOCKED_TEXT,
            Self::KeysLost => KEYS_LOST_TEXT,
            Self::RolledBack => ROLLED_BACK_TEXT,
            Self::StaleInstance => STALE_INSTANCE_TEXT,
            Self::PortInUse => PORT_IN_USE_TEXT,
            Self::ReceiveRoot(e) => root_text(e),
            Self::BadName(_) => BAD_NAME_TEXT,
            Self::InputTooLong => INPUT_TOO_LONG_TEXT,
            Self::Friends(e) => friends_text(e),
            Self::Connect(e) => connect_text(e),
            Self::Transfer(e) => transfer_text(e),
            Self::Upnp(e) => match e {
                chervo_upnp::UpnpError::NoGateway => UPNP_NO_GATEWAY_TEXT,
                chervo_upnp::UpnpError::Ambiguous => UPNP_AMBIGUOUS_TEXT,
                _ => UPNP_TEXT,
            },
            Self::Clock(_) => CLOCK_TEXT,
            Self::Unsupported => UNSUPPORTED_TEXT,
            Self::Shutdown => SHUTDOWN_TEXT,
            Self::Io => IO_TEXT,
            Self::NoSpace => NO_SPACE_TEXT,
            Self::InvalidValue => INVALID_VALUE_TEXT,
            Self::LimitReached => LIMIT_REACHED_TEXT,
        }
    }
}

impl NodeWarning {
    pub fn user_text(&self) -> &'static str {
        match self {
            Self::AnchorNotUpdated => ANCHOR_NOT_UPDATED_TEXT,
            Self::RootUnavailable => ROOT_UNAVAILABLE_TEXT,
            Self::SettingsNotSaved => SETTINGS_NOT_SAVED_TEXT,
            Self::HostileOfferDeclined => HOSTILE_DECLINED_TEXT,
        }
    }
}

impl TransferResult {
    /// Русский текст итога. Для `Failed` с причиной `Disconnected` (этап 14б) это
    /// `DISCONNECTED_TEXT`.
    pub fn user_text(&self) -> &'static str {
        match self {
            Self::Completed => RESULT_COMPLETED_TEXT,
            Self::Declined => DECLINED_TEXT,
            Self::Cancelled { by_us: true } => RESULT_CANCELLED_BY_US_TEXT,
            Self::Cancelled { by_us: false } => PEER_CANCELLED_TEXT,
            Self::Failed { reason } => match reason {
                FailReason::Declined => DECLINED_TEXT,
                FailReason::Expired => EXPIRED_TEXT,
                FailReason::Busy => RESULT_BUSY_TEXT,
                FailReason::Limits => RESULT_LIMITS_TEXT,
                FailReason::PeerForgot => PEER_FORGOT_TEXT,
                FailReason::NotFriend => RESULT_NOT_FRIEND_TEXT,
                FailReason::Disconnected => DISCONNECTED_TEXT,
                _ => RESULT_PROTOCOL_TEXT,
            },
        }
    }
}
