//! Тексты для пользователя (по-русски, без подстановок).

use chervo_addr::{LanMode, LanStatus};

pub const MODE_OFF_TEXT: &str = "Не искать друзей в локальной сети.";
pub const MODE_LISTEN_TEXT: &str = "Только слушать: программа узнаёт друзей, которые сообщают о себе в этой сети, и сама ничего в сеть не рассылает.";
pub const MODE_ANNOUNCE_TEXT: &str = "Слушать и сообщать о себе: раз в полминуты программа рассылает в локальную сеть короткое сообщение, по которому вас узнают только ваши друзья. Имени, ключей и номера порта в нём нет, но другие устройства сети видят, что здесь работает Червоточина. Включайте на компьютере, который стоит дома. На ноутбуке, который бывает в кафе и гостиницах, оставьте «Только слушать».";

pub const STATUS_OFF_TEXT: &str = MODE_OFF_TEXT;
pub const STATUS_NO_PRIVATE_ROUTE_TEXT: &str =
    "Поиск в локальной сети не работает: у компьютера нет частного адреса домашней сети.";
pub const STATUS_PORT_BUSY_TEXT: &str =
    "Поиск в локальной сети недоступен: его порт занят другой программой.";
pub const STATUS_LISTENING_TEXT: &str = "Слушаем локальную сеть.";
pub const STATUS_ANNOUNCING_TEXT: &str = "Сообщаем о себе друзьям в локальной сети.";
pub const STATUS_FAILED_TEXT: &str =
    "Поиск в локальной сети не удалось запустить. Программа попробует снова.";

/// Начало строки «адреса, на которых идёт поиск»; дальше адреса через запятую.
pub const ADDRS_PREFIX_TEXT: &str = "Ищем на адресах: ";
/// Подсказка про VPN рядом с состоянием поиска.
pub const VPN_HINT_TEXT: &str = "Если включён VPN или прокси, домашние устройства могут быть не видны: VPN может перекрывать домашнюю сеть.";

/// Текст состояния. Для новых состояний (перечисление открыто) общий текст сбоя.
pub fn status_text(s: LanStatus) -> &'static str {
    match s {
        LanStatus::Off => STATUS_OFF_TEXT,
        LanStatus::NoPrivateRoute => STATUS_NO_PRIVATE_ROUTE_TEXT,
        LanStatus::PortBusy => STATUS_PORT_BUSY_TEXT,
        LanStatus::Listening => STATUS_LISTENING_TEXT,
        LanStatus::Announcing => STATUS_ANNOUNCING_TEXT,
        LanStatus::Failed => STATUS_FAILED_TEXT,
        _ => STATUS_FAILED_TEXT,
    }
}

/// Текст режима для настроек.
pub fn mode_text(m: LanMode) -> &'static str {
    match m {
        LanMode::Off => MODE_OFF_TEXT,
        LanMode::Listen => MODE_LISTEN_TEXT,
        LanMode::Announce => MODE_ANNOUNCE_TEXT,
    }
}
