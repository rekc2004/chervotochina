//! Все тексты интерфейса в одной таблице (этап 18б, вопрос владельца Q2): русский, один язык в
//! первой версии. Чтобы добавить другой язык, нужно заменить эту таблицу. Тексты ядра
//! (ошибки, предупреждения, итоги передач) берутся из `chervo_core::texts` и здесь не
//! дублируются.

/// Заголовок окна: константа, никогда не имя друга и не имя файла.
pub const WINDOW_TITLE: &str = "Червоточина";

// Старт и ошибки (экран 1)
pub const STARTING: &str = "Запуск…";
pub const FIRST_RUN_TITLE: &str = "Первый запуск";
pub const FOLDER_LABEL: &str = "Папка для принимаемых файлов";
pub const BTN_PICK_FOLDER: &str = "Выбрать…";
pub const BTN_CONTINUE: &str = "Продолжить";
pub const CHECK_NO_OTHER_USERS: &str = "других пользователей на этом ПК нет";
pub const FOLDER_EMPTY: &str = "Укажите папку для принимаемых файлов.";
pub const BTN_QUIT: &str = "Закрыть программу";
pub const BTN_RETRY: &str = "Повторить";
pub const BTN_UNLOCK: &str = "Разблокировать";
pub const BTN_START_OVER: &str = "Начать заново";
pub const BTN_ACCEPT_OLDER: &str = "Принять старый список";
pub const BTN_RESET_SETTINGS: &str = "Сбросить настройки";
pub const BTN_USE_PORT: &str = "Использовать этот порт";
pub const PORT_LABEL: &str = "Новый порт (1024–65535)";
pub const PORT_BAD: &str = "Порт должен быть числом от 1024 до 65535.";
/// Linux: хранилища может не быть вовсе. Программа ничего не устанавливает (решение владельца
/// 2026-10-09).
pub const LINUX_NO_SECRET_SERVICE: &str = "Если хранилища ключей нет, установите gnome-keyring или KWallet и войдите в сеанс заново. Программа ничего не устанавливает сама.";
pub const START_OVER_WARNING: &str =
    "Друзей придётся добавить заново: у них останутся прежние записи, у вас список будет пуст.";
pub const PORT_NOT_SAVED: &str =
    "Порт использован на этот запуск, но сохранить его в настройках не удалось.";
pub const INTERNAL_NOTICE: &str = "Не удалось обновить список разрешённых друзей.";

// Разделы главного окна (заглушки до этапов 2-9 экранов)
pub const NAV_FRIENDS: &str = "Друзья";
pub const NAV_ADD_FRIEND: &str = "Добавить друга";
pub const NAV_SEND: &str = "Отправить";
pub const NAV_OFFERS: &str = "Входящие";
pub const NAV_TRANSFERS: &str = "Передачи";
pub const NAV_DIAGNOSIS: &str = "Диагностика";
pub const NAV_SETTINGS: &str = "Настройки";
pub const NAV_UPDATES: &str = "Обновления";

// Закрытие (экран 10)
pub const CLOSE_ASK_TITLE: &str = "Закрыть программу?";
pub const CLOSE_ASK_TEXT: &str = "Передачи приостановятся и продолжатся при следующем запуске.";
pub const BTN_CLOSE: &str = "Закрыть";
pub const BTN_STAY: &str = "Остаться";
pub const CLOSING: &str = "Закрываем программу…";

// Друзья, приглашения, отправка, входящие, передачи (экраны 2-6)
pub const PASTE_EMPTY: &str = "Вставьте текст.";
pub const BAD_MANUAL_ADDR: &str = "Адрес должен быть вида 203.0.113.5:50000 (IP и порт).";
pub const SAS_NAME_EMPTY: &str = "Введите имя друга.";
pub const SEND_NO_FRIEND: &str = "Выберите друга.";
pub const SEND_NO_FILES: &str = "Выберите файлы или папки.";
pub const NO_REVOCATION_NEEDED: &str = "Готово. Ключа этой пары уже не было, отзыв не нужен.";
pub const ADDR_APPLIED: &str = "Адрес друга сохранён, пробуем соединиться.";
pub const AUTO_ACCEPTED: &str = "Файлы от друга приняты автоматически (автоприём включён).";
pub const INVITE_ADDED: &str = "Друг добавлен.";
pub const INVITE_DECLINED: &str = "Код не совпал или вы отказались: друг не добавлен.";
pub const INVITE_EXPIRED: &str = "Срок приглашения истёк. Создайте новое.";
pub const INVITE_FAILED: &str = "Не удалось добавить друга.";
pub const NOTICES_HIDE: &str = "Скрыть";
/// Токены и приглашения содержат адрес: кто увидит текст, узнает IP.
pub const IP_WARNING: &str = "Внимание: в этом тексте ваш IP-адрес. Кто увидит текст, узнает ваш адрес. Отправляйте его только другу.";
pub const BTN_COPY: &str = "Копировать";
pub const BTN_CANCEL: &str = "Отмена";
pub const BTN_OK: &str = "Готово";

pub const FRIENDS_EMPTY: &str = "Друзей пока нет. Добавьте друга на вкладке «Добавить друга».";
pub const BTN_PASTE_FRIEND_TOKEN: &str = "Вставить токен друга";
pub const BTN_REKEY_ALL: &str = "Пересоздать все ключи";
pub const BTN_SEND: &str = "Отправить";
pub const BTN_CONNECT: &str = "Соединить";
pub const BTN_DIAGNOSE: &str = "Диагностика";
pub const BTN_RENAME: &str = "Переименовать";
pub const BTN_BLOCK: &str = "Заблокировать";
pub const BTN_UNBLOCK: &str = "Разблокировать";
pub const BTN_REMOVE: &str = "Удалить";
pub const BTN_REKEY: &str = "Пересоздать ключ";
pub const BTN_AUTO_ON: &str = "Включить автоприём";
pub const BTN_AUTO_OFF: &str = "Выключить автоприём";
pub const BTN_SEND_ADDR: &str = "Отправить свой адрес";
pub const BTN_SAVE: &str = "Сохранить";
pub const BTN_YES_TRUST: &str = "Да, доверяю";
pub const BTN_NO: &str = "Нет";
pub const BTN_APPLY: &str = "Применить";
pub const BTN_CREATE_TOKEN: &str = "Создать токен";
pub const BTN_NEW_INVITE: &str = "Создать приглашение для друга";
pub const LABEL_NAME: &str = "Имя";
pub const LABEL_SAME_NETWORK: &str = "мы в одной сети";
pub const LABEL_PASTE_HERE: &str = "Вставьте текст, который прислал друг";
pub const STATE_ONLINE: &str = "в сети";
pub const STATE_OFFLINE: &str = "не в сети";
pub const STATE_ACTIVE: &str = "друг";
pub const STATE_BLOCKED: &str = "заблокирован";
pub const STATE_REVOKED: &str = "друг отозвал ключ";
pub const STATE_RETIRED: &str = "ключ пересоздан или друг удалён";
pub const PATH_LAN: &str = "локальная сеть";
pub const PATH_IPV6: &str = "IPv6";
pub const PATH_MAPPED: &str = "проброс порта";
pub const PATH_DIRECT: &str = "прямое соединение";
pub const AUTO_ON_LABEL: &str = "автоприём включён";
pub const CONFIRM_REMOVE: &str = "Удалить друга? Покажем текст отзыва: отправьте его другу, иначе он узнает об удалении, только когда не сможет соединиться.";
pub const CONFIRM_REKEY: &str = "Пересоздать ключ для этого друга? Старый ключ будет отозван, придётся отправить другу текст отзыва и создать новое приглашение.";
pub const CONFIRM_REKEY_ALL: &str = "Пересоздать ключи для всех друзей? Каждому другу нужно будет отправить текст отзыва и создать новое приглашение.";
pub const REVOCATION_REMOVED: &str = "Друг удалён. Отправьте этот текст другу любым способом: пока он не вставит его у себя, он не узнает об удалении.";
pub const REVOCATION_REKEY: &str = "Ключ пересоздан. Отправьте этот текст другу любым способом, затем создайте для него новое приглашение.";
pub const REKEY_PARTIAL: &str = "Для некоторых друзей ключ пересоздать не удалось";
pub const ADDR_TOKEN_TITLE: &str = "Отправить свой адрес другу";
pub const PASTE_TOKEN_TITLE: &str = "Токен адреса друга";

pub const ADD_TAB_INVITE: &str = "Пригласить";
pub const ADD_TAB_ACCEPT: &str = "Принять приглашение";
pub const ADD_MANUAL_LABEL: &str = "Свой адрес с пробросом порта (необязательно), IP:порт";
pub const BTN_CREATE_INVITE: &str = "Создать приглашение";
pub const BTN_ACCEPT_INVITE: &str = "Принять приглашение";
pub const INVITE_WAIT: &str =
    "Отправьте приглашение другу (текстом или QR). Ждём, пока друг примет его.";
pub const INVITE_ACCEPT_WAIT: &str = "Приглашение принято. Ждём проверочный код.";
pub const SAS_TITLE: &str = "Проверочный код";
pub const SAS_HINT: &str = "Сверьте цифры с другом по телефону или лично. Подтверждайте, только если цифры совпадают на обоих экранах.";
pub const BTN_SAS_MATCH: &str = "Совпадает";
pub const BTN_SAS_MISMATCH: &str = "Не совпадает";

pub const SEND_TITLE: &str = "Отправить файлы";
pub const SEND_HINT: &str = "Выберите файлы или папки или перетащите их в окно. Папки отправляются целиком; ссылки не разворачиваются.";
pub const BTN_PICK_FILES: &str = "Выбрать файлы…";
pub const BTN_PICK_DIR: &str = "Выбрать папку…";
pub const BTN_REMOVE_ITEM: &str = "Убрать";
pub const SEND_TO: &str = "Кому";
pub const SEND_NO_ACTIVE_FRIENDS: &str = "Нет друзей, которым можно отправить.";
pub const FOLDER_WORD: &str = "папка";

pub const OFFERS_EMPTY: &str = "Входящих предложений нет.";
pub const OFFER_FROM: &str = "От";
pub const OFFER_SPACE_UNKNOWN: &str = "свободное место узнать не удалось";
pub const BTN_ACCEPT: &str = "Принять";
pub const BTN_DECLINE: &str = "Отклонить";
pub const BTN_OTHER_FOLDER: &str = "Выбрать другую папку";
pub const MARK_RISKY: &str = "(!) ";
pub const KIND_SAFE: &str = "обычный файл";
pub const KIND_EXEC: &str = "программа или опасный тип";
pub const KIND_UNKNOWN: &str = "неизвестный тип";

pub const TRANSFERS_EMPTY: &str = "Передач пока нет.";
pub const BTN_RETRY_TRANSFER: &str = "Повторить";
pub const BTN_CANCEL_TRANSFER: &str = "Отменить передачу";
pub const SIDE_SEND: &str = "отправка";
pub const SIDE_RECEIVE: &str = "приём";
pub const STATE_AWAITING_ANSWER: &str = "ждём ответа друга";
pub const STATE_AWAITING_USER: &str = "ждёт вашего ответа";
pub const STATE_ACTIVE_TRANSFER: &str = "идёт";
pub const STATE_PAUSED: &str = "приостановлена";
pub const STATE_FINISHED: &str = "завершена";
pub const SAVED_TO: &str = "Файлы лежат в папке";

// Диагностика (7), настройки (8), уведомления (9)
pub const OWN_ADDR_CHANGED: &str = "Ваш адрес изменился. Если друзья не могут соединиться, отправьте им новый токен адреса (кнопка «Отправить свой адрес»).";
pub const MIN_FREE_BAD: &str = "Запас места: число от 0 до 100.";
pub const FORWARD_BAD: &str = "Внешний порт: число от 1 до 65535 или пусто, чтобы убрать.";
pub const UPNP_ALLOWED: &str = "Роутер разрешён. Состояние проброса показано в этом разделе.";
pub const CLOCK_APPLIED: &str = "Поправка часов применена.";
pub const CLOCK_RESET: &str = "Поправка часов сброшена.";
pub const ROOT_CHANGED: &str =
    "Папка приёма изменена. Изменение вступит в силу после перезапуска программы.";
pub const CLOCK_SKEW_HINT: &str =
    "Возможно, часы у вас или у друга идут неверно. Сверьте свои часы в настройках.";
pub const LAN_EXPIRED_HINT: &str = "Адрес в локальной сети устарел (он живёт сутки). Отправьте токен адреса с отметкой «мы в одной сети».";
pub const BTN_CLOCK_HINT: &str = "Сверить часы";

pub const DIAG_TITLE: &str = "Диагностика соединения";
pub const DIAG_NAT_TITLE: &str = "Ваша сеть";
pub const DIAG_CONNECTED: &str = "соединение есть";
pub const DIAG_NO_REASON: &str = "причина пока не ясна";
pub const MEDIATOR_LATER: &str = "Сервер-посредник мог бы помочь; он появится в следующей версии.";
pub const DIAG_NO_FRIENDS: &str = "Друзей пока нет.";
pub const NAT_NO_IPV4: &str = "IPv4-адреса нет.";
pub const NAT_PUBLIC: &str = "У вас белый IP: друзья могут звонить вам напрямую.";
pub const NAT_MAPPED: &str = "Порт открыт через роутер.";
pub const NAT_EIM: &str = "NAT подходит для прямых соединений.";
pub const NAT_MANUAL: &str = "Задан ручной проброс порта.";
pub const NAT_CONFLICT: &str = "Сведения о вашем адресе противоречат друг другу.";
pub const BTN_REFRESH_MAPPING: &str = "Обновить проброс";

pub const SET_TITLE_FOLDERS: &str = "Папка приёма";
pub const SET_CURRENT: &str = "Сейчас";
pub const SET_EXTRA_FOLDERS: &str = "Дополнительные папки (недокачанные передачи)";
pub const BTN_CHANGE_FOLDER: &str = "Сменить папку";
pub const SET_MIN_FREE: &str = "Запас свободного места, % тома";
pub const SET_PORT: &str = "Порт UDP (вступит в силу после перезапуска)";
pub const SET_FORWARD: &str = "Внешний порт ручного проброса (пусто: нет)";
pub const SET_RESTART: &str = "Есть изменения, которые вступят в силу после перезапуска программы.";
pub const SET_TITLE_UPNP: &str = "Проброс порта на роутере";
pub const BTN_FIND_ROUTER: &str = "Найти роутер";
pub const BTN_YES: &str = "Да";
pub const SET_ROUTERS: &str = "Разрешённые роутеры";
pub const SET_ROUTER_ITEM: &str = "Роутер";
pub const SET_ROUTER_PERMANENT: &str = "бессрочная аренда разрешена";
pub const BTN_FORGET: &str = "Забыть";
pub const SET_NO_ROUTERS: &str = "Разрешённых роутеров нет.";
pub const SET_TITLE_CLOCK: &str = "Часы";
pub const BTN_SYNC_CLOCK: &str = "Сверить часы";
pub const BTN_RESET_CLOCK: &str = "Сбросить поправку";
pub const SET_NTP: &str = "Серверы времени";
pub const SET_CLOCK_NOTE: &str = "Сверка идёт только по кнопке и обращается к серверам времени.";
pub const BTN_APPLY_OFFSET: &str = "Применить поправку";
pub const SET_TITLE_KEYS: &str = "Ключи";
pub const SET_KEY_STORE: &str = "Хранилище ключей";
pub const KEYS_CREDENTIAL: &str = "Диспетчер учётных данных Windows";
pub const KEYS_KEYCHAIN: &str = "Связка ключей macOS";
pub const KEYS_SECRET: &str = "Secret Service (Linux)";
pub const KEYS_OTHER: &str = "хранилище ОС";
pub const KEYS_LOCAL_UNAVAILABLE: &str = "Режим «локальные ключи» в этой версии недоступен.";
pub const SET_RETIRED: &str = "Тексты отзыва, которые ещё не сняты с учёта";
pub const SET_NO_RETIRED: &str = "Таких текстов нет.";
pub const BTN_FORGET_RETIRED: &str = "Друг получил, убрать";
pub const SET_TITLE_ABOUT: &str = "О программе";
pub const ABOUT_VERSION: &str = "Версия";
pub const ABOUT_LICENCES: &str =
    "Список лицензий сторонних библиотек появится вместе с выпуском программы (этап 19).";

// Обновления (этап 19г-2, SPEC 19г разд. 6; дословно)
pub const UPD_CONSENT_TITLE: &str = "Проверять, не вышла ли новая версия?";
pub const UPD_CONSENT_TEXT: &str = "Раз в сутки программа может спрашивать у GitHub, вышла ли новая версия. При каждой проверке GitHub видит ваш IP-адрес и то, что на этом адресе стоит Червоточина. Программа ничего не скачивает и сама не обновляется: она только сообщит номер новой версии. Решение можно изменить в разделе «Обновления».";
pub const BTN_UPD_ENABLE: &str = "Включить проверку";
pub const BTN_UPD_DISABLE: &str = "Не проверять";
pub const UPD_RUNNING: &str = "Установлена версия";
pub const UPD_TOGGLE: &str = "Проверять новые версии раз в сутки (GitHub увидит ваш IP-адрес)";
pub const BTN_UPD_CHECK_NOW: &str = "Проверить сейчас";
pub const UPD_CHECK_NEEDS_CONSENT: &str = "Включите проверку, чтобы проверить сейчас.";
pub const UPD_CHECKING: &str = "Проверяем…";
pub const BTN_UPD_WHERE: &str = "Где скачать";
pub const UPD_LINK_TEXT: &str =
    "Скачайте файлы со страницы выпусков и проверьте их здесь, в разделе «Обновления», до запуска.";
pub const UPD_NO_NETWORK: &str = "Нет связи с GitHub.";
pub const UPD_BAD_RESPONSE: &str = "Ответ не прошёл проверку.";
pub const UPD_NO_KEYS: &str = "Ключи владельца не вшиты: проверка невозможна.";
pub const UPD_SKIPPED: &str = "Проверка выключена или была меньше минуты назад.";
pub const UPD_VERIFY_TITLE: &str = "Проверить скачанные файлы";
pub const UPD_VERIFY_HINT: &str = "Выберите список файлов выпуска (chervo-release.txt), его подпись (chervo-release.txt.minisig) и скачанные файлы. Проверка идёт без сети.";
pub const BTN_UPD_PICK_MANIFEST: &str = "Список файлов…";
pub const BTN_UPD_PICK_SIG: &str = "Подпись…";
pub const BTN_UPD_PICK_FILES: &str = "Файлы…";
pub const BTN_UPD_VERIFY: &str = "Проверить";
pub const UPD_ALLOW_DOWNGRADE: &str = "Разрешить старую версию (откат)";
pub const UPD_FILE_NEWER: &str = "подходит, новее установленной";
pub const UPD_FILE_SAME: &str = "подходит, та же версия";
pub const UPD_FILE_OLDER: &str = "подходит, но это СТАРАЯ версия: откат разрешён вами";
pub const UPD_REPLACE_HINT: &str =
    "Файл подлинный. Закройте программу и замените её этим файлом вручную.";
pub const UPD_KEYS_TITLE: &str = "Вшитые ключи владельца (сверьте с README)";
pub const UPD_KEYS_NONE: &str = "Ключи владельца не вшиты.";
pub const UPD_ROLE_PRIMARY: &str = "основной";
pub const UPD_ROLE_BACKUP: &str = "запасной";
// ошибки сверки по варианту (SPEC 19г разд. 6)
pub const UPD_ERR_TOO_LARGE: &str = "файл больше допустимого предела";
pub const UPD_ERR_SIG_FORMAT: &str = "файл подписи повреждён или не того формата";
pub const UPD_ERR_UNKNOWN_KEY: &str = "подписано не ключом владельца";
pub const UPD_ERR_BAD_SIG: &str = "подпись не сходится: список файлов изменён или подпись чужая";
pub const UPD_ERR_MANIFEST_FORMAT: &str = "список файлов повреждён или не того формата";
pub const UPD_ERR_NOT_IN_MANIFEST: &str = "этого файла нет в подписанном списке";
pub const UPD_ERR_WRONG_TARGET: &str = "файл для другой системы";
pub const UPD_ERR_SIZE: &str = "размер файла не совпал";
pub const UPD_ERR_DOWNGRADE: &str =
    "это старая версия; чтобы всё же принять её, отметьте «Разрешить старую версию»";
pub const UPD_ERR_IO: &str = "файл не удалось прочитать";
pub const UPD_ERR_OTHER: &str = "проверка не прошла";

/// «Вышла версия {new} (у вас {cur}).»; подставляются только два номера версии.
pub fn upd_newer(new: &chervo_core::update::Version, cur: &str) -> String {
    format!("Вышла версия {new} (у вас {cur}).")
}

/// «Установлена последняя версия ({cur}).»
pub fn upd_up_to_date(cur: &str) -> String {
    format!("Установлена последняя версия ({cur}).")
}

/// «Подписано ключом владельца: {role}, key_id {id}. Версия выпуска {ver}.»
pub fn upd_signed_by(role: &str, key_id: &str, ver: &chervo_core::update::Version) -> String {
    format!("Подписано ключом владельца: {role}, key_id {key_id}. Версия выпуска {ver}.")
}

/// «{role}: {id}»
pub fn upd_key_row(role: &str, key_id: &str) -> String {
    format!("{role}: {key_id}")
}

pub fn clock_proposal_text(offset_ms: i64) -> String {
    let secs = offset_ms / 1000;
    format!(
        "Часы расходятся с серверами времени на {} мин {} с ({}). Поправка больше 5 минут: применить?",
        secs.abs() / 60,
        secs.abs() % 60,
        if offset_ms >= 0 {
            "ваши отстают"
        } else {
            "ваши спешат"
        }
    )
}

pub fn clock_offset_text(offset_ms: i64) -> String {
    format!("Текущая поправка: {} мс", offset_ms)
}

pub fn offer_summary(count: usize, total: u64) -> String {
    format!("Файлов: {count}, всего {}", human_size(total))
}

pub fn space_line(needed: u64, available: u64) -> String {
    format!(
        "Места нужно (с запасом): {}, свободно: {}",
        human_size(needed),
        human_size(available)
    )
}

pub fn progress_text(done: u64, total: u64) -> String {
    format!("{} из {}", human_size(done), human_size(total))
}

pub fn send_summary(files: usize, dirs: usize, files_total: u64) -> String {
    let mut s = format!("Файлов: {files}, размер: {}", human_size(files_total));
    if dirs > 0 {
        s.push_str(&format!(
            ", папок: {dirs} (их размер программа посчитает при отправке)"
        ));
    }
    s
}

/// Размер человеку: Б, КиБ, МиБ, ГиБ, ТиБ (степени 1024).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} Б")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 Б");
        assert_eq!(human_size(1023), "1023 Б");
        assert_eq!(human_size(1024), "1.0 КиБ");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 ГиБ");
    }
}
