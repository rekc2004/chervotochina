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
pub const PLACEHOLDER: &str = "Этот раздел появится в следующем шаге этапа 18.";
pub const FRIENDS_COUNT: &str = "Друзей в списке";
pub const ACTIVE_TRANSFERS: &str = "Активных передач";

// Закрытие (экран 10)
pub const CLOSE_ASK_TITLE: &str = "Закрыть программу?";
pub const CLOSE_ASK_TEXT: &str = "Передачи приостановятся и продолжатся при следующем запуске.";
pub const BTN_CLOSE: &str = "Закрыть";
pub const BTN_STAY: &str = "Остаться";
pub const CLOSING: &str = "Закрываем программу…";
