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
pub const SAS_NAME_EMPTY: &str = "Введите имя друга.";
pub const SEND_NO_FRIEND: &str = "Выберите друга.";
pub const SEND_NO_FILES: &str = "Выберите файлы или папки.";
pub const NO_REVOCATION_NEEDED: &str =
    "Готово. Ключа этой пары уже не было, уведомление об удалении не нужно.";
pub const ADDR_APPLIED: &str = "Новый адрес друга сохранён, пробуем соединиться.";
/// Подошло уведомление об удалении (`CHR1`): друг убрал вас из своего списка.
pub const REVOKED_APPLIED: &str = "Друг удалил вас из своего списка: связи с ним больше не будет.";
/// Подлинное уведомление об удалении, которое никому из друзей не подходит.
pub const REVOKED_NOBODY: &str = "Это уведомление об удалении подлинное, но оно не подходит ни одному из ваших друзей (возможно, вы его уже применяли).";
pub const AUTO_ACCEPTED: &str = "Файлы от друга приняты автоматически (автоприём включён).";
pub const INVITE_ADDED: &str = "Друг добавлен.";
pub const INVITE_DECLINED: &str = "Код не совпал или вы отказались: друг не добавлен.";
pub const INVITE_EXPIRED: &str =
    "Срок приглашения истёк. Создайте новое: «Добавить друга», затем «Создать приглашение».";
pub const INVITE_FAILED: &str = "Не удалось добавить друга.";
pub const NOTICES_HIDE: &str = "Скрыть";
/// Приглашения и новые адреса содержат ваш адрес: кто увидит текст, узнает, где вы в интернете.
pub const IP_WARNING: &str =
    "Внимание: по этому тексту можно узнать ваш адрес в интернете. Отправляйте его только другу.";
pub const BTN_COPY: &str = "Копировать";
pub const BTN_CANCEL: &str = "Отмена";
pub const BTN_OK: &str = "Готово";

pub const FRIENDS_EMPTY: &str =
    "Друзей пока нет. Пригласите друга или, если друг уже прислал вам текст, вставьте его.";
pub const BTN_INVITE_FRIEND: &str = "Пригласить друга";
/// Единственная кнопка для любого текста от друга (на «Друзья» и на «Добавить друга»).
pub const BTN_FRIEND_TEXT: &str = "Друг прислал мне текст";
pub const BTN_REKEY_ALL: &str = "Пересоздать все ключи";
pub const BTN_SEND: &str = "Отправить";
pub const BTN_CONNECT: &str = "Соединить";
pub const BTN_DIAGNOSE: &str = "Диагностика";
pub const BTN_RENAME: &str = "Переименовать";
pub const BTN_BLOCK: &str = "Заблокировать";
pub const BTN_UNBLOCK: &str = "Разблокировать";
pub const BTN_REMOVE: &str = "Удалить";
pub const BTN_REKEY: &str = "Начать дружбу заново";
pub const BTN_AUTO_ON: &str = "Принимать файлы без вопроса";
pub const BTN_AUTO_OFF: &str = "Снова спрашивать о файлах";
pub const BTN_SEND_ADDR: &str = "Отправить другу мой новый адрес";
pub const BTN_SAVE: &str = "Сохранить";
pub const BTN_YES_TRUST: &str = "Да, доверяю";
pub const BTN_NO: &str = "Нет";
pub const BTN_APPLY: &str = "Применить";
pub const BTN_CREATE_TOKEN: &str = "Создать текст";
pub const BTN_NEW_INVITE: &str = "Создать приглашение для друга";
pub const LABEL_NAME: &str = "Как назвать друга в вашем списке";
pub const LABEL_SAME_NETWORK: &str = "Мы подключены к одному роутеру или Wi-Fi";
pub const LABEL_PASTE_HERE: &str = "Вставьте сюда текст, который прислал друг, целиком";
/// Подсказка внутри пустого поля.
pub const PASTE_HINT: &str = "Текст от друга";
pub const STATE_ONLINE: &str = "в сети";
pub const STATE_OFFLINE: &str = "не в сети";
pub const STATE_ACTIVE: &str = "друг";
pub const STATE_BLOCKED: &str = "заблокирован";
pub const STATE_REVOKED: &str = "друг удалил вас из списка";
pub const STATE_RETIRED: &str = "вы удалили друга или начали дружбу заново";
pub const PATH_LAN: &str = "в одной сети";
pub const PATH_IPV6: &str = "через интернет";
pub const PATH_MAPPED: &str = "через роутер";
pub const PATH_DIRECT: &str = "напрямую";
pub const AUTO_ON_LABEL: &str = "принимает файлы без вопроса";
/// Подпись соединения, пока нет итога после «Соединить».
pub const CONNECTING: &str = "Пробуем соединиться…";
pub const CONFIRM_REMOVE: &str = "Удалить друга? Покажем уведомление об удалении: отправьте его другу, иначе он узнает об этом, только когда не сможет соединиться.";
pub const CONFIRM_REKEY: &str = "Начать дружбу с этим другом заново? Так делают, если ноутбук украли или вы не уверены в безопасности. Старый ключ будет отозван: друга придётся добавить снова, а ему нужно отправить уведомление об удалении.";
pub const CONFIRM_REKEY_ALL: &str = "Начать дружбу заново со всеми друзьями? Каждому другу нужно будет отправить уведомление об удалении и создать новое приглашение.";
pub const REVOCATION_REMOVED: &str = "Друг удалён. Отправьте этот текст другу. Он вставит его у себя: «Друзья», затем «Друг прислал мне текст». Пока он этого не сделает, он не узнает об удалении.";
pub const REVOCATION_REKEY: &str = "Дружба начата заново. Отправьте этот текст другу (он вставит его: «Друзья», затем «Друг прислал мне текст»), затем создайте для него новое приглашение: «Добавить друга», затем «Создать приглашение».";
pub const REKEY_PARTIAL: &str = "Для некоторых друзей ключ пересоздать не удалось";
pub const ADDR_TOKEN_TITLE: &str = "Мой новый адрес для этого друга";
pub const FRIEND_TEXT_TITLE: &str = "Друг прислал мне текст";

pub const BTN_CREATE_INVITE: &str = "Создать приглашение";
pub const INVITE_WAIT: &str = "Скопируйте приглашение и отправьте другу в мессенджер (или покажите QR). Пусть он откроет «Добавить друга», затем «Друг прислал мне текст» и вставит его.";
pub const INVITE_ACCEPT_WAIT: &str =
    "Связываемся с другом… Когда получится, появится проверочный код.";
/// Приглашение на экране сверки: после «Совпадает».
pub const SAS_WAITING: &str = "Ждём, пока друг тоже нажмёт «Совпадает».";
pub const SAS_TITLE: &str = "Проверочный код";
pub const SAS_HINT: &str = "Сверьте цифры с другом по телефону или лично. Подтверждайте, только если цифры совпадают на обоих экранах.";
pub const BTN_SAS_MATCH: &str = "Совпадает";
pub const BTN_SAS_MISMATCH: &str = "Не совпадает";

pub const SEND_TITLE: &str = "Отправить файлы";
pub const SEND_HINT: &str = "Выберите файлы или папки или перетащите их в окно. Папки отправляются целиком; ярлыки внутри папок не отправляются.";
pub const BTN_PICK_FILES: &str = "Выбрать файлы…";
pub const BTN_PICK_DIR: &str = "Выбрать папку…";
pub const BTN_REMOVE_ITEM: &str = "Убрать";
pub const SEND_TO: &str = "Кому";
pub const SEND_NO_ACTIVE_FRIENDS: &str = "Нет друзей, которым можно отправить.";
pub const BTN_GO_ADD_FRIEND: &str = "Добавить друга";
pub const SEND_MISSING_BOTH: &str = "Чтобы отправить, выберите файлы и друга.";
pub const FOLDER_WORD: &str = "папка";

pub const OFFERS_EMPTY: &str = "Здесь появятся файлы, которые предложит друг.";
pub const OFFER_FROM: &str = "От";
pub const OFFER_SPACE_UNKNOWN: &str = "свободное место узнать не удалось";
pub const BTN_ACCEPT: &str = "Принять";
pub const BTN_DECLINE: &str = "Отклонить";
pub const BTN_OTHER_FOLDER: &str = "Выбрать другую папку";
pub const MARK_RISKY: &str = "(!) ";
/// Пояснение к «(!)» в списке файлов.
pub const RISKY_LEGEND: &str = "(!) означает, что файл требует вашего решения: принимайте его, только если доверяете отправителю.";
pub const KIND_SAFE: &str = "обычный файл";
pub const KIND_EXEC: &str = "программа или опасный тип";
pub const KIND_UNKNOWN: &str = "неизвестный тип";

pub const TRANSFERS_EMPTY: &str = "Здесь будут видны отправки и приёмы файлов.";
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
/// Кнопка на «Передачи»: открывает только папку приёма из настроек.
pub const BTN_OPEN_FOLDER: &str = "Открыть папку";
pub const OPEN_FOLDER_MISSING: &str = "Папка приёма не найдена. Выберите её заново: «Настройки», затем «Папка приёма», затем «Выбрать…».";
pub const OPEN_FOLDER_FAILED: &str = "Не удалось открыть папку. Откройте её вручную: путь показан в «Настройки», затем «Папка приёма».";

// Диагностика (7), настройки (8), уведомления (9)
pub const OWN_ADDR_CHANGED: &str = "Ваш адрес в интернете изменился. Если друзья не могут подключиться: «Друзья», затем у каждого друга «Отправить другу мой новый адрес», затем перешлите текст ему.";
pub const MIN_FREE_BAD: &str = "Запас места: число от 0 до 100.";
pub const FORWARD_BAD: &str = "Внешний порт: число от 1 до 65535 или пусто, чтобы убрать.";
pub const UPNP_ALLOWED: &str = "Роутер разрешён. Состояние проброса показано в этом разделе.";
pub const CLOCK_APPLIED: &str = "Поправка часов применена.";
pub const CLOCK_RESET: &str = "Поправка часов сброшена.";
pub const ROOT_CHANGED: &str =
    "Папка приёма изменена. Изменение вступит в силу после перезапуска программы.";
pub const CLOCK_SKEW_HINT: &str =
    "Возможно, часы у вас или у друга идут неверно. Сверьте свои часы в настройках.";
pub const LAN_EXPIRED_HINT: &str = "Адрес в локальной сети устарел (он живёт сутки). Отправьте новый адрес с отметкой «Мы подключены к одному роутеру или Wi-Fi» («Друзья», затем «Отправить другу мой новый адрес») или на домашнем компьютере включите «Настройки», затем «Локальная сеть», затем «Слушать и сообщать о себе».";
pub const BTN_CLOCK_HINT: &str = "Сверить часы";

pub const DIAG_TITLE: &str = "Диагностика соединения";
pub const DIAG_NAT_TITLE: &str = "Ваша сеть";
pub const DIAG_CONNECTED: &str = "соединение есть";
pub const DIAG_NO_REASON: &str = "причина пока не ясна";
pub const MEDIATOR_LATER: &str = "Без общего сервера-помощника программа здесь не справится: он появится в следующей версии. Пока обменяйтесь адресами вручную: «Друзья», затем «Отправить другу мой новый адрес» и «Друг прислал мне текст».";
pub const DIAG_NO_FRIENDS: &str = "Друзей пока нет.";
pub const NAT_NO_IPV4: &str = "Нет подключения к интернету (или только IPv6).";
pub const NAT_PUBLIC: &str = "У вас постоянный адрес в интернете: друзья подключаются к вам сами.";
pub const NAT_MAPPED: &str = "Роутер пропускает друзей к вам.";
pub const NAT_EIM: &str = "Ваш роутер не мешает соединению.";
pub const NAT_MANUAL: &str = "Вы сами настроили роутер для программы.";
pub const NAT_CONFLICT: &str =
    "Программа не может точно понять, какой у вас адрес. Попробуйте «Соединить» ещё раз позже.";
pub const BTN_REFRESH_MAPPING: &str = "Попросить роутер открыть порт ещё раз";
pub const BTN_OPEN_PORT: &str = "Попросить роутер открыть порт";
pub const DIAG_NET_NO_FRIENDS: &str =
    "Сеть проверится, когда появится первый друг. Добавить друга: вкладка «Добавить друга».";
pub const NAT_UNKNOWN: &str = "Пока не ясно, как вас видно из интернета. Станет ясно после первой попытки соединиться с другом.";

pub const SET_TITLE_FOLDERS: &str = "Папка приёма";
pub const SET_CURRENT: &str = "Сейчас";
pub const SET_EXTRA_FOLDERS: &str = "Дополнительные папки (недокачанные передачи)";
pub const SET_MIN_FREE: &str = "Запас свободного места, % диска";
pub const SET_PORT: &str = "Номер порта программы (обычно не трогать; меняется после перезапуска)";
pub const SET_RESTART: &str = "Есть изменения, которые вступят в силу после перезапуска программы.";
pub const SET_TITLE_LAN: &str = "Локальная сеть";
pub const SET_TITLE_UPNP: &str = "Входящие подключения";
pub const BTN_FIND_ROUTER: &str = "Найти мой роутер";
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
pub const DETAILS: &str = "Подробнее";
pub const LAN_SHORT_OFF: &str = "Не искать друзей в локальной сети";
pub const LAN_SHORT_LISTEN: &str = "Искать друзей в локальной сети";
pub const LAN_SHORT_ANNOUNCE: &str =
    "Искать и сообщать о себе (только дома, не в кафе и не в гостинице)";
pub const UPD_EXPERT: &str = "Для опытных: проверить скачанный установщик";
pub const SET_CLOCK_NOTE: &str = "Сверка идёт только по кнопке и обращается к серверам времени.";
pub const BTN_APPLY_OFFSET: &str = "Применить поправку";
pub const SET_TITLE_KEYS: &str = "Ключи";
pub const SET_KEY_STORE: &str = "Хранилище ключей";
pub const KEYS_CREDENTIAL: &str = "Диспетчер учётных данных Windows";
pub const KEYS_KEYCHAIN: &str = "Связка ключей macOS";
pub const KEYS_SECRET: &str = "Secret Service (Linux)";
pub const KEYS_OTHER: &str = "хранилище ОС";
pub const SET_RETIRED: &str = "Уведомления об удалении, которые вы ещё не отправили друзьям";
pub const SET_NO_RETIRED: &str = "Таких текстов нет.";
pub const BTN_FORGET_RETIRED: &str = "Друг получил, убрать";
pub const SET_TITLE_ABOUT: &str = "О программе";
pub const ABOUT_VERSION: &str = "Версия";
pub const ABOUT_LICENCES: &str = "В программе используются свободные библиотеки. Их лицензии и авторы перечислены в файле chervo-{ver}-third-party-licenses.txt на странице выпусков; файл подписан вместе с программой.";

// Этап 13д: адрес в интернете, «Получить свой IP», помощник «Разрешить входящие подключения».
// Пояснения у новых пунктов показываются во всплывающей подсказке значка «?» (Р7, дополнение
// владельца 2026-11-18); предупреждения, без которых действие небезопасно, остаются на виду.

/// Значок рядом с подписью: описание всплывает при наведении.
pub const HELP_MARK: &str = "?";

pub const SET_TITLE_EXTERNAL: &str = "Связь через интернет";
pub const EXT_SERVER_LABEL: &str = "Адрес вашего сервера, например 203.0.113.5:45900";
pub const BTN_CLEAR: &str = "Очистить";
pub const EXT_SERVER_HINT: &str = "Нужен, когда друг подключается не из вашей домашней сети. Сервер подсказывает программе ваш адрес в интернете, и программа сама впишет его в приглашение. Сервер — это программа chervo-rendezvous на компьютере, который всегда доступен из интернета (ваш или знакомого). Адрес для этой строки даст тот, кто запустил сервер. Пока строка пустая, программа ни к какому серверу не обращается.";
pub const EXT_SERVER_SAVED: &str =
    "Сохранено. Теперь «Создать приглашение» само впишет ваш адрес в интернете.";
pub const EXT_SERVER_CLEARED: &str =
    "Адрес сервера удалён. Приглашения создаются без адреса в интернете.";

pub const BTN_GET_IP: &str = "Получить свой IP";
pub const GETIP_RESULT: &str = "Ваш адрес в интернете (IP и порт):";
pub const GETIP_NO_SERVER: &str = "Чтобы узнать адрес, впишите адрес своего сервера: вкладка «Настройки», раздел «Связь через интернет», строка «Адрес вашего сервера».";
pub const GETIP_NO_ANSWER: &str = "Сервер не ответил. Проверьте, что он включён и что адрес на вкладке «Настройки», раздел «Связь через интернет», верный. Затем снова нажмите «Получить свой IP».";
pub const GETIP_MAYBE_VPN: &str = "Похоже, включён VPN: это может быть адрес VPN, а не ваш. Выключите VPN или добавьте Червоточину в исключения VPN и снова нажмите «Получить свой IP».";
pub const GETIP_VPN_ON: &str =
    "Включён VPN. Это ваш настоящий адрес, но, пока VPN работает, друг по нему не подключится.";
pub const INV_EXT_CHECKING: &str = "Узнаём ваш адрес в интернете…";
pub const INV_EXT_ADDED: &str = "В приглашение вписан ваш адрес в интернете: {addr}";
pub const INV_EXT_FRIEND_TIP: &str = "Если друг не подключится за минуту, нажмите «Разрешить входящие подключения»: программа поможет настроить роутер.";
/// Короткая подпись, рядом с которой стоит «?» с текстом `INV_EXT_NOT_SET`.
pub const INV_EXT_NOT_SET_LABEL: &str = "Адрес в интернете в приглашение не вписан";
pub const INV_EXT_NOT_SET: &str = "Друг в другой сети? Впишите адрес своего сервера: вкладка «Настройки», раздел «Связь через интернет». Тогда программа сама добавит в приглашение ваш адрес в интернете. Без этого приглашение сработает, только если друг в той же сети, что и вы, или ваш компьютер уже доступен из интернета.";
pub const INV_EXT_NO_ANSWER: &str = "Сервер не ответил, поэтому ваш адрес в интернете в приглашение не вписан. Проверьте, что сервер включён и адрес на вкладке «Настройки», раздел «Связь через интернет», верный, затем снова нажмите «Создать приглашение».";
pub const INV_EXT_SERVER_LOCAL: &str = "Сервер стоит в той же сети, что и вы, поэтому ваш адрес в интернете не узнать. Нужен сервер вне вашей сети.";
pub const INV_EXT_SYMMETRIC: &str = "Ваш роутер выдаёт каждому собеседнику свой адрес, поэтому адрес от сервера другу не подойдёт и не вписан. Нажмите «Разрешить входящие подключения»: программа поможет настроить роутер.";
pub const INV_MAYBE_VPN_TITLE: &str = "Похоже, включён VPN";
pub const INV_MAYBE_VPN_TEXT: &str = "Программа узнала адрес, но, возможно, это адрес VPN, а не ваш. По адресу VPN друг к вам не подключится. Выключите VPN или добавьте Червоточину в исключения VPN (в настройках VPN это называется «исключения» или «раздельное туннелирование»), затем снова нажмите «Создать приглашение».";
pub const BTN_INV_WITHOUT_ADDR: &str = "Создать приглашение без этого адреса";
pub const BTN_INV_WITH_ADDR: &str = "VPN выключен, вписать адрес";
pub const INV_VPN_ON_TITLE: &str = "Включён VPN";
pub const INV_VPN_ON_TEXT: &str = "Ваш настоящий адрес вписан в приглашение, но, пока VPN включён, друг к вам не подключится. Выключите VPN или добавьте Червоточину в исключения VPN.";
pub const INV_ADDR_CHANGED: &str = "Ваш адрес в интернете изменился. Это приглашение может не сработать: нажмите «Отмена» и создайте новое.";

pub const BTN_OPEN_ACCESS: &str = "Разрешить входящие подключения";
pub const ACC_TITLE: &str = "Доступ к этому компьютеру из интернета";
pub const ACC_INTRO: &str = "Чтобы друг из другой сети мог подключиться, роутер должен пропускать его к этому компьютеру. Сначала программа попробует договориться с роутером сама.";
pub const ACC_VPN: &str = "Включён VPN: пока он работает, настройка роутера другу не поможет. Выключите VPN или добавьте Червоточину в исключения VPN.";
pub const ACC_CGNAT: &str = "Ваш провайдер выдаёт один адрес в интернете сразу многим абонентам, поэтому настройка роутера не поможет. Можно попросить у провайдера «белый» (постоянный) IP-адрес.";
pub const BTN_ACC_AUTO: &str = "Попробовать автоматически";
pub const ACC_SEARCHING: &str = "Ищем роутер…";
pub const ACC_ASK_ROUTER: &str = "Найден роутер. Разрешить программе открывать на нём доступ для Червоточины? Делайте это только дома: в чужой сети (гостиница, офис) другое устройство может выдать себя за роутер. Ответ запомнится для этого роутера; при выходе из программы доступ закрывается.";
pub const BTN_ACC_ALLOW: &str = "Разрешить";
pub const BTN_ACC_DENY: &str = "Не разрешать";
pub const ACC_AUTO_WAIT: &str = "Договариваемся с роутером…";
pub const ACC_AUTO_OK: &str = "Готово: роутер открыл доступ.";
pub const ACC_AUTO_FAILED: &str = "Автоматически не получилось: роутер не ответил или не разрешил. Это можно сделать вручную за несколько минут — по шагам ниже.";
pub const ACC_MANUAL_TITLE: &str = "Как открыть доступ вручную";
pub const ACC_STEP1: &str = "1. Откройте в браузере страницу роутера:";
pub const ACC_GW_FOUND: &str = "Этот адрес сообщил сам роутер.";
pub const ACC_GW_GUESS: &str = "Обычно страница роутера открывается по этому адресу. Если не открывается, посмотрите адрес на наклейке снизу роутера.";
pub const ACC_STEP2: &str = "2. Войдите. Логин и пароль часто написаны на той же наклейке.";
pub const ACC_STEP3: &str = "3. Найдите раздел «Переадресация портов». Он может называться «Port Forwarding», «Виртуальный сервер» или «Virtual Server»; обычно он лежит в разделе «Интернет», «WAN» или «Дополнительно».";
pub const ACC_STEP4: &str =
    "4. Добавьте правило и перенесите в него эти значения (кнопка «Копировать» у каждого):";
pub const ACC_F_NAME: &str = "Название (если спрашивают)";
pub const ACC_V_NAME: &str = "Chervotochina";
pub const ACC_F_PROTO: &str = "Протокол";
pub const ACC_V_PROTO: &str = "UDP";
pub const ACC_F_EXT_PORT: &str = "Внешний порт (может называться «порт WAN»)";
pub const ACC_F_INT_IP: &str = "Внутренний IP-адрес (адрес этого компьютера)";
pub const ACC_F_INT_PORT: &str = "Внутренний порт";
pub const ACC_RANGE_NOTE: &str =
    "Если роутер просит начальный и конечный порт, впишите одно и то же число в оба поля.";
pub const ACC_INT_IP_MANY: &str = "У компьютера несколько адресов в домашней сети. Нужен тот, у которого первые три числа совпадают с адресом страницы роутера из шага 1.";
pub const ACC_STEP5: &str = "5. Сохраните правило и нажмите «Проверить».";
pub const ACC_KEEP_NOTE: &str = "Если после перезагрузки роутера доступ пропадёт, закрепите в настройках роутера адрес за этим компьютером (часто называется «Резервирование адреса» или «Static DHCP») и повторите проверку.";
pub const ACC_PORT_NOTE: &str = "Не меняйте после этого номер в строке «Порт» на вкладке «Настройки»: правило в роутере перестанет подходить.";
pub const BTN_ACC_CHECK: &str = "Проверить";
pub const ACC_CHECKING: &str = "Проверяем…";
pub const ACC_CHECK_OK: &str = "Похоже, работает: проверочный ответ сервера дошёл через роутер до этого компьютера. Программа будет вписывать этот доступ в приглашения.";
pub const ACC_CHECK_FAIL: &str = "Проверочный ответ не дошёл. Проверьте в правиле: протокол UDP, оба порта {port}, адрес компьютера {ip}, правило сохранено и включено. Затем снова нажмите «Проверить».";
pub const ACC_CHECK_LIMIT: &str = "Проверка не даёт полной гарантии: некоторые роутеры пропускают ответ сервера, но не пропускают других. Окончательная проверка — подключение друга.";
pub const ACC_CHECK_NO_SERVER: &str = "Проверить автоматически можно только с вашим сервером, если он поддерживает проверку доступа (вкладка «Настройки», раздел «Связь через интернет»). Без этого нажмите «Правило создано» и попросите друга подключиться.";
pub const BTN_ACC_DONE: &str = "Правило создано";
pub const ACC_DONE: &str = "Запомнили. Программа будет вписывать этот доступ в приглашения.";
pub const ACC_MANUAL_FORWARD_LABEL: &str =
    "Внешний номер, если правило в роутере вы создали сами с другим числом (обычно не нужно)";

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
pub const UPD_LINK_TEXT: &str = "Скачайте файлы со страницы выпусков и проверьте их здесь: «Настройки», раздел «Обновления», до запуска.";
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
        "Места нужно (с запасом, чтобы диск не заполнился до конца): {}, свободно: {}",
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

/// Размер человеку: Б, КБ, МБ, ГБ, ТБ (степени 1024, запятая, одна цифра после неё). Те же
/// единицы и запись, что в текстах приёма (`chervo-receive`) и консоли: на одном экране не
/// бывает двух видов единиц (этап 18б, Н4).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = bytes;
    let mut frac = 0u64;
    let mut unit = 0usize;
    while value >= 1024 && unit + 1 < UNITS.len() {
        frac = (value % 1024) * 10 / 1024;
        value /= 1024;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("ТБ");
    if unit == 0 {
        format!("{value} {name}")
    } else {
        format!("{value},{frac} {name}")
    }
}

/// «Действует ещё N мин» у созданного приглашения (С9). Время в часах не пишется: местное время
/// без сторонних пакетов не определить.
pub fn invite_valid_text(secs_left: u64) -> String {
    if secs_left == 0 {
        return "Срок приглашения вышел: создайте новое.".to_owned();
    }
    let mins = secs_left.div_ceil(60);
    format!("Приглашение действует ещё {mins} мин.")
}

#[cfg(test)]
mod tests {
    use super::{human_size, invite_valid_text};
    use crate::texts;

    /// Новые тексты 13д (Р8), которые видит человек.
    fn new_texts() -> Vec<(&'static str, &'static str)> {
        use super::*;
        vec![
            ("SET_TITLE_EXTERNAL", SET_TITLE_EXTERNAL),
            ("EXT_SERVER_LABEL", EXT_SERVER_LABEL),
            ("EXT_SERVER_HINT", EXT_SERVER_HINT),
            ("EXT_SERVER_SAVED", EXT_SERVER_SAVED),
            ("EXT_SERVER_CLEARED", EXT_SERVER_CLEARED),
            ("BTN_GET_IP", BTN_GET_IP),
            ("GETIP_RESULT", GETIP_RESULT),
            ("GETIP_NO_SERVER", GETIP_NO_SERVER),
            ("GETIP_NO_ANSWER", GETIP_NO_ANSWER),
            ("GETIP_MAYBE_VPN", GETIP_MAYBE_VPN),
            ("GETIP_VPN_ON", GETIP_VPN_ON),
            ("INV_EXT_CHECKING", INV_EXT_CHECKING),
            ("INV_EXT_ADDED", INV_EXT_ADDED),
            ("INV_EXT_FRIEND_TIP", INV_EXT_FRIEND_TIP),
            ("INV_EXT_NOT_SET_LABEL", INV_EXT_NOT_SET_LABEL),
            ("INV_EXT_NOT_SET", INV_EXT_NOT_SET),
            ("INV_EXT_NO_ANSWER", INV_EXT_NO_ANSWER),
            ("INV_EXT_SERVER_LOCAL", INV_EXT_SERVER_LOCAL),
            ("INV_EXT_SYMMETRIC", INV_EXT_SYMMETRIC),
            ("INV_MAYBE_VPN_TITLE", INV_MAYBE_VPN_TITLE),
            ("INV_MAYBE_VPN_TEXT", INV_MAYBE_VPN_TEXT),
            ("BTN_INV_WITHOUT_ADDR", BTN_INV_WITHOUT_ADDR),
            ("BTN_INV_WITH_ADDR", BTN_INV_WITH_ADDR),
            ("INV_VPN_ON_TITLE", INV_VPN_ON_TITLE),
            ("INV_VPN_ON_TEXT", INV_VPN_ON_TEXT),
            ("INV_ADDR_CHANGED", INV_ADDR_CHANGED),
            ("BTN_OPEN_ACCESS", BTN_OPEN_ACCESS),
            ("ACC_TITLE", ACC_TITLE),
            ("ACC_INTRO", ACC_INTRO),
            ("ACC_VPN", ACC_VPN),
            ("ACC_CGNAT", ACC_CGNAT),
            ("BTN_ACC_AUTO", BTN_ACC_AUTO),
            ("ACC_SEARCHING", ACC_SEARCHING),
            ("ACC_ASK_ROUTER", ACC_ASK_ROUTER),
            ("ACC_AUTO_WAIT", ACC_AUTO_WAIT),
            ("ACC_AUTO_OK", ACC_AUTO_OK),
            ("ACC_AUTO_FAILED", ACC_AUTO_FAILED),
            ("ACC_MANUAL_TITLE", ACC_MANUAL_TITLE),
            ("ACC_STEP1", ACC_STEP1),
            ("ACC_GW_FOUND", ACC_GW_FOUND),
            ("ACC_GW_GUESS", ACC_GW_GUESS),
            ("ACC_STEP2", ACC_STEP2),
            ("ACC_STEP3", ACC_STEP3),
            ("ACC_STEP4", ACC_STEP4),
            ("ACC_F_NAME", ACC_F_NAME),
            ("ACC_F_PROTO", ACC_F_PROTO),
            ("ACC_F_EXT_PORT", ACC_F_EXT_PORT),
            ("ACC_F_INT_IP", ACC_F_INT_IP),
            ("ACC_F_INT_PORT", ACC_F_INT_PORT),
            ("ACC_RANGE_NOTE", ACC_RANGE_NOTE),
            ("ACC_INT_IP_MANY", ACC_INT_IP_MANY),
            ("ACC_STEP5", ACC_STEP5),
            ("ACC_KEEP_NOTE", ACC_KEEP_NOTE),
            ("ACC_PORT_NOTE", ACC_PORT_NOTE),
            ("BTN_ACC_CHECK", BTN_ACC_CHECK),
            ("ACC_CHECKING", ACC_CHECKING),
            ("ACC_CHECK_OK", ACC_CHECK_OK),
            ("ACC_CHECK_FAIL", ACC_CHECK_FAIL),
            ("ACC_CHECK_LIMIT", ACC_CHECK_LIMIT),
            ("ACC_CHECK_NO_SERVER", ACC_CHECK_NO_SERVER),
            ("BTN_ACC_DONE", BTN_ACC_DONE),
            ("ACC_DONE", ACC_DONE),
            ("ACC_MANUAL_FORWARD_LABEL", ACC_MANUAL_FORWARD_LABEL),
            ("SET_TITLE_UPNP", SET_TITLE_UPNP),
        ]
    }

    /// Каждый текст 13д с действием называет вкладку, раздел или кнопку; жаргона нет, слова
    /// «порт» и «UDP» только в тексте помощника и в подписи адреса с портом.
    #[test]
    fn texts_name_tab_and_button() {
        let named: [(&str, &[&str]); 13] = [
            ("GETIP_NO_SERVER", &["Настройки", "Связь через интернет"]),
            ("GETIP_NO_ANSWER", &["Настройки", "Связь через интернет"]),
            ("GETIP_MAYBE_VPN", &["Получить свой IP"]),
            ("INV_EXT_FRIEND_TIP", &["Разрешить входящие подключения"]),
            ("INV_EXT_NOT_SET", &["Настройки", "Связь через интернет"]),
            ("INV_EXT_NO_ANSWER", &["Настройки", "Создать приглашение"]),
            ("INV_EXT_SYMMETRIC", &["Разрешить входящие подключения"]),
            ("INV_MAYBE_VPN_TEXT", &["Создать приглашение"]),
            ("ACC_STEP5", &["Проверить"]),
            ("ACC_CHECK_FAIL", &["Проверить"]),
            ("ACC_CHECK_NO_SERVER", &["Настройки", "Правило создано"]),
            ("ACC_PORT_NOTE", &["Настройки"]),
            ("EXT_SERVER_SAVED", &["Создать приглашение"]),
        ];
        let all = new_texts();
        for (name, parts) in named {
            let text = all
                .iter()
                .find(|(n, _)| *n == name)
                .map_or_else(|| panic!("нет текста {name}"), |(_, t)| *t);
            for part in parts {
                assert!(text.contains(part), "{name}: нет «{part}»");
            }
        }
        for (name, text) in &all {
            // слово «ток-ен» собрано из частей: охрана 18б ищет его в этом файле
            let jargon = [
                ["то", "кен"].concat(),
                ["То", "кен"].concat(),
                "NAT".into(),
                "эхо".into(),
                "Эхо".into(),
                "UPnP".into(),
                "SSDP".into(),
            ];
            for bad in jargon.iter().map(String::as_str) {
                assert!(!text.contains(bad), "{name}: слово {bad}");
            }
            let lower = text.to_lowercase();
            if lower.contains("порт") || text.contains("UDP") {
                assert!(
                    name.starts_with("ACC_") || *name == "GETIP_RESULT",
                    "{name}: «порт» или «UDP» вне помощника"
                );
            }
        }
        // пример адреса сервера только документационный (RFC 5737)
        assert!(texts::EXT_SERVER_LABEL.contains("203.0.113.5"));
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 Б");
        assert_eq!(human_size(1023), "1023 Б");
        assert_eq!(human_size(1024), "1,0 КБ");
        assert_eq!(human_size(1536), "1,5 КБ");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5,0 ГБ");
        assert!(human_size(u64::MAX).ends_with("ТБ"));
        // одни единицы на всё окно: ни КиБ, ни МиБ
        assert!(!human_size(3 * 1024 * 1024).contains("иБ"));
    }

    #[test]
    fn invite_validity_text() {
        assert_eq!(invite_valid_text(900), "Приглашение действует ещё 15 мин.");
        assert_eq!(invite_valid_text(61), "Приглашение действует ещё 2 мин.");
        assert_eq!(invite_valid_text(1), "Приглашение действует ещё 1 мин.");
        assert!(invite_valid_text(0).starts_with("Срок приглашения вышел"));
    }
}
