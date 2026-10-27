//! Ссылки и виды для оболочек (GUI, CLI). Ссылки непрозрачны: из них нельзя достать `PairId` и
//! ключ передачи. `Debug` всех видов, где есть имена, пути, адреса или SAS, скрыт: печатается
//! только имя типа (этап 17, B3; инвариант 4 спецификации 18а).

use std::fmt;
use std::path::Path;

use chervo_connect::{NoDirectPath, PathKind};
use chervo_identity::PairId;
use chervo_token::Sas;
use chervo_transfer::{FailReason, PauseReason, Side, TransferKey, TransferState};
use chervo_upnp::RouterId;

pub use super::store::KeyStoreKind;

macro_rules! opaque_ref {
    ($(#[$m:meta])* $name:ident($inner:ty)) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name($inner);

        impl $name {
            pub(crate) fn new(v: $inner) -> Self {
                Self(v)
            }

            pub(crate) fn inner(&self) -> &$inner {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

opaque_ref!(
    /// Друг (или пара приглашения). Стабильна, пока работает узел.
    FriendRef(PairId)
);
opaque_ref!(
    /// Передача (исходящая или входящая).
    TransferRef(TransferKey)
);
opaque_ref!(
    /// Приглашение в работе.
    InviteRef(PairId)
);

impl FriendRef {
    /// Ссылка на друга для приглашения, ставшего дружбой: пара та же.
    pub fn from_invite(invite: InviteRef) -> Self {
        Self(*invite.inner())
    }
}

/// Проверочный код: 8 цифр группами 4+4 (решение владельца 2026-10-25).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SasView(Sas);

impl SasView {
    pub(crate) fn new(s: Sas) -> Self {
        Self(s)
    }

    /// `"1234 5678"`.
    pub fn digits(&self) -> String {
        self.0.digits()
    }

    /// Для экранного диктора, цифра за цифрой: `"1 2 3 4 5 6 7 8"`.
    pub fn spoken(&self) -> String {
        let d = self.0.digits();
        let digits: Vec<String> = d
            .chars()
            .filter(char::is_ascii_digit)
            .map(String::from)
            .collect();
        digits.join(" ")
    }
}

impl fmt::Debug for SasView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SasView(..)")
    }
}

/// Подписанный нами отзыв: его отправляют другу вручную. `Debug` скрыт.
#[derive(Clone, PartialEq, Eq)]
pub struct RevocationText(String);

impl RevocationText {
    pub(crate) fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RevocationText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevocationText(..)")
    }
}

/// Текст приглашения или токена адреса. Внутри ваши адреса, в том числе внешний IP: кто увидит
/// текст, узнает IP. `Debug` скрыт.
#[derive(Clone, PartialEq, Eq)]
pub struct AddrToken(String);

impl AddrToken {
    pub(crate) fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Всегда `true`: оболочка обязана показать предупреждение об IP рядом с текстом.
    pub const fn reveals_ip(&self) -> bool {
        true
    }
}

impl fmt::Debug for AddrToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddrToken(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FriendStatus {
    Active,
    Blocked,
    RevokedByPeer,
    /// Мы удалили друга или пересоздали ключ: остался только текст отзыва для отправки.
    Retired,
}

/// Друг в списке. `Debug` скрыт (внутри имя).
#[derive(Clone, PartialEq, Eq)]
pub struct FriendView {
    pub friend: FriendRef,
    pub name: String,
    pub state: FriendStatus,
    pub online: bool,
    pub auto_accept: bool,
    /// Ключ пары пропал или изменён: «добавьте друга заново» (`KEY_LOST_TEXT`).
    pub key_problem: bool,
    /// Путь последнего соединения (остаётся после обрыва).
    pub last_path: Option<PathKind>,
}

impl fmt::Debug for FriendView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FriendView(..)")
    }
}

/// Итог передачи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferResult {
    Completed,
    /// Получатель (мы или друг) отказался от предложения.
    Declined,
    /// Отменена нами (`by_us`) или другом.
    Cancelled {
        by_us: bool,
    },
    Failed {
        reason: FailReason,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransferView {
    pub transfer: TransferRef,
    pub friend: FriendRef,
    pub side: Side,
    pub state: TransferState,
    pub done: u64,
    pub total: u64,
    /// Причина паузы, если передача приостановлена.
    pub pause: Option<PauseReason>,
    /// Отправитель хэширует файлы: сколько байт обработано из скольких.
    pub preparing: Option<(u64, u64)>,
    pub result: Option<TransferResult>,
    /// Входящая: папка, куда складываются файлы (текст для показа и копирования). Файлы не
    /// открываются и не запускаются.
    pub dest_root: Option<String>,
}

impl fmt::Debug for TransferView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransferView(..)")
    }
}

/// Тип файла, как его классифицирует приём (этап 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileKind {
    /// Заведомо безопасный тип из списка: автоприём возможен.
    Safe,
    /// Программа, сценарий, образ диска или документ с макросами.
    ExecutableLike,
    /// Прочий неизвестный тип: вопрос «Вы доверяете отправителю?».
    Unknown,
}

/// Файл предложения. Имя только санитизированное (`SafeRelPath`), без bidi, нулевой ширины и
/// `..`. `Debug` скрыт.
#[derive(Clone, PartialEq, Eq)]
pub struct OfferFile {
    pub index: u32,
    pub name: String,
    pub size: u64,
    pub kind: FileKind,
    /// Имя выглядит как документ или фото, а это программа.
    pub deceptive: bool,
    /// Для этого файла нужен вопрос о доверии (тип не из списка безопасных).
    pub needs_question: bool,
    /// Имя изменено для безопасного сохранения или содержит необычные символы.
    pub name_changed: bool,
}

impl fmt::Debug for OfferFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfferFile(..)")
    }
}

/// Место на диске для предложения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceView {
    /// Предложение плюс запас `min_free_percent`, байт.
    pub needed: u64,
    /// Свободно за вычетом остальных приёмов; `None`: узнать не удалось.
    pub available: Option<u64>,
    pub short: bool,
}

/// Входящее предложение, как его видит человек. `Debug` скрыт.
#[derive(Clone, PartialEq, Eq)]
pub struct IncomingOffer {
    pub transfer: TransferRef,
    pub friend: FriendRef,
    pub files: Vec<OfferFile>,
    pub total: u64,
    pub space: SpaceView,
    /// Хотя бы для одного файла нужен вопрос о доверии (`ASK_FILE_TEXT`).
    pub needs_question: bool,
    /// Тексты предупреждений (русские, фиксированные, из этапа 15) в порядке показа.
    pub warnings: Vec<&'static str>,
}

impl fmt::Debug for IncomingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IncomingOffer(..)")
    }
}

/// Почему друг недоступен и чем это лечится. `text` русский, без адресов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosisView {
    pub reason: NoDirectPath,
    pub text: &'static str,
    /// Сервер-посредник мог бы помочь (в этой версии его нет: показывается честный текст).
    pub rendezvous_could_help: bool,
}

/// Найденный роутер (непрозрачный). Появляется только после нажатия кнопки «Найти роутер».
#[derive(Clone, PartialEq, Eq)]
pub struct RouterCandidate(pub(crate) RouterId);

impl fmt::Debug for RouterCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RouterCandidate(..)")
    }
}

/// Разрешённый пользователем роутер.
#[derive(Clone, PartialEq, Eq)]
pub struct RouterView {
    pub router: RouterCandidate,
    pub permanent_ok: bool,
    /// Роутер потребовал бессрочную аренду, а согласия ещё нет: вопрос `NEED_PERMANENT_TEXT`
    /// относится именно к нему (только чтение, поведение узла не меняется).
    pub needs_permanent: bool,
}

impl fmt::Debug for RouterView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RouterView(..)")
    }
}

/// Поправка часов больше 5 минут: применяется только после `Node::confirm_clock`.
#[derive(Clone, PartialEq, Eq)]
pub struct ClockProposal {
    pub(crate) offset_ms: i64,
}

impl ClockProposal {
    /// Поправка к системному времени, мс.
    pub fn offset_ms(&self) -> i64 {
        self.offset_ms
    }
}

impl fmt::Debug for ClockProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClockProposal(..)")
    }
}

/// Итог кнопки «Сверить часы».
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockSync {
    /// Поправка до 5 минут применена и сохранена.
    Applied { offset_ms: i64 },
    /// Больше 5 минут: показать подтверждение, затем `confirm_clock`.
    NeedsConfirm(ClockProposal),
}

#[derive(Clone, PartialEq, Eq)]
pub struct SettingsView {
    pub port: u16,
    pub receive_root: String,
    pub shared_root_confirmed: bool,
    pub extra_roots: Vec<String>,
    pub min_free_percent: u8,
    pub invite_ttl_secs: u64,
    pub manual_forward: Option<u16>,
    pub routers: Vec<RouterView>,
    pub clock_offset_ms: i64,
    /// Когда поправка записана, секунды UTC; 0: не записывалась.
    pub clock_offset_at: u64,
    /// Серверы времени (по умолчанию список из `chervo_timesync`).
    pub ntp_servers: Vec<String>,
    pub key_store: KeyStoreKind,
    /// Порт, папка приёма, запас места или ручной проброс изменены: вступят в силу после
    /// перезапуска программы.
    pub restart_needed: bool,
}

impl fmt::Debug for SettingsView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SettingsView(..)")
    }
}

/// Предупреждения (не ошибки): действие выполнено.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeWarning {
    /// Сохранено, но счётчик защиты от отката не обновлён: перезапустите программу (S1 L3).
    AnchorNotUpdated,
    /// Дополнительная папка приёма недоступна (удалена или отключена); недокачанные там
    /// передачи не возобновятся, пока папка не вернётся.
    RootUnavailable,
    /// Действие выполнено, но настройки на диск записать не удалось.
    SettingsNotSaved,
    /// Предложение отклонено автоматически: имена файлов недопустимы (`HOSTILE_DECLINED_TEXT`).
    HostileOfferDeclined,
}

/// Текст пути для показа: без префикса `\\?\` Windows.
pub(crate) fn path_for_display(p: &Path) -> String {
    let s = p.to_string_lossy().into_owned();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => rest.to_owned(),
        _ => s,
    }
}
