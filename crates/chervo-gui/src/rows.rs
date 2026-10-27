//! Строки для окна: копии нужных полей видов ядра с локальными номерами вместо непрозрачных
//! ссылок. Окно и модель ссылок ядра не держат (их владеет фоновый поток), поэтому модель
//! проверяется тестами без узла.

use std::path::PathBuf;

use crate::redact::redacted_debug_struct;

redacted_debug_struct!(PickedPath);

use chervo_core::{
    FileKind, FriendStatus, KeyStoreKind, PathKind, PauseReason, Side, SpaceView, TransferResult,
    TransferState,
};

/// Локальный номер друга, приглашения или передачи. Выдаёт фоновый поток.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(pub u32);

#[derive(Clone)]
pub struct FriendRow {
    pub id: Id,
    pub name: String,
    pub status: FriendStatus,
    pub online: bool,
    pub auto_accept: bool,
    pub key_problem: bool,
    pub path: Option<PathKind>,
}

#[derive(Clone)]
pub struct FileRow {
    /// Только санитизированное имя из плана приёма.
    pub name: String,
    pub size: u64,
    pub kind: FileKind,
    pub needs_question: bool,
}

#[derive(Clone)]
pub struct OfferRow {
    pub id: Id,
    pub friend: String,
    pub files: Vec<FileRow>,
    pub total: u64,
    pub space: SpaceView,
    pub needs_question: bool,
    pub warnings: Vec<&'static str>,
}

#[derive(Clone)]
pub struct TransferRow {
    pub id: Id,
    pub friend: String,
    pub side: Side,
    pub state: TransferState,
    pub done: u64,
    pub total: u64,
    pub pause: Option<PauseReason>,
    pub preparing: Option<(u64, u64)>,
    pub result: Option<TransferResult>,
    /// Куда складываются файлы (текст для показа и копирования; не открывается).
    pub dest_root: Option<String>,
}

impl TransferRow {
    /// Передача ещё идёт (для вопроса при закрытии).
    pub fn is_active(&self) -> bool {
        self.result.is_none() && self.state != TransferState::Finished
    }
}

/// Разрешённый роутер в списке настроек. `id` стабилен (не позиция в списке).
#[derive(Clone)]
pub struct RouterRow {
    pub id: Id,
    pub permanent_ok: bool,
    /// Этот роутер потребовал бессрочную аренду и ждёт ответа пользователя.
    pub needs_permanent: bool,
}

/// Снимок настроек для экрана 8.
#[derive(Clone)]
pub struct SettingsRow {
    pub port: u16,
    pub receive_root: String,
    pub extra_roots: Vec<String>,
    pub min_free_percent: u8,
    pub manual_forward: Option<u16>,
    pub routers: Vec<RouterRow>,
    pub clock_offset_ms: i64,
    pub ntp_servers: Vec<String>,
    pub key_store: KeyStoreKind,
    pub restart_needed: bool,
}

/// Текст отзыва, который ещё не снят с учёта (удалённый или пересозданный друг).
#[derive(Clone)]
pub struct RetiredRow {
    pub id: Id,
    pub friend: String,
    pub text: String,
}

/// Почему друг недоступен (экран 7).
#[derive(Clone)]
pub struct DiagRow {
    pub friend: Id,
    pub text: &'static str,
    pub could_help: bool,
    /// Последний путь был по локальной сети, а адреса больше нет: подсказка про токен «мы в одной
    /// сети» (адреса локальной сети живут сутки).
    pub lan_hint: bool,
}

/// Выбранный для отправки путь с тем, что известно без обхода папки.
#[derive(Clone, PartialEq, Eq)]
pub struct PickedPath {
    pub path: PathBuf,
    pub is_dir: bool,
    /// Размер файла; для папки 0 (её размер считает узел при отправке).
    pub size: u64,
}
