//! Строки для окна: копии нужных полей видов ядра с локальными номерами вместо непрозрачных
//! ссылок. Окно и модель ссылок ядра не держат (их владеет фоновый поток), поэтому модель
//! проверяется тестами без узла.

use std::path::PathBuf;

use chervo_core::{
    FileKind, FriendStatus, PathKind, PauseReason, Side, SpaceView, TransferResult, TransferState,
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

/// Выбранный для отправки путь с тем, что известно без обхода папки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedPath {
    pub path: PathBuf,
    pub is_dir: bool,
    /// Размер файла; для папки 0 (её размер считает узел при отправке).
    pub size: u64,
}
