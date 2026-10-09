//! Безопасный приём файлов: лимиты и заглушка санитайзера путей.
//! Результат всегда должен оставаться внутри корня (реализация в этапе 15).

use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveLimits {
    pub max_files: u32,
    pub max_depth: u16,
    pub max_name_bytes: u16,
    pub max_path_bytes: u16,
    pub max_total_bytes: u64,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_depth: 16,
            max_name_bytes: 255,
            max_path_bytes: 1024,
            max_total_bytes: 64 * 1024 * 1024 * 1024, // placeholder, revisit in stage 15
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    Empty,
    TooLong,
    NotImplemented,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Empty => "empty path",
            Self::TooLong => "path too long",
            Self::NotImplemented => "not implemented",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PathError {}

/// Заглушка: пусто → `Empty`, длиннее лимита → `TooLong`, иначе `NotImplemented`. Никогда не `Ok`.
pub fn sanitize_relative_path(
    _root: &Path,
    untrusted: &str,
    limits: &ReceiveLimits,
) -> Result<PathBuf, PathError> {
    if untrusted.is_empty() {
        return Err(PathError::Empty);
    }
    if untrusted.len() > usize::from(limits.max_path_bytes) {
        return Err(PathError::TooLong);
    }
    Err(PathError::NotImplemented)
}
