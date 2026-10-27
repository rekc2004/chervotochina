//! Лимиты приёма и ошибки разбора имён.

use std::fmt;

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
            // Рев. 3: объёма как предела нет (решение владельца); остаётся предел протокола этапа 14.
            max_total_bytes: u64::MAX,
        }
    }
}

impl ReceiveLimits {
    /// Все поля больше нуля; `max_name_bytes <= 255`, `max_path_bytes <= 1024` (предел
    /// протокола), `max_files <= 10_000`.
    pub fn validate(&self) -> Result<(), PathError> {
        let ok = self.max_files > 0
            && self.max_files <= 10_000
            && self.max_depth > 0
            && self.max_name_bytes > 0
            && self.max_name_bytes <= 255
            && self.max_path_bytes > 0
            && self.max_path_bytes <= 1024
            && self.max_total_bytes > 0;
        if ok {
            Ok(())
        } else {
            Err(PathError::BadLimits)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    Empty,
    TooLong,
    Control,
    Backslash,
    Absolute,
    Drive,
    TooDeep,
    EmptyComponent,
    DotComponent,
    TooManyFiles,
    TooLarge,
    BadLimits,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Empty => "empty path",
            Self::TooLong => "path too long",
            Self::Control => "control character in path",
            Self::Backslash => "backslash in path",
            Self::Absolute => "absolute path",
            Self::Drive => "drive prefix in path",
            Self::TooDeep => "path too deep",
            Self::EmptyComponent => "empty path component",
            Self::DotComponent => "dot component in path",
            Self::TooManyFiles => "too many files",
            Self::TooLarge => "offer too large",
            Self::BadLimits => "invalid limits",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PathError {}
