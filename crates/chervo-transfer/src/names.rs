//! Идентификаторы и недоверенные имена. Имя из сети лежит в `UntrustedName`: нет `Display`,
//! `Debug` скрыт, нет преобразования в `Path`/`OsStr`. Смысл имени решает этап 15.

use std::fmt;

use chervo_identity::PairId;

use crate::codec::ProtocolError;
use crate::limits::MAX_NAME_BYTES;

/// Случайный (его выбирает отправитель).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferKey {
    pub pair: PairId,
    pub id: TransferId,
}

/// Корректный UTF-8, 1..=1024 байт, без NUL; больше ничего не проверяется.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedName(String);

impl fmt::Debug for UntrustedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UntrustedName(..)")
    }
}

impl UntrustedName {
    /// `BadName`: пусто, длиннее 1024 байт или есть NUL.
    pub fn new(s: &str) -> Result<Self, ProtocolError> {
        if s.is_empty() || s.len() > MAX_NAME_BYTES || s.contains('\0') {
            return Err(ProtocolError::BadName);
        }
        Ok(Self(s.to_owned()))
    }

    /// Имя пришло по проводу или из файла состояния: байты не доверяются.
    pub(crate) fn from_bytes(b: &[u8]) -> Result<Self, ProtocolError> {
        let s = std::str::from_utf8(b).map_err(|_| ProtocolError::BadName)?;
        Self::new(s)
    }

    /// Строка как есть. Использовать только для хранения и кодирования.
    pub fn untrusted_str(&self) -> &str {
        &self.0
    }

    /// Длина в байтах (всегда 1..=1024).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Без Debug: имя не печатается через derive.
#[derive(Clone)]
pub struct OfferedFile {
    pub name: UntrustedName,
    pub size: u64,
}
