use std::fmt;

use crate::{ACCOUNT_PREFIX, IdentityError};

/// Временный несекретный идентификатор-заглушка для других крейтов. Не публичный ключ:
/// байты не проверяются. Не используется API ключей пар. Будет заменён или удалён
/// по решению U10b (этапы 9/11).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceId(..)")
    }
}

/// Идентификатор пары друзей: 16 случайных байт, локальный и несекретный.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairId([u8; 16]);

impl PairId {
    /// Новый случайный идентификатор из CSPRNG ОС.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(|_| IdentityError::RandomUnavailable)?;
        Ok(Self(b))
    }

    /// Любые 16 байт допустимы (значение берётся из списка друзей).
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Имя записи в хранилище ОС: `pair-v1-` и 32 строчные hex-цифры.
    pub fn account_name(&self) -> String {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        format!("{ACCOUNT_PREFIX}{hex}")
    }
}

impl fmt::Debug for PairId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairId(..)")
    }
}
