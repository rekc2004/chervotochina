//! Набор доверенных публичных ключей: вшитые в бинарь и собранные из файлов (тесты, fuzz).

use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::{UpdateError, minisig};

/// Основной ключ владельца вшит файлом `keys/primary.pub` (формат minisign).
const PRIMARY_PUB: &[u8] = include_bytes!("../keys/primary.pub");
/// Запасной ключ (хранится офлайн) вшит файлом `keys/backup.pub`.
const BACKUP_PUB: &[u8] = include_bytes!("../keys/backup.pub");

/// Идентификатор ключа: 8 байт из файла minisign.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyId(pub [u8; 8]);

/// Печатается как в комментарии minisign: 16 заглавных hex-цифр числа `u64` (little-endian).
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", u64::from_le_bytes(self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyRole {
    Primary,
    Backup,
}

/// Строка публичного ключа в формате minisign (`RWQ...`, 56 символов) для сверки с README.
pub fn pubkey_line(id: KeyId, pk: &[u8; 32]) -> String {
    minisig::pubkey_line(id, pk)
}

pub struct KeySet {
    keys: Vec<(KeyRole, KeyId, VerifyingKey)>,
}

impl KeySet {
    /// Ключи, вшитые в бинарь. Пока файлы пусты (владелец ещё не создал ключи), `NoTrustedKeys`.
    pub fn embedded() -> Result<KeySet, UpdateError> {
        let mut files: Vec<(KeyRole, &[u8])> = Vec::new();
        if !PRIMARY_PUB.is_empty() {
            files.push((KeyRole::Primary, PRIMARY_PUB));
        }
        if !BACKUP_PUB.is_empty() {
            files.push((KeyRole::Backup, BACKUP_PUB));
        }
        KeySet::from_pubkey_files(&files)
    }

    /// Набор из файлов публичных ключей minisign. Пусто: `NoTrustedKeys`; повтор `key_id`:
    /// `KeysetInvalid`; ошибка разбора любого файла отвергает весь набор.
    pub fn from_pubkey_files(files: &[(KeyRole, &[u8])]) -> Result<KeySet, UpdateError> {
        if files.is_empty() {
            return Err(UpdateError::NoTrustedKeys);
        }
        let mut keys: Vec<(KeyRole, KeyId, VerifyingKey)> = Vec::with_capacity(files.len());
        for (role, bytes) in files {
            let p = minisig::parse_pubkey(bytes)?;
            if keys.iter().any(|(_, id, _)| *id == p.key_id) {
                return Err(UpdateError::KeysetInvalid);
            }
            keys.push((*role, p.key_id, p.key));
        }
        Ok(KeySet { keys })
    }

    /// Роль, идентификатор и байты публичного ключа каждой записи набора.
    pub fn list(&self) -> Vec<(KeyRole, KeyId, [u8; 32])> {
        self.keys
            .iter()
            .map(|(role, id, key)| (*role, *id, key.to_bytes()))
            .collect()
    }

    pub(crate) fn find(&self, id: KeyId) -> Option<(KeyRole, &VerifyingKey)> {
        self.keys
            .iter()
            .find(|(_, k, _)| *k == id)
            .map(|(role, _, key)| (*role, key))
    }
}
