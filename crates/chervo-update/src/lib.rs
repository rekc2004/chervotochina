//! Проверка выпусков Червоточины: подпись minisign, манифест, сверка файла. Офлайн.
//!
//! Крейт не ходит в сеть, не пишет файлы, не запускает процессы и не заменяет бинарь
//! (охраняется тестом `src_guard`). Примитивы только из библиотек: Ed25519 `verify_strict`
//! (`ed25519-dalek`), BLAKE2b-512 (`blake2`), SHA-256 (`ring`). Свой здесь только разбор формата.

use std::fmt;

mod b64;
mod keys;
mod manifest;
mod minisig;
mod verify;

pub use keys::{KeyId, KeyRole, KeySet, pubkey_line};
pub use manifest::{Artifact, Manifest, Target, Version};
pub use verify::{
    CheckedArtifact, Freshness, VerifiedManifest, check_artifact, check_artifact_path,
    verify_manifest,
};

pub const MAX_MANIFEST_LEN: usize = 64 * 1024;
pub const MAX_MINISIG_LEN: usize = 4096;
pub const MAX_PUBKEY_LEN: usize = 1024;
pub const MAX_ARTIFACTS: usize = 32;

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    TooLarge,
    MalformedPubkey,
    MalformedSignature,
    UnsupportedAlgorithm,
    NoTrustedKeys,
    KeysetInvalid,
    UnknownKey,
    BadSignature,
    BadGlobalSignature,
    UnsupportedManifestVersion,
    MalformedManifest {
        line: u32,
    },
    NotInManifest,
    WrongTarget {
        expected: Option<Target>,
        found: Target,
    },
    SizeMismatch,
    Downgrade {
        running: Version,
        offered: Version,
    },
    Io(std::io::ErrorKind),
}

/// Текст не содержит байтов входа: только фиксированные слова и номера строк, версии, цели.
impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::TooLarge => f.write_str("файл больше допустимого предела"),
            UpdateError::MalformedPubkey => f.write_str("файл публичного ключа повреждён"),
            UpdateError::MalformedSignature => f.write_str("файл подписи повреждён"),
            UpdateError::UnsupportedAlgorithm => f.write_str("алгоритм подписи не поддерживается"),
            UpdateError::NoTrustedKeys => f.write_str("ключи владельца не вшиты"),
            UpdateError::KeysetInvalid => f.write_str("набор ключей неверен (повтор key_id)"),
            UpdateError::UnknownKey => f.write_str("подпись сделана неизвестным ключом"),
            UpdateError::BadSignature => f.write_str("подпись манифеста неверна"),
            UpdateError::BadGlobalSignature => {
                f.write_str("подпись доверенного комментария неверна")
            }
            UpdateError::UnsupportedManifestVersion => {
                f.write_str("версия формата манифеста не поддерживается")
            }
            UpdateError::MalformedManifest { line } => {
                write!(f, "манифест неверен (строка {line})")
            }
            UpdateError::NotInManifest => f.write_str("файла нет в подписанном манифесте"),
            UpdateError::WrongTarget { expected, found } => match expected {
                Some(e) => write!(f, "файл для другой системы: нужен {e}, в манифесте {found}"),
                None => write!(f, "эта система не из списка, в манифесте {found}"),
            },
            UpdateError::SizeMismatch => f.write_str("размер файла не совпал с манифестом"),
            UpdateError::Downgrade { running, offered } => write!(
                f,
                "откат версии: запущена {running}, предложена {offered} (нужен --allow-downgrade)"
            ),
            UpdateError::Io(kind) => write!(f, "ошибка чтения файла: {kind}"),
        }
    }
}

impl std::error::Error for UpdateError {}
