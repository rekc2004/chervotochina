//! Файл состояния получателя и список хэшей `<i>.hashes`. С диска не доверяется ничего:
//! длина ограничена, есть контрольная сумма, раскладка пересчитывается по размеру файла,
//! список хэшей сверяется с корнем. Состояние лишь говорит, какие блоки перечитать.
//! Здесь только разбор и сборка байт; пути и ввод-вывод в `paths.rs`.

use std::fmt;

use chervo_identity::PairId;

use crate::codec::{ProtocolError, Rd};
use crate::hash::{BlockHash, FileRoot, file_root, sha256};
use crate::layout::{Layout, bitmap_len, layout};
use crate::limits::{
    ENTRY_OVERHEAD, MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_INPROGRESS, MAX_NAME_BYTES,
    MAX_OFFER_BYTES, MAX_OFFER_TOTAL, MAX_STATE_LEN,
};
use crate::names::{TransferId, UntrustedName};

const MAGIC: &[u8; 8] = b"CHVXFR1\n";
const TRAILER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// Длина больше `MAX_STATE_LEN` (проверяется до разбора).
    TooLong,
    Truncated,
    BadMagic,
    BadChecksum,
    /// Поле вне границ, несовпадение с раскладкой, лишние байты и тому подобное.
    Malformed,
    /// Список хэшей не воспроизводит корень.
    HashMismatch,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooLong => "state too long",
            Self::Truncated => "state truncated",
            Self::BadMagic => "bad state magic",
            Self::BadChecksum => "bad state checksum",
            Self::Malformed => "malformed state",
            Self::HashMismatch => "hash list does not match root",
        };
        f.write_str(text)
    }
}

impl std::error::Error for StateError {}

/// Ход получения одного файла: раскладка, подтверждённый корень и битовая карта готовых блоков
/// (`ceil(count/8)` байт, неиспользуемые старшие биты нулевые).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) layout: Layout,
    pub(crate) root: FileRoot,
    pub(crate) bitmap: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum FileStatus {
    Waiting,
    InProgress(Progress),
    Verified(FileRoot),
    Placed(FileRoot),
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StateFile {
    pub(crate) name: UntrustedName,
    pub(crate) size: u64,
    pub(crate) status: FileStatus,
}

/// Состояние одной передачи на стороне получателя. Поля видны только крейту; снаружи
/// (для fuzz) доступны `decode_state` и `encode_state`.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RecvState {
    pub(crate) pair: PairId,
    pub(crate) id: TransferId,
    pub(crate) created_unix: u64,
    pub(crate) last_progress_unix: u64,
    pub(crate) total_size: u64,
    pub(crate) files: Vec<StateFile>,
}

impl fmt::Debug for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecvState(..)")
    }
}

impl RecvState {
    /// Прогресс файла сброшен: файл снова ждёт (манифест будет запрошен заново).
    /// `false`: такого файла нет или он не в процессе.
    pub fn clear_progress(&mut self, index: usize) -> bool {
        match self.files.get_mut(index) {
            Some(f) if matches!(f.status, FileStatus::InProgress(_)) => {
                f.status = FileStatus::Waiting;
                true
            }
            _ => false,
        }
    }
}

const S_WAITING: u8 = 0;
const S_IN_PROGRESS: u8 = 1;
const S_VERIFIED: u8 = 2;
const S_PLACED: u8 = 3;
const S_FAILED: u8 = 4;

/// Имя подкаталога состояния: 32 hex-цифры, первые 16 байт `SHA256(pair || id)`.
pub fn state_dir_name(pair: &PairId, id: &TransferId) -> String {
    let digest = sha256(&[pair.as_bytes(), &id.0]);
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Сборка байт файла состояния с контрольной суммой SHA-256 в конце.
#[doc(hidden)]
pub fn encode_state(s: &RecvState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(s.pair.as_bytes());
    out.extend_from_slice(&s.id.0);
    out.extend_from_slice(&s.created_unix.to_be_bytes());
    out.extend_from_slice(&s.last_progress_unix.to_be_bytes());
    let count = u32::try_from(s.files.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&s.total_size.to_be_bytes());
    for f in &s.files {
        out.extend_from_slice(&f.size.to_be_bytes());
        let name = f.name.untrusted_str().as_bytes();
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&name_len.to_be_bytes());
        out.extend_from_slice(name);
        match &f.status {
            FileStatus::Waiting => out.push(S_WAITING),
            FileStatus::InProgress(p) => {
                out.push(S_IN_PROGRESS);
                out.extend_from_slice(&p.layout.block_size.to_be_bytes());
                out.extend_from_slice(&p.layout.block_count.to_be_bytes());
                out.extend_from_slice(&p.root.0);
                out.extend_from_slice(&p.bitmap);
            }
            FileStatus::Verified(root) => {
                out.push(S_VERIFIED);
                out.extend_from_slice(&root.0);
            }
            FileStatus::Placed(root) => {
                out.push(S_PLACED);
                out.extend_from_slice(&root.0);
            }
            FileStatus::Failed => out.push(S_FAILED),
        }
    }
    let sum = sha256(&[&out]);
    out.extend_from_slice(&sum);
    out
}

fn m<T>(r: Result<T, ProtocolError>) -> Result<T, StateError> {
    r.map_err(|_| StateError::Malformed)
}

/// Разбор файла состояния. Любое отклонение это ошибка; ничего из файла не принимается на веру.
#[doc(hidden)]
pub fn decode_state(b: &[u8]) -> Result<RecvState, StateError> {
    if u64::try_from(b.len()).map_or(true, |n| n > MAX_STATE_LEN) {
        return Err(StateError::TooLong);
    }
    let body_len = b
        .len()
        .checked_sub(TRAILER)
        .filter(|n| *n >= MAGIC.len())
        .ok_or(StateError::Truncated)?;
    let (body, trailer) = b.split_at_checked(body_len).ok_or(StateError::Truncated)?;
    if sha256(&[body]).as_slice() != trailer {
        return Err(StateError::BadChecksum);
    }
    let mut r = Rd::new(body);
    if m(r.arr::<8>())? != *MAGIC {
        return Err(StateError::BadMagic);
    }
    let pair = PairId::from_bytes(m(r.arr::<16>())?);
    let id = TransferId(m(r.arr::<16>())?);
    let created_unix = m(r.u64())?;
    let last_progress_unix = m(r.u64())?;
    let file_count = m(r.u32())?;
    let total_size = m(r.u64())?;
    if file_count == 0 || file_count > MAX_FILES_PER_OFFER || total_size > MAX_OFFER_TOTAL {
        return Err(StateError::Malformed);
    }
    // Запись занимает не меньше 8 + 2 + 1 + 1 байт.
    let cap = usize::try_from(file_count)
        .unwrap_or(usize::MAX)
        .min(r.len() / 12);
    let mut files = Vec::with_capacity(cap);
    let mut sum = 0u64;
    let mut name_bytes = 0u64;
    let mut in_progress = 0usize;
    for _ in 0..file_count {
        let size = m(r.u64())?;
        if size > MAX_FILE_SIZE {
            return Err(StateError::Malformed);
        }
        let name_len = usize::from(m(r.u16())?);
        if name_len == 0 || name_len > MAX_NAME_BYTES {
            return Err(StateError::Malformed);
        }
        let name = m(UntrustedName::from_bytes(m(r.take(name_len))?))?;
        sum = sum.checked_add(size).ok_or(StateError::Malformed)?;
        name_bytes = name_bytes
            .checked_add(ENTRY_OVERHEAD)
            .and_then(|v| v.checked_add(u64::try_from(name_len).ok()?))
            .ok_or(StateError::Malformed)?;
        if name_bytes > u64::from(MAX_OFFER_BYTES) {
            return Err(StateError::Malformed);
        }
        let status = match m(r.u8())? {
            S_WAITING => FileStatus::Waiting,
            S_IN_PROGRESS => {
                in_progress += 1;
                if in_progress > MAX_INPROGRESS {
                    return Err(StateError::Malformed);
                }
                let block_size = m(r.u32())?;
                let block_count = m(r.u32())?;
                let canon = m(layout(size))?;
                if canon.block_size != block_size || canon.block_count != block_count {
                    return Err(StateError::Malformed);
                }
                let root = FileRoot(m(r.arr::<32>())?);
                let bitmap = m(r.take(bitmap_len(block_count)))?.to_vec();
                if !high_bits_clear(&bitmap, block_count) {
                    return Err(StateError::Malformed);
                }
                FileStatus::InProgress(Progress {
                    layout: canon,
                    root,
                    bitmap,
                })
            }
            S_VERIFIED => FileStatus::Verified(FileRoot(m(r.arr::<32>())?)),
            S_PLACED => FileStatus::Placed(FileRoot(m(r.arr::<32>())?)),
            S_FAILED => FileStatus::Failed,
            _ => return Err(StateError::Malformed),
        };
        files.push(StateFile { name, size, status });
    }
    m(r.end())?;
    if sum != total_size {
        return Err(StateError::Malformed);
    }
    Ok(RecvState {
        pair,
        id,
        created_unix,
        last_progress_unix,
        total_size,
        files,
    })
}

/// Биты за `count` в последнем байте карты нулевые.
fn high_bits_clear(bitmap: &[u8], count: u32) -> bool {
    let used = count % 8;
    if used == 0 {
        return true;
    }
    match bitmap.last() {
        Some(last) => last >> used == 0,
        None => true,
    }
}

/// Содержимое `<i>.hashes`: хэши блоков подряд.
pub fn encode_hashes(leaves: &[BlockHash]) -> Vec<u8> {
    let mut out = Vec::with_capacity(leaves.len().saturating_mul(32));
    for l in leaves {
        out.extend_from_slice(&l.0);
    }
    out
}

/// Разбор `<i>.hashes`: длина ровно `block_count * 32`, и хэши обязаны воспроизвести `root`.
/// Иначе прогресс файла сбрасывается (`RecvState::clear_progress`), файл начнётся заново.
pub fn parse_hashes(
    raw: &[u8],
    size: u64,
    l: Layout,
    root: &FileRoot,
) -> Result<Vec<BlockHash>, StateError> {
    let canon = layout(size).map_err(|_| StateError::Malformed)?;
    if canon != l {
        return Err(StateError::Malformed);
    }
    let want = usize::try_from(l.block_count)
        .ok()
        .and_then(|n| n.checked_mul(32))
        .ok_or(StateError::Malformed)?;
    if raw.len() != want {
        return Err(StateError::Malformed);
    }
    // Длина кратна 32 (проверено выше), остатка нет.
    let (chunks, _) = raw.as_chunks::<32>();
    let leaves: Vec<BlockHash> = chunks.iter().map(|c| BlockHash(*c)).collect();
    match file_root(size, l, &leaves) {
        Ok(got) if got == *root => Ok(leaves),
        _ => Err(StateError::HashMismatch),
    }
}
