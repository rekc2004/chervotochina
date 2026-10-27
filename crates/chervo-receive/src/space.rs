//! Свободное место на томе папки приёма (Рев. 3, решение владельца 2026-10-18: единственная
//! защита автоприёма от переполнения диска). Без `unsafe` в нашем коде: системный вызов делает
//! крейт `fs4` 1.1.0 (Рев. 4, решение владельца 2026-10-18), одинаково на всех ОС.
//!
//! Что берём из `fs4::statvfs` (прочитано в исходнике fs4 1.1.0):
//! * Windows: `available_space` это «свободно для текущего пользователя»
//!   (`lpFreeBytesAvailableToCaller` из `GetDiskFreeSpaceExW`, учитывает квоты), не общий
//!   остаток тома; `total_space` это объём тома (`GetDiskFreeSpaceW`: кластеры * размер кластера).
//! * Unix: `available_space` это `f_bavail * f_frsize` (доступно непривилегированному
//!   пользователю), не `f_bfree`; `total_space` это `f_blocks * f_frsize`.
//!
//! Неизвестное место никогда не считается достаточным: ошибка системного вызова даёт `None`.

use std::path::{Path, PathBuf};

use chervo_transfer::InboundReservation;

/// Объём тома и доступное нам место, в байтах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

impl DiskSpace {
    /// Хватит ли места: после приёма `incoming` байт на томе должно остаться не меньше
    /// `min_free_percent` процентов его объёма. Значение больше 100 считается за 100.
    pub fn allows(&self, incoming: u64, min_free_percent: u8) -> bool {
        let pct = u128::from(min_free_percent.min(100));
        let keep = u128::from(self.total_bytes) * pct / 100;
        u128::from(self.available_bytes)
            .checked_sub(u128::from(incoming))
            .is_some_and(|left| left >= keep)
    }
}

/// Место на томе, где лежит `path`; `None`, если узнать нельзя.
#[cfg(any(unix, windows))]
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    let s = fs4::statvfs(path).ok()?;
    Some(DiskSpace {
        total_bytes: s.total_space(),
        available_bytes: s.available_space(),
    })
}

/// Прочие ОС: способа нет, место неизвестно.
#[cfg(not(any(unix, windows)))]
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    let _ = path;
    None
}

impl DiskSpace {
    /// Сколько свободного места нужно, чтобы принять `incoming` байт и оставить запас
    /// `min_free_percent` процентов объёма тома (значение больше 100 считается за 100).
    pub fn needed(&self, incoming: u64, min_free_percent: u8) -> u64 {
        let pct = u128::from(min_free_percent.min(100));
        let keep = u128::from(self.total_bytes) * pct / 100;
        u64::try_from(u128::from(incoming) + keep).unwrap_or(u64::MAX)
    }
}

/// Не хватает места для предложения (Рев. 5, решение владельца 2026-10-18). `needed` это размер
/// предложения плюс запас `min_free_percent`, `available` это свободное место тома за вычетом
/// ещё не полученных байтов остальных приёмов на этом томе. `Debug` без пути.
#[derive(Clone, PartialEq, Eq)]
pub struct SpaceShortfall {
    pub needed: u64,
    pub available: u64,
    /// Папка приёма, для которой посчитано.
    pub root: PathBuf,
}

impl std::fmt::Debug for SpaceShortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceShortfall")
            .field("needed", &self.needed)
            .field("available", &self.available)
            .finish_non_exhaustive()
    }
}

/// Итог проверки места для одного предложения в одной папке приёма.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceCheck {
    Fits,
    /// Место узнать не удалось: автоприём не включается, обычный вопрос.
    Unknown,
    Short(SpaceShortfall),
}

pub(crate) type SpaceProbe = dyn Fn(&Path) -> Option<DiskSpace> + Send + Sync;

/// Хватает ли места на томе `root` для `incoming` байт, если остальным принятым и идущим
/// приёмам (`inbound`) на этом же томе ещё нужны их невыполненные байты. Приёмы на других
/// томах не считаются; если том приёма определить нельзя, он считается тем же (запас в
/// безопасную сторону).
pub(crate) fn check_space(
    probe: &SpaceProbe,
    root: &Path,
    incoming: u64,
    min_free_percent: u8,
    inbound: &[InboundReservation],
) -> SpaceCheck {
    let Some(s) = probe(root) else {
        return SpaceCheck::Unknown;
    };
    let reserved = inbound
        .iter()
        .filter(|r| same_volume(&r.partial_dir, root))
        .fold(0u64, |acc, r| acc.saturating_add(r.outstanding));
    let free = DiskSpace {
        total_bytes: s.total_bytes,
        available_bytes: s.available_bytes.saturating_sub(reserved),
    };
    if free.allows(incoming, min_free_percent) {
        SpaceCheck::Fits
    } else {
        SpaceCheck::Short(SpaceShortfall {
            needed: free.needed(incoming, min_free_percent),
            available: free.available_bytes,
            root: root.to_path_buf(),
        })
    }
}

/// Лежат ли `a` и `b` на одном томе. Неизвестно: «да» (лишний резерв безопаснее недостающего).
/// Unix: одинаковое устройство. Windows: одинаковый диск или общий ресурс в начале
/// канонического пути (точка монтирования тома внутри диска считается тем же диском: запас
/// получается больше, не меньше). Прочие ОС: «да».
pub(crate) fn same_volume(a: &Path, b: &Path) -> bool {
    match (volume_key(a), volume_key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

#[cfg(unix)]
fn volume_key(p: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.dev().to_string())
}

#[cfg(windows)]
fn volume_key(p: &Path) -> Option<String> {
    prefix_key(&std::fs::canonicalize(p).ok()?)
}

#[cfg(not(any(unix, windows)))]
fn volume_key(p: &Path) -> Option<String> {
    let _ = p;
    None
}

/// Диск или общий ресурс в начале пути Windows, без различия регистра и вида префикса
/// (`C:\`, `\\?\C:\`, `\\srv\share`, `\\?\UNC\srv\share`).
#[cfg(windows)]
pub(crate) fn prefix_key(p: &Path) -> Option<String> {
    use std::path::{Component, Prefix};
    let Some(Component::Prefix(pre)) = p.components().next() else {
        return None;
    };
    Some(match pre.kind() {
        Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
            format!("disk:{}", char::from(d.to_ascii_uppercase()))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
            "unc:{}\\{}",
            server.to_string_lossy().to_lowercase(),
            share.to_string_lossy().to_lowercase()
        ),
        Prefix::DeviceNS(name) | Prefix::Verbatim(name) => {
            format!("ns:{}", name.to_string_lossy().to_lowercase())
        }
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::prefix_key;
    use std::path::Path;

    #[test]
    fn windows_prefixes_compare_by_disk_or_share() {
        let k = |s: &str| prefix_key(Path::new(s));
        assert_eq!(k(r"C:\a\b"), k(r"c:\x"));
        assert_eq!(k(r"C:\a"), k(r"\\?\C:\x\y"));
        assert_ne!(k(r"C:\a"), k(r"D:\a"));
        assert_eq!(k(r"\\srv\Share\a"), k(r"\\?\UNC\SRV\share\b"));
        assert_ne!(k(r"\\srv\one\a"), k(r"\\srv\two\a"));
        assert_ne!(k(r"C:\a"), k(r"\\srv\C\a"));
    }
}
