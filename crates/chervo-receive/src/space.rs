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

use std::path::Path;

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
