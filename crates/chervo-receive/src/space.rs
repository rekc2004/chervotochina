//! Свободное место на томе папки приёма (Рев. 3, решение владельца 2026-10-18: единственная
//! защита автоприёма от переполнения диска). Без `unsafe`.
//!
//! * Unix (Linux, macOS): `statvfs` через безопасный API `rustix` (крейт уже в `Cargo.lock`).
//! * Windows: безопасного способа нет. В std нет такой функции, а `GetDiskFreeSpaceExW` из
//!   `windows-sys` это `unsafe fn` (в проекте `unsafe_code = "forbid"`). Поэтому `disk_space`
//!   даёт `None`, и автоприём на Windows не срабатывает (всегда вопрос) до решения владельца
//!   (см. спецификацию 15, Рев. 3). Неизвестное место никогда не считается достаточным.

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
#[cfg(unix)]
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    let s = rustix::fs::statvfs(path).ok()?;
    let unit = if s.f_frsize != 0 {
        s.f_frsize
    } else {
        s.f_bsize
    };
    Some(DiskSpace {
        total_bytes: s.f_blocks.checked_mul(unit)?,
        available_bytes: s.f_bavail.checked_mul(unit)?,
    })
}

/// Windows и прочие ОС: безопасного способа без `unsafe` нет.
#[cfg(not(unix))]
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    let _ = path;
    None
}
