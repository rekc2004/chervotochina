//! Метки происхождения принятого файла (спецификация 15, решение 13). Ошибки меток
//! игнорируются: на FAT/exFAT нет потоков, на других ФС нет расширенных атрибутов.
//! Ничего не запускается и не открывается программами.

use std::path::Path;

/// Содержимое потока `Zone.Identifier` (Windows): зона «Интернет».
#[cfg(windows)]
pub(crate) const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";
/// Имя альтернативного потока (наша константа, из входных данных не берётся).
#[cfg(windows)]
const ZONE_STREAM_SUFFIX: &str = ":Zone.Identifier";
#[cfg(target_os = "macos")]
const QUARANTINE_ATTR: &str = "com.apple.quarantine";

/// Метка до жёсткой ссылки: ссылка и переименование переносят поток вместе с файлом.
/// Windows: поток `<temp>:Zone.Identifier`. macOS: атрибут карантина. Иначе: ничего.
pub(crate) fn mark_origin(temp: &Path, motw: bool, quarantine: bool) {
    #[cfg(windows)]
    if motw {
        let mut name = temp.as_os_str().to_os_string();
        name.push(ZONE_STREAM_SUFFIX);
        let _ = std::fs::write(std::path::PathBuf::from(name), ZONE_IDENTIFIER);
    }
    #[cfg(target_os = "macos")]
    if quarantine && let Ok(f) = std::fs::File::open(temp) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let value = format!("0081;{secs:08x};Chervotochina;");
        let _ = rustix::fs::fsetxattr(
            &f,
            QUARANTINE_ATTR,
            value.as_bytes(),
            rustix::fs::XattrFlags::empty(),
        );
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = (temp, motw, quarantine);
    #[cfg(windows)]
    let _ = quarantine;
    #[cfg(target_os = "macos")]
    let _ = motw;
}
