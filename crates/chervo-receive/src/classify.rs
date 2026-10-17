//! Классификация файла по итоговому имени (спецификация 15, решение 14). Один список для
//! всех ОС. Архивы по решению владельца обычные файлы: отдельного класса и предупреждения нет.

use crate::name::{SafeRelPath, split_ext};

/// По возрастанию опасности; старший класс побеждает.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileClass {
    Ordinary,
    ActiveDocument,
    DiskImage,
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeInfo {
    pub class: FileClass,
    pub deceptive: bool,
}

const EXECUTABLE: &[&str] = &[
    "exe",
    "com",
    "scr",
    "pif",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "psd1",
    "ps1xml",
    "psc1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "wsc",
    "hta",
    "msi",
    "msp",
    "mst",
    "msix",
    "msixbundle",
    "appx",
    "appxbundle",
    "appinstaller",
    "application",
    "gadget",
    "cpl",
    "msc",
    "dll",
    "sys",
    "drv",
    "ocx",
    "inf",
    "reg",
    "lnk",
    "url",
    "scf",
    "chm",
    "jar",
    "jnlp",
    "xll",
    "library-ms",
    "search-ms",
    "settingcontent-ms",
    "diagcab",
    "theme",
    "themepack",
    "rdp",
    "iqy",
    "slk",
    "website",
    "pyw", // macOS
    "app",
    "command",
    "tool",
    "pkg",
    "mpkg",
    "scpt",
    "scptd",
    "applescript",
    "workflow",
    "action",
    "terminal",
    "kext",
    "prefpane",
    "dylib",
    "osax",
    "saver",
    "webloc", // Unix
    "sh",
    "bash",
    "zsh",
    "csh",
    "ksh",
    "fish",
    "run",
    "bin",
    "desktop",
    "appimage",
    "deb",
    "rpm",
    "snap",
    "flatpakref",
    "py",
    "pyc",
    "pl",
    "rb",
    "php",
];

const DISK_IMAGE: &[&str] = &["iso", "img", "vhd", "vhdx", "dmg"];

const ACTIVE_DOCUMENT: &[&str] = &[
    "docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm", "html",
    "htm", "mht", "mhtml", "xhtml",
];

/// Каталоги-пакеты: всё внутри считается программой.
const BUNDLE_DIRS: &[&str] = &[
    ".app",
    ".framework",
    ".bundle",
    ".plugin",
    ".kext",
    ".appex",
];

/// Расширения, под которые маскируют программу (`photo.jpg.exe`).
const DECOYS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "heic", "webp", "bmp", "tif", "tiff", "mp4", "mov", "avi", "mkv",
    "mp3", "wav", "flac", "m4a", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
    "zip",
];

/// Расширение в нижнем регистре; `None`, если его нет или оно не ASCII.
fn ascii_ext(comp: &str) -> Option<String> {
    let (_, ext) = split_ext(comp);
    let e = ext.strip_prefix('.')?;
    e.is_ascii().then(|| e.to_ascii_lowercase())
}

pub fn classify(p: &SafeRelPath) -> TypeInfo {
    let comps = p.components();
    let Some((last, dirs)) = comps.split_last() else {
        return TypeInfo {
            class: FileClass::Ordinary,
            deceptive: false,
        };
    };
    let ext = ascii_ext(last);
    let in_bundle = dirs.iter().any(|d| {
        let lower = d.to_ascii_lowercase();
        BUNDLE_DIRS.iter().any(|b| lower.ends_with(b))
    });
    let class = match ext.as_deref() {
        _ if in_bundle => FileClass::Executable,
        Some(e) if EXECUTABLE.contains(&e) => FileClass::Executable,
        Some(e) if DISK_IMAGE.contains(&e) => FileClass::DiskImage,
        Some(e) if ACTIVE_DOCUMENT.contains(&e) => FileClass::ActiveDocument,
        _ => FileClass::Ordinary,
    };
    TypeInfo {
        class,
        deceptive: class == FileClass::Executable && has_decoy(last),
    }
}

/// Предыдущий сегмент через `.` (без пробелов по краям) входит в список приманок.
fn has_decoy(last: &str) -> bool {
    let (stem, _) = split_ext(last);
    stem.rsplit_once('.').is_some_and(|(_, seg)| {
        let seg = seg.trim_matches(' ').to_ascii_lowercase();
        DECOYS.contains(&seg.as_str())
    })
}
