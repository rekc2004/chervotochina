//! Классификация файла по итоговому имени (спецификация 15, решение 14). Один список для
//! всех ОС. Архивы по решению владельца обычные файлы: отдельного класса и предупреждения нет.

use crate::name::{SafeRelPath, fold, split_ext};

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
    "pyw",
    // Рев. 3, F2: запускатели и установщики Windows.
    "appref-ms",
    "msu",
    "ppkg",
    "vsto",
    "xbap",
    "deskthemepack",
    "searchconnector-ms",
    "diagcfg",
    "diagpkg",
    "wsb",
    "pyz",
    "pyzw",
    "dqy",
    "rqy",
    "wll",
    // Рев. 3, F2: macOS и Linux.
    "fileloc",
    "inetloc",
    "flatpak",
    // macOS
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

const DISK_IMAGE: &[&str] = &["iso", "img", "vhd", "vhdx", "dmg", "sparseimage"];

const ACTIVE_DOCUMENT: &[&str] = &[
    "docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm", "html",
    "htm", "mht", "mhtml", "xhtml",
    // Рев. 3, F2: активное содержимое в разметке.
    "svg", "svgz", "xht",
    "shtml", // старый Office (макросы возможны в любом из них)
    "doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps", "ppa", "wbk",
    // Access и OneNote.
    "mdb", "accdb", "accde", "mde", "adp", "ade", "one", "onepkg",
];

/// Каталоги-пакеты: всё внутри считается программой.
const BUNDLE_DIRS: &[&str] = &[
    ".app",
    ".framework",
    ".bundle",
    ".plugin",
    ".kext",
    ".appex",
    // Рев. 3, F2.
    ".prefpane",
    ".saver",
    ".scptd",
    ".workflow",
    ".action",
    ".mpkg",
    ".wdgt",
    ".qlgenerator",
    ".mdimporter",
    ".xpc",
    ".osax",
];

/// Рев. 3 (решения владельца 2026-10-18): расширения заведомо безопасных типов, которые от
/// друга с включённым автоприёмом принимаются сами. Всё остальное, включая неизвестные
/// расширения и файлы без расширения, это вопрос пользователю. Список расширяемый, но
/// пополнять его можно только типами без исполняемого и активного содержимого.
/// Нарочно НЕТ: `bin` (класс Executable), `pt pth ckpt pkl pickle` (формат pickle исполняет код
/// при загрузке), `rtf csv xml json` (двусмысленные), `ts` (TypeScript), `cab`, `psd`.
const KNOWN_INERT: &[&str] = &[
    // фото и RAW
    "jpg",
    "jpeg",
    "jpe",
    "png",
    "gif",
    "webp",
    "bmp",
    "tif",
    "tiff",
    "heic",
    "heif",
    "avif",
    "jxl",
    "dng",
    "cr2",
    "cr3",
    "crw",
    "nef",
    "nrw",
    "arw",
    "srf",
    "sr2",
    "raf",
    "orf",
    "rw2",
    "pef",
    "raw",
    "rwl",
    "3fr",
    "erf",
    "kdc",
    "mrw",
    "mef",
    "dcr",
    "x3f", // видео
    "mp4",
    "m4v",
    "mov",
    "avi",
    "mkv",
    "webm",
    "wmv",
    "flv",
    "mpg",
    "mpeg",
    "mts",
    "m2ts",
    "3gp",
    "mxf",
    "braw",
    "r3d",
    "ogv", // аудио
    "mp3",
    "wav",
    "flac",
    "m4a",
    "aac",
    "ogg",
    "oga",
    "opus",
    "wma",
    "aif",
    "aiff",
    "alac",
    "mid",
    "midi", // документы без активного содержимого
    "pdf",
    "txt",
    "md",
    "srt", // архивы (решение владельца: обычные файлы)
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "zst", // файлы моделей
    "gguf",
    "safetensors",
];

/// Расширения, под которые маскируют программу (`photo.jpg.exe`).
const DECOYS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "heic", "webp", "bmp", "tif", "tiff", "mp4", "mov", "avi", "mkv",
    "mp3", "wav", "flac", "m4a", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
    "zip",
];

/// Суффиксы, которые только сжимают один файл и не являются контейнером (Рев. 5, решение
/// владельца 2026-10-18): `x.iso.gz` это образ диска, а не «архив». Сравниваются после `fold`
/// (`.Z` даёт `z`). Контейнеры (zip 7z rar tar tgz) сюда НЕ входят: они остаются обычными
/// файлами (решение владельца 2026-10-17).
const COMPRESSION_ONLY: &[&str] = &["gz", "xz", "bz2", "zst", "lz", "lz4", "z"];

/// Имя без внешних суффиксов сжатия, если под ними есть собственное расширение:
/// `x.iso.gz` даёт `x.iso`, `x.exe.xz` даёт `x.exe`, `a.tar.gz` даёт `a.tar`, `x.img.zst.gz`
/// даёт `x.img`. Без внутреннего расширения (`x.gz`) имя остаётся как есть. Каждый шаг
/// укорачивает имя, поэтому цикл конечен.
///
/// Рев. 6, M1: основа перед снятым суффиксом очищается от хвостовых `.` и пробелов, как это
/// делает Windows (`x.exe..gz` после распаковки это `x.exe.` то есть `x.exe`). Второе значение
/// истинно, если такая очистка что-то убрала: имя «замаскировано» и в безопасный тип не входит.
fn peel_compression(last: &str) -> (&str, bool) {
    let mut cur = last;
    let mut trimmed = false;
    loop {
        let (stem, ext) = split_ext(cur);
        let Some(e) = ext.strip_prefix('.') else {
            return (cur, trimmed);
        };
        if !COMPRESSION_ONLY.contains(&fold(e).as_str()) {
            return (cur, trimmed);
        }
        let clean = stem.trim_end_matches(['.', ' ']);
        trimmed |= clean.len() != stem.len();
        if split_ext(clean).1.is_empty() {
            return (cur, trimmed);
        }
        cur = clean;
    }
}

fn effective_name(last: &str) -> &str {
    peel_compression(last).0
}

/// Из суффикса сжатия вычищены хвостовые `.` или пробелы основы (Рев. 6, M1).
fn has_trimmed_stem(last: &str) -> bool {
    peel_compression(last).1
}

/// Расширение после `fold` (Рев. 3, F3): `ſ` даёт `s`, `ı` даёт `i`, знак Кельвина `k`; так
/// `x.vbſ` попадает в тот же класс, что `x.vbs`. У сжатого одиночного файла берётся внутреннее
/// расширение (Рев. 5). `None`, если расширения нет.
fn folded_ext(comp: &str) -> Option<String> {
    let (_, ext) = split_ext(effective_name(comp));
    Some(fold(ext.strip_prefix('.')?))
}

/// Подозрительное расширение последнего компонента: не-ASCII символ (после `fold` оно может
/// совпасть с расширением программы, оболочка ОС этого может не показывать) или хвостовые `.`
/// и пробелы перед суффиксом сжатия (Рев. 6, M1). У сжатого одиночного файла проверяется и
/// внутреннее расширение.
pub(crate) fn has_suspicious_ext(p: &SafeRelPath) -> bool {
    p.components().last().is_some_and(|last| {
        !split_ext(last).1.is_ascii()
            || !split_ext(effective_name(last)).1.is_ascii()
            || has_trimmed_stem(last)
    })
}

/// Файл заведомо безопасного типа (решения владельца 2026-10-18): класс обычный, расширение
/// ASCII и входит в список `KNOWN_INERT`. Только такие файлы принимаются без вопроса. Сжатый
/// одиночный файл (`x.jpg.gz`) оценивается по внутреннему расширению (Рев. 5): внутри
/// неизвестный тип (`x.foo.gz`) это вопрос.
pub fn is_known_inert(p: &SafeRelPath) -> bool {
    if classify(p).class != FileClass::Ordinary {
        return false;
    }
    let Some(last) = p.components().last() else {
        return false;
    };
    if has_trimmed_stem(last) {
        return false;
    }
    let (_, ext) = split_ext(effective_name(last));
    if !ext.is_ascii() {
        return false;
    }
    folded_ext(last).is_some_and(|e| KNOWN_INERT.contains(&e.as_str()))
}

pub fn classify(p: &SafeRelPath) -> TypeInfo {
    let comps = p.components();
    let Some((last, dirs)) = comps.split_last() else {
        return TypeInfo {
            class: FileClass::Ordinary,
            deceptive: false,
        };
    };
    let ext = folded_ext(last);
    let in_bundle = dirs.iter().any(|d| {
        let lower = fold(d);
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
        deceptive: class == FileClass::Executable && has_decoy(effective_name(last)),
    }
}

/// Предыдущий сегмент через `.` (без пробелов по краям) входит в список приманок.
fn has_decoy(last: &str) -> bool {
    let (stem, _) = split_ext(last);
    stem.rsplit_once('.').is_some_and(|(_, seg)| {
        let seg = fold(seg.trim_matches(' '));
        DECOYS.contains(&seg.as_str())
    })
}
