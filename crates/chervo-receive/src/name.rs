//! Переносимый санитайзер имён (спецификация 15, решения 5 и 12). Чистые функции, без файловой
//! системы: одинаковый результат на Windows, macOS и Linux.
//!
//! Порядок: проверки H1-H7 (отказ, без правок), затем для каждого компонента NFC и правила
//! R1-R6. NFC стоит перед R1 (а не после R6, как в черновике спецификации): иначе NFC мог бы
//! создать зарезервированное имя (U+212A KELVIN SIGN даёт `K`, то есть `CLOCK$`) или удлинить
//! имя за предел после усечения. Все шаги после NFC сохраняют NFC и идемпотентность.

use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

use crate::limits::{PathError, ReceiveLimits};

/// Предел длины компонента для `is_portable_component` и `portable_component`.
const NAME_MAX: usize = 255;
/// Предел длины пути отправителя (предел протокола).
const PATH_MAX: usize = 1024;
/// Длина расширения не больше этого числа байт после точки.
const EXT_MAX: usize = 32;

/// Безопасный относительный путь: компоненты проходят `is_portable_component`.
#[derive(Clone, PartialEq, Eq)]
pub struct SafeRelPath {
    parts: Vec<String>,
}

impl std::fmt::Debug for SafeRelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SafeRelPath(..)")
    }
}

impl SafeRelPath {
    pub(crate) fn from_parts(parts: Vec<String>) -> Self {
        Self { parts }
    }

    pub fn components(&self) -> &[String] {
        &self.parts
    }

    /// Компоненты через `/`.
    pub fn display(&self) -> String {
        self.parts.join("/")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NameFlags {
    pub changed: bool,
    pub suspicious: bool,
    pub renamed_in_offer: bool,
    pub long_path: bool,
}

fn is_control(c: char) -> bool {
    c <= '\u{1F}' || c == '\u{7F}' || ('\u{80}'..='\u{9F}').contains(&c)
}

/// R1, первая часть: недопустимые символы Windows и похожие на разделители.
fn is_map_char(c: char) -> bool {
    matches!(
        c,
        '<' | '>'
            | ':'
            | '"'
            | '|'
            | '?'
            | '*'
            | '\u{2215}'
            | '\u{2044}'
            | '\u{FF0F}'
            | '\u{29F8}'
            | '\u{FF3C}'
            | '\u{29F5}'
            | '\u{29F9}'
            | '\u{FE68}'
            | '\u{FF1A}'
            | '\u{2236}'
            | '\u{A789}'
            | '\u{FE55}'
            | '\u{FE13}'
    )
}

/// R1, вторая часть: невидимые и управляющие направлением символы.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Исключение R1: ZWJ и селекторы вариантов остаются после эмодзи. `prev` это предыдущий
/// символ результата (после замены), поэтому правило устойчиво при повторном запуске.
fn keeps_emoji_joiner(c: char, prev: Option<char>) -> bool {
    matches!(c, '\u{200D}' | '\u{FE0E}' | '\u{FE0F}')
        && prev.is_some_and(|p| ('\u{2600}'..='\u{27BF}').contains(&p) || p >= '\u{1F000}')
}

fn map_char(c: char, prev: Option<char>, suspicious: &mut bool) -> char {
    if is_map_char(c) {
        '_'
    } else if is_invisible(c) {
        if keeps_emoji_joiner(c, prev) {
            c
        } else {
            *suspicious = true;
            '_'
        }
    } else {
        c
    }
}

/// Самая длинная часть не длиннее `max` байт, обрезанная по границе символа.
pub(crate) fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("")
}

/// Последняя `.` в позиции > 0 с 1..=32 байтами после неё: (основа, ".расширение").
pub(crate) fn split_ext(c: &str) -> (&str, &str) {
    if let Some(pos) = c.rfind('.') {
        let after = c.len() - pos - 1;
        if pos > 0
            && (1..=EXT_MAX).contains(&after)
            && let Some((stem, ext)) = c.split_at_checked(pos)
        {
            return (stem, ext);
        }
    }
    (c, "")
}

/// R4: имя устройства Windows или служебный файл.
fn is_reserved(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or("").trim_end_matches(' ');
    let up = stem.to_ascii_uppercase();
    let numbered = up.len() == 4
        && (up.starts_with("COM") || up.starts_with("LPT"))
        && up.as_bytes().get(3).is_some_and(u8::is_ascii_digit);
    numbered
        || matches!(
            up.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "CONIN$"
                | "CONOUT$"
                | "CLOCK$"
                | "COM\u{B9}"
                | "COM\u{B2}"
                | "COM\u{B3}"
                | "LPT\u{B9}"
                | "LPT\u{B2}"
                | "LPT\u{B3}"
        )
        || c.eq_ignore_ascii_case("desktop.ini")
        || c.eq_ignore_ascii_case("autorun.inf")
}

/// R5: `~` перед цифрой становится `_`.
fn replace_short_aliases(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '~' && it.peek().is_some_and(|d| d.is_ascii_digit()) {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    out
}

/// R6: усечь до `max` байт, сохранив расширение (если оно помещается).
fn fit(comp: &str, max: usize) -> String {
    if comp.len() <= max {
        return comp.to_owned();
    }
    let (stem, ext) = split_ext(comp);
    let (stem, ext) = if ext.len() < max {
        (stem, ext)
    } else {
        (comp, "")
    };
    let cut_stem = cut(stem, max - ext.len()).trim_end_matches(['.', ' ']);
    let base = if cut_stem.is_empty() { "_" } else { cut_stem };
    format!("{base}{ext}")
}

/// R1-R6 для одного компонента, прошедшего H-проверки. `max_name` не меньше 1.
pub(crate) fn rewrite_component(c: &str, max_name: usize, suspicious: &mut bool) -> String {
    // NFC (см. заголовок модуля).
    let nfc: String = c.nfc().collect();
    // R1.
    let mut r1 = String::with_capacity(nfc.len());
    let mut prev: Option<char> = None;
    for ch in nfc.chars() {
        let out = map_char(ch, prev, suspicious);
        r1.push(out);
        prev = Some(out);
    }
    // R2.
    let trimmed = r1.trim_end_matches(['.', ' ']).trim_start_matches(' ');
    let mut cur = if trimmed.is_empty() {
        "_".to_owned()
    } else {
        trimmed.to_owned()
    };
    // R3.
    if cur.starts_with('.') {
        cur = format!("_{}", cur.get(1..).unwrap_or(""));
    }
    // R4.
    if is_reserved(&cur) {
        cur = format!("_{cur}");
    }
    // R5.
    cur = replace_short_aliases(&cur);
    // R6 и повторный R4. Цикл ограничен: по построению хватает двух кругов.
    cur = fit(&cur, max_name);
    for _ in 0..4 {
        if is_reserved(&cur) {
            cur = format!("_{cur}");
        }
        if cur.len() <= max_name {
            return cur;
        }
        cur = fit(&cur, max_name);
    }
    "_".to_owned()
}

fn is_dots_and_spaces(c: &str) -> bool {
    c.chars().all(|ch| ch == '.' || ch == ' ')
}

/// Санитайзер недоверенного пути (H1-H7, затем R1-R6 по компонентам).
pub fn sanitize_path(s: &str, l: &ReceiveLimits) -> Result<(SafeRelPath, NameFlags), PathError> {
    l.validate()?;
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.len() > usize::from(l.max_path_bytes) {
        return Err(PathError::TooLong);
    }
    if s.chars().any(is_control) {
        return Err(PathError::Control);
    }
    if s.contains('\\') {
        return Err(PathError::Backslash);
    }
    if s.starts_with('/') {
        return Err(PathError::Absolute);
    }
    let mut it = s.chars();
    if let (Some(a), Some(':')) = (it.next(), it.next())
        && a.is_ascii_alphabetic()
    {
        return Err(PathError::Drive);
    }
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() > usize::from(l.max_depth) {
        return Err(PathError::TooDeep);
    }
    if parts.iter().any(|p| p.is_empty()) {
        return Err(PathError::EmptyComponent);
    }
    if parts.iter().any(|p| is_dots_and_spaces(p)) {
        return Err(PathError::DotComponent);
    }
    let max_name = usize::from(l.max_name_bytes);
    let mut flags = NameFlags::default();
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        let r = rewrite_component(p, max_name, &mut flags.suspicious);
        if r != p {
            flags.changed = true;
        }
        out.push(r);
    }
    Ok((SafeRelPath::from_parts(out), flags))
}

/// Сторона отправителя: один локальный компонент через те же правила. Отказ: пусто, длиннее
/// 1024 байт, управляющие символы, `\`, `/` внутри компонента (`EmptyComponent`), только
/// точки и пробелы. Двоеточие и прочее не отказ, а замена (`C:x` даёт `C_x`).
pub fn portable_component(s: &str) -> Result<String, PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.len() > PATH_MAX {
        return Err(PathError::TooLong);
    }
    if s.chars().any(is_control) {
        return Err(PathError::Control);
    }
    if s.contains('\\') {
        return Err(PathError::Backslash);
    }
    if s.contains('/') {
        return Err(PathError::EmptyComponent);
    }
    if is_dots_and_spaces(s) {
        return Err(PathError::DotComponent);
    }
    let mut suspicious = false;
    Ok(rewrite_component(s, NAME_MAX, &mut suspicious))
}

/// Инварианты результата санитайзера для одного компонента (пределы по умолчанию).
pub fn is_portable_component(s: &str) -> bool {
    if s.is_empty() || s.len() > NAME_MAX || is_dots_and_spaces(s) {
        return false;
    }
    if s.ends_with(['.', ' ']) || s.starts_with([' ', '.']) {
        return false;
    }
    let mut prev: Option<char> = None;
    let mut prev_tilde = false;
    for c in s.chars() {
        if is_control(c) || c == '/' || c == '\\' || is_map_char(c) {
            return false;
        }
        if is_invisible(c) && !keeps_emoji_joiner(c, prev) {
            return false;
        }
        if prev_tilde && c.is_ascii_digit() {
            return false;
        }
        prev_tilde = c == '~';
        prev = Some(c);
    }
    if is_reserved(s) {
        return false;
    }
    s.nfc().eq(s.chars())
}

/// Ключ коллизий: каждый символ в верхний регистр, затем результат в нижний (таблицы std).
pub fn fold(s: &str) -> String {
    s.chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Для свойства фаззинга: `root.join(санитизированный путь)`. Файловой системы не касается.
pub fn sanitize_relative_path(
    root: &Path,
    s: &str,
    l: &ReceiveLimits,
) -> Result<PathBuf, PathError> {
    let (p, _) = sanitize_path(s, l)?;
    let mut out = root.to_path_buf();
    for c in p.components() {
        out.push(c);
    }
    Ok(out)
}
