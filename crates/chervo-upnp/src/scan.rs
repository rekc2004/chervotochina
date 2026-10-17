//! Сканер фиксированного подмножества XML: самое важное место разбора враждебного ввода.
//!
//! Библиотек XML нет. Сканер отвергает всё, что раскрывается или исполняется: DTD, сущности,
//! комментарии, CDATA, инструкции обработки (кроме одного объявления в начале), ссылки на
//! символы и неизвестные сущности. Ничего не раскрывается, поэтому бомба этапа 8 отвергается на
//! первом `<!`. Все проверки по всему телу делаются до первого события; остальные ошибки
//! (несовпадение тегов, глубина, обрыв) могут прийти уже после событий: потребитель обязан
//! считать документ отвергнутым целиком при любой ошибке.

use crate::error::ScanError;
use crate::limits::{
    BODY_MAX, VALUE_MAX, XML_DECL_MAX, XML_MAX_DEPTH, XML_MAX_ELEMENTS, XML_NAME_MAX,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event<'a> {
    /// `name`: локальное имя (часть после последнего `:`).
    Start {
        name: &'a str,
    },
    End {
        name: &'a str,
    },
    /// Сырые байты текста между тегами (сущности не раскрыты, но проверены).
    Text {
        raw: &'a [u8],
    },
}

/// Пять разрешённых сущностей.
const ENTITIES: [(&[u8], char); 5] = [
    (b"&amp;", '&'),
    (b"&lt;", '<'),
    (b"&gt;", '>'),
    (b"&quot;", '"'),
    (b"&apos;", '\''),
];

const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_control(b: u8) -> bool {
    matches!(b, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F)
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')
}

/// Проверки по всему телу до первого события.
fn precheck(body: &[u8]) -> Result<&[u8], ScanError> {
    if body.len() > BODY_MAX {
        return Err(ScanError::TooLarge);
    }
    let b = body.strip_prefix(BOM).unwrap_or(body);
    if b.iter().any(|&c| is_control(c)) {
        return Err(ScanError::Control);
    }
    if b.windows(2).any(|w| w == b"<!") {
        return Err(ScanError::Markup);
    }
    Ok(b)
}

/// Сущность, начинающаяся с `&` в позиции `i`: символ и длина в байтах.
fn entity_at(b: &[u8], i: usize) -> Result<(char, usize), ScanError> {
    let rest = b.get(i..).unwrap_or_default();
    for (pat, ch) in ENTITIES {
        if rest.starts_with(pat) {
            return Ok((ch, pat.len()));
        }
    }
    Err(ScanError::Entity)
}

/// Имя: `[A-Za-z_][A-Za-z0-9_.:-]*`, до `XML_NAME_MAX` байт, только ASCII.
fn parse_name(b: &[u8], i: usize) -> Result<(&str, usize), ScanError> {
    if !b.get(i).copied().is_some_and(is_name_start) {
        return Err(ScanError::Syntax);
    }
    let mut j = i + 1;
    while b.get(j).copied().is_some_and(is_name_char) {
        j += 1;
        if j - i > XML_NAME_MAX {
            return Err(ScanError::NameTooLong);
        }
    }
    let name = b
        .get(i..j)
        .and_then(|s| std::str::from_utf8(s).ok())
        .ok_or(ScanError::Syntax)?;
    Ok((name, j))
}

/// Локальное имя: после последнего `:`; не пустое и начинается как имя.
fn local_name(name: &str) -> Result<&str, ScanError> {
    let local = name.rsplit(':').next().unwrap_or_default();
    if local.bytes().next().is_some_and(is_name_start) {
        Ok(local)
    } else {
        Err(ScanError::Syntax)
    }
}

/// Объявление `<?xml ... ?>`: целиком не длиннее `XML_DECL_MAX`, без `< & [ %`, только ASCII.
/// `i` указывает на `<?`; возвращает позицию после `?>`.
fn decl_end(b: &[u8], i: usize) -> Result<usize, ScanError> {
    let rest = b.get(i..).unwrap_or_default();
    let window = rest.get(..XML_DECL_MAX.min(rest.len())).unwrap_or_default();
    let tail = window.get(2..).unwrap_or_default();
    let pos = tail
        .windows(2)
        .position(|w| w == b"?>")
        .ok_or(ScanError::Markup)?;
    let interior = tail.get(..pos).unwrap_or_default();
    let clean = interior
        .iter()
        .all(|&c| (c.is_ascii_graphic() || is_ws(c)) && !matches!(c, b'<' | b'&' | b'[' | b'%'));
    let is_xml = interior
        .strip_prefix(b"xml")
        .and_then(|r| r.first().copied())
        .is_some_and(is_ws);
    if !clean || !is_xml {
        return Err(ScanError::Markup);
    }
    Ok(i + 2 + pos + 2)
}

/// Значение в кавычках; `j` указывает на открывающую кавычку; возвращает позицию после закрывающей.
fn skip_quoted(b: &[u8], j: usize) -> Result<usize, ScanError> {
    let quote = b.get(j).copied().ok_or(ScanError::Syntax)?;
    let mut k = j + 1;
    loop {
        match b.get(k).copied() {
            None | Some(b'<') => return Err(ScanError::Syntax),
            Some(c) if c == quote => return Ok(k + 1),
            Some(b'&') => k += entity_at(b, k)?.1,
            Some(_) => k += 1,
        }
    }
}

/// Атрибуты до `>`; возвращает (самозакрывающийся, позиция после `>`).
/// Вне кавычек допустим только ASCII; `<` и `&` вне кавычек недопустимы.
fn skip_attrs(b: &[u8], mut j: usize) -> Result<(bool, usize), ScanError> {
    loop {
        match b.get(j).copied() {
            None | Some(b'<') => return Err(ScanError::Syntax),
            Some(b'>') => return Ok((false, j + 1)),
            Some(b'/') => {
                return if b.get(j + 1).copied() == Some(b'>') {
                    Ok((true, j + 2))
                } else {
                    Err(ScanError::Syntax)
                };
            }
            Some(b'"' | b'\'') => j = skip_quoted(b, j)?,
            Some(b'&') => return Err(ScanError::Entity),
            Some(c) if c >= 0x80 => return Err(ScanError::Syntax),
            Some(_) => j += 1,
        }
    }
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
    /// Полные имена открытых элементов (с префиксом).
    stack: Vec<&'a str>,
    elements: usize,
    root_seen: bool,
    markup_seen: bool,
}

impl<'a> Scanner<'a> {
    fn start_tag<E: From<ScanError>>(
        &mut self,
        f: &mut impl FnMut(Event<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        let (name, j) = parse_name(self.b, self.i + 1)?;
        let local = local_name(name)?;
        if !self
            .b
            .get(j)
            .copied()
            .is_some_and(|c| is_ws(c) || c == b'>' || c == b'/')
        {
            return Err(ScanError::Syntax.into());
        }
        // второй корень
        if self.stack.is_empty() && self.root_seen {
            return Err(ScanError::Syntax.into());
        }
        self.elements += 1;
        if self.elements > XML_MAX_ELEMENTS {
            return Err(ScanError::Elements.into());
        }
        if self.stack.len() >= XML_MAX_DEPTH {
            return Err(ScanError::Depth.into());
        }
        let (self_closing, next) = skip_attrs(self.b, j)?;
        self.root_seen = true;
        f(Event::Start { name: local })?;
        if self_closing {
            f(Event::End { name: local })?;
        } else {
            self.stack.push(name);
        }
        self.i = next;
        Ok(())
    }

    fn end_tag<E: From<ScanError>>(
        &mut self,
        f: &mut impl FnMut(Event<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        let (name, mut j) = parse_name(self.b, self.i + 2)?;
        while self.b.get(j).copied().is_some_and(is_ws) {
            j += 1;
        }
        if self.b.get(j).copied() != Some(b'>') {
            return Err(ScanError::Syntax.into());
        }
        if self.stack.last().copied() != Some(name) {
            return Err(ScanError::Mismatch.into());
        }
        let local = local_name(name)?;
        self.stack.pop();
        f(Event::End { name: local })?;
        self.i = j + 1;
        Ok(())
    }

    fn text_run<E: From<ScanError>>(
        &mut self,
        f: &mut impl FnMut(Event<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        let start = self.i;
        let mut k = start;
        let mut non_ws = false;
        while let Some(c) = self.b.get(k).copied() {
            match c {
                b'<' => break,
                b'&' => {
                    k += entity_at(self.b, k)?.1;
                    non_ws = true;
                }
                _ => {
                    non_ws |= !is_ws(c);
                    k += 1;
                }
            }
        }
        if self.stack.is_empty() {
            if non_ws {
                return Err(ScanError::Syntax.into());
            }
        } else if let Some(raw) = self.b.get(start..k) {
            f(Event::Text { raw })?;
        }
        self.i = k;
        Ok(())
    }

    fn run<E: From<ScanError>>(
        &mut self,
        f: &mut impl FnMut(Event<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        while let Some(c) = self.b.get(self.i).copied() {
            if c != b'<' {
                self.text_run(f)?;
                continue;
            }
            match self.b.get(self.i + 1).copied() {
                Some(b'?') => {
                    // единственное объявление и только как первая разметка
                    if self.markup_seen {
                        return Err(ScanError::Markup.into());
                    }
                    self.i = decl_end(self.b, self.i)?;
                }
                Some(b'/') => self.end_tag(f)?,
                Some(n) if is_name_start(n) => self.start_tag(f)?,
                _ => return Err(ScanError::Syntax.into()),
            }
            self.markup_seen = true;
        }
        if !self.stack.is_empty() || !self.root_seen {
            return Err(ScanError::Syntax.into());
        }
        Ok(())
    }
}

/// Разбор тела: события `Start`, `End`, `Text`. Любая ошибка означает отказ всему документу.
pub(crate) fn scan<'a, E: From<ScanError>>(
    body: &'a [u8],
    mut f: impl FnMut(Event<'a>) -> Result<(), E>,
) -> Result<(), E> {
    let b = precheck(body)?;
    let mut s = Scanner {
        b,
        i: 0,
        stack: Vec::new(),
        elements: 0,
        root_seen: false,
        markup_seen: false,
    };
    s.run(&mut f)
}

/// Содержимое элемента, у которого нет дочерних элементов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leaf<'a> {
    Empty,
    Text(&'a [u8]),
    /// Есть дочерние элементы.
    Branch,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Node<'a, 'p> {
    /// `path`: локальные имена от корня до открытого элемента включительно.
    Open { path: &'p [&'a str] },
    /// Элемент закрыт; `path` включает его самого.
    Close { path: &'p [&'a str], leaf: Leaf<'a> },
}

/// Обход с путём из локальных имён. Лист (элемент без дочерних) отдаёт сырой текст целиком:
/// без CDATA и комментариев текст листа это ровно один непрерывный отрезок.
pub(crate) fn walk<'a, E: From<ScanError>>(
    body: &'a [u8],
    mut f: impl FnMut(Node<'a, '_>) -> Result<(), E>,
) -> Result<(), E> {
    let mut path: Vec<&'a str> = Vec::new();
    // на каждый открытый элемент: есть ли дочерние и его текст
    let mut frames: Vec<(bool, Option<&'a [u8]>)> = Vec::new();
    scan(body, |ev| match ev {
        Event::Start { name } => {
            if let Some(top) = frames.last_mut() {
                top.0 = true;
            }
            path.push(name);
            frames.push((false, None));
            f(Node::Open { path: &path })
        }
        Event::Text { raw } => {
            if let Some(top) = frames.last_mut() {
                top.1 = Some(raw);
            }
            Ok(())
        }
        Event::End { .. } => {
            let (has_child, text) = frames.pop().unwrap_or((false, None));
            let leaf = match (has_child, text) {
                (true, _) => Leaf::Branch,
                (false, Some(t)) if !t.is_empty() => Leaf::Text(t),
                _ => Leaf::Empty,
            };
            let r = f(Node::Close { path: &path, leaf });
            path.pop();
            r
        }
    })
}

/// Значение поля: обрезка ASCII-пробелов, раскрытие пяти сущностей, итог только ASCII
/// 0x20-0x7E длиной не более `VALUE_MAX`.
pub(crate) fn value(raw: &[u8]) -> Result<String, ScanError> {
    let t = raw.trim_ascii();
    let mut out = String::new();
    let mut i = 0usize;
    while let Some(c) = t.get(i).copied() {
        if c == b'&' {
            let (ch, n) = entity_at(t, i)?;
            out.push(ch);
            i += n;
        } else if (0x20..=0x7E).contains(&c) {
            out.push(char::from(c));
            i += 1;
        } else {
            return Err(ScanError::Value);
        }
        if out.len() > VALUE_MAX {
            return Err(ScanError::Value);
        }
    }
    Ok(out)
}

/// Значение листа; ветка, а не лист, это `Value`.
pub(crate) fn leaf_value(leaf: Leaf<'_>) -> Result<String, ScanError> {
    match leaf {
        Leaf::Empty => Ok(String::new()),
        Leaf::Text(t) => value(t),
        Leaf::Branch => Err(ScanError::Value),
    }
}
