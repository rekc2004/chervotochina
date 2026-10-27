//! HTTP/1.1: точный запрос и узкий разбор ответа над `impl Read` (без сети, тестируется на байтах).
//!
//! Весь ответ недоверенный. Пределы проверяются до чтения: заголовки не больше
//! `MAX_HEADER_BYTES`, тело не больше предела вызывающего. Никакие байты ответа не попадают
//! в тексты ошибок: ошибки это закрытый список `CheckError`.

use std::io::{self, Read};

use crate::{ALLOWED_HOSTS, CheckError, MAX_HEADER_BYTES, MAX_LOCATION_LEN};

/// Размер одного чтения при поиске конца заголовков.
pub(crate) const READ_CHUNK: usize = 4096;

/// Запрос ровно этими байтами (кроме пути и хоста). Без `Cookie`, `Referer`, `Accept-Encoding`,
/// `Accept-Language`, версии программы и ОС.
pub(crate) fn request_bytes(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: chervo\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Результат одного обмена. `Redirect` хранит значение `Location` как есть (только значение
/// заголовка без управляющих байтов); оно годится лишь как вход `parse_location`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Response {
    Body(Vec<u8>),
    Redirect(String),
}

/// Цель следующего запроса: хост берётся из вшитого списка, а не из ответа.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub(crate) host: &'static str,
    pub(crate) path: String,
}

/// Ошибка ввода-вывода в закрытую ошибку проверки. Срок вышел: `Timeout`; ошибка TLS
/// (сертификат, протокол): `BadResponse`; остальное: `Network`.
pub(crate) fn map_io(e: &io::Error) -> CheckError {
    if matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        return CheckError::Timeout;
    }
    if let Some(inner) = e.get_ref()
        && inner.downcast_ref::<rustls::Error>().is_some()
    {
        return CheckError::BadResponse;
    }
    CheckError::Network
}

/// `Location` для следующего запроса: только `https://<хост из ALLOWED_HOSTS><путь>`, без порта,
/// `userinfo`, фрагмента, IP-литерала и кодирования в хосте; путь `/...` из байтов `0x21..=0x7E`.
pub(crate) fn parse_location(s: &str) -> Result<Location, CheckError> {
    if s.len() > MAX_LOCATION_LEN {
        return Err(CheckError::BadResponse);
    }
    let rest = s.strip_prefix("https://").ok_or(CheckError::BadResponse)?;
    let slash = rest.find('/').ok_or(CheckError::BadResponse)?;
    let (host, path) = rest.split_at(slash);
    let host = ALLOWED_HOSTS
        .iter()
        .copied()
        .find(|h| *h == host)
        .ok_or(CheckError::BadResponse)?;
    if !path.bytes().all(|b| (0x21..=0x7E).contains(&b)) || path.contains('#') {
        return Err(CheckError::BadResponse);
    }
    Ok(Location {
        host,
        path: path.to_owned(),
    })
}

fn read_some<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, CheckError> {
    loop {
        match r.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(map_io(&e)),
        }
    }
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Делит блок заголовков по `\r\n`. Всегда возвращает хотя бы одну строку. Одиночные `\r` и
/// `\n` остаются в строках и отвергаются как управляющие байты.
fn split_crlf(h: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < h.len() {
        if h[i] == b'\r' && h[i + 1] == b'\n' {
            out.push(&h[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    out.push(&h[start..]);
    out
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if *first == b' ' || *first == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = v {
        if *last == b' ' || *last == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

fn is_ctl(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7F
}

/// Строка статуса: `HTTP/1.1 <3 цифры>` и необязательно пробел с пояснением.
fn parse_status(line: &[u8]) -> Result<u16, CheckError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .ok_or(CheckError::BadResponse)?;
    let (digits, tail) = rest.split_at_checked(3).ok_or(CheckError::BadResponse)?;
    if !digits.iter().all(u8::is_ascii_digit) || !(b'1'..=b'5').contains(&digits[0]) {
        return Err(CheckError::BadResponse);
    }
    match tail {
        [] => {}
        [b' ', reason @ ..] => {
            if !reason
                .iter()
                .all(|b| (0x20..=0x7E).contains(b) || *b == b'\t')
            {
                return Err(CheckError::BadResponse);
            }
        }
        _ => return Err(CheckError::BadResponse),
    }
    Ok(digits
        .iter()
        .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0')))
}

fn parse_content_length(v: &[u8]) -> Result<u64, CheckError> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return Err(CheckError::BadResponse);
    }
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(CheckError::BadResponse)
}

/// Читает один ответ. Статусы: 200 даёт тело (не больше `max_body`), 301/302/303/307/308 дают
/// `Location` (тело не читается), всё остальное ошибка. Любой `Transfer-Encoding`, повтор
/// `Location` или `Content-Length`, кривой заголовок: ошибка.
pub(crate) fn read_response<R: Read>(mut r: R, max_body: usize) -> Result<Response, CheckError> {
    // 1. Заголовки: не больше MAX_HEADER_BYTES + 4 байт (с завершающими CRLFCRLF).
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let end = loop {
        if let Some(i) = find_crlfcrlf(&buf) {
            break i;
        }
        let room = MAX_HEADER_BYTES + 4 - buf.len().min(MAX_HEADER_BYTES + 4);
        if room == 0 {
            return Err(CheckError::BadResponse);
        }
        let mut chunk = [0u8; READ_CHUNK];
        let n = read_some(&mut r, &mut chunk[..READ_CHUNK.min(room)])?;
        if n == 0 {
            return Err(CheckError::BadResponse);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if end > MAX_HEADER_BYTES {
        return Err(CheckError::BadResponse);
    }
    let head = &buf[..end];

    // 2. Статус и заголовки.
    let mut lines = split_crlf(head);
    let status_line = lines.remove(0);
    let status = parse_status(status_line)?;

    let mut content_length: Option<u64> = None;
    let mut location: Option<&[u8]> = None;
    let mut transfer_encoding = false;
    for line in lines {
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(CheckError::BadResponse)?;
        let (name, value) = (&line[..colon], trim_ows(&line[colon + 1..]));
        if name.is_empty() || !name.iter().all(|b| (0x21..=0x7E).contains(b)) {
            return Err(CheckError::BadResponse);
        }
        if value.iter().any(|b| is_ctl(*b)) {
            return Err(CheckError::BadResponse);
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(CheckError::BadResponse);
            }
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case(b"location") {
            if location.is_some() {
                return Err(CheckError::BadResponse);
            }
            location = Some(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // любой Transfer-Encoding (и повтор) недопустим: разборщика chunked нет
            transfer_encoding = true;
        }
    }
    if transfer_encoding {
        return Err(CheckError::BadResponse);
    }

    match status {
        301 | 302 | 303 | 307 | 308 => {
            let v = location.ok_or(CheckError::BadResponse)?;
            if v.is_empty() || v.len() > MAX_LOCATION_LEN {
                return Err(CheckError::BadResponse);
            }
            let s = String::from_utf8(v.to_vec()).map_err(|_| CheckError::BadResponse)?;
            Ok(Response::Redirect(s))
        }
        200 => read_body(&mut r, buf[end + 4..].to_vec(), content_length, max_body),
        _ => Err(CheckError::BadResponse),
    }
}

/// Тело 200: `have` это уже прочитанные байты после заголовков.
fn read_body<R: Read>(
    r: &mut R,
    mut body: Vec<u8>,
    content_length: Option<u64>,
    max_body: usize,
) -> Result<Response, CheckError> {
    let io_err = |e: io::Error| map_io(&e);
    match content_length {
        Some(n) => {
            let n = usize::try_from(n).map_err(|_| CheckError::BadResponse)?;
            if n > max_body || body.len() > n {
                return Err(CheckError::BadResponse);
            }
            let missing = (n - body.len()) as u64;
            r.take(missing).read_to_end(&mut body).map_err(io_err)?;
            if body.len() != n {
                return Err(CheckError::BadResponse);
            }
        }
        None => {
            if body.len() > max_body {
                return Err(CheckError::BadResponse);
            }
            // читаем до закрытия, но не больше предела + 1 байт
            let allowed = (max_body + 1 - body.len()) as u64;
            r.take(allowed).read_to_end(&mut body).map_err(io_err)?;
            if body.len() > max_body {
                return Err(CheckError::BadResponse);
            }
        }
    }
    Ok(Response::Body(body))
}
