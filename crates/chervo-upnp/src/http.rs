//! HTTP/1.0: построение запросов и разбор ответа. Сокетов здесь нет.
//!
//! Запрос всегда HTTP/1.0 с `Connection: close`; сервер не должен слать chunked клиенту 1.0,
//! поэтому любой `Transfer-Encoding` отвергается. Тело кончается по `Content-Length` или по EOF.
//! Перенаправления это ошибка.

use crate::error::HttpError;
use crate::limits::{BODY_MAX, HTTP_HEAD_MAX, HTTP_MAX_HEADERS};
use crate::url::{GatewayAddr, Path};

/// Запрос GET (описание устройства).
pub(crate) fn get_request(gw: &GatewayAddr, path: &Path) -> Vec<u8> {
    let a = gw.addr();
    format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        path.as_str(),
        a.ip(),
        a.port()
    )
    .into_bytes()
}

/// Запрос POST с SOAP. `service_type` и `action` это только наши константы.
pub(crate) fn post_request(
    gw: &GatewayAddr,
    path: &Path,
    service_type: &'static str,
    action: &'static str,
    body: &str,
) -> Vec<u8> {
    let a = gw.addr();
    format!(
        "POST {} HTTP/1.0\r\nHost: {}:{}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{}#{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path.as_str(),
        a.ip(),
        a.port(),
        service_type,
        action,
        body.len(),
        body
    )
    .into_bytes()
}

/// Ответ с телом: статус 200 или 500 (тело 500 уходит в разбор SOAP-ошибки).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reply(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineError {
    /// Строка начинается с пробела: перенос заголовка (obs-fold).
    ObsFold,
    Malformed,
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// `Имя: значение` (без переноса); значение обрезано по краям от пробелов.
pub(crate) fn header_line(line: &str) -> Result<(&str, &str), LineError> {
    if line.starts_with([' ', '\t']) {
        return Err(LineError::ObsFold);
    }
    let (name, value) = line.split_once(':').ok_or(LineError::Malformed)?;
    if name.is_empty() || !name.bytes().all(is_token_char) {
        return Err(LineError::Malformed);
    }
    Ok((name, value.trim_matches(' ')))
}

/// Только печатаемый ASCII и CR LF.
pub(crate) fn printable_or_crlf(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| (0x20..=0x7E).contains(&c) || c == b'\r' || c == b'\n')
}

/// Позиция после `\r\n\r\n` или `None`.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `HTTP/1.0 ddd` или `HTTP/1.1 ddd`, затем пробел или конец строки.
fn parse_status_line(line: &str) -> Result<u16, HttpError> {
    let rest = line
        .strip_prefix("HTTP/1.0 ")
        .or_else(|| line.strip_prefix("HTTP/1.1 "))
        .ok_or(HttpError::BadStatusLine)?;
    let (code, tail) = rest.split_at_checked(3).ok_or(HttpError::BadStatusLine)?;
    if !code.bytes().all(|b| b.is_ascii_digit()) || !(tail.is_empty() || tail.starts_with(' ')) {
        return Err(HttpError::BadStatusLine);
    }
    let n: u16 = code.parse().map_err(|_| HttpError::BadStatusLine)?;
    if (100..=599).contains(&n) {
        Ok(n)
    } else {
        Err(HttpError::BadStatusLine)
    }
}

/// Разбор принятых байт (до EOF). Статус 200 и 500 дают тело; 3xx это `Redirect`;
/// остальное `Status(код)`.
pub(crate) fn parse_response(buf: &[u8]) -> Result<Reply, HttpError> {
    let head_end = match find_head_end(buf) {
        Some(e) if e <= HTTP_HEAD_MAX => e,
        Some(_) => return Err(HttpError::HeadTooLarge),
        None if buf.len() > HTTP_HEAD_MAX => return Err(HttpError::HeadTooLarge),
        None => return Err(HttpError::Truncated),
    };
    let head = buf.get(..head_end).unwrap_or_default();
    if !printable_or_crlf(head) {
        return Err(HttpError::NonAscii);
    }
    let text = std::str::from_utf8(head).map_err(|_| HttpError::NonAscii)?;
    // без завершающей пустой строки; каждая строка заканчивается ровно CRLF
    let text = text.strip_suffix("\r\n\r\n").ok_or(HttpError::Truncated)?;
    if text.split("\r\n").any(|l| l.contains(['\r', '\n'])) {
        return Err(HttpError::BadHeader);
    }
    let mut lines = text.split("\r\n");
    let status = parse_status_line(lines.next().ok_or(HttpError::BadStatusLine)?)?;

    let mut count = 0usize;
    let mut content_length: Option<usize> = None;
    for line in lines {
        count += 1;
        if count > HTTP_MAX_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }
        let (name, value) = header_line(line).map_err(|e| match e {
            LineError::ObsFold => HttpError::ObsFold,
            LineError::Malformed => HttpError::BadHeader,
        })?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::Chunked);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::BadContentLength);
            }
            content_length = Some(parse_content_length(value)?);
        }
    }

    match status {
        200 | 500 => {}
        300..=399 => return Err(HttpError::Redirect),
        other => return Err(HttpError::Status(other)),
    }
    let rest = buf.get(head_end..).unwrap_or_default();
    let body = match content_length {
        Some(n) => rest.get(..n).ok_or(HttpError::ShortBody)?,
        None if rest.len() > BODY_MAX => return Err(HttpError::TooLarge),
        None => rest,
    };
    Ok(Reply {
        status,
        body: body.to_vec(),
    })
}

/// Только цифры, не более `BODY_MAX`.
fn parse_content_length(v: &str) -> Result<usize, HttpError> {
    if v.is_empty() || v.len() > 6 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::BadContentLength);
    }
    let n: usize = v.parse().map_err(|_| HttpError::BadContentLength)?;
    if n > BODY_MAX {
        return Err(HttpError::TooLarge);
    }
    Ok(n)
}
