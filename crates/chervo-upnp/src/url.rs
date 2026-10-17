//! Адреса из ответов роутера: только `http://` + IPv4-литерал, путь из узкого набора.
//! Имена хостов, IPv6, учётные данные, запросы и фрагменты отвергаются.
//! Перенаправлений и разрешения по `URLBase` нет.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::UrlError;
use crate::limits::PATH_MAX;

/// Адрес шлюза для TCP. Конструктор только здесь и только после проверки, что хост адреса
/// равен адресу ответившего (`parse_location`, `parse_http_url`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GatewayAddr(SocketAddrV4);

impl GatewayAddr {
    pub(crate) fn addr(&self) -> SocketAddrV4 {
        self.0
    }
}

impl fmt::Debug for GatewayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAddr(..)")
    }
}

/// Проверенный путь: начинается с `/`, узкий набор символов, без `..`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Path(String);

impl Path {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(s: &str) -> Result<Self, UrlError> {
        check_path(s)?;
        Ok(Path(s.to_owned()))
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Path(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HttpTarget {
    pub(crate) gw: GatewayAddr,
    pub(crate) path: Path,
}

impl fmt::Debug for HttpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpTarget(..)")
    }
}

/// Строгий IPv4: четыре десятичные части по 1-3 цифры, значение до 255, без лидирующих нулей.
pub(crate) fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut n = 0usize;
    for part in s.split('.') {
        let slot = octets.get_mut(n)?;
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *slot = part.parse().ok()?;
        n += 1;
    }
    (n == 4).then(|| Ipv4Addr::from(octets))
}

/// Порт: 1-5 цифр, значение 1..=65535.
pub(crate) fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p != 0)
}

fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'/'
                | b'!'
                | b'$'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'%'
        )
}

fn check_path(s: &str) -> Result<(), UrlError> {
    if s.len() > PATH_MAX {
        return Err(UrlError::TooLong);
    }
    if !s.starts_with('/') {
        return Err(UrlError::NoPath);
    }
    let b = s.as_bytes();
    let mut i = 0usize;
    while let Some(c) = b.get(i).copied() {
        if !is_path_char(c) {
            return Err(UrlError::PathChar);
        }
        if c == b'%' {
            let hi = b.get(i + 1).copied().filter(u8::is_ascii_hexdigit);
            let lo = b.get(i + 2).copied().filter(u8::is_ascii_hexdigit);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(UrlError::Percent);
            };
            // %00, %2f, %5c в любом регистре
            let pair = [hi.to_ascii_lowercase(), lo.to_ascii_lowercase()];
            if pair == *b"00" || pair == *b"2f" || pair == *b"5c" {
                return Err(UrlError::Percent);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    // сегменты `.` и `..`, в том числе записанные как %2e
    for seg in s.split('/') {
        let norm = seg.to_ascii_lowercase().replace("%2e", ".");
        if norm == "." || norm == ".." {
            return Err(UrlError::DotSegment);
        }
    }
    Ok(())
}

/// Отрезает `http://` (схема без учёта регистра).
fn strip_http(value: &str) -> Option<&str> {
    let head = value.get(..7)?;
    if head.eq_ignore_ascii_case("http://") {
        value.get(7..)
    } else {
        None
    }
}

/// `хост[:порт]` с IPv4-литералом; порт по умолчанию 80.
fn parse_authority(auth: &str) -> Result<SocketAddrV4, UrlError> {
    if auth.contains('@') {
        return Err(UrlError::Authority);
    }
    if auth.contains('[') {
        return Err(UrlError::Authority);
    }
    let (host, port) = match auth.split_once(':') {
        Some((h, p)) => (h, parse_port(p).ok_or(UrlError::Port)?),
        None => (auth, 80),
    };
    let ip = parse_ipv4(host).ok_or(UrlError::Host)?;
    Ok(SocketAddrV4::new(ip, port))
}

/// `http://IPv4[:порт]` и путь. Путь обязателен, если `require_path`.
fn parse_http_url(
    value: &str,
    require_path: bool,
) -> Result<(SocketAddrV4, Option<Path>), UrlError> {
    let rest = strip_http(value).ok_or(UrlError::Scheme)?;
    let (auth, path) = match rest.find('/') {
        Some(p) => rest.split_at_checked(p).ok_or(UrlError::NoPath)?,
        None => (rest, ""),
    };
    let addr = parse_authority(auth)?;
    if path.is_empty() {
        return if require_path {
            Err(UrlError::NoPath)
        } else {
            Ok((addr, None))
        };
    }
    Ok((addr, Some(Path::parse(path)?)))
}

/// Заголовок `LOCATION`: хост обязан быть равен адресу ответившего.
pub(crate) fn parse_location(value: &str, responder: Ipv4Addr) -> Result<HttpTarget, UrlError> {
    let (addr, path) = parse_http_url(value, true)?;
    if *addr.ip() != responder {
        return Err(UrlError::HostMismatch);
    }
    let path = path.ok_or(UrlError::NoPath)?;
    Ok(HttpTarget {
        gw: GatewayAddr(addr),
        path,
    })
}

/// `controlURL`: путь с `/`, полный `http://` (хост и порт как у LOCATION) или относительный.
pub(crate) fn control_url(value: &str, location: &HttpTarget) -> Result<Path, UrlError> {
    if value.is_empty() {
        return Err(UrlError::Empty);
    }
    if value.starts_with('/') {
        return Path::parse(value);
    }
    if strip_http(value).is_some() {
        let (addr, path) = parse_http_url(value, true)?;
        if addr != location.gw.0 {
            return Err(UrlError::HostMismatch);
        }
        return path.ok_or(UrlError::NoPath);
    }
    // относительная ссылка не может начинаться с сегмента со схемой (`https:...`)
    if value.split('/').next().unwrap_or_default().contains(':') {
        return Err(UrlError::Scheme);
    }
    Path::parse(&format!("/{value}"))
}

/// `URLBase`: должен разбираться и совпадать с LOCATION по хосту и порту; не используется для
/// разрешения ссылок. Путь не обязателен.
pub(crate) fn check_urlbase(value: &str, location: &HttpTarget) -> Result<(), UrlError> {
    let (addr, _) = parse_http_url(value, false)?;
    if addr != location.gw.0 {
        return Err(UrlError::HostMismatch);
    }
    Ok(())
}
