//! SSDP: построение M-SEARCH и разбор ответа. Сокетов здесь нет.
//!
//! Ответ принимается, только если источник из частной сети, не мы сами, ответ короткий,
//! печатный ASCII, и адрес описания `LOCATION` указывает на самого ответившего.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use chervo_addr::{AddrClass, classify};

use crate::error::SsdpError;
use crate::http::{LineError, header_line, printable_or_crlf};
use crate::limits::{MAX_RESPONDERS, SSDP_DGRAM_MAX, SSDP_HOST, SSDP_MAX_HEADERS};
use crate::url::{HttpTarget, parse_location};

pub(crate) const ST_IGD_V1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
pub(crate) const ST_IGD_V2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
/// Обе цели поиска; каждая отправляется отдельной датаграммой.
pub(crate) const SEARCH_TARGETS: [&str; 2] = [ST_IGD_V1, ST_IGD_V2];

/// Датаграмма M-SEARCH. Ни ключей, ни имён, ни User-Agent.
pub(crate) fn msearch(st: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_HOST}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
    )
    .into_bytes()
}

/// Политика источника. Loopback допускается только в тестах (`Net.allow_loopback`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SsdpPolicy {
    pub(crate) allow_loopback: bool,
}

impl SsdpPolicy {
    pub(crate) const STRICT: SsdpPolicy = SsdpPolicy {
        allow_loopback: false,
    };
}

/// Принятый ответчик: его IP и проверенный адрес описания.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Responder {
    pub(crate) ip: Ipv4Addr,
    pub(crate) target: HttpTarget,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Responder(..)")
    }
}

fn line_err(e: LineError) -> SsdpError {
    match e {
        LineError::ObsFold => SsdpError::ObsFold,
        LineError::Malformed => SsdpError::BadHeader,
    }
}

/// Разбор одной датаграммы-ответа. Источник проверяется первым (дёшево).
pub(crate) fn parse_response(
    dgram: &[u8],
    src: SocketAddrV4,
    own_ip: Ipv4Addr,
    policy: SsdpPolicy,
) -> Result<Responder, SsdpError> {
    let class = classify(IpAddr::V4(*src.ip()));
    let class_ok =
        class == AddrClass::Private || (policy.allow_loopback && class == AddrClass::Loopback);
    if !class_ok {
        return Err(SsdpError::BadSource);
    }
    if *src.ip() == own_ip {
        return Err(SsdpError::SelfSource);
    }
    if dgram.len() > SSDP_DGRAM_MAX {
        return Err(SsdpError::Oversize);
    }
    if !printable_or_crlf(dgram) {
        return Err(SsdpError::NonAscii);
    }
    let text = std::str::from_utf8(dgram).map_err(|_| SsdpError::NonAscii)?;
    // каждая строка заканчивается CRLF; одиночные CR и LF недопустимы
    let mut lines = text.split("\r\n");
    if text.split("\r\n").any(|l| l.contains(['\r', '\n'])) {
        return Err(SsdpError::BadHeader);
    }
    let status = lines.next().ok_or(SsdpError::BadStatus)?;
    let status_ok = status
        .strip_prefix("HTTP/1.1 200")
        .is_some_and(|t| t.is_empty() || t.starts_with(' '));
    if !status_ok {
        return Err(SsdpError::BadStatus);
    }

    let mut headers = 0usize;
    let mut location: Option<&str> = None;
    let mut st: Option<&str> = None;
    let mut blank = false;
    for line in lines {
        if blank {
            // после пустой строки допустим только конец датаграммы
            if line.is_empty() {
                continue;
            }
            return Err(SsdpError::Trailing);
        }
        if line.is_empty() {
            blank = true;
            continue;
        }
        headers += 1;
        if headers > SSDP_MAX_HEADERS {
            return Err(SsdpError::TooManyHeaders);
        }
        let (name, value) = header_line(line).map_err(line_err)?;
        if name.eq_ignore_ascii_case("location") {
            if location.replace(value).is_some() {
                return Err(SsdpError::DuplicateLocation);
            }
        } else if name.eq_ignore_ascii_case("st") && st.replace(value).is_some() {
            return Err(SsdpError::DuplicateSt);
        }
    }
    let location = location.ok_or(SsdpError::MissingLocation)?;
    let st = st.ok_or(SsdpError::MissingSt)?;
    if !SEARCH_TARGETS.contains(&st) {
        return Err(SsdpError::StMismatch);
    }
    let target = parse_location(location, *src.ip()).map_err(SsdpError::Location)?;
    Ok(Responder {
        ip: *src.ip(),
        target,
    })
}

/// Один ответчик на IP. IP, приславший два разных LOCATION, отбрасывается целиком.
/// Порядок прихода сохраняется; не более `MAX_RESPONDERS`.
pub(crate) fn select(responders: Vec<Responder>) -> Vec<Responder> {
    let conflicting = |ip: Ipv4Addr| {
        responders.iter().any(|r| {
            r.ip == ip
                && responders
                    .iter()
                    .any(|o| o.ip == ip && o.target != r.target)
        })
    };
    let mut out: Vec<Responder> = Vec::new();
    for r in &responders {
        if out.iter().any(|o| o.ip == r.ip) || conflicting(r.ip) {
            continue;
        }
        out.push(r.clone());
        if out.len() == MAX_RESPONDERS {
            break;
        }
    }
    out
}
