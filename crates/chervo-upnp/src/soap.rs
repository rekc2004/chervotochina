//! SOAP: шаблоны запросов (только наши числа, наш IPv4 и константы) и разбор ответов.
//! Пути в ответе проверяются по локальным именам: `Envelope/Body/<Действие>Response/<поле>`.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::desc::ServiceKind;
use crate::error::SoapError;
use crate::limits::DESC;
use crate::scan::{Leaf, Node, leaf_value, value, walk};
use crate::url::{parse_ipv4, parse_port};

/// Действие и его аргументы. Строки роутера сюда не попадают.
/// `AddAny` существует в шаблоне для любой службы; вызывать его для не-WanIp2 запрещено логикой
/// жизненного цикла (U2), а не шаблоном.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    GetExternalIp,
    Add {
        ext: u16,
        internal: SocketAddrV4,
        lease: u32,
    },
    AddAny {
        ext: u16,
        internal: SocketAddrV4,
        lease: u32,
    },
    GetSpecific {
        ext: u16,
    },
    Delete {
        ext: u16,
    },
}

impl Action {
    /// Имя действия для `SOAPAction` и тега.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Action::GetExternalIp => "GetExternalIPAddress",
            Action::Add { .. } => "AddPortMapping",
            Action::AddAny { .. } => "AddAnyPortMapping",
            Action::GetSpecific { .. } => "GetSpecificPortMappingEntry",
            Action::Delete { .. } => "DeletePortMapping",
        }
    }

    fn args(&self) -> String {
        let key = |ext: u16| {
            format!(
                "<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>UDP</NewProtocol>"
            )
        };
        let full = |ext: u16, internal: SocketAddrV4, lease: u32| {
            format!(
                "{}<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{DESC}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration>",
                key(ext),
                internal.port(),
                internal.ip()
            )
        };
        match *self {
            Action::GetExternalIp => String::new(),
            Action::Add {
                ext,
                internal,
                lease,
            }
            | Action::AddAny {
                ext,
                internal,
                lease,
            } => full(ext, internal, lease),
            Action::GetSpecific { ext } | Action::Delete { ext } => key(ext),
        }
    }

    /// Тело запроса: конверт в одну строку без пробелов между тегами.
    pub(crate) fn body(&self, kind: ServiceKind) -> String {
        let name = self.name();
        let urn = kind.urn();
        let args = self.args();
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{name} xmlns:u=\"{urn}\">{args}</u:{name}></s:Body></s:Envelope>"
        )
    }
}

/// Код ошибки UPnP из ответа 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    Upnp(u16),
    /// Нет кода, код не один или формат неверен.
    NoCode,
}

/// Запись `GetSpecificPortMappingEntry`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) internal_port: u16,
    pub(crate) internal_client: Ipv4Addr,
    pub(crate) enabled: bool,
    /// Описание равно нашему `DESC` байт в байт после раскрытия сущностей.
    pub(crate) description_is_ours: bool,
    pub(crate) lease: u32,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entry(..)")
    }
}

/// Находит поля ответа: `Envelope/Body/<response>/<поле>`. Элемент ответа ровно один; каждое
/// ожидаемое поле не более одного раза; неизвестные дети игнорируются. Результат: по полю сырой
/// лист (`None` если поля нет).
fn extract<'a>(
    body: &'a [u8],
    response: &str,
    fields: &[&str],
) -> Result<Vec<Option<Leaf<'a>>>, SoapError> {
    let mut out: Vec<Option<Leaf<'a>>> = vec![None; fields.len()];
    let mut responses = 0usize;
    walk(body, |node| {
        match node {
            Node::Open { path } => {
                if path.len() == 1 && path.first() != Some(&"Envelope") {
                    return Err(SoapError::WrongRoot);
                }
                if path.len() == 3 && is_response_path(path, response) {
                    responses += 1;
                    if responses > 1 {
                        return Err(SoapError::Duplicate);
                    }
                }
            }
            Node::Close { path, leaf } => {
                if path.len() == 4
                    && path.get(..3).is_some_and(|p| is_response_path(p, response))
                    && let Some(name) = path.get(3)
                    && let Some(idx) = fields.iter().position(|f| f == name)
                    && let Some(slot) = out.get_mut(idx)
                {
                    if slot.is_some() {
                        return Err(SoapError::Duplicate);
                    }
                    *slot = Some(leaf);
                }
            }
        }
        Ok(())
    })?;
    if responses == 0 {
        return Err(SoapError::NoResponse);
    }
    Ok(out)
}

fn is_response_path(path: &[&str], response: &str) -> bool {
    path.len() >= 3
        && path.first() == Some(&"Envelope")
        && path.get(1) == Some(&"Body")
        && path.get(2) == Some(&response)
}

/// Обязательное поле как строка значения.
fn required(slot: Option<&Option<Leaf<'_>>>) -> Result<String, SoapError> {
    match slot.copied().flatten() {
        None => Err(SoapError::Missing),
        Some(Leaf::Branch) => Err(SoapError::Malformed),
        Some(l) => Ok(leaf_value(l)?),
    }
}

fn parse_lease(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok().filter(|&n| n <= 604_800)
}

fn parse_enabled(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

/// `GetExternalIPAddress`: пустая строка это `None` (роутер за CGNAT может отвечать пусто).
pub(crate) fn parse_external_ip(body: &[u8]) -> Result<Option<Ipv4Addr>, SoapError> {
    let f = extract(
        body,
        "GetExternalIPAddressResponse",
        &["NewExternalIPAddress"],
    )?;
    let v = required(f.first())?;
    if v.is_empty() {
        return Ok(None);
    }
    parse_ipv4(&v).map(Some).ok_or(SoapError::BadValue)
}

/// `AddAnyPortMapping`: `NewReservedPort` 1..=65535.
pub(crate) fn parse_add_any(body: &[u8]) -> Result<u16, SoapError> {
    let f = extract(body, "AddAnyPortMappingResponse", &["NewReservedPort"])?;
    parse_port(&required(f.first())?).ok_or(SoapError::BadValue)
}

/// `GetSpecificPortMappingEntry`: все пять полей обязательны.
pub(crate) fn parse_specific(body: &[u8]) -> Result<Entry, SoapError> {
    let f = extract(
        body,
        "GetSpecificPortMappingEntryResponse",
        &[
            "NewInternalPort",
            "NewInternalClient",
            "NewEnabled",
            "NewPortMappingDescription",
            "NewLeaseDuration",
        ],
    )?;
    let internal_port = parse_port(&required(f.first())?).ok_or(SoapError::BadValue)?;
    let internal_client = parse_ipv4(&required(f.get(1))?).ok_or(SoapError::BadValue)?;
    let enabled = parse_enabled(&required(f.get(2))?).ok_or(SoapError::BadValue)?;
    // чужое описание (не ASCII, длинное) просто не наше, это не ошибка разбора
    let description_is_ours = match f.get(3).copied().flatten() {
        None => return Err(SoapError::Missing),
        Some(Leaf::Branch) => return Err(SoapError::Malformed),
        Some(Leaf::Empty) => false,
        Some(Leaf::Text(t)) => value(t).is_ok_and(|v| v == DESC),
    };
    let lease = parse_lease(&required(f.get(4))?).ok_or(SoapError::BadValue)?;
    Ok(Entry {
        internal_port,
        internal_client,
        enabled,
        description_is_ours,
        lease,
    })
}

/// Ошибка 500: `Envelope/Body/Fault/detail/UPnPError/errorCode` ровно один раз, 1-4 цифры.
/// Всё остальное (в том числе обрыв разбора) это `NoCode`.
pub(crate) fn parse_fault(body: &[u8]) -> Fault {
    const CODE_PATH: [&str; 6] = [
        "Envelope",
        "Body",
        "Fault",
        "detail",
        "UPnPError",
        "errorCode",
    ];
    let mut codes: Vec<Leaf<'_>> = Vec::new();
    let r: Result<(), SoapError> = walk(body, |node| {
        if let Node::Close { path, leaf } = node
            && path == CODE_PATH
        {
            codes.push(leaf);
            if codes.len() > 1 {
                return Err(SoapError::Duplicate);
            }
        }
        Ok(())
    });
    let code = match (r, codes.first().copied()) {
        (Ok(()), Some(leaf)) => leaf_value(leaf).ok(),
        _ => None,
    };
    match code {
        Some(s) if (1..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse::<u16>().map_or(Fault::NoCode, Fault::Upnp)
        }
        _ => Fault::NoCode,
    }
}
