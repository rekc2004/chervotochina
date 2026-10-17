//! Извлечение из описания устройства: корневое устройство IGD, его UDN и службы подключения.
//! Пути элементов сравниваются по локальным именам; всё извлекается из листьев сканера.

use std::fmt;

use crate::error::DescError;
use crate::limits::{MAX_SERVICES, UDN_MAX};
use crate::scan::{Leaf, Node, leaf_value, walk};
use crate::url::{HttpTarget, Path, check_urlbase, control_url};

const IGD_V1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const IGD_V2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";

/// Вид службы; порядок объявления задаёт предпочтение (меньше значит лучше).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ServiceKind {
    WanIp2,
    WanIp1,
    WanPpp1,
}

impl ServiceKind {
    /// Наша константа типа службы; строка роутера в запросы не попадает.
    pub(crate) fn urn(self) -> &'static str {
        match self {
            ServiceKind::WanIp2 => "urn:schemas-upnp-org:service:WANIPConnection:2",
            ServiceKind::WanIp1 => "urn:schemas-upnp-org:service:WANIPConnection:1",
            ServiceKind::WanPpp1 => "urn:schemas-upnp-org:service:WANPPPConnection:1",
        }
    }

    fn from_urn(s: &str) -> Option<Self> {
        [
            ServiceKind::WanIp2,
            ServiceKind::WanIp1,
            ServiceKind::WanPpp1,
        ]
        .into_iter()
        .find(|k| k.urn() == s)
    }
}

/// Идентификатор корневого устройства (`uuid:...`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Udn(String);

impl Udn {
    /// `uuid:` и символы `A-Za-z0-9-:._`, длина не более `UDN_MAX`.
    pub(crate) fn parse(s: &str) -> Result<Self, DescError> {
        let ok = s.len() <= UDN_MAX
            && s.starts_with("uuid:")
            && s.len() > 5
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'.' | b'_'));
        if ok {
            Ok(Udn(s.to_owned()))
        } else {
            Err(DescError::BadUdn)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Udn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Udn(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Service {
    pub(crate) kind: ServiceKind,
    pub(crate) control: Path,
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Service(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Description {
    pub(crate) udn: Udn,
    pub(crate) services: Vec<Service>,
}

impl fmt::Debug for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Description(..)")
    }
}

/// Накопитель полей одного элемента `service`.
struct ServiceAcc {
    /// Длина пути самого элемента `service`.
    depth: usize,
    service_type: Option<String>,
    control_url: Option<String>,
}

/// Лист или отказ документу; пустое значение допустимо, ветка нет.
fn text_of(leaf: Leaf<'_>) -> Result<String, DescError> {
    match leaf {
        Leaf::Branch => Err(DescError::Malformed),
        l => Ok(leaf_value(l)?),
    }
}

/// Записывает значение в слот ровно один раз.
fn set_once(slot: &mut Option<String>, v: String) -> Result<(), DescError> {
    if slot.is_some() {
        return Err(DescError::Duplicate);
    }
    *slot = Some(v);
    Ok(())
}

pub(crate) fn parse_description(
    body: &[u8],
    location: &HttpTarget,
) -> Result<Description, DescError> {
    let mut devices_under_root = 0usize;
    let mut device_type: Option<String> = None;
    let mut udn: Option<String> = None;
    let mut urlbase: Option<String> = None;
    let mut current: Option<ServiceAcc> = None;
    let mut found: Vec<Service> = Vec::new();

    walk(body, |node| {
        match node {
            Node::Open { path } => {
                let name = path.last().copied().unwrap_or_default();
                if path.len() == 1 && name != "root" {
                    return Err(DescError::NotRoot);
                }
                if path.len() == 2 && name == "device" && path.first() == Some(&"root") {
                    devices_under_root += 1;
                }
                if name == "service" {
                    if current.is_some() {
                        return Err(DescError::Malformed);
                    }
                    current = Some(ServiceAcc {
                        depth: path.len(),
                        service_type: None,
                        control_url: None,
                    });
                }
            }
            Node::Close { path, leaf } => {
                let name = path.last().copied().unwrap_or_default();
                // поля корневого устройства: первое `device` прямо под `root`
                let in_root_device = devices_under_root == 1
                    && path.len() == 3
                    && path.first() == Some(&"root")
                    && path.get(1) == Some(&"device");
                if in_root_device && name == "deviceType" {
                    set_once(&mut device_type, text_of(leaf)?)?;
                } else if in_root_device && name == "UDN" {
                    set_once(&mut udn, text_of(leaf)?)?;
                } else if path.len() == 2 && name == "URLBase" && path.first() == Some(&"root") {
                    set_once(&mut urlbase, text_of(leaf)?)?;
                }
                // поля службы: прямые дочерние элементы `service`
                if let Some(acc) = current.as_mut()
                    && path.len() == acc.depth + 1
                {
                    if name == "serviceType" {
                        set_once(&mut acc.service_type, text_of(leaf)?)?;
                    } else if name == "controlURL" {
                        set_once(&mut acc.control_url, text_of(leaf)?)?;
                    }
                }
                // конец `service`
                let closes_service =
                    current.as_ref().is_some_and(|a| path.len() == a.depth) && name == "service";
                if closes_service && let Some(acc) = current.take() {
                    let kind = acc.service_type.as_deref().and_then(ServiceKind::from_urn);
                    if let Some(kind) = kind {
                        let raw = acc.control_url.ok_or(DescError::MissingControl)?;
                        found.push(Service {
                            kind,
                            control: control_url(&raw, location)?,
                        });
                    }
                }
            }
        }
        Ok(())
    })?;

    if let Some(base) = urlbase {
        check_urlbase(&base, location)?;
    }
    match device_type.as_deref() {
        Some(IGD_V1 | IGD_V2) => {}
        _ => return Err(DescError::NotIgd),
    }
    let udn = Udn::parse(&udn.ok_or(DescError::MissingUdn)?)?;

    // порядок WanIp2, WanIp1, WanPpp1 (стабильно), без повторов (вид, путь), не более MAX_SERVICES
    found.sort_by_key(|s| s.kind);
    let mut services: Vec<Service> = Vec::new();
    for s in found {
        if !services.contains(&s) {
            services.push(s);
        }
    }
    services.truncate(MAX_SERVICES);
    if services.is_empty() {
        return Err(DescError::NoService);
    }
    Ok(Description { udn, services })
}
