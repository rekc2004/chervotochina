//! Контракт автоматического проброса порта (этап 13а, часть U0): типы и блокирующий
//! интерфейс. Реализация (UPnP) живёт в `chervo-upnp`, потребитель (`chervo-connect`) видит
//! только этот интерфейс. Сокетного кода здесь нет.

use std::fmt;
use std::net::SocketAddrV4;
use std::time::Duration;

use crate::own::GatewayInfo;

/// Что пробросить: собственный маршрутный IPv4 (частный) и порт прослушивания (не 0).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MapRequest {
    pub internal: SocketAddrV4,
}

impl fmt::Debug for MapRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapRequest(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MapStatus {
    Off,
    NotHomeNetwork,
    NoGateway,
    Ambiguous,
    WanUnknown,
    BehindCgnat,
    DoubleNat,
    NeedPermanentConsent,
    Refused(u16),
    Failed,
    Mapped,
    MappedPermanent,
}

/// Итог одного вызова. `gateway` заполнен только по правилам этапа 13а: `mapping` лишь после
/// подтверждения `GetSpecificPortMappingEntry`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MapReport {
    pub status: MapStatus,
    pub gateway: Option<GatewayInfo>,
    pub retry_after: Duration,
}

impl fmt::Debug for MapReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapReport(..)")
    }
}

pub trait PortMapper: Send + Sync {
    /// Блокирующий вызов. Возвращается не позже 25 с, что бы ни делала сеть.
    fn refresh(&self, req: MapRequest) -> MapReport;
    /// Блокирующий вызов, не более 5 с. Удаляет текущий проброс, если роутер всё ещё
    /// показывает его нашим.
    fn release(&self);
}
