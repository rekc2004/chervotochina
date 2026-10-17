//! Пределы разбора и времени (этап 13а, U1). Все значения заданы спецификацией.

use std::time::Duration;

/// Максимальный размер датаграммы SSDP (1500 минус IP и UDP).
pub(crate) const SSDP_DGRAM_MAX: usize = 1472;
/// Буфер приёма SSDP: датаграмма, заполнившая буфер, отбрасывается.
pub(crate) const SSDP_RECV_BUF: usize = 2048;
pub(crate) const SSDP_MAX_HEADERS: usize = 20;
pub(crate) const SSDP_MAX_DGRAMS: usize = 64;
pub(crate) const MAX_RESPONDERS: usize = 8;
pub(crate) const DISCOVERY_WINDOW: Duration = Duration::from_secs(2);
pub(crate) const HTTP_DEADLINE: Duration = Duration::from_secs(3);
/// Строка состояния и заголовки вместе с пустой строкой.
pub(crate) const HTTP_HEAD_MAX: usize = 8192;
pub(crate) const HTTP_MAX_HEADERS: usize = 64;
pub(crate) const BODY_MAX: usize = 65536;
pub(crate) const XML_MAX_DEPTH: usize = 16;
pub(crate) const XML_MAX_ELEMENTS: usize = 2048;
pub(crate) const XML_NAME_MAX: usize = 64;
/// Объявление `<?xml ... ?>` целиком, с `<?` и `?>`.
pub(crate) const XML_DECL_MAX: usize = 128;
pub(crate) const VALUE_MAX: usize = 256;
pub(crate) const PATH_MAX: usize = 256;
pub(crate) const UDN_MAX: usize = 128;
pub(crate) const MAX_SERVICES: usize = 4;
pub(crate) const LEASE_SECS: u32 = 3600;
pub(crate) const MIN_RENEW: Duration = Duration::from_secs(60);
pub(crate) const MAX_REFRESH: Duration = Duration::from_secs(25);
pub(crate) const RELEASE_BUDGET: Duration = Duration::from_secs(5);
pub(crate) const ALT_PORT_TRIES: usize = 3;
pub(crate) const MAX_ROUTERS: usize = 4;
/// Нейтральное описание нашего проброса (видно любому устройству сети).
pub(crate) const DESC: &str = "udp";
/// Адрес multicast SSDP: единственное место в крейте, где он записан.
pub(crate) const SSDP_HOST: &str = "239.255.255.250:1900";
