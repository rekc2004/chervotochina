//! Пределы и константы маяка (этап 13в). Адрес группы и порт записаны только здесь.

use std::net::Ipv4Addr;
use std::time::Duration;

use chervo_identity::{LAN_NONCE_LEN, LAN_SLOT_LEN};

/// Группа «все узлы» (RFC 1112): в неё входят все узлы сети, отчёты IGMP на неё не шлются.
pub(crate) const LAN_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// Порт маяка. Вне диапазона 49152-65535, чтобы не совпасть с нашим случайным портом
/// прослушивания.
pub const LAN_PORT: u16 = 45817;
/// Длина датаграммы: `ver(1) || reserved(1) || nonce(12) || слоты 16 * 26`.
pub(crate) const DGRAM_LEN: usize = 430;
/// Буфер приёма: больше датаграммы, чтобы переполнение буфера отличалось от точной длины.
pub(crate) const RECV_BUF: usize = 512;
/// Слотов в датаграмме.
pub(crate) const SLOTS: usize = 16;
pub(crate) const MAX_DGRAMS_PER_ROUND: usize = 4;
/// Предел числа пар в таблице.
pub(crate) const MAX_PEERS: usize = 1024;
/// Период раунда и разброс (± JITTER).
pub(crate) const INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const JITTER: Duration = Duration::from_secs(5);
/// Серия раундов после запуска, смены адреса или набора пар.
pub(crate) const BURST: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(7),
];
/// Жёсткий бюджет отправки: датаграмм за окно.
pub(crate) const SEND_BUDGET_COUNT: usize = 24;
pub(crate) const SEND_BUDGET_WINDOW: Duration = Duration::from_secs(60);
/// Глобальное ограничение приёма: датаграмм в секунду и всплеск.
pub(crate) const RX_RATE: u32 = 32;
pub(crate) const RX_BURST: u32 = 64;
/// С одного адреса: датаграмм за окно; адресов в карте.
pub(crate) const PER_IP: u32 = 16;
pub(crate) const PER_IP_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const IP_MAP: usize = 256;
/// Очередь находок.
pub(crate) const MAX_SIGHTINGS: usize = 64;
pub(crate) const READ_TIMEOUT: Duration = Duration::from_millis(250);
pub(crate) const FAIL_RETRY: Duration = Duration::from_secs(60);
/// Интерфейсов, на которых идёт поиск (опрос маршрутов находит их до этого числа).
pub(crate) const MAX_IFACES: usize = 4;
/// Повторный опрос маршрутов, пока служба не в режиме `Off`.
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Порт целей опроса: пакет не отправляется, порт нужен только для `connect`.
pub(crate) const SWEEP_PORT: u16 = 9;
/// Через сколько обращений к опросу проверяется остановка.
pub(crate) const SWEEP_CHUNK: usize = 64;

const _: () = assert!(DGRAM_LEN == 2 + LAN_NONCE_LEN + SLOTS * LAN_SLOT_LEN);
const _: () = assert!(RECV_BUF > DGRAM_LEN);
const _: () = assert!(LAN_PORT < 49152);
