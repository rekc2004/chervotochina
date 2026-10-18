//! Часы и проба маршрута. Время для подписей и сроков берётся только отсюда.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chervo_addr::{RouteSources, probe_route_sources, route_source_for};

/// Секунды UTC с учётом поправки пользователя.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

/// Поправка часов вне допустимого предела.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockRangeError;

impl fmt::Display for ClockRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("clock offset out of range")
    }
}

impl std::error::Error for ClockRangeError {}

/// Предел поправки: 7 суток в миллисекундах.
const MAX_OFFSET_MS: i64 = 7 * 24 * 3600 * 1000;

pub struct SystemClock {
    offset_ms: AtomicI64,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            offset_ms: AtomicI64::new(0),
        }
    }

    /// `|ms| <= 7 суток`.
    pub fn set_offset_ms(&self, ms: i64) -> Result<(), ClockRangeError> {
        if ms.unsigned_abs() > MAX_OFFSET_MS.unsigned_abs() {
            return Err(ClockRangeError);
        }
        self.offset_ms.store(ms, Ordering::Relaxed);
        Ok(())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SystemClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemClock(..)")
    }
}

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let adjusted = ms.saturating_add(self.offset_ms.load(Ordering::Relaxed));
        u64::try_from(adjusted.max(0)).unwrap_or(0) / 1000
    }
}

/// Источник сведений о маршруте (для тестов подменяется).
pub trait RouteProbe: Send + Sync {
    fn probe(&self) -> RouteSources;
    /// Наш адрес-источник на маршруте к `target` (пакет не отправляется). `None`: адрес не
    /// определён. Вызывается вне замка состояния.
    fn source_for(&self, target: SocketAddr) -> Option<IpAddr>;
}

/// Настоящая проба: `chervo_addr::probe_route_sources`.
pub struct SystemProbe;

impl RouteProbe for SystemProbe {
    fn probe(&self) -> RouteSources {
        probe_route_sources()
    }

    fn source_for(&self, target: SocketAddr) -> Option<IpAddr> {
        route_source_for(target)
    }
}
