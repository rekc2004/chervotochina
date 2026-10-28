//! Ограничение приёма до разбора: общая корзина токенов и окно «не больше N за T» по адресу
//! источника (карта ограничена, самый старый вытесняется). Арифметика с насыщением.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::limits::{IP_MAP, PER_IP, PER_IP_WINDOW, RX_BURST, RX_RATE};

/// Одна «монета» = 1_000_000 микрототенов; пополнение `rate` монет в секунду = `rate` микрототенов
/// за микросекунду.
const TOKEN: u64 = 1_000_000;

pub(crate) struct TokenBucket {
    rate: u64,
    cap: u64,
    tokens: u64,
    last: Instant,
}

impl fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenBucket(..)")
    }
}

impl TokenBucket {
    /// Корзина полная.
    pub(crate) fn new(rate_per_sec: u32, burst: u32, now: Instant) -> Self {
        let cap = u64::from(burst).saturating_mul(TOKEN);
        Self {
            rate: u64::from(rate_per_sec),
            cap,
            tokens: cap,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if us == 0 {
            return;
        }
        self.tokens = self
            .tokens
            .saturating_add(us.saturating_mul(self.rate))
            .min(self.cap);
        // `last` сдвигается ровно на учтённые микросекунды: частые вызовы не теряют долю.
        self.last = self
            .last
            .checked_add(Duration::from_micros(us))
            .unwrap_or(now);
    }

    /// Взять одну монету. `false`: корзина пуста.
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        match self.tokens.checked_sub(TOKEN) {
            Some(rest) => {
                self.tokens = rest;
                true
            }
            None => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RxVerdict {
    Pass,
    /// Общий предел.
    DropGlobal,
    /// Предел по адресу источника.
    DropIp,
}

struct IpWindow {
    start: Instant,
    count: u32,
}

pub(crate) struct RxLimiter {
    global: TokenBucket,
    per_ip: HashMap<Ipv4Addr, IpWindow>,
    per_ip_max: u32,
    per_ip_window: Duration,
    map_cap: usize,
    dropped_global: u64,
    dropped_ip: u64,
}

impl fmt::Debug for RxLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RxLimiter(..)")
    }
}

impl RxLimiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self::with_params(RX_RATE, RX_BURST, PER_IP, PER_IP_WINDOW, IP_MAP, now)
    }

    pub(crate) fn with_params(
        rate: u32,
        burst: u32,
        per_ip_max: u32,
        per_ip_window: Duration,
        map_cap: usize,
        now: Instant,
    ) -> Self {
        Self {
            global: TokenBucket::new(rate, burst, now),
            per_ip: HashMap::new(),
            per_ip_max,
            per_ip_window,
            map_cap: map_cap.max(1),
            dropped_global: 0,
            dropped_ip: 0,
        }
    }

    /// Проверка до разбора. Сначала общая корзина (токен расходуется всегда), затем адрес.
    /// Адреса не IPv4 учитываются только в общей корзине (разборщик их отбросит).
    pub(crate) fn check(&mut self, now: Instant, src: SocketAddr) -> RxVerdict {
        if !self.global.take(now) {
            self.dropped_global = self.dropped_global.saturating_add(1);
            return RxVerdict::DropGlobal;
        }
        let SocketAddr::V4(v4) = src else {
            return RxVerdict::Pass;
        };
        let ip = *v4.ip();
        if !self.per_ip.contains_key(&ip) && self.per_ip.len() >= self.map_cap {
            self.evict_oldest();
        }
        let w = self.per_ip.entry(ip).or_insert(IpWindow {
            start: now,
            count: 0,
        });
        if now.saturating_duration_since(w.start) >= self.per_ip_window {
            w.start = now;
            w.count = 0;
        }
        if w.count >= self.per_ip_max {
            self.dropped_ip = self.dropped_ip.saturating_add(1);
            return RxVerdict::DropIp;
        }
        w.count = w.count.saturating_add(1);
        RxVerdict::Pass
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .per_ip
            .iter()
            .min_by_key(|(_, w)| w.start)
            .map(|(ip, _)| *ip);
        if let Some(ip) = oldest {
            self.per_ip.remove(&ip);
        }
    }

    pub(crate) fn dropped_global(&self) -> u64 {
        self.dropped_global
    }

    pub(crate) fn dropped_ip(&self) -> u64 {
        self.dropped_ip
    }

    pub(crate) fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }
}
