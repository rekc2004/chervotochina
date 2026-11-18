//! Лимиты сервера (этап 13д, Р4): на ключ (IPv4 /32, IPv6 /64) не больше `burst` ответов за
//! окно, всего не больше `global` ответов в секунду, в таблице не больше `max_tracked` ключей.
//! Когда таблица полна, новый ключ сразу считается превысившим лимит. Устаревшие ключи
//! выбрасываются не реже раза в секунду: адреса не хранятся дольше окна лимита и секунды.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::{GLOBAL_PER_SEC, MAX_TRACKED, PER_IP_BURST, PER_IP_WINDOW};

/// Ключ лимита: IPv4 целиком, IPv6 по первым 64 битам.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    V4(u32),
    V6(u64),
}

pub(crate) fn key_of(ip: IpAddr) -> Key {
    match ip.to_canonical() {
        IpAddr::V4(a) => Key::V4(u32::from(a)),
        IpAddr::V6(a) => Key::V6((u128::from(a) >> 64) as u64),
    }
}

pub(crate) struct Limiter {
    burst: u32,
    window: Duration,
    max_tracked: usize,
    global_per_sec: u32,
    table: HashMap<Key, (Instant, u32)>,
    global: (Instant, u32),
    last_purge: Instant,
}

impl Limiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self::with_limits(
            PER_IP_BURST,
            PER_IP_WINDOW,
            MAX_TRACKED,
            GLOBAL_PER_SEC,
            now,
        )
    }

    pub(crate) fn with_limits(
        burst: u32,
        window: Duration,
        max_tracked: usize,
        global_per_sec: u32,
        now: Instant,
    ) -> Self {
        Self {
            burst,
            window,
            max_tracked,
            global_per_sec,
            table: HashMap::new(),
            global: (now, 0),
            last_purge: now,
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.table.len()
    }

    /// Можно ли ответить этому ключу сейчас. Расходует лимит только при `true`.
    pub(crate) fn allow(&mut self, key: Key, now: Instant) -> bool {
        self.purge(now);
        if now.saturating_duration_since(self.global.0) >= Duration::from_secs(1) {
            self.global = (now, 0);
        }
        if self.global.1 >= self.global_per_sec {
            return false;
        }
        let ok = match self.table.get_mut(&key) {
            Some(entry) => {
                if now.saturating_duration_since(entry.0) >= self.window {
                    *entry = (now, 0);
                }
                if entry.1 >= self.burst {
                    false
                } else {
                    entry.1 += 1;
                    true
                }
            }
            None => {
                if self.table.len() >= self.max_tracked {
                    false
                } else {
                    self.table.insert(key, (now, 1));
                    true
                }
            }
        };
        if ok {
            self.global.1 += 1;
        }
        ok
    }

    /// Выбросить ключи, чьё окно истекло; не чаще раза в секунду (или в окно, если оно короче).
    fn purge(&mut self, now: Instant) {
        let every = self.window.min(Duration::from_secs(1));
        if now.saturating_duration_since(self.last_purge) < every {
            return;
        }
        self.last_purge = now;
        let window = self.window;
        self.table
            .retain(|_, e| now.saturating_duration_since(e.0) < window);
    }
}
