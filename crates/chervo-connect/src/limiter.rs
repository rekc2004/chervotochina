//! Ограничитель набора номера для каждого назначения (обзор 12, M1; решение 5 спецификации).
//!
//! Ключ записи: нормализованный `SocketAddr`. Отдельно считается предел на IP по всем парам и
//! портам: сколько раз за `per_ip_window` мы позволили себе стучать на этот IP. Адрес из книги
//! друга (любой источник, любые флаги) может попасть в набор только через `take`. Вся
//! арифметика насыщающая: ни переполнения, ни паники.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use chervo_addr::normalize;
use tokio::time::Instant;

use crate::config::ConnectConfig;

/// Год: запасной срок, когда сумма времени не помещается в `Instant`.
const FAR: Duration = Duration::from_secs(365 * 24 * 3600);

/// `Instant + Duration` без паники.
pub(crate) fn add_sat(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).or_else(|| t.checked_add(FAR)).unwrap_or(t)
}

#[derive(Clone, Copy)]
struct Entry {
    fails: u32,
    next: Instant,
    last_use: Instant,
    /// Когда адрес в последний раз вошёл в набор (`take`). Сбросы и быстрое окно его не трогают.
    last_take: Option<Instant>,
}

/// Запас к `dial_base` для адресов со слов друга: транспорт запускает адрес `i` набора через
/// `i * connect_stagger` (до 8 адресов по 250 мс), и серия у адресата не должна сблизиться
/// с прошлой из-за сдвига номера адреса в наборе.
const STRICT_MARGIN: Duration = Duration::from_secs(2);

pub(crate) struct Limiter {
    strict_floor: Duration,
    base: Duration,
    cap: Duration,
    hint_base: Duration,
    hint_cap: Duration,
    fast_period: Duration,
    per_ip_dials: u32,
    per_ip_window: Duration,
    capacity: usize,
    entries: HashMap<SocketAddr, Entry>,
    ip_log: HashMap<IpAddr, VecDeque<Instant>>,
}

/// `base << (fails - 1)`, но не больше `cap`; без переполнения.
pub(crate) fn backoff(base: Duration, cap: Duration, fails: u32) -> Duration {
    let shift = fails.saturating_sub(1).min(30);
    let mult = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    base.checked_mul(mult).unwrap_or(cap).min(cap)
}

impl Limiter {
    pub(crate) fn new(cfg: &ConnectConfig) -> Self {
        Self {
            strict_floor: cfg.dial_base.saturating_add(STRICT_MARGIN),
            base: cfg.dial_base,
            cap: cfg.dial_cap,
            hint_base: cfg.hint_base,
            hint_cap: cfg.hint_cap,
            fast_period: cfg.fast_period,
            per_ip_dials: cfg.per_ip_dials,
            per_ip_window: cfg.per_ip_window,
            capacity: cfg.limiter_capacity,
            entries: HashMap::new(),
            ip_log: HashMap::new(),
        }
    }

    fn recent(&self, ip: &IpAddr, now: Instant) -> usize {
        self.ip_log.get(ip).map_or(0, |log| {
            log.iter()
                .filter(|t| now.saturating_duration_since(**t) < self.per_ip_window)
                .count()
        })
    }

    /// Можно ли сейчас стучать на адрес: срок записи наступил и предел на IP не исчерпан.
    /// `strict` (адрес со слов друга): ещё и не раньше `dial_base` + запас после прошлого
    /// набора этого адреса, что бы ни делали быстрое окно, `connect_now` и новые обновления.
    pub(crate) fn allow(&self, addr: SocketAddr, strict: bool, now: Instant) -> bool {
        let addr = normalize(addr);
        if let Some(e) = self.entries.get(&addr) {
            if e.next > now {
                return false;
            }
            if strict
                && e.last_take
                    .is_some_and(|t| add_sat(t, self.strict_floor) > now)
            {
                return false;
            }
        }
        let used = self.recent(&addr.ip(), now);
        u32::try_from(used).is_ok_and(|u| u < self.per_ip_dials)
    }

    /// Записать попытку по каждому адресу (предел на IP и учёт давности использования).
    pub(crate) fn charge(&mut self, addrs: &[SocketAddr], now: Instant) {
        for a in addrs {
            let a = normalize(*a);
            let window = self.per_ip_window;
            let log = self.ip_log.entry(a.ip()).or_default();
            while log
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= window)
            {
                log.pop_front();
            }
            log.push_back(now);
            self.touch(a, now);
            if let Some(e) = self.entries.get_mut(&a) {
                e.last_take = Some(now);
            }
        }
        self.trim_ip_log(now);
    }

    /// `allow` и сразу `charge`: единственный путь адреса в набор номера.
    pub(crate) fn take(&mut self, addr: SocketAddr, strict: bool, now: Instant) -> bool {
        if !self.allow(addr, strict, now) {
            return false;
        }
        self.charge(&[addr], now);
        true
    }

    fn touch(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.last_use = now;
            return;
        }
        self.entries.insert(
            addr,
            Entry {
                fails: 0,
                next: now,
                last_use: now,
                last_take: None,
            },
        );
        self.evict_entries();
    }

    /// Сверх ёмкости вытесняется запись с самым давним использованием.
    fn evict_entries(&mut self) {
        while self.entries.len() > self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(a, e)| (e.last_use, **a))
                .map(|(a, _)| *a);
            match oldest {
                Some(a) => {
                    self.entries.remove(&a);
                }
                None => break,
            }
        }
    }

    /// Журнал IP не растёт без предела: сперва убирается всё устаревшее, затем самое давнее.
    fn trim_ip_log(&mut self, now: Instant) {
        if self.ip_log.len() <= self.capacity {
            return;
        }
        let window = self.per_ip_window;
        self.ip_log.retain(|_, log| {
            log.back()
                .is_some_and(|t| now.saturating_duration_since(*t) < window)
        });
        while self.ip_log.len() > self.capacity {
            let oldest = self
                .ip_log
                .iter()
                .min_by_key(|(ip, log)| (log.back().copied(), **ip))
                .map(|(ip, _)| *ip);
            match oldest {
                Some(ip) => {
                    self.ip_log.remove(&ip);
                }
                None => break,
            }
        }
    }

    /// Неудача набора: `fails += 1`; в быстром окне следующая попытка через `fast_period`,
    /// иначе через `min(base << (fails - 1), cap)` (для подсказок свои значения).
    pub(crate) fn failed(&mut self, addrs: &[SocketAddr], hint: bool, fast: bool, now: Instant) {
        let (base, cap) = if hint {
            (self.hint_base, self.hint_cap)
        } else {
            (self.base, self.cap)
        };
        for a in addrs {
            let a = normalize(*a);
            self.touch(a, now);
            if let Some(e) = self.entries.get_mut(&a) {
                e.fails = e.fails.saturating_add(1);
                let wait = if fast {
                    self.fast_period
                } else {
                    backoff(base, cap, e.fails)
                };
                e.next = add_sat(now, wait);
                e.last_use = now;
            }
        }
    }

    /// Успех: запись снимается.
    pub(crate) fn succeeded(&mut self, addr: SocketAddr) {
        self.entries.remove(&normalize(addr));
    }

    /// Новый номер обновления от друга: `fails = 0, next = now` для адресов этой пары.
    pub(crate) fn reset_pair(&mut self, addrs: &[SocketAddr], now: Instant) {
        for a in addrs {
            if let Some(e) = self.entries.get_mut(&normalize(*a)) {
                e.fails = 0;
                e.next = now;
            }
        }
    }

    /// Смена собственных адресов: у всех записей `fails = 0, next = now`. Предел на IP остаётся.
    pub(crate) fn reset_all(&mut self, now: Instant) {
        for e in self.entries.values_mut() {
            e.fails = 0;
            e.next = now;
        }
    }

    #[cfg(test)]
    pub(crate) fn entry_state(&self, addr: SocketAddr, now: Instant) -> Option<(u32, Duration)> {
        self.entries
            .get(&normalize(addr))
            .map(|e| (e.fails, e.next.saturating_duration_since(now)))
    }

    #[cfg(test)]
    pub(crate) fn entries_len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn has_entry(&self, addr: SocketAddr) -> bool {
        self.entries.contains_key(&normalize(addr))
    }
}
