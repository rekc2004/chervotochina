//! Лимиты до аутентификации: лимитер по IP с ограниченной картой и ворота перебора Noise KK
//! (семафор и бюджет кандидатов до `spawn_blocking`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chervo_identity::{ChannelBinding, KK_MSG1_LEN, KK_MSG2_LEN, KkResponder, KxPeer, kk_respond};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep, timeout_at};

use crate::{QuinnConfig, TransportStats};

/// Счётчики адаптера (вместо журналов).
#[derive(Default)]
pub(crate) struct Counters {
    pub retry_sent: AtomicU64,
    pub ignored_rate: AtomicU64,
    pub ignored_busy: AtomicU64,
    pub auth_ok: AtomicU64,
    pub auth_failed: AtomicU64,
    pub auth_timeout: AtomicU64,
    pub duplicates_closed: AtomicU64,
    pub queue_full: AtomicU64,
    pub kk_trials: AtomicU64,
    pub kk_candidates: AtomicU64,
    pub kk_trials_peak: AtomicU64,
    pub kk_denied: AtomicU64,
    pub knock_ok: AtomicU64,
    pub knock_bad: AtomicU64,
    pub knock_replay: AtomicU64,
    pub knock_skewed: AtomicU64,
    pub dropped_unadmitted: AtomicU64,
    pub admit_full: AtomicU64,
    pub admit_exhausted: AtomicU64,
    pub connect_silent: AtomicU64,
    pub removed_closed: AtomicU64,
    kk_active: AtomicU64,
}

impl Counters {
    pub(crate) fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> TransportStats {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        TransportStats {
            retry_sent: g(&self.retry_sent),
            ignored_rate: g(&self.ignored_rate),
            ignored_busy: g(&self.ignored_busy),
            auth_ok: g(&self.auth_ok),
            auth_failed: g(&self.auth_failed),
            auth_timeout: g(&self.auth_timeout),
            duplicates_closed: g(&self.duplicates_closed),
            queue_full: g(&self.queue_full),
            kk_trials: g(&self.kk_trials),
            kk_candidates: g(&self.kk_candidates),
            kk_trials_peak: g(&self.kk_trials_peak),
            kk_denied: g(&self.kk_denied),
            knock_ok: g(&self.knock_ok),
            knock_bad: g(&self.knock_bad),
            knock_replay: g(&self.knock_replay),
            knock_skewed: g(&self.knock_skewed),
            dropped_unadmitted: g(&self.dropped_unadmitted),
            admit_full: g(&self.admit_full),
            admit_exhausted: g(&self.admit_exhausted),
            connect_silent: g(&self.connect_silent),
            removed_closed: g(&self.removed_closed),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Лимитер по IP
// ---------------------------------------------------------------------------------------------

/// Ключ лимитера: IPv4 целиком, IPv6 по /64, v4-mapped как IPv4.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IpKey {
    V4(u32),
    V6(u64),
}

pub(crate) fn ip_key(ip: IpAddr) -> IpKey {
    match ip {
        IpAddr::V4(a) => IpKey::V4(u32::from(a)),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => IpKey::V4(u32::from(v4)),
            None => IpKey::V6((u128::from(a) >> 64) as u64),
        },
    }
}

pub(crate) struct IpLimiter {
    max: u32,
    window: Duration,
    cap: usize,
    map: HashMap<IpKey, (Instant, u32)>,
}

impl IpLimiter {
    pub(crate) fn new(max: u32, window: Duration, cap: usize) -> Self {
        Self {
            max,
            window,
            cap: cap.max(1),
            map: HashMap::new(),
        }
    }

    /// Допустила бы `allow` это рукопожатие сейчас. Ничего не списывает и не вытесняет.
    pub(crate) fn would_allow(&self, ip: IpAddr, now: Instant) -> bool {
        if self.max == 0 {
            return false;
        }
        match self.map.get(&ip_key(ip)) {
            Some(e) => now.saturating_duration_since(e.0) >= self.window || e.1 < self.max,
            None => true,
        }
    }

    /// Можно ли принять ещё одно рукопожатие с этого адреса; учитывает попытку.
    pub(crate) fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.max == 0 {
            return false;
        }
        let key = ip_key(ip);
        if let Some(e) = self.map.get_mut(&key) {
            if now.saturating_duration_since(e.0) >= self.window {
                *e = (now, 1);
                return true;
            }
            if e.1 >= self.max {
                return false;
            }
            e.1 += 1;
            return true;
        }
        if self.map.len() >= self.cap {
            let oldest = self.map.iter().min_by_key(|(_, v)| v.0).map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.map.remove(&k);
            }
        }
        self.map.insert(key, (now, 1));
        true
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Списано рукопожатий в текущем окне (0, если ключа нет).
    #[cfg(test)]
    pub(crate) fn charged(&self, ip: IpAddr) -> u32 {
        self.map.get(&ip_key(ip)).map_or(0, |e| e.1)
    }
}

// ---------------------------------------------------------------------------------------------
// Ворота перебора KK
// ---------------------------------------------------------------------------------------------

/// Причина отказа ворот. Наружу (в сеть) не различается: адаптер на любую причину идёт в `refuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateError {
    /// Ворота не пропустили: семафор, бюджет или дедлайн до старта перебора.
    Denied,
    /// Перебор запущен, но дедлайн истёк до результата.
    TimedOut,
    /// Блокирующая задача упала или перебор вернул ошибку.
    Failed,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    /// Действующая ёмкость: не меньше `base_cap` и не меньше числа пар.
    cap: u32,
}

pub(crate) struct KkGate {
    sem: Arc<Semaphore>,
    bucket: Mutex<Bucket>,
    rate: u32,
    /// Ёмкость ведра из конфигурации (не меньше 1).
    base_cap: u32,
    counters: Arc<Counters>,
}

/// Уменьшает счётчик активных переборов при любом выходе из замыкания (в том числе при панике).
struct ActiveGuard(Arc<Counters>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.kk_active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl KkGate {
    pub(crate) fn new(cfg: &QuinnConfig, counters: Arc<Counters>) -> Self {
        let permits = cfg.max_kk_trials.clamp(1, cfg.max_preauth.max(1));
        let cap = cfg.kk_budget_burst.max(1);
        Self {
            sem: Arc::new(Semaphore::new(permits)),
            bucket: Mutex::new(Bucket {
                tokens: f64::from(cap),
                last: Instant::now(),
                cap,
            }),
            rate: cfg.kk_budget_per_sec,
            base_cap: cap,
            counters,
        }
    }

    /// Ёмкость ведра не меньше числа пар `n`: иначе стоимость перебора обрезалась бы до ёмкости, и
    /// реальная нагрузка превышала бы заданный `kk_budget_per_sec`. При росте добавленная часть
    /// выдаётся сразу; при уменьшении лишнее срезается. Ниже `kk_budget_burst` не опускается.
    pub(crate) fn set_min_burst(&self, n: usize) {
        let want = u32::try_from(n).unwrap_or(u32::MAX).max(self.base_cap);
        let mut b = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
        if want > b.cap {
            b.tokens += f64::from(want - b.cap);
        }
        b.cap = want;
        b.tokens = b.tokens.min(f64::from(want));
    }

    fn deny(&self) -> GateError {
        Counters::bump(&self.counters.kk_denied);
        GateError::Denied
    }

    /// Списывает `cost` кандидатов (не больше ёмкости ведра) или решает, что ждать нельзя.
    async fn take_budget(&self, deadline: Instant, cost: usize) -> Result<u64, GateError> {
        let cost = u32::try_from(cost).unwrap_or(u32::MAX);
        let c = loop {
            let wait = {
                let mut b = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
                let c = cost.min(b.cap);
                let need = f64::from(c);
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
                b.last = now;
                b.tokens = (b.tokens + elapsed * f64::from(self.rate)).min(f64::from(b.cap));
                if b.tokens >= need {
                    b.tokens -= need;
                    break c;
                }
                if self.rate == 0 {
                    return Err(self.deny());
                }
                let w = Duration::from_secs_f64((need - b.tokens) / f64::from(self.rate));
                if now + w > deadline {
                    return Err(self.deny());
                }
                w
            };
            sleep(wait).await;
        };
        self.counters
            .kk_candidates
            .fetch_add(u64::from(c), Ordering::Relaxed);
        Ok(u64::from(c))
    }

    /// Единственный путь запуска блокирующего перебора. Порядок: семафор, бюджет, затем
    /// блокирующая задача; разрешение живёт внутри замыкания.
    pub(crate) async fn run<R, F>(
        &self,
        deadline: Instant,
        cost: usize,
        f: F,
    ) -> Result<R, GateError>
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        let permit = match timeout_at(deadline, self.sem.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => return Err(self.deny()),
        };
        self.take_budget(deadline, cost).await?;
        let counters = self.counters.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now_active = counters.kk_active.fetch_add(1, Ordering::SeqCst) + 1;
            let _guard = ActiveGuard(counters.clone());
            counters
                .kk_trials_peak
                .fetch_max(now_active, Ordering::SeqCst);
            counters.kk_trials.fetch_add(1, Ordering::Relaxed);
            f()
        });
        match timeout_at(deadline, handle).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err(GateError::Failed),
            Err(_) => Err(GateError::TimedOut),
        }
    }

    /// Перебор KK через ворота. Любая ошибка перебора сводится к `Failed`.
    pub(crate) async fn respond(
        &self,
        deadline: Instant,
        snapshot: Arc<Vec<KxPeer>>,
        allowed: Vec<usize>,
        binding: ChannelBinding,
        msg1: [u8; KK_MSG1_LEN],
    ) -> Result<(KkResponder, [u8; KK_MSG2_LEN]), GateError> {
        let cost = allowed.len();
        let res = self
            .run(deadline, cost, move || {
                let refs: Vec<&KxPeer> = allowed.iter().filter_map(|i| snapshot.get(*i)).collect();
                kk_respond(&refs, &binding, &msg1).map_err(|_| ())
            })
            .await?;
        res.map_err(|_| GateError::Failed)
    }
}
