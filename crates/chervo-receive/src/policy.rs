//! Решение о приёме предложения (спецификация 15, решение 15). По умолчанию спрашиваем.
//! Автоприём только для друга с явным `Permission::AutoAccept`, в пределах его лимитов и
//! общего потолка за скользящие 24 часа, и только если все файлы обычные, имена чистые
//! (ни одного изменения и флага), а путь короткий. Программы, образы дисков и документы с
//! макросами не принимаются автоматически никогда. Архивы по решению владельца обычные файлы.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use chervo_friends::{AutoAcceptLimits, Permission};
use chervo_identity::PairId;
use chervo_transfer::{AcceptPolicy, OfferView, PolicyVerdict};

use crate::limits::ReceiveLimits;
use crate::plan::plan_offer_for_root;
use crate::root::{ReceiveConfig, ReceiveRoot};

/// Окно учёта автоприёма.
const WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

type Clock = dyn Fn() -> Instant + Send + Sync;
type Usage = VecDeque<(Instant, u64, u32)>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct ReceivePolicy {
    root: ReceiveRoot,
    limits: ReceiveLimits,
    ceiling: AutoAcceptLimits,
    quota: Mutex<HashMap<PairId, Usage>>,
    declined: AtomicU64,
    clock: Arc<Clock>,
}

impl std::fmt::Debug for ReceivePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceivePolicy(..)")
    }
}

impl ReceivePolicy {
    pub fn new(root: ReceiveRoot, cfg: &ReceiveConfig) -> Self {
        Self::with_clock(root, cfg, Arc::new(Instant::now))
    }

    /// Свои часы (проверка скользящего окна в тестах).
    #[doc(hidden)]
    pub fn with_clock(root: ReceiveRoot, cfg: &ReceiveConfig, clock: Arc<Clock>) -> Self {
        let limits = if cfg.limits.validate().is_ok() {
            cfg.limits
        } else {
            ReceiveLimits::default()
        };
        Self {
            root,
            limits,
            ceiling: cfg.auto_ceiling,
            quota: Mutex::new(HashMap::new()),
            declined: AtomicU64::new(0),
            clock,
        }
    }

    /// Сколько предложений отклонено автоматически как враждебные (для экрана, этап 18).
    pub fn declined_hostile(&self) -> u64 {
        self.declined.load(Ordering::SeqCst)
    }

    /// Укладывается ли предложение в остаток окна друга; при успехе записывает расход.
    fn take_quota(&self, pair: &PairId, bytes: u64, files: u32, eff: AutoAcceptLimits) -> bool {
        if bytes > eff.max_total_bytes || files > eff.max_files {
            return false;
        }
        let now = (self.clock)();
        let mut q = lock(&self.quota);
        let usage = q.entry(*pair).or_default();
        while usage
            .front()
            .is_some_and(|(t, _, _)| now.saturating_duration_since(*t) >= WINDOW)
        {
            usage.pop_front();
        }
        let (used_b, used_f) = usage.iter().fold((0u64, 0u32), |(b, f), (_, ub, uf)| {
            (b.saturating_add(*ub), f.saturating_add(*uf))
        });
        let fits = used_b
            .checked_add(bytes)
            .is_some_and(|b| b <= eff.max_total_bytes)
            && used_f
                .checked_add(files)
                .is_some_and(|f| f <= eff.max_files);
        if fits {
            usage.push_back((now, bytes, files));
        }
        fits
    }
}

impl AcceptPolicy for ReceivePolicy {
    fn decide(&self, pair: &PairId, p: Permission, offer: &OfferView) -> PolicyVerdict {
        let Ok(plan) = plan_offer_for_root(&offer.files, &self.limits, &self.root) else {
            self.declined.fetch_add(1, Ordering::SeqCst);
            return PolicyVerdict::Decline;
        };
        let Permission::AutoAccept(l) = p else {
            return PolicyVerdict::Ask;
        };
        let eff = AutoAcceptLimits {
            max_total_bytes: l.max_total_bytes.min(self.ceiling.max_total_bytes),
            max_files: l.max_files.min(self.ceiling.max_files),
        };
        let Ok(files) = u32::try_from(plan.files.len()) else {
            return PolicyVerdict::Ask;
        };
        if plan.auto_ok() && self.take_quota(pair, plan.total, files, eff) {
            PolicyVerdict::Accept
        } else {
            PolicyVerdict::Ask
        }
    }
}
