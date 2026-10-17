//! Решение о приёме предложения (спецификация 15, решение 15 в редакции Рев. 3, решения
//! владельца 2026-10-18). По умолчанию спрашиваем. Автоприём только для друга с явным
//! `Permission::AutoAccept` (его включают после вопроса доверия, см. `trust.rs`) и только если
//! каждый файл заведомо безопасного типа (список `KNOWN_INERT`), имена чистые (ни одного
//! изменения и флага), а путь короткий. Любой другой или неизвестный тип, программы, образы
//! дисков, документы с макросами: вопрос пользователю. Лимитов объёма нет. Единственная
//! защита: после приёма на томе должно остаться не меньше `min_free_percent` процентов; если
//! места не хватает или оно неизвестно, это обычный вопрос.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chervo_friends::Permission;
use chervo_identity::PairId;
use chervo_transfer::{AcceptPolicy, OfferView, PolicyVerdict};

use crate::limits::ReceiveLimits;
use crate::plan::plan_offer_for_root;
use crate::root::{ReceiveConfig, ReceiveRoot};
use crate::space::{DiskSpace, disk_space};

type SpaceProbe = dyn Fn(&Path) -> Option<DiskSpace> + Send + Sync;

pub struct ReceivePolicy {
    root: ReceiveRoot,
    limits: ReceiveLimits,
    min_free_percent: u8,
    declined: AtomicU64,
    probe: Arc<SpaceProbe>,
}

impl std::fmt::Debug for ReceivePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceivePolicy(..)")
    }
}

impl ReceivePolicy {
    pub fn new(root: ReceiveRoot, cfg: &ReceiveConfig) -> Self {
        Self::with_space_probe(root, cfg, Arc::new(disk_space))
    }

    /// Свой способ узнать свободное место (тесты; на Windows `disk_space` ничего не знает).
    #[doc(hidden)]
    pub fn with_space_probe(
        root: ReceiveRoot,
        cfg: &ReceiveConfig,
        probe: Arc<SpaceProbe>,
    ) -> Self {
        let limits = if cfg.limits.validate().is_ok() {
            cfg.limits
        } else {
            ReceiveLimits::default()
        };
        Self {
            root,
            limits,
            min_free_percent: cfg.min_free_percent,
            declined: AtomicU64::new(0),
            probe,
        }
    }

    /// Сколько предложений отклонено автоматически как враждебные (для экрана, этап 18).
    pub fn declined_hostile(&self) -> u64 {
        self.declined.load(Ordering::SeqCst)
    }

    /// После приёма `bytes` на томе останется достаточно места. Неизвестное место: нет.
    fn space_ok(&self, bytes: u64) -> bool {
        (self.probe)(self.root.root()).is_some_and(|s| s.allows(bytes, self.min_free_percent))
    }
}

impl AcceptPolicy for ReceivePolicy {
    fn decide(&self, _pair: &PairId, p: Permission, offer: &OfferView) -> PolicyVerdict {
        let Ok(plan) = plan_offer_for_root(&offer.files, &self.limits, &self.root) else {
            self.declined.fetch_add(1, Ordering::SeqCst);
            return PolicyVerdict::Decline;
        };
        // Значения лимитов в `AutoAccept` не читаются: объёма как предела нет.
        let Permission::AutoAccept(_) = p else {
            return PolicyVerdict::Ask;
        };
        if plan.auto_ok() && self.space_ok(plan.total) {
            PolicyVerdict::Accept
        } else {
            PolicyVerdict::Ask
        }
    }
}
