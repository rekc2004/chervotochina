//! Решение о приёме предложения (спецификация 15, решение 15 в редакции Рев. 3, решения
//! владельца 2026-10-18). По умолчанию спрашиваем. Автоприём только для друга с явным
//! `Permission::AutoAccept` (его включают после вопроса доверия, см. `trust.rs`) и только если
//! каждый файл заведомо безопасного типа (список `KNOWN_INERT`), имена чистые (ни одного
//! изменения и флага), а путь короткий. Любой другой или неизвестный тип, программы, образы
//! дисков, документы с макросами: вопрос пользователю. Лимитов объёма нет.
//!
//! Единственная защита от переполнения диска (Рев. 5): перед решением (и для автоприёма, и для
//! обычного вопроса) считается свободное место тома папки приёма за вычетом ещё не полученных
//! байтов ВСЕХ идущих и приостановленных приёмов на этом томе (их даёт `OfferView::inbound`;
//! `Transfers` решает по одному предложению за раз, поэтому два одновременных предложения не
//! получают одно и то же место). Предложение плюс запас `min_free_percent` не помещается:
//! `ReceiveDecision::InsufficientSpace` (никогда не автоприём; экран предупреждает обоими
//! числами и предлагает выбрать другую папку, см. `ReceivePlacement::choose_root`). Место
//! узнать нельзя: автоприёма нет, обычный вопрос.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chervo_friends::Permission;
use chervo_identity::PairId;
use chervo_transfer::{AcceptPolicy, OfferView, PolicyVerdict};

use crate::limits::ReceiveLimits;
use crate::plan::plan_offer_for_root;
use crate::root::{ReceiveConfig, ReceiveRoot};
use crate::space::{SpaceCheck, SpaceProbe, SpaceShortfall, check_space, disk_space};

/// Решение политики приёма до сведения к `PolicyVerdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveDecision {
    Accept,
    Ask,
    Decline,
    /// Места в основной папке приёма не хватает: никогда не автоприём; пользователю нужно
    /// показать `needed` и `available` и предложить другую папку.
    InsufficientSpace(SpaceShortfall),
}

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

    /// Свой способ узнать свободное место (тесты).
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

    /// Хватает ли места в основной папке приёма для этого предложения прямо сейчас (с резервом
    /// остальных приёмов из `offer.inbound`). Для экрана вопроса: предложение берётся из
    /// `Transfers::offer`, чтобы числа были свежими. Сумма размеров считается по файлам.
    pub fn space_check(&self, offer: &OfferView) -> SpaceCheck {
        let total = offer
            .files
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.size));
        check_space(
            &*self.probe,
            self.root.root(),
            total,
            self.min_free_percent,
            &offer.inbound,
        )
    }

    /// Полное решение. `decide` сводит его к `PolicyVerdict`: `InsufficientSpace` там это `Ask`
    /// (пользователь решает; экран зовёт `space_check` и показывает предупреждение).
    pub fn evaluate(&self, p: Permission, offer: &OfferView) -> ReceiveDecision {
        let Ok(plan) = plan_offer_for_root(&offer.files, &self.limits, &self.root) else {
            self.declined.fetch_add(1, Ordering::SeqCst);
            return ReceiveDecision::Decline;
        };
        let space = check_space(
            &*self.probe,
            self.root.root(),
            plan.total,
            self.min_free_percent,
            &offer.inbound,
        );
        if let SpaceCheck::Short(s) = space {
            return ReceiveDecision::InsufficientSpace(s);
        }
        // Значения лимитов в `AutoAccept` не читаются: объёма как предела нет.
        let Permission::AutoAccept(_) = p else {
            return ReceiveDecision::Ask;
        };
        if plan.auto_ok() && space == SpaceCheck::Fits {
            ReceiveDecision::Accept
        } else {
            ReceiveDecision::Ask
        }
    }
}

impl AcceptPolicy for ReceivePolicy {
    fn decide(&self, _pair: &PairId, p: Permission, offer: &OfferView) -> PolicyVerdict {
        match self.evaluate(p, offer) {
            ReceiveDecision::Accept => PolicyVerdict::Accept,
            ReceiveDecision::Decline => PolicyVerdict::Decline,
            ReceiveDecision::Ask | ReceiveDecision::InsufficientSpace(_) => PolicyVerdict::Ask,
        }
    }
}
