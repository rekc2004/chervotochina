//! Общее состояние `Transfers`: реестры сессий и связь с движком соединений.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_identity::PairId;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::events::PauseReason;
use crate::links::Links;
use crate::names::TransferKey;
use crate::policy::{AcceptPolicy, InboundReservation, OfferView};
use crate::receiver::{RPhase, RecvSession};
use crate::sender::SendSession;
use crate::shared::{Shared, lock};

#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) out: HashMap<TransferKey, Arc<SendSession>>,
    pub(crate) inb: HashMap<TransferKey, Arc<RecvSession>>,
    /// Недавние потоки управления от каждого друга (для предела в минуту).
    pub(crate) ctl_recent: HashMap<PairId, VecDeque<Instant>>,
}

pub(crate) struct Inner<L: Links> {
    pub(crate) sh: Arc<Shared>,
    pub(crate) links: Arc<L>,
    pub(crate) policy: Arc<dyn AcceptPolicy>,
    pub(crate) reg: Mutex<Registry>,
    /// Растёт при каждом событии движка: получатели ждут появления соединения.
    pub(crate) conn_gen: watch::Sender<u64>,
    /// Период опроса соединения и прав друзей (5 с).
    pub(crate) poll: Duration,
    /// Решения о предложениях принимаются по одному: политика видит резерв места всех уже
    /// принятых передач, а принятое предложение сразу попадает в этот резерв (Рев. 5).
    pub(crate) decide_lock: Mutex<()>,
}

impl<L: Links> Inner<L> {
    pub(crate) fn find_out(&self, key: &TransferKey) -> Option<Arc<SendSession>> {
        lock(&self.reg).out.get(key).cloned()
    }

    pub(crate) fn find_inb(&self, key: &TransferKey) -> Option<Arc<RecvSession>> {
        lock(&self.reg).inb.get(key).cloned()
    }

    /// Место, которое ещё понадобится всем остальным входящим передачам (кроме `except`).
    pub(crate) fn inbound_reservations(&self, except: &TransferKey) -> Vec<InboundReservation> {
        lock(&self.reg)
            .inb
            .values()
            .filter(|s| s.key != *except)
            .filter_map(|s| s.reservation())
            .collect()
    }

    /// Предложение вместе с резервом места остальных передач.
    pub(crate) fn offer_view_for(&self, s: &Arc<RecvSession>) -> OfferView {
        let mut v = s.offer_view();
        v.inbound = self.inbound_reservations(&s.key);
        v
    }

    pub(crate) fn remove_out(&self, key: &TransferKey) {
        lock(&self.reg).out.remove(key);
    }

    pub(crate) fn remove_inb(&self, key: &TransferKey) {
        lock(&self.reg).inb.remove(key);
    }

    pub(crate) fn bump(&self) {
        self.conn_gen.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Сколько входящих передач сейчас идут (`Active`). Передачи на паузе и ожидающие решения
    /// не считаются: они остаются в списке, но не занимают места для новых приёмов.
    pub(crate) fn active_inbound(&self) -> usize {
        lock(&self.reg)
            .inb
            .values()
            .filter(|s| lock(&s.core).phase == RPhase::Active)
            .count()
    }

    /// Занимает место среди активных входящих (атомарно по реестру). `None`: мест нет.
    /// `Some(prev)`: занято; `prev` это причина паузы, из которой передача вышла (`None`, если
    /// она была не на паузе).
    pub(crate) fn claim_slot(&self, s: &Arc<RecvSession>) -> Option<Option<PauseReason>> {
        let reg = lock(&self.reg);
        let others = reg
            .inb
            .values()
            .filter(|x| !Arc::ptr_eq(x, s) && lock(&x.core).phase == RPhase::Active)
            .count();
        if others >= self.sh.cfg.max_inbound_active {
            return None;
        }
        let mut c = lock(&s.core);
        match c.phase {
            RPhase::Paused(r) => {
                c.phase = RPhase::Active;
                Some(Some(r))
            }
            RPhase::Pending => {
                c.phase = RPhase::Active;
                Some(None)
            }
            RPhase::Active | RPhase::Ended => Some(None),
        }
    }

    /// Не больше `ctl_in_per_min` потоков управления в минуту от одного друга.
    pub(crate) fn ctl_rate_ok(&self, pair: &PairId) -> bool {
        let cap = usize::try_from(self.sh.cfg.ctl_in_per_min).unwrap_or(usize::MAX);
        let now = Instant::now();
        let mut reg = lock(&self.reg);
        let q = reg.ctl_recent.entry(*pair).or_default();
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= cap {
            return false;
        }
        q.push_back(now);
        // записи ушедших друзей не копятся
        if reg.ctl_recent.len() > 4096 {
            reg.ctl_recent.retain(|_, q| !q.is_empty());
        }
        true
    }
}

impl<L: Links> Inner<L> {
    /// Остановка всех передач: задачи завершаются, блокирующие проверки прерываются. Состояние
    /// получателя на диске остаётся для возобновления.
    pub(crate) fn stop_all(&self) {
        self.sh.shutdown.stop();
        let reg = lock(&self.reg);
        for s in reg.out.values() {
            s.shutdown();
        }
        for s in reg.inb.values() {
            s.halt.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
