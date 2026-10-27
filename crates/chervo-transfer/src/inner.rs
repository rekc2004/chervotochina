//! Общее состояние `Transfers`: реестры сессий и связь с движком соединений.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_identity::PairId;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::events::PauseReason;
use crate::links::Links;
use crate::names::TransferKey;
use crate::policy::{AcceptPolicy, InboundReservation, OfferView};
use crate::receiver::{RPhase, RecvSession, Reoffer};
use crate::sender::SendSession;
use crate::shared::{Shared, lock};

#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) out: HashMap<TransferKey, Arc<SendSession>>,
    pub(crate) inb: HashMap<TransferKey, Arc<RecvSession>>,
    /// Недавние потоки управления от каждого друга (для предела в минуту).
    pub(crate) ctl_recent: HashMap<PairId, VecDeque<Instant>>,
}

/// Окончательный ответ на ожидавшее предложение, который отправитель мог не получить.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tomb {
    Decline,
    Expired,
    Busy,
    Limits,
    Protocol,
}

/// Сколько надгробие живёт сверх `offer_relink_grace`.
const TOMB_EXTRA: Duration = Duration::from_secs(30);

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
    /// Каналы повторов для ожидающих предложений (ёмкость 1). Запись есть, только пока идёт
    /// `pending_task`. Замок берётся после `reg`, никогда до него.
    pub(crate) relink: Mutex<HashMap<TransferKey, mpsc::Sender<Reoffer<L::Conn>>>>,
    /// Надгробия: ответ на предложение, который отправитель мог не получить. Не больше
    /// `max_pending_offers`, живут `offer_relink_grace + 30 с`. Замок берётся после `reg`.
    pub(crate) tombs: Mutex<VecDeque<(TransferKey, Tomb, Instant)>>,
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

    /// Снимает ожидающее предложение и пишет надгробие под одним замком `reg`: повтор не
    /// увидит промежуток между ними и не получит новое окно решения.
    pub(crate) fn remove_inb_tomb(&self, key: &TransferKey, tomb: Tomb) {
        let mut reg = lock(&self.reg);
        reg.inb.remove(key);
        let now = Instant::now();
        let until = now + self.sh.cfg.offer_relink_grace + TOMB_EXTRA;
        let mut t = lock(&self.tombs);
        t.retain(|(k, _, u)| *u > now && k != key);
        while t.len() >= self.sh.cfg.max_pending_offers {
            t.pop_front();
        }
        t.push_back((*key, tomb, until));
    }

    /// Надгробие ключа, если оно ещё действует (просроченные убираются при обращении).
    pub(crate) fn tomb_get(&self, key: &TransferKey) -> Option<Tomb> {
        let now = Instant::now();
        let mut t = lock(&self.tombs);
        t.retain(|(_, _, u)| *u > now);
        t.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| *v)
    }

    /// Ключ известен: есть сессия или действующее надгробие (подсказка для разбора ошибок
    /// сборки; решение принимается позже под замком `reg`).
    pub(crate) fn is_known(&self, key: &TransferKey) -> bool {
        lock(&self.reg).inb.contains_key(key) || self.tomb_get(key).is_some()
    }

    pub(crate) fn unreg_relink(&self, key: &TransferKey) {
        lock(&self.relink).remove(key);
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

    /// Не больше `ctl_in_per_min` потоков управления в минуту от одного друга. `Some(метка)`:
    /// поток засчитан (метку принимает `refund_reoffer`).
    ///
    /// Поток считается до первого сообщения, когда ключ ещё неизвестен. Честный отправитель
    /// после потери связи повторяет предложение до `MAX_OFFER_RELINKS` раз за секунды, и без
    /// возврата 1 + 8 потоков не уложились бы в 6 в минуту: именно при обрывах связи повтор
    /// молча терялся бы. Поэтому поток, чьё первое сообщение это OFFER_HEAD с ключом
    /// существующей сессии, возвращает свою запись (`refund_reoffer`). Возврат ограничен
    /// `MAX_OFFER_RELINKS` на сессию (счётчик в `RecvSession`), так что враждебный друг не
    /// получает бесплатных потоков сверх 8 на каждое своё предложение, которое само занимает
    /// слот и подчинено пределу. Потоки с неизвестными ключами и RESUME остаются под общим
    /// пределом целиком.
    pub(crate) fn ctl_rate_ok(&self, pair: &PairId) -> Option<Instant> {
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
            return None;
        }
        q.push_back(now);
        // записи ушедших друзей не копятся
        if reg.ctl_recent.len() > 4096 {
            reg.ctl_recent.retain(|_, q| !q.is_empty());
        }
        Some(now)
    }

    /// Первое сообщение потока это OFFER_HEAD с ключом существующей сессии: запись потока
    /// возвращается в предел, пока не исчерпан запас сессии (см. `ctl_rate_ok`).
    pub(crate) fn refund_reoffer(&self, key: &TransferKey, token: Instant) {
        let mut reg = lock(&self.reg);
        let Some(s) = reg.inb.get(key).cloned() else {
            return;
        };
        if !s.take_refund() {
            return;
        }
        if let Some(q) = reg.ctl_recent.get_mut(&key.pair)
            && let Some(i) = q.iter().position(|t| *t == token)
        {
            q.remove(i);
        }
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
