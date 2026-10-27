//! Общее состояние запущенного узла и насос событий (этап 18а, A2). Насос сводит события
//! движка и передач в `NodeEvent` и ведёт небольшие таблицы для снимков: путь друга, проблемы
//! ключей и передачи.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chervo_connect::{Diagnosis, Engine, EngineEvent, EngineEvents, InviteOutcome, PathKind};
use chervo_connect::{SystemClock, SystemProbe, user_text};
use chervo_identity::{EpochStore, PairId};
use chervo_receive::{ReceiveConfig, ReceivePlacement, ReceivePolicy, ReceiveRoot};
use chervo_transfer::{
    FailReason, PauseReason, Side, TransferEvent, TransferEvents, TransferKey, Transfers,
};
use chervo_transport_quinn::QuinnTransport;
use chervo_upnp::UpnpMapper;
use tokio::runtime::Handle;
use tokio::time::{MissedTickBehavior, interval};

use super::events::{EventSink, NodeEvent};
use super::settings::Settings;
use super::store::NodeStore;
use super::views::{
    DiagnosisView, FriendRef, InviteRef, NodeWarning, SasView, TransferRef, TransferResult,
};

pub(crate) type Eng = Engine<QuinnTransport, NodeStore>;

/// Сколько записей о передачах помнит узел для снимков (законченные вытесняются первыми).
const MAX_TRANSFER_ENTRIES: usize = 256;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Значения, с которыми узел запущен: настройки, которые вступают в силу только после
/// перезапуска, сравниваются с ними (`SettingsView::restart_needed`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LiveConfig {
    pub(crate) port_setting: u16,
    pub(crate) receive_root: PathBuf,
    pub(crate) min_free_percent: u8,
    pub(crate) manual_forward: Option<u16>,
}

pub(crate) struct TEntry {
    pub(crate) side: Side,
    pub(crate) done: u64,
    pub(crate) total: u64,
    pub(crate) pause: Option<PauseReason>,
    pub(crate) preparing: Option<(u64, u64)>,
    pub(crate) result: Option<TransferResult>,
    pub(crate) dest_root: Option<PathBuf>,
    pub(crate) seq: u64,
}

#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) transfers: HashMap<TransferKey, TEntry>,
    next_seq: u64,
    pub(crate) last_path: HashMap<PairId, PathKind>,
    pub(crate) key_problems: HashSet<PairId>,
}

impl Registry {
    /// Запись о передаче; новая получает сторону `side`.
    pub(crate) fn entry(&mut self, key: TransferKey, side: Side) -> &mut TEntry {
        if !self.transfers.contains_key(&key) {
            self.prune();
            self.next_seq = self.next_seq.saturating_add(1);
        }
        let seq = self.next_seq;
        self.transfers.entry(key).or_insert_with(|| TEntry {
            side,
            done: 0,
            total: 0,
            pause: None,
            preparing: None,
            result: None,
            dest_root: None,
            seq,
        })
    }

    fn prune(&mut self) {
        while self.transfers.len() >= MAX_TRANSFER_ENTRIES {
            let oldest = self
                .transfers
                .iter()
                .filter(|(_, e)| e.result.is_some())
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.transfers.remove(&k);
                }
                None => break,
            }
        }
    }
}

pub(crate) struct Core {
    pub(crate) rt: Handle,
    pub(crate) dir: PathBuf,
    pub(crate) engine: Arc<Eng>,
    pub(crate) transport: Arc<QuinnTransport>,
    pub(crate) store: Arc<NodeStore>,
    pub(crate) clock: Arc<SystemClock>,
    pub(crate) probe: Arc<SystemProbe>,
    pub(crate) transfers: Transfers<Eng>,
    pub(crate) placement: Arc<ReceivePlacement>,
    pub(crate) policy: Arc<ReceivePolicy>,
    pub(crate) rcfg: ReceiveConfig,
    pub(crate) root: ReceiveRoot,
    pub(crate) sink: Arc<EventSink>,
    pub(crate) settings: Mutex<Settings>,
    pub(crate) live: LiveConfig,
    pub(crate) reg: Mutex<Registry>,
    pub(crate) mapper: Mutex<Option<Arc<UpnpMapper>>>,
}

impl Core {
    pub(crate) fn warn(&self, w: NodeWarning) {
        self.sink.emit(NodeEvent::Warning(w));
    }

    /// Запись о передаче по событию: сторону берём у `Transfers`.
    fn touch(&self, key: TransferKey, hint: Side, f: impl FnOnce(&mut TEntry)) {
        let side = self.transfers.status(&key).map_or(hint, |s| s.side);
        let mut reg = lock(&self.reg);
        f(reg.entry(key, side));
    }

    /// Итог передачи. Первый итог окончательный: поздние события о том же (например, отказ
    /// сообщается и ответом, и ошибкой) его не меняют и второго события не дают.
    fn finished(&self, key: TransferKey, result: TransferResult) {
        let mut first = true;
        self.touch(key, Side::Receiver, |e| {
            if e.result.is_some() {
                first = false;
                return;
            }
            e.result = Some(result);
            e.pause = None;
            e.preparing = None;
        });
        if !first {
            return;
        }
        self.sink.emit(NodeEvent::TransferFinished {
            transfer: TransferRef::new(key),
            result,
        });
    }

    fn changed(&self, key: TransferKey) {
        self.sink.emit(NodeEvent::TransferChanged {
            transfer: TransferRef::new(key),
        });
    }

    pub(crate) fn on_transfer_event(&self, ev: TransferEvent) {
        match ev {
            TransferEvent::OfferReceived { key } => {
                self.touch(key, Side::Receiver, |_| {});
                self.sink.emit(NodeEvent::OfferIncoming {
                    transfer: TransferRef::new(key),
                });
            }
            TransferEvent::OfferAnswered { key, accepted } => {
                let known = lock(&self.reg).transfers.contains_key(&key);
                let status_side = self.transfers.status(&key).map(|s| s.side);
                self.touch(key, Side::Receiver, |_| {});
                if accepted {
                    // предложение принято без нашего вопроса: решила политика (автоприём)
                    if !known && status_side == Some(Side::Receiver) {
                        self.sink.emit(NodeEvent::OfferAutoAccepted {
                            transfer: TransferRef::new(key),
                        });
                    } else {
                        self.changed(key);
                    }
                } else {
                    self.finished(key, TransferResult::Declined);
                }
            }
            TransferEvent::Started { key } => {
                self.touch(key, Side::Receiver, |e| e.pause = None);
                self.changed(key);
            }
            TransferEvent::Progress { key, done, total } => {
                self.touch(key, Side::Receiver, |e| {
                    e.done = done;
                    e.total = total;
                });
                self.changed(key);
            }
            TransferEvent::Preparing { key, hashed, total } => {
                self.touch(key, Side::Sender, |e| {
                    e.preparing = Some((hashed, total));
                    e.total = total;
                });
                self.changed(key);
            }
            TransferEvent::Verifying { key }
            | TransferEvent::FileReceived { key, .. }
            | TransferEvent::FileDelivered { key, .. }
            | TransferEvent::FileFailed { key, .. } => {
                self.touch(key, Side::Receiver, |e| e.preparing = None);
                self.changed(key);
            }
            TransferEvent::Paused { key, reason } => {
                self.touch(key, Side::Receiver, |e| e.pause = Some(reason));
                self.changed(key);
            }
            TransferEvent::Resumed { key } => {
                self.touch(key, Side::Receiver, |e| e.pause = None);
                self.changed(key);
            }
            TransferEvent::Completed { key } => self.finished(key, TransferResult::Completed),
            TransferEvent::Cancelled { key, by } => {
                let mut by_us = false;
                self.touch(key, Side::Receiver, |e| by_us = e.side == by);
                self.finished(key, TransferResult::Cancelled { by_us });
            }
            TransferEvent::Failed { key, reason } => {
                // отказ получателя это «отклонено», а не сбой
                let result = match reason {
                    FailReason::Declined => TransferResult::Declined,
                    other => TransferResult::Failed { reason: other },
                };
                self.finished(key, result);
            }
            _ => {}
        }
    }

    pub(crate) fn on_engine_event(self: &Arc<Self>, ev: EngineEvent) {
        match ev {
            EngineEvent::Connected { pair, path } => {
                lock(&self.reg).last_path.insert(pair, path);
                self.sink.emit(NodeEvent::FriendOnline {
                    friend: FriendRef::new(pair),
                    path,
                });
            }
            EngineEvent::Disconnected { pair } => {
                self.sink.emit(NodeEvent::FriendOffline {
                    friend: FriendRef::new(pair),
                });
            }
            EngineEvent::SasReady { pair, sas } => {
                self.sink.emit(NodeEvent::InviteSas {
                    invite: InviteRef::new(pair),
                    sas: SasView::new(sas),
                });
            }
            EngineEvent::InviteFinished { pair, outcome } => {
                self.sink.emit(NodeEvent::InviteFinished {
                    invite: InviteRef::new(pair),
                    outcome,
                });
                if outcome == InviteOutcome::Added {
                    self.check_anchor_async();
                }
            }
            EngineEvent::KeyProblem { pair, .. } => {
                lock(&self.reg).key_problems.insert(pair);
                self.sink.emit(NodeEvent::FriendKeyProblem {
                    friend: FriendRef::new(pair),
                });
            }
            EngineEvent::OwnAddrsChanged => self.sink.emit(NodeEvent::OwnAddressChanged),
            EngineEvent::MappingChanged { status } => {
                self.sink.emit(NodeEvent::MappingChanged { status });
            }
            EngineEvent::ClockSkew { pair } => {
                self.sink.emit(NodeEvent::ClockSkewSuspected {
                    friend: FriendRef::new(pair),
                });
            }
            EngineEvent::Unreachable { pair, diagnosis } => {
                self.sink.emit(NodeEvent::Unreachable {
                    friend: FriendRef::new(pair),
                    diagnosis: diagnosis_view(diagnosis),
                });
            }
            EngineEvent::Internal => self.sink.emit(NodeEvent::Internal),
            _ => {}
        }
    }

    /// Дружба записана движком: если запись якоря не удалась (S1 L3), движок это скрыл, а узел
    /// сообщает предупреждением. Чтение хранилища может занять секунды: на блокирующем потоке.
    fn check_anchor_async(self: &Arc<Self>) {
        let core = self.clone();
        drop(self.rt.spawn_blocking(move || {
            let book_epoch = core.engine.read_book(chervo_friends::FriendBook::epoch);
            if matches!(core.store.read_epoch(), Ok(Some(s)) if s < book_epoch) {
                core.warn(NodeWarning::AnchorNotUpdated);
            }
        }));
    }
}

pub(crate) fn diagnosis_view(d: Diagnosis) -> DiagnosisView {
    DiagnosisView {
        reason: d.reason,
        text: user_text(d.reason),
        rendezvous_could_help: d.rendezvous_could_help,
    }
}

/// Насос событий: одна задача на фоновой среде.
pub(crate) async fn pump(core: Arc<Core>, mut ev: EngineEvents, mut tev: TransferEvents) {
    let mut tick = interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // враждебные предложения политика отклоняет сама и событий о них не даёт: следим за счётчиком
    let mut hostile_seen = core.policy.declined_hostile();
    loop {
        tokio::select! {
            e = ev.recv() => match e {
                Some(e) => core.on_engine_event(e),
                None => break,
            },
            t = tev.recv() => match t {
                Some(t) => core.on_transfer_event(t),
                None => break,
            },
            _ = tick.tick() => {
                core.sink.flush_lagged();
                let now = core.policy.declined_hostile();
                if now > hostile_seen {
                    hostile_seen = now;
                    core.warn(NodeWarning::HostileOfferDeclined);
                }
            }
        }
    }
}
