//! События узла для оболочки. Все события, кроме `Lagged`, это сигналы «что-то изменилось»:
//! состояние берётся снимками (`friends()`, `transfers()`, `offer()`), поэтому потеря события не
//! теряет данных, а `Lagged` говорит оболочке перечитать снимки.
//!
//! Канал ограниченный (1024). Когда он полон, событие отбрасывается и один раз уходит `Lagged`.
//! После каждой отправки вызывается необязательный будильник (GUI просит перерисовку).

use std::fmt;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chervo_addr::{LanStatus, MapStatus};
use chervo_connect::{InviteOutcome, PathKind};

use super::views::{
    DiagnosisView, FriendRef, InviteRef, NodeWarning, SasView, TransferRef, TransferResult,
};

/// Ёмкость очереди событий.
pub(crate) const EVENT_QUEUE: usize = 1024;

/// `Debug` печатает только имя варианта: в событиях бывают SAS и ссылки на друзей.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeEvent {
    FriendOnline {
        friend: FriendRef,
        path: PathKind,
    },
    FriendOffline {
        friend: FriendRef,
    },
    InviteSas {
        invite: InviteRef,
        sas: SasView,
    },
    InviteFinished {
        invite: InviteRef,
        outcome: InviteOutcome,
    },
    FriendKeyProblem {
        friend: FriendRef,
    },
    ClockSkewSuspected {
        friend: FriendRef,
    },
    Unreachable {
        friend: FriendRef,
        diagnosis: DiagnosisView,
    },
    OwnAddressChanged,
    MappingChanged {
        status: MapStatus,
    },
    /// Состояние поиска друзей в локальной сети изменилось (`Node::lan_status`).
    LanStatusChanged {
        status: LanStatus,
    },
    OfferIncoming {
        transfer: TransferRef,
    },
    OfferAutoAccepted {
        transfer: TransferRef,
    },
    TransferChanged {
        transfer: TransferRef,
    },
    TransferFinished {
        transfer: TransferRef,
        result: TransferResult,
    },
    Warning(NodeWarning),
    /// Сбой внутри (например, публикация списка разрешённых друзей не удалась).
    Internal,
    /// События потеряны из-за переполнения очереди: перечитайте снимки.
    Lagged,
    Stopped,
}

impl NodeEvent {
    fn name(&self) -> &'static str {
        match self {
            Self::FriendOnline { .. } => "FriendOnline",
            Self::FriendOffline { .. } => "FriendOffline",
            Self::InviteSas { .. } => "InviteSas",
            Self::InviteFinished { .. } => "InviteFinished",
            Self::FriendKeyProblem { .. } => "FriendKeyProblem",
            Self::ClockSkewSuspected { .. } => "ClockSkewSuspected",
            Self::Unreachable { .. } => "Unreachable",
            Self::OwnAddressChanged => "OwnAddressChanged",
            Self::MappingChanged { .. } => "MappingChanged",
            Self::LanStatusChanged { .. } => "LanStatusChanged",
            Self::OfferIncoming { .. } => "OfferIncoming",
            Self::OfferAutoAccepted { .. } => "OfferAutoAccepted",
            Self::TransferChanged { .. } => "TransferChanged",
            Self::TransferFinished { .. } => "TransferFinished",
            Self::Warning(_) => "Warning",
            Self::Internal => "Internal",
            Self::Lagged => "Lagged",
            Self::Stopped => "Stopped",
        }
    }
}

impl fmt::Debug for NodeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Получатель событий узла.
pub struct NodeEvents {
    rx: Receiver<NodeEvent>,
}

impl NodeEvents {
    pub fn recv_timeout(&self, d: Duration) -> Result<NodeEvent, RecvTimeoutError> {
        self.rx.recv_timeout(d)
    }

    pub fn try_recv(&self) -> Result<NodeEvent, TryRecvError> {
        self.rx.try_recv()
    }
}

impl fmt::Debug for NodeEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeEvents(..)")
    }
}

type Waker = Arc<dyn Fn() + Send + Sync>;

/// Отправляющая сторона: ограниченная очередь, метка «были потери» и будильник.
pub(crate) struct EventSink {
    tx: SyncSender<NodeEvent>,
    lagged: Mutex<bool>,
    waker: Mutex<Option<Waker>>,
}

impl EventSink {
    pub(crate) fn channel() -> (Arc<Self>, NodeEvents) {
        Self::with_capacity(EVENT_QUEUE)
    }

    pub(crate) fn with_capacity(cap: usize) -> (Arc<Self>, NodeEvents) {
        let (tx, rx) = sync_channel(cap);
        let sink = Arc::new(Self {
            tx,
            lagged: Mutex::new(false),
            waker: Mutex::new(None),
        });
        (sink, NodeEvents { rx })
    }

    pub(crate) fn set_waker(&self, w: Box<dyn Fn() + Send + Sync>) {
        *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(w));
    }

    fn wake(&self) {
        let w = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(w) = w {
            w();
        }
    }

    /// Поставить событие. Очередь полна: событие отбрасывается, ставится метка потери.
    pub(crate) fn emit(&self, e: NodeEvent) {
        self.flush_lagged();
        match self.tx.try_send(e) {
            Ok(()) => self.wake(),
            // потеря события: для InviteSas снимка нет, поэтому при потере код сверки не вернуть
            // (приглашение закончится по сроку, ничего не подтверждается молча)
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                *self.lagged.lock().unwrap_or_else(PoisonError::into_inner) = true;
            }
            // получатель отпущен: события никому не нужны
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
        }
    }

    /// Отправить `Lagged` один раз, когда в очереди появилось место.
    pub(crate) fn flush_lagged(&self) {
        let mut g = self.lagged.lock().unwrap_or_else(PoisonError::into_inner);
        if *g && self.tx.try_send(NodeEvent::Lagged).is_ok() {
            *g = false;
            drop(g);
            self.wake();
        }
    }
}
