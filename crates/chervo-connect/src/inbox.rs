//! Общий приёмник потоков и удержание соединения (этап 14, X0).
//!
//! Слой соединения не знает видов потоков, кроме ADDR_INFO: другие слои регистрируют вид
//! байтом (`Engine::stream_inbox`) и получают поток целиком после байта вида. Зависимости от
//! этих слоёв здесь нет. Недоверенные байты после байта вида отсюда не читаются.

use std::fmt;
use std::sync::{Arc, Weak};

use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_token::STREAM_ADDR_INFO;
use chervo_transport::{Connection, ManagedTransport};
use tokio::sync::mpsc;

use crate::engine::{ConnectError, Engine, Inner};

/// Поток друга, байт вида уже прочитан. `Debug` скрыт.
pub struct IncomingStream<C: Connection> {
    pub pair: PairId,
    pub kind: u8,
    pub conn: C,
    pub tx: C::Tx,
    pub rx: C::Rx,
}

impl<C: Connection> fmt::Debug for IncomingStream<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IncomingStream(..)")
    }
}

/// Приёмник зарегистрированных видов потоков (один на вызов `stream_inbox`).
pub struct StreamInbox<C: Connection> {
    rx: mpsc::Receiver<IncomingStream<C>>,
}

impl<C: Connection> StreamInbox<C> {
    pub(crate) fn new(rx: mpsc::Receiver<IncomingStream<C>>) -> Self {
        Self { rx }
    }

    /// `None`: движок остановлен.
    pub async fn recv(&mut self) -> Option<IncomingStream<C>> {
        self.rx.recv().await
    }
}

impl<C: Connection> fmt::Debug for StreamInbox<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamInbox(..)")
    }
}

/// Освобождение удержания (реализует `Inner`; `ConnHold` не зависит от типов движка).
pub(crate) trait HoldSink: Send + Sync {
    fn release(&self, pair: &PairId, conn_id: u64);
}

/// Пока жив хоть один `ConnHold` живого соединения, `max_live` его не закрывает. Относится к
/// одному соединению (`conn_id`): после замены соединения старое удержание ничего не значит.
/// Слабая ссылка на движок: забытое удержание не держит гнездо транспорта после остановки.
pub struct ConnHold {
    sink: Weak<dyn HoldSink>,
    pair: PairId,
    conn_id: u64,
}

impl ConnHold {
    pub(crate) fn new(sink: Weak<dyn HoldSink>, pair: PairId, conn_id: u64) -> Self {
        Self {
            sink,
            pair,
            conn_id,
        }
    }
}

impl Drop for ConnHold {
    fn drop(&mut self) {
        if let Some(sink) = self.sink.upgrade() {
            sink.release(&self.pair, self.conn_id);
        }
    }
}

impl fmt::Debug for ConnHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnHold(..)")
    }
}

impl<T, S> HoldSink for Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    fn release(&self, pair: &PairId, conn_id: u64) {
        let mut st = self.lock();
        if let Some((id, n)) = st.holds.get_mut(pair)
            && *id == conn_id
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.holds.remove(pair);
            }
        }
    }
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Регистрирует виды потоков `kinds`; по каждому виду один раз (пока приёмник жив).
    /// `InvalidKind`: пустой список, 0, `STREAM_ADDR_INFO`, повтор в списке. `KindTaken`: вид
    /// уже закреплён за живым приёмником. Приёмник, который сбросили, вид освобождает.
    /// Поток доходит до приёмника после байта вида, проверки `Active` и предела в минуту.
    pub fn stream_inbox(&self, kinds: &[u8]) -> Result<StreamInbox<T::Conn>, ConnectError> {
        if self.inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let mut seen = [false; 256];
        for &k in kinds {
            let slot = seen.get_mut(usize::from(k)).ok_or(ConnectError::Internal)?;
            if k == 0 || k == STREAM_ADDR_INFO || *slot {
                return Err(ConnectError::InvalidKind);
            }
            *slot = true;
        }
        if kinds.is_empty() {
            return Err(ConnectError::InvalidKind);
        }
        let (tx, rx) = mpsc::channel(self.inner.cfg.stream_inbox_capacity.max(1));
        let mut map = self.inner.kinds_lock();
        if kinds
            .iter()
            .any(|k| map.get(k).is_some_and(|s| !s.is_closed()))
        {
            return Err(ConnectError::KindTaken);
        }
        for &k in kinds {
            map.insert(k, tx.clone());
        }
        Ok(StreamInbox::new(rx))
    }

    /// Второй и следующие получатели событий движка.
    pub fn subscribe(&self) -> crate::engine::EngineEvents {
        self.inner.subscribe_events()
    }

    /// `None`: живого соединения с этой парой нет. Пока существует удержание живого
    /// соединения, предел `max_live` его не закрывает.
    pub fn hold(&self, pair: &PairId) -> Option<ConnHold> {
        let id = {
            let mut st = self.inner.lock();
            let id = st.live.get(pair).map(|l| l.id)?;
            match st.holds.get_mut(pair) {
                Some((hid, n)) if *hid == id => *n = n.saturating_add(1),
                _ => {
                    st.holds.insert(*pair, (id, 1));
                }
            }
            id
        };
        let weak: Weak<Inner<T, S>> = Arc::downgrade(&self.inner);
        let sink: Weak<dyn HoldSink> = weak;
        Some(ConnHold::new(sink, *pair, id))
    }
}
