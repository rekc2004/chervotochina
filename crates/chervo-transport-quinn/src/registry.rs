//! Правило одного соединения на пару и фоновая задача соединения (смена адреса, уборка).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

use chervo_identity::PairId;
use quinn::VarInt;

use crate::CLOSE_DUPLICATE;
use crate::conn::{QuinnConn, close_duplicate};
use crate::{Inner, TransportEvent};

#[derive(Clone)]
struct Entry {
    conn: quinn::Connection,
    initiator: bool,
    /// Публичный ключ X25519 звонящего в этом соединении.
    caller_pub: [u8; 32],
}

pub(crate) enum Verdict {
    /// Новое соединение выиграло; старое (если было живо) надо закрыть.
    Keep { replaced: Option<quinn::Connection> },
    /// Новое проиграло; победитель жив.
    Lose {
        winner: quinn::Connection,
        winner_initiator: bool,
    },
}

#[derive(Default)]
pub(crate) struct Registry {
    map: Mutex<HashMap<PairId, Vec<Entry>>>,
}

impl Registry {
    /// Правило одного соединения: одно направление, новое побеждает; встречные: остаётся то,
    /// где звонящий имеет меньший публичный X25519.
    pub(crate) fn admit(
        &self,
        pair: PairId,
        conn: quinn::Connection,
        initiator: bool,
        caller_pub: [u8; 32],
    ) -> Verdict {
        let new = Entry {
            conn,
            initiator,
            caller_pub,
        };
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let list = map.entry(pair).or_default();
        list.retain(|e| e.conn.close_reason().is_none());
        match list.pop() {
            None => {
                list.push(new);
                Verdict::Keep { replaced: None }
            }
            Some(old) => {
                let new_wins = old.initiator == new.initiator || new.caller_pub < old.caller_pub;
                if new_wins {
                    list.push(new);
                    Verdict::Keep {
                        replaced: Some(old.conn),
                    }
                } else {
                    let verdict = Verdict::Lose {
                        winner: old.conn.clone(),
                        winner_initiator: old.initiator,
                    };
                    list.push(old);
                    verdict
                }
            }
        }
    }

    pub(crate) fn remove(&self, pair: &PairId, stable_id: usize) {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(list) = map.get_mut(pair) {
            list.retain(|e| e.conn.stable_id() != stable_id);
            if list.is_empty() {
                map.remove(pair);
            }
        }
    }
}

pub(crate) enum Promoted {
    Winner(QuinnConn),
    /// Новое проиграло: живой победитель.
    Lost(QuinnConn),
}

/// Пара подтверждена: поднять лимиты, применить правило одного соединения.
pub(crate) fn promote(
    inner: &Arc<Inner>,
    conn: quinn::Connection,
    pair: PairId,
    initiator: bool,
    caller_pub: [u8; 32],
) -> Promoted {
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(inner.cfg.post_auth_bidi));
    conn.set_receive_window(VarInt::MAX);
    match inner
        .registry
        .admit(pair, conn.clone(), initiator, caller_pub)
    {
        Verdict::Keep { replaced } => {
            if let Some(old) = replaced {
                close_duplicate(&old);
                let _ = inner
                    .events
                    .send(TransportEvent::ConnectionReplaced { pair });
            }
            spawn_monitor(inner, conn.clone(), pair);
            Promoted::Winner(QuinnConn {
                conn,
                pair,
                initiator,
            })
        }
        Verdict::Lose {
            winner,
            winner_initiator,
        } => {
            close_duplicate(&conn);
            inner
                .counters
                .duplicates_closed
                .fetch_add(1, Ordering::Relaxed);
            Promoted::Lost(QuinnConn {
                conn: winner,
                pair,
                initiator: winner_initiator,
            })
        }
    }
}

/// Опрос `remote_address()` раз в `addr_poll` до закрытия; событие смены адреса; уборка записи.
fn spawn_monitor(inner: &Arc<Inner>, conn: quinn::Connection, pair: PairId) {
    let inner = inner.clone();
    tokio::spawn(async move {
        let mut last = conn.remote_address();
        let mut tick =
            tokio::time::interval(inner.cfg.addr_poll.max(std::time::Duration::from_millis(1)));
        let reason = loop {
            tokio::select! {
                e = conn.closed() => break e,
                _ = tick.tick() => {
                    let now = conn.remote_address();
                    if now != last {
                        last = now;
                        let _ = inner.events.send(TransportEvent::RemoteAddrChanged { pair });
                    }
                }
            }
        };
        // Нас вытеснила другая сторона (аутентифицированный собеседник закрыл кодом дубликата):
        // событие такое же, как у стороны, закрывшей старое соединение сама.
        if let quinn::ConnectionError::ApplicationClosed(ac) = &reason
            && ac.error_code == VarInt::from_u32(CLOSE_DUPLICATE)
        {
            let _ = inner
                .events
                .send(TransportEvent::ConnectionReplaced { pair });
        }
        inner.registry.remove(&pair, conn.stable_id());
    });
}
