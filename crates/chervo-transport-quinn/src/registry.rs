//! Правило одного соединения на пару и фоновая задача соединения (смена адреса, уборка).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use chervo_identity::{KxPeer, PairId};
use quinn::VarInt;

use crate::CLOSE_DUPLICATE;
use crate::conn::{QuinnConn, close_duplicate, refuse};
use crate::{Inner, TransportEvent};

/// Есть ли в наборе пара с точно такой тройкой `(пара, наш X25519, X25519 собеседника)`.
fn has_triple(peers: &[KxPeer], pair: &PairId, ours: &[u8; 32], theirs: &[u8; 32]) -> bool {
    peers.iter().any(|p| {
        p.pair() == *pair && p.ours_public().to_bytes() == *ours && p.theirs().to_bytes() == *theirs
    })
}

/// Номера соединений процесса: выдаются по возрастанию и не повторяются. `stable_id()` quinn
/// это адрес в памяти, и после сброса соединения аллокатор может отдать его следующему.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone)]
struct Entry {
    /// Номер соединения (`Connection::conn_id`), назначен при вставке записи.
    id: u64,
    conn: quinn::Connection,
    initiator: bool,
    /// Публичный ключ X25519 звонящего в этом соединении.
    caller_pub: [u8; 32],
    /// Публичный X25519 этой стороны и собеседника: тройка `(пара, ours, theirs)` должна
    /// оставаться в наборе, иначе соединение закрывается (`set_peers`).
    ours_pub: [u8; 32],
    theirs_pub: [u8; 32],
}

pub(crate) enum Verdict {
    /// Тройки нет в текущем наборе (набор сменился во время KK): соединение не принимается.
    NotAllowed,
    /// Новое соединение выиграло; старое (если было живо) надо закрыть.
    Keep {
        id: u64,
        replaced: Option<quinn::Connection>,
    },
    /// Новое проиграло; победитель жив.
    Lose {
        winner: quinn::Connection,
        winner_id: u64,
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
    ///
    /// Порядок замков: реестр, затем набор пар. Членство тройки в текущем наборе проверяется
    /// под замком реестра, тем же, под которым `replace_peers` меняет набор.
    pub(crate) fn admit(
        &self,
        peers: &Mutex<Arc<Vec<KxPeer>>>,
        pair: PairId,
        conn: quinn::Connection,
        initiator: bool,
        ours_pub: [u8; 32],
        theirs_pub: [u8; 32],
    ) -> Verdict {
        let caller_pub = if initiator { ours_pub } else { theirs_pub };
        let new = Entry {
            id: next_conn_id(),
            conn,
            initiator,
            caller_pub,
            ours_pub,
            theirs_pub,
        };
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let allowed = {
            let cur = peers.lock().unwrap_or_else(PoisonError::into_inner);
            has_triple(&cur, &pair, &ours_pub, &theirs_pub)
        };
        if !allowed {
            return Verdict::NotAllowed;
        }
        let list = map.entry(pair).or_default();
        list.retain(|e| e.conn.close_reason().is_none());
        match list.pop() {
            None => {
                let id = new.id;
                list.push(new);
                Verdict::Keep { id, replaced: None }
            }
            Some(old) => {
                let new_wins = old.initiator == new.initiator || new.caller_pub < old.caller_pub;
                if new_wins {
                    let id = new.id;
                    list.push(new);
                    Verdict::Keep {
                        id,
                        replaced: Some(old.conn),
                    }
                } else {
                    let verdict = Verdict::Lose {
                        winner: old.conn.clone(),
                        winner_id: old.id,
                        winner_initiator: old.initiator,
                    };
                    list.push(old);
                    verdict
                }
            }
        }
    }

    /// Живые соединения: (пара, адрес собеседника).
    pub(crate) fn live_remotes(&self) -> Vec<(PairId, std::net::SocketAddr)> {
        let map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        map.iter()
            .flat_map(|(pair, list)| {
                list.iter()
                    .filter(|e| e.conn.close_reason().is_none())
                    .map(|e| (*pair, e.conn.remote_address()))
            })
            .collect()
    }

    /// Заменяет набор пар и возвращает живые соединения, чьей тройки в новом наборе нет
    /// (они убраны из реестра; закрывает вызывающий после снятия замка).
    pub(crate) fn replace_peers(
        &self,
        peers: &Mutex<Arc<Vec<KxPeer>>>,
        new: Vec<KxPeer>,
    ) -> Vec<(PairId, quinn::Connection)> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let new = Arc::new(new);
        *peers.lock().unwrap_or_else(PoisonError::into_inner) = new.clone();
        let mut removed = Vec::new();
        for (pair, list) in map.iter_mut() {
            list.retain(|e| {
                if e.conn.close_reason().is_some() {
                    return true;
                }
                if has_triple(&new, pair, &e.ours_pub, &e.theirs_pub) {
                    return true;
                }
                removed.push((*pair, e.conn.clone()));
                false
            });
        }
        map.retain(|_, list| !list.is_empty());
        removed
    }

    pub(crate) fn remove(&self, pair: &PairId, id: u64) {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(list) = map.get_mut(pair) {
            list.retain(|e| e.id != id);
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
    /// Тройки нет в текущем наборе: соединение закрыто отказом.
    NotAllowed,
}

/// Пара подтверждена: поднять лимиты, применить правило одного соединения.
pub(crate) fn promote(
    inner: &Arc<Inner>,
    conn: quinn::Connection,
    pair: PairId,
    initiator: bool,
    ours_pub: [u8; 32],
    theirs_pub: [u8; 32],
) -> Promoted {
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(inner.cfg.post_auth_bidi));
    conn.set_receive_window(VarInt::from_u32(inner.cfg.post_auth_receive_window));
    match inner.registry.admit(
        &inner.peers,
        pair,
        conn.clone(),
        initiator,
        ours_pub,
        theirs_pub,
    ) {
        Verdict::NotAllowed => {
            refuse(&conn);
            Promoted::NotAllowed
        }
        Verdict::Keep { id, replaced } => {
            if let Some(old) = replaced {
                close_duplicate(&old);
                let _ = inner
                    .events
                    .send(TransportEvent::ConnectionReplaced { pair });
            }
            spawn_monitor(inner, conn.clone(), pair, id);
            Promoted::Winner(QuinnConn {
                id,
                conn,
                pair,
                initiator,
            })
        }
        Verdict::Lose {
            winner,
            winner_id,
            winner_initiator,
        } => {
            close_duplicate(&conn);
            inner
                .counters
                .duplicates_closed
                .fetch_add(1, Ordering::Relaxed);
            Promoted::Lost(QuinnConn {
                id: winner_id,
                conn: winner,
                pair,
                initiator: winner_initiator,
            })
        }
    }
}

/// Опрос `remote_address()` раз в `addr_poll` до закрытия; событие смены адреса; уборка записи.
fn spawn_monitor(inner: &Arc<Inner>, conn: quinn::Connection, pair: PairId, id: u64) {
    let inner = inner.clone();
    let mut last = conn.remote_address();
    // закрепление адреса собеседника до закрытия (берётся синхронно, до конца `serve`);
    // при смене адреса перепинивается
    let mut pin = inner.knock.pin(last);
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(inner.cfg.addr_poll.max(std::time::Duration::from_millis(1)));
        let reason = loop {
            tokio::select! {
                e = conn.closed() => break e,
                _ = tick.tick() => {
                    let now = conn.remote_address();
                    if now != last {
                        last = now;
                        pin = inner.knock.pin(now);
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
        drop(pin);
        inner.registry.remove(&pair, id);
    });
}
