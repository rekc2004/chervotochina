//! Таблица меток приёмника: `id -> (пара, окно)` для окон `w-1, w, w+1` по каждой действующей
//! паре (направление приёма). Один поиск в хэш-таблице на слот; AEAD только при попадании.
//! Метка, совпавшая у двух разных пар, убирается из таблицы (отказ в закрытом виде).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;

#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};

use chervo_identity::{LAN_ID_LEN, LAN_NONCE_LEN, LanKeys, PairId};

use crate::limits::MAX_PEERS;

type Id = [u8; LAN_ID_LEN];

pub(crate) struct IdTable {
    peers: Vec<(PairId, LanKeys)>,
    window: u64,
    map: HashMap<Id, (usize, u64)>,
    collisions: usize,
    /// Только для тестов: сколько раз вызывался `open` (проверка «0 вызовов AEAD»).
    #[cfg(test)]
    opens: AtomicU32,
}

impl fmt::Debug for IdTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdTable(..)")
    }
}

/// Окна таблицы вокруг `w` без повторов на краях диапазона.
fn windows_around(w: u64) -> Vec<u64> {
    let mut v = vec![w.saturating_sub(1), w, w.saturating_add(1)];
    v.dedup();
    v
}

impl IdTable {
    pub(crate) fn empty() -> Self {
        Self {
            peers: Vec::new(),
            window: 0,
            map: HashMap::new(),
            collisions: 0,
            #[cfg(test)]
            opens: AtomicU32::new(0),
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn from_peers(peers: Vec<(PairId, LanKeys)>, window: u64) -> Self {
        let mut t = Self::empty();
        t.set_peers(peers, window);
        t
    }

    /// Новый набор пар. Повтор пары отбрасывается (остаётся первая запись), сверх `MAX_PEERS`
    /// лишние отбрасываются.
    pub(crate) fn set_peers(&mut self, peers: Vec<(PairId, LanKeys)>, window: u64) {
        let mut seen: HashSet<PairId> = HashSet::new();
        let mut kept: Vec<(PairId, LanKeys)> = Vec::new();
        for (id, k) in peers {
            if kept.len() >= MAX_PEERS {
                break;
            }
            if seen.insert(id) {
                kept.push((id, k));
            }
        }
        self.peers = kept;
        self.rebuild(window);
    }

    /// Пересчёт меток под окно `window` (смена окна).
    pub(crate) fn rebuild(&mut self, window: u64) {
        self.build_with(window, &|k, w| k.recv_id(w));
    }

    /// Построение с подменой функции метки: только чтобы проверить столкновение меток, которое
    /// на настоящих ключах недостижимо.
    #[cfg(test)]
    pub(crate) fn from_peers_with(
        peers: Vec<(PairId, LanKeys)>,
        window: u64,
        f: &dyn Fn(usize, u64) -> Id,
    ) -> Self {
        let mut t = Self::empty();
        t.peers = peers;
        t.build_indexed(window, f);
        t
    }

    fn build_with(&mut self, window: u64, id_of: &dyn Fn(&LanKeys, u64) -> Id) {
        let ids: Vec<Vec<(u64, Id)>> = self
            .peers
            .iter()
            .map(|(_, k)| {
                windows_around(window)
                    .into_iter()
                    .map(|w| (w, id_of(k, w)))
                    .collect()
            })
            .collect();
        self.fill(window, ids);
    }

    #[cfg(test)]
    fn build_indexed(&mut self, window: u64, f: &dyn Fn(usize, u64) -> Id) {
        let ids: Vec<Vec<(u64, Id)>> = (0..self.peers.len())
            .map(|i| {
                windows_around(window)
                    .into_iter()
                    .map(|w| (w, f(i, w)))
                    .collect()
            })
            .collect();
        self.fill(window, ids);
    }

    fn fill(&mut self, window: u64, ids: Vec<Vec<(u64, Id)>>) {
        let mut map: HashMap<Id, (usize, u64)> = HashMap::new();
        let mut poisoned: HashSet<Id> = HashSet::new();
        for (idx, list) in ids.into_iter().enumerate() {
            for (w, id) in list {
                if poisoned.contains(&id) {
                    continue;
                }
                match map.get(&id) {
                    Some((prev, _)) if *prev != idx => {
                        poisoned.insert(id);
                    }
                    // та же пара в соседнем окне с той же меткой: остаётся первая запись
                    Some(_) => {}
                    None => {
                        map.insert(id, (idx, w));
                    }
                }
            }
        }
        for id in &poisoned {
            map.remove(id);
        }
        self.collisions = poisoned.len();
        self.map = map;
        self.window = window;
    }

    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    pub(crate) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Число меток, убранных из-за столкновения.
    #[cfg(test)]
    pub(crate) fn collisions(&self) -> usize {
        self.collisions
    }

    /// Число меток в таблице.
    #[cfg(test)]
    pub(crate) fn id_count(&self) -> usize {
        self.map.len()
    }

    /// Пары и их ключи (для сборки своих датаграмм).
    pub(crate) fn peers(&self) -> impl Iterator<Item = (PairId, &LanKeys)> {
        self.peers.iter().map(|(p, k)| (*p, k))
    }

    #[cfg(test)]
    pub(crate) fn contains_id(&self, id: &Id) -> bool {
        self.map.contains_key(id)
    }

    /// Разбор слота по метке: пара, окно метки и AEAD-открытие. `None`, если метки нет в
    /// таблице (AEAD не вызывается) или слот не открылся.
    pub(crate) fn open_slot(
        &self,
        nonce: &[u8; LAN_NONCE_LEN],
        src: Ipv4Addr,
        slot: &[u8],
    ) -> Option<(PairId, u16)> {
        let id: Id = slot.get(..LAN_ID_LEN)?.try_into().ok()?;
        let (idx, w) = *self.map.get(&id)?;
        let (pair, keys) = self.peers.get(idx)?;
        #[cfg(test)]
        self.opens.fetch_add(1, Ordering::Relaxed);
        let port = keys.open(w, nonce, src, slot)?;
        Some((*pair, port))
    }

    #[cfg(test)]
    pub(crate) fn opens(&self) -> u32 {
        self.opens.load(Ordering::Relaxed)
    }
}
