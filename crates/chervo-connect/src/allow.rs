//! Набор пар, которым транспорт разрешает соединяться (фильтр до чтения прикладных данных).

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use chervo_identity::PairId;
use chervo_transport::PeerFilter;

pub struct AllowSet {
    pairs: RwLock<HashSet<PairId>>,
}

impl AllowSet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pairs: RwLock::new(HashSet::new()),
        })
    }

    /// Заменить набор целиком; возвращает прежний (для отката).
    pub(crate) fn replace(&self, new: HashSet<PairId>) -> HashSet<PairId> {
        let mut g = self
            .pairs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::replace(&mut *g, new)
    }
}

impl fmt::Debug for AllowSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AllowSet(..)")
    }
}

impl PeerFilter for AllowSet {
    fn is_allowed(&self, pair: &PairId) -> bool {
        self.pairs.read().is_ok_and(|g| g.contains(pair))
    }
}
