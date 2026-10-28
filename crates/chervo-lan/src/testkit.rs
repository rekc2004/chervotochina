//! Тестовая оснастка: пары с настоящими ключами из хранилища в памяти. Только под `test` и
//! `fuzzing`.

use std::collections::HashMap;
use std::sync::Mutex;

use chervo_identity::{IdentityError, KxPeer, LanKeys, PairId, SecretStore, create};
use zeroize::Zeroizing;

use crate::table::IdTable;

/// Хранилище ключей в памяти.
#[derive(Default)]
pub(crate) struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let g = self
            .map
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        Ok(g.get(pair).map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        let mut g = self
            .map
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        g.insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        let mut g = self
            .map
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        g.remove(pair);
        Ok(())
    }
}

/// Одна пара с двух сторон: ключи отправителя A, ключи получателя B и открытые ключи обмена
/// (для проверки «в маяке нет ключей»).
pub(crate) struct Duo {
    pub(crate) pair: PairId,
    pub(crate) a: LanKeys,
    pub(crate) b: LanKeys,
    pub(crate) pubs: [[u8; 32]; 2],
}

/// Пара с настоящими случайными ключами: (идентификатор, участник A, участник B).
pub(crate) fn peer_duo() -> Option<(PairId, KxPeer, KxPeer)> {
    let pair = PairId::generate().ok()?;
    let (sa, sb) = (MemStore::default(), MemStore::default());
    let ka = create(&sa, &pair).ok()?;
    let kb = create(&sb, &pair).ok()?;
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    Some((
        pair,
        KxPeer::new(pair, ka.into_kx(), pb),
        KxPeer::new(pair, kb.into_kx(), pa),
    ))
}

/// Одна пара с двух сторон в виде ключей маяка и открытые ключи обмена.
pub(crate) fn duo() -> Option<Duo> {
    let (pair, pa_peer, pb_peer) = peer_duo()?;
    Some(Duo {
        pair,
        pubs: [
            pa_peer.ours_public().to_bytes(),
            pb_peer.ours_public().to_bytes(),
        ],
        a: pa_peer.lan_keys().ok()?,
        b: pb_peer.lan_keys().ok()?,
    })
}

/// Таблица получателя из `n` пар (окно 1000), ключи отправителей отбрасываются.
pub(crate) fn fuzz_table(n: usize) -> IdTable {
    let peers: Vec<(PairId, LanKeys)> = (0..n)
        .filter_map(|_| duo().map(|d| (d.pair, d.b)))
        .collect();
    IdTable::from_peers(peers, 1000)
}
