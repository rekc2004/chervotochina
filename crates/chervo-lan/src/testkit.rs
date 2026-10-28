//! Тестовая оснастка: пары с настоящими ключами из хранилища в памяти. Только под `test` и
//! `fuzzing`.

use std::collections::HashMap;
use std::sync::Mutex;

use chervo_identity::{
    IdentityError, KEY_BLOB_VERSION, KxPeer, LanKeys, PairId, PairKey, PublicKey, SecretStore,
    create, load,
};
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

/// Ключ пары из фиксированных секретов (по метке `tag`): запись в хранилище собирается вручную и
/// читается обычным `chervo_identity::load`, обходных входов в идентичность нет.
fn fixed_pair_key(pair: PairId, tag: u8) -> Option<PairKey> {
    let seed = [tag; 32];
    let x_secret = [tag.wrapping_add(100); 32];
    let ed_public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let x_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x_secret)).to_bytes();
    let mut blob = vec![KEY_BLOB_VERSION];
    for part in [&seed, &ed_public, &x_secret, &x_public] {
        blob.extend_from_slice(part);
    }
    let store = MemStore::default();
    store.write(&pair, &blob).ok()?;
    let expected = PublicKey::try_from_slice(&ed_public).ok()?;
    load(&store, &pair, &expected).ok()
}

/// Пара `i` с фиксированными ключами: (идентификатор, участник A, участник B). Одни и те же
/// байты при каждом запуске: нужна fuzz-цели и корпусу с настоящей датаграммой.
pub(crate) fn fixed_peer_duo(i: u8) -> Option<(PairId, KxPeer, KxPeer)> {
    let pair = PairId::from_bytes([i; 16]);
    let ka = fixed_pair_key(pair, i.wrapping_mul(2).wrapping_add(1))?;
    let kb = fixed_pair_key(pair, i.wrapping_mul(2).wrapping_add(2))?;
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

/// Окно, адрес и порт, под которые собран корпус fuzz-цели.
pub(crate) const FUZZ_WINDOW: u64 = 1000;
pub(crate) const FUZZ_PORT: u16 = 40_000;

/// Таблица получателя из `n` пар с фиксированными ключами (окно `FUZZ_WINDOW`).
pub(crate) fn fuzz_table(n: usize) -> IdTable {
    let peers: Vec<(PairId, LanKeys)> = (0..u8::try_from(n).unwrap_or(0))
        .filter_map(|i| {
            let (pair, _, b) = fixed_peer_duo(i)?;
            Some((pair, b.lan_keys().ok()?))
        })
        .collect();
    IdTable::from_peers(peers, FUZZ_WINDOW)
}

/// Верная датаграмма отправителя от `n` пар с фиксированными ключами: её разберёт `fuzz_table(n)`
/// с источником 192.168.50.7. Случайны только nonce, порядок слотов и пустые слоты.
pub(crate) fn fuzz_datagram(n: usize, src: std::net::Ipv4Addr) -> Option<Vec<u8>> {
    let keyed: Vec<(PairId, LanKeys)> = (0..u8::try_from(n).unwrap_or(0))
        .filter_map(|i| {
            let (pair, a, _) = fixed_peer_duo(i)?;
            Some((pair, a.lan_keys().ok()?))
        })
        .collect();
    let refs: Vec<(PairId, &LanKeys)> = keyed.iter().map(|(p, k)| (*p, k)).collect();
    let d = crate::wire::build(&refs, FUZZ_WINDOW, src, FUZZ_PORT, 0, &[0x33; 32]).ok()?;
    d.first().map(|x| x.to_vec())
}
