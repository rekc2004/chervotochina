#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
//! Общие помощники интеграционных тестов О1: хранилища и временный каталог.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_identity::{
    IdentityError, KxPublicKey, ListKeyStore, PairId, PairKey, PublicKey, SecretStore, create,
};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
    pub deletes: AtomicUsize,
}

impl MemStore {
    pub fn has(&self, pair: &PairId) -> bool {
        self.map.lock().unwrap().contains_key(pair)
    }

    pub fn pair_count(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn list_key(&self) -> Option<Vec<u8>> {
        self.list.lock().unwrap().as_ref().map(|k| k.to_vec())
    }

    pub fn put_raw(&self, pair: &PairId, blob: &[u8]) {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
    }
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.put_raw(pair, blob);
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .list
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = None;
        Ok(())
    }
}

/// Запись ключа пары всегда падает; ключ списка работает.
#[derive(Default)]
pub struct FailingCreateStore {
    pub inner: MemStore,
}

impl SecretStore for FailingCreateStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read(pair)
    }

    fn write(&self, _pair: &PairId, _blob: &[u8]) -> Result<(), IdentityError> {
        Err(IdentityError::StorageUnavailable)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.inner.delete(pair)
    }
}

impl ListKeyStore for FailingCreateStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read_list_key()
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.inner.write_list_key(key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        self.inner.delete_list_key()
    }
}

/// Все операции: заданная ошибка хранилища.
pub struct ErrStore(pub IdentityError);

pub fn locked_store() -> ErrStore {
    ErrStore(IdentityError::StorageLocked)
}

pub fn unavailable_store() -> ErrStore {
    ErrStore(IdentityError::StorageUnavailable)
}

impl SecretStore for ErrStore {
    fn read(&self, _p: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Err(self.0)
    }

    fn write(&self, _p: &PairId, _b: &[u8]) -> Result<(), IdentityError> {
        Err(self.0)
    }

    fn delete(&self, _p: &PairId) -> Result<(), IdentityError> {
        Err(self.0)
    }
}

impl ListKeyStore for ErrStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Err(self.0)
    }

    fn write_list_key(&self, _k: &[u8]) -> Result<(), IdentityError> {
        Err(self.0)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        Err(self.0)
    }
}

pub type LockedStore = ErrStore;
pub type UnavailableStore = ErrStore;

/// Проверяет при каждой записи ключа пары, что запись pending уже лежит в файле списка.
pub struct ProbeStore {
    pub inner: MemStore,
    pub path: PathBuf,
    pub pending_seen: Mutex<Vec<usize>>,
}

impl ProbeStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            inner: MemStore::default(),
            path,
            pending_seen: Mutex::new(Vec::new()),
        }
    }
}

impl SecretStore for ProbeStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read(pair)
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        let n = FriendBook::open(&self.path, &self.inner)
            .map(|b| b.pending().len())
            .unwrap_or(usize::MAX);
        self.pending_seen.lock().unwrap().push(n);
        self.inner.write(pair, blob)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.inner.delete(pair)
    }
}

impl ListKeyStore for ProbeStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.inner.read_list_key()
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.inner.write_list_key(key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        self.inner.delete_list_key()
    }
}

/// Временный каталог под `CARGO_TARGET_TMPDIR`, удаляется при уничтожении.
pub struct TestDir(pub PathBuf);

static COUNTER: AtomicUsize = AtomicUsize::new(0);

impl TestDir {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut rnd = [0u8; 4];
        getrandom::fill(&mut rnd).unwrap();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "friends-{}-{n}-{}",
            std::process::id(),
            u32::from_be_bytes(rnd)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn file(&self) -> PathBuf {
        self.0.join("friends.chfl")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ключи «друга» (чужая сторона пары).
pub struct Remote {
    pub ed: PublicKey,
    pub x: KxPublicKey,
    pub key: PairKey,
}

pub fn remote() -> Remote {
    let key = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    Remote {
        ed: key.public_key(),
        x: key.kx_public(),
        key,
    }
}

pub struct Added {
    pub pair: PairId,
    pub remote: Remote,
    pub our_ed: PublicKey,
    pub our_x: KxPublicKey,
}

pub fn new_friend(name: &str, r: &Remote, our_ed: PublicKey, our_x: KxPublicKey) -> NewFriend {
    NewFriend {
        name: name.to_owned(),
        friend_ed: r.ed,
        friend_x: r.x,
        our_ed,
        our_x,
        addrs: Vec::new(),
        now_unix: 1234,
    }
}

/// begin_pair(Inviter) + finish_pair с новым «другом».
pub fn add_friend(book: &mut FriendBook, store: &MemStore, name: &str) -> Added {
    let (pair, key) = book
        .begin_pair(store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    drop(key);
    let r = remote();
    book.finish_pair(store, &pair, new_friend(name, &r, our_ed, our_x))
        .unwrap();
    Added {
        pair,
        remote: r,
        our_ed,
        our_x,
    }
}
