#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use chervo_identity::{IdentityError, PairId, SecretStore};
use zeroize::Zeroizing;

/// Хранилище в памяти.
#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Хранилище с готовой записью (для испорченных записей).
    pub fn with_raw(pair: &PairId, bytes: Vec<u8>) -> Self {
        let s = Self::new();
        s.map.lock().unwrap().insert(*pair, Zeroizing::new(bytes));
        s
    }

    /// Только для тестов.
    pub fn raw(&self, pair: &PairId) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(pair).map(|v| v.to_vec())
    }

    pub fn is_empty(&self) -> bool {
        self.map.lock().unwrap().is_empty()
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
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

/// `read` всегда возвращает заданные байты, запись не принимается.
pub struct FixedStore(pub Vec<u8>);

impl SecretStore for FixedStore {
    fn read(&self, _pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(Some(Zeroizing::new(self.0.clone())))
    }

    fn write(&self, _pair: &PairId, _blob: &[u8]) -> Result<(), IdentityError> {
        Err(IdentityError::StorageUnavailable)
    }

    fn delete(&self, _pair: &PairId) -> Result<(), IdentityError> {
        Ok(())
    }
}

/// `write` успешен, но `read` ничего не находит.
pub struct LossyStore;

impl SecretStore for LossyStore {
    fn read(&self, _pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(None)
    }

    fn write(&self, _pair: &PairId, _blob: &[u8]) -> Result<(), IdentityError> {
        Ok(())
    }

    fn delete(&self, _pair: &PairId) -> Result<(), IdentityError> {
        Ok(())
    }
}

/// Всё возвращает заданную ошибку.
pub struct FailingStore(pub IdentityError);

impl SecretStore for FailingStore {
    fn read(&self, _pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Err(self.0)
    }

    fn write(&self, _pair: &PairId, _blob: &[u8]) -> Result<(), IdentityError> {
        Err(self.0)
    }

    fn delete(&self, _pair: &PairId) -> Result<(), IdentityError> {
        Err(self.0)
    }
}
