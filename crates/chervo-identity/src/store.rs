use zeroize::Zeroizing;

use crate::keys::PairKey;
use crate::{IdentityError, KEY_BLOB_LEN, KEY_BLOB_VERSION, PairId, PublicKey};

/// Хранилище секретов по парам. `read` возвращает `None`, только если записи точно нет.
pub trait SecretStore: Send + Sync {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;
    /// Перезапись записи.
    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError>;
    /// Записи нет: `Ok(())`.
    fn delete(&self, pair: &PairId) -> Result<(), IdentityError>;
}

/// Заглушка хранилища: всегда `NotImplemented`.
pub struct UnavailableKeyStore;

impl SecretStore for UnavailableKeyStore {
    fn read(&self, _pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Err(IdentityError::NotImplemented)
    }

    fn write(&self, _pair: &PairId, _blob: &[u8]) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented)
    }

    fn delete(&self, _pair: &PairId) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented)
    }
}

/// Новый ключ и запись для хранилища: `[версия][seed][публичный ключ]`.
fn fresh_key() -> Result<(PairKey, Zeroizing<[u8; KEY_BLOB_LEN]>), IdentityError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| IdentityError::RandomUnavailable)?;
    let key = PairKey::from_seed(&seed);
    let public = key.public_key().to_bytes();

    let mut blob = Zeroizing::new([0u8; KEY_BLOB_LEN]);
    *blob.first_mut().ok_or(IdentityError::CorruptKey)? = KEY_BLOB_VERSION;
    blob.get_mut(1..33)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(seed.as_slice());
    blob.get_mut(33..KEY_BLOB_LEN)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(public.as_slice());
    Ok((key, blob))
}

/// Записать новый ключ и убедиться, что хранилище вернуло те же байты.
fn write_new<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError> {
    let (key, blob) = fresh_key()?;
    store.write(pair, blob.as_slice())?;
    match store.read(pair)? {
        Some(back) if back.as_slice() == blob.as_slice() => Ok(key),
        _ => Err(IdentityError::StorageInconsistent),
    }
}

/// Явное создание ключа пары. Существующую запись (даже испорченную) не трогает.
pub fn create<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError> {
    if store.read(pair)?.is_some() {
        return Err(IdentityError::KeyAlreadyExists);
    }
    write_new(store, pair)
}

/// Загрузка с проверкой формата, целостности и ожидаемого публичного ключа.
/// Ничего не создаёт и не перезаписывает.
pub fn load<S: SecretStore + ?Sized>(
    store: &S,
    pair: &PairId,
    expected: &PublicKey,
) -> Result<PairKey, IdentityError> {
    let blob = store.read(pair)?.ok_or(IdentityError::KeyMissing)?;
    let first = blob.first().ok_or(IdentityError::CorruptKey)?;
    if *first != KEY_BLOB_VERSION {
        return Err(IdentityError::UnsupportedKeyVersion);
    }
    if blob.len() != KEY_BLOB_LEN {
        return Err(IdentityError::CorruptKey);
    }
    let seed_src = blob.get(1..33).ok_or(IdentityError::CorruptKey)?;
    let public_src = blob
        .get(33..KEY_BLOB_LEN)
        .ok_or(IdentityError::CorruptKey)?;

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(seed_src);
    let key = PairKey::from_seed(&seed);
    let public = key.public_key();
    if public.to_bytes().as_slice() != public_src {
        return Err(IdentityError::CorruptKey);
    }
    if public != *expected {
        return Err(IdentityError::KeyMismatch);
    }
    Ok(key)
}

/// Явное пересоздание ключа. Записи нет: `KeyMissing`. Запись есть (в том числе
/// испорченная): заменяется новым ключом.
pub fn rekey<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError> {
    if store.read(pair)?.is_none() {
        return Err(IdentityError::KeyMissing);
    }
    write_new(store, pair)
}
