use zeroize::Zeroizing;

use crate::keys::PairKey;
use crate::kx::KxPublicKey;
use crate::{IdentityError, KEY_BLOB_LEN, KEY_BLOB_VERSION, PairId, PublicKey};

// Раскладка записи v2.
const ED_SEED: core::ops::Range<usize> = 1..33;
const ED_PUBLIC: core::ops::Range<usize> = 33..65;
const X_SECRET: core::ops::Range<usize> = 65..97;
const X_PUBLIC: core::ops::Range<usize> = 97..129;

/// Хранилище секретов по парам. `read` возвращает `None`, только если записи точно нет.
pub trait SecretStore: Send + Sync {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;
    /// Перезапись записи.
    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError>;
    /// Записи нет: `Ok(())`.
    fn delete(&self, pair: &PairId) -> Result<(), IdentityError>;
}

/// Хранилище ключа списка друзей: одна запись `LIST_KEY_ACCOUNT`, отдельная от записей пар.
/// `read_list_key` возвращает `None`, только если записи точно нет.
pub trait ListKeyStore: Send + Sync {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;
    /// Перезапись записи.
    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError>;
    /// Записи нет: `Ok(())`.
    fn delete_list_key(&self) -> Result<(), IdentityError>;
}

/// Заглушка хранилища: всегда `NotImplemented`.
pub struct UnavailableKeyStore;

impl ListKeyStore for UnavailableKeyStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Err(IdentityError::NotImplemented)
    }

    fn write_list_key(&self, _key: &[u8]) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        Err(IdentityError::NotImplemented)
    }
}

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

/// Новый ключ; запись для хранилища `[версия][seed Ed25519][публичный Ed25519][секрет X25519]
/// [публичный X25519]` заполняется в переданном буфере, чтобы массивы с секретами не перемещались.
fn fresh_key(blob: &mut Zeroizing<[u8; KEY_BLOB_LEN]>) -> Result<PairKey, IdentityError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| IdentityError::RandomUnavailable)?;
    let mut x_secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(x_secret.as_mut_slice()).map_err(|_| IdentityError::RandomUnavailable)?;
    let key = PairKey::from_secrets(&seed, &x_secret);
    let public = key.public_key().to_bytes();
    let x_public = key.kx_public().to_bytes();

    *blob.first_mut().ok_or(IdentityError::CorruptKey)? = KEY_BLOB_VERSION;
    blob.get_mut(ED_SEED)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(seed.as_slice());
    blob.get_mut(ED_PUBLIC)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(public.as_slice());
    blob.get_mut(X_SECRET)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(x_secret.as_slice());
    blob.get_mut(X_PUBLIC)
        .ok_or(IdentityError::CorruptKey)?
        .copy_from_slice(x_public.as_slice());
    Ok(key)
}

/// Записать новый ключ и убедиться, что хранилище вернуло те же байты.
fn write_new<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError> {
    let mut blob = Zeroizing::new([0u8; KEY_BLOB_LEN]);
    let key = fresh_key(&mut blob)?;
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
    let seed_src = blob.get(ED_SEED).ok_or(IdentityError::CorruptKey)?;
    let public_src = blob.get(ED_PUBLIC).ok_or(IdentityError::CorruptKey)?;
    let x_secret_src = blob.get(X_SECRET).ok_or(IdentityError::CorruptKey)?;
    let x_public_src = blob.get(X_PUBLIC).ok_or(IdentityError::CorruptKey)?;

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(seed_src);
    let mut x_secret = Zeroizing::new([0u8; 32]);
    x_secret.copy_from_slice(x_secret_src);
    let key = PairKey::from_secrets(&seed, &x_secret);
    let public = key.public_key();
    if public.to_bytes().as_slice() != public_src {
        return Err(IdentityError::CorruptKey);
    }
    if key.kx_public().to_bytes().as_slice() != x_public_src {
        return Err(IdentityError::CorruptKey);
    }
    KxPublicKey::try_from_slice(x_public_src).map_err(|_| IdentityError::CorruptKey)?;
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
