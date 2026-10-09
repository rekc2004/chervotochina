use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

use crate::IdentityError;

/// Домены подписи. Тег добавляется перед сообщением и разделяет назначения подписей.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignDomain {
    Invite,
    AddressUpdate,
    KeyRevocation,
}

impl SignDomain {
    pub const ALL: &'static [SignDomain] = &[
        SignDomain::Invite,
        SignDomain::AddressUpdate,
        SignDomain::KeyRevocation,
    ];

    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Invite => b"chervotochina/v1/invite\0",
            Self::AddressUpdate => b"chervotochina/v1/address-update\0",
            Self::KeyRevocation => b"chervotochina/v1/key-revocation\0",
        }
    }
}

fn tagged(domain: SignDomain, msg: &[u8]) -> Vec<u8> {
    let tag = domain.tag();
    let mut buf = Vec::with_capacity(tag.len().saturating_add(msg.len()));
    buf.extend_from_slice(tag);
    buf.extend_from_slice(msg);
    buf
}

/// Проверенный публичный ключ Ed25519.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Единственный путь для недоверенных байт ключа. Отвергает неверную длину,
    /// не-точки, малый порядок и неканоническую кодировку.
    pub fn try_from_slice(b: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; 32] = b.try_into().map_err(|_| IdentityError::InvalidPublicKey)?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::InvalidPublicKey)?;
        if vk.is_weak() {
            return Err(IdentityError::InvalidPublicKey);
        }
        // `to_bytes()` возвращает исходный ввод, поэтому каноничность проверяем перекодированием.
        let canonical = VerifyingKey::from(vk.to_edwards()).to_bytes();
        if canonical != arr {
            return Err(IdentityError::InvalidPublicKey);
        }
        Ok(Self(vk))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Строгая проверка подписи над `тег домена || msg`. Любая ошибка даёт `BadSignature`.
    pub fn verify(&self, domain: SignDomain, msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
        let arr: [u8; 64] = sig.try_into().map_err(|_| IdentityError::BadSignature)?;
        let signature = Signature::from_bytes(&arr);
        self.0
            .verify_strict(&tagged(domain, msg), &signature)
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(..)")
    }
}

/// Ключ пары. Приватная часть обнуляется при уничтожении, наружу не отдаётся.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::PairKey>();
/// ```
///
/// Нет `PartialEq`:
///
/// ```compile_fail
/// fn needs<T: PartialEq>() {}
/// needs::<chervo_identity::PairKey>();
/// ```
///
/// Нет `Hash`:
///
/// ```compile_fail
/// fn needs<T: std::hash::Hash>() {}
/// needs::<chervo_identity::PairKey>();
/// ```
///
/// Нет `Deref`:
///
/// ```compile_fail
/// fn needs<T: std::ops::Deref>() {}
/// needs::<chervo_identity::PairKey>();
/// ```
///
/// Положительные контроли (та же конструкция `needs::<T>()` компилируется там,
/// где свойство есть, поэтому `compile_fail` выше падают не из-за опечатки в пути):
///
/// ```
/// fn needs<T: Clone + PartialEq + std::hash::Hash>() {}
/// needs::<chervo_identity::PairId>();
/// ```
///
/// ```
/// fn needs<T: std::ops::Deref>() {}
/// needs::<zeroize::Zeroizing<Vec<u8>>>();
/// ```
pub struct PairKey(SigningKey);

impl PairKey {
    /// Создаётся только из seed в `store`; seed копируется внутрь и обнуляется там.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Подпись над `тег домена || msg`.
    pub fn sign(&self, domain: SignDomain, msg: &[u8]) -> Result<[u8; 64], IdentityError> {
        let sig = self
            .0
            .try_sign(&tagged(domain, msg))
            .map_err(|_| IdentityError::SigningFailed)?;
        Ok(sig.to_bytes())
    }
}

impl fmt::Debug for PairKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairKey(..)")
    }
}

// Единственное поле `SigningKey` обнуляется само при уничтожении (ed25519-dalek, фича zeroize).
impl ZeroizeOnDrop for PairKey {}
