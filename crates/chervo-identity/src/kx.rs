use std::fmt;

use curve25519_dalek::montgomery::MontgomeryPoint;
use x25519_dalek::StaticSecret;
use zeroize::ZeroizeOnDrop;

use crate::IdentityError;

/// Проверенный публичный ключ X25519 (ключ обмена пары).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KxPublicKey([u8; 32]);

impl KxPublicKey {
    /// Единственный путь для недоверенных байт ключа обмена. Отвергает неверную длину,
    /// точки кручения (в том числе u = -1), точки малого порядка и неканоническую
    /// кодировку (старший бит, u >= p). Только вызовы curve25519-dalek.
    pub fn try_from_slice(b: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| IdentityError::InvalidKxPublicKey)?;
        let edwards = MontgomeryPoint(arr)
            .to_edwards(0)
            .ok_or(IdentityError::InvalidKxPublicKey)?;
        if edwards.is_small_order() {
            return Err(IdentityError::InvalidKxPublicKey);
        }
        if edwards.to_montgomery().to_bytes() != arr {
            return Err(IdentityError::InvalidKxPublicKey);
        }
        Ok(Self(arr))
    }

    /// Только для ключей, выведенных из собственного секрета (заведомо корректных).
    pub(crate) const fn from_derived(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for KxPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KxPublicKey(..)")
    }
}

/// Ключ обмена пары (X25519): секрет и публичная часть. Секрет обнуляется при
/// уничтожении, наружу не отдаётся. Получается только из `PairKey::into_kx`.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::PairKx>();
/// ```
///
/// Нет `PartialEq`:
///
/// ```compile_fail
/// fn needs<T: PartialEq>() {}
/// needs::<chervo_identity::PairKx>();
/// ```
///
/// Нет `Hash`:
///
/// ```compile_fail
/// fn needs<T: std::hash::Hash>() {}
/// needs::<chervo_identity::PairKx>();
/// ```
///
/// Нет `Deref`:
///
/// ```compile_fail
/// fn needs<T: std::ops::Deref>() {}
/// needs::<chervo_identity::PairKx>();
/// ```
pub struct PairKx {
    pub(crate) secret: StaticSecret,
    public: KxPublicKey,
}

impl PairKx {
    pub(crate) fn new(secret: StaticSecret, public: KxPublicKey) -> Self {
        Self { secret, public }
    }

    pub fn public(&self) -> KxPublicKey {
        self.public
    }
}

impl fmt::Debug for PairKx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairKx(..)")
    }
}

// Поле `StaticSecret` обнуляется само при уничтожении (x25519-dalek, фича zeroize).
impl ZeroizeOnDrop for PairKx {}
