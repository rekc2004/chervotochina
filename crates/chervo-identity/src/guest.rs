//! Одноразовый гостевой секрет приглашения (X25519). Не ключ пары: по замыслу его публичная
//! часть и сам секрет уходят в токен приглашения (`docs/specs/stage-11-invite.md`, решение 2).

use std::fmt;

use x25519_dalek::StaticSecret;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::IdentityError;
use crate::kx::{KxPublicKey, PairKx};

/// Гостевой секрет X25519 и его публичная часть. Секрет обнуляется при уничтожении.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::GuestSecret>();
/// ```
///
/// Нет `PartialEq`:
///
/// ```compile_fail
/// fn needs<T: PartialEq>() {}
/// needs::<chervo_identity::GuestSecret>();
/// ```
///
/// Нет `Deref`:
///
/// ```compile_fail
/// fn needs<T: std::ops::Deref>() {}
/// needs::<chervo_identity::GuestSecret>();
/// ```
pub struct GuestSecret {
    secret: StaticSecret,
    public: KxPublicKey,
}

impl GuestSecret {
    /// Новый случайный секрет из CSPRNG ОС.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut_slice()).map_err(|_| IdentityError::RandomUnavailable)?;
        Self::from_bytes(b.as_slice())
    }

    /// Секрет из байт токена. Неверная длина или непригодный публичный ключ:
    /// `InvalidGuestSecret`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, IdentityError> {
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            b.try_into()
                .map_err(|_| IdentityError::InvalidGuestSecret)?,
        );
        let secret = StaticSecret::from(*arr);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let public = KxPublicKey::try_from_slice(public.as_slice())
            .map_err(|_| IdentityError::InvalidGuestSecret)?;
        Ok(Self { secret, public })
    }

    pub fn public(&self) -> KxPublicKey {
        self.public
    }

    /// Копия секрета для токена (только из `as_bytes`, в `Zeroizing`).
    pub fn to_token_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.secret.as_bytes())
    }

    /// Гостевая пара ключей обмена для `KxPeer`.
    pub fn into_kx(self) -> PairKx {
        let Self { secret, public } = self;
        PairKx::new(secret, public)
    }
}

impl fmt::Debug for GuestSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestSecret(..)")
    }
}

// Поле `StaticSecret` обнуляется само при уничтожении (x25519-dalek, фича zeroize).
impl ZeroizeOnDrop for GuestSecret {}
