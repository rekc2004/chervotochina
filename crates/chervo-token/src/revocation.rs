//! Токен отзыва ключа пары: `CHR1…`, подписан старым ключом пары (домен `KeyRevocation`).
//!
//! Формат (139 байт, числа big-endian):
//! `[0x01][0x02][issued_at u64][revoked_ed 32][revoked_x 32][reason u8][подпись 64]`;
//! подпись над первыми 75 байтами.

use std::fmt;

use chervo_identity::{KxPublicKey, PairKey, PublicKey, SignDomain};

use crate::{KIND_REVOCATION, REVOCATION_PREFIX, TOKEN_VERSION, TokenError, base32};

const BODY_LEN: usize = 75;
const TOTAL_LEN: usize = 139;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationReason {
    /// Байт 1.
    Rekey,
    /// Байт 2.
    Removed,
}

impl RevocationReason {
    const fn byte(self) -> u8 {
        match self {
            Self::Rekey => 1,
            Self::Removed => 2,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Rekey),
            2 => Some(Self::Removed),
            _ => None,
        }
    }
}

/// Проверенный отзыв: подпись проверена ключом из самого отзыва.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RevocationNotice {
    pub revoked_ed: PublicKey,
    pub revoked_x: KxPublicKey,
    pub reason: RevocationReason,
    pub issued_at: u64,
}

impl fmt::Debug for RevocationNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevocationNotice(..)")
    }
}

/// Текст отзыва, подписанный `key` (старый ключ пары).
pub fn issue_revocation(
    key: &PairKey,
    reason: RevocationReason,
    issued_at: u64,
) -> Result<String, TokenError> {
    let mut b = Vec::with_capacity(TOTAL_LEN);
    b.push(TOKEN_VERSION);
    b.push(KIND_REVOCATION);
    b.extend_from_slice(&issued_at.to_be_bytes());
    b.extend_from_slice(&key.public_key().to_bytes());
    b.extend_from_slice(&key.kx_public().to_bytes());
    b.push(reason.byte());
    let sig = key
        .sign(SignDomain::KeyRevocation, &b)
        .map_err(|_| TokenError::SigningFailed)?;
    b.extend_from_slice(&sig);
    Ok(format!("{REVOCATION_PREFIX}{}", base32::encode(&b)))
}

/// Разбор двоичного отзыва (версия и вид уже проверены `decode`).
pub(crate) fn parse(b: &[u8]) -> Result<RevocationNotice, TokenError> {
    if b.len() != TOTAL_LEN {
        return Err(TokenError::Malformed);
    }
    let body = b.get(..BODY_LEN).ok_or(TokenError::Malformed)?;
    let sig = b.get(BODY_LEN..).ok_or(TokenError::Malformed)?;
    let issued_at = u64::from_be_bytes(
        b.get(2..10)
            .and_then(|s| s.try_into().ok())
            .ok_or(TokenError::Malformed)?,
    );
    let ed = b.get(10..42).ok_or(TokenError::Malformed)?;
    let x = b.get(42..74).ok_or(TokenError::Malformed)?;
    let reason = b
        .get(74)
        .copied()
        .and_then(RevocationReason::from_byte)
        .ok_or(TokenError::Malformed)?;
    let revoked_ed = PublicKey::try_from_slice(ed).map_err(|_| TokenError::BadKey)?;
    let revoked_x = KxPublicKey::try_from_slice(x).map_err(|_| TokenError::BadKey)?;
    revoked_ed
        .verify(SignDomain::KeyRevocation, body, sig)
        .map_err(|_| TokenError::BadSignature)?;
    Ok(RevocationNotice {
        revoked_ed,
        revoked_x,
        reason,
        issued_at,
    })
}
