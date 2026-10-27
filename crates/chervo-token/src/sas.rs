//! SAS (короткая строка для сверки людьми) и сообщение-решение.

use std::fmt;

use blake2::{Blake2s256, Digest};
use chervo_identity::{KxPublicKey, PublicKey};

use crate::{DECISION_LEN, InviteError, MSG_DECISION, PROTO_V1, SAS_TAG};

/// SAS: первые 8 байт хэша; на экран выводится как 8 десятичных цифр.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas([u8; 8]);

impl Sas {
    /// Сырые 8 байт: чтобы GUI мог показать SAS другим алфавитом без изменения ядра.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// 8 цифр в виде `"1234 5678"`: `u64::from_be_bytes % 100_000_000`.
    pub fn digits(&self) -> String {
        let n = u64::from_be_bytes(self.0) % 100_000_000;
        format!("{:04} {:04}", n / 10_000, n % 10_000)
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sas(..)")
    }
}

/// `SAS = первые 8 байт BLAKE2s-256(SAS_TAG || token_hash || A_ed || A_x || B_ed || B_x || r_A || r_B)`.
/// Экспортёр TLS, хэш рукопожатия и эфемерные ключи в SAS не входят (спецификация, решение 1).
pub(crate) fn compute(
    token_hash: &[u8; 32],
    a_ed: &PublicKey,
    a_x: &KxPublicKey,
    b_ed: &PublicKey,
    b_x: &KxPublicKey,
    r_a: &[u8; 32],
    r_b: &[u8; 32],
) -> Sas {
    let mut h = Blake2s256::new();
    h.update(SAS_TAG);
    h.update(token_hash);
    h.update(a_ed.to_bytes());
    h.update(a_x.to_bytes());
    h.update(b_ed.to_bytes());
    h.update(b_x.to_bytes());
    h.update(r_a);
    h.update(r_b);
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 8];
    for (o, f) in out.iter_mut().zip(full.iter()) {
        *o = *f;
    }
    Sas(out)
}

/// Решение стороны: `[MSG_DECISION][PROTO_V1][1 подтвердил | 0 отказ]`.
pub fn encode_decision(confirm: bool) -> [u8; DECISION_LEN] {
    [MSG_DECISION, PROTO_V1, u8::from(confirm)]
}

/// Только ровно эти 3 байта, последний 0 или 1.
pub fn decode_decision(b: &[u8]) -> Result<bool, InviteError> {
    match b {
        [m, p, v] if *m == MSG_DECISION && *p == PROTO_V1 => match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(InviteError::Malformed),
        },
        _ => Err(InviteError::Malformed),
    }
}
