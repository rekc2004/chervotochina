//! Beacon wire format (spec section 3), pure: no sockets, no clock.
//!
//! ```text
//! offset  len  field
//! 0       1    ver = 0x01
//! 1       12   nonce
//! 13      544  16 slots, sorted ascending by id; slot = id(16) || ct(2) || tag(16)
//! total   557
//! ```
//! Exactly one length and one version are accepted; there are no length fields and no
//! reserved bits.

use chervo_identity::{LAN_NONCE_LEN, LAN_SLOT_LEN};

use crate::limits::{BEACON_LEN, BEACON_VERSION, LAN_SLOTS};

/// Why a datagram is not a beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    Len,
    Version,
}

/// A datagram of the exact length and version. `slots` is `LAN_SLOTS * LAN_SLOT_LEN` bytes.
pub(crate) struct Parsed<'a> {
    pub(crate) nonce: [u8; LAN_NONCE_LEN],
    pub(crate) slots: &'a [u8],
}

pub(crate) fn parse(data: &[u8]) -> Result<Parsed<'_>, ParseError> {
    if data.len() != BEACON_LEN {
        return Err(ParseError::Len);
    }
    let (Some(&ver), Some(rest)) = (data.first(), data.get(1..)) else {
        return Err(ParseError::Len);
    };
    if ver != BEACON_VERSION {
        return Err(ParseError::Version);
    }
    let (Some(nonce), Some(slots)) = (rest.get(..LAN_NONCE_LEN), rest.get(LAN_NONCE_LEN..)) else {
        return Err(ParseError::Len);
    };
    let Ok(nonce) = <[u8; LAN_NONCE_LEN]>::try_from(nonce) else {
        return Err(ParseError::Len);
    };
    if slots.len() != LAN_SLOTS * LAN_SLOT_LEN {
        return Err(ParseError::Len);
    }
    Ok(Parsed { nonce, slots })
}

/// Assembles a beacon from exactly `LAN_SLOTS` slots (the caller sorts them by id).
pub(crate) fn build(
    nonce: &[u8; LAN_NONCE_LEN],
    slots: &[[u8; LAN_SLOT_LEN]],
) -> Option<[u8; BEACON_LEN]> {
    if slots.len() != LAN_SLOTS {
        return None;
    }
    let mut out = [0u8; BEACON_LEN];
    let (ver, rest) = out.split_first_mut()?;
    *ver = BEACON_VERSION;
    let (n, body) = rest.split_at_mut(LAN_NONCE_LEN);
    n.copy_from_slice(nonce);
    for (dst, src) in body.as_chunks_mut::<LAN_SLOT_LEN>().0.iter_mut().zip(slots) {
        dst.copy_from_slice(src);
    }
    Some(out)
}
