//! «Стук»: 48 байт, которые звонящий шлёт до QUIC; вызываемый до верного стука молчит.
//!
//! Ключ направления `K(S→R) = BLAKE2s-MAC-256(key = ss, KNOCK_KDF_LABEL || pub_S || pub_R)`,
//! где `ss` — секрет пары X25519 (наружу не отдаётся). Формат `id(16) || nonce(16) || tag(16)`,
//! `id = first16(MAC(K, ID_LABEL || w))`, `tag = first16(MAC(K, TAG_LABEL || w || id || nonce))`,
//! `w` — номер окна времени (u64, big-endian). Только вызовы blake2 (`Mac`).
//! Спецификация: `docs/specs/stage-09b-knock.md`.

use std::fmt;

use blake2::Blake2sMac256;
use blake2::digest::Mac;
use x25519_dalek::PublicKey as XPublic;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{IdentityError, KxPeer};

/// Длина стука.
pub const KNOCK_LEN: usize = 48;
/// Метка вывода ключа направления.
pub const KNOCK_KDF_LABEL: &[u8] = b"chervotochina/v1/knock-key\0";
/// Метка идентификатора окна.
pub const KNOCK_ID_LABEL: &[u8] = b"chervotochina/v1/knock-id\0";
/// Метка тега стука.
pub const KNOCK_TAG_LABEL: &[u8] = b"chervotochina/v1/knock-tag\0";

const ID_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;

/// Ключи стука пары: `send` для своих стуков, `recv` для проверки чужих.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::KnockKeys>();
/// ```
///
/// Нет `PartialEq`:
///
/// ```compile_fail
/// fn needs<T: PartialEq>() {}
/// needs::<chervo_identity::KnockKeys>();
/// ```
///
/// Нет `Hash`:
///
/// ```compile_fail
/// fn needs<T: std::hash::Hash>() {}
/// needs::<chervo_identity::KnockKeys>();
/// ```
///
/// Нет `Deref`:
///
/// ```compile_fail
/// fn needs<T: std::ops::Deref>() {}
/// needs::<chervo_identity::KnockKeys>();
/// ```
pub struct KnockKeys {
    send: Zeroizing<[u8; 32]>,
    recv: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for KnockKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KnockKeys(..)")
    }
}

// Оба поля `Zeroizing` обнуляются при уничтожении.
impl ZeroizeOnDrop for KnockKeys {}

fn mac_new(key: &[u8; 32]) -> Option<Blake2sMac256> {
    <Blake2sMac256 as Mac>::new_from_slice(key).ok()
}

/// Полный MAC (32 байта) над склейкой частей; `None` только при невозможной ошибке длины ключа.
fn mac_full(key: &[u8; 32], parts: &[&[u8]]) -> Option<Zeroizing<[u8; 32]>> {
    let mut m = mac_new(key)?;
    for p in parts {
        m.update(p);
    }
    let out = m.finalize().into_bytes();
    let mut arr = Zeroizing::new([0u8; 32]);
    if out.len() != arr.len() {
        return None;
    }
    arr.copy_from_slice(&out);
    Some(arr)
}

fn first16(full: &[u8; 32]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (d, s) in o.iter_mut().zip(full.iter()) {
        *d = *s;
    }
    o
}

/// `id` окна под ключом.
fn id_for(key: &[u8; 32], window: u64) -> Option<[u8; ID_LEN]> {
    let w = window.to_be_bytes();
    mac_full(key, &[KNOCK_ID_LABEL, &w]).map(|f| first16(&f))
}

fn tag_for(key: &[u8; 32], window: u64, id: &[u8], nonce: &[u8]) -> Option<[u8; TAG_LEN]> {
    let w = window.to_be_bytes();
    mac_full(key, &[KNOCK_TAG_LABEL, &w, id, nonce]).map(|f| first16(&f))
}

fn derive(
    ss: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    mac_full(ss, &[KNOCK_KDF_LABEL, sender, receiver]).ok_or(IdentityError::AuthFailed)
}

impl KxPeer {
    /// Ключи стука пары. Ключ друга, равный нашему, или нулевой общий секрет
    /// (непригодный ключ) дают `AuthFailed`.
    pub fn knock_keys(&self) -> Result<KnockKeys, IdentityError> {
        let ours_pub = self.ours.public().to_bytes();
        let theirs_pub = self.theirs.to_bytes();
        if ours_pub == theirs_pub {
            return Err(IdentityError::AuthFailed);
        }
        let ss = self.ours.secret.diffie_hellman(&XPublic::from(theirs_pub));
        if !ss.was_contributory() {
            return Err(IdentityError::AuthFailed);
        }
        let send = derive(ss.as_bytes(), &ours_pub, &theirs_pub)?;
        let recv = derive(ss.as_bytes(), &theirs_pub, &ours_pub)?;
        Ok(KnockKeys { send, recv })
    }
}

impl KnockKeys {
    /// Стук на окно `window` ключом `send`; свежий nonce из ГСЧ ОС.
    pub fn make(&self, window: u64) -> Result<[u8; KNOCK_LEN], IdentityError> {
        let id = id_for(&self.send, window).ok_or(IdentityError::AuthFailed)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| IdentityError::RandomUnavailable)?;
        let tag = tag_for(&self.send, window, &id, &nonce).ok_or(IdentityError::AuthFailed)?;
        let mut out = [0u8; KNOCK_LEN];
        let (a, rest) = out.split_at_mut(ID_LEN);
        let (b, c) = rest.split_at_mut(NONCE_LEN);
        a.copy_from_slice(&id);
        b.copy_from_slice(&nonce);
        c.copy_from_slice(&tag);
        Ok(out)
    }

    /// `id`, который имеет стук друга в окне `window` (ключ `recv`). Нужен вызываемому
    /// для таблицы поиска.
    pub fn recv_id(&self, window: u64) -> [u8; 16] {
        id_for(&self.recv, window).unwrap_or([0u8; ID_LEN])
    }

    /// Проверка стука друга в окне `window`: длина, `id`, `tag` (сравнение за постоянное время).
    pub fn verify(&self, window: u64, knock: &[u8]) -> bool {
        if knock.len() != KNOCK_LEN {
            return false;
        }
        let (Some(id), Some(rest)) = (knock.get(..ID_LEN), knock.get(ID_LEN..)) else {
            return false;
        };
        let (Some(nonce), Some(tag)) = (rest.get(..NONCE_LEN), rest.get(NONCE_LEN..)) else {
            return false;
        };
        let w = window.to_be_bytes();
        let Some(mut m_id) = mac_new(&self.recv) else {
            return false;
        };
        m_id.update(KNOCK_ID_LABEL);
        m_id.update(&w);
        let ok_id = m_id.verify_truncated_left(id).is_ok();
        let Some(mut m_tag) = mac_new(&self.recv) else {
            return false;
        };
        m_tag.update(KNOCK_TAG_LABEL);
        m_tag.update(&w);
        m_tag.update(id);
        m_tag.update(nonce);
        let ok_tag = m_tag.verify_truncated_left(tag).is_ok();
        ok_id & ok_tag
    }
}
