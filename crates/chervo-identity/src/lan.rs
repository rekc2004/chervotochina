//! Ключи и слоты маяка поиска друзей в локальной сети (этап 13в, часть L1).
//!
//! Тот же состав примитивов, что у «стука» (`knock.rs`): секрет пары `ss` = X25519, ключ
//! направления `K(S→R) = BLAKE2s-MAC-256(key = ss, LAN_KDF_LABEL || pub_S || pub_R)`, из него два
//! отдельных ключа: `K_id` (метки окон) и `K_aead` (ChaCha20-Poly1305 из `ring`).
//! Окно `w` = номер 30-секундного окна (u64, big-endian), `id(w) = first8(MAC(K_id, LAN_ID_LABEL || w))`.
//! Слот (26 байт) = `id(8) || шифртекст порта(2) || тег(16)`, AAD = `LAN_HDR || w || src_ipv4 || id`.
//! Своей криптографии нет: только вызовы `blake2` (`Mac`) и `ring::aead`.
//! Спецификация: `docs/specs/stage-13v-lan.md`, решение 4.

use std::fmt;
use std::net::Ipv4Addr;

use blake2::Blake2sMac256;
use blake2::digest::Mac;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use x25519_dalek::PublicKey as XPublic;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{IdentityError, KxPeer};

/// Длина окна времени маяка, секунд.
pub const LAN_WINDOW_SECS: u64 = 30;
/// Длина метки слота.
pub const LAN_ID_LEN: usize = 8;
/// Длина слота: `id(8) || шифртекст(2) || тег(16)`.
pub const LAN_SLOT_LEN: usize = 26;
/// Длина nonce датаграммы.
pub const LAN_NONCE_LEN: usize = 12;
/// Заголовок датаграммы: версия 1, резерв 0. Входит в AAD каждого слота.
pub const LAN_HDR: [u8; 2] = [0x01, 0x00];
/// Метка вывода ключа направления.
pub const LAN_KDF_LABEL: &[u8] = b"chervotochina/v1/lan-key\0";
/// Метка вывода ключа меток.
pub const LAN_IDKEY_LABEL: &[u8] = b"chervotochina/v1/lan-id-key\0";
/// Метка вывода ключа AEAD.
pub const LAN_AEADKEY_LABEL: &[u8] = b"chervotochina/v1/lan-aead-key\0";
/// Метка вычисления метки окна.
pub const LAN_ID_LABEL: &[u8] = b"chervotochina/v1/lan-id\0";

/// Метка вычисления метки пустого слота (ключ `R` случайный, живёт в памяти службы).
pub const LAN_PAD_LABEL: &[u8] = b"chervotochina/v1/lan-pad\0";

const PORT_LEN: usize = 2;
const TAG_LEN: usize = 16;
/// `LAN_HDR(2) || window(8) || src(4) || id(8)`.
const AAD_LEN: usize = 2 + 8 + 4 + LAN_ID_LEN;

/// Ключи маяка пары: `send_*` для своих слотов, `recv_*` для слотов друга.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::LanKeys>();
/// ```
///
/// Нет `PartialEq`:
///
/// ```compile_fail
/// fn needs<T: PartialEq>() {}
/// needs::<chervo_identity::LanKeys>();
/// ```
///
/// Нет `Hash`:
///
/// ```compile_fail
/// fn needs<T: std::hash::Hash>() {}
/// needs::<chervo_identity::LanKeys>();
/// ```
///
/// Нет `Deref`:
///
/// ```compile_fail
/// fn needs<T: std::ops::Deref>() {}
/// needs::<chervo_identity::LanKeys>();
/// ```
pub struct LanKeys {
    send_id: Zeroizing<[u8; 32]>,
    send_aead: Zeroizing<[u8; 32]>,
    recv_id: Zeroizing<[u8; 32]>,
    recv_aead: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for LanKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanKeys(..)")
    }
}

// Все поля `Zeroizing` обнуляются при уничтожении.
impl ZeroizeOnDrop for LanKeys {}

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

fn id_of(key: &[u8; 32], window: u64) -> Option<[u8; LAN_ID_LEN]> {
    let w = window.to_be_bytes();
    let full = mac_full(key, &[LAN_ID_LABEL, &w])?;
    let mut o = [0u8; LAN_ID_LEN];
    for (d, s) in o.iter_mut().zip(full.iter()) {
        *d = *s;
    }
    Some(o)
}

/// Метка пустого слота `index` в окне `window`:
/// `first8(BLAKE2s-MAC(R, LAN_PAD_LABEL || w || index))`. Постоянна внутри окна, как метки
/// настоящих слотов (`LanKeys::send_id`), поэтому по числу постоянных меток в серии датаграмм
/// число друзей не определить. Меняется со сменой окна и ключа `R`; ключ `R` создаёт служба
/// заново при запуске и при смене набора интерфейсов и никуда не пишет.
pub fn lan_pad_id(
    key: &[u8; 32],
    window: u64,
    index: u8,
) -> Result<[u8; LAN_ID_LEN], IdentityError> {
    let w = window.to_be_bytes();
    let full = mac_full(key, &[LAN_PAD_LABEL, &w, &[index]]).ok_or(IdentityError::AuthFailed)?;
    let mut o = [0u8; LAN_ID_LEN];
    for (d, s) in o.iter_mut().zip(full.iter()) {
        *d = *s;
    }
    Ok(o)
}

fn aead_key(key: &[u8; 32]) -> Option<LessSafeKey> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key.as_slice()).ok()?;
    Some(LessSafeKey::new(unbound))
}

fn aad_of(window: u64, src: Ipv4Addr, id: &[u8; LAN_ID_LEN]) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    let w = window.to_be_bytes();
    let s = src.octets();
    let parts: [&[u8]; 4] = [&LAN_HDR, &w, &s, id];
    let mut off = 0usize;
    for p in parts {
        for (d, b) in a.iter_mut().skip(off).zip(p.iter()) {
            *d = *b;
        }
        off = off.saturating_add(p.len());
    }
    a
}

type Key32 = Zeroizing<[u8; 32]>;
/// Пара (`K_id`, `K_aead`).
type KeyPair = (Key32, Key32);

/// Ключ направления и два ключа из него (`K_id`, `K_aead`).
fn derive_pair(
    ss: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
) -> Result<KeyPair, IdentityError> {
    let k = mac_full(ss, &[LAN_KDF_LABEL, sender, receiver]).ok_or(IdentityError::AuthFailed)?;
    let k_id = mac_full(&k, &[LAN_IDKEY_LABEL]).ok_or(IdentityError::AuthFailed)?;
    let k_aead = mac_full(&k, &[LAN_AEADKEY_LABEL]).ok_or(IdentityError::AuthFailed)?;
    Ok((k_id, k_aead))
}

impl KxPeer {
    /// Ключи маяка пары. Ключ друга, равный нашему, или нулевой общий секрет
    /// (непригодный ключ) дают `AuthFailed`, как у `knock_keys`.
    pub fn lan_keys(&self) -> Result<LanKeys, IdentityError> {
        let ours_pub = self.ours.public().to_bytes();
        let theirs_pub = self.theirs.to_bytes();
        if ours_pub == theirs_pub {
            return Err(IdentityError::AuthFailed);
        }
        let ss = self.ours.secret.diffie_hellman(&XPublic::from(theirs_pub));
        if !ss.was_contributory() {
            return Err(IdentityError::AuthFailed);
        }
        let (send_id, send_aead) = derive_pair(ss.as_bytes(), &ours_pub, &theirs_pub)?;
        let (recv_id, recv_aead) = derive_pair(ss.as_bytes(), &theirs_pub, &ours_pub)?;
        Ok(LanKeys {
            send_id,
            send_aead,
            recv_id,
            recv_aead,
        })
    }
}

impl LanKeys {
    /// Только для тестов: ключ AEAD своих слотов (слот с портом 0 `seal` не выпускает).
    #[cfg(test)]
    pub(crate) fn test_send_aead(&self) -> &[u8; 32] {
        &self.send_aead
    }

    /// Метка наших слотов в окне `window`.
    pub fn send_id(&self, window: u64) -> [u8; LAN_ID_LEN] {
        id_of(&self.send_id, window).unwrap_or([0u8; LAN_ID_LEN])
    }

    /// Метка, которую имеют слоты друга в окне `window` (для таблицы поиска).
    pub fn recv_id(&self, window: u64) -> [u8; LAN_ID_LEN] {
        id_of(&self.recv_id, window).unwrap_or([0u8; LAN_ID_LEN])
    }

    /// Слот на окно `window`: `id || ChaCha20-Poly1305(порт)`. Порт 0 даёт `AuthFailed`.
    /// `aad = LAN_HDR || window_be || src.octets() || id`. Nonce один на датаграмму, случайный,
    /// выбирает вызывающий; один и тот же nonce под одним ключом дважды не используется,
    /// потому что на ключ (пару) приходится один слот в датаграмме.
    pub fn seal(
        &self,
        window: u64,
        nonce: &[u8; LAN_NONCE_LEN],
        src: Ipv4Addr,
        port: u16,
    ) -> Result<[u8; LAN_SLOT_LEN], IdentityError> {
        if port == 0 {
            return Err(IdentityError::AuthFailed);
        }
        let id = id_of(&self.send_id, window).ok_or(IdentityError::AuthFailed)?;
        let aad = aad_of(window, src, &id);
        let mut ct = port.to_be_bytes();
        let key = aead_key(&self.send_aead).ok_or(IdentityError::AuthFailed)?;
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad.as_slice()),
                &mut ct,
            )
            .map_err(|_| IdentityError::AuthFailed)?;
        let mut out = [0u8; LAN_SLOT_LEN];
        let (a, rest) = out.split_at_mut(LAN_ID_LEN);
        let (b, c) = rest.split_at_mut(PORT_LEN);
        a.copy_from_slice(&id);
        b.copy_from_slice(&ct);
        let tag_bytes = tag.as_ref();
        if tag_bytes.len() != TAG_LEN || c.len() != TAG_LEN {
            return Err(IdentityError::AuthFailed);
        }
        c.copy_from_slice(tag_bytes);
        Ok(out)
    }

    /// Разбор слота друга: длина, метка (== `recv_id(window)`, сравнение за постоянное время),
    /// AEAD с AAD из адреса источника датаграммы. `None` при любой ошибке и при порте 0.
    pub fn open(
        &self,
        window: u64,
        nonce: &[u8; LAN_NONCE_LEN],
        src: Ipv4Addr,
        slot: &[u8],
    ) -> Option<u16> {
        if slot.len() != LAN_SLOT_LEN {
            return None;
        }
        let id: [u8; LAN_ID_LEN] = slot.get(..LAN_ID_LEN)?.try_into().ok()?;
        let body = slot.get(LAN_ID_LEN..)?;
        let w = window.to_be_bytes();
        let mut m = mac_new(&self.recv_id)?;
        m.update(LAN_ID_LABEL);
        m.update(&w);
        let ok_id = m.verify_truncated_left(&id).is_ok();
        let aad = aad_of(window, src, &id);
        let mut buf = [0u8; PORT_LEN + TAG_LEN];
        if body.len() != buf.len() {
            return None;
        }
        buf.copy_from_slice(body);
        let key = aead_key(&self.recv_aead)?;
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad.as_slice()),
                &mut buf,
            )
            .ok()?;
        if !ok_id {
            return None;
        }
        let arr: [u8; PORT_LEN] = (&*plain).try_into().ok()?;
        match u16::from_be_bytes(arr) {
            0 => None,
            p => Some(p),
        }
    }
}
