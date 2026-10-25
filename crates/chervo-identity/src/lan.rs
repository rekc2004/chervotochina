//! Поиск в LAN (этап 13в): ключи и метки ячеек маяка.
//!
//! Ключи направления берутся из секрета пары `ss` (X25519, наружу не отдаётся), как у стука:
//! `K_id(S→R) = BLAKE2s-MAC-256(ss, LAN_ID_KEY_LABEL || pub_S || pub_R)`,
//! `K_seal(S→R) = BLAKE2s-MAC-256(ss, LAN_SEAL_KEY_LABEL || pub_S || pub_R)`.
//! Метка эпохи `id(S→R, e) = first16(MAC(K_id, LAN_ID_LABEL || be64(e)))`. Порт запечатан
//! ChaCha20-Poly1305 под `K_seal` (nonce маяка, AAD с эпохой, адресом источника и меткой).
//! Только вызовы `blake2` (`Mac`) и `chacha20poly1305` (`AeadInPlace`, `KeyInit`).
//! Спецификация: `docs/specs/stage-13v-lan.md`.

use std::fmt;
use std::net::IpAddr;

use blake2::Blake2sMac256;
use blake2::digest::Mac;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use x25519_dalek::PublicKey as XPublic;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{IdentityError, KxPeer};

/// Метка вывода ключа меток.
pub const LAN_ID_KEY_LABEL: &[u8] = b"chervotochina/v1/lan-id-key\0";
/// Метка вывода ключа запечатывания порта.
pub const LAN_SEAL_KEY_LABEL: &[u8] = b"chervotochina/v1/lan-seal-key\0";
/// Метка метки ячейки в эпохе.
pub const LAN_ID_LABEL: &[u8] = b"chervotochina/v1/lan-id\0";
/// Метка AAD запечатанного порта.
pub const LAN_AAD_LABEL: &[u8] = b"chervotochina/v1/lan-aad\0";
/// Версия формата маяка (входит в AAD).
pub const LAN_FORMAT_VERSION: u8 = 1;
/// Длина метки ячейки.
pub const LAN_ID_LEN: usize = 16;
/// Длина nonce маяка.
pub const LAN_NONCE_LEN: usize = 12;
/// Длина ячейки: метка 16, зашифрованный порт 2, тег 16.
pub const LAN_SLOT_LEN: usize = 34;

const PORT_LEN: usize = 2;
const TAG_LEN: usize = 16;

/// Ключи поиска в LAN одной пары: `*_send` для своих ячеек, `*_recv` для ячеек друга.
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
    id_send: Zeroizing<[u8; 32]>,
    id_recv: Zeroizing<[u8; 32]>,
    seal_send: Zeroizing<[u8; 32]>,
    seal_recv: Zeroizing<[u8; 32]>,
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

/// Полный MAC (32 байта) над склейкой частей.
fn mac_full(key: &[u8; 32], parts: &[&[u8]]) -> Option<Zeroizing<[u8; 32]>> {
    let mut m = mac_new(key)?;
    for p in parts {
        m.update(p);
    }
    let mut out = m.finalize().into_bytes();
    let mut arr = Zeroizing::new([0u8; 32]);
    let ok = out.len() == arr.len();
    if ok {
        arr.copy_from_slice(&out);
    }
    // the finalized block is a key (or key-derived) copy: wipe it (the hash state stays as is)
    out.as_mut_slice().zeroize();
    ok.then_some(arr)
}

fn first16(full: &[u8; 32]) -> [u8; LAN_ID_LEN] {
    let mut o = [0u8; LAN_ID_LEN];
    for (d, s) in o.iter_mut().zip(full.iter()) {
        *d = *s;
    }
    o
}

fn derive(
    ss: &[u8; 32],
    label: &[u8],
    sender: &[u8; 32],
    receiver: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    mac_full(ss, &[label, sender, receiver]).ok_or(IdentityError::AuthFailed)
}

fn id_for(key: &[u8; 32], epoch: u64) -> Option<[u8; LAN_ID_LEN]> {
    mac_full(key, &[LAN_ID_LABEL, &epoch.to_be_bytes()]).map(|f| first16(&f))
}

/// Адрес источника в AAD: v4-mapped приводится к v4.
fn aad_for(epoch: u64, src: IpAddr, id: &[u8]) -> Vec<u8> {
    let src = match src {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let mut aad = Vec::with_capacity(LAN_AAD_LABEL.len() + 1 + 8 + 1 + 16 + id.len());
    aad.extend_from_slice(LAN_AAD_LABEL);
    aad.push(LAN_FORMAT_VERSION);
    aad.extend_from_slice(&epoch.to_be_bytes());
    match src {
        IpAddr::V4(a) => {
            aad.push(4);
            aad.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            aad.push(6);
            aad.extend_from_slice(&a.octets());
        }
    }
    aad.extend_from_slice(id);
    aad
}

impl KxPeer {
    /// Ключи поиска в LAN. Ключ друга, равный нашему, или нулевой общий секрет
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
        let ss = ss.as_bytes();
        Ok(LanKeys {
            id_send: derive(ss, LAN_ID_KEY_LABEL, &ours_pub, &theirs_pub)?,
            id_recv: derive(ss, LAN_ID_KEY_LABEL, &theirs_pub, &ours_pub)?,
            seal_send: derive(ss, LAN_SEAL_KEY_LABEL, &ours_pub, &theirs_pub)?,
            seal_recv: derive(ss, LAN_SEAL_KEY_LABEL, &theirs_pub, &ours_pub)?,
        })
    }
}

impl LanKeys {
    /// Метка ячейки друга для нас в эпохе `epoch`.
    pub fn recv_id(&self, epoch: u64) -> [u8; LAN_ID_LEN] {
        id_for(&self.id_recv, epoch).unwrap_or([0u8; LAN_ID_LEN])
    }

    /// Наша ячейка для этого друга. `src` — IP, с которого уйдёт маяк. Порт 0 и любая
    /// ошибка AEAD дают `AuthFailed`.
    pub fn seal_slot(
        &self,
        epoch: u64,
        nonce: &[u8; LAN_NONCE_LEN],
        src: IpAddr,
        port: u16,
    ) -> Result<[u8; LAN_SLOT_LEN], IdentityError> {
        if port == 0 {
            return Err(IdentityError::AuthFailed);
        }
        let id = id_for(&self.id_send, epoch).ok_or(IdentityError::AuthFailed)?;
        let aad = aad_for(epoch, src, &id);
        let mut ct = port.to_be_bytes();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.seal_send));
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), &aad, &mut ct)
            .map_err(|_| IdentityError::AuthFailed)?;
        let mut out = [0u8; LAN_SLOT_LEN];
        let (a, rest) = out.split_at_mut(LAN_ID_LEN);
        let (b, c) = rest.split_at_mut(PORT_LEN);
        a.copy_from_slice(&id);
        b.copy_from_slice(&ct);
        c.copy_from_slice(&tag);
        Ok(out)
    }

    /// Ячейка друга: длина 34, метка равна `recv_id(epoch)` (сравнение за постоянное
    /// время), AEAD открывается с AAD (эпоха, адрес источника, метка), порт не 0.
    /// Всё остальное даёт `None`.
    pub fn open_slot(
        &self,
        epoch: u64,
        nonce: &[u8; LAN_NONCE_LEN],
        src: IpAddr,
        slot: &[u8],
    ) -> Option<u16> {
        if slot.len() != LAN_SLOT_LEN {
            return None;
        }
        let id = slot.get(..LAN_ID_LEN)?;
        let rest = slot.get(LAN_ID_LEN..)?;
        let ct = rest.get(..PORT_LEN)?;
        let tag = rest.get(PORT_LEN..)?;
        if tag.len() != TAG_LEN {
            return None;
        }
        let mut m = mac_new(&self.id_recv)?;
        m.update(LAN_ID_LABEL);
        m.update(&epoch.to_be_bytes());
        m.verify_truncated_left(id).ok()?;
        let aad = aad_for(epoch, src, id);
        let mut buf = [0u8; PORT_LEN];
        buf.copy_from_slice(ct);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.seal_recv));
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                &aad,
                &mut buf,
                Tag::from_slice(tag),
            )
            .ok()?;
        match u16::from_be_bytes(buf) {
            0 => None,
            p => Some(p),
        }
    }
}
