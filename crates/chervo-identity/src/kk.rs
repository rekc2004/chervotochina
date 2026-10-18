//! Аутентификация соединения Noise KK (snow), привязанная к каналу TLS.
//!
//! Prologue: `KK_PROLOGUE_TAG || [KK_KIND_V1] || binding`. Сообщения фиксированной длины:
//! 49 (вид + e + тег), 48 (e + тег), 16 (подтверждение звонящего). Только вызовы snow.
//! Спецификация: `docs/specs/stage-10b-kx.md`.

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::kx::{KxPublicKey, PairKx};
use crate::{IdentityError, PairId};

/// Набор Noise.
pub const NOISE_PARAMS: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
/// Метка домена prologue; оканчивается единственным нулевым байтом.
pub const KK_PROLOGUE_TAG: &[u8] = b"chervotochina/v1/conn-kk\0";
/// Байт вида первого сообщения (`0x02` зарезервирован за этапом 11).
pub const KK_KIND_V1: u8 = 0x01;
/// Первое сообщение: `[KK_KIND_V1][e 32][тег 16]`, полезная нагрузка пустая.
pub const KK_MSG1_LEN: usize = 49;
/// Ответ: `[e 32][тег 16]`.
pub const KK_MSG2_LEN: usize = 48;
/// Подтверждение звонящего: транспортное сообщение с пустой нагрузкой.
pub const KK_MSG3_LEN: usize = 16;
/// Длина значения экспортёра TLS.
pub const BINDING_LEN: usize = 32;

const PROLOGUE_LEN: usize = KK_PROLOGUE_TAG.len() + 1 + BINDING_LEN;

/// Значение экспортёра TLS, связывающее рукопожатие с каналом.
#[derive(Clone, Copy)]
pub struct ChannelBinding([u8; BINDING_LEN]);

impl ChannelBinding {
    pub const fn from_bytes(b: [u8; BINDING_LEN]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelBinding(..)")
    }
}

/// Пара глазами Noise KK: наш ключ обмена и ключ обмена друга.
///
/// `Clone` делит секрет (`Arc<PairKx>`), а не копирует его: в памяти один экземпляр, он
/// обнуляется при уничтожении последней ссылки. Нужен движку, чтобы убрать из набора транспорта
/// пары, переставшие быть допущенными, не загружая ключи заново (этап 17, S2, L4).
#[derive(Clone)]
pub struct KxPeer {
    pair: PairId,
    pub(crate) ours: Arc<PairKx>,
    pub(crate) theirs: KxPublicKey,
}

impl KxPeer {
    /// Ключ друга, равный нашему собственному, не отвергается здесь (интерфейс
    /// остаётся прежним), а делает пару непригодной: `kk_initiate` возвращает
    /// `AuthFailed`, а `kk_respond` пропускает такого кандидата (защита от отражения).
    pub fn new(pair: PairId, ours: PairKx, theirs: KxPublicKey) -> Self {
        Self {
            pair,
            ours: Arc::new(ours),
            theirs,
        }
    }

    pub fn pair(&self) -> PairId {
        self.pair
    }

    pub fn ours_public(&self) -> KxPublicKey {
        self.ours.public()
    }

    pub fn theirs(&self) -> KxPublicKey {
        self.theirs
    }
}

impl fmt::Debug for KxPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KxPeer(..)")
    }
}

/// Состояние звонящего между сообщениями 1 и 2.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::KkInitiator>();
/// ```
pub struct KkInitiator {
    hs: snow::HandshakeState,
}

impl fmt::Debug for KkInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KkInitiator(..)")
    }
}

/// Состояние вызываемого между сообщениями 2 и 3.
///
/// Нет `Clone`:
///
/// ```compile_fail
/// fn needs<T: Clone>() {}
/// needs::<chervo_identity::KkResponder>();
/// ```
pub struct KkResponder {
    hs: snow::HandshakeState,
    pair: PairId,
}

impl fmt::Debug for KkResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KkResponder(..)")
    }
}

/// Ошибки snow наружу не отдаются: только `AuthFailed` (или `RandomUnavailable`).
fn map_snow(e: snow::Error) -> IdentityError {
    match e {
        snow::Error::Rng => IdentityError::RandomUnavailable,
        _ => IdentityError::AuthFailed,
    }
}

fn prologue(binding: &ChannelBinding) -> Zeroizing<Vec<u8>> {
    let mut p = Vec::with_capacity(PROLOGUE_LEN);
    p.extend_from_slice(KK_PROLOGUE_TAG);
    p.push(KK_KIND_V1);
    p.extend_from_slice(&binding.0);
    Zeroizing::new(p)
}

/// Сборка snow: ровно 32 байта секрета и ровно 32 байта удалённого ключа (типы `[u8; 32]`).
fn build(
    peer: &KxPeer,
    prologue: &[u8],
    initiator: bool,
) -> Result<snow::HandshakeState, IdentityError> {
    // Ключ друга == наш ключ: отражение собственного сообщения прошло бы как «друг».
    if peer.theirs == peer.ours.public() {
        return Err(IdentityError::AuthFailed);
    }
    let params = NOISE_PARAMS.parse().map_err(map_snow)?;
    let theirs: [u8; 32] = peer.theirs.to_bytes();
    let builder = snow::Builder::new(params)
        .local_private_key(peer.ours.secret.as_bytes())
        .map_err(map_snow)?
        .remote_public_key(&theirs)
        .map_err(map_snow)?
        .prologue(prologue)
        .map_err(map_snow)?;
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(map_snow)
}

/// Звонящий: сообщение 1.
pub fn kk_initiate(
    peer: &KxPeer,
    binding: &ChannelBinding,
) -> Result<(KkInitiator, [u8; KK_MSG1_LEN]), IdentityError> {
    let prologue = prologue(binding);
    let mut hs = build(peer, &prologue, true)?;
    let mut buf = [0u8; KK_MSG1_LEN];
    let body = buf.get_mut(1..).ok_or(IdentityError::AuthFailed)?;
    let n = hs.write_message(&[], body).map_err(map_snow)?;
    if n != KK_MSG1_LEN - 1 {
        return Err(IdentityError::AuthFailed);
    }
    *buf.first_mut().ok_or(IdentityError::AuthFailed)? = KK_KIND_V1;
    Ok((KkInitiator { hs }, buf))
}

impl KkInitiator {
    /// Проверяет msg2 (подлинность вызываемого) и возвращает msg3.
    pub fn finish(self, msg2: &[u8]) -> Result<[u8; KK_MSG3_LEN], IdentityError> {
        if msg2.len() != KK_MSG2_LEN {
            return Err(IdentityError::AuthFailed);
        }
        let mut hs = self.hs;
        hs.read_message(msg2, &mut [])
            .map_err(|_| IdentityError::AuthFailed)?;
        let mut transport = hs
            .into_transport_mode()
            .map_err(|_| IdentityError::AuthFailed)?;
        let mut msg3 = [0u8; KK_MSG3_LEN];
        let n = transport
            .write_message(&[], &mut msg3)
            .map_err(|_| IdentityError::AuthFailed)?;
        if n != KK_MSG3_LEN {
            return Err(IdentityError::AuthFailed);
        }
        Ok(msg3)
    }
}

/// Попытка одного кандидата: без раннего выхода наружу; любая ошибка = «не совпало».
/// `reached` вызывается непосредственно перед `read_message` (для теста «дошли до дешифровки»).
fn try_peer<F: FnMut()>(
    peer: &KxPeer,
    prologue: &[u8],
    body: &[u8],
    reached: &mut F,
) -> Option<snow::HandshakeState> {
    build(peer, prologue, false).ok().and_then(|mut hs| {
        reached();
        hs.read_message(body, &mut []).ok().map(|_| hs)
    })
}

/// Перебор всех кандидатов; `on_try` вызывается на каждую попытку, дошедшую до
/// `read_message` (для теста «посещены все»).
fn respond_with<F: FnMut()>(
    peers: &[&KxPeer],
    binding: &ChannelBinding,
    msg1: &[u8],
    mut on_try: F,
) -> Result<(KkResponder, [u8; KK_MSG2_LEN]), IdentityError> {
    if msg1.len() != KK_MSG1_LEN || msg1.first() != Some(&KK_KIND_V1) || peers.is_empty() {
        return Err(IdentityError::AuthFailed);
    }
    let body = msg1.get(1..).ok_or(IdentityError::AuthFailed)?;
    let prologue = prologue(binding);

    let mut found: Option<(snow::HandshakeState, PairId)> = None;
    for peer in peers {
        let attempt = try_peer(peer, &prologue, body, &mut on_try);
        if found.is_none()
            && let Some(hs) = attempt
        {
            found = Some((hs, peer.pair));
        }
    }

    let (mut hs, pair) = found.ok_or(IdentityError::AuthFailed)?;
    let mut out = [0u8; KK_MSG2_LEN];
    let n = hs.write_message(&[], &mut out).map_err(map_snow)?;
    if n != KK_MSG2_LEN {
        return Err(IdentityError::AuthFailed);
    }
    Ok((KkResponder { hs, pair }, out))
}

/// Перебирает ВСЕ `peers` без раннего выхода; первый совпавший побеждает.
pub fn kk_respond(
    peers: &[&KxPeer],
    binding: &ChannelBinding,
    msg1: &[u8],
) -> Result<(KkResponder, [u8; KK_MSG2_LEN]), IdentityError> {
    respond_with(peers, binding, msg1, || {})
}

impl KkResponder {
    /// Проверяет msg3. Только здесь пара считается подтверждённой.
    pub fn finish(self, msg3: &[u8]) -> Result<PairId, IdentityError> {
        if msg3.len() != KK_MSG3_LEN {
            return Err(IdentityError::AuthFailed);
        }
        let mut transport = self
            .hs
            .into_transport_mode()
            .map_err(|_| IdentityError::AuthFailed)?;
        transport
            .read_message(msg3, &mut [])
            .map_err(|_| IdentityError::AuthFailed)?;
        Ok(self.pair)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::PairKey;

    fn kx_pair(a: u8, b: u8) -> (PairKx, PairKx) {
        let ka = PairKey::from_secrets(&[a; 32], &[a.wrapping_add(100); 32]);
        let kb = PairKey::from_secrets(&[b; 32], &[b.wrapping_add(100); 32]);
        (ka.into_kx(), kb.into_kx())
    }

    /// Для пары i: (peer звонящего, peer вызываемого).
    fn peers_of(i: u8) -> (KxPeer, KxPeer) {
        let (a, b) = kx_pair(i, i.wrapping_add(50));
        let (pa, pb) = (a.public(), b.public());
        let id = PairId::from_bytes([i; 16]);
        (KxPeer::new(id, a, pb), KxPeer::new(id, b, pa))
    }

    #[test]
    fn trial_visits_all_candidates() {
        let binding = ChannelBinding::from_bytes([9; BINDING_LEN]);
        let n = 5u8;
        let callee: Vec<KxPeer> = (0..n).map(|i| peers_of(i).1).collect();
        let refs: Vec<&KxPeer> = callee.iter().collect();

        for caller_idx in 0..n {
            let (caller, _) = peers_of(caller_idx);
            let (_, msg1) = kk_initiate(&caller, &binding).unwrap();
            let mut tries = 0;
            let res = respond_with(&refs, &binding, &msg1, || tries += 1);
            assert!(res.is_ok());
            assert_eq!(tries, usize::from(n), "совпадение на позиции {caller_idx}");
        }

        let (stranger, _) = peers_of(77);
        let (_, msg1) = kk_initiate(&stranger, &binding).unwrap();
        let mut tries = 0;
        let res = respond_with(&refs, &binding, &msg1, || tries += 1);
        assert_eq!(res.err(), Some(IdentityError::AuthFailed));
        assert_eq!(tries, usize::from(n));
    }
}
