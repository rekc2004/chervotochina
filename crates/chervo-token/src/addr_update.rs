//! Токен обновления адреса: `CHA1…`, отдельный на каждого друга, подписан ключом пары
//! (домен `AddressUpdate`) и привязан к обоим ключам пары.
//!
//! Двоичный формат (числа big-endian), подпись Ed25519 над
//! `ключ_подписанта(32) || ключ_получателя(32) || байты[0..L-64]`:
//! `[0] версия 0x01 [1] вид 0x03 [2..10] seq u64 (>= 1) [10] n (1..=8)`, затем n раз
//! `[0x04|0x06][IP 4|16][порт u16 != 0][флаги u8]`, затем подпись (64 байта).
//! `L = 75 + сумма записей` (83..=235). Ключи в токене не передаются.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use chervo_addr::{PublishSet, UpdateAddr, update_allowed};
use chervo_identity::{PairId, PairKey, PublicKey, SignDomain};

use crate::{
    ADDR_UPDATE_MAX_LEN, ADDR_UPDATE_MIN_LEN, ADDR_UPDATE_PREFIX, FLAG_HINT, FLAG_SHORT_LIVED,
    KIND_ADDR_UPDATE, TOKEN_VERSION, TokenError, base32,
};

const SIG_LEN: usize = 64;
const HEADER_LEN: usize = 11;
const MAX_ENTRIES: usize = 8;
const FLAGS_KNOWN: u8 = FLAG_SHORT_LIVED | FLAG_HINT;

/// Структурно верный токен, подпись ещё НЕ проверена. Содержимое до `verify` не читается.
#[derive(Clone)]
pub struct SignedAddrUpdate {
    bytes: Vec<u8>,
    seq: u64,
    addrs: Vec<UpdateAddr>,
}

impl fmt::Debug for SignedAddrUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedAddrUpdate(..)")
    }
}

/// Проверенное обновление: подпись сошлась для пары ключей.
pub struct AddrUpdate {
    seq: u64,
    addrs: Vec<UpdateAddr>,
}

impl AddrUpdate {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn addrs(&self) -> &[UpdateAddr] {
        &self.addrs
    }
}

impl fmt::Debug for AddrUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddrUpdate(..)")
    }
}

/// Выпущенный токен: двоичная запись, номер и (если задана) пара, для которой он выпущен.
/// Пара не входит в формат токена и не передаётся по сети: это локальная привязка, по
/// которой помощники ADDR_INFO отказывают на соединении другой пары (`WrongPeer`).
#[derive(Clone)]
pub struct IssuedAddrUpdate {
    bytes: Vec<u8>,
    seq: u64,
    pair: Option<PairId>,
}

impl IssuedAddrUpdate {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Пара (в нашем списке друзей), для которой выпущен токен; `None`, если не привязан.
    pub fn pair(&self) -> Option<PairId> {
        self.pair
    }

    /// Привязать токен к паре.
    #[must_use]
    pub fn for_pair(mut self, pair: PairId) -> Self {
        self.pair = Some(pair);
        self
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `CHA1` и base32 от двоичной записи.
    pub fn text(&self) -> String {
        format!("{ADDR_UPDATE_PREFIX}{}", base32::encode(&self.bytes))
    }
}

impl fmt::Debug for IssuedAddrUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedAddrUpdate(..)")
    }
}

impl SignedAddrUpdate {
    /// Номер из разобранного, но НЕ проверенного токена. Годится только для дешёвых отказов
    /// до проверки подписи (устаревший номер, лимит); принимать по нему ничего нельзя.
    pub fn unverified_seq(&self) -> u64 {
        self.seq
    }

    /// `signer` = `friend_ed`, `recipient` = наш `our_ed` этой пары. Любая ошибка даёт
    /// `BadSignature`.
    pub fn verify(
        &self,
        signer: &PublicKey,
        recipient: &PublicKey,
    ) -> Result<AddrUpdate, TokenError> {
        let split = self
            .bytes
            .len()
            .checked_sub(SIG_LEN)
            .ok_or(TokenError::BadSignature)?;
        let (body, sig) = self
            .bytes
            .split_at_checked(split)
            .ok_or(TokenError::BadSignature)?;
        let msg = signed_message(signer, recipient, body);
        signer
            .verify(SignDomain::AddressUpdate, &msg, sig)
            .map_err(|_| TokenError::BadSignature)?;
        Ok(AddrUpdate {
            seq: self.seq,
            addrs: self.addrs.clone(),
        })
    }
}

/// `ключ_подписанта || ключ_получателя || тело`.
fn signed_message(signer: &PublicKey, recipient: &PublicKey, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(body.len().saturating_add(64));
    msg.extend_from_slice(&signer.to_bytes());
    msg.extend_from_slice(&recipient.to_bytes());
    msg.extend_from_slice(body);
    msg
}

/// Читает `N` байт со смещения `*pos` и сдвигает его.
fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], TokenError> {
    let end = pos.checked_add(n).ok_or(TokenError::Malformed)?;
    let s = b.get(*pos..end).ok_or(TokenError::Malformed)?;
    *pos = end;
    Ok(s)
}

/// Разбор двоичной записи. Порядок ошибок: длина, версия, вид, seq, n, затем по
/// записям (семейство, флаги, порт и класс адреса, повтор), затем остаток. Подпись
/// проверяется только в `verify`.
pub(crate) fn parse(b: &[u8]) -> Result<SignedAddrUpdate, TokenError> {
    let total = b.len();
    if !(ADDR_UPDATE_MIN_LEN..=ADDR_UPDATE_MAX_LEN).contains(&total) {
        return Err(TokenError::Malformed);
    }
    let body_len = total.saturating_sub(SIG_LEN);
    let body = b.get(..body_len).ok_or(TokenError::Malformed)?;
    let mut pos = 0usize;
    let head = take(body, &mut pos, HEADER_LEN)?;
    let version = *head.first().ok_or(TokenError::Malformed)?;
    let kind = *head.get(1).ok_or(TokenError::Malformed)?;
    if version != TOKEN_VERSION {
        return Err(TokenError::UnsupportedVersion);
    }
    if kind != KIND_ADDR_UPDATE {
        return Err(TokenError::BadKind);
    }
    let seq = u64::from_be_bytes(
        head.get(2..10)
            .and_then(|s| s.try_into().ok())
            .ok_or(TokenError::Malformed)?,
    );
    if seq == 0 {
        return Err(TokenError::Malformed);
    }
    let n = usize::from(*head.get(10).ok_or(TokenError::Malformed)?);
    if !(1..=MAX_ENTRIES).contains(&n) {
        return Err(TokenError::Malformed);
    }
    let mut addrs: Vec<UpdateAddr> = Vec::with_capacity(n);
    for _ in 0..n {
        let family = *take(body, &mut pos, 1)?
            .first()
            .ok_or(TokenError::Malformed)?;
        let ip = match family {
            4 => {
                let o: [u8; 4] = take(body, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| TokenError::Malformed)?;
                IpAddr::V4(Ipv4Addr::from(o))
            }
            6 => {
                let o: [u8; 16] = take(body, &mut pos, 16)?
                    .try_into()
                    .map_err(|_| TokenError::Malformed)?;
                IpAddr::V6(Ipv6Addr::from(o))
            }
            _ => return Err(TokenError::Malformed),
        };
        let port_bytes: [u8; 2] = take(body, &mut pos, 2)?
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        let port = u16::from_be_bytes(port_bytes);
        let flags = *take(body, &mut pos, 1)?
            .first()
            .ok_or(TokenError::Malformed)?;
        if flags & !FLAGS_KNOWN != 0 || (ip.is_ipv4() && flags & FLAG_SHORT_LIVED != 0) {
            return Err(TokenError::Malformed);
        }
        if port == 0 || !update_allowed(ip) {
            return Err(TokenError::BadAddress);
        }
        let addr = SocketAddr::new(ip, port);
        if addrs.iter().any(|a| a.addr == addr) {
            return Err(TokenError::BadAddress);
        }
        addrs.push(UpdateAddr {
            addr,
            short_lived: flags & FLAG_SHORT_LIVED != 0,
            hint: flags & FLAG_HINT != 0,
        });
    }
    if pos != body_len {
        return Err(TokenError::Malformed);
    }
    Ok(SignedAddrUpdate {
        bytes: b.to_vec(),
        seq,
        addrs,
    })
}

/// Разбор внутриполосного пути: те же правила, что и для текста после base32.
pub fn decode_addr_update_bin(b: &[u8]) -> Result<SignedAddrUpdate, TokenError> {
    parse(b)
}

/// Токен для друга `recipient` от пары ключей `key`. `seq >= 1` (иначе `Malformed`),
/// набор из 1..=8 записей (иначе `BadAddress`), `recipient` не наш ключ (иначе `BadKey`).
/// Результат разбирается тем же разбором; сбой даёт `Malformed`.
pub fn issue_addr_update(
    key: &PairKey,
    recipient: &PublicKey,
    seq: u64,
    set: &PublishSet,
) -> Result<IssuedAddrUpdate, TokenError> {
    if seq == 0 {
        return Err(TokenError::Malformed);
    }
    let entries = set.as_slice();
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(TokenError::BadAddress);
    }
    let signer = key.public_key();
    if *recipient == signer {
        return Err(TokenError::BadKey);
    }
    let n = u8::try_from(entries.len()).map_err(|_| TokenError::BadAddress)?;
    let mut b: Vec<u8> = Vec::with_capacity(ADDR_UPDATE_MAX_LEN);
    b.push(TOKEN_VERSION);
    b.push(KIND_ADDR_UPDATE);
    b.extend_from_slice(&seq.to_be_bytes());
    b.push(n);
    for e in entries {
        match e.addr.ip() {
            IpAddr::V4(ip) => {
                b.push(4);
                b.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                b.push(6);
                b.extend_from_slice(&ip.octets());
            }
        }
        b.extend_from_slice(&e.addr.port().to_be_bytes());
        let mut flags = 0u8;
        if e.short_lived {
            flags |= FLAG_SHORT_LIVED;
        }
        if e.hint {
            flags |= FLAG_HINT;
        }
        b.push(flags);
    }
    let msg = signed_message(&signer, recipient, &b);
    let sig = key
        .sign(SignDomain::AddressUpdate, &msg)
        .map_err(|_| TokenError::SigningFailed)?;
    b.extend_from_slice(&sig);
    parse(&b).map_err(|_| TokenError::Malformed)?;
    Ok(IssuedAddrUpdate {
        bytes: b,
        seq,
        pair: None,
    })
}
