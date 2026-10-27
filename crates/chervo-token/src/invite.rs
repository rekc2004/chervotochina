//! Токен приглашения (`CHV1…`), состояние пригласившего (A) и приглашённого (B).
//!
//! Двоичный формат приглашения (числа big-endian), подпись Ed25519 A в домене `Invite`
//! над байтами `[0..L-64]`:
//! `[0] версия [1] вид [2..10] issued_at [10..18] expires_at [18..50] A_ed [50..82] A_x`
//! `[82..114] g (гостевой секрет) [114..146] c_A = BLAKE2s-256(COMMIT_TAG || r_A)`
//! `[146] n адресов (1..=8)`, затем n раз `[0x04|0x06][IP][порт u16]`, затем подпись (64).
//! `token_hash = BLAKE2s-256(TOKEN_HASH_TAG || все L байт)`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use blake2::{Blake2s256, Digest};
use chervo_identity::{GuestSecret, KxPublicKey, PairKey, PublicKey, SignDomain};
use zeroize::Zeroizing;

use crate::sas::{self, Sas};
use crate::{
    CLOCK_TOLERANCE_SECS, COMMIT_TAG, INVITE_PREFIX, InviteError, KIND_INVITE, M1_LEN, M2_LEN,
    MAX_INVITE_ADDRS, MAX_INVITE_SESSIONS, MAX_TTL_SECS, MIN_TTL_SECS, MSG_M1, MSG_M2, PROTO_V1,
    TOKEN_HASH_TAG, TOKEN_VERSION, TokenError, base32,
};

const HEAD_LEN: usize = 147;
const SIG_LEN: usize = 64;
const M1_BODY_LEN: usize = 130;

fn arr32(b: &[u8], r: Range<usize>) -> Option<[u8; 32]> {
    b.get(r)?.try_into().ok()
}

fn hash_commit(r: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(COMMIT_TAG);
    h.update(r);
    h.finalize().into()
}

fn hash_token(bytes: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(TOKEN_HASH_TAG);
    h.update(bytes);
    h.finalize().into()
}

/// Адрес допустим для токена: порт не 0, не неуказанный, не multicast, не широковещательный
/// IPv4, не IPv6 вида `::ffff:a.b.c.d`.
fn addr_ok(ip: &IpAddr, port: u16) -> bool {
    if port == 0 || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(a) => !a.is_broadcast(),
        IpAddr::V6(a) => a.to_ipv4_mapped().is_none(),
    }
}

/// 1..=8 адресов, каждый допустим, без повторов (по паре IP и порт).
fn check_addrs(addrs: &[SocketAddr]) -> Result<(), TokenError> {
    if addrs.is_empty() || addrs.len() > MAX_INVITE_ADDRS {
        return Err(TokenError::BadAddress);
    }
    for (i, a) in addrs.iter().enumerate() {
        if !addr_ok(&a.ip(), a.port()) {
            return Err(TokenError::BadAddress);
        }
        if addrs
            .iter()
            .take(i)
            .any(|p| p.ip() == a.ip() && p.port() == a.port())
        {
            return Err(TokenError::BadAddress);
        }
    }
    Ok(())
}

/// Разобранный и проверенный (подпись, длины, адреса, TTL) токен приглашения.
/// Нет `Debug`, нет `Clone`: внутри гостевой секрет.
pub struct InviteToken {
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) inviter_ed: PublicKey,
    pub(crate) inviter_x: KxPublicKey,
    guest: Zeroizing<[u8; 32]>,
    /// Публичная часть гостевой пары, вычислена при разборе.
    guest_pub: KxPublicKey,
    pub(crate) commit: [u8; 32],
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) hash: [u8; 32],
}

impl InviteToken {
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn inviter_ed(&self) -> PublicKey {
        self.inviter_ed
    }

    pub fn inviter_x(&self) -> KxPublicKey {
        self.inviter_x
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Гостевой секрет для `KxPeer` приглашённого.
    pub fn guest_secret(&self) -> Result<GuestSecret, TokenError> {
        GuestSecret::from_bytes(self.guest.as_slice()).map_err(|_| TokenError::BadKey)
    }

    /// Мягкая проверка времени с допуском `CLOCK_TOLERANCE_SECS`; решает время пригласившего.
    pub fn check_time(&self, now_unix: u64) -> Result<(), TokenError> {
        if now_unix.saturating_add(CLOCK_TOLERANCE_SECS) < self.issued_at {
            return Err(TokenError::NotYetValid);
        }
        if now_unix > self.expires_at.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(TokenError::Expired);
        }
        Ok(())
    }

    pub(crate) fn guest_public(&self) -> KxPublicKey {
        self.guest_pub
    }
}

/// Разбор двоичного приглашения (версия и вид уже проверены `decode`).
/// Порядок: длина и структура, адреса, время, ключи, подпись.
pub(crate) fn parse(b: &[u8]) -> Result<InviteToken, TokenError> {
    let n = usize::from(*b.get(HEAD_LEN - 1).ok_or(TokenError::Malformed)?);
    if !(1..=MAX_INVITE_ADDRS).contains(&n) {
        return Err(TokenError::Malformed);
    }
    let mut off = HEAD_LEN;
    let mut addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let family = *b.get(off).ok_or(TokenError::Malformed)?;
        let ip_len = match family {
            0x04 => 4usize,
            0x06 => 16usize,
            _ => return Err(TokenError::BadAddress),
        };
        let ip_end = off
            .checked_add(1)
            .and_then(|v| v.checked_add(ip_len))
            .ok_or(TokenError::Malformed)?;
        let ip_bytes = b.get(off + 1..ip_end).ok_or(TokenError::Malformed)?;
        let port_bytes: [u8; 2] = b
            .get(ip_end..ip_end + 2)
            .and_then(|s| s.try_into().ok())
            .ok_or(TokenError::Malformed)?;
        let ip = if ip_len == 4 {
            let a: [u8; 4] = ip_bytes.try_into().map_err(|_| TokenError::Malformed)?;
            IpAddr::V4(Ipv4Addr::from(a))
        } else {
            let a: [u8; 16] = ip_bytes.try_into().map_err(|_| TokenError::Malformed)?;
            IpAddr::V6(Ipv6Addr::from(a))
        };
        addrs.push(SocketAddr::new(ip, u16::from_be_bytes(port_bytes)));
        off = ip_end + 2;
    }
    if off.checked_add(SIG_LEN) != Some(b.len()) {
        return Err(TokenError::Malformed);
    }
    check_addrs(&addrs)?;

    let issued_at = u64::from_be_bytes(
        b.get(2..10)
            .and_then(|s| s.try_into().ok())
            .ok_or(TokenError::Malformed)?,
    );
    let expires_at = u64::from_be_bytes(
        b.get(10..18)
            .and_then(|s| s.try_into().ok())
            .ok_or(TokenError::Malformed)?,
    );
    let ttl = expires_at
        .checked_sub(issued_at)
        .ok_or(TokenError::BadTtl)?;
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
        return Err(TokenError::BadTtl);
    }

    let inviter_ed = PublicKey::try_from_slice(b.get(18..50).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::BadKey)?;
    let inviter_x = KxPublicKey::try_from_slice(b.get(50..82).ok_or(TokenError::Malformed)?)
        .map_err(|_| TokenError::BadKey)?;
    let mut guest = Zeroizing::new([0u8; 32]);
    guest.copy_from_slice(b.get(82..114).ok_or(TokenError::Malformed)?);
    let guest_pub = GuestSecret::from_bytes(guest.as_slice())
        .map_err(|_| TokenError::BadKey)?
        .public();
    if guest_pub == inviter_x {
        return Err(TokenError::BadKey);
    }
    let commit = arr32(b, 114..146).ok_or(TokenError::Malformed)?;

    let body_end = b.len() - SIG_LEN;
    let body = b.get(..body_end).ok_or(TokenError::Malformed)?;
    let sig = b.get(body_end..).ok_or(TokenError::Malformed)?;
    inviter_ed
        .verify(SignDomain::Invite, body, sig)
        .map_err(|_| TokenError::BadSignature)?;

    Ok(InviteToken {
        issued_at,
        expires_at,
        inviter_ed,
        inviter_x,
        guest,
        guest_pub,
        commit,
        addrs,
        hash: hash_token(b),
    })
}

/// Параметры приглашения. Без `Debug`: адреса не печатаются.
pub struct InviteDraft {
    pub issued_at: u64,
    pub ttl_secs: u64,
    pub addrs: Vec<SocketAddr>,
}

/// Сторона A. Возвращает состояние приглашения и текст токена (`CHV1…`).
pub fn issue_invite(
    draft: &InviteDraft,
    key: &PairKey,
) -> Result<(PendingInvite, String), TokenError> {
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&draft.ttl_secs) {
        return Err(TokenError::BadTtl);
    }
    let expires_at = draft
        .issued_at
        .checked_add(draft.ttl_secs)
        .ok_or(TokenError::BadTtl)?;
    check_addrs(&draft.addrs)?;
    let a_ed = key.public_key();
    let a_x = key.kx_public();

    let mut guest = GuestSecret::generate().map_err(|_| TokenError::RandomUnavailable)?;
    if guest.public() == a_x {
        guest = GuestSecret::generate().map_err(|_| TokenError::RandomUnavailable)?;
        if guest.public() == a_x {
            return Err(TokenError::BadKey);
        }
    }
    let guest_public = guest.public();
    let mut r_a = Zeroizing::new([0u8; 32]);
    getrandom::fill(r_a.as_mut_slice()).map_err(|_| TokenError::RandomUnavailable)?;
    let commit = hash_commit(&r_a);

    let mut b: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(400));
    b.push(TOKEN_VERSION);
    b.push(KIND_INVITE);
    b.extend_from_slice(&draft.issued_at.to_be_bytes());
    b.extend_from_slice(&expires_at.to_be_bytes());
    b.extend_from_slice(&a_ed.to_bytes());
    b.extend_from_slice(&a_x.to_bytes());
    b.extend_from_slice(guest.to_token_bytes().as_slice());
    b.extend_from_slice(&commit);
    // число адресов проверено `check_addrs` (1..=8)
    b.push(u8::try_from(draft.addrs.len()).map_err(|_| TokenError::BadAddress)?);
    for a in &draft.addrs {
        match a.ip() {
            IpAddr::V4(ip) => {
                b.push(0x04);
                b.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                b.push(0x06);
                b.extend_from_slice(&ip.octets());
            }
        }
        b.extend_from_slice(&a.port().to_be_bytes());
    }
    let sig = key
        .sign(SignDomain::Invite, &b)
        .map_err(|_| TokenError::SigningFailed)?;
    b.extend_from_slice(&sig);
    let token_hash = hash_token(&b);
    let encoded = Zeroizing::new(base32::encode(&b));
    let text = format!("{INVITE_PREFIX}{}", encoded.as_str());
    drop(guest);
    Ok((
        PendingInvite {
            r_a,
            token_hash,
            a_ed,
            a_x,
            guest_public,
            expires_at,
            sessions: 0,
            used: false,
        },
        text,
    ))
}

/// Состояние A: `r_A`, хэш токена, ключи A, публичный G, срок, счётчик сессий, признак
/// использования. Нет `Clone`. Гостевой секрет после выпуска токена не хранится.
pub struct PendingInvite {
    r_a: Zeroizing<[u8; 32]>,
    token_hash: [u8; 32],
    a_ed: PublicKey,
    a_x: KxPublicKey,
    guest_public: KxPublicKey,
    expires_at: u64,
    sessions: u32,
    used: bool,
}

impl std::fmt::Debug for PendingInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingInvite(..)")
    }
}

/// Ключи приглашённого B, подтверждённые подписью M1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InviteeKeys {
    pub ed: PublicKey,
    pub x: KxPublicKey,
}

impl std::fmt::Debug for InviteeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteeKeys(..)")
    }
}

impl PendingInvite {
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Публичная часть гостевой пары (для `KxPeer` пригласившего).
    pub fn guest_public(&self) -> KxPublicKey {
        self.guest_public
    }

    /// Вызывать на каждое соединение гостевой пары до `flow::inviter_exchange`.
    pub fn begin_session(&mut self, now_unix: u64) -> Result<(), InviteError> {
        if self.used {
            return Err(InviteError::Used);
        }
        if now_unix >= self.expires_at {
            return Err(InviteError::Expired);
        }
        if self.sessions >= MAX_INVITE_SESSIONS {
            return Err(InviteError::TooManySessions);
        }
        self.sessions = self.sessions.saturating_add(1);
        Ok(())
    }

    /// Разбор M1. Принимается ровно один раз: после успеха `used`, ошибка `used` не ставит.
    /// Возвращает M2 (раскрытие `r_A`), SAS и ключи B.
    ///
    /// `now_unix` читается вызывающим сразу перед вызовом (после чтения M1): срок проверяется
    /// здесь, а не только при `begin_session`. Порядок проверок: нет сессии, использовано,
    /// истёк срок (`now_unix >= expires_at`), затем разбор M1. Просроченное приглашение
    /// `used` не ставит.
    pub fn on_m1(
        &mut self,
        m1: &[u8],
        now_unix: u64,
    ) -> Result<([u8; M2_LEN], Sas, InviteeKeys), InviteError> {
        if self.sessions == 0 {
            return Err(InviteError::NoSession);
        }
        if self.used {
            return Err(InviteError::Used);
        }
        if now_unix >= self.expires_at {
            return Err(InviteError::Expired);
        }
        if m1.len() != M1_LEN || m1.first() != Some(&MSG_M1) || m1.get(1) != Some(&PROTO_V1) {
            return Err(InviteError::Malformed);
        }
        let token_hash = arr32(m1, 2..34).ok_or(InviteError::Malformed)?;
        if token_hash != self.token_hash {
            return Err(InviteError::WrongToken);
        }
        let b_ed = PublicKey::try_from_slice(m1.get(34..66).ok_or(InviteError::Malformed)?)
            .map_err(|_| InviteError::BadKey)?;
        let b_x = KxPublicKey::try_from_slice(m1.get(66..98).ok_or(InviteError::Malformed)?)
            .map_err(|_| InviteError::BadKey)?;
        let r_b = arr32(m1, 98..130).ok_or(InviteError::Malformed)?;
        if b_x == self.a_x || b_x == self.guest_public || b_ed == self.a_ed {
            return Err(InviteError::BadKey);
        }
        let body = m1.get(..M1_BODY_LEN).ok_or(InviteError::Malformed)?;
        let sig = m1.get(M1_BODY_LEN..).ok_or(InviteError::Malformed)?;
        b_ed.verify(SignDomain::InviteAccept, body, sig)
            .map_err(|_| InviteError::BadSignature)?;
        self.used = true;
        let sas = sas::compute(
            &self.token_hash,
            &self.a_ed,
            &self.a_x,
            &b_ed,
            &b_x,
            &self.r_a,
            &r_b,
        );
        let mut m2 = [0u8; M2_LEN];
        m2[0] = MSG_M2;
        m2[1] = PROTO_V1;
        m2[2..].copy_from_slice(self.r_a.as_slice());
        Ok((m2, sas, InviteeKeys { ed: b_ed, x: b_x }))
    }
}

/// Сторона B. Нет `Clone`.
pub struct InviteeSession {
    token_hash: [u8; 32],
    commit: [u8; 32],
    a_ed: PublicKey,
    a_x: KxPublicKey,
    b_ed: PublicKey,
    b_x: KxPublicKey,
    r_b: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for InviteeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteeSession(..)")
    }
}

impl InviteeSession {
    /// `key` это новый ключ пары B. Возвращает состояние и M1 (194 байта).
    pub fn start(token: &InviteToken, key: &PairKey) -> Result<(Self, [u8; M1_LEN]), InviteError> {
        let b_ed = key.public_key();
        let b_x = key.kx_public();
        let guest_public = token.guest_public();
        if b_x == token.inviter_x || b_x == guest_public || b_ed == token.inviter_ed {
            return Err(InviteError::BadKey);
        }
        let mut r_b = Zeroizing::new([0u8; 32]);
        getrandom::fill(r_b.as_mut_slice()).map_err(|_| InviteError::RandomUnavailable)?;

        let mut m1 = [0u8; M1_LEN];
        m1[0] = MSG_M1;
        m1[1] = PROTO_V1;
        m1[2..34].copy_from_slice(&token.hash);
        m1[34..66].copy_from_slice(&b_ed.to_bytes());
        m1[66..98].copy_from_slice(&b_x.to_bytes());
        m1[98..130].copy_from_slice(r_b.as_slice());
        let sig = key
            .sign(SignDomain::InviteAccept, &m1[..M1_BODY_LEN])
            .map_err(|_| InviteError::SigningFailed)?;
        m1[M1_BODY_LEN..].copy_from_slice(&sig);
        Ok((
            Self {
                token_hash: token.hash,
                commit: token.commit,
                a_ed: token.inviter_ed,
                a_x: token.inviter_x,
                b_ed,
                b_x,
                r_b,
            },
            m1,
        ))
    }

    /// Разбор M2: проверка обязательства `c_A`, затем SAS.
    pub fn on_m2(self, m2: &[u8]) -> Result<Sas, InviteError> {
        if m2.len() != M2_LEN || m2.first() != Some(&MSG_M2) || m2.get(1) != Some(&PROTO_V1) {
            return Err(InviteError::Malformed);
        }
        let r_a = Zeroizing::new(arr32(m2, 2..34).ok_or(InviteError::Malformed)?);
        if hash_commit(&r_a) != self.commit {
            return Err(InviteError::CommitMismatch);
        }
        Ok(sas::compute(
            &self.token_hash,
            &self.a_ed,
            &self.a_x,
            &self.b_ed,
            &self.b_x,
            &r_a,
            &self.r_b,
        ))
    }
}
