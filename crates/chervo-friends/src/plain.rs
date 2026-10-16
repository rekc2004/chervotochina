//! Открытый текст v2 (внутри AEAD, числа big-endian); читается и v1, пишется всегда v2.
//!
//! `[0x02][n_friends u16]`, на друга: `[pair 16][name_len u8][name][friend_ed 32][friend_x 32]`
//! `[our_ed 32][state u8 0|1|2][perm u8 0|1 (+ max_total_bytes u64 + max_files u32 при 1)]`
//! `[last_addr_seq u64][addr_seq_out u64][added_at u64][n_addrs u8]`, на адрес:
//! `[семейство 0x04|0x06][IP][порт u16][source u8 0..=6][last_seen u64][flags u8]`, где
//! flags: бит 0 short_lived, бит 1 hint, остальные 0; затем `[n_pending u16]`, на запись:
//! `[pair 16][role u8 0|1][expires_at u64]`.
//!
//! v1 (только чтение): нет `addr_seq_out` (при чтении 0), `source` 0..=5, байт после
//! `last_seen` это short_lived 0|1 (hint = false). Любая другая версия: `Corrupt`.
//!
//! Разбор строгий: счётчики против остатка буфера, лимиты, дубликаты `pair`, неизвестные
//! значения перечислений, имена, ключи через `try_from_slice`, лишние байты в конце.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use chervo_addr::{AddrSource, KnownAddr};
use chervo_identity::{KxPublicKey, PairId, PublicKey};
use zeroize::Zeroizing;

use crate::{
    AutoAcceptLimits, BookData, Friend, FriendState, FriendsError, MAX_ADDRS_PER_FRIEND,
    MAX_FRIENDS, MAX_NAME_BYTES, MAX_PENDING, PendingEntry, PendingRole, Permission,
};

pub(crate) const PLAIN_VERSION: u8 = 0x02;
const PLAIN_V1: u8 = 0x01;
/// Минимальный размер записи друга (имя из 0 байт, 0 адресов, `Ask`): для проверки счётчика.
const MIN_FRIEND_LEN_V1: usize = 16 + 1 + 32 * 3 + 1 + 1 + 8 + 8 + 1;
const MIN_FRIEND_LEN_V2: usize = MIN_FRIEND_LEN_V1 + 8;
const FLAG_SHORT_LIVED: u8 = 0x01;
const FLAG_HINT: u8 = 0x02;
const PENDING_LEN: usize = 16 + 1 + 8;

/// Имя допустимо: непусто, не больше `MAX_NAME_BYTES` байт, без управляющих символов.
pub(crate) fn name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_BYTES && !name.chars().any(char::is_control)
}

fn source_byte(s: AddrSource) -> u8 {
    match s {
        AddrSource::Interface => 0,
        AddrSource::Lan => 1,
        AddrSource::PortMapping => 2,
        AddrSource::Invite => 3,
        AddrSource::AddressUpdate => 4,
        AddrSource::ObservedByFriend => 5,
        AddrSource::Contact => 6,
    }
}

/// `max` — наибольший допустимый байт источника в этой версии (v1: 5, v2: 6).
fn source_from(b: u8, max: u8) -> Option<AddrSource> {
    if b > max {
        return None;
    }
    Some(match b {
        0 => AddrSource::Interface,
        1 => AddrSource::Lan,
        2 => AddrSource::PortMapping,
        3 => AddrSource::Invite,
        4 => AddrSource::AddressUpdate,
        5 => AddrSource::ObservedByFriend,
        6 => AddrSource::Contact,
        _ => return None,
    })
}

/// Точный размер записи (при успешном `encode`): версия, счётчики, друзья, pending.
fn encoded_len(data: &BookData) -> usize {
    let friends: usize = data
        .friends
        .iter()
        .map(|f| {
            let perm = match f.permission {
                Permission::Ask => 1,
                Permission::AutoAccept(_) => 1 + 8 + 4,
            };
            let addrs: usize = f
                .known_addrs
                .iter()
                .map(|a| (if a.addr.is_ipv4() { 1 + 4 } else { 1 + 16 }) + 2 + 1 + 8 + 1)
                .sum();
            // pair, длина имени, имя, три ключа, состояние, право, три u64, число адресов
            16 + 1 + f.name.len() + 3 * 32 + 1 + perm + 8 + 8 + 8 + 1 + addrs
        })
        .sum();
    // версия, число друзей, число pending; pending: pair, роль, срок
    1 + 2 + 2 + friends + data.pending.len() * (16 + 1 + 8)
}

/// Запись; те же проверки, что у разбора (файл, который нельзя прочитать, не пишется).
pub(crate) fn encode(data: &BookData) -> Result<Zeroizing<Vec<u8>>, FriendsError> {
    if data.friends.len() > MAX_FRIENDS || data.pending.len() > MAX_PENDING {
        return Err(FriendsError::LimitExceeded);
    }
    let mut seen = HashSet::new();
    // точный размер заранее: буфер не перевыделяется, копии открытого текста не остаются
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(encoded_len(data)));
    out.push(PLAIN_VERSION);
    let n_friends = u16::try_from(data.friends.len()).map_err(|_| FriendsError::LimitExceeded)?;
    out.extend_from_slice(&n_friends.to_be_bytes());
    for f in &data.friends {
        if !seen.insert(*f.pair.as_bytes()) {
            return Err(FriendsError::AlreadyExists);
        }
        if !name_ok(&f.name) {
            return Err(FriendsError::InvalidName);
        }
        if f.known_addrs.len() > MAX_ADDRS_PER_FRIEND {
            return Err(FriendsError::LimitExceeded);
        }
        out.extend_from_slice(f.pair.as_bytes());
        out.push(u8::try_from(f.name.len()).map_err(|_| FriendsError::InvalidName)?);
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(&f.friend_ed.to_bytes());
        out.extend_from_slice(&f.friend_x.to_bytes());
        out.extend_from_slice(&f.our_ed.to_bytes());
        out.push(match f.state {
            FriendState::Active => 0,
            FriendState::Blocked => 1,
            FriendState::RevokedByPeer => 2,
        });
        match f.permission {
            Permission::Ask => out.push(0),
            Permission::AutoAccept(l) => {
                if l.max_files == 0 || l.max_total_bytes == 0 {
                    return Err(FriendsError::InvalidLimits);
                }
                out.push(1);
                out.extend_from_slice(&l.max_total_bytes.to_be_bytes());
                out.extend_from_slice(&l.max_files.to_be_bytes());
            }
        }
        out.extend_from_slice(&f.last_addr_seq.to_be_bytes());
        out.extend_from_slice(&f.addr_seq_out.to_be_bytes());
        out.extend_from_slice(&f.added_at_unix.to_be_bytes());
        out.push(u8::try_from(f.known_addrs.len()).map_err(|_| FriendsError::LimitExceeded)?);
        for a in &f.known_addrs {
            match a.addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(0x04);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(0x06);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&a.addr.port().to_be_bytes());
            out.push(source_byte(a.source));
            out.extend_from_slice(&a.last_seen_unix.to_be_bytes());
            let mut flags = 0u8;
            if a.short_lived {
                flags |= FLAG_SHORT_LIVED;
            }
            if a.hint {
                flags |= FLAG_HINT;
            }
            out.push(flags);
        }
    }
    let n_pending = u16::try_from(data.pending.len()).map_err(|_| FriendsError::LimitExceeded)?;
    out.extend_from_slice(&n_pending.to_be_bytes());
    let mut seen_pending = HashSet::new();
    for p in &data.pending {
        if !seen_pending.insert(*p.pair.as_bytes()) || seen.contains(p.pair.as_bytes()) {
            return Err(FriendsError::AlreadyExists);
        }
        out.extend_from_slice(p.pair.as_bytes());
        out.push(match p.role {
            PendingRole::Inviter => 0,
            PendingRole::Invitee => 1,
        });
        out.extend_from_slice(&p.expires_at_unix.to_be_bytes());
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FriendsError> {
        let (head, rest) = self.b.split_at_checked(n).ok_or(FriendsError::Corrupt)?;
        self.b = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, FriendsError> {
        self.take(1)?.first().copied().ok_or(FriendsError::Corrupt)
    }

    fn u16(&mut self) -> Result<u16, FriendsError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| FriendsError::Corrupt)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, FriendsError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| FriendsError::Corrupt)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, FriendsError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| FriendsError::Corrupt)?,
        ))
    }

    fn pair(&mut self) -> Result<PairId, FriendsError> {
        let a: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| FriendsError::Corrupt)?;
        Ok(PairId::from_bytes(a))
    }

    /// v1: байт short_lived, только 0|1.
    fn flag(&mut self) -> Result<bool, FriendsError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FriendsError::Corrupt),
        }
    }
}

/// Строгий разбор открытого текста (v1 или v2). Любое отклонение: `Corrupt`.
pub(crate) fn decode(buf: &[u8]) -> Result<BookData, FriendsError> {
    let mut r = Reader { b: buf };
    let version = r.u8()?;
    let (v2, min_friend, max_source) = match version {
        PLAIN_V1 => (false, MIN_FRIEND_LEN_V1, 5u8),
        PLAIN_VERSION => (true, MIN_FRIEND_LEN_V2, 6u8),
        _ => return Err(FriendsError::Corrupt),
    };
    let n_friends = usize::from(r.u16()?);
    if n_friends > MAX_FRIENDS || n_friends.saturating_mul(min_friend) > r.b.len() {
        return Err(FriendsError::Corrupt);
    }
    let mut friends = Vec::with_capacity(n_friends);
    let mut seen = HashSet::new();
    for _ in 0..n_friends {
        let pair = r.pair()?;
        if !seen.insert(*pair.as_bytes()) {
            return Err(FriendsError::Corrupt);
        }
        let name_len = usize::from(r.u8()?);
        let name = std::str::from_utf8(r.take(name_len)?)
            .map_err(|_| FriendsError::Corrupt)?
            .to_owned();
        if !name_ok(&name) {
            return Err(FriendsError::Corrupt);
        }
        let friend_ed =
            PublicKey::try_from_slice(r.take(32)?).map_err(|_| FriendsError::Corrupt)?;
        let friend_x =
            KxPublicKey::try_from_slice(r.take(32)?).map_err(|_| FriendsError::Corrupt)?;
        let our_ed = PublicKey::try_from_slice(r.take(32)?).map_err(|_| FriendsError::Corrupt)?;
        let state = match r.u8()? {
            0 => FriendState::Active,
            1 => FriendState::Blocked,
            2 => FriendState::RevokedByPeer,
            _ => return Err(FriendsError::Corrupt),
        };
        let permission = match r.u8()? {
            0 => Permission::Ask,
            1 => {
                let max_total_bytes = r.u64()?;
                let max_files = r.u32()?;
                if max_total_bytes == 0 || max_files == 0 {
                    return Err(FriendsError::Corrupt);
                }
                Permission::AutoAccept(AutoAcceptLimits {
                    max_total_bytes,
                    max_files,
                })
            }
            _ => return Err(FriendsError::Corrupt),
        };
        let last_addr_seq = r.u64()?;
        let addr_seq_out = if v2 { r.u64()? } else { 0 };
        let added_at_unix = r.u64()?;
        let n_addrs = usize::from(r.u8()?);
        if n_addrs > MAX_ADDRS_PER_FRIEND {
            return Err(FriendsError::Corrupt);
        }
        let mut known_addrs = Vec::with_capacity(n_addrs);
        for _ in 0..n_addrs {
            let ip = match r.u8()? {
                0x04 => {
                    let a: [u8; 4] = r.take(4)?.try_into().map_err(|_| FriendsError::Corrupt)?;
                    IpAddr::V4(Ipv4Addr::from(a))
                }
                0x06 => {
                    let a: [u8; 16] = r.take(16)?.try_into().map_err(|_| FriendsError::Corrupt)?;
                    IpAddr::V6(Ipv6Addr::from(a))
                }
                _ => return Err(FriendsError::Corrupt),
            };
            let port = r.u16()?;
            let source = source_from(r.u8()?, max_source).ok_or(FriendsError::Corrupt)?;
            let last_seen_unix = r.u64()?;
            let (short_lived, hint) = if v2 {
                let flags = r.u8()?;
                if flags & !(FLAG_SHORT_LIVED | FLAG_HINT) != 0 {
                    return Err(FriendsError::Corrupt);
                }
                (flags & FLAG_SHORT_LIVED != 0, flags & FLAG_HINT != 0)
            } else {
                (r.flag()?, false)
            };
            known_addrs.push(KnownAddr {
                addr: SocketAddr::new(ip, port),
                source,
                last_seen_unix,
                short_lived,
                hint,
            });
        }
        friends.push(Friend {
            pair,
            name,
            friend_ed,
            friend_x,
            our_ed,
            state,
            permission,
            known_addrs,
            last_addr_seq,
            addr_seq_out,
            added_at_unix,
        });
    }
    let n_pending = usize::from(r.u16()?);
    if n_pending > MAX_PENDING || n_pending.saturating_mul(PENDING_LEN) > r.b.len() {
        return Err(FriendsError::Corrupt);
    }
    let mut pending = Vec::with_capacity(n_pending);
    let mut seen_pending = HashSet::new();
    for _ in 0..n_pending {
        let pair = r.pair()?;
        if !seen_pending.insert(*pair.as_bytes()) || seen.contains(pair.as_bytes()) {
            return Err(FriendsError::Corrupt);
        }
        let role = match r.u8()? {
            0 => PendingRole::Inviter,
            1 => PendingRole::Invitee,
            _ => return Err(FriendsError::Corrupt),
        };
        let expires_at_unix = r.u64()?;
        pending.push(PendingEntry {
            pair,
            role,
            expires_at_unix,
        });
    }
    if !r.b.is_empty() {
        return Err(FriendsError::Corrupt);
    }
    Ok(BookData { friends, pending })
}
