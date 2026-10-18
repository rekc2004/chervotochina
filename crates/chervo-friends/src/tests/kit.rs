//! Помощники тестов: ключи, образцы данных, сравнение, ГПСЧ для fuzz-смоука.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use chervo_addr::{AddrSource, KnownAddr};
use chervo_identity::{IdentityError, PairId, PairKey, SecretStore, create};
use chervo_token::{RevocationReason, issue_revocation};
use zeroize::Zeroizing;

use crate::{
    AutoAcceptLimits, BookData, Friend, FriendState, PendingEntry, PendingRole, Permission, Retired,
};

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

pub fn key() -> PairKey {
    create(&MemStore::default(), &PairId::generate().unwrap()).unwrap()
}

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Друг с настоящими ключами; адреса обоих семейств.
pub fn friend(i: u8) -> Friend {
    let k = key();
    let o = key();
    Friend {
        pair: PairId::from_bytes([i; 16]),
        name: format!("Друг {i}"),
        friend_ed: k.public_key(),
        friend_x: k.kx_public(),
        our_ed: o.public_key(),
        state: FriendState::Active,
        permission: Permission::Ask,
        known_addrs: vec![
            KnownAddr {
                addr: addr("203.0.113.7:4455"),
                source: AddrSource::Invite,
                last_seen_unix: 11,
                short_lived: false,
                hint: false,
            },
            KnownAddr {
                addr: addr("[2001:db8::1]:9"),
                source: AddrSource::ObservedByFriend,
                last_seen_unix: 22,
                short_lived: true,
                hint: false,
            },
        ],
        last_addr_seq: 7,
        addr_seq_out: 9,
        added_at_unix: 1000 + u64::from(i),
        retired: None,
    }
}

pub fn pending(i: u8, role: PendingRole) -> PendingEntry {
    PendingEntry {
        pair: PairId::from_bytes([0xE0 ^ i; 16]),
        role,
        expires_at_unix: 5000 + u64::from(i),
    }
}

/// Друг `Retired` с настоящим подписанным отзывом нашего ключа.
pub fn retired_friend(i: u8, reason: RevocationReason) -> Friend {
    let ours = key();
    let mut f = friend(i);
    f.our_ed = ours.public_key();
    f.state = FriendState::Retired;
    f.known_addrs.clear();
    f.retired = Some(Retired {
        revocation: issue_revocation(&ours, reason, 4242).unwrap(),
        reason,
    });
    f
}

/// Образец: три друга (Ask и AutoAccept, `Blocked`, `RevokedByPeer`, `Retired`) и две записи pending.
pub fn sample() -> BookData {
    let mut a = friend(1);
    a.state = FriendState::Blocked;
    let mut b = friend(2);
    b.permission = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1 << 30,
        max_files: 10,
    });
    b.state = FriendState::RevokedByPeer;
    b.known_addrs.clear();
    BookData {
        epoch: 77,
        friends: vec![a, b, retired_friend(3, RevocationReason::Removed)],
        pending: vec![
            pending(1, PendingRole::Inviter),
            pending(2, PendingRole::Invitee),
        ],
    }
}

pub fn same_friend(a: &Friend, b: &Friend) -> bool {
    a.pair == b.pair
        && a.name == b.name
        && a.friend_ed == b.friend_ed
        && a.friend_x == b.friend_x
        && a.our_ed == b.our_ed
        && a.state == b.state
        && a.permission == b.permission
        && a.known_addrs == b.known_addrs
        && a.last_addr_seq == b.last_addr_seq
        && a.addr_seq_out == b.addr_seq_out
        && a.added_at_unix == b.added_at_unix
        && a.retired == b.retired
}

pub fn same(a: &BookData, b: &BookData) -> bool {
    a.epoch == b.epoch
        && a.friends.len() == b.friends.len()
        && a.pending == b.pending
        && a.friends
            .iter()
            .zip(b.friends.iter())
            .all(|(x, y)| same_friend(x, y))
}

pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Число итераций: `CHERVO_FUZZ_ITERS`; по умолчанию 20 000 (release) или 2 000 (debug).
pub fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Одна случайная мутация: переворот бита, вставка, удаление, обрезка, замена байта.
pub fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(5) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() + 1);
            let len = 1 + rng.below(4);
            for (k, b) in rng.bytes(len).into_iter().enumerate() {
                v.insert(i + k, b);
            }
        }
        2 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        3 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}
