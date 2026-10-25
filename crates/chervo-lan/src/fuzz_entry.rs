//! Fixtures shared by the crate's tests and the libFuzzer entry points (`fuzz/`, outside the
//! workspace). Present only in test builds and with the `fuzzing` feature; product builds do
//! not contain it.
//!
//! The fixture is a pair with two DISTINCT key-exchange keys (an equal key is refused by
//! `lan_keys` and would leave the table empty). `fuzz_lan_ready` runs a positive control: the
//! real beacon of the other side produces exactly one found item, so a vacuous run is a
//! crash, not a pass. `fuzz_beacon` feeds one datagram to a long-lived receiver core; the
//! clock advances by more than every throttle between calls, so the budgets never starve it.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use chervo_addr::LanPeer;
use chervo_identity::{IdentityError, KxPeer, PairId, SecretStore, create};
use zeroize::Zeroizing;

use crate::core::{CoreConfig, LanCore};
use crate::limits::BEACON_LEN;

/// Wall clock used by the fixture: epoch 30 000 001 exactly.
pub(crate) const FIX_UNIX: u64 = 1_800_000_060;
/// Address and port of the receiving side.
pub(crate) const RECV_LOCAL: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::new(192, 168, 77, 13), 41_000);
/// Address and port of the sending side (the real beacon comes from here).
pub(crate) const SEND_LOCAL: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::new(192, 168, 77, 12), 42_000);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Memory store for the one-off keys of the fixture.
#[derive(Default)]
struct MemStore(Mutex<HashMap<PairId, Vec<u8>>>);

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(lock(&self.0).get(pair).cloned().map(Zeroizing::new))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        lock(&self.0).insert(*pair, blob.to_vec());
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        lock(&self.0).remove(pair);
        Ok(())
    }
}

/// One pair seen from both sides: `a` is the receiver, `b` the sender.
#[derive(Clone)]
pub(crate) struct PairFixture {
    pub(crate) pair: PairId,
    pub(crate) a: KxPeer,
    pub(crate) b: KxPeer,
}

impl PairFixture {
    pub(crate) fn new() -> Option<Self> {
        Self::with_pair(PairId::generate().ok()?)
    }

    pub(crate) fn with_pair(pair: PairId) -> Option<Self> {
        let (sa, sb) = (MemStore::default(), MemStore::default());
        let ka = create(&sa, &pair).ok()?;
        let kb = create(&sb, &pair).ok()?;
        let (pa, pb) = (ka.kx_public(), kb.kx_public());
        Some(Self {
            pair,
            a: KxPeer::new(pair, ka.into_kx(), pb),
            b: KxPeer::new(pair, kb.into_kx(), pa),
        })
    }

    /// Peer entry for the receiving side.
    pub(crate) fn peer_a(&self) -> Option<LanPeer> {
        Some(LanPeer {
            pair: self.pair,
            keys: self.a.lan_keys().ok()?,
        })
    }

    /// Peer entry for the sending side.
    pub(crate) fn peer_b(&self) -> Option<LanPeer> {
        Some(LanPeer {
            pair: self.pair,
            keys: self.b.lan_keys().ok()?,
        })
    }

    /// A core of the receiving side with the fixture endpoint.
    pub(crate) fn receiver(&self) -> Option<LanCore> {
        let mut core = LanCore::new(CoreConfig::default());
        core.set_local(Some(RECV_LOCAL), Duration::ZERO);
        core.set_peers(vec![self.peer_a()?]);
        Some(core)
    }

    /// The real beacon of the sending side at `FIX_UNIX`.
    pub(crate) fn real_beacon(&self) -> Option<[u8; BEACON_LEN]> {
        let mut core = LanCore::new(CoreConfig::default());
        core.set_local(Some(SEND_LOCAL), Duration::ZERO);
        core.set_peers(vec![self.peer_b()?]);
        core.set_wanted(vec![self.pair]);
        core.poll_send(Duration::ZERO, FIX_UNIX)
    }
}

pub(crate) fn send_src() -> SocketAddr {
    SocketAddr::V4(SEND_LOCAL)
}

struct FuzzState {
    core: LanCore,
    now: Duration,
}

fn state() -> Option<&'static Mutex<FuzzState>> {
    static STATE: OnceLock<Option<Mutex<FuzzState>>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let fx = PairFixture::new()?;
            // positive control: the real beacon is found exactly once, with the right data
            let mut probe = fx.receiver()?;
            if probe.peer_count() != 1 {
                return None;
            }
            let beacon = fx.real_beacon()?;
            probe.on_datagram(send_src(), &beacon, Duration::from_secs(1), FIX_UNIX);
            let found = probe.take_found();
            let f = found.first()?;
            if found.len() != 1 || f.pair != fx.pair || f.addr != SEND_LOCAL {
                return None;
            }
            Some(Mutex::new(FuzzState {
                core: fx.receiver()?,
                now: Duration::from_secs(1),
            }))
        })
        .as_ref()
}

/// Only for fuzzing: true when the fixture exists and its positive control found the real
/// beacon of the other side exactly once.
#[doc(hidden)]
pub fn fuzz_lan_ready() -> bool {
    state().is_some()
}

/// Only for fuzzing: feeds one datagram (from the fixture friend's address) to the receiver.
/// True means a found item was produced; for anything but the one real, secret beacon that
/// must never happen.
#[doc(hidden)]
pub fn fuzz_beacon(data: &[u8]) -> bool {
    let Some(st) = state() else {
        return false;
    };
    let mut st = lock(st);
    st.now += Duration::from_secs(11);
    let now = st.now;
    st.core.on_datagram(send_src(), data, now, FIX_UNIX);
    !st.core.take_found().is_empty()
}
