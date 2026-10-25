//! `LanCore`: the pure state machine of LAN discovery (spec sections 1 D2-D7 and 7).
//! No sockets, no clock, no threads: time is injected (`now` monotonic, `unix` wall clock with
//! the user's offset). Every received datagram is hostile; the order of checks in
//! `on_datagram` is fixed by the specification and each step is O(1) in the datagram.
//! The core never produces a datagram in reaction to a received one.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use chervo_addr::{AddrClass, LAN_FOUND_MAX, LanFound, LanPeer, classify};
use chervo_identity::{LAN_ID_LEN, LAN_NONCE_LEN, LAN_SLOT_LEN, PairId};

use crate::limits::{
    BEACON_INTERVAL, BEACON_JITTER_MS, BEACON_LEN, BURST_OFFSETS, FOUND_MAP_MAX, FOUND_REPEAT,
    GLOBAL_BURST, GLOBAL_PERIOD, LAN_EPOCH_SECS, LAN_SLOTS, MAX_OPENS, MAX_WAIT, SEND_CAP,
    SEND_CAP_WINDOW, SOURCE_BURST, SOURCE_MAP_MAX, SOURCE_PERIOD,
};
use crate::wire::{self, ParseError};

/// Epoch number of a wall-clock time.
pub fn lan_epoch(unix: u64) -> u64 {
    unix / LAN_EPOCH_SECS
}

/// Tests only; production is always `CoreConfig::default()`.
#[derive(Clone, Copy, Default)]
pub struct CoreConfig {
    /// Accept 127/8 as local address and as beacon source, and do not drop our own address.
    pub allow_loopback: bool,
}

/// Counters. Plain numbers: nothing about addresses, pairs or keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LanStats {
    pub dgrams_in: u64,
    pub dropped_budget: u64,
    pub dropped_len: u64,
    pub dropped_ver: u64,
    pub dropped_src: u64,
    pub dropped_source_rate: u64,
    pub lookups: u64,
    pub aead_opens: u64,
    pub found: u64,
    pub found_throttled: u64,
    pub beacons_out: u64,
    pub send_errors: u64,
    pub rng_errors: u64,
}

/// What stops the core from using sockets (for the driver's status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// `set_local` was never called.
    NoLocal,
    /// No usable private local address.
    NoLan,
    NoPeers,
    Ready,
}

fn bump(c: &mut u64) {
    *c = c.saturating_add(1);
}

/// Token bucket with whole tokens and a refill period.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: u32,
    last: Duration,
}

impl Bucket {
    fn full(burst: u32, now: Duration) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    /// Tokens and reference time after refilling to `now` (pure).
    fn refilled(&self, burst: u32, period: Duration, now: Duration) -> (u32, Duration) {
        let elapsed = now.saturating_sub(self.last);
        let add = elapsed.as_millis() / period.as_millis().max(1);
        let tokens = u128::from(self.tokens)
            .saturating_add(add)
            .min(u128::from(burst));
        let tokens = u32::try_from(tokens).unwrap_or(burst);
        if tokens >= burst {
            (burst, now.max(self.last))
        } else {
            let steps = u32::try_from(add).unwrap_or(burst);
            (tokens, self.last + period * steps)
        }
    }

    fn available(&self, burst: u32, period: Duration, now: Duration) -> u32 {
        self.refilled(burst, period, now).0
    }

    fn take(&mut self, burst: u32, period: Duration, now: Duration) -> bool {
        let (tokens, last) = self.refilled(burst, period, now);
        self.tokens = tokens;
        self.last = last;
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

struct SourceEntry {
    bucket: Bucket,
    used: Duration,
}

/// One slot of the announced set of the current epoch.
enum SlotPlan {
    Real(PairId),
    Filler([u8; LAN_ID_LEN]),
}

struct EpochState {
    epoch: u64,
    slots: Vec<SlotPlan>,
}

#[derive(Default)]
struct Table {
    /// Epoch the table was built around (e-1, e, e+1).
    center: Option<u64>,
    dirty: bool,
    /// id -> (index in `peers`, epoch of that id)
    map: HashMap<[u8; LAN_ID_LEN], (usize, u64)>,
}

#[derive(Default)]
struct Sched {
    next_periodic: Option<Duration>,
    bursts: Vec<Duration>,
    sent: VecDeque<Duration>,
}

/// Pure state machine. RNG: `getrandom`; a failure skips that beacon.
pub struct LanCore {
    cfg: CoreConfig,
    local: Option<SocketAddrV4>,
    ever_local: bool,
    peers: Vec<LanPeer>,
    wanted: Vec<PairId>,
    active: bool,
    want_burst: bool,
    ep: Option<EpochState>,
    table: Table,
    sched: Sched,
    global: Bucket,
    sources: HashMap<Ipv4Addr, SourceEntry>,
    found_seen: HashMap<(PairId, SocketAddrV4), Duration>,
    found: VecDeque<LanFound>,
    stats: LanStats,
}

fn fill_random(buf: &mut [u8]) -> bool {
    getrandom::fill(buf).is_ok()
}

impl LanCore {
    pub fn new(cfg: CoreConfig) -> Self {
        Self {
            cfg,
            local: None,
            ever_local: false,
            peers: Vec::new(),
            wanted: Vec::new(),
            active: false,
            want_burst: false,
            ep: None,
            table: Table::default(),
            sched: Sched::default(),
            global: Bucket::full(GLOBAL_BURST, Duration::ZERO),
            sources: HashMap::new(),
            found_seen: HashMap::new(),
            found: VecDeque::new(),
            stats: LanStats::default(),
        }
    }

    fn local_ok(&self, ip: Ipv4Addr) -> bool {
        match classify(IpAddr::V4(ip)) {
            AddrClass::Private => true,
            AddrClass::Loopback => self.cfg.allow_loopback,
            _ => false,
        }
    }

    /// Recomputes `active`; a switch on asks for a burst, a switch off drops the schedule.
    fn refresh_active(&mut self) {
        let now_active = self.wants_sockets().is_some();
        if now_active && !self.active {
            self.want_burst = true;
        }
        if !now_active {
            self.ep = None;
            self.want_burst = false;
            self.sched.bursts.clear();
            self.sched.next_periodic = None;
        }
        self.active = now_active;
    }

    fn schedule_burst(&mut self, now: Duration) {
        self.sched.bursts = BURST_OFFSETS.iter().map(|o| now + *o).collect();
    }

    /// Our private IPv4 of the default route and the QUIC port. Port 0 counts as `None`.
    pub fn set_local(&mut self, local: Option<SocketAddrV4>, now: Duration) {
        let local = local.filter(|l| l.port() != 0);
        self.ever_local = true;
        if self.local == local {
            return;
        }
        self.local = local;
        // a new endpoint restarts the epoch state (spec D5, exception b)
        self.ep = None;
        self.refresh_active();
        if self.active {
            self.want_burst = false;
            self.schedule_burst(now);
        }
    }

    /// Replaces all peers. A removed pair is dropped from the announced set at once (its slot
    /// becomes a fresh filler) and its beacons stop matching.
    pub fn set_peers(&mut self, peers: Vec<LanPeer>) {
        self.peers = peers;
        self.table.dirty = true;
        let mut reset = false;
        if let Some(ep) = self.ep.as_mut() {
            for slot in &mut ep.slots {
                let gone = match slot {
                    SlotPlan::Real(p) => !self.peers.iter().any(|q| q.pair == *p),
                    SlotPlan::Filler(_) => false,
                };
                if gone {
                    let mut id = [0u8; LAN_ID_LEN];
                    if fill_random(&mut id) {
                        *slot = SlotPlan::Filler(id);
                    } else {
                        bump(&mut self.stats.rng_errors);
                        reset = true;
                    }
                }
            }
        }
        if reset {
            self.ep = None;
        }
        self.refresh_active();
    }

    /// Pairs without a live connection; read when the next epoch is frozen.
    pub fn set_wanted(&mut self, wanted: Vec<PairId>) {
        self.wanted = wanted;
    }

    /// Burst (start, user action). The rate cap applies when sending.
    pub fn trigger(&mut self, now: Duration) {
        if self.active {
            self.want_burst = false;
            self.schedule_burst(now);
        } else {
            self.want_burst = true;
        }
    }

    /// `Some(ip)` iff local is set, private (loopback only in tests) and peers is not empty.
    pub fn wants_sockets(&self) -> Option<Ipv4Addr> {
        let local = self.local?;
        if self.peers.is_empty() || !self.local_ok(*local.ip()) {
            return None;
        }
        Some(*local.ip())
    }

    pub(crate) fn readiness(&self) -> Readiness {
        if !self.ever_local {
            Readiness::NoLocal
        } else if !self.local.is_some_and(|l| self.local_ok(*l.ip())) {
            Readiness::NoLan
        } else if self.peers.is_empty() {
            Readiness::NoPeers
        } else {
            Readiness::Ready
        }
    }

    pub(crate) fn note_send_error(&mut self) {
        bump(&mut self.stats.send_errors);
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    pub(crate) fn source_map_len(&self) -> usize {
        self.sources.len()
    }

    #[cfg(test)]
    pub(crate) fn found_len(&self) -> usize {
        self.found.len()
    }

    pub fn stats(&self) -> LanStats {
        self.stats
    }

    /// Next beacon interval: 60 s with uniform jitter of plus and minus 10 s.
    fn interval(&mut self) -> Duration {
        let mut r = [0u8; 4];
        if !fill_random(&mut r) {
            bump(&mut self.stats.rng_errors);
            return BEACON_INTERVAL;
        }
        let span = BEACON_JITTER_MS.saturating_mul(2).saturating_add(1);
        let v = u32::from_le_bytes(r) % span;
        BEACON_INTERVAL.saturating_sub(Duration::from_millis(u64::from(BEACON_JITTER_MS)))
            + Duration::from_millis(u64::from(v))
    }

    /// Freezes the announced set for epoch `epoch` (spec D5).
    fn freeze(&mut self, epoch: u64) -> Option<EpochState> {
        let mut wanted: Vec<PairId> = self
            .wanted
            .iter()
            .copied()
            .filter(|p| self.peers.iter().any(|q| q.pair == *p))
            .collect();
        wanted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        wanted.dedup();
        let n = wanted.len();
        let mut slots: Vec<SlotPlan> = Vec::with_capacity(LAN_SLOTS);
        if n <= LAN_SLOTS {
            slots.extend(wanted.into_iter().map(SlotPlan::Real));
        } else {
            let start =
                usize::try_from((u128::from(epoch) * LAN_SLOTS as u128) % n as u128).unwrap_or(0);
            for i in 0..LAN_SLOTS {
                let idx = start.saturating_add(i) % n;
                if let Some(p) = wanted.get(idx) {
                    slots.push(SlotPlan::Real(*p));
                }
            }
        }
        while slots.len() < LAN_SLOTS {
            let mut id = [0u8; LAN_ID_LEN];
            if !fill_random(&mut id) {
                bump(&mut self.stats.rng_errors);
                return None;
            }
            slots.push(SlotPlan::Filler(id));
        }
        Some(EpochState { epoch, slots })
    }

    fn build_beacon(&mut self, unix: u64) -> Option<[u8; BEACON_LEN]> {
        let local = self.local?;
        let epoch = lan_epoch(unix);
        let mut ep = match self.ep.take() {
            Some(ep) if ep.epoch == epoch => ep,
            _ => self.freeze(epoch)?,
        };
        let out = self.assemble(&ep, epoch, local);
        // keep the frozen set even when this beacon failed (retry within the epoch)
        ep.epoch = epoch;
        self.ep = Some(ep);
        out
    }

    fn assemble(
        &mut self,
        ep: &EpochState,
        epoch: u64,
        local: SocketAddrV4,
    ) -> Option<[u8; BEACON_LEN]> {
        let mut nonce = [0u8; LAN_NONCE_LEN];
        if !fill_random(&mut nonce) {
            bump(&mut self.stats.rng_errors);
            return None;
        }
        let mut slots: Vec<[u8; LAN_SLOT_LEN]> = Vec::with_capacity(LAN_SLOTS);
        for plan in &ep.slots {
            let mut slot = [0u8; LAN_SLOT_LEN];
            match plan {
                SlotPlan::Real(pair) => {
                    let peer = self.peers.iter().find(|p| p.pair == *pair)?;
                    slot = peer
                        .keys
                        .seal_slot(epoch, &nonce, IpAddr::V4(*local.ip()), local.port())
                        .ok()?;
                }
                SlotPlan::Filler(id) => {
                    let (a, b) = slot.split_at_mut(LAN_ID_LEN);
                    a.copy_from_slice(id);
                    if !fill_random(b) {
                        bump(&mut self.stats.rng_errors);
                        return None;
                    }
                }
            }
            slots.push(slot);
        }
        slots.sort_by(|a, b| a.get(..LAN_ID_LEN).cmp(&b.get(..LAN_ID_LEN)));
        wire::build(&nonce, &slots)
    }

    /// Earliest time a beacon may be sent, or `None` when nothing is scheduled.
    fn next_due(&self, now: Duration) -> Option<Duration> {
        if !self.active {
            return None;
        }
        let mut due = if self.want_burst { Some(now) } else { None };
        for t in self
            .sched
            .bursts
            .iter()
            .copied()
            .chain(self.sched.next_periodic)
        {
            due = Some(due.map_or(t, |d| d.min(t)));
        }
        let due = due?;
        // the rolling cap pushes the earliest time out
        let recent: Vec<Duration> = self
            .sched
            .sent
            .iter()
            .copied()
            .filter(|t| now.saturating_sub(*t) < SEND_CAP_WINDOW)
            .collect();
        if recent.len() >= SEND_CAP
            && let Some(first) = recent.first()
        {
            return Some(due.max(*first + SEND_CAP_WINDOW));
        }
        Some(due)
    }

    /// At most one beacon per call, only when due and under the cap.
    pub fn poll_send(&mut self, now: Duration, unix: u64) -> Option<[u8; BEACON_LEN]> {
        if !self.active {
            return None;
        }
        if self.want_burst {
            self.want_burst = false;
            self.schedule_burst(now);
        }
        if self.sched.next_periodic.is_none() {
            let iv = self.interval();
            self.sched.next_periodic = Some(now + iv);
        }
        let burst_due = self.sched.bursts.iter().any(|t| *t <= now);
        let periodic_due = self.sched.next_periodic.is_some_and(|t| t <= now);
        if !burst_due && !periodic_due {
            return None;
        }
        self.sched
            .sent
            .retain(|t| now.saturating_sub(*t) < SEND_CAP_WINDOW);
        if self.sched.sent.len() >= SEND_CAP {
            return None;
        }
        let beacon = self.build_beacon(unix)?;
        self.sched.bursts.retain(|t| *t > now);
        if periodic_due {
            let iv = self.interval();
            self.sched.next_periodic = Some(now + iv);
        }
        self.sched.sent.push_back(now);
        bump(&mut self.stats.beacons_out);
        Some(beacon)
    }

    /// Time until the next useful call, at most `MAX_WAIT`.
    pub fn next_wakeup(&self, now: Duration) -> Duration {
        match self.next_due(now) {
            Some(due) => due.saturating_sub(now).min(MAX_WAIT),
            None => MAX_WAIT,
        }
    }

    /// False: the global budget is empty; the driver pauses reading.
    pub fn may_read(&self, now: Duration) -> bool {
        self.global.available(GLOBAL_BURST, GLOBAL_PERIOD, now) > 0
    }

    fn source_ok(&self, ip: Ipv4Addr) -> bool {
        match classify(IpAddr::V4(ip)) {
            AddrClass::Private => {
                self.cfg.allow_loopback || self.local.is_none_or(|l| *l.ip() != ip)
            }
            AddrClass::Loopback => self.cfg.allow_loopback,
            _ => false,
        }
    }

    fn charge_source(&mut self, ip: Ipv4Addr, now: Duration) -> bool {
        if !self.sources.contains_key(&ip) && self.sources.len() >= SOURCE_MAP_MAX {
            let oldest = self
                .sources
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.sources.remove(&k);
            }
        }
        let entry = self.sources.entry(ip).or_insert_with(|| SourceEntry {
            bucket: Bucket::full(SOURCE_BURST, now),
            used: now,
        });
        entry.used = now;
        entry.bucket.take(SOURCE_BURST, SOURCE_PERIOD, now)
    }

    fn ensure_table(&mut self, center: u64) {
        if !self.table.dirty && self.table.center == Some(center) {
            return;
        }
        self.table.map.clear();
        for (i, p) in self.peers.iter().enumerate() {
            for d in [-1i64, 0, 1] {
                if let Some(e) = center.checked_add_signed(d) {
                    self.table.map.insert(p.keys.recv_id(e), (i, e));
                }
            }
        }
        self.table.center = Some(center);
        self.table.dirty = false;
    }

    /// Untrusted datagram from `src`, any length. Order: global budget, length, version,
    /// source, per-source budget, table lookups, at most `MAX_OPENS` opens, found throttle.
    pub fn on_datagram(&mut self, src: SocketAddr, data: &[u8], now: Duration, unix: u64) {
        bump(&mut self.stats.dgrams_in);
        if !self.global.take(GLOBAL_BURST, GLOBAL_PERIOD, now) {
            bump(&mut self.stats.dropped_budget);
            return;
        }
        let parsed = match wire::parse(data) {
            Ok(p) => p,
            Err(ParseError::Len) => {
                bump(&mut self.stats.dropped_len);
                return;
            }
            Err(ParseError::Version) => {
                bump(&mut self.stats.dropped_ver);
                return;
            }
        };
        let ip = match src {
            SocketAddr::V4(a) if self.active && self.source_ok(*a.ip()) => *a.ip(),
            _ => {
                bump(&mut self.stats.dropped_src);
                return;
            }
        };
        if !self.charge_source(ip, now) {
            bump(&mut self.stats.dropped_source_rate);
            return;
        }
        self.ensure_table(lan_epoch(unix));
        let mut opens = 0u32;
        let mut hit: Option<(PairId, u16)> = None;
        for slot in parsed.slots.as_chunks::<LAN_SLOT_LEN>().0.iter() {
            bump(&mut self.stats.lookups);
            let Some(id) = slot
                .get(..LAN_ID_LEN)
                .and_then(|s| <[u8; LAN_ID_LEN]>::try_from(s).ok())
            else {
                continue;
            };
            let Some(&(idx, epoch)) = self.table.map.get(&id) else {
                continue;
            };
            if opens >= MAX_OPENS {
                break;
            }
            opens += 1;
            bump(&mut self.stats.aead_opens);
            let Some(peer) = self.peers.get(idx) else {
                continue;
            };
            if let Some(port) = peer
                .keys
                .open_slot(epoch, &parsed.nonce, IpAddr::V4(ip), slot)
            {
                hit = Some((peer.pair, port));
                break;
            }
        }
        let Some((pair, port)) = hit else {
            return;
        };
        let addr = SocketAddrV4::new(ip, port);
        if self
            .found_seen
            .get(&(pair, addr))
            .is_some_and(|t| now.saturating_sub(*t) < FOUND_REPEAT)
        {
            bump(&mut self.stats.found_throttled);
            return;
        }
        self.remember_found(pair, addr, now);
        bump(&mut self.stats.found);
        if self.found.len() >= LAN_FOUND_MAX {
            self.found.pop_front();
        }
        self.found.push_back(LanFound { pair, addr });
    }

    fn remember_found(&mut self, pair: PairId, addr: SocketAddrV4, now: Duration) {
        if self.found_seen.len() >= FOUND_MAP_MAX && !self.found_seen.contains_key(&(pair, addr)) {
            self.found_seen
                .retain(|_, t| now.saturating_sub(*t) < FOUND_REPEAT);
            if self.found_seen.len() >= FOUND_MAP_MAX {
                let oldest = self
                    .found_seen
                    .iter()
                    .min_by_key(|(_, t)| **t)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.found_seen.remove(&k);
                }
            }
        }
        self.found_seen.insert((pair, addr), now);
    }

    /// At most `LAN_FOUND_MAX` items, oldest first; the queue is emptied.
    pub fn take_found(&mut self) -> Vec<LanFound> {
        self.found.drain(..).collect()
    }
}
