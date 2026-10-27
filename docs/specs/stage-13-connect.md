# SPEC 13: Connection (without rendezvous)          criticality: CRITICAL (parts C1, C3, C4)

Author: combine-architect (opus), 2026-10-16, revision 1. Labels: [P] verified by me in the source (file:line); [V] architect's inference; [D] from memory, not re-checked; [NP] not verified. **Nothing was run.** No new crates: only path crates and crates already in `Cargo.lock`; one new feature on an existing dev-dependency (`tokio/test-util`, adds no packages, fact 12). New normal edges: `chervo-connect -> {chervo-addr, chervo-token, chervo-friends, tokio}`. `chervo-connect` never depends on quinn/rustls (U7).

Goal: the connection layer `chervo-connect` keeps every Active friend reachable while the app runs: it chooses candidate addresses and their order (U7), dials them with first-wins racing and at most one outgoing dial per pair (stage 9 N4), repeats dials periodically so that two NATed friends meet by simultaneous open (DECISION 3.2, no port guessing, U8), watches our own addresses and re-knocks and re-announces after a change (9b N3, stage 12), runs the invite flow end to end (stage 11 carried items), and, when nothing works, says why in plain words (BRIEF 5). Order of the owner (BRIEF 1): stationary IPv4 first (white IP, port forward), then the laptop changing networks. **Stage 13b (rendezvous) is deferred by the owner: this stage contains no rendezvous code and sends no packet to any rendezvous; only the diagnosis flag "a rendezvous could help" exists.**

Read: this file; `docs/specs/stage-12-addr.md` ("Interface", "Requirements for other stages"); `docs/specs/stage-11-invite.md` ("Requirements for other stages"); `crates/chervo-connect/*`; `crates/chervo-transport/src/lib.rs`; `crates/chervo-transport-quinn/src/{lib,client,registry,conn,knock}.rs`, `src/tests/{knock,peers}.rs`; `crates/chervo-token/src/{invite,flow,addr_flow}.rs`; `crates/chervo-addr/src/{own,book}.rs`; `crates/chervo-friends/src/book.rs`, `tests/{invite_net,addr_net}.rs`; `scripts/check-forbidden.sh`; root `Cargo.toml`. Search nothing else.

## Scope of this stage and what is deferred (with reason)
| Item of TASK 13 | Here | Reason |
|---|---|---|
| Path selection in the connection layer (U7), parallel attempts first-wins, N4 | yes | |
| IPv4: white IP, manual port forward, periodic simultaneous open to known addresses | yes | owner's first target |
| Diagnosis "no direct path" with cause and text; CGNAT text; rendezvous only as a flag | yes | 13b deferred by owner |
| Carried items of stages 9, 9b, 11, 12 | yes (table "Carried requirements") | |
| **UPnP IGD** (+ mapping close on end) | **no -> stage 13a** (open question Q1) | igd-next 0.18.0 crashes on a 547-byte XML bomb from any LAN host (SECURITY-REVIEW-STAGE08 item 1, High); igd-next and its XML stack are not in the local registry, so neither a patched fork nor process isolation can be verified now (CORE 3); the review-8 rule "gateway = default-route gateway" needs the OS route table, which std does not expose and `unsafe_code = "forbid"` (root `Cargo.toml:53-54` [P]) rules out FFI |
| **NAT-PMP / PCP** | no | deferred by owner (TASK stage 8 line: "NAT-PMP/PCP ... нужны для CGNAT, отложено владельцем"); same gateway-address problem |
| **LAN discovery (mDNS, U9)** | **no -> stage 13c** (Q2) | no mDNS crate in the registry to verify; a hand-written DNS parser is a new hostile-input surface; sharing UDP 5353 with OS responders needs SO_REUSEADDR/REUSEPORT (std cannot; socket2 0.6.5 is in the lock and has `set_reuse_address`, fact 13; REUSEPORT per OS [NP]); U9 announcement content still needs a design. Partial cover now: LAN addresses travel in-band over private paths and in invites by choice (stage 12 decision 10) |
| **IPv6 listening** | no -> small stage after 13a (Q2) | owner: IPv6 rare, must not block. A dual-stack socket changes knock address handling (V4 vs v4-mapped in `KnockSocket` send and the admit table) [NP]; quinn itself maps V4 to v4-mapped (fact 7). Stage 13 binds IPv4 only; IPv6 candidates are skipped and feed the `NoIpv6` diagnosis |

## Decisions (rationale)
1. **Who chooses the path (U7).** `chervo-connect` decides *which* addresses are tried, *in which order*, *how often*, and *which transport* (one today). The transport executes one ordered candidate list per `connect` call: it may race them, but authenticates at most one connection per call. TCP later = a second `ManagedTransport`; the engine's single-flight then spans transports (future spec) [V].
2. **N4 (two outgoing dials of one side to one pair can close both, `registry.rs:89` [P]).** Two layers: (a) the engine keeps at most one in-flight dial per pair (single-flight map); (b) defence in depth in quinn: a second concurrent `connect` for a pair already being dialed returns `TransportError::Busy` at once, no packet sent. Opposite-direction dials (simultaneous open) stay legal and are resolved by the existing registry rule (smaller caller X25519 wins, `registry.rs:51-105` [P]).
3. **First-wins inside one call (quinn).** Today addresses are tried one after another, each up to `auth_deadline` = 10 s (`client.rs:31-38`, `lib.rs:138` [P]): 8 dead addresses cost 80 s. New: start address *i* at `i * connect_stagger` (250 ms) with its own knock schedule; the first connection that finishes the QUIC handshake goes to KK; if KK fails, the next finished one; every other connection is refused before KK, so the peer's registry sees one authenticated connection per call [V]. One overall deadline `auth_deadline`.
4. **Silence is reported.** `TransportError::NoResponse` when no raced address sent back a single packet (`pin.heard()` false for all, `client.rs:102-110` [P] counts it today only). Needed for the UDP-blocked diagnosis.
5. **Dial limiter for every destination (review 12 M1).** Keyed by normalized `SocketAddr` with a per-IP cap across all pairs and ports. Background: first retry after 30 s (hint 60 s), doubling to 10 min (hint 30 min). Fast window (5 s period, 120 s) only on **local** triggers: start, own address change, user "connect now", accepting an invite. A friend's new update only resets that friend's backoff (no fast window), so a lying friend cannot keep us in fast mode. Bound per victim IP from us: `per_ip_dials` = 4 per 10 s during our own fast windows, otherwise ≤ 1 dial per 10-30 min per address; one dial = 3 knocks of 48 B + a few QUIC Initials [V]. Instead of the optional "drop AddressUpdate entries after N failures": the 10-minute cap; dropping would lose a legitimate friend who was offline for a day [V].
6. **Periodic simultaneous open (DECISION 3.2).** Scheduler tick 1 s; dials go only to friends without a live connection. In a fast window a pair is dialed back to back (attempt up to 10 s, then 5 s pause), as in the stage-8 periodic mode that passed all EIM rows (SPIKE_TRANSPORT 9.5 [P doc]). No port prediction, no extra ports: only addresses from the friend book or the invite token.
7. **Keep connections to online friends** (max 64 live, LRU-closed beyond): needed so that after our IP change friends learn the new address in-band (BRIEF 4); QUIC keep-alive 10 s also keeps NAT mappings (`lib.rs:152` [P]).
8. **Manual port forward** (white IP needs no config): user setting `manual_forward: Option<u16>` (external port; the listen port is a fixed user/app setting). In `chervo-addr` a new `NatView::ManualForward` makes us `stable_reachable` and publishes `newest observed IP : manual port` with flag `hint` (the IP still comes from a friend, N6; conservative).
9. **Issue address updates lazily.** `FriendBook::issue_addr_update` rewrites the whole friends file per call (`book.rs:706-745` [P]); on an address change only friends with a live connection (or the next connection) get a new token, and only when `publishable(ctx)` differs from the last one sent. The sender always includes its latest update in every ADDR_INFO; this covers "resend after RateLimited" (review 12 L4/L6) at the cost of one cheap `StaleSeq` check.
10. **QUIC migration (U25).** After our address change the same connection continues after `reknock` (connection migration inside quinn). Stage 13 treats this as transport continuity, not path selection; the engine still owns candidates. Owner may veto (then: drop and redial).
11. **No new wire formats.** Stage 13 uses ADDR_INFO, invite M1/M2/decision and knock unchanged. The only new untrusted inputs are a stream kind byte and transport events.
12. **No logging, no sockets in `chervo-connect`.** The engine opens no socket of its own (route probe is in `chervo-addr`); a source guard enforces this, which also proves "no packet to a rendezvous, STUN, DNS".

## Facts from the source
1. `chervo-connect` is a stub: `PathKind` 4 variants, `NoDirectPath` 6, `connect_direct` returns `NotImplemented` (`src/lib.rs:8-49`); deps identity+transport (`Cargo.toml:8-10`); test pins `PathKind` names by exhaustive match (`tests/connect.rs:15-22`) [P].
2. `Connection` has `remote_pair, remote_addr, open_bi, accept_bi, close`; no id, role or close future (`chervo-transport/src/lib.rs:75-86`) [P].
3. quinn `connect`: filter, known pair, addresses in sequence (`client.rs:17-39`); per attempt: pin, knock, `knock_lead`, `connect_with`, knocks at `resend`, `3*resend`, deadline `auth_deadline` (`client.rs:48-114`); success -> `promote`, `Lost` returns the live winner (`client.rs:115-124`) [P].
4. `set_peers -> Result<(), DuplicatePairError>`, closes removed triples (`lib.rs:377-394`); events: broadcast(64) of `TransportEvent {RemoteAddrChanged, ConnectionReplaced, ClockSkewSuspected, PeerRemoved}` (`lib.rs:166-184, 311`); `reknock` spawns a task per call, no coalescing (`lib.rs:399-401`, `client.rs:174-200`) [P].
5. `QuinnConfig::default`: `auth_deadline` 10 s, `per_ip_max` 5 per 10 s, `idle_timeout` 30 s, `keep_alive` 10 s, `knock_resend_after` 1 s, `knock_admit_attempts` 2 (`lib.rs:135-163`) [P].
6. `QuinnConn` is `Clone`, has `is_initiator()`; `stable_id` used by the registry (`conn.rs:83-101`, `registry.rs:146-154`) [P].
7. quinn 0.11.12 `connect_with`: IPv6 target on an IPv4 endpoint -> `InvalidRemoteAddress`; on an IPv6 endpoint V4 is mapped (`quinn-0.11.12/src/endpoint.rs:218-225`) [P].
8. `PendingInvite::begin_session` checks used, expiry, `MAX_INVITE_SESSIONS = 3` (`chervo-token/src/invite.rs:351-363`, `lib.rs:48`); `on_m1` has no time check (`invite.rs:367-408`); `inviter_exchange` reads M1 then calls `on_m1` (`flow.rs:41-50`) [P].
9. Invite addresses: 1..=8, port != 0, not unspecified/multicast/broadcast/v4-mapped; loopback and private allowed (`invite.rs:48-76`) [P].
10. `FriendBook`: `kx_peers` Active only (`book.rs:662-685`); `usable_addrs` empty for non-Active (`book.rs:881-888`); `apply_addr_update` cheap stale/rate checks before Ed25519 (`book.rs:828-850`); `MIN_INBAND_UPDATE_INTERVAL_SECS = 10` (`book.rs:61`); `chervo_addr::usable` returns bare `SocketAddr` without flags (`chervo-addr/src/book.rs:160-171`) [P].
11. `OwnAddrs::nat_view` order and `stable_reachable = Public|PortMapped` (`chervo-addr/src/own.rs:290-351`); `publishable` steps 1-5 (`own.rs:364-430`) [P].
12. tokio 1.53.3: `test-util = ["rt", "sync", "time"]`, no optional deps (`tokio-1.53.3/Cargo.toml:133-137`) [P].
13. socket2 0.6.5 is in the registry: `set_only_v6` (`src/socket.rs:2080`), `set_reuse_address` (`:1125`), `join_multicast_v4` (`:1312`) [P] (for 13c and IPv6 later; not used here).
14. The local registry `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f` has no `igd-next`, `xmltree`, `xml-rs`, `attohttpc`, or any mDNS crate [P: directory listing].
15. Layout test forbids `quinn`, `tokio`, `rustls`, `iroh` only in `chervo-core`'s own manifest (`chervo-core/tests/layout.rs:34-40`) [P].

## Do (three builder calls; verify each step before the next, CORE 5)

### Call 1: builder sonnet/high. Parts C1, C2
1. `cargo --version`, `rustc --version` (1.99.1); `BASE=$(git rev-parse HEAD)`.
2. `grep -rn "fn on_m1\|fn inviter_exchange\|TransportEvent\|DuplicatePairError" crates --include=*.rs` -> only files named in facts 3-8 and their tests. Otherwise STOP.
3. **C1 transport**: `chervo-transport` trait additions; quinn: impls, race, single-flight, `NoResponse`, reknock coalescing, type moves (re-export old paths). Tests C1.
4. **C2**: `chervo-token` `on_m1`/`inviter_exchange` with time; `chervo-addr` manual forward + `usable_entries`; `chervo-friends` `usable_known`. Tests C2.
5. Criteria for changed crates; report.

### Call 2: builder sonnet/high. Part C3 (engine core)
6. `chervo-connect`: modules `config, clock, allow, limiter, plan, watch, engine, dispatch, addrinfo, diag, texts`. Fake transport and paused-time tests C3; source guard.

### Call 3: builder sonnet/high. Parts C4, C5
7. C4 `invite` module + loopback integration tests with quinn (dev-dependency) + `examples/node13.rs`.
8. C5 `tools/netns/stage13.sh` (Linux + root; **cannot run on this Windows host**: write, `bash -n`, shellcheck if present; run later on the owner's Ubuntu mini-PC). All criteria; report.

## Interface (exact)
All `Debug` on types holding addresses, keys, names, SAS print `"TypeName(..)"`. No `Display` printing input. No panics (lint block of `chervo-identity/src/lib.rs:6-13` in `chervo-connect`), no logging, no printing. Time: `Clock::now_unix()` (UTC seconds incl. user clock offset) and `tokio::time::Instant` for intervals.

### C1. chervo-transport and chervo-transport-quinn
```rust
// chervo-transport (TransportError stays #[non_exhaustive])
pub enum TransportError { /* existing */, Busy, NoResponse }   // Display: "dial already in progress", "no response"
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct DuplicatePairError;          // moved from quinn
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum TransportEvent { RemoteAddrChanged { pair: PairId }, ConnectionReplaced { pair: PairId },
                          ClockSkewSuspected { pair: PairId }, PeerRemoved { pair: PairId }, Lagged }  // moved; Lagged new
pub trait Connection: Send + Sync {
    /* existing five */
    /// Unique among connections of one transport instance; equal for clones of one connection.
    fn conn_id(&self) -> u64;
    fn is_initiator(&self) -> bool;
    /// Resolves once the connection is closed for any reason.
    fn closed(&self) -> impl Future<Output = ()> + Send;
}
pub trait Transport { /* unchanged signature; doc of `connect`: "addrs in priority order; the
    implementation may race them; at most one authentication per call; first authenticated wins" */ }
pub trait EventSource: Send + 'static {
    /// `None`: transport gone. Lost events are reported as `Some(TransportEvent::Lagged)`.
    fn recv(&mut self) -> impl Future<Output = Option<TransportEvent>> + Send;
}
pub trait ManagedTransport: Transport + 'static {
    type Events: EventSource;
    fn set_peers(&self, peers: Vec<KxPeer>) -> Result<(), DuplicatePairError>;
    /// Coalesced: while a re-knock sequence runs, further calls only mark "again" (one rerun).
    fn reknock(&self);
    fn subscribe(&self) -> Self::Events;
}
```
`NullConnection`/`NullTransport` updated (uninhabited / `NotImplemented`).

quinn:
- `pub use chervo_transport::{DuplicatePairError, TransportEvent};` (old paths keep compiling). `impl ManagedTransport for QuinnTransport` (`Events = QuinnEvents(broadcast::Receiver)`: `Lagged(_)` -> `Some(Lagged)`, `Closed` -> `None`). Inherent `set_peers`, `reknock`, `events` stay.
- `QuinnConn`: `conn_id = conn.stable_id() as u64`; `is_initiator`; `closed` = `conn.closed().await` discarded.
- `QuinnConfig` += `connect_stagger: Duration` (250 ms), `max_race: usize` (8). `TransportStats` += `reknock_runs: u64`, `race_losers: u64`.
- `client::connect` (critical): checks as now; `Inner.dialing: Mutex<HashSet<PairId>>` with RAII guard: pair present -> `Busy` before any packet. Candidates: `normalize` (v4-mapped -> V4), drop family mismatching the endpoint (fact 7), dedupe, keep first `max_race`; empty -> `Io`. One deadline `t0 + auth_deadline`. A `tokio::task::JoinSet`: task *i* sleeps `i * connect_stagger`, then exactly today's per-address path up to an established `quinn::Connection` (pin held for the task's life, knock, `knock_lead`, `connect_with`, knocks at `resend`/`3*resend` from that task's start). Main loop: `join_next` until deadline; on an established connection run `caller_handshake` (remaining deadline); success -> `abort_all`, `refuse` every connection still returned by the set, count them in `race_losers`, `promote` (unchanged); KK failure -> `refuse`, continue. End without success: `NoResponse` if no task's pin heard a packet, else `TimedOut` (deadline) or the last mapped error. Counters as today.
- `reknock_live` coalescing: `Inner.reknock: Mutex<(bool /*running*/, bool /*again*/)>`; running -> set again, return; else spawn on `inner.rt` the existing three-knock sequence; at its end, if again: clear, recompute `live_remotes()`, run once more; `reknock_runs += 1` per sequence.

### C2. chervo-token, chervo-addr, chervo-friends
```rust
// chervo-token invite.rs: order NoSession -> Used -> (now_unix >= expires_at) Expired -> existing checks
pub fn on_m1(&mut self, m1: &[u8], now_unix: u64) -> Result<([u8; M2_LEN], Sas, InviteeKeys), InviteError>;
// flow.rs: `now` is called after M1 was read, right before on_m1
pub async fn inviter_exchange<C: Connection, F: Fn() -> u64 + Send>(conn: &C, pending: &mut PendingInvite, now: F)
    -> Result<(InviteChannel<C>, Sas, InviteeKeys), FlowError>;
// chervo-addr own.rs
pub enum NatView { /* existing */, ManualForward }     // appended (#[non_exhaustive])
impl OwnAddrs { pub fn set_manual_forward(&mut self, port: Option<u16>); } // Some(0) == None; NOT cleared by set_local
// chervo-addr book.rs: same filter and order as `usable`, with flags
pub fn usable_entries(addrs: &[KnownAddr], now_unix: u64) -> Vec<KnownAddr>;
// chervo-friends
impl FriendBook { pub fn usable_known(&self, pair: &PairId, now_unix: u64) -> Vec<KnownAddr>; } // non-Active/unknown: empty
```
`nat_view` change (only insertion): after the `Conflicting` check and the `wan_global` `DoubleNat` check, before `Symmetric`: `manual.is_some() && !live.is_empty()` -> `ManualForward`. `stable_reachable` = `Public | PortMapped | ManualForward`. `observed_v4` unchanged (None for ManualForward). `publishable` new step (2b) after (2): `nat_view == ManualForward` -> push `(newest live observation IP, manual port)`, `short_lived false`, `hint true`.

### C3. chervo-connect (engine core)
Cargo: normal deps `chervo-identity, chervo-addr, chervo-transport, chervo-token, chervo-friends, tokio` (workspace features); dev-deps `chervo-transport-quinn`, `tokio` with `test-util`.
```rust
pub struct ConnectConfig {
    pub manual_forward: Option<u16>,        // None
    pub probe_interval: Duration,           // 2 s
    pub tick: Duration,                     // 1 s
    pub fast_window: Duration,              // 120 s
    pub fast_period: Duration,              // 5 s
    pub dial_base: Duration, pub dial_cap: Duration,   // 30 s, 600 s
    pub hint_base: Duration, pub hint_cap: Duration,   // 60 s, 1800 s
    pub per_ip_dials: u32, pub per_ip_window: Duration, // 4, 10 s
    pub max_concurrent_dials: usize,        // 16
    pub max_live: usize,                    // 64
    pub limiter_capacity: usize,            // 4096 entries, evict the entry with the oldest last use
    pub addr_info_timeout: Duration,        // 5 s
    pub addr_info_in_per_min: u32,          // 4 incoming ADDR_INFO streams per connection per 60 s
    pub addr_info_out_interval: Duration,   // 10 s per friend
    pub invite_session: Duration,           // 300 s
    pub expire_interval: Duration,          // 60 s
    pub unreachable_after_fails: u32,       // 3
    pub udp_blocked_window: Duration, pub udp_blocked_min_friends: usize, // 600 s, 2
}  // impl Default with the values above
pub trait Clock: Send + Sync { fn now_unix(&self) -> u64; }
pub struct SystemClock { /* offset_ms: AtomicI64 */ }
impl SystemClock { pub fn new() -> Self; pub fn set_offset_ms(&self, ms: i64) -> Result<(), ClockRangeError>; } // |ms| <= 7 days
pub trait RouteProbe: Send + Sync { fn probe(&self) -> RouteSources; }
pub struct SystemProbe;   // probe() = chervo_addr::probe_route_sources()
pub struct AllowSet { /* RwLock<HashSet<PairId>> */ }   // impl PeerFilter; pub fn new() -> Arc<Self>; mutation pub(crate)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind { Lan, Ipv6, PortMapped, SimultaneousOpen }  // approximate, see "Path kind"
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum NoDirectPath { NoKnownAddress, NeedToken, BehindCgnat, SymmetricNat, UdpBlockedSuspected, NoIpv6, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnosis { pub reason: NoDirectPath, pub rendezvous_could_help: bool } // true only for BehindCgnat, NeedToken
pub fn user_text(reason: NoDirectPath) -> &'static str;
pub fn revocation_error_text(e: FriendsError) -> &'static str;  // Io -> REVOCATION_NOT_SENT_TEXT, else generic text
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum ConnectError { Friends(FriendsError), Token(TokenError), Invite(InviteError), NoAddresses, UnknownPair,
                        NotActive, InviteSessionsExhausted, Internal, Shutdown }
#[derive(Clone, Copy, PartialEq, Eq)] #[non_exhaustive]   // Debug redacted (Sas)
pub enum EngineEvent { Connected { pair: PairId, path: PathKind }, Disconnected { pair: PairId },
    SasReady { pair: PairId, sas: Sas }, InviteFinished { pair: PairId, outcome: InviteOutcome },
    KeyProblem { pair: PairId, status: KeyStatus }, OwnAddrsChanged, ClockSkew { pair: PairId },
    Unreachable { pair: PairId, diagnosis: Diagnosis }, Internal }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteOutcome { Added, Declined, PeerUnreachable, Expired, Failed }
pub struct EngineEvents { /* broadcast::Receiver<EngineEvent>, capacity 256 */ }
impl EngineEvents { pub async fn recv(&mut self) -> Option<EngineEvent>; } // lag is skipped silently
pub enum InviteAddrs { Auto { same_network: bool }, Manual(Vec<SocketAddr>) } // Manual: user-typed (forward/white IP); also tests

pub struct Engine<T: ManagedTransport, S: SecretStore + ListKeyStore + 'static>  // T::Conn: Clone + 'static
impl<T, S> Engine<T, S> {
    /// Inside a tokio runtime. Order: drop_all_pending; set_manual_forward; publish; spawn
    /// watcher, accept loop, scheduler, event loop, expire timer. Fast window starts.
    pub fn start(transport: Arc<T>, allow: Arc<AllowSet>, book: FriendBook, store: Arc<S>,
                 clock: Arc<dyn Clock>, probe: Arc<dyn RouteProbe>, cfg: ConnectConfig)
                 -> Result<(Self, EngineEvents), ConnectError>;
    /// The only way to change the book: runs `f`, then publish (AllowSet + set_peers),
    /// forget_reporter for pairs no longer Active, drop their live connections' state.
    pub fn update_book<R>(&self, f: impl FnOnce(&mut FriendBook, &S) -> Result<R, FriendsError>) -> Result<R, ConnectError>;
    pub fn read_book<R>(&self, f: impl FnOnce(&FriendBook) -> R) -> R;
    pub fn connect_now(&self, pair: &PairId) -> Result<(), ConnectError>;   // Active only; fast window for that pair
    pub fn connection(&self, pair: &PairId) -> Option<T::Conn>;
    pub fn diagnose(&self, pair: &PairId) -> Result<Option<Diagnosis>, ConnectError>; // None: connected or undecided
    pub fn nat_view(&self) -> NatView;
    pub fn shutdown(&self);
    // C4:
    pub fn create_invite(&self, ttl_secs: u64, addrs: InviteAddrs) -> Result<(PairId, String), ConnectError>;
    pub fn accept_invite(&self, text: &str) -> Result<PairId, ConnectError>;
    pub fn confirm_sas(&self, pair: &PairId, confirm: bool, name: &str) -> Result<(), ConnectError>;
    pub fn cancel_invite(&self, pair: &PairId) -> Result<(), ConnectError>;
}
```
Old `connect_direct` is removed; `tests/connect.rs` is rewritten for the new enums.

**State** (one `std::sync::Mutex<State>`, never held across `.await`; clippy `await_holding_lock` is denied by `-D warnings`): book, own (`OwnAddrs`), limiter, live map `PairId -> (conn, conn_id, since)`, in-flight set, invites, per-friend `last_sent: Option<(PublishSet, IssuedAddrUpdate)>`, `last_sent_at`, `deferred_update: Option<SignedAddrUpdate>` (one slot per pair), per-pair dial history for diagnosis.

**Publish** (after start, every `update_book`, invite start/finish/expiry): `(peers, bad) = book.kx_peers(store)`; append guest `KxPeer`s of live invites whose pair is not a friend; new allow set = their pairs. Save old allow set, `allow.replace(new)`, `transport.set_peers(peers)`; `Err(DuplicatePairError)` -> restore old allow set, emit `Internal`, return `ConnectError::Internal` (transport keeps its old set, `lib.rs:374-381` [P]). `bad` -> one `KeyProblem` per pair (never creates keys).

**Candidates (path selection).** For an Active friend: `book.usable_known(pair, now)`; drop entries whose family differs from `transport.local_addrs()` (IPv4-only now; remember "had IPv6 only" for `NoIpv6`); stable sort: LAN (`Private`, `Loopback`) first, then the book order (update non-hint, invite, contact, hint); keep those the limiter allows now; cap 8. For an invitee guest pair: token addresses only, same limiter. Never anything else (U6 v6; guard test).

**Limiter** (`limiter.rs`, critical, see decision 5): `allow(addr, hint, now) -> bool` = entry's `next <= now` and per-IP count in the last `per_ip_window` < `per_ip_dials`; `charge(addrs, now)`; `failed(addrs, hint, fast, now)`: `fails += 1`, `next = now + (fast ? fast_period : min(base << (fails-1), cap))` with base/cap by `hint`; `succeeded(addr)`: entry removed; `reset_pair(addrs)`: `fails = 0, next = now` (on a newer seq from that friend); `reset_all()` (own address change). Saturating arithmetic only.

**Scheduler** (every `tick`): for each Active friend without a live connection and not in flight, while in-flight < `max_concurrent_dials`: candidates; none -> skip; else charge, insert in-flight, spawn `transport.connect(PeerAddr{pair, addrs})`. Result: Ok -> `on_connection` (below); `Busy` -> treated as a bug (`Internal`, never expected); other error -> `limiter.failed`, record `(now, NoResponse?)` per pair; after `unreachable_after_fails` consecutive failures, or when the pair's fast window ends without success, compute `diagnose` and emit `Unreachable` once per change of reason.

**Watcher** (every `probe_interval`): `LocalSnapshot { route: probe.probe(), listen: transport.local_addrs() }` (the only construction in the crate); `own.set_local(snap)`; first call only stores; on later `true`: `transport.reknock()`, `limiter.reset_all()`, global fast window, schedule ADDR_INFO re-send to every live friend (respecting `addr_info_out_interval`), emit `OwnAddrsChanged`. `set_gateway` is never called in this stage.

**Connections** (`on_connection`, both from `connect` and `accept`): pair is a live guest -> C4; pair not Active -> `close()`; same `conn_id` as the live entry -> ignore (Lost path / accept duplicate); otherwise replace the entry, emit `Connected{path}`, `book.note_contact(pair, remote_addr)` (errors ignored), spawn: the `closed()` watcher (remove entry if same `conn_id`, emit `Disconnected`), the stream accept loop, and, if `is_initiator()`, `send_addr_info`. Events: `RemoteAddrChanged` -> `note_contact`; `ConnectionReplaced`/`PeerRemoved` -> handled by `closed()`; `ClockSkewSuspected` -> `ClockSkew`; `Lagged` -> resync live map from `closed()` futures (nothing else). Over `max_live`: close the connection with the oldest `since` that has no open streams of other kinds.

**Stream dispatch** (per friend connection): `accept_bi`; read exactly 1 byte with `addr_info_timeout`; `STREAM_ADDR_INFO` -> if more than `addr_info_in_per_min` in the last 60 s drop both halves, else `answer_addr_info(conn, pair, tx, rx, ours)`; any other kind -> drop both halves (stage 14 adds kinds). Never on guest pairs.

**ADDR_INFO lifecycle** (`addrinfo.rs`, critical): `ours(pair)`: `set = own.publishable(PublishCtx::for_connection(conn.remote_addr()), now)`; empty -> `None`; equal to `last_sent.0` -> cached token; else `book.issue_addr_update(store, pair, &set, now)` (persists seq first) and cache. Sending (`send_addr_info`): `timeout(addr_info_timeout, exchange_addr_info(conn, pair, ours))`; at most once per `addr_info_out_interval` per friend (a skipped re-send is retried by the next tick). With a `PeerAddrInfo`: if `book.is_active(pair)`: `own.observe(pair, info.via, info.observed_me, now)`; update present -> `book.apply_addr_update`: `Ok` -> `limiter.reset_pair(friend addrs)`; `StaleSeq` -> ignore; `RateLimited` -> store in `deferred_update`, retried by the tick after `MIN_INBAND_UPDATE_INTERVAL_SECS`; other errors ignored. Errors and timeouts drop the stream, never the connection.

**Path kind** (informative, for stage 16 tables): `r = normalize(remote_addr)`; class Private/Loopback/LinkLocal -> `Lan`; IPv6 -> `Ipv6`; IPv4 Global: (initiator and the matching book entry is non-hint) or (not initiator and `own.stable_reachable`) -> `PortMapped` (one side reachable: white IP or forward); else `SimultaneousOpen`.

**Diagnosis** (`diag.rs`, first match): no candidates ever (book empty for pair) -> `findability == NeedToken` ? `NeedToken` : `NoKnownAddress`; only IPv6 entries -> `NoIpv6`; `nat_view == BehindCgnat` -> `BehindCgnat`; `Symmetric` -> `SymmetricNat`; global UDP heuristic: no live connection, and in the last `udp_blocked_window` at least `udp_blocked_min_friends` distinct Active friends with a non-hint Global IPv4 entry had only `NoResponse` failures and none succeeded -> `UdpBlockedSuspected`; `findability == NeedToken` -> `NeedToken`; else `Unknown`. CGNAT is recognised only when our own interface address is in 100.64/10 (behind a home router it needs the UPnP WAN IP of 13a).

**Texts** (`texts.rs`; Russian; no placeholders for addresses):
- `CGNAT_TEXT = "Вы за CGNAT: к вам не достучаться напрямую. Соединение возможно, если у друга белый IP или проброс порта (звоните вы). Сервер-посредник для поиска появится в следующей версии; без вашего согласия программа к нему не обращается."`
- `SYMMETRIC_TEXT = "У вас симметричный NAT: друзья не могут позвонить вам по известному адресу. Соединение возможно, если у друга белый IP или проброс порта (звоните вы)."`
- `UDP_BLOCKED_TEXT = "Ни один друг с постоянным адресом не ответил. Возможно, ваша сеть или провайдер блокирует UDP: тогда прямое соединение невозможно. Или друзья сейчас выключены."`
- `NO_IPV6_TEXT = "Для друга известны только адреса IPv6, а эта версия программы соединяется только по IPv4."`
- `NO_KNOWN_ADDRESS_TEXT = "Адрес друга неизвестен. Попросите у друга токен обновления адреса."`
- `UNKNOWN_TEXT = "Друг не отвечает: возможно, он выключен или сменил адрес. Если не выйдет, попросите токен обновления адреса."`
- `NeedToken` -> `chervo_addr::NEED_TOKEN_TEXT`; `REVOCATION_NOT_SENT_TEXT = "Отзыв не отправлен, повторите."`; `PEER_UNREACHABLE_INVITE_TEXT = "Друг недоступен. Добавьте друга заново."`

### C4. Invite orchestration (`invite.rs`, critical)
- **A, `create_invite(ttl, addrs)`**: addresses = `Auto{same_network}` -> `own.publishable(PublishCtx{include_lan: same_network}, now).socket_addrs()`, empty -> `NoAddresses` (UI: `NO_PUBLIC_ADDR_TEXT`); `Manual(v)` -> as given (validated by the token). `book.begin_pair(Inviter, now + ttl)` via `update_book`; `issue_invite`; keep `PendingInvite` in memory; publish (guest added).
- **B, `accept_invite(text)`**: `decode` -> `Token::Invite`, `check_time(now)`, `begin_pair(Invitee, expires_at + CLOCK_TOLERANCE_SECS)`, `InviteeSession::start`, keep `(session, m1, token addrs, inviter keys, sessions_used = 0, m1_sent = false)`; publish; fast window for this pair; the scheduler dials the guest pair with token addresses.
- **Guest connection (either direction)**: session counter on our side: B `sessions_used < MAX_INVITE_SESSIONS` else close and `InviteFinished{Failed}`; B with `m1_sent` -> close (no automatic retry after M1, review 11 item 3); A `pending.begin_session(now)` (its own ≤ 3 and expiry). Session deadline = `min(now + invite_session, expires_at)` (A) / `min(now + invite_session, token expires_at)` (B). A: `inviter_exchange(conn, pending, || clock.now_unix())`; B: set `m1_sent = true` immediately before writing M1, then `invitee_exchange`. SAS -> `SasReady`; wait for `confirm_sas` or the deadline; `exchange_decision`. Both confirmed -> `update_book(finish_pair(NewFriend{name, keys, addrs}))` where A's `addrs` = one `Contact` entry from the guest connection's `remote_addr` (`chervo_addr::note_contact` on an empty vec), B's = `chervo_addr::from_invite(token addrs, now)`; the invite entry is removed from memory **before** that `update_book`, so its publish adds the friend and drops the guest in the **same `set_peers` call** (review 11 High) -> `InviteFinished{Added}`, fast window for the new friend. Declined -> `abort_pair`, `Declined`. Deadline or error after M1 -> `abort_pair`, `PeerUnreachable` (owner decision stage 11 q.4).
- `expire` every `expire_interval` and on start `drop_all_pending` (in-memory invites lost on restart); expiry -> `Expired`, publish.
- `cancel_invite` -> `abort_pair`, publish.

### C5. netns stand (`tools/netns/stage13.sh`, Linux + root only)
Reuse helpers of `stage9.sh`. Node: `cargo run --example node13 -p chervo-connect` (in-memory test key store inside the example only; args: `--port`, `--forward`, `--book-dir`, `--invite-out FILE`, `--invite-in FILE`, `--sas-auto-confirm`, `--expect-connected PAIRS --deadline S`). Rows (expected): white-white OK; forward(FC)-PR OK `PortMapped`; PR-PR after both learned addresses through a common white-IP friend OK `SimultaneousOpen`; SYM-PR NO + `SymmetricNat` on SYM (two white friends report different ports) ; host in 100.64/10 -> `BehindCgnat` and no packet to any non-friend address; UDP dropped by nft on A -> `UdpBlockedSuspected`; A's address changed mid-connection (`ip addr del/add`) -> connection survives or redials within 15 s, friends get a new ADDR_INFO; capture on A: destinations ⊆ friend/token addresses, 0 DNS packets, 0 packets to 192.0.2.1 and 2001:db8::1.

## Do not
- No UPnP/IGD, NAT-PMP, PCP, mDNS, multicast, DNS lookup, STUN, rendezvous traffic; no new crate; no `unsafe`; no IPv6 socket.
- No socket in `chervo-connect` (`UdpSocket`, `TcpStream`, `TcpListener`, `send_to`, `lookup_host`, `to_socket_addrs`).
- No address from one friend sent to another; no address dialed that is not from `usable_known` or an invite token.
- Do not change KK, knock format, ADDR_INFO, invite messages, `SecretStore`, friends file format.
- No logging of addresses, tokens, SAS, names, keys.

## Untrusted input
- Stream kind byte: exactly one byte under `addr_info_timeout`; unknown kind -> drop.
- ADDR_INFO, invite M1/M2/decision: existing parsers (stages 11-12).
- Addresses from friends: only as dial targets through the limiter; never published.
- Transport events: only `PairId` + kind; `Lagged` tolerated.

## Carried requirements (where each is met)
| Source | Requirement | Where |
|---|---|---|
| 9 N4 | parallel outgoing of one side to one pair | dec. 2, C1 `Busy`, C3 single-flight; tests `parallel_connect_same_pair_busy`, `single_flight_per_pair` |
| 9 arch N2 / 8 N5 | one connection per pair, Lost duplicates | C3 dedupe by `conn_id`; `dedupe_by_conn_id`, `simultaneous_dial_keeps_one` |
| 9b N3 | watch own addresses, re-knock | C3 watcher; `watch_change_reknocks_once_and_fast_window` |
| 8 High 1, M2, M3 | igd-next only isolated/patched; gateway checks; mapping lifecycle | **deferred to 13a** with UPnP; acceptance: no `igd` in `cargo tree` |
| 8 M4 | gateway text in logs | no logging in this stage |
| 11 | ≤ 3 B sessions per token, no auto retry after M1 | C4; `invitee_max_three_sessions`, `invitee_no_auto_retry_after_m1` |
| 11 | expiry checked right before `on_m1`, session ≤ token life | C2 `on_m1(now)`, closure in `inviter_exchange`; C4 deadline; tests below |
| 11 | guest removed in the same `set_peers` that adds the friend; handle `DuplicatePairError` | C4 order, C3 publish; `publish_guest_removed_with_friend_added_same_call`, `publish_duplicate_error_keeps_old_allowset` |
| 11 | UI text for `Io` on revocation | `revocation_error_text` |
| 11 | dispatcher guest vs friend; `drop_all_pending` at start; `expire` each minute; publish after each change | C3/C4 |
| 12 M1 | per-destination rate limit for all sources/flags | limiter; `limiter_*` tests |
| 12 M2 | dial only Active | candidates; `candidates_only_active` |
| 12 L5 | `LocalSnapshot` only from probe/`local_addrs` + grep guard | watcher; `src_guard` |
| 12 L6 | coalesce re-knocks | C1; `reknock_coalesced` |
| 12 L4 | resend after `RateLimited` | dec. 9, `deferred_update`; `addrinfo_ratelimited_retried_later`, `addrinfo_sender_includes_latest_update` |
| 12 spec | ADDR_INFO 5 s, ≤ 4/min, never guests, observe only Active, note_contact, re-send ≤ 1/10 s, invite addrs from publishable, IPv6 only if listening | C3/C4 |

## Tests (exact names)
C1 (`chervo-transport-quinn/src/tests/race.rs`, `tests/` where no internals are needed; loopback, knock on): `race_first_live_wins_over_dead` (order [dead, dead, live]; connected < 3 s), `race_one_kk_per_call` (peer stats: `auth_ok` +1, `duplicates_closed` 0 after a call with [live, dead, live-dup]), `race_two_live_addresses_one_auth` (`#[cfg(not(target_os = "macos"))]`, peer on 0.0.0.0, dial 127.0.0.1 and 127.0.0.2; if 127.0.0.2 is unusable on Windows mark linux-only and report), `race_deadline_total_not_per_address` (8 dead addresses -> error within `auth_deadline + 1 s`), `connect_all_dead_is_no_response`, `connect_dedup_normalize_and_cap` (v4-mapped + duplicates + 12 addresses -> at most 8 distinct attempted; count via peer-side test hooks or a recording socket), `connect_v6_on_v4_endpoint_skipped`, `parallel_connect_same_pair_busy` (second call returns `Busy` immediately; first succeeds), `busy_guard_released_on_cancel` (drop first future, next call proceeds), `simultaneous_dial_keeps_one` (20 rounds both sides connect at once: each side one live connection, round trip works), `reknock_coalesced` (10 calls within 100 ms -> `reknock_runs` ≤ 2), `events_lagged_reported` (overflow broadcast -> `Lagged`), `conn_trait_methods` (`conn_id` equal across clones, `is_initiator` per side, `closed()` resolves after `close`).
C2 (`chervo-token/tests/flow.rs`, `chervo-addr/tests/own.rs`, `chervo-friends/tests/book.rs`): `on_m1_after_expiry_rejected` (session opened before expiry, M1 at `now = expires_at` -> `Expired`, `used` stays false, a later valid call still `Expired`), `on_m1_order_no_session_used_expired`, `inviter_exchange_reads_clock_after_m1` (MemConn delays M1; closure value set past expiry after the read starts -> `Expired`), `manual_forward_view_and_publish`, `manual_forward_needs_observation`, `manual_forward_not_over_conflict_or_double_nat`, `manual_forward_zero_is_none`, `manual_forward_survives_set_local`, `stable_reachable_includes_manual`, `usable_entries_matches_usable`, `usable_known_empty_for_blocked`.
C3 (`chervo-connect/src/tests/*.rs` with a scripted fake `ManagedTransport` recording every `connect` call, `set_peers` call and `reknock`; `#[tokio::test(start_paused = true)]`): limiter: `limiter_backoff_and_cap`, `limiter_hint_slower`, `limiter_per_ip_cap_across_pairs_and_ports` (victim IP listed by 3 friends × 8 ports -> ≤ `per_ip_dials` per window), `limiter_new_seq_resets_pair_only`, `limiter_fast_window_only_local_triggers` (an applied in-band update does not shorten intervals of other pairs nor open a fast window), `limiter_capacity_evicts`, `limiter_saturating`; candidates: `candidates_lan_first_then_book_order`, `candidates_skip_ipv6_on_v4_transport`, `candidates_only_active`, `candidates_guest_only_token_addrs`; engine: `single_flight_per_pair` (slow fake connect; never two in flight, never `Busy`), `no_dial_when_live`, `max_concurrent_dials_respected`, `dial_targets_only_from_book_or_token` (all recorded addresses ⊆ book/token addresses; never our own observed address, never another friend's address), `dedupe_by_conn_id`, `replaced_conn_switches_entry`, `peer_removed_drops_conn`, `max_live_closes_oldest`; watcher: `watch_first_snapshot_no_reknock`, `watch_change_reknocks_once_and_fast_window`, `watch_no_change_no_reknock`, `watch_change_resends_addr_info_rate_limited`; addrinfo: `addrinfo_initiator_opens_acceptor_answers`, `addrinfo_timeout_keeps_connection`, `addrinfo_incoming_cap_per_min`, `addrinfo_never_on_guest`, `addrinfo_observe_only_active`, `addrinfo_stale_ignored`, `addrinfo_ratelimited_retried_later`, `addrinfo_sender_includes_latest_update`, `addrinfo_issue_only_on_change` (seq unchanged when the set is unchanged), `addrinfo_issue_lazy_only_live` (10 friends, 1 live, own change -> 1 issue), `unknown_stream_kind_dropped`, `kind_byte_timeout`; publish: `publish_after_every_book_change`, `publish_duplicate_error_keeps_old_allowset`, `forget_reporter_on_block_and_remove`, `key_problem_reported_key_not_created`; diagnosis: `diag_no_known_address`, `diag_need_token`, `diag_cgnat_from_route` (+ `rendezvous_could_help`, and the fake recorded no destination outside friend addresses), `diag_symmetric`, `diag_udp_blocked_suspected`, `diag_not_udp_blocked_when_one_answers`, `diag_no_ipv6`, `unreachable_emitted_once_per_reason`; texts: `texts_present` (non-empty, Cyrillic, no `{`), `revocation_io_text`; guard `src_guard` (scan `src/` with CRLF normalized: none of the socket/DNS identifiers listed in "Do not"; `LocalSnapshot {` exactly once and only in `watch.rs`; `RouteSources {` absent; `set_gateway(` absent; `.observe(` and `issue_addr_update(` only in `addrinfo.rs`; no `rendezvous`, `stun`, `igd`, `upnp`, `mdns`, case-insensitive).
C4 (`chervo-connect/src/tests/invite.rs` with the fake; `chervo-connect/tests/engine_net.rs` with two or three `QuinnTransport` on 127.0.0.1, `InviteAddrs::Manual`): `invitee_max_three_sessions`, `invitee_no_auto_retry_after_m1`, `inviter_session_capped_by_token_expiry` (ttl 60 s, session 300 s -> ends at expiry), `inviter_on_m1_after_expiry_rejected`, `invite_expire_every_minute`, `drop_all_pending_on_start`, `invite_auto_lan_only_by_choice`, `invite_auto_no_addresses_error`, `publish_guest_removed_with_friend_added_same_call` (exactly one `set_peers` call contains the friend triple and no guest triple), `engine_invite_then_friend_connect` (both `SasReady` with equal digits, both confirm -> `Added` both, guest connections closed, `Connected` both within 15 s, A's book has B's `Contact`), `engine_invite_declined_nothing_saved`, `engine_simultaneous_both_dial_one_conn`, `engine_reconnect_after_peer_restart` (B engine and transport rebuilt on the same port; A `connect_now` -> connected within 15 s), `engine_block_closes_and_stops_dialing`, `engine_three_no_cross_addresses` (A friend of B and C; after exchanges B's book holds no address of C), `engine_probe_change_reknocks_and_keeps_conn` (`RouteProbe` fake toggles the v4 source; `reknock_runs` +1; round trip still works).
C5: `bash -n tools/netns/stage13.sh`; rows above **not run here**.

## Acceptance criteria (each as a command; output in report)
- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked` (all names above, except `#[ignore]`)
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'quinn|rustls|igd|xml'; test $? -eq 1`
- [ ] `cargo tree --workspace -e normal | grep -Ei 'igd|xml-rs|mdns'; test $? -eq 1`
- [ ] `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `for i in $(seq 20); do cargo test -q --locked -p chervo-transport-quinn -- race_ parallel_ simultaneous_ reknock_ || exit 1; done`
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-connect --test engine_net || exit 1; done`; same 10× for `-p chervo-friends --test invite_net --test addr_net`
- [ ] `bash -n tools/netns/stage13.sh`
- [ ] CI: all jobs green (3 OS, supply-chain).

## Where verified
- **Windows locally and CI (3 OS):** everything in C1-C4 (loopback, fake transport, paused time).
- **Only Linux netns with root (not this machine; candidate: owner's Ubuntu mini-PC): not verified here.** All C5 rows: real NAT types, simultaneous open through NAT, manual forward, CGNAT and UDP-block diagnoses, real interface address change, traffic capture (destinations, DNS, probe).
- **Only real networks (stage 16):** operators, ТСПУ, router UDP timeouts, hairpin, timings.

## Not verified in this stage (write in report, do not claim)
- Racing and per-address knocks through real NATs; that refusing extra QUIC connections before KK costs the peer nothing beyond its per-IP limiter.
- `reknock` keeping a connection across a real interface change (stage 12 open item, C5 row).
- `127.0.0.2` loopback on Windows (test may become linux-only).
- UDP-blocked heuristic quality (it cannot tell "UDP blocked" from "friends offline"; text says so).
- CGNAT behind a home router (needs 13a WAN IP).

## Stop conditions
Spec contradicts code; a new crate, `unsafe`, or a change of KK/knock/ADDR_INFO/invite formats/`SecretStore` is needed; a fact above does not match the source; a criterion cannot be checked; a race test unstable after two fix attempts; the fake transport cannot express a required test without changing the public API. Stop and report.

## Limit
At most 2 review-fix rounds, then report to the owner.

## Builder report (max 25 lines per call)
Changed files; criteria commands with last output lines; not done; deviations with reason; what was not runnable on Windows.

## Process and executors
1. Call 1 (C1, C2): `combine-builder` sonnet/high. Conductor runs tests of changed crates and clippy.
2. Call 2 (C3): `combine-builder` sonnet/high.
3. Call 3 (C4, C5): `combine-builder` sonnet/high.
4. `combine-verifier` (sonnet/low): all criteria.
5. `combine-security` (opus/high), once on the full diff: decisions 2-6, 8, 9; quinn race and single-flight; limiter bounds; ADDR_INFO lifecycle (lazy issue, deferred update); publish order and `DuplicatePairError`; invite sessions, expiry closure, session deadline; source guard; manual forward publishing.
Critical: C1 race/single-flight/coalescing, C2 `on_m1`, C3 limiter/candidates/publish/addrinfo/watcher, C4 entirely. Not critical: texts, path kind, C5 script.

## Requirements for other stages (not implemented here)
- **13a UPnP IGD** (after Q1): client choice; gateway identification without OS FFI (or with a vetted crate); review 8 items 1-3 (lease ≤ 1 h, renew at half, delete on exit and stale ones at start, own internal IP only, neutral description, error 725 -> ask user, laptop in foreign networks: off by default); `set_gateway` only after `GetSpecificPortMappingEntry`; WAN IP gives CGNAT/double-NAT diagnosis; mapping closed on shutdown and on network change.
- **13c LAN discovery (U9)**: announcement without key and name; sockets via socket2 0.6.5 (`set_reuse_address`, fact 13); parser fuzz.
- **IPv6 stage**: dual-stack socket (`set_only_v6(false)`, fact 13), knock send/admit with v4-mapped normalization, candidates unblocked, `NO_IPV6_TEXT` reworded.
- **13b rendezvous**: consent question uses `Diagnosis::rendezvous_could_help`; no traffic before consent.
- **14**: stream kinds besides `STREAM_ADDR_INFO` through a handler on the engine; revocation sent over the live connection, `revocation_error_text` on `Io`.
- **16**: rows of C5 plus real machines; table by `PathKind`.
- **17**: fuzz of nothing new; check that `Debug` of engine types is redacted; logs policy.
- **18**: settings for listen port (stable across restarts) and `manual_forward`; show `user_text`, `CGNAT_TEXT`; invite "same network" and manual address input with T8 warning; SAS screen from `SasReady`.
- **THREAT_MODEL (conductor, after acceptance):** T2: lying-friend dial amplification bound (decision 5 numbers); T1: periodic knocks + Initials to known addresses are a recognisable pattern (≤ every 5 s in fast windows, ≤ every 10-30 min per address otherwise); T8: manual invite addresses.

## For the owner (кратко, по-русски)
- Новый слой соединения сам решает, по каким адресам и в каком порядке звонить другу (сначала локальная сеть, затем постоянные адреса, затем подсказки); транспорт только пробует их наперегонки, побеждает первый, проверка ключа пары идёт ровно по одному соединению. Два одновременных исходящих звонка к одному другу невозможны (исправляет Н4 этапа 9).
- Пока программа открыта, она периодически звонит друзьям, с которыми нет связи: часто (раз в 5 с, 2 минуты) только после ваших собственных событий (запуск, смена сети, кнопка «соединить»), иначе редко, от 30 с до 10 минут. Так два компьютера за обычным NAT встречаются без сервера, а друг-лжец не может заставить нас часто стучать на чужой адрес.
- В этом этапе: белый IP, ручной проброс порта (настройка «внешний порт»), одновременное открытие, смена сети ноутбука (повторный стук и рассылка нового адреса друзьям), приглашение друга целиком (не больше 3 сессий на токен, срок проверяется прямо перед приёмом, гость снимается тем же действием, что добавляет друга).
- Отложено: UPnP (библиотека igd-next падает от маленького ответа любого устройства в сети, проверить исправление здесь нечем) - вопрос 1; поиск в локальной сети и IPv6 - вопрос 2. Сервер-посредник (13б) отложен вами: программа к нему не обращается вообще, при CGNAT честно пишет, что посредник появится позже.
- Если соединиться нельзя, программа называет причину: CGNAT, симметричный NAT, возможно заблокирован UDP, у друга только IPv6, адрес неизвестен (нужен токен обновления), неизвестно.
- Проверяется на Windows и в CI: всё на локальной петле и на модели сети. Реальные NAT и смену адреса интерфейса здесь проверить нельзя: скрипт для netns запускается на Linux с root (например на вашем мини-ПК).

## Open questions for the owner
**Q1. UPnP (security).** Options: (A) igd-next 0.18.0 in a child process of our own binary with a hard timeout and output limit (std has no memory limit, so a bomb may eat RAM for seconds before the kill; large unverified dependency tree); (B) vendored igd-next patched to reject bodies with `<!DOCTYPE` (we maintain a fork of an XML stack); (C) own minimal IGD client without an XML library: HTTP/1.0, body ≤ 64 KiB, 3 s deadline, any `<!` rejected, fixed tag extraction, fuzzed (≈ 600-900 lines of hostile-input code, security review); (D) never UPnP, only manual forward. **Recommendation: C in a separate stage 13a; until then manual forward (this stage).** Additional point for 13a: how to identify the real gateway without OS route APIs (review 8 item 2).
**Q2. Deferring LAN discovery (mDNS) to 13c and IPv6 to a small later stage.** Recommendation: defer both (owner order: IPv4 stationary first; IPv6 rare). Cost: two computers in one LAN that never met there find each other only via an invite with "same network", via the public address (needs hairpin) or after a first contact over LAN.
