# SPEC 12: Addresses and IP change          criticality: CRITICAL (parts A1-A5)

Author: combine-architect (opus), 2026-10-16, revision 1. Labels: [P] verified by me in the source (file:line); [V] architect's inference; [D] from memory, not re-checked; [NP] not verified. **Nothing was run.** No new crates: only path crates and crates already in `[workspace.dependencies]` / `Cargo.lock`. New edges: `chervo-addr -> chervo-identity`, `chervo-token -> chervo-addr`.

Goal: each side keeps a book of its friends' addresses (source, time, short-lived IPv6, U12) and its own address view (interfaces, port mapping, addresses observed by friends). Friends exchange addresses only inside an authenticated connection (U10b), or by a manual **address update token** (BRIEF 4) that is per friend, signed by that pair's key, has a strictly increasing number, and is never accepted by another pair. Addresses of one friend are never given to another (U6 v6). When neither side has a stable address, the app says plainly that a manual token is needed (BRIEF 4).

Read: this file; `docs/specs/stage-11-invite.md` ("Interface", "Untrusted input"); `crates/chervo-addr/*`; `crates/chervo-identity/src/{keys,store,lib}.rs`; `crates/chervo-token/src/*`, `crates/chervo-token/tests/{flow,fuzz_smoke}.rs`; `crates/chervo-friends/src/*`, `crates/chervo-friends/tests/{book,invite_net}.rs`; `crates/chervo-transport/src/lib.rs`; `crates/chervo-transport-quinn/src/{lib,client,knock}.rs`, `src/tests/knock.rs`; `scripts/check-forbidden.sh`; root `Cargo.toml`. Search nothing else.

## Decisions (rationale)
1. **Token format carries no key identifier.** The signed message is `signer_ed || recipient_ed || body`; neither key is transmitted. The recipient trial-verifies with each Active friend's `(friend_ed, our_ed)` (at most `MAX_FRIENDS = 1024` Ed25519 verifications per paste, user-initiated; cost not measured [NP], order 0.1 s in release [D]). Binding both keys means: a token of pair P1 never verifies in pair P2, even if a hostile friend reuses one Ed25519 key in two pairs (the recipient's own key differs per pair) [V]. No stable identifier is visible to the messenger beyond the addresses themselves (T8, T14) [V]. In-band the pair is already known (`Connection::remote_pair`), so only one verification.
2. **Sequence numbers.** Per direction of each pair: the sender keeps `addr_seq_out`, the receiver keeps `last_addr_seq` (field already exists, `chervo-friends/src/types.rs:37` [P], starts at 0, `book.rs:402` [P]). Accept iff `seq > last_addr_seq` (strict; equal = stale). Issue: `seq = max(addr_seq_out + 1, now_unix * 1000)` (`SEQ_TIME_SCALE = 1000`); `addr_seq_out == u64::MAX` -> `SeqExhausted`. The time floor makes the sender survive a rollback of its own friends file (restored from backup, T5/stage 17): the next seq is still above every seq issued before, as long as the clock did not go backwards [V].
3. **Where the counter lives: in the encrypted friends file** (`Friend::addr_seq_out`, plaintext v2). Write-ahead: the new `addr_seq_out` is committed (`seal` -> `.tmp` -> `sync_all` -> `rename` -> dir fsync, existing `FriendBook::save`, `book.rs:220-261` [P]) **before** the token is signed and returned; save error -> no token. Receiver: verify -> seq check -> merge -> commit; save error -> in-memory rollback (existing `commit`, `book.rs:263-282` [P]), nothing applied. Rejected alternatives: OS keystore record (changes key blob v2 or the entry-count model of stage 10, keychain write per update); separate file (second file to keep consistent, same rollback problem). **Stage 17 interaction:** rollback of the receiver's file lowers `last_addr_seq`, so an older token can be accepted again until the file generation counter of stage 17 exists; effect is only stale addresses and a failed connection (T5 residual, unchanged) [V].
4. **One-way type guard for U6 v6.** Only `chervo_addr::PublishSet` can be signed (`chervo_token::issue_addr_update` takes `&PublishSet`). `PublishSet` has private fields and no public constructor or `From`; it is produced only by `OwnAddrs::publishable`, which reads only our own sources (route probe, our listen port, our port mapping, observations **about us**). There is no conversion from a friend's `KnownAddr` into anything publishable [V]. Compile-fail doctests pin this.
5. **Observed address (U6 v5, owner N6 2026-10-16).** A friend reports, inside the authenticated connection, the address it sees us at (`conn.remote_addr()` computed by the helper itself, never caller-supplied). Verification before use: only from an Active friend's authenticated connection; family equals the path family; on a global path the observed IP must be Global; observed IP != reporter's own IP; port != 0; TTL 30 min; one entry per reporter (newest), at most 16; dropped when the reporter is blocked or removed; all observations dropped when our local addresses change. Per N6 **one report is enough to publish**; additionally (stricter only on contradiction) nothing observed is published while two live reports disagree on the IP (`Conflicting`), or agree on IP but not on port (symmetric NAT, port useless to others), or contradict a Global gateway WAN IP (`DoubleNat`). Published observed addresses carry flag `HINT`, so receivers treat them as unverified (stage 13 rate-limits attempts to them). Residual: a single lying friend can still make all our friends send QUIC Initials and knocks to a victim address (N6 accepted by owner; security review 8 item 7) [V].
6. **IPv6 privacy (U12, T8).** EUI-64 (MAC-derived, IID bytes 11-12 = `ff fe`) addresses are never published. Temporary (RFC 4941) and stable-privacy (RFC 7217) addresses cannot be told apart without OS APIs (and `unsafe_code = "forbid"`, root `Cargo.toml:53-54` [P], rules out FFI here), so **every published IPv6 is flagged `SHORT_LIVED`**; receivers drop short-lived entries 24 h after `last_seen`. IPv6 is rare for the owner and not blocking (OWNER_DECISIONS 2026-10-15).
7. **Own interface addresses: std-only route probe.** `probe_route_sources()` creates a UDP socket, `connect`s it to the documentation address `192.0.2.1:9` (and `[2001:db8::1]:9`) and reads `local_addr()`: the OS route lookup yields the source address; for UDP `connect` sends no datagram [D: POSIX/Winsock semantics; verify by capture in stage 16, see "Not verified"]. No third party is contacted (BRIEF 2.2). Limits: one address per family; LAN-only secondary interfaces are not seen (LAN discovery is mDNS, stage 13). No interface enumeration crate exists in `Cargo.lock` (grep for if-addrs/netdev/local-ip-address/network-interface: none) [P].
8. **On own address change: `reknock`, not `rebind`.** Requirement N3 (review 9b): after an address change the peer drops our packets from the new source until a knock arrives. The socket is bound to a wildcard address, so the OS sends from the new source by itself [D]; what is missing is the knock. New `QuinnTransport::reknock()` sends knocks on every live connection from the **same** socket: the listening port and any port forwarding stay valid. `rebind` remains for the case where the socket itself must change (stage 13 decides). Both use one fixed path: the first knock (t = 0) is sent by the async `KnockState::send`, which waits for writability on `WouldBlock` (`knock.rs:584-608` [P]); `send_now` (`knock.rs:571-582`, drops the knock on `WouldBlock`, used only at `client.rs:178` [P]) is deleted. To always have a task context, `Inner` stores the `tokio::runtime::Handle` captured in `from_socket` (which already requires a runtime, `lib.rs:304-306` [P]).
9. **In-band exchange `ADDR_INFO`** (one bidirectional stream, each side sends one frame and finishes): "what address I see you at" + optional signed update. The connecting side opens it right after `connect`; the accepting side's stream dispatcher (stage 13) reads the kind byte and calls `answer_addr_info`. A `Connection` exists only after Noise KK, so addresses are never sent before authentication (U10b) [V]; the helper also refuses if `conn.remote_pair()` differs from the pair the update was issued for.
10. **LAN addresses.** In a manual token only on explicit user choice "same network" (owner decision stage 11 q.3, applied to update tokens too). In-band, LAN addresses are included automatically only when the connection itself runs over a Private address (the friend already sees our LAN address as `remote_addr`; nothing leaks to a third party) [V].
11. **Receiver address rules.** Update tokens may carry only `Global` or `Private` (RFC 1918, ULA) addresses; loopback, link-local, CGNAT shared space, documentation, benchmark, reserved, multicast, broadcast, unspecified, v4-mapped are rejected. Private is kept so that LAN friends work; a lying friend can aim our attempts at LAN hosts (T2 residual, stage 13 rate limit) [V].
12. **No expiry inside the update token.** Ordering is by seq; an older-than-applied token is rejected; a never-applied token delivered late is still the newest the friend made [V]. Removes a clock dependency.
13. **No architect review after builder.** Format, protocol and persistence order are fixed here; `combine-security` checks conformance.

## Facts from the source
1. `SignDomain::AddressUpdate` exists, tag `b"chervotochina/v1/address-update\0"`, included in `SignDomain::ALL` (`chervo-identity/src/keys.rs:13-35`) [P]. `PairKey::sign(domain, msg)` signs `tag || msg` (`keys.rs:38-44, 163-169`); `PublicKey::verify` uses `verify_strict` (`keys.rs:72-78`) [P]. Test `sign_domains_pairwise_not_prefix` exists per stage 11 spec K1 [NP: test file not opened].
2. `identity::load(store, pair, expected_ed) -> Result<PairKey, IdentityError>` (`store.rs:111-115`) [P].
3. `chervo-token`: `decode` checks `MAX_TOKEN_TEXT_LEN` first, ASCII, strips whitespace, uppercases, 4-char prefix, strict base32, version, kind (`src/lib.rs:31-106`); `base32::{encode, decode}` are `pub(crate)` (`base32.rs:14,34`); `Token` is `#[non_exhaustive]` (`lib.rs:57-61`) [P].
4. `chervo-friends` plaintext v1 layout and strict reader (`plain.rs:1-10, 24-27, 34-55, 216-336`); version mismatch returns `Corrupt` (`plain.rs:219-221`) [P]. `src/tests/kit.rs:65-78` builds friends with `AddrSource::ObservedByFriend`, `short_lived: true`, `last_addr_seq: 7` [P].
5. `chervo-addr` is a stub with `AddrSource` (6 variants) and `KnownAddr { addr, source, last_seen_unix, short_lived }`, no dependencies (`src/lib.rs:1-22`, `Cargo.toml:8`) [P].
6. `chervo_transport::Connection` offers `remote_pair`, `remote_addr`, `open_bi`, `accept_bi`, `close` only (`chervo-transport/src/lib.rs:75-86`) [P]. `QuinnTransport::local_addrs` returns `endpoint.local_addr()` only (`chervo-transport-quinn/src/lib.rs:447-449`) [P].
7. `rebind` -> `client::reknock_live` (`lib.rs:394-407`); `reknock_live` sends the first knock by `send_now` synchronously, then spawns knocks at `resend` and `3*resend`, the last of these by system time when an offset is set (`client.rs:171-198`) [P].
8. `chervo-token/tests/flow.rs` tests exchanges over an in-memory `MemConn` without tokio (`flow.rs:1, 75`) [P].

## Do (two builder calls; verify each step before the next, CORE 5)

### Call 1: builder sonnet/high. Parts A1, A2, A3
1. Environment: `cargo --version`, `rustc --version` (expect 1.99.1); `BASE=$(git rev-parse HEAD)`.
2. `grep -rn "send_now" crates/` -> only `chervo-transport-quinn/src/{knock,client}.rs`. `grep -rln "AddressUpdate\|KnownAddr\|AddrSource" crates --include=*.rs` -> only files named in facts 1, 4, 5 and `chervo-friends/{src/book.rs,src/plain.rs,src/types.rs,tests/book.rs}`. Otherwise STOP.
3. **A1 `chervo-addr` (own side):** lint block as in `chervo-identity/src/lib.rs:6-13`; dependency `chervo-identity.workspace = true`; modules `class`, `probe`, `own`. `KnownAddr`/`AddrSource` untouched in this call. Tests A1.
4. **A2 `chervo-token`:** dependency `chervo-addr.workspace = true`; module `addr_update` (format, issue, parse, verify, text) wired into `decode`; module `addr_flow` (frame codec + exchange helpers). Tests A2 and fuzz smoke.
5. **A3 `chervo-transport-quinn`:** `Inner.rt`, `reknock_live` rewrite, delete `send_now`, `QuinnTransport::reknock`. Tests A3.
6. Criteria below for changed crates; report.

### Call 2: builder sonnet/high. Parts A4, A5
7. **A4 `chervo-addr` (friend side):** `AddrSource::Contact`, `KnownAddr::hint`, module `book` (friend address rules, findability, texts). **`chervo-friends`:** plaintext v2 with v1 migration, `Friend::addr_seq_out`, `FriendBook` methods, error variants; update all struct literals in crate and tests. Tests A4.
8. **A5:** `crates/chervo-friends/tests/addr_net.rs` (two `QuinnTransport` on loopback with knock, as `invite_net.rs`); `scripts/check-forbidden.sh` patterns. All criteria; report.

## Interface (exact)
All `Debug` impls on types holding addresses or keys print `"TypeName(..)"`. No `Display` that prints input bytes. No panics, no logging, no clocks inside crates: time comes as `now_unix` (UTC seconds incl. clock offset) from the caller.

### A1. chervo-addr, own side
```rust
// class.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum AddrClass { Global, Private, Shared, Loopback, LinkLocal, Unspecified, Multicast,
                     Broadcast, Documentation, Benchmark, V4Mapped, Reserved }
pub fn classify(ip: IpAddr) -> AddrClass;            // tables below, first match wins; own prefix code, no unstable std
pub fn is_eui64(ip: &Ipv6Addr) -> bool;              // octets[11] == 0xff && octets[12] == 0xfe
pub fn normalize(a: SocketAddr) -> SocketAddr;       // IPv6 v4-mapped -> IPv4 (same port); else unchanged
pub fn update_allowed(ip: IpAddr) -> bool;           // classify(ip) is Global or Private
```
IPv4 table: `0.0.0.0/32` Unspecified; `0.0.0.0/8` Reserved; `10/8` Private; `100.64/10` Shared; `127/8` Loopback; `169.254/16` LinkLocal; `172.16/12` Private; `192.0.0/24` Reserved; `192.0.2/24` Documentation; `192.88.99/24` Reserved; `192.168/16` Private; `198.18/15` Benchmark; `198.51.100/24` Documentation; `203.0.113/24` Documentation; `224/4` Multicast; `255.255.255.255/32` Broadcast; `240/4` Reserved; else Global. [D: ranges from the IANA special-purpose registry (RFC 6890 and updates) by memory; the table here is normative for the code.]
IPv6 table: `::/128` Unspecified; `::1/128` Loopback; `::ffff:0:0/96` V4Mapped; `::/96` Reserved; `64:ff9b::/96` Reserved; `64:ff9b:1::/48` Reserved; `100::/64` Reserved; `ff00::/8` Multicast; `fe80::/10` LinkLocal; `fec0::/10` Reserved; `fc00::/7` Private; `2001:db8::/32` Documentation; `3fff::/20` Documentation; `2001::/23` Reserved; `2002::/16` Reserved; `2000::/3` Global; else Reserved.

```rust
// probe.rs: the only socket code in the crate; never sends (guard test)
#[derive(Clone, Copy, PartialEq, Eq, Default)] pub struct RouteSources { pub v4: Option<Ipv4Addr>, pub v6: Option<Ipv6Addr> }
pub const PROBE_V4: SocketAddr = /* 192.0.2.1:9 */;  pub const PROBE_V6: SocketAddr = /* [2001:db8::1]:9 */;
/// bind 0.0.0.0:0 / [::]:0, connect(PROBE_*), local_addr().ip(); any error -> None for that family.
/// Result Unspecified/Loopback -> None. Never calls send/send_to.
pub fn probe_route_sources() -> RouteSources;

// own.rs
pub const OBSERVED_TTL_SECS: u64 = 1_800;
pub const MAX_OBSERVATIONS: usize = 16;
pub const MAX_UPDATE_ADDRS: usize = 8;

#[derive(Clone, PartialEq, Eq)] pub struct LocalSnapshot { pub route: RouteSources, pub listen: Vec<SocketAddr> } // listen = transport.local_addrs()
/// Set by stage 13 only after its own checks (gateway = default route, mapping confirmed by
/// GetSpecificPortMappingEntry; security review 8 item 2). Not validated further here except class.
#[derive(Clone, Copy, PartialEq, Eq)] pub struct GatewayInfo { pub wan_ip: Option<Ipv4Addr>, pub mapping: Option<SocketAddrV4> }

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ObserveOutcome { Accepted, IgnoredLocalPath, Rejected(ObserveReject) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ObserveReject { FamilyMismatch, NotGlobal, ReporterOwnIp, ZeroPort }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum NatView { NoIpv4, Public, PortMapped, BehindCgnat, DoubleNat, Conflicting, Symmetric, Eim, Unknown }

#[derive(Clone, Copy, PartialEq, Eq)] pub struct UpdateAddr { pub addr: SocketAddr, pub short_lived: bool, pub hint: bool }
/// Our own publishable addresses. No public constructor, no From, no Default (U6 v6 guard).
#[derive(Clone, PartialEq, Eq)] pub struct PublishSet { addrs: Vec<UpdateAddr> }
impl PublishSet { pub fn as_slice(&self) -> &[UpdateAddr]; pub fn is_empty(&self) -> bool; pub fn socket_addrs(&self) -> Vec<SocketAddr>; }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub struct PublishCtx { pub include_lan: bool }
impl PublishCtx { pub fn for_connection(remote: SocketAddr) -> Self; } // include_lan = classify(normalize(remote).ip()) == Private

#[derive(Default)] pub struct OwnAddrs { /* local: Option<LocalSnapshot>, gateway: Option<GatewayInfo>, obs: Vec<Obs{reporter: PairId, via: SocketAddr, observed: SocketAddr, at: u64}> */ }
impl OwnAddrs {
    pub fn new() -> Self;
    /// true if route or listen set differs from the previous snapshot (first call: true).
    /// On change: observations and gateway info are cleared (they describe the old network).
    pub fn set_local(&mut self, snap: LocalSnapshot) -> bool;
    pub fn local(&self) -> Option<&LocalSnapshot>;
    pub fn set_gateway(&mut self, g: Option<GatewayInfo>);
    /// `via` = conn.remote_addr(), `observed` = what the friend says. Caller guarantees `reporter`
    /// is an Active friend (FriendBook::is_active). Both addresses are `normalize`d first. Rules in order:
    /// observed.port()==0 -> ZeroPort; family(observed) != family(via) -> FamilyMismatch;
    /// classify(via) != Global -> IgnoredLocalPath (nothing stored);
    /// classify(observed) != Global -> NotGlobal; observed.ip()==via.ip() -> ReporterOwnIp;
    /// else store/replace the reporter's entry (at = now), evict oldest beyond MAX_OBSERVATIONS -> Accepted.
    pub fn observe(&mut self, reporter: PairId, via: SocketAddr, observed: SocketAddr, now_unix: u64) -> ObserveOutcome;
    pub fn forget_reporter(&mut self, reporter: &PairId);
    pub fn nat_view(&self, now_unix: u64) -> NatView;
    pub fn stable_reachable(&self, now_unix: u64) -> bool;          // nat_view is Public or PortMapped
    pub fn observed_v4(&self, now_unix: u64) -> Option<SocketAddrV4>;
    pub fn publishable(&self, ctx: PublishCtx, now_unix: u64) -> PublishSet;
}
```
Live observations = IPv4 entries with `now_unix < at + OBSERVED_TTL_SECS` and `at <= now_unix + 60` (otherwise treated as expired).
`nat_view`, first match: no snapshot or `route.v4 == None` -> NoIpv4; `route.v4` Global -> Public; `route.v4` Shared -> BehindCgnat; gateway `wan_ip` Shared -> BehindCgnat; `wan_ip` Private -> DoubleNat; `wan_ip` Global and `mapping.ip() == wan_ip` -> PortMapped; live observations with ≥2 distinct IPs -> Conflicting; `wan_ip` Global and a live observation IP != `wan_ip` -> DoubleNat; same IP, ≥2 distinct ports -> Symmetric; ≥2 reporters with equal ip:port -> Eim; else Unknown.
`observed_v4`: `Some(newest live observation)` only if `nat_view` is Unknown or Eim; else None.
`publishable` (in this order; dedup by `SocketAddr`; cap `MAX_UPDATE_ADDRS`): `p4` = port of the first IPv4 listen address, `p6` = port of the first IPv6 listen address (none -> that family is not published from interfaces); (1) `route.v4` Global with `p4` -> flags 0; (2) gateway mapping when nat_view is PortMapped -> flags 0; (3) `observed_v4` -> `hint`; (4) `route.v6` Global, not EUI-64, with `p6` -> `short_lived`; (5) only if `ctx.include_lan`: `route.v4` Private with `p4` -> flags 0; `route.v6` Private (ULA), not EUI-64, with `p6` -> `short_lived`.

### A2. chervo-token: address update token and ADDR_INFO
```rust
pub const ADDR_UPDATE_PREFIX: &str = "CHA1";
pub const KIND_ADDR_UPDATE: u8 = 0x03;
pub const ADDR_UPDATE_MIN_LEN: usize = 83;   // 1 IPv4
pub const ADDR_UPDATE_MAX_LEN: usize = 235;  // 8 IPv6
pub const FLAG_SHORT_LIVED: u8 = 0x01;  pub const FLAG_HINT: u8 = 0x02;
pub const STREAM_ADDR_INFO: u8 = 0x21;
pub const ADDR_INFO_MAX_LEN: usize = 258;

// Token gains: Token::AddrUpdate(SignedAddrUpdate)   (decode: prefix CHA1 <-> kind 0x03)
/// Structurally valid, signature NOT yet checked. Contents are not readable before `verify`.
#[derive(Clone)] pub struct SignedAddrUpdate { /* bytes: Vec<u8> (whole binary), parsed fields */ } // Debug redacted; no accessors
impl SignedAddrUpdate {
    /// signer = friend_ed, recipient = our_ed of that pair. Error -> TokenError::BadSignature.
    pub fn verify(&self, signer: &PublicKey, recipient: &PublicKey) -> Result<AddrUpdate, TokenError>;
}
pub struct AddrUpdate { /* seq, addrs */ }  // Debug redacted
impl AddrUpdate { pub fn seq(&self) -> u64; pub fn addrs(&self) -> &[UpdateAddr]; }
#[derive(Clone)] pub struct IssuedAddrUpdate { /* bytes */ }  // Debug redacted
impl IssuedAddrUpdate { pub fn seq(&self) -> u64; pub fn bytes(&self) -> &[u8]; pub fn text(&self) -> String; } // text = "CHA1" + base32(bytes)
/// seq >= 1 (else Malformed); set with 1..=8 entries (else BadAddress); recipient == key.public_key() -> BadKey.
/// The output is parsed again by the same parser before returning; failure -> Malformed.
pub fn issue_addr_update(key: &PairKey, recipient: &PublicKey, seq: u64, set: &PublishSet) -> Result<IssuedAddrUpdate, TokenError>;
pub fn decode_addr_update_bin(b: &[u8]) -> Result<SignedAddrUpdate, TokenError>; // in-band path; same parser
#[doc(hidden)] pub fn encode_addr_update_bytes(bytes: &[u8]) -> String;          // tests only, like encode_invite_bytes
```
**Binary format** (big-endian):
```
[0]      TOKEN_VERSION 0x01        [1]  KIND_ADDR_UPDATE 0x03
[2..10]  seq u64 (>= 1)            [10] n, 1..=8
n times: [family 0x04|0x06][IP 4|16][port u16 != 0][flags u8]
[L-64..L] Ed25519 signature
```
Entry 8 bytes (IPv4) or 20 (IPv6); `L = 75 + Σ entries`, 83..=235. Signature: `signer.sign(SignDomain::AddressUpdate, signer_ed(32) || recipient_ed(32) || bytes[0..L-64])`; verification with `PublicKey::verify` over the same message. Text: `CHA1` + base32 (max 380 chars).
**Parse order** (`TokenError`): `L` outside 83..=235 -> Malformed; version -> UnsupportedVersion; kind != 0x03 -> BadKind; seq == 0 -> Malformed; n outside 1..=8 -> Malformed; per entry: unknown family -> Malformed; flags with bits other than 0x03 set, or `FLAG_SHORT_LIVED` on IPv4 -> Malformed; port 0 or `!update_allowed(ip)` -> BadAddress; duplicate `SocketAddr` -> BadAddress; consumed bytes != `L-64` -> Malformed. Signature only in `verify`.
`issue_addr_update` builds entries from `set.as_slice()` in order (flags from `short_lived`/`hint`).

**ADDR_INFO frame** (one per direction on one bi stream):
```
[0] STREAM_ADDR_INFO 0x21   [1] PROTO_V1 0x01
[2] family 0x04|0x06, IP 4|16, port u16      -- observed: normalize(conn.remote_addr()) at send time
[..] update_len u16: 0 (none) or ADDR_UPDATE_MIN_LEN..=ADDR_UPDATE_MAX_LEN
[..] update bytes (binary address update)
```
Length 11..=258. Observed rules: port != 0; IP not Unspecified/Multicast/Broadcast/V4Mapped (class checks happen in `OwnAddrs::observe`). Update bytes parsed by `decode_addr_update_bin`.
```rust
pub mod addr_flow {   // generic over chervo_transport::Connection; no tokio
    pub struct PeerAddrInfo { pub observed_me: SocketAddr, pub via: SocketAddr, pub update: Option<SignedAddrUpdate> } // Debug redacted
    pub fn encode_addr_info(observed: SocketAddr, ours: Option<&IssuedAddrUpdate>) -> Result<Vec<u8>, AddrFlowError>;
    pub fn decode_addr_info(frame: &[u8]) -> Result<(SocketAddr, Option<SignedAddrUpdate>), AddrFlowError>;
    /// Connecting side: remote_pair != *pair -> WrongPeer (nothing sent); open_bi, write frame, finish,
    /// read one full frame (kind byte included), then require EOF.
    pub async fn exchange_addr_info<C: Connection>(conn: &C, pair: &PairId, ours: Option<&IssuedAddrUpdate>) -> Result<PeerAddrInfo, AddrFlowError>;
    /// Accepting side; the dispatcher (stage 13) already consumed byte 0 == STREAM_ADDR_INFO.
    /// remote_pair != *pair -> WrongPeer (nothing written); read rest of frame, require EOF, write own frame, finish.
    pub async fn answer_addr_info<C: Connection>(conn: &C, pair: &PairId, tx: C::Tx, rx: C::Rx, ours: Option<&IssuedAddrUpdate>) -> Result<PeerAddrInfo, AddrFlowError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum AddrFlowError { Transport(TransportError), Truncated, Malformed, TrailingData, WrongPeer }
```
Reading: into a fixed `[u8; ADDR_INFO_MAX_LEN]`: header, family byte, then exactly 6 or 18 bytes, `update_len`, then exactly `update_len` bytes (bound checked before reading), then one more read must give `Ok(None)` (else `TrailingData`); short stream -> `Truncated`; then `decode_addr_info` on the assembled slice. `via = normalize(conn.remote_addr())` at receipt. Timeouts belong to the caller (stage 13: 5 s).

### A3. chervo-transport-quinn
- `Inner` += `rt: tokio::runtime::Handle` (captured in `from_socket`).
- `client::reknock_live`: no synchronous send; `inner.rt.spawn` one task: for `(n, at)` in `[0, resend, 3*resend]`: `sleep_until(t0 + at)`; `raw = n == 2 && offset != 0`; for each target: `make_knock` and `knock.send(..).await`. Delete `KnockState::send_now`.
- `pub fn reknock(&self)` on `QuinnTransport`: calls `client::reknock_live`. Doc: "call after our own address changed while the socket stays (same port); `rebind` only when the socket must change". Trait `chervo_transport` unchanged.

### A4. chervo-addr friend side + chervo-friends
```rust
// chervo-addr
pub enum AddrSource { Interface, Lan, PortMapping, Invite, AddressUpdate, ObservedByFriend, Contact } // Contact appended (byte 6)
pub struct KnownAddr { pub addr: SocketAddr, pub source: AddrSource, pub last_seen_unix: u64,
                       pub short_lived: bool, pub hint: bool }   // hint: the sender flagged it as observed
// book.rs
pub const SHORT_LIVED_TTL_SECS: u64 = 86_400; pub const HINT_TTL_SECS: u64 = 86_400;
pub const CONTACT_TTL_SECS: u64 = 86_400;     pub const CONTACT_REFRESH_SECS: u64 = 3_600;
pub const MAX_CONTACT_ADDRS: usize = 4;
pub fn from_invite(addrs: &[SocketAddr], now_unix: u64) -> Vec<KnownAddr>; // source Invite, IPv6 short_lived, first 8
/// Remove all Invite and AddressUpdate entries, insert update entries as AddressUpdate (last_seen = now), keep Contact.
pub fn merge_update(addrs: &mut Vec<KnownAddr>, update: &[UpdateAddr], now_unix: u64);
/// Upsert Contact entry; true if the stored vector changed (new addr, or last_seen older than CONTACT_REFRESH_SECS);
/// keep the MAX_CONTACT_ADDRS newest Contact entries. Addr is normalized first.
pub fn note_contact(addrs: &mut Vec<KnownAddr>, addr: SocketAddr, now_unix: u64) -> bool;
/// Drop: short_lived or hint older than their TTL; Contact older than CONTACT_TTL_SECS.
pub fn prune(addrs: &mut Vec<KnownAddr>, now_unix: u64);
/// Pruned view for dialing, order: AddressUpdate non-hint, Invite, Contact, hint; IPv4 before IPv6 within a group.
pub fn usable(addrs: &[KnownAddr], now_unix: u64) -> Vec<SocketAddr>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Findability { Ok, NeedToken }
/// friend_stable = some pruned entry with source Invite|AddressUpdate, !short_lived, !hint, Global.
/// NeedToken iff !own_stable && !friend_stable.
pub fn findability(own_stable: bool, friend: &[KnownAddr], now_unix: u64) -> Findability;
pub const NEED_TOKEN_TEXT: &str = "Ни у вас, ни у друга нет постоянного адреса, а известные адреса не отвечают. Без сервера-посредника вы не найдёте друг друга автоматически: отправьте другу токен обновления адреса или попросите прислать свой (любым мессенджером).";
pub const NO_PUBLIC_ADDR_TEXT: &str = "Не удалось определить ваш внешний адрес: нет белого IP, проброса порта или подсказки от друга. Подключитесь к другу сами, когда узнаете его адрес.";
```
```rust
// chervo-friends
pub struct Friend { /* + */ pub addr_seq_out: u64 }   // finish_pair sets 0
pub const MIN_INBAND_UPDATE_INTERVAL_SECS: u64 = 10;
// FriendsError += StaleSeq, BadAddrUpdate, NoAddresses, SeqExhausted, RateLimited, NotActive (fixed Display texts)
impl FriendBook {
    pub fn is_active(&self, pair: &PairId) -> bool;
    /// Active only (else UnknownPair / NotActive); set empty -> NoAddresses; load(store, pair, our_ed)
    /// (errors as in kx_peers: KeyMissing/KeyMismatch/CorruptKey -> KeyMissingOrChanged, UnsupportedKeyVersion ->
    /// KeyNeedsDecision, locked/unavailable -> KeyStorageUnavailable); seq = next_seq; commit(addr_seq_out = seq);
    /// only then issue_addr_update(key, friend_ed, seq, set).
    pub fn issue_addr_update<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, pair: &PairId,
        set: &PublishSet, now_unix: u64) -> Result<IssuedAddrUpdate, FriendsError>;
    /// Paste path: decode must give Token::AddrUpdate; verify against every Active friend (friend_ed, our_ed);
    /// exactly one match else BadAddrUpdate; seq <= last_addr_seq -> StaleSeq; merge_update + prune,
    /// last_addr_seq = seq, commit. Returns the pair.
    pub fn apply_addr_update_text<K: ListKeyStore + ?Sized>(&mut self, keys: &K, text: &str, now_unix: u64) -> Result<PairId, FriendsError>;
    /// In-band path (pair = conn.remote_pair()): Active only; verify with that friend only (else BadAddrUpdate);
    /// StaleSeq as above; if an in-band update for this pair was applied < MIN_INBAND_UPDATE_INTERVAL_SECS ago
    /// -> RateLimited (in-memory map, not persisted); merge, commit, record time.
    pub fn apply_addr_update<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId, update: &SignedAddrUpdate, now_unix: u64) -> Result<(), FriendsError>;
    /// Active only; commit only when chervo_addr::note_contact returns true.
    pub fn note_contact<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId, addr: SocketAddr, now_unix: u64) -> Result<(), FriendsError>;
    pub fn usable_addrs(&self, pair: &PairId, now_unix: u64) -> Vec<SocketAddr>;   // unknown pair -> empty
    pub fn findability(&self, pair: &PairId, own_stable: bool, now_unix: u64) -> Result<Findability, FriendsError>;
}
// next_seq(prev, now) = max(prev.checked_add(1)?, now.saturating_mul(1000)); None -> SeqExhausted. Private fn, unit-tested.
```
**Plaintext v2** (`PLAIN_VERSION = 0x02`; outer `FILE_VERSION` unchanged): per friend `... [last_addr_seq u64][addr_seq_out u64][added_at u64][n_addrs u8]`; per address `[family][IP][port u16][source u8 0..=6][last_seen u64][flags u8: bit0 short_lived, bit1 hint, other bits 0]`. Reader accepts v1 (old layout, source 0..=5, flags byte 0|1, `addr_seq_out = 0`, `hint = false`) and v2; any other version -> `Corrupt` (as now); writer always v2. `MIN_FRIEND_LEN` per version. All existing strictness rules stay.

### A5. scripts/check-forbidden.sh
Add fixed-string patterns: `stun:` `stun.l.google` `ipify` `ifconfig.me` `icanhazip` `checkip.` `ipinfo.io` `whatismyip` (no public "what is my IP" or STUN, BRIEF 2.2). Self-test unchanged and green.

## Do not
- No new crates in `Cargo.lock`; no `unsafe`; no OS interface APIs; no UPnP/NAT-PMP/PCP, mDNS, dial loops, timers, background tasks in `chervo-addr`/`chervo-token`/`chervo-friends` (stage 13).
- No datagram sending in `chervo-addr` (only `connect` + `local_addr` in `probe.rs`).
- No path from a friend's `KnownAddr` to `PublishSet`/`UpdateAddr` publishing; never put one friend's addresses in a message to another.
- Do not change KK, knock format, `SecretStore`, key blob, invite/revocation formats, `chervo_transport` traits. In the transport only A3.
- No logging/printing of addresses, tokens, keys; no `Debug` with content.

## Untrusted input
- Update token text: all stage-11 text rules (length first, ASCII, whitespace, case, prefix, canonical base32), then the binary parse order above. No allocation sized by input beyond `L <= 235`.
- ADDR_INFO frame: only fixed buffers; length field bounded before reading; EOF required.
- Observation: rules in `OwnAddrs::observe`; only from Active friends.
- Friends file v1/v2: strict as in stage 11 (counters vs remaining bytes, enums, flag bits, trailing bytes).
- No panic on any input (lint block + fuzz smoke).

## Tests (exact names)
A1 (`crates/chervo-addr/tests/{class,own,guard}.rs`): `classify_v4_table` (first and last address of every range and both neighbours, e.g. `100.63.255.255` Global, `100.64.0.0`/`100.127.255.255` Shared, `100.128.0.0` Global, `172.15.255.255`/`172.32.0.0` Global), `classify_v6_table` (same for every prefix), `eui64_detection`, `normalize_v4_mapped`, `probe_no_panic` (any result), `set_local_change_clears_observations_and_gateway`, `set_local_same_snapshot_no_change`, `observe_rules` (each `ObserveReject`; `IgnoredLocalPath` for private, shared and loopback `via`), `observe_replace_per_reporter_and_cap` (17 reporters -> 16, oldest gone), `observe_expiry` (`OBSERVED_TTL_SECS` boundary, future `at`), `forget_reporter_drops_hint`, `nat_view_rules` (one case per variant), `publish_white_ip`, `publish_mapping_requires_global_wan_match`, `publish_observed_single_friend_hint` (N6), `publish_observed_withheld_on_conflict`, `publish_observed_withheld_on_symmetric`, `publish_observed_withheld_on_double_nat`, `publish_v6_short_lived_never_eui64`, `publish_lan_only_with_ctx`, `publish_needs_listen_family`, `publish_dedup_and_cap`, `for_connection_lan_rule`, `no_send_in_src` (scan `src/` text: no `.send(`, `send_to(`; only `probe.rs` contains `UdpSocket`). Doctests on `PublishSet`: `compile_fail` struct literal, `compile_fail` `let s: PublishSet = Vec::new().into();`, positive control `OwnAddrs::new().publishable(PublishCtx::default(), 0)` compiles.
A2 (`crates/chervo-token/tests/{addr_update,addr_flow,fuzz_smoke}.rs`): `addr_update_roundtrip` (issue -> text -> decode -> verify -> same seq, addrs, flags), `addr_update_bin_equals_text_payload`, `addr_update_text_whitespace_and_case`, `addr_update_foreign_pair_rejected` (keys of another pair), `addr_update_wrong_recipient_rejected` (same signer, other recipient), `addr_update_swapped_roles_rejected` (signer and recipient swapped), `addr_update_any_byte_flip_rejected` (every byte of the binary; decode or verify fails), `addr_update_every_truncation_rejected`, `addr_update_trailing_bytes_rejected`, `addr_update_every_wrong_length` (0..=300 with valid-looking headers), `addr_update_count_rules` (n = 0, 9, n not matching length), `addr_update_addr_rules` (port 0, family 0x05, each rejected class, duplicate; Private and Global accepted), `addr_update_flag_rules` (bits 2..7, SHORT_LIVED on IPv4), `addr_update_seq_zero_rejected`, `addr_update_other_domain_rejected` (same message signed in `Invite`, `KeyRevocation`, `InviteAccept`), `addr_update_prefix_kind_mismatch` (`CHA1` + kind 1, `CHV1` + kind 3), `addr_update_unknown_version`, `addr_update_max_size` (8 IPv6 = 235 bytes, text <= 2048), `issue_addr_update_rules` (seq 0, empty set, recipient == signer), `addr_info_roundtrip`, `addr_info_every_truncation`, `addr_info_len_field_bounds` (1..=82 and 236..=65535 sampled -> Malformed), `addr_info_trailing_rejected`, `addr_info_bad_header`, `addr_flow_memconn_exchange` (MemConn as in `tests/flow.rs`: both sides get the other's observed address and update), `addr_flow_wrong_peer_sends_nothing`, `addr_flow_trailing_after_frame`, `addr_flow_futures_are_send`, `fuzz_smoke_addr_update` (text and binary), `fuzz_smoke_addr_info`. Test `PublishSet` values are built only through `OwnAddrs` (`set_local` with a Global route address and listen port, `set_gateway`, `observe`).
A3 (`crates/chervo-transport-quinn/src/tests/knock.rs`, with knock, `knock_resend_after = 30 s` so only the t = 0 knock can help): `rebind_first_knock_not_lost` (after `rebind`, a bi-stream round trip on the live connection succeeds within 3 s), `reknock_without_rebind` (the counter used by the existing `rebind_reknock` test rises within 2 s; connection alive), `send_now_absent` (src text scan).
A4 (`crates/chervo-addr/tests/book.rs`; `crates/chervo-friends/src/tests/plain.rs`; `crates/chervo-friends/tests/book.rs`): `from_invite_marks_v6`, `merge_update_replaces_invite_and_update_keeps_contact`, `note_contact_refresh_and_cap`, `prune_ttls` (each TTL boundary), `usable_order`, `findability_rules`, `texts_present`; `plain_v1_migrates` (hand-built v1 blob -> fields; re-encode starts with 0x02), `plain_v2_roundtrip_new_fields`, `plain_v2_rejects_bad_flags`, `plain_v2_rejects_source_7`, `fuzz_smoke_vault_plain` (extended to v2); `next_seq_rules` (time floor, +1, `u64::MAX` -> SeqExhausted), `issue_persists_seq_before_returning` (book whose path lies in a removed directory so `save` fails: `Io`, no token, in-memory `addr_seq_out` unchanged; normal path: after `issue`, a fresh `FriendBook::open` shows the returned seq), `issue_seq_strictly_increasing_across_reopen`, `issue_seq_survives_file_rollback` (copy the file, issue twice, restore the copy, issue again at a later `now`: seq above all previous), `issue_requires_active_and_nonempty`, `apply_text_roundtrip` (books A and B, each with its own MemStore and one pair), `apply_text_old_seq_rejected` (`seq < last` and `seq == last` -> StaleSeq), `apply_text_foreign_pair_rejected`, `apply_text_blocked_friend_rejected`, `apply_text_modified_byte_rejected`, `apply_text_bad_length_rejected`, `apply_inband_wrong_pair_rejected`, `apply_inband_rate_limited`, `apply_save_error_rolls_back`, `note_contact_persists_only_on_change`, `observation_not_published_to_others` (A gets an observation from friend F; the publish set signed for friend G contains it only as A's own `hint` address and never any address from F's `known_addrs`).
A5 (`crates/chervo-friends/tests/addr_net.rs`, loopback, two `QuinnTransport` with knock): `addr_info_end_to_end_quinn` (after connect, exchange; each side's `observed_me` equals its own socket address; `observe` gives `IgnoredLocalPath`; update applied, `usable_addrs` updated, `last_addr_seq` set), `addr_info_replay_is_stale` (same issued update sent again -> `StaleSeq`, file unchanged), `addr_info_other_pairs_update_rejected` (an update issued by C for A, sent by B over B's connection -> BadAddrUpdate), `addr_info_only_after_auth` (stranger without the pair: `connect` fails, A reads no frame). `bash scripts/check-forbidden.sh --self-test` and full scan green.

## Acceptance criteria (each as a command; output in report)
- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked` (all, incl. the names above, except `#[ignore]`)
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-token -p chervo-friends fuzz_smoke -- --nocapture` (iterations printed per target)
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`
- [ ] `cargo tree -p chervo-addr -p chervo-token -p chervo-friends -e normal | grep -E 'quinn|tokio|rustls'; test $? -eq 1`
- [ ] `grep -rn "send_now" crates/; test $? -eq 1`
- [ ] `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `for i in $(seq 20); do cargo test -q --locked -p chervo-transport-quinn -- rebind_ reknock_ || exit 1; done`; `for i in $(seq 10); do cargo test -q --locked -p chervo-friends --test addr_net || exit 1; done`
- [ ] CI: all jobs green (3 OS, supply-chain).

## Not verified in this stage (write in report, do not claim)
- That UDP `connect` in `probe_route_sources` emits no packet on Windows/macOS/Linux (stage 16: capture shows 0 packets to 192.0.2.1 / 2001:db8::1).
- That `reknock` alone keeps a connection across a real interface IP change with a wildcard socket (stage 16 netns, G1 variant); fallback if not: `rebind` to a new port + updates.
- Classification tables against the live IANA registry (written from memory, conservative).
- Trial-verify cost with 1024 friends; real NAT/EIM/EDM behaviour; IPv6 on real networks.
- File rollback protection (stage 17).

## Stop conditions
Spec contradicts code; a new crate, `unsafe`, or change to KK/knock format/`SecretStore` needed; a fact above does not match the source; a criterion cannot be checked; a race test unstable after two fix attempts. Stop and report.

## Limit
At most 2 review-fix rounds, then report to the owner.

## Builder report (max 25 lines per call)
Changed files; criteria commands with last output lines; fuzz iterations; not done; deviations with reason.

## Process and executors
1. Call 1 (A1-A3): `combine-builder` sonnet/high. Conductor then runs `cargo test` for changed crates and clippy itself.
2. Call 2 (A4-A5): `combine-builder` sonnet/high (persistence order and hostile parsing are critical).
3. `combine-verifier` (sonnet/low): all criteria.
4. `combine-security` (opus/high), once on the full stage diff: decisions 1-5, 8-11; token format and parser; ADDR_INFO; persistence order of seq; v1->v2 migration; U6 v6 type guard; A3 knock path.
Critical (security review required): A1 `classify`/`observe`/`publishable`, A2 entirely, A3, A4 seq/persistence/apply/plaintext v2. Not critical: texts, `usable` ordering.

## Requirements for other stages (not implemented here)
- **Stage 13 (connection):** every ~2 s call `probe_route_sources`, build `LocalSnapshot` with `transport.local_addrs()`, `own.set_local`; on `true`: `transport.reknock()`, redo port mapping (security review 8 items 1-3) then `set_gateway`, reconnect friends. After every authenticated friend connection: connecting side `exchange_addr_info`, accepting side dispatches on `STREAM_ADDR_INFO` -> `answer_addr_info`; 5 s timeout; at most 4 ADDR_INFO streams per minute per connection; never on guest (pending) pairs. With the result: `own.observe` only if `book.is_active`; `book.apply_addr_update` (ignore `StaleSeq`, `RateLimited`); `book.note_contact(pair, conn.remote_addr())`. Keep in memory per friend the last sent `(PublishSet, IssuedAddrUpdate)`; issue a new update only when `own.publishable(PublishCtx::for_connection(remote))` differs; re-send on live connections when it changes, at most once per 10 s per friend. `forget_reporter` on block/remove. Dial `book.usable_addrs`; attempts to `hint` addresses rate-limited (proposal: 1 per 30 s per address, stop after 5 failures until a newer update). Map `NatView` to `NoDirectPath` messages (CGNAT; symmetric: the symmetric side must call). Show `NEED_TOKEN_TEXT` when all attempts failed and `findability == NeedToken`. Invite token addresses = `own.publishable(ctx).socket_addrs()` (LAN only by user choice); B's addresses reach A through the first ADDR_INFO after friendship. Own IPv6 is published only if the transport listens on IPv6.
- **Stage 16:** the two network items under "Not verified"; EDM detection with two friends; a lying-friend hint scenario (victim receives only rate-limited attempts).
- **Stage 17:** libFuzzer targets for address update and ADDR_INFO; friends-file generation counter (rollback of `last_addr_seq`/`addr_seq_out`); logs without IPs.
- **Stage 18:** paste of `CHA1` tokens; per-friend "send address token" (`issue_addr_update` -> `text()`), with T8 warning ("мессенджер увидит ваш IP") and a "same network" checkbox; show `NO_PUBLIC_ADDR_TEXT` on `NoAddresses`; messages for `StaleSeq` ("токен уже применён или устарел") and `BadAddrUpdate` ("токен не подходит ни к одному другу или повреждён").
- **THREAT_MODEL (conductor, after acceptance):** T2: N6 amplification residual and conflict withholding; T5: time-floor seq and rollback interaction; T8: EUI-64 never published, all IPv6 short-lived.

## For the owner (кратко, по-русски)
- Адреса друзей хранятся с источником и временем; IPv6 всегда считаются короткоживущими (сутки), адреса, выдающие MAC (EUI-64), никогда не отправляются.
- При смене сети программа заново «стучится» по живым соединениям с того же порта (проброс порта не ломается) и после проверки ключа пары сообщает друзьям новые адреса.
- Токен обновления адреса: отдельный на каждого друга, подписан ключом этой пары, привязан к обоим ключам пары (к другой паре не подходит), номер только растёт (старый не примется); номер растёт и после восстановления списка из старой копии, если часы не ушли назад.
- Адрес «как меня видит друг»: по вашему решению Н6 хватает одного друга; дополнительно, если два друга видят нас по-разному, такой адрес не рассылается. Остаток: друг-лжец может направить попытки остальных друзей на чужой адрес (частота попыток ограничивается на этапе 13).
- Адреса одних друзей другим не попадают никогда: подписать можно только набор собственных адресов, это проверяет компилятор.
- Если постоянного адреса нет ни у вас, ни у друга, программа прямо скажет, что нужен токен обновления адреса.

## Open questions for the owner
None genuinely contested. Decision 5 (withholding the observed address when two friends contradict each other) is stricter than N6 only on contradiction; the owner may veto it (recommendation: keep).
