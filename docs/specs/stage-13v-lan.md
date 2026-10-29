# SPEC 13в: LAN discovery (U9), own beacon          criticality: КРИТИЧНЫЙ (parts L1-L4; L5 partly)

Author: combine-architect (opus), 2026-10-28, revision 1. Labels: [P] verified by me in the source (file:line); [V] architect's inference; [D] from memory, not re-checked; [NP] not verified. **Nothing was run.** Web was not available: every statement about RFCs, OS socket behaviour and crates.io is [D] and has a check (stand row, manual item or conductor command).

**New:** one path crate `chervo-lan`. **No new external package:** its external normal deps are `socket2 =0.6.5` and `getrandom` (workspace), both already in `Cargo.lock`. One new edge `chervo-identity -> ring` (workspace `=0.17.14`, already in the product tree through `chervo-friends`, `chervo-transfer`, quinn) for ChaCha20-Poly1305. `chervo-connect` never depends on `chervo-lan` (trait in `chervo-addr`, as UPnP in 13a).

Goal: two friends' computers in one home LAN find each other without any address in the book: a computer in mode «сообщать о себе» periodically multicasts a short beacon that only its friends can recognise; a friend that hears it dials the sender's LAN address through the existing knock + QUIC + Noise KK. An outsider learns only «here runs Червоточина» and cannot link the device across networks. Owner context: release 1 includes 13в (`docs/OWNER_DECISIONS.md:172`); private friend addresses expire after 24 h (`:129`, `chervo-addr/src/book.rs:15-18` [P]).

Read: this file; `docs/specs/stage-13-connect.md` (Decisions 5, 6, 12; "Candidates"; "Limiter"); `docs/specs/stage-13a-upnp.md` (Decisions 2, 4, 6; U0; `net.rs`); `docs/specs/stage-18-gui.md` §2.1 A1-A4, §2.3, §4.2; `crates/chervo-identity/src/{knock.rs,kk.rs:50-90,lib.rs}`; `crates/chervo-friends/src/vault.rs:1-80` (ring AEAD pattern); `crates/chervo-addr/src/{lib.rs,mapper.rs,class.rs}`; `crates/chervo-connect/src/{plan.rs,engine.rs:365-515,655-725,855-895,1077-1215,gateway.rs,watch.rs}`, `src/tests/{src_guard,kit}.rs`, `tests/engine_net.rs`; `crates/chervo-upnp/src/{lib.rs,net.rs,limits.rs}`, `src/tests/{fuzz,src_guard}.rs` (patterns); `crates/chervo-core/src/node/{mod.rs,network.rs,settings.rs,events.rs,views.rs}`, `tests/{layout,features_guard,redaction}.rs`; `crates/chervo-transfer/examples/node16.rs`; `tools/netns/lib16.sh`; `fuzz/Cargo.toml`. Search nothing else.

## Scope
| Item | Here | Note |
|---|---|---|
| Beacon format, keys from the pair secret, sender, receiver, limits, fuzz | yes | L1-L3 |
| Candidate from a beacon into dialing, priority, events | yes | L4 |
| Mode setting, node API, CLI command, GUI settings section, texts | yes | L5 |
| netns stand | yes | L6 (owner's Linux machine) |
| Standard mDNS / DNS-SD, port 5353, responder, queries | **no** | decision 1, owner Q2 |
| IPv6 (ff02::1, link-local scope ids) | **no -> stage 13г «приём по IPv6»** | transport listens on IPv4 only (13 scope table) [P] |
| Persisting LAN-found addresses | no | after a connection the existing `Contact` record does it (24 h) |
| Switching a live internet connection to the LAN path | no | |

## Decisions (rationale)
1. **Own beacon, not mDNS/DNS-SD.**
   | | mDNS/DNS-SD (crate, e.g. `mdns-sd`) | own UDP multicast beacon |
   |---|---|---|
   | Packages | new crate + its tree (by memory: flume, if-addrs, `log` [D]; product has no `log` today, T12 L3) | none new |
   | Hostile input | full DNS message parser of a third party sees **all** mDNS traffic of the LAN (printers, TVs) | one fixed 430-byte format, exact length, O(1) table lookups |
   | Port | 5353 shared with the OS responder: needs `SO_REUSEPORT` on macOS = socket2 feature `all` (`socket2-0.6.5/src/sys/unix.rs:2237-2247` [P]), forbidden since 13a | own port, `SO_REUSEADDR` only (`socket.rs:1125`, no `all` [P]) |
   | Privacy | service type `_x._udp` names the app anyway; crates announce the hostname and answer queries [D] | no name, no responder, listener silent |
   | Interop | discoverable by other mDNS tools (no benefit for us) | none needed: only our app reads it |
   Conclusion: own beacon. BRIEF 5 item 1 says «LAN (mDNS)»; this is a change of method, not of the requirement, so it is owner Q2 (CORE 2). If the owner picks mDNS, this spec stops and the conductor first runs the crate checks in "Commands for the conductor".
2. **Two roles, listener silent.** Mode `Off | Listen | Announce` (`Announce` also listens). `Listen` sends nothing at all; it only receives beacons and, on a match, dials that friend (the dial is the usual knock + QUIC to the friend's LAN address). `Announce` multicasts beacons. Default and consent: owner Q1; recommendation **`Listen` by default, `Announce` only by explicit user choice per device** (hint: home desktop yes, laptop no). Analogy to UPnP «свой роутер»: nothing that announces us is on by default. We cannot recognise "my network" without OS route/SSID APIs (`unsafe` forbidden, 13a decision 4) [P doc], so `Announce` applies in every network whose default-route IPv4 is private; the text says so.
3. **Link-local only.** Destination `224.0.0.1:LAN_PORT` (all-hosts group): every host is a member, no IGMP report is ever sent for it, so a `Listen` socket is invisible on the wire (RFC 2236 §6, RFC 3376 [D]; stand row LAN2 checks 0 IGMP). 224.0.0.0/24 is never forwarded by routers (RFC 5771 [D]); in addition `IP_MULTICAST_TTL 1`, `IP_MULTICAST_IF = own IP`, loop off (`socket.rs:1546,1574,1604` [P]). Only the default-route interface is used: own IP = `RouteSources.v4` of the existing probe (13a decision 4a), class `Private` only (Global = ISP segment, Shared = CGNAT/overlay: never announce). Other interfaces are not enumerated (std cannot, no new crate). `LAN_PORT` = 45817 [NP: the conductor checks it against the IANA registry before Call 2; if assigned, 46931, then 47411]; outside 49152-65535 so it never equals our random listen port (`chervo-core/src/node/mod.rs:150-157` [P]).
4. **Beacon crypto: library primitives only, same construction family as the reviewed knock** (`chervo-identity/src/knock.rs:3-6,112-136` [P]).
   - `ss = X25519(our pair secret, friend's pair public)`; contributory check and "friend key = our key" -> error (as `knock_keys`).
   - Direction key `K(S→R) = BLAKE2s-MAC-256(key = ss, LAN_KDF_LABEL || pub_S || pub_R)`.
   - `K_id = BLAKE2s-MAC-256(K, LAN_IDKEY_LABEL)`, `K_aead = BLAKE2s-MAC-256(K, LAN_AEADKEY_LABEL)` (separate keys per primitive).
   - Window `w = now_unix / 30` (corrected clock of the engine, as the knock). `id(w) = first8(BLAKE2s-MAC-256(K_id, LAN_ID_LABEL || w_be8))`.
   - Slot (26 B) = `id(8) || ct(2) || tag(16)`, `(ct, tag) = ChaCha20-Poly1305(K_aead, nonce12).seal(pt = listen_port_be16, aad = HDR(2) || w_be8 || src_ipv4(4) || id(8))` via `ring::aead` (`ring-0.17.14/src/aead.rs:29-36` [P], pattern `chervo-friends/src/vault.rs:5-44` [P]).
   - Datagram (430 B, fixed) = `ver = 0x01 || reserved = 0x00 || nonce(12, random per datagram) || slot × 16`. Unused slots: 8-byte label `first8(BLAKE2s-MAC(R, "chervotochina/v1/lan-pad\0" || w_be8 || k))` (k = index of the unused slot in the datagram, `R` = random 32-byte key made at service start and at every (re)opening of the sockets, in memory only, never on disk; without `R` nothing is sent) followed by 18 random bytes, new in every datagram like the ciphertext and tag of a real slot (whose nonce changes). So inside one 30 s window all 16 labels of a datagram, real and unused, are constant and an observer cannot tell a real slot from an unused one or count real friends by comparing two datagrams of a series (security review 13в, MEDIUM). Slot order shuffled per datagram. One slot per Active pair; ≤ 16 pairs per datagram, ≤ 4 datagrams per round, more than 64 pairs rotate between rounds.
   - Receiver: table `id -> (pair, w)` for `w-1, w, w+1` and every Active pair (recv direction); per slot one hash lookup; only on a hit `open` with `aad` built from the **datagram's source IP**; port must be ≠ 0. A hit gives `(pair, src_ip:port)`.
   - Properties [V; review by security]: no key, name, pair id or port in clear; ids rotate every 30 s and are per pair and direction; forging needs `ss`; a slot replayed from another IP fails AEAD (src IP in aad); a replay from the same (spoofed) IP within ≤ 90 s repeats true information; nonce reuse under one `K_aead` is a 96-bit random collision; a third friend C of both A and B cannot compute A-B ids. No replay cache is needed (decision 6).
5. **What a beacon still reveals** (T20): «Червоточина runs at this IP/MAC», the bucket `⌈n/16⌉` of Active friends (datagrams per round), the round timing (30 s ± 5 s), and linkability of the ids within one 30-60 s window (a device that changes network inside a window). Holders of the pair secret (the friend; malware with our keys, T10) recognise us in any network where we announce.
6. **Receive rules and limits (hostile input).** First the O(1) source-class check without parsing (IPv6, v4-mapped, anything not `Private`, own interface addresses are dropped; conductor's decision, security review 13в: a flood from public addresses must not use up the shared bucket and starve LAN reception), then the global token bucket `LAN_RX_RATE` 32 datagrams/s, burst 64, before any parsing; per source IP ≤ 16 per 10 s, map ≤ 256 IPs (oldest evicted); exact length; header bytes; source class `Private` and ≠ own IP; ≤ 16 lookups; AEAD only on an id hit; one sighting per pair per datagram; sightings queue ≤ 64, one per pair (newest wins). A sighting only adds a dial candidate; dials go through the existing limiter as **strict** (≤ 1 dial per IP per 32 s in any mode, `plan.rs:106-113`, T1 [P]). So a replay or a lying friend on the LAN can cause at most what T1 already accepts.
7. **Engine integration and priority.** The engine keeps an in-memory `lan_seen: PairId -> (SocketAddrV4, Instant)` for Active pairs without a live connection, TTL `lan_seen_ttl` 120 s, never written to the book. In `plan_dials` the LAN candidate is put **first** (the quinn race starts address *i* at `i × 250 ms`, 13 decision 3 [P]), deduplicated against book entries (a book entry `Contact` with the same address keeps non-strict), cap 8 unchanged. A sighting opens **no fast window and resets no limiter** (it is remote data, 13 decision 5). After the connection `note_contact` stores the address as today, `PathKind::Lan` (`plan.rs:150-152` [P]). Guests (invites) are never in the beacon set and never dialed from a sighting.
8. **Sender schedule.** Only in `Announce`, with a private own IP, a non-zero IPv4 listen port and ≥ 1 Active pair. Burst of 3 rounds at +1, +3, +7 s after: start, own address change, change of the pair set; then every 30 s ± 5 s (random jitter). Hard budget 24 datagrams per 60 s.
9. **No new wire format elsewhere**: knock, KK, ADDR_INFO, invite, friends file unchanged. `AddrSource::Lan` exists (`chervo-addr/src/lib.rs:38-47`, `chervo-friends/src/plain.rs:53-75` [P]) and stays unused.
10. **IPv6** is a separate stage (section "Stage 13г").

## Facts from the source
1. `plan.rs:37-42, 75-77` LAN-first stable sort; `:106-113` strict = hint or not `Contact`; `:129-140` `select` with limiter `take(addr, strict, now)`; `MAX_DIAL_ADDRS = 8` `:12` [P].
2. `engine.rs:420-455` `publish_once`: `book.kx_peers(store)` then guests appended; `:395-418` `drop_stale_pairs`; `:655-713` `plan_dials` (Active, no key problem, not live/in flight, `min_redial`); `:860-893` `tick` [P].
3. `watch.rs:71-85` `on_own_change` (reknock, `reset_all`, fast window, `gw.wake()`); `gateway.rs:65-82` `request_of` (route v4 `Private`, listen v4 port ≠ 0); `gateway.rs:213-223` `attach_mapper` (`OnceLock`, second call `Internal`) [P].
4. `src/tests/src_guard.rs:51-82,124-130`: no socket words, no `mdns|upnp|igd|stun|rendezvous`, manifest without `socket2` [P].
5. `knock.rs:74-136`: BLAKE2s-MAC helpers, `knock_keys` contributory and equal-key checks; `KnockKeys` zeroizing, no Clone/PartialEq/Hash/Deref (compile_fail docs) [P]. `KxPeer { pair, ours: Arc<PairKx>, theirs }`, `pair()` (`kk.rs:54-74`) [P].
6. `chervo-identity/Cargo.toml:8-15`: no `ring` yet; workspace `ring =0.17.14`, features `alloc` (`Cargo.toml:65`) [P].
7. socket2 0.6.5: `join_multicast_v4` (`socket.rs:1312`), `set_reuse_address` (`:1125`), `set_multicast_if_v4` (`:1546`), `set_multicast_loop_v4` (`:1574`), `set_multicast_ttl_v4` (`:1604`) not behind `all`; `set_reuse_port` needs `all` [P].
8. Node: `connect_config` `mod.rs:170-177`; mapper attached only with routers `mod.rs:472-482`; `sync_mapper` pattern `network.rs:90-110` [P].
9. No mDNS crate in the local registry (glob `*mdns*` empty, 2026-10-28) [P].

## Do (four builder calls; verify each before the next, CORE 5)
- **Call 1 (L1 + L2), builder sonnet/high.** `cargo --version`, `rustc --version` (1.99.1); `BASE=$(git rev-parse HEAD)`; check facts 1-7 by `grep -n`, mismatch -> STOP. L1 `chervo-identity/src/lan.rs`; L2 `crates/chervo-lan` pure modules `limits, wire, table, rate, texts, error` + unit tests + fuzz smoke; `chervo-addr/src/lan.rs` (types and trait).
- **Call 2 (L3), builder sonnet/high.** Conductor first confirms `LAN_PORT` (command below). `net.rs` (only socket code), `service.rs`, `examples/lan_probe.rs` (`join-check` sends nothing: open the listen socket, join, report OK/error; `listen SECS`; `announce-test` only with `--i-know`), crate `src_guard`. Run `cargo run -p chervo-lan --example lan_probe -- join-check` on the Windows dev box; error -> STOP (decision 3 then needs the conductor).
- **Call 3 (L4), builder sonnet/high.** `chervo-connect/src/lan.rs`, engine hooks, events, tests, guard update, `tests/engine_net.rs` LAN test.
- **Call 4 (L5 + L6), builder sonnet/high for node and settings, the same call does CLI/GUI at medium care.** Node, settings key, CLI, GUI section, `node16 --lan`, `fuzz/fuzz_targets/lan_beacon.rs`, `tools/netns/stage13v.sh` (**not runnable on Windows**: write, `bash -n`, shellcheck if present).

## Interface (exact)
All `Debug` of types with addresses, ports, ids or keys print `"TypeName(..)"`. Errors without `String`. No logging, no printing (lint block `chervo-identity/src/lib.rs` style: no unwrap/expect/indexing/panic/print).

### L1. chervo-identity `src/lan.rs` (re-exported)
```rust
pub const LAN_WINDOW_SECS: u64 = 30;
pub const LAN_ID_LEN: usize = 8; pub const LAN_SLOT_LEN: usize = 26; pub const LAN_NONCE_LEN: usize = 12;
pub const LAN_HDR: [u8; 2] = [0x01, 0x00];
pub const LAN_KDF_LABEL: &[u8] = b"chervotochina/v1/lan-key\0";
pub const LAN_IDKEY_LABEL: &[u8] = b"chervotochina/v1/lan-id-key\0";
pub const LAN_AEADKEY_LABEL: &[u8] = b"chervotochina/v1/lan-aead-key\0";
pub const LAN_ID_LABEL: &[u8] = b"chervotochina/v1/lan-id\0";
pub struct LanKeys { send_id, send_aead, recv_id, recv_aead: Zeroizing<[u8; 32]> } // no Clone/PartialEq/Hash/Deref, Debug "LanKeys(..)"
impl KxPeer { pub fn lan_keys(&self) -> Result<LanKeys, IdentityError>; }   // AuthFailed as knock_keys
impl LanKeys {
    pub fn send_id(&self, window: u64) -> [u8; LAN_ID_LEN];
    pub fn recv_id(&self, window: u64) -> [u8; LAN_ID_LEN];
    /// port 0 -> Err(AuthFailed). aad = LAN_HDR || window_be || src.octets() || id.
    pub fn seal(&self, window: u64, nonce: &[u8; LAN_NONCE_LEN], src: Ipv4Addr, port: u16) -> Result<[u8; LAN_SLOT_LEN], IdentityError>;
    /// Length, id (== recv_id(window)), AEAD; None on any failure or port 0.
    pub fn open(&self, window: u64, nonce: &[u8; LAN_NONCE_LEN], src: Ipv4Addr, slot: &[u8]) -> Option<u16>;
}
```
`LessSafeKey` is built per call from `Zeroizing` bytes (ring does not zeroize its key) [D]. MACs only through `blake2::Blake2sMac256` as in `knock.rs`.

### L2. chervo-addr `src/lan.rs` (no socket code; re-exported)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum LanMode { Off, Listen, Announce }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum LanStatus { Off, NoPrivateRoute, PortBusy, Listening, Announcing, Failed }
#[derive(Clone, Copy, PartialEq, Eq)] pub struct LanLocal { pub own: Ipv4Addr, pub listen_port: u16 }  // Debug redacted
#[derive(Clone, Copy, PartialEq, Eq)] pub struct LanSighting { pub pair: PairId, pub addr: SocketAddrV4 } // Debug redacted
pub trait LanDiscovery: Send + Sync {
    fn set_local(&self, local: Option<LanLocal>);   // None: stop sending and listening, close sockets
    fn set_peers(&self, peers: Vec<KxPeer>);        // Active friends only; keys derived on the service thread, not here
    fn take_sightings(&self) -> Vec<LanSighting>;   // non-blocking, ≤ 64, one per pair
    fn status(&self) -> LanStatus;
    fn shutdown(&self);                             // non-blocking signal; thread exits ≤ 250 ms
}
```

### L2/L3. chervo-lan (deps: chervo-identity, chervo-addr, `socket2 =0.6.5` default-features false, getrandom)
**limits.rs** (all used): `LAN_GROUP = 224.0.0.1`, `LAN_PORT`, `DGRAM_LEN = 430`, `RECV_BUF = 512`, `SLOTS = 16`, `MAX_DGRAMS_PER_ROUND = 4`, `MAX_PEERS = 1024`, `INTERVAL = 30 s`, `JITTER = 5 s`, `BURST = [1 s, 3 s, 7 s]`, `SEND_BUDGET = 24 / 60 s`, `RX_RATE = 32/s`, `RX_BURST = 64`, `PER_IP = 16 / 10 s`, `IP_MAP = 256`, `MAX_SIGHTINGS = 64`, `READ_TIMEOUT = 250 ms`, `FAIL_RETRY = 60 s`.
**wire.rs** (pure): `build(peers: &[(PairId, &LanKeys)], window, src: Ipv4Addr, port, round: u64) -> Result<Vec<[u8; DGRAM_LEN]>, LanError>` (rotation by `round` when > 64 pairs; random padding and shuffle from getrandom; RNG failure -> error, nothing sent); `parse(dgram: &[u8], src: SocketAddr, own: Ipv4Addr, table: &IdTable, policy: SrcPolicy) -> Vec<LanSighting>` (order: length, header, src rules, slots).
**table.rs**: `IdTable` built from `(PairId, LanKeys)` for windows `w-1..=w+1`; rebuilt on window or peer change; an id present for two pairs is removed (fail closed).
**rate.rs**: token bucket + per-IP window map, saturating arithmetic.
**net.rs** (only socket code): listen socket: socket2 UDP v4, `set_reuse_address(true)`, bind unix `(LAN_GROUP, LAN_PORT)`, Windows `(0.0.0.0, LAN_PORT)`; `join_multicast_v4(LAN_GROUP, own)`; read timeout `READ_TIMEOUT`; `std::net::UdpSocket::from(sock)` for safe `recv_from`; `AddrInUse` -> `PortBusy`. Send socket: bind `(own, 0)`, `set_multicast_if_v4(own)`, `set_multicast_ttl_v4(1)`, `set_multicast_loop_v4(false)`; destination only `(LAN_GROUP, LAN_PORT)` (tests: `Net.target`). Sealing uses the send socket's bound IP.
**service.rs**: `pub struct LanBeacon`; `impl LanBeacon { pub fn new(mode: LanMode, now_unix: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self; pub fn set_mode(&self, m: LanMode); }` (no socket and no thread until mode ≠ Off **and** `set_local(Some)`); `impl LanDiscovery for LanBeacon`. One std thread: loop { shutdown? ; apply mode/local/peer changes (rebind on local change, close all on Off/None); rebuild table on window change; send due round; `recv_from` until timeout; per datagram: rate -> parse -> push sightings }. Status per decision 2/3. Errors other than `AddrInUse` -> `Failed`, retry after `FAIL_RETRY` or on `set_local`.
`pub fn status_text(LanStatus) -> &'static str; pub fn mode_text(LanMode) -> &'static str;` `#[cfg(any(test, feature = "fuzzing"))] #[doc(hidden)] pub fn fuzz_beacon(bytes: &[u8])` (fixed table of 3 test pairs). `#[cfg(any(test, feature = "test-net"))] #[doc(hidden)] pub fn new_for_tests(mode, now_unix, TestNet { target: SocketAddrV4, bind: Ipv4Addr, allow_loopback: bool, interval: Duration })`.

### L4. chervo-connect
- `ConnectConfig` += `lan_seen_ttl: Duration` (120 s).
- `Engine` += `pub fn attach_lan(&self, l: Arc<dyn LanDiscovery>) -> Result<(), ConnectError>` (second call `Internal`; immediately `set_local(lan_local(st))` and `set_peers(active friend peers)`), `pub fn lan_status(&self) -> Option<LanStatus>`.
- `EngineEvent` += `LanStatusChanged { status: LanStatus }` (emitted by `tick` once per change).
- New module **`lan.rs`** (critical): `lan_local(st)` = `request_of(st)` mapped to `LanLocal`; hooks: `publish_once` after a successful `set_peers` -> `l.set_peers(peers before guests)`; `drop_stale_pairs` after success -> same with kept non-guest peers; `on_own_change` -> `l.set_local(lan_local)`; `tick` -> `take_sightings()`, keep only Active, no key problem, not live -> `lan_seen` insert; prune `lan_seen` by TTL and in `cleanup_inactive`; `plan_dials` friend branch: LAN candidate first (decision 7); `Engine::shutdown` -> `l.shutdown()`.
- `src_guard`: `LanDiscovery` and `take_sightings(` only in `lan.rs`; all other rules unchanged (the word `mdns` stays forbidden). Manifest: no `chervo-lan` in normal deps (dev-dependency with `test-net` allowed).

### L5. chervo-core, CLI, GUI
- Settings key `lan=off|listen|announce` (once; other value -> `SettingsCorrupt`); absent -> default of owner Q1. `Node::set_lan_mode(LanMode) -> Result<(), NodeError>` (persist, then `sync_lan` like `sync_mapper`: create `LanBeacon` and `attach_lan` on first non-Off, else `set_mode`); `Node::lan_status() -> Option<LanStatus>`; `SettingsView.lan_mode`; `NodeEvent::LanStatusChanged { status }`; `set_port(LAN_PORT)` -> `NodeError::PortInUse`. `Node::shutdown`: after `engine.shutdown()`, wait ≤ 1 s for the LAN thread. `connect_config` comment updated (only `lan_seen_ttl` default; the mode lives in `LanBeacon`, like `UpnpSettings`).
- `chervo-core/tests/layout.rs` lists `chervo-lan`; `features_guard.rs`: no product manifest enables `test-net`.
- CLI REPL: `lan` (status and mode texts), `lan off|listen|announce`.
- GUI settings section «Локальная сеть»: three choices with `mode_text`, status line `status_text`, no other control. Hint for an expired LAN friend (18 §4.2 item 9) += «или включите „Сообщать о себе“ на домашнем компьютере».
- Texts (`chervo-lan/src/texts.rs`, Russian, no placeholders):
  - `MODE_OFF_TEXT = "Не искать друзей в локальной сети."`
  - `MODE_LISTEN_TEXT = "Только слушать: программа узнаёт друзей, которые сообщают о себе в этой сети, и сама ничего в сеть не рассылает."`
  - `MODE_ANNOUNCE_TEXT = "Слушать и сообщать о себе: раз в полминуты программа рассылает в локальную сеть короткое сообщение, по которому вас узнают только ваши друзья. Имени, ключей и номера порта в нём нет, но другие устройства сети видят, что здесь работает Червоточина. Сообщение получат все устройства этой сети, в том числе виртуальные сети и VPN с частными адресами. Включайте на компьютере, который стоит дома. На ноутбуке, который бывает в кафе и гостиницах, оставьте «Только слушать»."`
  - `STATUS_NO_PRIVATE_ROUTE_TEXT = "Поиск в локальной сети не работает: у компьютера нет частного адреса домашней сети."`, `STATUS_PORT_BUSY_TEXT = "Поиск в локальной сети недоступен: его порт занят другой программой."`, `STATUS_LISTENING_TEXT = "Слушаем локальную сеть."`, `STATUS_ANNOUNCING_TEXT = "Сообщаем о себе друзьям в локальной сети."`, `STATUS_FAILED_TEXT = "Поиск в локальной сети не удалось запустить. Программа попробует снова."`, `STATUS_OFF_TEXT = MODE_OFF_TEXT`.

### L6. Stand `tools/netns/stage13v.sh` (reuse `lib16.sh`; node `node16 --lan off|listen|announce`, `--dump-pubkeys FILE` writes hex of this node's pair public keys, example only)
Bridge `br0` 192.168.50.0/24 with A, B, observer O; router R to `br1` with C. Rows: **LAN1** A announce, B listen, books share the pair, A restarted on a new port (B's addresses stale) -> B `Connected{Lan}` ≤ 40 s. **LAN2** A and B listen -> no connection by LAN in 70 s; capture: 0 datagrams to `LAN_PORT`, 0 IGMP from A and B. **LAN3** O captures 10 min of A's beacons: every payload 430 B; no pubkey from `--dump-pubkeys`, no 4-byte own IP, no hostname bytes; listen port bytes not at a constant offset; no 8-byte id repeated across windows; the 16 slot labels (real and unused) of the j-th datagram of a round are the same in every round of one window; datagrams per round = ⌈n/16⌉ (n = 1, 17). **LAN4** O floods 100 000 random 430-byte datagrams and replays captured beacons from its own IP -> 0 packets B->O, B still finds A, B's CPU recorded. **LAN5** A leaves (`ip addr del`), O replays A's beacon with spoofed source = A's old IP -> B dials that IP ≤ once per 32 s. **LAN6** C (behind R) in listen -> 0 beacons received. **LAN7** A with a non-private default-route address -> 0 beacons sent. **LAN8** A's address changes -> burst from the new IP ≤ 4 s (decision of the conductor: the engine notices an address change every 2 s and the burst follows 1 s later, so 2 s cannot be met; `LAN8_BURST_S`), B reconnects. **CAPTURE** A: destinations ⊆ {224.0.0.1:LAN_PORT, friend addresses}; DNS 0; nothing to 5353 or 1900. **HOSTSAFE** as stand 16.

## Do not
- No mDNS/DNS-SD, port 5353, responder or query; no broadcast address; no IPv6 socket; no interface enumeration; no `unsafe`; no new package (only `chervo-lan` in the lock diff); no socket2 `all`; no tokio in `chervo-lan`.
- No hostname, user name, device name, pair id, public key or port in clear anywhere in a datagram; no persistent identifier; no beacon slot for guests.
- No change of knock, KK, ADDR_INFO, invite, friends file, `SecretStore`; LAN addresses never written to the book directly.
- A sighting never opens a fast window, resets the limiter, triggers `reknock` or ADDR_INFO.
- No logging; no `Display` of datagram bytes.

## Untrusted input
Every datagram on `LAN_PORT` (LAN hosts, anything routed to a Windows socket bound to 0.0.0.0) and every byte of it, including the source address. Order of checks (decision of the conductor, security review 13в): source class (IPv6, not `Private`, own address) first, O(1) and without parsing, then the global bucket and the per-IP window, then length, header and slots. Hostile table:
| Input | Expected |
|---|---|
| over rate (global or per IP) | dropped before parsing, counter |
| length ≠ 430 (0, 1, 13, 14, 429, 431, 512 = buffer full, 1472) | drop |
| version ≠ 1, reserved ≠ 0 | drop |
| source own IP, loopback, 0.0.0.0, 255.255.255.255, multicast, 169.254/16, 100.64/10, global, IPv6 or v4-mapped | drop (test policy may allow loopback) |
| random slots | 0 sightings, 0 AEAD calls |
| real slot replayed from another IP | id hit, AEAD fails, 0 sightings |
| real datagram replayed, same source, ≤ 1 window later | same sighting as the original; dial bounded by the strict limiter |
| ids of `w±2` | no hit |
| any bit flipped in nonce, header, id, ct, tag | 0 sightings for that slot |
| decrypted port 0 | drop |
| same pair twice in one datagram | one sighting |
| id colliding between two of our pairs | both removed from the table |
| receive errors | counted; ≥ 64 per second -> sleep 1 s |

## Tests (exact names)
L1 (`chervo-identity/src/tests/lan.rs`): `lan_keys_directional` (A.send_id = B.recv_id, A.send_id ≠ A.recv_id), `lan_seal_open_roundtrip`, `lan_open_rejects_other_src_ip`, `lan_open_rejects_other_window`, `lan_open_rejects_other_nonce`, `lan_open_rejects_every_bit_flip` (26 × 8 + header), `lan_seal_port_zero_rejected`, `lan_open_port_zero_rejected`, `lan_keys_equal_pubkeys_rejected`, `lan_labels_distinct_from_knock`, `lan_golden_vector` (fixed secrets, window, nonce, IP, port -> fixed 26 bytes), `lan_keys_debug_redacted`; compile_fail doctests (no Clone/PartialEq/Hash/Deref); `fuzz_smoke_lan_open`.
L2 (`chervo-lan/src/tests/{wire,table,rate}.rs`): `wire_exact_len_any_n` (n = 1, 5, 16), `wire_n17_two_datagrams`, `wire_n65_rotates`, `wire_slots_shuffled`, `wire_bad_len_table`, `wire_bad_header`, `wire_src_class_table`, `wire_v6_src_dropped`, `wire_random_no_sighting`, `wire_replay_other_ip_rejected`, `wire_replay_same_ip_same_info`, `wire_window_pm2_rejected`, `wire_dup_pair_once`, `wire_port_zero_rejected`, `beacon_contains_no_identifiers` (1000 datagrams: no 32-byte public key, no pair id, no own IPv4, no hostname from `COMPUTERNAME`/`HOSTNAME` if ≥ 4 bytes), `beacon_unlinkable_across_windows` (no equal 8-byte slot between windows w and w+1 and no equal nonce), `table_collision_fail_closed`, `table_rebuild_on_window`, `rate_global_bucket`, `rate_per_ip`, `rate_map_capacity`, `rate_saturating`, `texts_present`, `debug_redacted`; fuzz `fuzz_smoke_beacon` (random bytes, mutations of valid datagrams; property: no panic; random input gives 0 sightings; a flipped byte never yields a different port).
L3 (`chervo-lan/src/tests/svc.rs`, loopback with `TestNet` unicast): `svc_off_opens_no_socket` (the port stays bindable), `svc_listen_sends_nothing` (recording socket: 0 datagrams in 3 s), `svc_no_local_sends_nothing`, `svc_no_peers_sends_nothing`, `svc_announce_burst_then_interval`, `svc_send_budget`, `svc_two_beacons_find_each_other`, `svc_rebind_on_local_change`, `svc_flood_bounded` (10 000 datagrams: parsed ≤ bucket, finishes < 2 s), `svc_port_busy_status`, `svc_sightings_bounded_dedup`, `svc_shutdown_fast` (≤ 250 ms + 50 ms slack); `#[ignore] multicast_real_lan`; `src_guard` (socket identifiers and `send_to` only in `net.rs`; `224, 0, 0, 1` and `LAN_PORT` literal only in `limits.rs`; no `lookup_host`, `to_socket_addrs`, `Command`, `std::process`, `tokio`, `unsafe`, `hostname`, `log::`, `tracing`; no `String` in `error.rs`).
L4 (`chervo-connect/src/tests/lan.rs`, fake `LanDiscovery` recording calls, paused time): `lan_not_called_without_attach`, `lan_attach_twice_rejected`, `lan_local_private_only` (public, CGNAT, no route -> `None`), `lan_local_on_own_change`, `lan_peers_active_only_no_guests`, `lan_peers_after_block_and_remove`, `lan_sighting_dials_first_and_strict` (next tick dials with the LAN address first; second sighting of the same IP within 32 s -> no dial to it), `lan_sighting_ignored_live_inactive_keyproblem`, `lan_sighting_no_fast_window_no_reset`, `lan_seen_expires`, `lan_sighting_not_persisted` (book unchanged until a connection, then one `Contact`), `lan_status_event_once`, `lan_shutdown_signalled`, `src_guard` (updated). `tests/engine_net.rs`: `engine_lan_finds_peer_after_port_change` (two quinn engines on 127.0.0.1, fake `RouteProbe` with a private route, `LanBeacon::new_for_tests` unicast; invite, then B rebuilt on a new port; A `Listen`, B `Announce` -> A connected ≤ 15 s, path `Lan`).
L5: `chervo-core` `settings_hostile_table` += rows (`lan=on`, `lan=` , duplicate `lan`, `lan=ANNOUNCE`), `settings_roundtrip` covers `lan`, `lan_off_no_socket`, `set_port_rejects_lan_port`, `events_debug_redacted` (new variant); `chervo-gui` model test `lan_mode_choice_persists`; CLI `repl_lan_command`.

Review round 1 additions (security review 13в): L1 `lan_pad_id_stable_and_golden`; L2 `beacon_window_labels_stable` (all 16 labels as a set are equal in datagrams of one window, tails differ), `beacon_pad_labels_rotate` (unused labels change with the window and with `R`), `rx_public_flood_does_not_starve_lan`; L3 `svc_pad_labels_stable_then_new_key_on_reopen`; L5 `lan_service_not_started_on_lan_port` (`port == LAN_PORT` from an old settings file: the settings parser still accepts it, the service is not started, status `PortBusy`); fuzz target `lan_beacon` with fixed keys and the corpus `fuzz/corpus/lan_beacon/` (test `fuzz_corpus_seed_opens`).

## Acceptance criteria (each by command; output in the report)
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '` prints exactly `+name = "chervo-lan"`
- [ ] `cargo tree -p chervo-lan -e normal | grep -Ei 'mdns|hickory|dns|tokio|if-addrs|netdev|pnet| log |tracing'; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'chervo-lan|chervo-upnp|socket2|quinn|rustls'; test $? -eq 1`
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-lan fuzz_smoke -- --nocapture` and `... -p chervo-identity fuzz_smoke_lan -- --nocapture` (iterations in output)
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-lan svc_ || exit 1; done`; `for i in $(seq 10); do cargo test -q --locked -p chervo-connect --test engine_net engine_lan_ || exit 1; done`
- [ ] `cargo test -p chervo-core --locked --test layout --test features_guard`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`; `cargo deny check`
- [ ] `bash -n tools/netns/stage13v.sh`; CI green (3 OS, supply-chain)
- [ ] Owner's Linux machine: `sudo tools/netns/stage13v.sh` all rows PASS; `cargo +nightly fuzz run lan_beacon -- -max_total_time=1200` 0 crashes (blocks release, not code acceptance).

## Where verified / Not verified
- Windows locally and CI: L1-L5 (pure code, loopback unicast, fake engine).
- Owner's Linux machine (netns): real multicast, 0 IGMP for 224.0.0.1, link-local scope, capture content, flood, replay.
- **Not verified here (write in the report):** reception of 224.0.0.1 on Windows and macOS between two real machines (join behaviour [D]); Windows Firewall for the second UDP port [D]; Wi-Fi access points that filter or convert multicast; VPN as default route (a tunnel with a private address would carry beacons to the VPN server [V]); RFC statements of decision 3 [D].

## Stop conditions
A fact above does not match; any new package or socket2 `all` is needed; `lan_probe join-check` fails on the Windows dev box; `ring` AEAD API differs from `vault.rs`; the crypto of decision 4 cannot be implemented exactly as written (do not improvise a variant); the engine would have to persist LAN addresses or change the friends file; a test unstable after two fix attempts; a criterion cannot be checked. Stop and report.

## Limit
At most 2 review-fix rounds, then report to the owner.

## Builder report (max 25 lines per call)
Changed files; criteria commands with last output lines; fuzz iterations; not done; deviations with reason; what could not run on Windows.

## Process and executors
Calls 1-4: `combine-builder` sonnet/high (CLI/GUI part of Call 4 is normal criticality). Conductor reruns tests and clippy after each call. `combine-verifier` (sonnet/low): all criteria. `combine-security` (opus/high) once on the full diff: decision 4 (keys, labels, aad, nonce, padding, shuffle), `open` constant-time path, decision 6 limits, src rules, sender gating (mode, private route, budget), listener silence, engine hooks (strict limiter, no fast window, guests excluded), guards, texts and default. Critical: L1, L2 `wire/table/rate`, L3 `net/service`, L4 `lan.rs`, L5 settings parser. Not critical: texts, GUI layout, example, stand script.

## THREAT_MODEL delta (conductor after acceptance): new T20, T1 line «Наблюдатель в LAN» updated
**T20. Поиск в локальной сети (маяк).** Шаг Ш1 (домашние ПК), Ш2 (ноутбук в чужой сети).
- **Актив:** несвязываемость устройства между сетями; граф друзей; порт прослушивания; наши наборы номера (не стучать на чужих); процессор.
- **Атакующие:** пассивный наблюдатель в LAN (кафе, гостевое устройство); активный хост LAN (подделка источника, повтор, поток); лгущий друг в той же LAN; держатель секрета пары (сам друг, вредонос T10).
- **Меры (эт. 13в, после приёмки):** режим «только слушать» ничего не шлёт, группа 224.0.0.1 без отчётов IGMP; маяк только в режиме «сообщать о себе» и только при частном адресе маршрута; в маяке нет ключа, имени, идентификатора пары и порта в открытом виде; идентификаторы слотов меняются каждые 30 с, по паре и направлению; порт зашифрован ChaCha20-Poly1305 (ring), адрес источника в AAD; подделка требует секрета пары; повтор с другого адреса отвергается; лимиты приёма до разбора; найденный адрес набирается строго (≤ 1 раза в 32 с на IP), без быстрого окна; гости не участвуют; адреса из маяка не сохраняются.
- **Остаётся:** факт «здесь работает Червоточина», IP и MAC отправителя, округлённое число друзей (⌈n/16⌉), ритм 30 с; связывание в пределах одного окна (смена сети за 30-60 с); друг и укравший ключи узнают нас в любой сети, где мы сообщаем о себе; лгущий друг в LAN — как T1 (≤ 1 набор в 32 с на IP); поток мусора отнимает только путь LAN (прочие пути работают); VPN с частным адресом как маршрут по умолчанию может унести маяк к серверу VPN [В]; оверлеи уровня L2 и mesh (ZeroTier, OpenVPN TAP и подобные) пересылают маяк всем участникам оверлея, как и виртуальные сети ВМ [В] (решение дирижёра, ревью безопасности 13в; в тексте режима «Сообщать о себе» об этом предупреждено); активный зонд на Windows видит режим «Только слушать»: приём на 0.0.0.0 не отвечает ICMP port unreachable на юникаст, порт 45817 по ответу не отличить от открытого [D] (кода не нужно, решение дирижёра); поведение Windows/macOS и точек доступа Wi-Fi не проверено.
T1 «Наблюдатель в LAN»: заменить на «маяк 13в: см. T20». «Что модель угроз НЕ покрывает»: убрать «поиск в LAN mDNS (13в)».

## Stage 13г «приём по IPv6» (separate small stage, own spec by architect; КРИТИЧНЫЙ: transport and knock)
Not part of 13в: it changes the transport socket and the knock admit table, not discovery. Content: node binds a dual-stack socket `[::]:port` with `set_only_v6(false)` (socket2, fact 13 of stage 13) and passes it to `QuinnTransport::from_socket`; knock send and admit normalise v4-mapped to V4 (13 scope table); `plan.rs` `family_ok` admits IPv6; `publishable` gives global IPv6 (temporary ones short-lived, EUI-64 never, T8); `NO_IPV6_TEXT` reworded; incoming through the home router's stateful firewall by simultaneous open; LAN beacon over `ff02::1` only if then requested. Tests: `::1` loopback race and knock, v4-mapped admit; stand rows IPv6 white, IPv6 behind a stateful firewall, dual-stack mixed; repeat G1/G2 for IPv6.

## Requirements for other stages
- **17 / release:** libFuzzer `lan_beacon` 1200 s; `SECURITY_REVIEW.md` «Этап 13в»; THREAT_MODEL T20 above; DECISION table row 4 note «свой маяк вместо mDNS».
- **18 manual checklist** += two real PCs in one Wi-Fi (Windows + other OS): B in «сообщать о себе», A in «только слушать»; change B's port in settings and restart; A connects by LAN ≤ 40 s.
- **16 / real networks:** home Wi-Fi access points (multicast filtering), Windows/macOS reception.

## Commands for the conductor (facts I could not check offline)
- Port: `curl -s https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv | awk -F, '$2=="45817"'` -> must print nothing (repeat for 46931, 47411 if needed).
- Only if the owner picks mDNS (Q2 б): `cargo info mdns-sd`; `cargo search mdns --limit 10`; in a scratch dir outside the repo `cargo new t && cd t && cargo add mdns-sd && cargo tree -e normal` (count packages, look for `log`, `if-addrs`, `flume`); read the repository `Cargo.toml`, `LICENSE`, last release date, open security issues, grep sources for `hostname` and `send_to`. Until then [D].

## Для владельца (кратко)
- Компьютер в режиме «сообщать о себе» раз в полминуты рассылает в домашнюю сеть 430 байт. В них нет ни имени, ни ключа, ни номера порта в открытом виде. Узнать «это мой друг» может только друг: метки считаются из секрета вашей пары и меняются каждые 30 секунд. Порт зашифрован, адрес отправителя проверяется. Подделать маяк без ключа пары нельзя. Повтор с чужого адреса отвергается.
- Режим «только слушать» не шлёт в сеть ничего. Программа узнаёт друга по его маяку и звонит ему обычным способом: стук, QUIC, проверка ключа. Подмена маяка в худшем случае даёт одну неудачную попытку не чаще раза в 32 с.
- Не mDNS, а свой маяк: без новых пакетов, разбор одного формата фиксированной длины. Стандартный mDNS дал бы чужой разборщик всего трафика сети и новые зависимости, а программу выдаёт всё равно (вопрос 2).
- Посторонний в сети видит только, что здесь работает Червоточина, IP и MAC отправителя и примерное число друзей (до 16, до 32…). Между сетями по маяку вас не связать.
- IPv6 — отдельный малый этап 13г после этого.
- Проверка: Windows и CI на петле; настоящий multicast, отсутствие IGMP, захват и поток мусора — стенд на Linux-машине владельца. Приём на Windows/macOS между двумя настоящими ПК не проверен.

## Вопросы владельцу
**В1. Умолчание и согласие.** (а) По умолчанию «только слушать»: программа ничего не рассылает, но находит друзей, которые сообщают о себе. «Сообщать о себе» вы включаете сами на нужном компьютере; действует в любой сети с частным адресом. (б) По умолчанию «слушать и сообщать» везде, где адрес частный. Так удобнее: два домашних ПК найдут друг друга без настройки. Минус: в кафе и гостинице чужие устройства увидят, что работает Червоточина, и примерное число ваших друзей. (в) Всё выключено по умолчанию, одна галочка. **Рекомендую (а).** При (а) двум домашним ПК нужна одна галочка на одном из них. Если на Windows приём через группу 224.0.0.1 не заработает и придётся взять отдельную группу, прослушивание станет заметно в сети. Тогда при (а) умолчание сменится на «выключено», это спросим отдельно.
**В2. Свой маяк вместо mDNS.** В BRIEF написано «LAN (mDNS)». (а) Свой короткий маяк, без новых пакетов. (б) Стандартный mDNS/DNS-SD через готовый крейт: новый пакет и его зависимости, чужой разборщик всего mDNS-трафика сети, общий порт 5353 с системной службой. Тип службы в анонсе всё равно выдаёт программу. (в) mDNS своим кодом: больше разбора без выгоды. **Рекомендую (а).**

## Дополнение 1: выбор интерфейса при VPN (2026-10-28)
Author: combine-architect, addendum to revision 1. Labels as at the top. **Nothing was run**; web unavailable. Status: proposal, takes effect only after owner answer В3.

### Finding and what it breaks
- Conductor, `route print` on the Windows dev box (fact, conductor's check): `0.0.0.0/0` via the home gateway metric 25 and via a tunnel adapter (VPN/proxy client, 172.18.x.x) metric 0; `224.0.0.0/4` also cheaper via the tunnel (256 vs 281). `probe_route_sources()` (`chervo-addr/src/probe.rs:55-71` [P]) returns 172.18.0.1, class `Private`, so `lan_local` (`chervo-connect/src/lan.rs:46-51` via `request_of`, `gateway.rs:65-82` [P]) passes it, and `net.rs:85,106` [P] join and send on the tunnel. Home neighbours never hear us; in `Announce` the beacon goes to the VPN client and maybe its server [V].
- Other tunnel defaults: Clash/mihomo TUN 198.18.0.1 [D] = `Benchmark` (`class.rs:56` [P]); Tailscale 100.64/10 = `Shared` (`class.rs:40` [P]); both -> `lan_local` None, LAN off entirely even with a home interface. WireGuard/AmneziaWG/WARP addresses are usually 10.x or 172.16.x [D] = `Private`.
- Hence the range rule of option (а) adds nothing reliable: 100.64/10 and 198.18/15 are already non-LAN [P]; 172.18.0.1 (sing-box default [D]) and 10.x tunnel addresses cannot be told from home LANs by range (Docker also uses 172.18/16 [D]). Dropped.

### Facts checked for this addendum
1. Root `Cargo.toml:77` `unsafe_code = "forbid"` [P]. No product crate depends directly on `windows-sys` or `libc`; `rustix =1.1.5` is direct in `chervo-receive` (`fs`) and `chervo-core` (`process, fs`) [P].
2. `windows-sys-0.61.2`: `GetAdaptersAddresses` (`src/Windows/Win32/NetworkManagement/IpHelper/mod.rs:79`), `GetBestInterface` (`:85`), `GetIpForwardTable2` (`:132`), `GetUnicastIpAddressTable` (`:195`), `IF_TYPE_PROP_VIRTUAL = 53` (`:776`), `IF_TYPE_TUNNEL = 131` (`:809`); features `Win32_NetworkManagement_IpHelper` (`Cargo.toml:109`), `Win32_Networking_WinSock` (`:135`) [P].
3. `libc-0.2.190`: `getifaddrs`/`freeifaddrs` in `src/unix/linux_like/mod.rs:2029-2031` and `src/unix/bsd/mod.rs:607-608` (macOS) [P]. `rustix-1.1.5`: `getifaddrs` appears only in `src/not_implemented.rs` [P].
4. `chervo_addr::route_source_for(target)`: bind unspecified, UDP `connect`, `local_addr`, nothing sent (`probe.rs:41-51` [P]; "no packet" itself [D], capture deferred to stage 16).
5. 13a `RouterId` is the root `UDN`, not an IP (13a decision 6) [P doc]: no persisted gateway address exists.
6. `service.rs:139-146` `local_ok` already checks the class of `own` inside `chervo-lan` [P].

### Options
| | How | Works with the found VPN | Security cost | Volume |
|---|---|---|---|---|
| (а) accept, honest status | show the addresses in use + VPN hint | **no**: discovery stays on the tunnel (sing-box) or off (Clash, Tailscale) | nothing new; `Announce` keeps beaconing into the tunnel (known residual) | texts + one getter |
| (б) FFI enumeration | `GetAdaptersAddresses` / `getifaddrs`; keep Up, IPv4 `Private`, not loopback; Windows `IfType` ∉ {53, 131}, Unix not `IFF_POINTOPOINT`; listen and send per interface | yes, any subnet; tunnel flag also keeps beacons out of Wintun/utun/wg; TAP-Windows (OpenVPN legacy) reports Ethernet [D] -> not complete | breaks the project invariant: `forbid` must be lifted for one crate (cargo does not mix `lints.workspace = true` with overrides [D] -> own lint table); ~8-10 `unsafe` blocks, ~70-100 lines (Windows: size/fill loop into an 8-aligned buffer, walk `Next` and `FirstUnicastAddress`, family check before reading `SOCKADDR_IN`; Unix: walk `ifa_next`, null `ifa_addr`, family check, `freeifaddrs` in `Drop`); two new direct deps (packages already locked, new features); Miri cannot execute the OS calls [D], only a walk over a synthetic list if factored out; new CI job; pointer code under security review | new crate ~250 lines + 3-OS tests; L3 multi-interface as in (в) |
| (в) route oracle, no `unsafe` | `route_source_for` for a fixed list of private targets; longest-prefix match picks the on-link interface containing the target regardless of the tunnel's lower metric [D]; keep distinct `Private` sources; listen and send on each | yes when the home subnet contains a list target (every 192.168.N.0/24; 10.N.0.0/16 and wider; a few common 10.x/24; 172.N.0.0/16) [V]; no when the VPN routes the home subnet itself (then the LAN is unreachable anyway) | no `unsafe`, no deps; 533 bind+connect per sweep, local only, but the "no packet" claim is multiplied -> stand capture row mandatory; `Announce` also reaches virtual switches (VMware, VirtualBox, Hyper-V, WSL, Docker) and still the tunnel if its address is `Private` | ~120 lines in `chervo-lan` + tests; one function in L4 |
| (в') oracle targets = UPnP gateway or book addresses | gateway IP is not persisted (fact 5) and is found over the same wrong interface -> circular; book `Contact` private addresses expire in 24 h and do not exist before the first LAN contact | partial at best | — | not recommended alone |
| (г) manual address | settings key with an IPv4, ownership checked by `bind((ip, 0))` | only while DHCP keeps the address; choosing from a list needs (б) or (в) anyway | one more hostile-input settings field; low | settings, GUI field |

### Recommendation
(в) plus the display part of (а). (б) only as a separate stage with owner consent, if the stand or manual checks show (в) misses real home networks. (г) not now.

### Exact changes (if В3 = в)
**Decisions.** 3: replace "Only the default-route interface is used: ... (std cannot, no new crate)." with "Interfaces: the set `own` (≤ `MAX_IFACES` = 4, every member class `Private`) found by the route-oracle sweep of Addendum 1. Listening joins `LAN_GROUP` on each member; sending uses one send socket per member. No OS interface enumeration API." 2, last sentence: "...applies on every private interface in `own`." 8: "own address change" = change of the set `own`; `SEND_BUDGET` per member (total ≤ 96 per 60 s). **Do not:** "no interface enumeration" -> "no OS interface enumeration (FFI, `ipconfig`, `/proc`, `/sys`); the sweep of Addendum 1 is the only way to find interfaces and never sends".

**L2 chervo-addr.** Trait and types unchanged; doc of `LanLocal.own`: "default-route IPv4 of any class (never loopback or unspecified); `chervo-lan` decides".

**L2 chervo-lan.**
- `limits.rs` += `MAX_IFACES = 4`, `SWEEP_INTERVAL = 60 s`, `SWEEP_PORT = 9`, `SWEEP_CHUNK = 64`.
- New pure `ifaces.rs`: `pub(crate) fn sweep_targets() -> impl Iterator<Item = SocketAddrV4>` in this order: `192.168.N.1` N = 0..=255; `10.N.0.1` N = 0..=255; `10.0.1.1, 10.1.1.1, 10.1.10.1, 10.10.10.1, 10.90.90.1` [D: common router defaults]; `172.N.0.1` N = 16..=31; all with `SWEEP_PORT`; 533 in total. `pub(crate) fn select(default: Ipv4Addr, oracle: &mut dyn FnMut(SocketAddrV4) -> Option<IpAddr>, policy: SrcPolicy, stop: &dyn Fn() -> bool) -> Vec<Ipv4Addr>`: start with `default` if `Private` (or `Loopback` under test policy); then each target in order: result V4, `Private` (test: or loopback), not yet present -> push; end at `MAX_IFACES`, or when `stop()` is true (checked every `SWEEP_CHUNK` calls).
- `wire.rs` `parse(.., own: &[Ipv4Addr], ..)`: source equal to any member -> drop.

**L3.**
- `net.rs` `Sockets::open(own: &[Ipv4Addr], want_send, route)`: one listen socket bound as now; `join_multicast_v4(LAN_GROUP, m)` per member; a failed join drops that member; none left -> `Failed`. One send socket per remaining member (bind `(m, 0)`, `IF = m`, TTL 1, loop off); sealing with each socket's bound IP (rule unchanged).
- `service.rs`: the sweep runs on the service thread only (oracle `chervo_addr::route_source_for` in the product, `TestNet.oracle: Arc<dyn Fn(SocketAddrV4) -> Option<IpAddr> + Send + Sync>` in tests): on `set_local(Some)`, on mode change to non-Off, and every `SWEEP_INTERVAL` while non-Off (a Wi-Fi change under a VPN does not change the default source, so `on_own_change` alone would miss it). Set changed -> rebind and burst. `local_ok` only requires `Some`; empty set -> `NoPrivateRoute`. `impl LanBeacon { pub fn addrs(&self) -> Vec<Ipv4Addr> }` (current set, empty when Off).
- `lan_probe` += subcommand `ifaces`: prints default source, the set, oracle call count and elapsed ms; opens no LAN socket, sends nothing.

**L4** (after the builder's current call; only this): `lan_local(st)` stops using `request_of`: `own` = `local.route.v4` of any class, listen v4 port ≠ 0, else `None`. Test `lan_local_private_only` -> `lan_local_any_class` (public, CGNAT, 198.18.0.1 -> `Some` with that `own`; no route v4 or port 0 -> `None`).

**L5.** `Node::lan_addrs() -> Vec<Ipv4Addr>` (from the node's `Arc<LanBeacon>`, empty without it). CLI `lan`: mode, status, `ADDRS_PREFIX_TEXT` + addresses joined by ", ". GUI section: status line, addresses line, then `VPN_HINT_TEXT`; refreshed on opening the section and on `LanStatusChanged`. Texts += `ADDRS_PREFIX_TEXT = "Ищем на адресах: "`, `VPN_HINT_TEXT = "Если включён VPN или прокси, домашние устройства могут быть не видны: VPN может перекрывать домашнюю сеть."`

**Tests** += L2 `ifaces_targets_order_and_count` (533, all `Private`, first `192.168.0.1:9`), `ifaces_vpn_default_finds_home` (oracle: 192.168.1.0/24 -> 192.168.1.5, else 172.18.0.1 -> `[172.18.0.1, 192.168.1.5]`), `ifaces_benchmark_default_excluded` (198.18.0.1 -> `[192.168.1.5]`), `ifaces_public_default_finds_home`, `ifaces_non_private_dropped` (global, shared, link-local, IPv6 results), `ifaces_cap`, `ifaces_dedup`, `ifaces_stop`, `ifaces_none`, `wire_src_any_own_dropped`; L3 `svc_multi_iface_both_send` (oracle gives 127.0.0.1 and 127.0.0.2; receiver gets sightings from both sources; if Windows refuses binding 127.0.0.2 -> STOP, conductor decides) [D], `svc_rebind_on_iface_change` (oracle result changes without `set_local`), `svc_send_budget_per_iface`, `svc_sweep_respects_shutdown`; L4 `lan_local_any_class`.

**Acceptance** += on the Windows dev box: VPN on, `cargo run -p chervo-lan --example lan_probe -- ifaces` lists the tunnel and the home address, elapsed ≤ 200 ms (more -> report; conductor decides on `SWEEP_INTERVAL`); VPN off -> home address only [NP until run]. Before Call changes, the conductor can confirm the core claim without code: PowerShell `Find-NetRoute -RemoteIPAddress <home gateway IP>` must show the home interface and address while the VPN is on [NP].

**Stand L6** += **LAN9** A: `tun0` 172.18.0.1/30 with default route metric 0 plus `br0` with a higher-metric default; A announce, B listen -> B `Connected{Lan}` ≤ 40 s; capture on all A's interfaces over 3 sweeps: 0 packets to any sweep target. **LAN10** as LAN9 with `tun0` 198.18.0.1/16. **LAN11** A listen with `tun0` default -> 0 datagrams from LAN code on `tun0` and `br0`.

**THREAT_MODEL T20 «Остаётся»**: replace «VPN с частным адресом как маршрут по умолчанию может унести маяк к серверу VPN [В]» with «маяк уходит на все частные интерфейсы компьютера (до 4): виртуальные сети ВМ и контейнеров и туннель VPN, если у него частный адрес; сервер VPN может увидеть маяк [В]». "Where verified": VPN item -> "`lan_probe ifaces` on the dev box with VPN; beacon behaviour inside the VPN client [NP]".

**Stop** += the oracle on the dev box with VPN on does not return the home address -> STOP before L3 changes; owner chooses (а) or (б).

### Stage 13а
Affected: same default source. Under the found VPN UPnP sends M-SEARCH into the tunnel (172.18, `Private`) or does nothing (198.18, 100.64). **Do not port the sweep to 13a:** under a full-tunnel VPN a mapping is useless: inbound reaches the home address, but replies of our `0.0.0.0` socket follow the default route into the tunnel and leave from the VPN server's address [V], so friends would get an address that fails. Security note: 13a decision 4(d) (TTL 1 proves on-link) does not hold for packets sent into a userspace TUN (sing-box, Clash terminate TCP locally and open it again elsewhere) [V]; the `UDN` allowlist (decision 6) and the WAN IP check (decision 8) remain the barrier. Separately, not in 13в and without 13a code changes: T16 «Остаётся» += that note; stage 16/18 manual row «UPnP при включённом VPN: ложный адрес не публикуется или сбой виден»; stage 18 UPnP hint text like `VPN_HINT_TEXT`.

### Для владельца (кратко)
- На машине разработки VPN забирает маршрут по умолчанию. Поэтому поиск в локальной сети слушает и рассылает в туннель, а не в домашнюю сеть, и соседей не видно. У VPN с адресом 198.18.x или 100.x поиск сейчас просто выключается.
- Предлагаю без unsafe и без новых пакетов: программа спрашивает у системы, через какой свой адрес шёл бы путь к 533 типичным домашним адресам. Сам пакет при этом не отправляется. Так находятся все частные адреса компьютера, до 4. На каждом программа слушает, а в режиме «сообщать о себе» и рассылает маяк. В настройках видно, на каких адресах идёт поиск, и есть подсказка про VPN.
- Цена: в режиме «сообщать о себе» маяк уходит также в виртуальные сети (ВМ, WSL, Docker) и в туннель VPN, если у него частный адрес. Режим «только слушать» по-прежнему ничего не шлёт.
- Не берём сейчас: перебор интерфейсов системными функциями (нужен unsafe, запрещённый во всём проекте) и ручной ввод адреса.
- UPnP (13а) при включённом VPN не поможет в принципе: ответы уходят через VPN. Там нужны только подсказка и пометка в модели угроз, отдельно от 13в.

### Вопрос владельцу
**В3. Поиск в локальной сети при VPN.** (а) Оставить как есть, только показать адреса и подсказку «при VPN соседи могут быть не видны». (в) Искать на всех частных адресах компьютера через опрос маршрутов, без unsafe и новых пакетов. (б) Системный перебор интерфейсов с unsafe отдельным этапом. (г) Ручной ввод адреса в настройках. **Рекомендую (в).**
