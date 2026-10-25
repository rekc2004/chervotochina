# SPEC 13v: LAN discovery (U9)          критичность: КРИТИЧНЫЙ

Author: combine-architect (opus/high), 2026-10-25, revision 1. Base: `f3d461a`. Labels: [P] verified by me in the source (file:line) or by a directory listing; [V] my inference; [D] from memory, not re-checked (must be verified in step S0 or by a test); [NP] not verified. **Nothing was built or run by me.** Naming: "13v" = TASK line "13в". Owner-facing text is in Russian (sections "Для владельца" and "Вопросы владельцу"); the questions are also in `docs/OPEN_QUESTIONS.md` ("13в Q1", "13в Q2").

Цель: two computers that are friends and sit in one home LAN find each other's current private address automatically, without a token and without any third party, even after the 24 h private-address TTL has expired or both got new DHCP addresses. The announcement carries no public key, no name, no stable identifier, and no QUIC port in clear; a discovered address is only a dial candidate for the existing knock + QUIC + Noise KK path and is never trusted or stored before authentication.

Прочитать: this file; `crates/chervo-identity/src/{knock.rs,kk.rs:50-90,ids.rs,error.rs}`, `crates/chervo-identity/tests/ss_src_guard.rs`; `crates/chervo-addr/src/{lib.rs,book.rs,class.rs,probe.rs,mapper.rs}`, `crates/chervo-addr/tests/guard.rs`; `crates/chervo-upnp/{Cargo.toml,src/net.rs,src/limits.rs,src/tests/fuzz.rs,src/tests/src_guard.rs}`; `crates/chervo-transport-quinn/src/fuzz_entry.rs` (fixture pattern); `crates/chervo-connect/src/{lib.rs,engine.rs:200-330,engine.rs:648-725,engine.rs:1069-1215,plan.rs,limiter.rs,gateway.rs,texts.rs}`, `src/tests/{src_guard.rs,kit.rs,gateway.rs}`, `tests/{engine_net.rs,redaction.rs}`, `examples/node13.rs`; `fuzz/{Cargo.toml,README.md,fuzz_targets/knock_check.rs}`; `tools/fuzz/run17.sh`; `tools/netns/stage13.sh` (helpers only); root `Cargo.toml`; `deny.toml`. Search nothing else, except the greps named below.

## 0. Scope and boundary
| Item | Here | Note |
|---|---|---|
| Own minimal multicast beacon, IPv4, link-local scope (TTL 1) | yes | decision D1 |
| Per-pair, per-epoch tags; port sealed per friend; fixed-size beacon | yes | D2-D5 |
| Hostile-input parser, rate limits, memory bounds, fuzz | yes | D7, "Untrusted input" |
| Engine integration: in-memory LAN candidate, strict limiter, knock + KK only | yes | D8 |
| Public API for stage 18a (`attach_lan`, `detach_lan`, `lan_status`, `LanDiscovery::start`) | yes | D9; **18a wires it later** |
| Off switch, default | API yes; UI in 18a/18b | D10, Q1 |
| `crates/chervo-core`, `chervo-transfer`, `chervo-receive`, `spikes/` | **not touched** | other sessions work there |
| IPv6 multicast (ff02::/16), IPv6 sockets | **no** -> small stage "приём по IPv6" | D11; the wire format is already family-aware |
| Real mDNS / DNS-SD interoperability (Bonjour, Avahi browsing) | no | D1 |

## 1. Decisions (with rationale)
**D1. Own beacon, not mDNS/DNS-SD.**
- The local registry has 877 crate directories and none whose name contains `dns` (so no `mdns-sd`, `libmdns`, `simple-mdns`, `simple-dns`, `hickory-*`, `dns-parser`), and no interface-enumeration crate (`if-addrs`, `netdev`, `local-ip-address`, `network-interface`, `ipconfig`, `netlink*`, `getifaddrs`) (fact 1) [P]. CORE 3: I pick no crate I cannot read, so **no new crate is requested**.
- Real DNS-SD would mean a hand-written DNS message parser (names, compression pointers, RR types) on hostile LAN input, plus sharing UDP 5353 with the OS responders (Windows dnscache, mDNSResponder, Avahi) [D]. That is a larger attack surface than a fixed-size datagram, and it buys nothing: no other software must understand our announcement. Worse, the DNS-SD model (service instance names, TXT records) pushes towards stable names, which U9 forbids.
- Own beacon: one fixed-length UDP datagram, no variable fields, no length fields, no text. The parser is a length check plus 16 table lookups. Precedent: stage 13a wrote its own minimal UPnP client instead of a library (owner Q1 = C).
- Only primitives already in `Cargo.lock`: BLAKE2s-MAC-256 (`blake2` 0.10.6, as the knock) for key derivation and tag ids, ChaCha20-Poly1305 (`chacha20poly1305` 0.10.1, already in the lock through `snow`, fact 4) for the per-friend sealed port, `getrandom` 0.4.3 for nonces, `socket2` 0.6.5 for multicast socket options. Standard constructions only: PRF-based KDF with domain labels (same construction as the knock, reviewed in stage 9b), PRF tags, AEAD with a random 96-bit nonce. **No own crypto.**

**D2. What is announced.** Exactly this, nothing else (format §3): version byte, a fresh random 12-byte nonce, 16 slots. A slot is `id(16) || sealed_port(2) || tag(16)`. Real slots are for friends we currently miss; the rest are random filler slots that look the same. No public key, no `PairId`, no name, no stable ID, no clear port, no slot count, no epoch number.

**D3. Keys and tags (per pair, per direction).** From the pair's X25519 shared secret `ss` (only inside `chervo-identity`, as for the knock, `knock.rs:112-136` [P]):
- `K_id(S→R) = BLAKE2s-MAC-256(key = ss, LAN_ID_KEY_LABEL || pub_S || pub_R)`
- `K_seal(S→R) = BLAKE2s-MAC-256(key = ss, LAN_SEAL_KEY_LABEL || pub_S || pub_R)`
- `id(S→R, e) = first16(BLAKE2s-MAC-256(K_id(S→R), LAN_ID_LABEL || be64(e)))`, where `e = floor(unix / 60)` by the engine clock (with the user's NTP offset).
- Sealed port: `ct || tag = ChaCha20-Poly1305(key = K_seal(S→R), nonce = beacon nonce, aad, plaintext = be16(port))`, `aad = LAN_AAD_LABEL || 0x01 || be64(e) || 0x04 || ip4(src) || id`.
Why: labels differ from the knock labels, so LAN ids and knock ids are independent [V, PRF]. Direction keys: A's slot for B and B's slot for A are unrelated, so an observer cannot pair two hosts by equal tags [V]. Separate subkeys for the MAC and the AEAD: no cross-primitive key reuse. The source IP is in the AAD: a beacon replayed from another IP fails, and one replayed with the true IP spoofed only points at the true address [V].

**D4. Epoch 60 s, receiver accepts e-1, e, e+1.** Discovery only helps if the knock then succeeds, and the knock accepts ±1 window of 30 s (T15); a wider LAN tolerance buys nothing [V]. Ids are constant inside an epoch (needed for the O(1) table), so an observer links beacons of one host for at most ~1 minute; it already links them by IP [V]. Across epochs nothing links without the key [V].

**D5. Fixed 16 slots, rotation, fillers, freeze per epoch.** Slots are for the "wanted" set: Active friends without a live connection. `W` is sorted by `PairId::as_bytes()`. If `|W| <= 16`, all are announced. Otherwise a window of 16 starting at `(e * 16) mod |W|`, wrapping, so every wanted friend is announced within `ceil(|W|/16)` epochs. Filler ids are fresh random per epoch and stay fixed inside the epoch, like real ids. Filler `ct || tag` is fresh random per beacon, like real slots (fresh nonce). Slots are sorted by id bytes. The announced set is frozen at the first beacon of an epoch. Exceptions: (a) a peer removed by `set_peers` (blocked, removed, rekeyed) is dropped at once, its slot replaced by a fresh filler, and its beacons no longer match. A new local endpoint (`set_local` with another value) does NOT reset the epoch state (round 1 of the security review, 2026-10-25): ids do not depend on the address, only the sealed port does, so an address change inside the epoch changes no id. Re-activation (the last friend goes away and comes back, or the endpoint disappears and returns) freezes a new epoch state from the `wanted` set the core already holds; a later `set_wanted` inside the epoch never alters the announced set (no re-freeze: it would leak the number of missing friends, real ids repeat while fillers change). **Ordering:** the caller (the engine) pushes `set_wanted` BEFORE `set_peers` and `set_local`, and the link thread applies all pending commands before it polls for a beacon, so `wanted` is known when the sockets are first wanted. Why: constant size, constant slot count and per-epoch stability of all 16 ids hide the number of friends and of missing friends [V]. Freezing avoids diffs that would separate real from filler ids [V].

**D6. When beacons are sent.** Only while the link has a private local endpoint **and** at least one peer (Active friend). No Active friend: sockets closed, no IGMP join, nothing sent (a fresh install reveals nothing). With peers, the rate is independent of the wanted set (fillers only if nobody is missing), so the rate leaks nothing about connection state. Interval 60 s with uniform jitter ±10 s. Burst of 3 beacons (at 0, +1 s, +3 s) on: attach (`trigger`), a new local endpoint, and `Engine::connect_now`. Hard cap: at most 8 beacons in any rolling 60 s. **No beacon is ever sent in reaction to a received datagram**: there is no query/response, so nobody on the LAN can elicit traffic from us [V].

**D7. Hostile input: strict and bounded** (details in "Untrusted input"). Exact length 557; version 1; IPv4 source of class `Private`, not our own IP; global budget charged on every received datagram; per-source budget; at most 2 AEAD opens per datagram; bounded tables and queues; per-pair found throttle. A flood can at worst stop LAN discovery itself; other paths are unaffected [V].

**D8. Integration: hint only, then the existing authenticated path.** A match yields `LanFound { pair, addr = (source IP, decrypted port) }`. The engine keeps at most one in-memory entry per Active pair. The entry is `KnownAddr { source: AddrSource::Lan, hint: true, short_lived: true }` with a TTL of 180 s. It is **never written to `FriendBook`**, never published, never sent to other friends (U6 v6), never fed to `own.observe`. The entry is prepended to that friend's `usable_known` entries before `friend_plan_confirmed`. It is strict (≤ 1 dial per 32 s per IP, `limiter.rs:34-37, 93-116` [P]) and uses the hint backoff. It drives only `transport.connect` (knock + QUIC + Noise KK). Only after KK succeeds does the existing `on_connection` -> `note_contact(remote_addr)` store a `Contact` (private, 24 h, `book.rs:15-18, 145-153` [P]). Why not persist the hint: a book write rewrites the encrypted friend file and the anchor (stage 17 Q1). A friend-triggered write per beacon is a disk-write DoS lever, and the address is unproven until KK [V]. `AddrSource::Lan` already exists and is serializable (`chervo-addr/src/lib.rs:38-47`, `chervo-friends/src/plain.rs:53-54` [P]), but it is used here in memory only.

**D9. Crates and contract (precedent: stage 13a `PortMapper`, fact 11).** The contract `LanLink` lives in `chervo-addr`, with no sockets. Keys `LanKeys` live in `chervo-identity`, the only place with `ss`. The new crate `chervo-lan` holds the wire format, the pure state machine `LanCore`, the socket driver and the thread `LanDiscovery`. The consumer `chervo-connect` sees only `Arc<dyn LanLink>`. It has no new normal dependency, no sockets, and no word `mdns` (its guard, fact 13). `chervo-lan` depends on `chervo-addr`, `chervo-identity`, `socket2 =0.6.5` (no default features, as `chervo-upnp/Cargo.toml:10` [P]) and `getrandom`. Its own thread is plain std: blocking `recv_from` with a 200 ms timeout. No tokio in it.

**D10. Off switch and default (Q1).** No socket, no IGMP join and no packet unless the node calls `attach_lan`. `detach_lan` closes everything at once. Default chosen until the owner answers: **the node keeps LAN discovery off until the user has answered a first-run question; the GUI asks with the box pre-checked** (18a/18b requirement). This is conservative: nothing is announced without one explicit "yes". It is also functional: one click enables it, as owner Q7 (release 1 with 13v) needs. Alternatives in Q1.

**D11. Interfaces and IP versions.** Only the IPv4 source address of the default route (`probe_route_sources().v4`, `probe.rs:41-71` [P]), via the engine's existing snapshot, and only if its class is `Private` (RFC 1918). Excluded automatically: public addresses on the interface (white IP, nothing to find and an open LAN port would be reachable from the internet), CGNAT and Tailscale-style 100.64/10 (`Shared`), link-local 169.254/16, no route. No interface enumeration (no crate, no FFI, `unsafe` forbidden). Consequence: a second LAN interface that is not the default route is not used. If a full-tunnel VPN owns the default route with a private address, beacons go to that tunnel's link (T17 residual; the user's off switch covers it) [V]. IPv6: no sockets in this stage. The AAD already carries a family byte (4 or 16 address bytes), so the IPv6 stage reuses the format with group ff02::/16 (candidate, to be checked then). That stage also has to solve the interface index, which std does not expose [V].

**D12. Group, port, socket options.** Group `LAN_GROUP_V4` from 239.255.0.0/16 (IPv4 Local Scope, administratively scoped, RFC 2365 [D]), not 239.255.255.250 (SSDP) and not the mDNS group 224.0.0.251. Fixed UDP port `LAN_PORT`. Both values are candidates that **S0 must check against the IANA registries** (stop if assigned).
- Send socket: bound to `(own_ip, 0)`, `set_multicast_if_v4(own_ip)`, `set_multicast_ttl_v4(1)`, `set_multicast_loop_v4(false)`, the same as SSDP in `chervo-upnp/src/net.rs:79-90` [P].
- Receive socket: `set_reuse_address(true)`, so that two OS users on one PC can both run. On Linux and macOS it is bound to `LAN_GROUP_V4:LAN_PORT`, so unicast to the port is not delivered and the OS answers ICMP port-unreachable as for a closed port (scanners see nothing) [D: unix semantics, verified by stand row PORTSCAN]. On Windows, where binding to a multicast address is not allowed [D], it is bound to `0.0.0.0:LAN_PORT`. Then `join_multicast_v4(LAN_GROUP_V4, own_ip)`, receive buffer 64 KiB, read timeout 200 ms.
- `SO_REUSEPORT` is not used (socket2 has it only with feature `all`, unix only, `sys/unix.rs:2237-2247` [P]).

## 2. Facts from the source
1. Registry `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f`: 877 `*/Cargo.toml`; Glob `*dns*/Cargo.toml` → none; `*{if-addr,if_addr,netdev,interface,ipconfig,netlink,local-ip,getifaddr}*/Cargo.toml` → only `windows-interface-0.59.3` (COM macro crate, unrelated) [P: Glob, 2026-10-25].
2. socket2 0.6.5: `bind` `socket.rs:168`, `recv_from` (MaybeUninit) `:528`, `set_recv_buffer_size` `:1081`, `set_read_timeout` `:1104`, `set_reuse_address` `:1125`, `join_multicast_v4(&Ipv4Addr, &Ipv4Addr)` `:1312` (no cfg gate), `leave_multicast_v4` `:1325`, `set_multicast_if_v4` `:1546`, `set_multicast_loop_v4` `:1574`, `set_multicast_ttl_v4` `:1604`, `join_multicast_v6(&Ipv6Addr, u32)` `:1874` [P].
3. `set_reuse_port` exists only with feature `all` on unix (`sys/unix.rs:2237-2247`) [P].
4. `chacha20poly1305` 0.10.1 is in `Cargo.lock:139-149` (deps aead, chacha20 0.9.1, cipher, poly1305, zeroize) [P]; `ChaCha20Poly1305` type `src/lib.rs:181`, `KeyInit::new` `:227-239`, `AeadInPlace::{encrypt,decrypt}_in_place_detached` `:250-277`, key zeroized on drop + `ZeroizeOnDrop` `:292-301`, tag compared in constant time via `subtle` (`src/cipher.rs:86-87`), default features `alloc, getrandom` (`Cargo.toml.orig:31`) [P]. Using it with `default-features = false` adds no package [V; acceptance checks the lock].
5. Knock construction: `K(S→R) = BLAKE2s-MAC-256(ss, LABEL || pub_S || pub_R)`, `id = first16(MAC(K, ID_LABEL || w))`, equal keys and non-contributory DH → `AuthFailed`, keys in `Zeroizing`, no Clone/PartialEq/Hash/Deref (compile_fail doctests) (`chervo-identity/src/knock.rs:1-137`) [P]. `IdentityError` has `AuthFailed`, `RandomUnavailable` (`error.rs`) [P]. `PairId` is Copy/Eq/Hash with `as_bytes()`, Debug redacted (`ids.rs`) [P].
6. `AddrSource::Lan` exists (`chervo-addr/src/lib.rs:38-47`) and is persisted as code 1 (`chervo-friends/src/plain.rs:53-54, 69-70`); no product code produces it (grep: only tests) [P].
7. `dead()`: `Private` entries die after `PRIVATE_TTL_SECS` = 86 400 (`book.rs:15-18, 145-153`) [P].
8. `plan.rs`: LAN-first stable sort (`:75-77`), dedupe keeps the first entry and `strict &= strict` (`:68-72`), `is_strict = hint || source != Contact` (`:111-113`), `MAX_DIAL_ADDRS` 8 (`:12`), `path_kind` Private/Loopback/LinkLocal → `Lan` (`:151`) [P].
9. `limiter.rs`: strict floor `dial_base + 2 s` per IP across ports (`:34-37, 93-116, 140-150`), hint backoff (`:235-255`) [P].
10. `engine.rs` `plan_dials`: Active friends without key problems, live/inflight skipped, `friend_plan_confirmed(usable_known, confirmed, local)` (`:651-713`); `State` fields incl. `published: Vec<KxPeer>` (`:208-241`); `Inner.gw: Gateway` (`:246-262`); `connect_now` at `:1162` [P].
11. 13a pattern: contract `PortMapper` in `chervo-addr/src/mapper.rs:55-61`; `attach_mapper` with `OnceLock`, task, `request_of` = route.v4 Private + v4 listen port ≠ 0 (`chervo-connect/src/gateway.rs:63-82, 205-223`) [P].
12. `probe_route_sources`: one source per family via UDP `connect`, no packet (`chervo-addr/src/probe.rs:41-71`); stage 12 spec decision 7 already says "LAN-only secondary interfaces are not seen (LAN discovery is mDNS, stage 13)" (`docs/specs/stage-12-addr.md:16`) [P].
13. `chervo-connect` `src_guard`: bans `UdpSocket`, `TcpStream`, `TcpListener`, `send_to`, `lookup_host`, `to_socket_addrs` and the words `rendezvous`, `stun`, `igd`, `upnp`, `mdns` (case-insensitive) in all of `src/`; bans `upnp`, `igd`, `socket2`, `mio`, `hyper` in the manifest (`src/tests/src_guard.rs:50-81, 123-130`) [P]. `chervo-addr/tests/guard.rs:33-54` bans `.send(` / `send_to(` in `src/` and allows `UdpSocket` only in `probe.rs` [P].
14. `scripts/check-forbidden.sh` patterns are iroh presets, relays, STUN and what-is-my-IP services only (`:4-6`): **no change needed for multicast** [P].
15. Fuzz: separate crate `fuzz/` (own workspace, nightly), bins listed in `fuzz/Cargo.toml`, entry points behind crate feature `fuzzing` (README); `run17.sh` takes the target list from the manifest (`:57-59`); stable smoke pattern xorshift64*, `CHERVO_FUZZ_ITERS`, `CHERVO_FUZZ_SEED` (`chervo-upnp/src/tests/fuzz.rs:48-79`); smoke command `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p <crate> fuzz_smoke -- --nocapture` (`docs/specs/stage-13a-upnp.md:211`); knock fixture with two distinct keys and a positive control (`fuzz/fuzz_targets/knock_check.rs`, `chervo-transport-quinn/src/fuzz_entry.rs:61-87`) [P].
16. Stage 18a: listen port random in 49152..=65535 and stable afterwards (`docs/specs/stage-18-gui.md:43`) [P]. So the port is a per-install identifier. In clear text in a multicast beacon it would let any LAN host (for example other Wi-Fi clients, who do not see our unicast) link the laptop across networks, defeating per-network MAC randomisation [V]. Hence the sealed port (D3).
17. All external users of `ConnectConfig` build it with `..ConnectConfig::default()` or `default()` (grep `crates/`) [P]. This stage does not change `ConnectConfig` anyway.
18. `chervo-core/tests/layout.rs` checks a subset of workspace members and the core manifest only (`:9-41`) [P]: adding `crates/chervo-lan` does not touch it.

Facts from memory to verify in S0 or by tests [D]: RFC 2365 (239.255/16 IPv4 Local Scope); IANA port and multicast registries for the candidates; Linux/macOS deliver only group traffic to a socket bound to the group address; Windows refuses bind to a multicast address; SO_REUSEADDR lets several sockets share a multicast port on Linux/macOS/Windows; Windows Defender Firewall prompts on first inbound use and may drop inbound multicast; macOS 15 "Local Network" permission; IGMP snooping behaviour of home routers.

## 3. Wire format (exact)
```
offset  len  field
0       1    ver = 0x01
1       12   nonce (OS RNG, fresh per beacon)
13      544  16 slots, sorted ascending by id bytes; slot k = id(16) || ct(2) || tag(16)
total   557  (BEACON_LEN); IPv4 + UDP = 585 bytes on the wire, never fragmented
```
- Real slot for friend F in epoch e: `seal_slot(e, nonce, own_ip, quic_port)` with the keys of our direction to F (D3).
- Filler slot: `id` = 16 random bytes generated once per epoch; `ct || tag` = 18 fresh random bytes per beacon.
- Nothing else is accepted: any other length, any `ver != 1` → drop. Reserved bits: none.

## 4. Do (verify each step before the next, CORE 5)
**S0 (conductor, `combine-scout` haiku/medium with web; before Call 2).** Read and quote: (a) IANA "Service Name and Transport Protocol Port Number Registry": the first of `47131, 46803, 45977` that is unassigned for UDP and TCP becomes `LAN_PORT`; (b) IANA "IPv4 Multicast Address Space Registry" and RFC 2365 §6: 239.255.0.0/16 is the IPv4 Local Scope, and `239.255.112.47` carries no assignment (fallback `239.255.83.19`). Record URL and date in this spec (append "S0 result"). If a registry cannot be read: **STOP**, and the conductor decides (CORE 3).

**Call 1: `combine-builder` sonnet/high. Keys and contract.**
1. `cargo --version`, `rustc --version` (1.99.1); `BASE=$(git rev-parse HEAD)`.
2. Grep check: `grep -rn "fn knock_keys\|LessSafeKey\|chacha20poly1305" crates --include=*.rs --include=Cargo.toml` → only `chervo-identity/src/knock.rs` for `knock_keys`; nothing else. Otherwise STOP.
3. Root `Cargo.toml`: `[workspace.dependencies] chacha20poly1305 = { version = "=0.10.1", default-features = false }`. `chervo-identity`: `chacha20poly1305.workspace = true`; new `src/lan.rs` exactly per "Interface: chervo-identity"; re-exports in `lib.rs`.
4. `chervo-addr`: new `src/lan.rs` (contract, "Interface: chervo-addr"), re-exports. No sockets, no `.send(` / `send_to(` (fact 13 guard).
5. Tests of Call 1; criteria for both crates; `git diff $BASE -- Cargo.lock | grep -E '^\+name = '` must print nothing (no package added yet).

**Call 2: `combine-builder` sonnet/high. Crate `chervo-lan`.**
6. New member `crates/chervo-lan`, root `[workspace.dependencies] chervo-lan = { path = "crates/chervo-lan", version = "0.0.0" }`. Manifest: `chervo-addr`, `chervo-identity`, `getrandom` (workspace), `socket2 = { version = "=0.6.5", default-features = false }`; `[features] fuzzing = []`; `[lints] workspace = true`. Lint block of `chervo-addr/src/lib.rs:6-13` (no unwrap/expect/indexing/panic/print).
7. Modules: `limits.rs` (all constants of "Untrusted input" and §1, group and port from S0), `wire.rs` (build/parse, pure), `core.rs` (`LanCore`, pure, time injected), `net.rs` (the **only** socket code), `link.rs` (`LanDiscovery`, thread, `impl LanLink`), `fuzz_entry.rs` (`#[cfg(any(test, feature = "fuzzing"))]`), `src/tests/*`.
8. `fuzz/`: `fuzz_targets/lan_beacon.rs`, `[[bin]] lan_beacon`, dependency `chervo-lan = { path = "../crates/chervo-lan", features = ["fuzzing"] }`, README line. Do not run nightly here.
9. Tests of Call 2; criteria for `chervo-lan`.

**Call 3: `combine-builder` sonnet/high. Engine, example, stand, texts.**
10. `chervo-connect/src/lan.rs` + minimal hooks in `engine.rs` (state field, `plan_dials` prefix, `connect_now` trigger, `shutdown` detach); `texts.rs` new texts; guard update; dev-dependency `chervo-lan`.
11. `examples/node13.rs`: flags `--lan` (start `LanDiscovery`, `attach_lan` after `Engine::start`) and `--expect-path lan`.
12. `tools/netns/stage13v.sh` (Linux + root; **cannot run on this Windows host**: write, `bash -n`, shellcheck if present).
13. All criteria; report.

## 5. Interface (exact; the builder may add private items only)
All `Debug` of types holding keys, pairs or addresses print `"TypeName(..)"`. No logging, no printing. No panics.

### chervo-identity (`src/lan.rs`)
```rust
pub const LAN_ID_KEY_LABEL: &[u8] = b"chervotochina/v1/lan-id-key\0";
pub const LAN_SEAL_KEY_LABEL: &[u8] = b"chervotochina/v1/lan-seal-key\0";
pub const LAN_ID_LABEL: &[u8] = b"chervotochina/v1/lan-id\0";
pub const LAN_AAD_LABEL: &[u8] = b"chervotochina/v1/lan-aad\0";
pub const LAN_FORMAT_VERSION: u8 = 1;
pub const LAN_ID_LEN: usize = 16;
pub const LAN_NONCE_LEN: usize = 12;
pub const LAN_SLOT_LEN: usize = 34;          // id 16 || ct 2 || tag 16
/// No Clone, PartialEq, Hash, Deref (compile_fail doctests as KnockKeys); ZeroizeOnDrop.
pub struct LanKeys { id_send, id_recv, seal_send, seal_recv: Zeroizing<[u8; 32]> }
impl KxPeer {
    /// Same refusals as `knock_keys`: equal keys or non-contributory DH -> AuthFailed.
    pub fn lan_keys(&self) -> Result<LanKeys, IdentityError>;
}
impl LanKeys {
    /// Id of the friend's slot for us in epoch `e` (K_id of the friend's direction).
    pub fn recv_id(&self, epoch: u64) -> [u8; LAN_ID_LEN];
    /// Our slot for this friend. `src` = the IP the beacon is sent from (v4-mapped -> V4).
    /// port 0 -> AuthFailed. AEAD failure -> AuthFailed.
    pub fn seal_slot(&self, epoch: u64, nonce: &[u8; LAN_NONCE_LEN], src: IpAddr, port: u16)
        -> Result<[u8; LAN_SLOT_LEN], IdentityError>;
    /// Friend's slot: len == 34, id equals recv_id(epoch) (MAC verify_truncated_left, constant time),
    /// AEAD opens with aad(epoch, src, id), port != 0. Anything else -> None.
    pub fn open_slot(&self, epoch: u64, nonce: &[u8; LAN_NONCE_LEN], src: IpAddr, slot: &[u8]) -> Option<u16>;
}
```
`aad = LAN_AAD_LABEL || LAN_FORMAT_VERSION || be64(epoch) || fam || ip_bytes || id`, `fam = 4` with 4 bytes, `fam = 6` with 16 bytes (after v4-mapped normalisation). The AEAD key is built per call from the `Zeroizing` bytes (`ChaCha20Poly1305::new`, dropped and zeroized after the call, fact 4). Only `blake2` and `chacha20poly1305` calls. No `std::fs`, no sockets (existing identity guards stay green).

### chervo-addr (`src/lan.rs`, contract)
```rust
pub const LAN_FOUND_MAX: usize = 64;
/// Debug "LanFound(..)".
#[derive(Clone, Copy, PartialEq, Eq)] pub struct LanFound { pub pair: PairId, pub addr: SocketAddrV4 }
/// Debug "LanPeer(..)". No Clone.
pub struct LanPeer { pub pair: PairId, pub keys: LanKeys }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum LanStatus { Off, NoPeers, NoLan, Unavailable, Running }
/// Every method is non-blocking (lock + store; no I/O), returns within milliseconds.
pub trait LanLink: Send + Sync {
    /// Our private IPv4 of the default route and the QUIC listen port; None closes the sockets.
    fn set_local(&self, local: Option<SocketAddrV4>);
    /// Replaces all peers. Removed pairs are never announced or matched again, immediately.
    fn set_peers(&self, peers: Vec<LanPeer>);
    /// Pairs without a live connection. Read when the epoch is frozen. Pushed BEFORE `set_peers` and `set_local`.
    fn set_wanted(&self, wanted: Vec<PairId>);
    /// Burst (start, user action). Rate cap applies.
    fn trigger(&self);
    /// At most LAN_FOUND_MAX items, oldest first; the queue is emptied.
    fn take_found(&self) -> Vec<LanFound>;
    fn status(&self) -> LanStatus;
    /// Signals the thread to stop and returns at once (no waiting, no sleeping: the caller may be a
    /// runtime worker); the thread closes both sockets within one receive timeout (<= 200 ms) and ends,
    /// detached. Idempotent.
    fn shutdown(&self);
}
```

### chervo-lan
```rust
pub use chervo_addr::{LanFound, LanLink, LanPeer, LanStatus};
pub const BEACON_LEN: usize = 557;
pub const LAN_SLOTS: usize = 16;
pub const LAN_EPOCH_SECS: u64 = 60;
pub const LAN_GROUP_V4: Ipv4Addr;   // from S0
pub const LAN_PORT: u16;            // from S0
pub fn lan_epoch(unix: u64) -> u64; // unix / 60

#[derive(Clone, Copy, Default)] pub struct CoreConfig { /// tests only; production false
    pub allow_loopback: bool }
/// Pure state machine: no sockets, no clock, no threads. RNG: getrandom (failure -> skip that beacon).
pub struct LanCore;
impl LanCore {
    pub fn new(cfg: CoreConfig) -> Self;
    pub fn set_local(&mut self, local: Option<SocketAddrV4>, now: Duration);
    pub fn set_peers(&mut self, peers: Vec<LanPeer>);
    pub fn set_wanted(&mut self, wanted: Vec<PairId>);
    pub fn trigger(&mut self, now: Duration);
    /// Some(ip) iff local is Some, its class is Private (or Loopback with allow_loopback) and peers is non-empty.
    pub fn wants_sockets(&self) -> Option<Ipv4Addr>;
    /// At most one beacon per call, only when due and under the cap.
    pub fn poll_send(&mut self, now: Duration, unix: u64) -> Option<[u8; BEACON_LEN]>;
    /// Untrusted datagram from `src` (any length).
    pub fn on_datagram(&mut self, src: SocketAddr, data: &[u8], now: Duration, unix: u64);
    /// false: global budget is empty; the driver pauses reading for 100 ms.
    pub fn may_read(&self, now: Duration) -> bool;
    pub fn take_found(&mut self) -> Vec<LanFound>;
    pub fn next_wakeup(&self, now: Duration) -> Duration;   // <= 200 ms
    pub fn stats(&self) -> LanStats;
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LanStats { pub dgrams_in: u64, pub dropped_budget: u64, pub dropped_len: u64, pub dropped_ver: u64,
    pub dropped_src: u64, pub dropped_source_rate: u64, pub lookups: u64, pub aead_opens: u64,
    pub found: u64, pub found_throttled: u64, pub beacons_out: u64, pub send_errors: u64, pub rng_errors: u64 }
/// Production link: own thread, real multicast sockets on wants_sockets().
pub struct LanDiscovery;
impl LanDiscovery {
    /// `now_unix`: the engine clock (with the user's NTP offset). Never blocks. Thread spawn
    /// failure -> status Unavailable, no panic.
    pub fn start(now_unix: Arc<dyn Fn() -> u64 + Send + Sync>) -> Arc<Self>;
    pub fn stats(&self) -> LanStats;
}
impl LanLink for LanDiscovery { /* contract */ }   // Drop of the last Arc = shutdown
#[cfg(any(test, feature = "fuzzing"))] #[doc(hidden)] pub fn fuzz_lan_ready() -> bool;
#[cfg(any(test, feature = "fuzzing"))] #[doc(hidden)] pub fn fuzz_beacon(data: &[u8]) -> bool; // true = found produced
```
Driver (`net.rs` + `link.rs`): the socket state follows `wants_sockets()`. Open = §1 D12 order; any failure → close both, status `Unavailable`, retry after 30 s. Loop: apply pending commands (stored as latest values plus a trigger counter, so memory is bounded whatever the call rate), `poll_send` → `send_to(LAN_GROUP_V4:LAN_PORT)`, then `recv_from` with timeout `next_wakeup` into a buffer of `BEACON_LEN + 1` bytes (`n > BEACON_LEN` → handled as wrong length), `on_datagram`; if `!may_read` sleep 100 ms without reading. Test-only `Net` (`pub(crate)`, built only in `src/tests`): unicast bind `127.0.0.1:p` without join, send to a given list of unicast targets, `allow_loopback = true`.

### chervo-connect (`src/lan.rs`, hooks in `engine.rs`)
```rust
impl<T, S> Engine<T, S> {
    /// Second call while attached -> Internal; after shutdown -> Shutdown. Never does I/O itself.
    /// Pushes wanted, peers, local (this order), then trigger(); spawns the lan task (period cfg.tick).
    pub fn attach_lan(&self, link: Arc<dyn LanLink>) -> Result<(), ConnectError>;
    /// link.shutdown(), all hints dropped; idempotent; attach_lan allowed again afterwards.
    pub fn detach_lan(&self);
    /// None when not attached.
    pub fn lan_status(&self) -> Option<LanStatus>;
}
pub const LAN_DISCOVERY_TEXT: &str;   // settings explanation, Russian, see §10
pub const LAN_FIRST_RUN_TEXT: &str;   // first-run question, Russian
```
The lan task, every `cfg.tick`:
1. `local` = route.v4 of `own.local()` if class `Private`, plus the first non-zero v4 listen port (same rule as `gateway.rs:63-82`); `set_local` only on change.
2. After every publish (book change, invite start/finish), peers are dirty. Under the lock, clone `st.published` filtered to `book.is_active(pair)` and not in `key_problems` (guests are excluded). Then **outside the lock** call `kx.lan_keys()` per peer; skip failures silently (the key problem is reported elsewhere). Then `set_peers`.
3. `wanted` = Active friends without a live entry and without key problems, sorted; `set_wanted` only on change.
4. `take_found()`: keep an item only if the pair is Active, not live, has no key problem, `classify(ip)` is `Private` or `Loopback` (the production link emits only `Private`; loopback is for the in-memory e2e test), the port is not 0, and the IP is not our route.v4. Then `st.lan_hints.insert(pair, (addr, now))` (one per pair, latest wins, at most `LAN_HINTS_MAX` = 256 with the oldest evicted). Hints older than `LAN_HINT_TTL` = 180 s are dropped. A pair's hint is dropped when it connects or stops being Active.
5. `plan_dials`: for a book friend with a hint, the entries become `[KnownAddr { addr, source: Lan, last_seen_unix: unix, short_lived: true, hint: true }] ++ usable_known`, then `friend_plan_confirmed` as now.

`connect_now` → `link.trigger()` if attached. `Engine::shutdown` → `detach_lan()`. No new `EngineEvent`, no `ConnectConfig` change.

## 6. Не делать
- No new external package (`Cargo.lock` gains only `chervo-lan`); no `unsafe`; no OS interface enumeration; no IPv6 socket; no broadcast (`set_broadcast`); no TCP; no DNS.
- Do not modify `crates/chervo-core`, `crates/chervo-transfer`, `crates/chervo-receive`, `spikes/`.
- Do not change the knock, KK, ADDR_INFO, invite or friends-file formats, `SecretStore`, `ConnectConfig`, `EngineEvent`.
- Never answer a received datagram; never send to any destination other than `LAN_GROUP_V4:LAN_PORT` in production.
- Never write a LAN hint to `FriendBook`, never publish it, never pass it to `own.observe`, never give it to another friend.
- No logging; no `Debug` that prints addresses, pairs, ids, keys, nonces or ports.

## 7. Недоверенный ввод (every received datagram is hostile)
Order in `on_datagram` (each step is O(1) and charges before the next):
| Step | Rule | Constant |
|---|---|---|
| 1 | global budget charged on **every** datagram, any length; empty → drop, the driver pauses reading 100 ms | bucket 100, refill 50/s (`GLOBAL_BURST`, `GLOBAL_PER_SEC`) |
| 2 | `data.len() == BEACON_LEN` exactly | 557 |
| 3 | `data[0] == 1` | |
| 4 | `src` is V4, `classify == Private` (Loopback only with `allow_loopback`), `!= own_ip`; V6, v4-mapped, public, Shared, link-local, multicast, broadcast, unspecified → drop | |
| 5 | per-source-IP bucket; source map LRU-bounded | 10 per 60 s per IP (`SOURCE_BURST` 10, refill 1/6 s); `SOURCE_MAP_MAX` 256 |
| 6 | 16 lookups `id → (peer, epoch)` in the table of `recv_id` for e-1, e, e+1 | table rebuilt per epoch: 3 × peers |
| 7 | `open_slot` only for hits, **at most 2 per datagram**, stop at the first success | `MAX_OPENS` 2 |
| 8 | found throttle: same `(pair, addr)` within 10 s → count `found_throttled`, drop | `FOUND_REPEAT` 10 s |
| 9 | found queue bounded, overflow drops the oldest | `LAN_FOUND_MAX` 64 |
- Memory is bounded by the constants above plus `3 × peers` table entries. No allocation depends on datagram content.
- Spoofed sources: a host on the LAN can rotate source IPs. The per-source map churns, the global budget caps CPU, and honest beacons may be starved. The effect is only "LAN discovery does not work during the flood" [V].
- Replays: same source IP → harmless (true address; throttle + strict limiter). Other source IP → AEAD fails. Older than ±1 epoch → no table hit.
- Lying friend (has the pair key): can make us dial any LAN IP it can use as source, at most one dial per 32 s per IP (strict limiter, fact 9). This is the same bound as for its address updates (T1/T2).
- Errors never carry datagram bytes; no panic on any input (fuzz).

## 8. Tests (exact names)
**chervo-identity** (`src/tests/lan.rs` or `tests/lan.rs`): `lan_keys_directional` (A `seal_slot` opens with B `open_slot`; B's `recv_id(e)` equals the id in A's slot; A's own `open_slot` on A's slot fails: reflection), `lan_ids_independent_of_knock` (for equal window/epoch numbers no LAN id equals a knock id of the same pair), `lan_id_changes_per_epoch`, `lan_slot_rejects_other_ip`, `lan_slot_rejects_other_epoch`, `lan_slot_rejects_other_nonce`, `lan_slot_rejects_every_flipped_bit` (each of 34×8 bits), `lan_slot_rejects_wrong_len` (0, 33, 35), `lan_slot_rejects_other_pair`, `lan_slot_port_zero_rejected` (seal → `AuthFailed`), `lan_slot_v4_mapped_equals_v4`, `lan_keys_equal_key_rejected`, `lan_keys_debug_redacted`; doctests `compile_fail` for `Clone`, `PartialEq`, `Hash`, `Deref` on `LanKeys`.
**chervo-addr**: `lan_found_debug_redacted`, `lan_peer_debug_redacted`.
**chervo-lan** pure core (`src/tests/core.rs`): `beacon_len_and_layout` (557, ver 1, slots sorted, 16 distinct ids), `beacon_fillers_only_when_none_wanted` (no slot opens for any peer), `beacon_real_slot_matches_friend`, `beacon_size_independent_of_wanted` (wanted ∈ {0, 1, 5, 16, 40} → same length and slot count), `beacon_ids_stable_within_epoch`, `stale_wanted_on_reactivation_is_frozen_per_epoch` (re-activation with stale wanted, `set_wanted` inside the epoch: the id set does not change), `endpoint_change_keeps_ids_within_epoch`, `beacon_ids_change_across_epoch` (no id repeats between consecutive epochs), `rotation_covers_all_wanted` (40 → each within 3 epochs), `wanted_frozen_per_epoch`, `removed_peer_dropped_immediately` (slot gone in the next beacon of the same epoch; its beacons no longer match), `no_peers_no_sockets`, `non_private_local_no_sockets` (Global, Shared, LinkLocal, None), `schedule_interval_and_jitter` (1 h simulated: gaps 50-70 s), `trigger_burst_and_cap` (100 triggers → ≤ 8 beacons in any 60 s), `set_local_change_bursts`, `no_send_on_receive` (1000 datagrams, valid or not, change no send time), `drop_wrong_len` (0, 1, 556, 558, 1500), `drop_wrong_version`, `drop_bad_source` (public, loopback in production, 100.64/10, 169.254/16, 224.0.0.1, 255.255.255.255, 0.0.0.0, IPv6, v4-mapped, own IP), `replay_other_ip_rejected`, `replay_same_ip_throttled`, `duplicate_slot_open_cap` (our id in all 16 slots with bad tags → `aead_opens` +2 only), `per_source_budget`, `global_budget_pauses_reading`, `source_map_bounded` (10^5 random private sources → ≤ 256), `found_queue_bounded`, `found_new_addr_not_throttled`, `epoch_tolerance` (±1 accepted, ±2 rejected), `stats_debug_has_no_addresses`.
**chervo-lan** sockets (`src/tests/net.rs`, unicast on 127.0.0.1, runs on Windows, Linux, macOS CI): `loopback_two_links_find_each_other` (real pair keys; each finds the other within 5 s; found addr = 127.0.0.1 + the other's quic port), `loopback_sends_only_to_target` (recording receiver; nothing else received on a second socket), `loopback_garbage_then_finds` (10 000 garbage datagrams, then a valid beacon is found within 5 s after the flood), `loopback_shutdown_closes_socket` (`shutdown` returns at once; the port can be bound again within 1 s), `start_never_blocks` (`start` + all contract calls < 50 ms). `#[ignore]` `multicast_live` (real group on the default-route interface, two links with `allow_loopback`-free production `Net` but a test switch that accepts the own host: **manual on the owner's machines**, not CI).
**chervo-lan** guards: `src/tests/src_guard.rs` (sockets, `send_to(`, `bind(`, `join_multicast_v4`, `set_multicast_` only in `net.rs`; `set_multicast_ttl_v4(1)` and `set_multicast_loop_v4(false)` present in `net.rs`; absent everywhere: `Domain::IPV6`, `set_broadcast`, `TcpStream`, `TcpListener`, `lookup_host`, `to_socket_addrs`, `tokio`, `Command::new`, `println!`, `eprintln!`; the group constructor literal only in `limits.rs`; `allow_loopback: true` only under `src/tests/`; manifest dependencies exactly `chervo-addr`, `chervo-identity`, `getrandom`, `socket2`); `tests/multicast_only_here.rs` (walks `crates/*/src` except `src/tests/`: `join_multicast` and `set_multicast_` occur only in `chervo-upnp/src/net.rs` and `chervo-lan/src/net.rs`, both files found = positive control; `allow_loopback: true` occurs in no product file).
**chervo-lan** fuzz smoke (`src/tests/fuzz.rs`, fact 15 pattern): `fuzz_smoke_beacon` (random bytes of random length 0..=1500, mutations of a real beacon: bit flips, slot swaps, slot duplication, truncation, version byte; random sources incl. bad classes; invariants: found only from a real beacon of the fixture friend, found addr IP = src IP, port ≠ 0, `aead_opens` per datagram ≤ 2, map and queue within bounds), `fuzz_smoke_core_sequence` (random interleaving of all `LanCore` calls with advancing time: every `poll_send` output is 557 bytes, ≤ 8 per 60 s, no panic); `fuzz_entry_ready` (`fuzz_lan_ready()` true: two distinct keys, positive control finds exactly once).
**chervo-connect** (`src/tests/lan.rs`, fake `LanLink` recording calls, paused time): `lan_attach_pushes_state_then_triggers` (order wanted → peers → local → trigger; peers = Active only, no guests, no blocked, no key-problem pairs), `lan_local_none_when_not_private` (Global, Shared, no route, port 0), `lan_found_dials_friend_first` (next tick: first address of the connect call = the hint), `lan_found_ignored` (unknown pair, blocked, guest, live, key problem, Global, port 0, multicast, own IP), `lan_hint_strict_limiter` (found every second for 2 min → ≤ 1 dial per 32 s to that IP), `lan_hint_expires`, `lan_hint_never_persisted` (book `known_addrs` byte-equal after found and failed dial; after a successful fake connection only a `Contact` appears, via `note_contact`), `lan_hint_not_published` (publishable set, issued ADDR_INFO and another friend's book unchanged), `lan_connect_now_triggers`, `lan_peers_refreshed_on_book_change` (block → `set_peers` without the pair), `lan_wanted_follows_connections`, `lan_detach_stops` (one `shutdown`, hints cleared, later found ignored, `lan_status` None), `lan_attach_twice_internal`, `lan_attach_after_shutdown`, `lan_engine_shutdown_detaches`; `src_guard` extended: `take_found(`, `AddrSource::Lan`, `lan_hints.insert` only in `lan.rs` (and `engine.rs` for the plan prefix and the field); the word `mdns` still banned; normal `[dependencies]` contain no `chervo-lan`. `texts_present` extended with the two new texts. `tests/redaction.rs` extended with `LanFound`, `LanStatus`.
**chervo-connect** e2e (`tests/lan_net.rs`, dev-deps quinn + chervo-lan): `lan_net_empty_books_connect` (two engines with `QuinnTransport` on 127.0.0.1, friends whose books hold **no address**; an in-memory test `LanLink` per side built on `chervo_lan::LanCore` with `allow_loopback: true`, carrying beacons between the two cores; both `Connected { path: Lan }` within 15 s; afterwards each book has the other's `Contact`), `lan_net_wrong_pair_no_connect` (the two engines are not friends → no `connect` attempt, no `Connected` within 20 s).

## 9. Критерии приёмки (each a command; output in the report)
- [ ] S0 result recorded in this file (URLs, date, chosen `LAN_PORT`, `LAN_GROUP_V4`).
- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked`: all names of §8 except `#[ignore]`, including the negative ones.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh` (unchanged script)
- [ ] `test "$(git diff $BASE -- Cargo.lock | grep -E '^\+name = ')" = '+name = "chervo-lan"'`
- [ ] `cargo tree -p chervo-lan -e normal --depth 1 | grep -Ei 'tokio|quinn|rustls|hyper|mio|dns'; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal --depth 1 | grep -E 'chervo-lan|socket2'; test $? -eq 1` (direct deps only: socket2 reaches chervo-connect transitively through tokio at baseline; conductor fix 2026-10-25)
- [ ] `cargo tree -p chervo-identity -e normal --depth 1 | grep -c chacha20poly1305` prints 1
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-lan fuzz_smoke -- --nocapture` (iterations per target in the output)
- [ ] `for i in $(seq 20); do cargo test -q --locked -p chervo-lan loopback_ || exit 1; done`
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-connect --test lan_net || exit 1; done`
- [ ] `bash -n tools/netns/stage13v.sh` (and `shellcheck tools/netns/stage13v.sh` if installed)
- [ ] CI: all jobs green (3 OS, supply-chain incl. `cargo deny`, `cargo audit`).
- [ ] **Linux box (conductor, owner's "yes" of stage 17 Q2 covers nightly + cargo-fuzz):** `bash tools/fuzz/run17.sh SECS=1200 TARGETS=lan_beacon` → OK, 0 crashes; corpus minimised and committed per README.
- [ ] **Linux box with root (owner):** stand rows of §11, all PASS.
- [ ] **Owner, two real PCs in the home LAN (Windows):** W1-W3 of §11. The stage is closed only after W1 passes (this is the reason for the stage).

## 10. Texts (Russian, `chervo-connect/src/texts.rs`)
- `LAN_DISCOVERY_TEXT = "Пока программа открыта, она примерно раз в минуту сообщает в локальную сеть, что работает. В сообщении нет имени, ключей и номера порта: узнать вас по нему могут только ваши друзья. Остальные устройства сети видят только, что здесь работает Червоточина. В чужих сетях (кафе, работа) поиск лучше выключить."`
- `LAN_FIRST_RUN_TEXT = "Искать друзей в этой локальной сети? Тогда компьютеры в одной сети найдут друг друга сами, даже если сменили адреса. Можно выключить в настройках."`

## 11. Stand and manual checks (not runnable on this Windows host)
`tools/netns/stage13v.sh` (helpers from `stage13.sh`; node = `cargo run --example node13 -p chervo-connect`). Bridge `br0` 192.168.77.0/24, no router; hosts A, B (nodes), C (stranger), D (silent).
- **LAN1:** A, B befriend (invite, `--sas-auto-confirm`), stop. Change both IPs (.2→.12, .3→.13). Start both with `--lan --expect-connected ... --expect-path lan --deadline 20` → PASS. Capture on br0: every UDP datagram from A or B to the group has UDP payload 557 and IP TTL 1. A and B send nothing to destinations other than each other, the group and IGMP (224.0.0.22).
- **LANOFF:** the same without `--lan`: not connected within 60 s; 0 datagrams to the group, 0 IGMP reports for the group.
- **STRANGER:** C sends 2000 random 557-byte datagrams/s to the group and replays captured A beacons from its own IP. B and A send 0 packets to C. After the flood, LAN1 passes within 30 s (record the result during the flood too).
- **SPOOF:** C replays A's beacon with its source rewritten to D (nft snat in C's namespace) → 0 packets from B to D.
- **IFACE:** A also has `br1` 10.9.0.0/24 (not the default route) with listener E joined to the group → E receives 0 beacons.
- **PORTSCAN (Linux):** unicast UDP from C to A:`LAN_PORT` → C receives ICMP port unreachable; A sends nothing else to C.
- **HOSTSAFE:** host network untouched (as stage 16).
Owner, two Windows PCs in the home LAN: **W1** both friends, both closed. Give each a new LAN address (router DHCP reservation, or wait > 24 h without contact). Open both; the friend shows as connected within 30 s, path "LAN". **W2** with LAN discovery off, no LAN connection appears (other paths may still work). **W3** record whether Windows Firewall showed a prompt and what was answered (Q2). Same checks on macOS/Linux if available, else [NP].

## 12. Where verified / not verified
- **Windows locally and CI (3 OS):** all of §8 (pure core, identity, unicast loopback sockets, fake engine, in-memory e2e with quinn on loopback).
- **Only the Linux stand (owner):** real multicast, TTL 1 on the wire, IGMP, interface choice, PORTSCAN, spoofing.
- **Only real machines (owner):** Windows Firewall behaviour, Wi-Fi APs (client isolation, IGMP snooping, multicast-to-unicast conversion), macOS Local Network permission, the full W1 scenario.
- **Not verified in this stage (write in the report, do not claim):** home routers and Wi-Fi APs (beacons may be pruned or dropped; if W1 fails for this reason, report it — a fallback such as limited broadcast needs a spec revision); Windows bind and delivery semantics beyond loopback; full-tunnel VPN behaviour; CPU cost under a line-rate flood beyond the global budget; IPv6.

## 13. Стоп-условия
S0 not done or a candidate is assigned. A fact of §2 does not match the source. A new external package appears in `Cargo.lock`. `unsafe` is needed. A change in `chervo-core`, `chervo-transfer`, `chervo-receive` or `spikes/` is needed. A change of `ConnectConfig`, `EngineEvent`, the knock, KK, ADDR_INFO, invite or friends-file formats is needed. `chacha20poly1305` with `default-features = false` does not offer `AeadInPlace` + `KeyInit`. The unicast loopback tests cannot pass on one CI OS (do not mark them `ignore` without the conductor). An existing guard (`chervo-addr/tests/guard.rs`, identity `src_has_no_io_or_default_store`, `ss_src_guard`, `chervo-connect` `src_guard`) would need an exception. A criterion cannot be checked. In each case: stop and report, do not work around.

## 14. Лимит
At most 2 review-fix rounds, then report to the owner.

## 15. Отчёт builder (max 25 lines per call)
Changed files; criteria commands with their last output lines; what was not done; deviations with reason; what could not run on Windows.

## 16. Process and executors
1. S0: conductor via `combine-scout` (haiku/medium, web).
2. Calls 1-3: `combine-builder` sonnet/**high** (crypto-adjacent keys, hostile-input parser, network). Conductor re-runs the tests of the changed crates and clippy after each call.
3. `combine-verifier` sonnet/low: all criteria of §9 that run on Windows/CI.
4. `combine-security` opus/high on the full diff: D2-D8 and D11-D12; `lan.rs` in identity (labels, subkeys, AAD, constant-time id check, zeroization); `on_datagram` order and bounds; the "never answer" property; the engine filter and strict limiter; non-persistence; guards; fuzz fixture not vacuous.
5. Conductor: libFuzzer on the Linux box; owner: stand and W1-W3.
Critical: everything in `chervo-identity/src/lan.rs`, `chervo-lan/src/{wire,core,net,link}.rs`, `chervo-connect/src/lan.rs`. Not critical: texts, node13 flags, stand script.

## 17. Requirements for other stages (not implemented here)
- **18a (node in `chervo-core`):** the settings key `lan` (`1`/`0`; absent = "not asked yet" = off). `Node::set_lan(on: bool)` persists it and calls `attach_lan(LanDiscovery::start(clock))` / `detach_lan()`. `Node::open` attaches only if `lan=1`. `shutdown` calls `detach_lan` before `engine.shutdown` (or relies on the engine doing it). `SettingsView` shows `lan` and `lan_status`. `chervo-core` may depend directly on `chervo-lan`; the layout allow-list (D1 of spec 18) gets `chervo-lan`.
- **18b (GUI):** the first-run screen shows `LAN_FIRST_RUN_TEXT` with the box pre-checked (Q1 default) and saves the answer. The settings toggle shows `LAN_DISCOVERY_TEXT`. Status line for `Unavailable`: «Не удалось включить поиск в локальной сети (порт занят или запрещён)».
- **18c (CLI):** `lan on|off|status`; until set, off.
- **IPv6 stage («приём по IPv6»):** group ff02::/16 (candidate, check the registry then), interface index of the default IPv6 route (std gives none: design needed), the same beacon format with `fam = 6`.
- **19:** Windows Firewall per Q2; macOS Local Network permission text in the installer notes.
- **SECURITY_REVIEW / 17 repeat:** section "Этап 13в" from the security review of this stage.
- **TASK / OPEN_QUESTIONS:** close U9 after acceptance; 16a Q1 (24 h constant) can stay, LAN discovery removes its main cost.

## 18. THREAT_MODEL deltas (to apply after acceptance; Russian text ready to paste)
- **Summary table, new row:** `| T17 | Поиск в LAN (маяки) | Ш1, Ш2 | маяк фиксированного размера без ключа, имени и порта в открытом виде; метки пар меняются раз в минуту; порт зашифрован для каждого друга; никогда не отвечаем; найденный адрес только кандидат для стука и KK, не сохраняется до KK | 13в, 18 | не реализовано (13в) | факт «здесь Червоточина» и IP виден LAN; поток мусора выключает только поиск в LAN; лгущий друг: ≤ 1 набора в 32 с на IP в LAN; при полном VPN маяки уходят в сеть VPN; время смены меток выдаёт сдвиг часов |`
- **T1, bullet «Наблюдатель в LAN» (replace):** «Поиск в LAN (этап 13в, T17): раз в ~60 с датаграмма 557 байт на 239.255.x.y (TTL 1) и вступление в группу (IGMP). Без ключа, имени и порта в открытом виде; связать устройство между сетями по маяку нельзя [В]. Видно: IP, факт работы программы, время запуска и смены сети. Роутер провайдера в домашней сети тоже это видит.»
- **T2 and T1 «лгущий друг» (add):** «Маяк друга с поддельным IP источника в той же LAN заставляет нас набрать этот IP не чаще раза в 32 с (строгий ограничитель), только частные адреса.»
- **T8 (add):** «Порт QUIC в маяке зашифрован для каждого друга (он постоянный и выдал бы ноутбук в разных сетях). IP в LAN виден всем в сегменте.»
- **T14 (add):** «Метки поиска в LAN: своя на пару и направление, меняется каждые 60 с, из ключа пары, независима от стука. Незнакомец не узнаёт ни пару, ни число друзей (всегда 16 ячеек, пустые неотличимы) [В]. Остаток: момент смены меток показывает сдвиг часов отправителя внутри минуты.»
- **T16 (add):** «Новый разборщик враждебного ввода из LAN: датаграмма ровно 557 байт, 16 поисков по таблице, не больше 2 расшифровок; общий и пер-IP бюджеты; fuzz `lan_beacon`. Поток (в том числе с поддельных IP) выключает только поиск в LAN.»
- **T15 (add):** «Эпоха поиска по скорректированным часам; сдвиг больше ~1 минуты — друзья в LAN не находятся (и стук не прошёл бы).»
- **T17, принятый остаток (круг 1 ревью безопасности, 2026-10-25) (add):** «Смена IP в пределах эпохи (≤ 60 с) связывает старый и новый адрес для наблюдателя в LAN: метки ячеек не зависят от адреса и не меняются внутри эпохи, меняется только зашифрованный порт. Через эпоху связь пропадает.»
- **New section T17 «Поиск друзей в локальной сети (этап 13в)»:** Актив: неотслеживаемость устройства и пар, число друзей, доступность, CPU. Атакующие: хост LAN не-друг (пассивный и активный, с подделкой IP), клиент того же Wi-Fi, роутер провайдера, лгущий друг, сканер из интернета (DMZ). Меры: D2-D12 этой спецификации кратко. Остаётся: присутствие и IP; IGMP; при DMZ/белом IP на Windows порт поиска принимает одноадресные датаграммы (на Linux/macOS нет, PORTSCAN); при полном VPN маяки идут в сеть VPN; поток мусора выключает поиск; сдвиг часов внутри минуты как слабый отпечаток; поведение реальных роутеров не проверено.
- **«Что модель угроз НЕ покрывает», last bullet:** remove «поиск в LAN mDNS (13в)» after acceptance.

## 19. Для владельца (кратко, по-русски)
- Делаем свой маленький «маяк», а не mDNS. Готовой библиотеки mDNS в доступном реестре нет. Разбор настоящих DNS-сообщений из сети опаснее и сложнее, а совместимость с чужими программами нам не нужна. Новых библиотек нет: только те, что уже в проекте (BLAKE2s, ChaCha20-Poly1305, socket2).
- Маяк — одна датаграмма 557 байт раз в минуту, только в своей локальной сети (TTL 1). В ней нет ключа, имени, номера порта и постоянного идентификатора. Есть 16 «ячеек»: часть для друзей, с которыми сейчас нет связи, остальные пустые. Пустые ячейки неотличимы от настоящих, поэтому чужой не узнаёт ни кто вы, ни сколько у вас друзей. Метки меняются каждую минуту, и связать ваш ноутбук в кафе и на работе по маяку нельзя.
- Друг узнаёт свою ячейку по ключу вашей пары и узнаёт из неё ваш адрес. Дальше обычный путь: стук и проверка ключа пары. Адрес из маяка ничему не доверяется и на диск не пишется. Сохраняется только после успешного соединения, как сейчас.
- Программа никогда не отвечает на чужие датаграммы, поэтому выманить из неё что-то нельзя. Мусор из сети ограничен по объёму и, в худшем случае, выключает только поиск в LAN.
- Работает только на основном сетевом подключении с частным адресом (192.168.x.x, 10.x.x.x, 172.16-31.x.x). IPv6 — в следующем малом этапе.
- По умолчанию поиск выключен, пока вы не ответите на вопрос при первом запуске (галочка уже стоит). Можно выключить в настройках (вопрос 1).
- Проверяется в CI (3 ОС) на локальной петле и модели. Настоящий multicast проверяется стендом на Linux-машине и вами на двух домашних ПК. Этап закрывается только после этой ручной проверки.

## 20. Вопросы владельцу (также в `docs/OPEN_QUESTIONS.md`)
**13в Q1. Включать ли поиск в LAN без вопроса.** Варианты: (А) включён сразу после установки; (Б) выключен, пока пользователь не ответит на вопрос при первом запуске (галочка уже стоит); (В) выключен, включается только в настройках. **Решение до ответа: (Б).** Ничего не уходит в сеть без одного явного «да», а включить можно одним нажатием (ваше решение Q7: релиз 1 с поиском в LAN). Минус (А): ноутбук сообщает о себе в каждой сети (кафе, работа), пока пользователь не узнает о настройке.
**13в Q2. Если брандмауэр Windows не пропускает маяки.** Варианты: (а) пользователь нажимает «Разрешить» в окне Windows при первом запуске, а программа объясняет, зачем это; (б) установщик (этап 19) сам добавляет правило брандмауэра, для этого нужны права администратора при установке; (в) ничего не делать, тогда на таких ПК поиск в LAN не работает. **Решение до ответа: (а).** Программа не меняет системные настройки без вашего решения. Проверка W3 покажет, нужно ли это вообще.

## S0 result (conductor, 2026-10-25)
- Ports: `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv` (downloaded 2026-10-25): `47131` falls in the row `,47101-47556,,Unassigned` (UDP and TCP) [P]. **`LAN_PORT = 47131`.**
- Multicast: `https://www.iana.org/assignments/multicast-addresses/multicast-addresses.txt` (Last Updated 2026-08-20): `239.0.0.0-239.255.255.255 Organization-Local Scope [RFC 2365]`, no sub-assignment covering 239.255.112.47 [P]. RFC 2365 (`https://www.rfc-editor.org/rfc/rfc2365.txt`) §6.1: "239.255.0.0/16 is defined to be the IPv4 Local Scope"; §9: only the high /24 (239.255.255.0/24) is reserved for relative assignments, the rest is for dynamic use [P]. **`LAN_GROUP_V4 = 239.255.112.47`.**
