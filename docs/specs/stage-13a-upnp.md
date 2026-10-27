# SPEC 13a: UPnP IGD, own minimal client          criticality: CRITICAL (parts U1, U2, U3 except texts)

Author: combine-architect (opus), 2026-10-17, revision 1. Labels: [P] verified by me in the source (file:line); [V] architect's inference; [D] from memory, not re-checked; [NP] not verified. **Nothing was run.** Owner decision: `docs/OWNER_DECISIONS.md:95` (Q1 = C: own client without an XML library, body ≤ 64 KiB, 3 s deadline, every `<!` rejected, fuzz, security review; igd-next never enters the product).

**New:** one path crate `chervo-upnp`. **No new external package:** its only external normal dependency is `socket2 =0.6.5`, already in `Cargo.lock` (fact 9), features none. `chervo-upnp` has no tokio, no XML/HTTP crate, no DNS. `chervo-connect` never depends on `chervo-upnp` (dependency inversion through a trait in `chervo-addr`).

Goal: on a stationary computer behind a home router, the program opens a UDP port on the router by UPnP IGD, verifies it, publishes it to friends as a stable address (`NatView::PortMapped`), keeps it alive with a short lease and closes it on exit and on network change; the router's WAN IP feeds the CGNAT / double-NAT diagnosis. On a laptop in a foreign network nothing happens by default. Every byte from the LAN is hostile input.

Read: this file; `docs/specs/stage-13-connect.md` ("Decisions" 8, 12; "Watcher"; "Diagnosis"; "Requirements for other stages"); `crates/chervo-addr/src/{own,probe,class}.rs`; `crates/chervo-connect/src/{engine,watch,diag,texts,clock,config,lib}.rs`, `src/tests/{src_guard,kit}.rs`; `crates/chervo-token/tests/fuzz_smoke.rs` (pattern); `spikes/transport/run8.sh` (miniupnpd stand helpers, for U4 only). Search nothing else.

## Scope
| Item | Here | Note |
|---|---|---|
| SSDP discovery, description, SOAP (4 actions + AddAny), lease lifecycle, consent hooks | yes | |
| Gateway identification without OS route APIs | yes (heuristic, decision 4) | residual risk stated; Q1 |
| WAN IP -> `BehindCgnat` / `DoubleNat` diagnosis | yes | new reason `DoubleNat` |
| NAT-PMP / PCP, IPv6 pinholes (WANIPv6FirewallControl) | no | deferred by owner (TASK stage 8 line); IPv6 stage later |
| Settings storage and UI screens | no -> stage 18 | this stage gives types, texts and status events |
| Wiring into the product binary (`chervo-core`/`chervo-cli`) | no -> stage 18 | example binary `upnp_probe` for the owner's real router |
| HTTP/1.1 chunked bodies, routers whose control port differs from the description port | no | Q3; stage 16 collects real-router evidence |

## Decisions (rationale)
1. **BRIEF 2 (no third parties) is respected.** BRIEF 5 item 3 lists "IPv4 с UPnP / NAT-PMP / PCP" as a direct path. The home router is the user's own device, already on the path of every packet; it is not a service, not a server of a third party, not STUN/DDNS/telemetry. The SSDP M-SEARCH is a multicast datagram with IP TTL 1 (decision 4): it never leaves the link, carries no key, name, pair id or user agent, only the fixed search target. HTTP/SOAP go only to the one validated responder on the link. No DNS (IPv4 literals only). In a network that is not the user's (hotel, office) the router is somebody else's equipment: **off by default** (decision 6). Stage 8 capture (SPIKE_TRANSPORT 9.3, G5 "traffic") confirmed for igd-next: SSDP + gateway + peer only, dns = 0 [P doc]; U4 repeats the capture for our client.
2. **Crate placement and direction.** New `crates/chervo-upnp` (normal deps: `chervo-addr`, `socket2 =0.6.5`). All network I/O is blocking `std`/`socket2` with explicit deadlines: no tokio inside, fully testable with std threads on Windows. The engine-facing contract is a **blocking trait in `chervo-addr`** (`PortMapper`, decision 10) which already owns `GatewayInfo`; `chervo-upnp` implements it, `chervo-connect` consumes it through `Arc<dyn PortMapper>` and calls it only inside `tokio::task::spawn_blocking` (tokio `rt` feature, fact 10). So `chervo-connect` still opens no socket and its source guard keeps forbidding sockets and the words `upnp`/`igd` (fact 6); only the `set_gateway(` rule changes (exactly in a new `gateway.rs`). Direction: `chervo-upnp -> chervo-addr -> chervo-identity`; `chervo-connect -> chervo-addr`; the product (stage 18) depends on both.
3. **HTTP/1.0 only.** Requests are `HTTP/1.0` with `Host` and `Connection: close`; a server must not send chunked to a 1.0 client, so any `Transfer-Encoding` header is rejected. Body ends at `Content-Length` or EOF, ≤ 64 KiB. Total deadline 3 s per request (connect + write + read), enforced by re-arming the read timeout with the remaining time before every `read` (defeats slowloris). Redirects (3xx) are errors, never followed.
4. **Gateway identification without route APIs and without unsafe.** std exposes neither the route table nor the netmask; `unsafe_code = "forbid"` excludes FFI (fact 8). The rules, all required:
   (a) own source IPv4 = `RouteSources.v4` from the existing probe (`probe.rs:31-59` [P]), class `Private`; `Global` (white IP, no mapping needed) or `Shared` (host inside CGNAT) -> the mapper is not called;
   (b) M-SEARCH from a UDP socket bound to `(own_ip, 0)`, `set_multicast_if_v4(own_ip)`, `set_multicast_ttl_v4(1)`, `set_multicast_loop_v4(false)` (fact 9): only on-link hosts receive it;
   (c) responder accepted only if its source IP is `Private`, differs from `own_ip`, the response is well-formed (limits below) and the `LOCATION` host is an IPv4 literal **equal to the responder's source IP**;
   (d) every TCP connection to the gateway is made with `socket2` `set_ttl_v4(1)` **before** `connect_timeout` and bound to `(own_ip, 0)`: a host that is not on-link can never complete the handshake (packets with TTL 1 are not forwarded), and the router sees requests from exactly the internal client we map (miniupnpd secure mode) [V; TTL behaviour on Windows NP, U4 row];
   (e) **exactly one IGD**: after the discovery window, distinct accepted responder IPs offering an IGD are counted; with an allowlist (decision 6) the candidates are those whose description `UDN` is allowlisted; more than one candidate -> `Ambiguous`, no mapping. **Rev. 2 after security review (fail closed):** the discovery is also `Ambiguous` (for mapping and for `identify()`, nothing is evaluated) when any responder IP sent two different LOCATIONs, the datagram cap `SSDP_MAX_DGRAMS` (or the same number of receive errors) was hit, more than `MAX_RESPONDERS` distinct responder IPs answered, or any responder could not be evaluated (description GET) before the overall deadline;
   (f) the WAN IP is checked (decision 8) and the mapping is believed only after `GetSpecificPortMappingEntry` confirms it (decision 7).
   **Residual risk (state in THREAT_MODEL T16; rev. 2: with the fail-closed rule of (e) a LAN host can no longer push the real router out of the choice by a spoofed datagram, a flood or a description stall; it is taken for the router only when the real router is genuinely silent or ARP-spoofed):** a host on the user's home LAN that knows the router's UDN and answers when the real router is silent (UPnP disabled, or the real response suppressed by ARP spoofing) is taken for the router: it can name a false WAN IP (we publish `false_ip:port` to friends as a non-hint address: friends dial it under their limiters, stage 13 decision 5) or fake a successful mapping (we look reachable and are not). An ARP-spoofing LAN attacker is a full MITM to the router anyway, so a route-table check would not stop him; it would only stop a non-spoofing impostor while the real router is silent. Any LAN host can also talk to an IGD without secure mode and delete or steal our mapping (UPnP has no authentication; review 8 item 3): then inbound fails; the knock (9b) and KK still protect the port. Spoofed SSDP source can make us GET one path from another on-link host (Low, review 8 "Прочее"). Q1.
5. **No XML library: a fixed-subset scanner** (`scan.rs`, U1 below) that refuses DTDs, comments, CDATA, processing instructions, unknown entities and character references, then two fixed extractors (`desc.rs`, `soap.rs`) that match element paths by local name. Nothing is expanded, so the stage-8 bomb (review 8 item 1) is rejected at its `<!`.
6. **Off by default; home network = allowlisted router.** `UpnpSettings { routers: Vec<AllowedRouter> }`, default empty = the mapper sends nothing at all. The user enables it by an explicit action "открывать порт автоматически на этом роутере": `UpnpMapper::identify(own_ip)` runs one discovery + description fetch and returns an opaque `RouterId` (the root device `UDN`), which the UI asks to confirm and stage 18 persists. In other networks (laptop) with a non-empty list: discovery + description fetch still run (needed to recognise the router), no SOAP is sent unless the UDN is allowlisted (`NotHomeNetwork`). ≤ 4 routers.
7. **Lease lifecycle.** Lease 3600 s (never more); renew at half of the confirmed lease (`max(lease/2, 60 s)`); internal client = own IP only; internal port = our listen port P; external port P first; description `"udp"` (neutral, visible to every LAN host). Ours = `NewInternalClient == own_ip && NewInternalPort == P && protocol UDP && description == "udp"`. At the first refresh after attach and after every network change: `GetSpecific(P)`; if it is ours -> `Delete` (stale entry of a crashed run), then `Add`. Without persistence a stale entry on another external port (after a 718 fallback) disappears at its lease end (≤ 1 h) [V]; permanent leases (725 consent) are always on ext = P, so the start-up check finds them. On network change the old mapping is deleted best-effort before mapping the new one; `release()` on exit deletes the current one after re-checking it is still ours. Errors: table "Error codes".
8. **WAN IP checks** (`GetExternalIPAddress`, before any `Add`): strict dotted IPv4; `Global` -> continue; `Shared` (100.64/10) -> `BehindCgnat`, no `Add`; `Private` -> `DoubleNat`, no `Add`; empty string -> `WanUnknown`, no `Add` (miniupnpd behind CGNAT returns empty, SPIKE 9.3 cgnat [P doc]); any other class -> `Failed`. `GatewayInfo.wan_ip` is set for Global, Shared, Private (diagnosis needs it), `mapping` only after confirmation.
9. **Engine side keeps stage-12 semantics.** `nat_view` is unchanged: confirmed mapping on a Global WAN -> `PortMapped`, published non-hint (`own.rs:325-329, 416-421` [P]). Stricter alternative (mapping only as hint until a friend's observation matches the WAN IP) was rejected: one lying friend could then cancel a router-confirmed mapping; the router of an allowlisted UDN is the better witness [V].
10. **Results flow.** The engine owns the schedule (attach, own address change, renew timer, user "refresh"); the mapper owns protocol state (its current mapping record). A result is applied only if the snapshot it was requested for (own IP, listen port) is still current; `set_local` already clears the gateway on every change (`own.rs:200-211` [P]).

## Facts from the source
1. `GatewayInfo { wan_ip: Option<Ipv4Addr>, mapping: Option<SocketAddrV4> }`, Debug redacted, comment "задаётся только этапом 13 ... GetSpecificPortMappingEntry" (`chervo-addr/src/own.rs:36-49`) [P].
2. `set_local` clears observations and gateway on any change (`own.rs:200-211`); `set_gateway` plain setter (`:217-219`) [P].
3. `nat_view`: route Global -> Public, Shared -> BehindCgnat, WAN Shared -> BehindCgnat, WAN Private -> DoubleNat, Global WAN with mapping IP == WAN -> PortMapped (`own.rs:302-329`); publish step (2) mapping non-hint (`:416-421`) [P].
4. Probe: UDP `connect` to 192.0.2.1:9, `local_addr`, no data sent (`probe.rs:1-59`); chervo-addr guard: `UdpSocket` only in `probe.rs`, no `.send(`/`send_to(` in `src` (`tests/guard.rs:22-43`) [P].
5. `AddrClass` and `classify` (`class.rs:11-24, 129-146`) [P].
6. chervo-connect `src_guard`: no `UdpSocket`, `TcpStream`, `TcpListener`, `send_to`, `lookup_host`, `to_socket_addrs`; no `rendezvous|stun|igd|upnp|mdns` (case-insensitive) except `rendezvous_could_help`; no `Command::new`, `std::process`, `tokio::net` in production code; `set_gateway(` count 0 (`src/tests/src_guard.rs:52-81, 106`) [P].
7. `Engine::start` signature and task spawning (`engine.rs:906-964`); `EngineEvent` `#[non_exhaustive]` (`:93-124`); watcher `on_own_change` (`watch.rs:31-45`); `diag` maps `BehindCgnat`, `Symmetric` (`diag.rs:137-138`), `rendezvous_could_help` for `BehindCgnat | NeedToken` (`:36-38`) [P].
8. Workspace lints `unsafe_code = "forbid"`; tokio `=1.53.3` features `rt, net, time, sync, macros` (root `Cargo.toml:51-54`) [P].
9. `socket2 0.6.5` in `Cargo.lock:1467-1474` (deps `libc`, `windows-sys 0.61.2`); features only `all = []` (`socket2-0.6.5/Cargo.toml:86-87`); not behind `all`: `connect_timeout` (`src/socket.rs:215`), `set_read_timeout` (`:1104`), `set_write_timeout` (`:1175`), `set_multicast_if_v4` (`:1546`, cfg not wasi), `set_multicast_loop_v4` (`:1574`), `set_multicast_ttl_v4` (`:1604`), `set_ttl_v4` (`:1630`), `send_to` (`:697`), `recv_from` (`:528`, `MaybeUninit` buffer; use `std::net::UdpSocket::from(socket)` for safe `recv_from`) [P].
10. `tokio::task::spawn_blocking` under `cfg_rt!` (`tokio-1.53.3/src/task/mod.rs:277-281`); blocking tasks cannot be aborted (`:140-141`) [P].
11. Layout test lists crates and forbids quinn/tokio/rustls/iroh in `chervo-core`'s manifest (`chervo-core/tests/layout.rs:9-40`) [P].
12. Fuzz-smoke pattern: xorshift64*, fixed seed, `CHERVO_FUZZ_ITERS` (`chervo-token/tests/fuzz_smoke.rs:1-3`) [P].
13. miniupnpd 2.3.4: mapping with 120 s / 30 s lease honoured, removed at lease end after `kill -9`; WAN in 100.64/10 -> empty external IP and `AddPortMapping` 501 (SPIKE_TRANSPORT 9.3) [P doc].

## Do (three builder calls; verify each step before the next, CORE 5)
### Call 1: builder sonnet/high. Part U1 (pure parsers, no sockets)
1. `cargo --version`, `rustc --version` (1.99.1); `BASE=$(git rev-parse HEAD)`. Check facts 1, 6, 9 by `grep -n`; mismatch -> STOP.
2. Create `crates/chervo-upnp` (workspace member and `workspace.dependencies` entry; `socket2 = { version = "=0.6.5", default-features = false }` in the crate only), lint block of `chervo-identity/src/lib.rs:6-13` (no unwrap/expect/indexing/panic, no print). Modules `limits, scan, url, ssdp (parse/build only), http (build/parse only), desc, soap, error`. Unit tests U1 + fuzz smoke.
### Call 2: builder sonnet/high. Part U2 (network and lifecycle)
3. `net.rs` (the only socket code), `mapper.rs`, `texts.rs`, `src/tests/fake_igd.rs` + tests U2, `examples/upnp_probe.rs`, crate `src_guard`.
### Call 3: builder sonnet/high. Parts U3, U4
4. `chervo-addr/src/mapper.rs` (trait and types), `chervo-connect` `gateway.rs`, diag `DoubleNat`, guard update, tests U3.
5. `tools/netns/stage13a.sh` (Linux + root; **cannot run on this Windows host**: write, `bash -n`, shellcheck if present). All criteria; report.
Note: U0 (the trait in `chervo-addr`) is needed by Call 2 (`impl PortMapper`): Call 2 creates `chervo-addr/src/mapper.rs` first; Call 3 only consumes it.

## Interface (exact)
All types holding addresses, UDNs, paths print `"TypeName(..)"` in `Debug`; no `Display` of router text; errors are enums without `String` (review 8 item 4). No logging.

### U0. chervo-addr (`src/mapper.rs`, re-exported; no socket code: chervo-addr guard unchanged)
```rust
#[derive(Clone, Copy, PartialEq, Eq)]                     // Debug redacted
pub struct MapRequest { pub internal: SocketAddrV4 }       // own route-source IPv4 (Private) : listen port (≠ 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum MapStatus { Off, NotHomeNetwork, NoGateway, Ambiguous, WanUnknown, BehindCgnat, DoubleNat,
                     NeedPermanentConsent, Refused(u16), Failed, Mapped, MappedPermanent }
#[derive(Clone, Copy, PartialEq, Eq)]                     // Debug redacted
pub struct MapReport { pub status: MapStatus, pub gateway: Option<GatewayInfo>, pub retry_after: Duration }
pub trait PortMapper: Send + Sync {
    /// Blocking. Returns within MAX_REFRESH (25 s) whatever the network does.
    fn refresh(&self, req: MapRequest) -> MapReport;
    /// Blocking, ≤ 5 s. Deletes the current mapping if the router still shows it as ours.
    fn release(&self);
}
```
`MapReport.gateway`: `Some` only per decision 8 (`mapping` only if confirmed). `retry_after`: Mapped -> `max(lease/2, 60 s)`; MappedPermanent -> 1800 s (re-check by `GetSpecific`); Refused/Failed/NoGateway/WanUnknown -> backoff computed by the mapper (60 s doubling to 1800 s, reset on success or network change); Off/NotHomeNetwork/NeedPermanentConsent/Ambiguous/BehindCgnat/DoubleNat -> 1800 s.

### U1. chervo-upnp parsers (private modules; `pub(crate)`)
**limits.rs** (constants, all used): `SSDP_DGRAM_MAX = 1472`, `SSDP_RECV_BUF = 2048`, `SSDP_MAX_HEADERS = 20`, `SSDP_MAX_DGRAMS = 64`, `MAX_RESPONDERS = 8`, `DISCOVERY_WINDOW = 2 s`, `HTTP_DEADLINE = 3 s`, `HTTP_HEAD_MAX = 8192`, `HTTP_MAX_HEADERS = 64`, `BODY_MAX = 65536`, `XML_MAX_DEPTH = 16`, `XML_MAX_ELEMENTS = 2048`, `XML_NAME_MAX = 64`, `XML_DECL_MAX = 128`, `VALUE_MAX = 256`, `PATH_MAX = 256`, `UDN_MAX = 128`, `MAX_SERVICES = 4`, `LEASE_SECS = 3600`, `MIN_RENEW = 60 s`, `MAX_REFRESH = 25 s`, `RELEASE_BUDGET = 5 s`, `ALT_PORT_TRIES = 3`, `MAX_ROUTERS = 4`, `DESC = "udp"`.

**url.rs.** `parse_location(&str, responder: Ipv4Addr) -> Result<HttpTarget, UrlError>`: exactly `http://` (scheme compared case-insensitively), authority = IPv4 literal `d.d.d.d` (each 1-3 digits, ≤ 255, no leading zero unless "0") with optional `:port` (1-5 digits, 1..=65535; absent -> 80); no userinfo (`@`), no IPv6 `[`, no hostname; host must equal `responder`; then path (required, starts `/`, ≤ `PATH_MAX`, chars `A-Za-z0-9-._~/!$'()*+,:@%` (rev. 2: `;` and `=` removed), no `..` segment, no `%` not followed by two hex digits, `%00`, `%2f`, `%5c` (case-insensitive) rejected); no `?`, `#`. `HttpTarget { gw: GatewayAddr, path: Path }`; `GatewayAddr(SocketAddrV4)` constructor `pub(crate)` in `url.rs` only, used by `ssdp.rs` after the responder check. `control_url(value, &HttpTarget /*LOCATION*/) -> Result<Path, UrlError>`: value starting `/` -> path rules; starting `http://` -> same parsing, host **and** port must equal LOCATION's, return path; otherwise (relative) -> `"/" + value`, then path rules. `URLBase` (IGDv1), if present, must parse and equal LOCATION's host and port, else reject the description; it is never used for resolution.

**scan.rs** (the core hostile-input code). `scan(body: &[u8], f: impl FnMut(Event) -> Result<(), ScanError>) -> Result<(), ScanError>`, `Event { Start{name}, End{name}, Text{raw} }` where `name` = local name (part after the last `:`) and `raw` is a byte slice. Order of checks over the whole body before any event: length ≤ `BODY_MAX`; optional UTF-8 BOM at offset 0 skipped; bytes 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F -> `Control`; substring `<!` anywhere -> `Markup` (DOCTYPE, ENTITY, comment, CDATA). Then a single pass:
- `<?` allowed only once, as the first markup after optional whitespace: must end with `?>` within `XML_DECL_MAX` bytes and contain no `<`, `&`, `[`, `%`; every other `<?` -> `Markup`.
- `&` must start exactly one of `&amp; &lt; &gt; &quot; &apos;`; `&#`, `&x;` or a bare `&` -> `Entity` (in text and in attribute values).
- Start tag: `<` + name (`[A-Za-z_][A-Za-z0-9_.:-]*`, ≤ `XML_NAME_MAX`, ASCII) + attributes skipped up to `>` with quote tracking (`"`/`'`; inside quotes `<` -> `Syntax`; bytes ≥ 0x80 allowed inside quotes only) + optional `/` before `>` (self-closing = Start + End). End tag: `</` + name + optional whitespace + `>`; must equal the top of the stack (full name, prefix included) -> else `Mismatch`.
- Depth ≤ `XML_MAX_DEPTH`, elements ≤ `XML_MAX_ELEMENTS`; non-whitespace text outside the root, a second root, EOF with open elements -> `Syntax`. Bytes ≥ 0x80 allowed only in text and quoted attribute values (never in names).
**Value decoding** (`value(raw) -> Result<String, ScanError>`, used only for extracted fields): trim ASCII whitespace; decode the five entities; result ASCII printable 0x20-0x7E only, length ≤ `VALUE_MAX`.

**desc.rs.** `parse_description(body, &HttpTarget) -> Result<Description, DescError>`, `Description { udn: Udn, services: Vec<Service> }` (`Service { kind: ServiceKind, control: Path }`, `ServiceKind { WanIp2, WanIp1, WanPpp1 }`). Rules: root element local name `root`; first `device` directly under `root` = root device; its direct child `deviceType` value must be `urn:schemas-upnp-org:device:InternetGatewayDevice:1` or `:2`; its direct child `UDN`: exactly once, starts with `uuid:`, ≤ `UDN_MAX`, chars `A-Za-z0-9-:._`; optional `URLBase` directly under `root` (at most once; url.rs rule). Each `service` element (any depth): direct children `serviceType` and `controlURL`, each **at most once** (a duplicate -> `Duplicate`, whole document rejected); `serviceType` equal to one of `urn:schemas-upnp-org:service:WANIPConnection:2`, `...WANIPConnection:1`, `...WANPPPConnection:1` -> candidate with `control_url(...)`; other types ignored; a candidate with missing or invalid controlURL -> reject the document. Candidates sorted WanIp2, WanIp1, WanPpp1 (stable), deduplicated by (kind, path), first `MAX_SERVICES` kept; none -> `NoService`. Duplicate `deviceType`/`UDN` under the root device -> `Duplicate`.

**ssdp.rs.** `msearch(st) -> Vec<u8>` exactly:
`M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: <st>\r\n\r\n` with `st` ∈ {`urn:schemas-upnp-org:device:InternetGatewayDevice:1`, `...:2`} (two datagrams, each sent at t = 0 and t = 300 ms). `parse_response(dgram, src: SocketAddrV4, own_ip, policy) -> Result<Responder, SsdpError>`: len ≤ `SSDP_DGRAM_MAX`; ASCII printable + CRLF only; first line starts `HTTP/1.1 200`; ≤ `SSDP_MAX_HEADERS` header lines, each `Name: value`, names case-insensitive, no leading whitespace (obs-fold); `LOCATION` exactly once, `ST` exactly once and equal to one of the two STs; `src.ip()` class `Private` (policy may allow `Loopback` in tests only, `pub(crate)`), ≠ own_ip; `parse_location(.., src.ip())`. `select(responders) -> Selection { responders, ambiguous }` (rev. 2 after security review): one entry per responder IP, ≤ `MAX_RESPONDERS`; an IP that sent two different LOCATIONs is not listed and sets `ambiguous` (it is no longer silently dropped, which let one spoofed datagram remove the real router); more than `MAX_RESPONDERS` distinct IPs also sets `ambiguous`. `discover` additionally sets `ambiguous` when the datagram cap or the receive-error cap is hit.

**http.rs.** Request builder `request(method, &GatewayAddr, &Path, soap: Option<(service_type: &'static str, action: &'static str, body: &str)>) -> Vec<u8>`:
```
GET <path> HTTP/1.0\r\nHost: <ip>:<port>\r\nConnection: close\r\n\r\n
POST <path> HTTP/1.0\r\nHost: <ip>:<port>\r\nContent-Type: text/xml; charset="utf-8"\r\nSOAPAction: "<serviceType>#<Action>"\r\nContent-Length: <n>\r\nConnection: close\r\n\r\n<body>
```
`serviceType` is our constant for the matched `ServiceKind`, never the router's string. Response parser over the received bytes: headers end at the first `\r\n\r\n` within `HTTP_HEAD_MAX` (else `HeadTooLarge`); status line `HTTP/1.0 ddd` or `HTTP/1.1 ddd` + space or CRLF; header bytes ASCII printable; ≤ `HTTP_MAX_HEADERS`; obs-fold -> reject; any `Transfer-Encoding` -> `Chunked`; `Content-Length` at most once, digits only, ≤ `BODY_MAX`; body = exactly `Content-Length` bytes (fewer before EOF -> `ShortBody`, extra bytes ignored) or up to EOF (more than `BODY_MAX` -> `TooLarge`). Status: 200 -> body; 500 -> body to the SOAP fault parser; 3xx -> `Redirect`; other -> `Status(u16)`. `Content-Type` not checked.

**soap.rs.** Envelope template (one line, no whitespace between tags):
`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:ACTION xmlns:u="SERVICETYPE">ARGS</u:ACTION></s:Body></s:Envelope>`
Arguments (only our numbers, our dotted IPv4 and constants; `NewRemoteHost` always empty):
- `GetExternalIPAddress`: none. Response `NewExternalIPAddress`.
- `AddPortMapping`: `<NewRemoteHost></NewRemoteHost><NewExternalPort>E</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>P</NewInternalPort><NewInternalClient>A.B.C.D</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>L</NewLeaseDuration>`. Response: none required.
- `AddAnyPortMapping` (WanIp2 only): same arguments; response `NewReservedPort` (1..=65535).
- `GetSpecificPortMappingEntry`: `<NewRemoteHost></NewRemoteHost><NewExternalPort>E</NewExternalPort><NewProtocol>UDP</NewProtocol>`; response `NewInternalPort`, `NewInternalClient`, `NewEnabled`, `NewPortMappingDescription`, `NewLeaseDuration`.
- `DeletePortMapping`: same three arguments; response none.
Response parsing: path by local names `Envelope/Body/<Action>Response/<field>`; the `<Action>Response` element exactly once; each expected field at most once (`Duplicate`); unknown children ignored; missing required field -> `Missing`. Field rules: ports 1-5 digits, 1..=65535; `NewEnabled` `1|0|true|false` (case-insensitive); lease 0..=604800 digits; IPv4 strict (url.rs octet rule); external IP may be empty (`None`); description compared byte-exact with `DESC` after value decoding. Fault (HTTP 500): `Envelope/Body/Fault/detail/UPnPError/errorCode` exactly once, 1-4 digits -> `Upnp(code)`; otherwise `FaultNoCode`.

### U2. chervo-upnp public API, network, lifecycle
```rust
pub struct RouterId(/* Udn */);                 // Debug redacted; Clone, PartialEq, Eq
impl RouterId { pub fn to_setting(&self) -> String; pub fn from_setting(s: &str) -> Result<Self, UpnpError>; } // UDN rules of desc.rs
#[derive(Clone, PartialEq, Eq)] pub struct AllowedRouter { pub id: RouterId, pub permanent_ok: bool }
#[derive(Clone, PartialEq, Eq, Default)] pub struct UpnpSettings { pub routers: Vec<AllowedRouter> } // > MAX_ROUTERS -> first 4
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum UpnpError { NoGateway, Ambiguous, Timeout, Io, Protocol, Rejected }   // no payload text
pub struct UpnpMapper { /* settings: Mutex, current: Mutex<Option<Mapping>>, needs_permanent: Mutex<Option<RouterId>>, backoff, net: Net (pub(crate)) */ }
impl UpnpMapper {
    pub fn new(settings: UpnpSettings) -> Self;
    pub fn set_settings(&self, s: UpnpSettings);
    /// Explicit user action (consent to search this network). Requires exactly one IGD responder.
    pub fn identify(&self, own_ip: Ipv4Addr) -> Result<RouterId, UpnpError>;
}
impl chervo_addr::PortMapper for UpnpMapper { /* refresh, release */ }
pub fn status_text(s: MapStatus) -> &'static str;   // texts.rs
```
`Net` (`pub(crate)`): `ssdp_target: SocketAddrV4` (production `239.255.255.250:1900`), `allow_loopback: bool` (false), `http_deadline`, `discovery_window` (production constants; tests shorten). Only `src/tests` constructs a non-default `Net`.

**net.rs (only socket code).** `discover(own_ip, &Net, deadline) -> Selection`: socket2 UDP v4, `bind((own_ip,0))`, multicast options of decision 4b (skipped when `ssdp_target` is unicast in tests), send the 4 datagrams, then `std::net::UdpSocket::from(sock)` and `recv_from` with read timeout = remaining window, ≤ `SSDP_MAX_DGRAMS`; buffer `SSDP_RECV_BUF`, a datagram filling the buffer or a recv error is skipped. `http(gw: &GatewayAddr, own_ip, request: &[u8], deadline) -> Result<Vec<u8>, NetError>`: socket2 TCP v4, `set_ttl_v4(1)`, `bind((own_ip,0))`, `connect_timeout(gw, remaining)`, write with write timeout = remaining, read loop re-arming `set_read_timeout(min(remaining, HTTP_DEADLINE))` before each read, stop at `HTTP_HEAD_MAX + BODY_MAX + 1` bytes (then `TooLarge`) or EOF; per request deadline = `min(now + http_deadline, overall)`. Destinations are only `ssdp_target` and `GatewayAddr` (type built only after the responder check).

**mapper.rs, `refresh(req)`** (overall deadline `now + MAX_REFRESH`; `own_ip = req.internal.ip()`, `P = req.internal.port()`):
0. (rev. 2) `refresh` is guarded by a busy mutex (`try_lock`): while another `refresh` runs (e.g. one abandoned by the engine timeout) a second returns `Failed` (60 s) at once and sends nothing.
1. Settings empty -> forget `current` without sending anything, `Off` (no packet at all).
2. `discover` (`ambiguous` -> `Ambiguous`, backoff); none -> `NoGateway`. For each responder (≤ 8, in arrival order): GET LOCATION, `parse_description`; failures skip that responder, but a responder not evaluated before the overall deadline -> `Ambiguous`. Candidates = responders whose UDN is allowlisted; 0 -> `NotHomeNetwork` (if at least one IGD parsed) else `NoGateway`; > 1 distinct IP -> `Ambiguous`. **Rev. 2 (L2):** in every one of these outcomes `current` is forgotten without sending anything (the address may be a foreign network with the same addressing; the lease <= 1 h expires). With exactly one candidate: if `current` is the same router (UDN, `GatewayAddr`, service) but `current.internal != req.internal` -> `delete_if_ours(current)` bounded by the overall deadline, clear; if `current` is another router -> clear without sending.
3. For each service of the candidate in order: `GetExternalIPAddress`; the first one that answers 200 is used. WAN per decision 8 (non-Global -> report with `gateway { wan_ip, mapping: None }` and stop).
4. Start-up / network-change clean (skipped on renew, see below): `GetSpecific(P)`: ours (decision 7, description compared) -> `Delete(P)`; 714 or another client -> continue.
5. `L = 0` if this router answered 725 before (`needs_permanent`, memory only) **and** its `AllowedRouter.permanent_ok`; else `LEASE_SECS`. `Add(E = P, L)`. Errors: see table. 718 and `L > 0`: WanIp2 -> `AddAnyPortMapping(P)` -> `E = NewReservedPort`; else up to `ALT_PORT_TRIES` random `E` in 49152..=65535 (`getrandom` is not a dependency: `std::collections::hash_map::RandomState` hash of (now, attempt) [V]); `L == 0` -> only `E = P`.
6. `GetSpecific(E)`: must be `client == own_ip`, `internal port == P`, enabled; lease `l`: `l == 0` with `L > 0` -> accepted, status `MappedPermanent` (router made it permanent; release still deletes it) only if `E == P`; with `E != P` (rev. 2, L3) -> `Delete(E)` if ours, `Failed`; `l > L` -> treated as `L`. Not confirmed -> `Failed`, best-effort `Delete(E)` only if ours, no mapping.
7. `current = Mapping { router, service, gw, internal, ext: E, lease }`; report `Mapped` / `MappedPermanent`, `gateway = { wan_ip: Some(wan), mapping: Some(wan:E) }`, `retry_after` per U0.
Renew = the same `refresh` (step 4 is skipped when `current` matches router, internal and `ext`; `Add` with the same arguments refreshes the lease [D: UPnP IGD semantics], then step 6).
`release()`: takes `current` (cleared in any case); rev. 2 (L2): sends nothing unless one discovery + description (budget `RELEASE_BUDGET` for everything) re-confirms the stored router as the single allowlisted candidate (same UDN, `GatewayAddr`, service); then `GetSpecific(ext)`; ours -> `Delete(ext)`. Empty settings or no confirmation -> nothing is sent.

**Error codes** (UPnP IGD WANIPConnection:1/2 [D: values from memory, standard document not available here]):
| Code | Meaning | Action |
|---|---|---|
| 718 ConflictInMappingEntry | ext port taken by another client | alternate port (step 5) |
| 725 OnlyPermanentLeasesSupported | IGDv1 needs lease 0 | remember `needs_permanent`; `permanent_ok` -> retry `L = 0, E = P` in the same refresh; else `NeedPermanentConsent`, no mapping |
| 724 SamePortValuesRequired | E must equal P | if E ≠ P -> `Refused(724)` |
| 606 Action not authorized, 501 ActionFailed, 402 InvalidArgs, 726, 727, 728 NoPortMapsAvailable, 729 ConflictWithOtherMechanisms, any other | refused | `Refused(code)`, backoff |
| 714 NoSuchEntryInArray | no entry | for GetSpecific/Delete: "absent", not an error |
| HTTP 3xx / other status / parse error / timeout | | `Failed` (or `NoGateway` in discovery), backoff |

**texts.rs** (Russian, no placeholders): `status_text` for every `MapStatus`, including
`NEED_PERMANENT_TEXT = "Роутер умеет открывать порт только бессрочно. Разрешить? Порт закрывается при выходе из программы; если программа аварийно завершится, порт останется открытым до её следующего запуска в этой сети."`,
`ENABLE_ON_ROUTER_TEXT = "Открывать порт автоматически на этом роутере? Включайте только в своей сети: в чужой сети (гостиница, офис) устройство, выдающее себя за роутер, может подменить адрес."`,
`AMBIGUOUS_TEXT = "В сети отвечают несколько устройств, похожих на роутер. Порт автоматически не открыт: настройте проброс вручную."`, `REFUSED_TEXT`, `NOT_HOME_TEXT`, `DOUBLE_NAT_UPNP_TEXT`, `CGNAT_UPNP_TEXT`.

### U3. chervo-connect
- `ConnectConfig` += nothing (settings live in `UpnpMapper`).
- `Engine` += `pub fn attach_mapper(&self, m: Arc<dyn PortMapper>) -> Result<(), ConnectError>` (second call -> `ConnectError::Internal`; spawns the gateway task); `pub fn refresh_mapping(&self)` (user action / settings changed: `Notify`); `pub fn mapping_status(&self) -> Option<MapStatus>`.
- `EngineEvent` += `MappingChanged { status: MapStatus }`.
- **`gateway.rs`** (critical) task loop: wait for `Notify` (attach, `refresh_mapping`, own change from `watch.rs::on_own_change`) or the timer `retry_after`. Read `own.local()`: `route.v4` class `Private` and listen v4 port ≠ 0 -> `req`; otherwise: if a request was ever made, `spawn_blocking(release)`, status `Off`, `set_gateway(None)`, wait. Else `timeout(MAX_REFRESH + 5 s, spawn_blocking(move || m.refresh(req)))`; timeout or join error -> treated as `Failed` with 60 s retry (the blocking thread is abandoned, fact 10). Apply under the lock only if the current `(route.v4, listen v4 port)` still equals `req`: `own.set_gateway(report.gateway)`; if `publishable(PublishCtx::default())` changed: mark `want_addr_info` for every live friend and emit `OwnAddrsChanged` (no reknock, no limiter reset, no fast window); emit `MappingChanged` when the status changes. Mapper calls are never concurrent (one task).
- `Engine::shutdown` unchanged; **the product calls `UpnpMapper::release()` after `shutdown`** (stage 18; `upnp_probe` example does so).
- `diag.rs`: after `BehindCgnat`: `NatView::DoubleNat` -> `NoDirectPath::DoubleNat` (new variant, `rendezvous_could_help = true` like CGNAT); `texts.rs` `DOUBLE_NAT_TEXT = "Ваш роутер сам стоит за другим роутером или за NAT провайдера: снаружи к вам не достучаться. Соединение возможно, если у друга белый IP или проброс порта (звоните вы)."` (no word "UPnP": guard).
- `src_guard` changes: `set_gateway(` count exactly 1 and only in `gateway.rs`; `spawn_blocking` only in `gateway.rs`; everything else unchanged.

### U4. netns stand (`tools/netns/stage13a.sh`, Linux + root, reuse miniupnpd setup of `spikes/transport/run8.sh`)
Rows (expected): map + reach from the white host + `GetSpecific` lease ≤ 3600; renew at half (lease 60 s in a test build of the example: entry still present at 90 s); `release` -> entry gone, inbound fails; `kill -9` -> entry gone after lease; restart -> stale entry deleted then re-added; WAN 100.64/10 -> `BehindCgnat`, no `AddPortMapping` in miniupnpd log; double NAT (miniupnpd inside behind another NAT) -> `DoubleNat`; second LAN host running the fake IGD -> `Ambiguous`; fake IGD two hops away with spoofed SSDP response -> TCP never established (TTL 1), `NoGateway`; capture on the host: only 239.255.255.250:1900 UDP and the router's TCP port, dns = 0, other = 0.

## Do not
- No XML/HTTP/UPnP crate, no new package in `Cargo.lock` except `chervo-upnp` itself, no `unsafe`, no tokio in `chervo-upnp`, no DNS, no hostname, no IPv6, no NAT-PMP/PCP.
- No redirect following, no `URLBase`-based resolution, no router string echoed into requests, errors or texts.
- No mapping for another internal client, no lease > 3600 s, lease 0 only after 725 and consent, no SOAP to a router that is not allowlisted, no packet at all with empty settings and no current mapping.
- `chervo-connect`: no dependency on `chervo-upnp`, no socket, no word `upnp`/`igd`.

## Untrusted input (all from the LAN)
SSDP datagrams; HTTP response heads and bodies (description, SOAP, faults); every extracted value. Limits in U1; parsers never panic (lint block + fuzz smoke).

## Tests (exact names)
U1 (`chervo-upnp/src/tests/{scan,url,desc,ssdp,http,soap}.rs`):
`scan_rejects_doctype`, `scan_rejects_review8_bomb` (the 547-byte parameter-entity bomb, fixed bytes in the test), `scan_rejects_billion_laughs`, `scan_rejects_comment_cdata`, `scan_rejects_pi_not_first`, `scan_xml_decl_rules`, `scan_rejects_unknown_entity_and_char_ref`, `scan_decodes_five_entities`, `scan_depth_limit` (16 ok, 17 rejected), `scan_element_limit`, `scan_mismatched_close`, `scan_unclosed_eof`, `scan_two_roots`, `scan_control_chars`, `scan_non_ascii_text_ok_name_rejected`, `scan_attr_quotes`, `scan_name_too_long`, `scan_bom_ok`;
`location_rules` (hostname, IPv6, userinfo, https, port 0/65536, no path, `..`, `%00`, `%2f`, `?`, `#`, leading-zero octet), `location_host_must_equal_responder`, `control_url_relative_absolute_and_full`, `control_url_other_host_or_port_rejected`, `urlbase_other_host_rejected`;
`desc_extracts_wanip1`, `desc_prefers_v2_v1_ppp`, `desc_duplicate_control_url_rejected`, `desc_duplicate_service_type_rejected`, `desc_duplicate_udn_rejected`, `desc_root_not_igd_rejected`, `desc_no_service`, `desc_udn_rules`, `desc_max_services`;
`ssdp_msearch_exact_bytes`, `ssdp_response_ok`, `ssdp_wrong_status`, `ssdp_two_locations_rejected`, `ssdp_st_mismatch`, `ssdp_oversize`, `ssdp_non_ascii_header`, `ssdp_obs_fold_rejected`, `ssdp_responder_public_or_self_rejected`, `ssdp_loopback_only_in_test_policy`, `ssdp_select_conflicting_location_is_ambiguous` (rev. 2);
`http_request_exact_bytes` (GET and POST golden), `http_status_lines`, `http_rejects_transfer_encoding` (`chunked`, `identity`, mixed case), `http_content_length_duplicate_or_bad`, `http_body_over_limit_with_and_without_length`, `http_head_over_8k`, `http_too_many_headers`, `http_redirect_is_error`, `http_short_body`;
`soap_templates_golden` (5 actions × 3 service kinds), `soap_parse_external_ip` (incl. empty), `soap_parse_specific_entry`, `soap_fault_code`, `soap_fault_without_code`, `soap_duplicate_field_rejected`, `soap_wrong_response_element_rejected`, `soap_value_limits`, `soap_ipv4_strict`.
Fuzz (`chervo-upnp/src/tests/fuzz.rs`, fact 12 pattern): `fuzz_smoke_scan`, `fuzz_smoke_desc`, `fuzz_smoke_soap`, `fuzz_smoke_ssdp`, `fuzz_smoke_http` (random bytes, mutations of valid samples: byte flips, truncation, splice of `<!`, `&`, deep nesting, duplicated elements; property: no panic; every accepted result satisfies the invariants: path charset, same host/port, ASCII values within limits).
U2 (`chervo-upnp/src/tests/fake_igd.rs`: std-thread fake IGD on 127.0.0.1, unicast SSDP, scripted responses, records every datagram and request; `igd.rs`): `igd_map_happy_path` (report `Mapped`, `retry_after` 1800 s, gateway set), `igd_request_values_only_ours` (client == own IP, desc `udp`, lease ≤ 3600, `NewRemoteHost` empty, `Host` header), `igd_tcp_bound_to_internal_ip` (fake sees peer IP == own_ip), `igd_bomb_description_no_crash` (no SOAP received), `igd_slowloris_deadline` (1 byte / 300 ms -> error within `http_deadline + 0.5 s`; one run with the production 3 s), `igd_oversized_body`, `igd_huge_headers`, `igd_chunked_rejected`, `igd_redirect_not_followed` (redirect target receives 0 connections), `igd_wrong_location_host_no_connect`, `igd_control_url_other_port_no_connect`, `igd_malformed_soap`, `igd_conflict_718_alt_port` (v1 random, v2 AddAny), `igd_725_needs_consent_then_permanent_same_port`, `igd_606_refused_backoff`, `igd_wan_empty_unknown_no_add`, `igd_wan_cgnat_no_add`, `igd_wan_private_double_nat_no_add`, `igd_wan_bogus_rejected` (0.0.0.0, 127.0.0.1, 224.0.0.1, 192.0.2.1), `igd_specific_other_client_not_confirmed`, `igd_router_permanent_silently`, `igd_router_short_lease_renew_half`, `igd_stale_own_deleted_at_start`, `igd_stale_foreign_not_deleted`, `igd_release_deletes_only_ours`, `igd_network_change_deletes_old`, `igd_settings_cleared_forgets_without_sending` (rev. 2), `igd_settings_cleared_permanent_deleted_once`, `igd_settings_other_router_permanent_deleted_once`, `igd_settings_cleared_permanent_unconfirmed_sends_nothing` (fix round 2), `igd_conflicting_location_ambiguous`, `igd_datagram_cap_hit_ambiguous`, `igd_more_than_eight_responders_ambiguous`, `igd_unevaluated_responder_ambiguous`, `igd_foreign_network_same_addressing_sends_nothing`, `igd_release_unconfirmed_router_sends_nothing`, `igd_current_forgotten_when_no_gateway_or_ambiguous`, `igd_unrequested_permanent_on_alt_port_deleted`, `igd_second_refresh_while_busy_fails_fast`, `igd_stale_delete_bounded_by_overall`, `igd_control_url_semicolon_rejected`, `igd_not_home_network_no_soap`, `igd_off_no_traffic` (0 datagrams), `igd_ambiguous_two_responders`, `igd_identify_returns_udn`, `igd_refresh_bounded_by_max_refresh` (every response stalls), `router_id_setting_roundtrip_and_limits`, `debug_redacted`; `#[ignore] multicast_discovery_real_lan` (manual on the owner's LAN). Crate guard `src_guard`: socket identifiers (`UdpSocket`, `TcpStream`, `Socket::new`, `send_to`, `connect_timeout`) only in `net.rs`; `lookup_host`, `to_socket_addrs`, `ToSocketAddrs`, `Command`, `std::process`, `tokio`, `https`, `unsafe` absent; `GatewayAddr(` constructed only in `url.rs`; `239.255.255.250` and `239, 255, 255, 250` (whitespace ignored) only in `limits.rs`, `net.rs` uses `SSDP_ADDR` (rev. 2); no `String` field in `error.rs`.
U3 (`chervo-connect/src/tests/gateway.rs`, fake `PortMapper` recording calls; paused time): `mapper_not_called_without_attach`, `mapper_called_on_attach_private_route_only`, `mapper_skipped_on_public_or_cgnat_route`, `mapper_result_sets_gateway_and_resends_addr_info`, `mapper_stale_result_ignored_after_network_change`, `mapper_renew_at_retry_after`, `mapper_rerun_on_own_change`, `mapper_release_when_route_not_private`, `mapper_timeout_abandons_and_retries`, `mapper_never_concurrent`, `attach_twice_rejected`, `mapping_changed_event_once_per_status`, `diag_double_nat`, `texts_present` (extended), `src_guard` (updated). `chervo-addr/tests/own.rs`: `port_mapper_types_debug_redacted`.
U4: `bash -n tools/netns/stage13a.sh`; rows **not run here**.

## Acceptance criteria (each as a command; output in report)
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '` prints exactly `+name = "chervo-upnp"`
- [ ] `cargo tree -p chervo-upnp -e normal | grep -Ei 'xml|igd|attohttpc|hyper|reqwest|ureq|tokio'; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'chervo-upnp|quinn|rustls'; test $? -eq 1`; `cargo tree --workspace -e normal | grep -Ei 'igd|xml'; test $? -eq 1`
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-upnp fuzz_smoke -- --nocapture` (iterations per target in output)
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-upnp igd_ || exit 1; done`
- [ ] `cargo test -p chervo-core --test layout` (list extended by `chervo-upnp`); `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `bash -n tools/netns/stage13a.sh`; CI green (3 OS, supply-chain)

## Where verified
- **Windows locally and CI (3 OS):** U1-U3 (parsers, fake IGD on loopback with unicast SSDP, engine with a fake mapper).
- **Linux netns with root only (not this machine; owner's Ubuntu mini-PC): not verified here.** All U4 rows: real multicast, TTL-1 effect, miniupnpd interoperability, lease expiry, capture.
- **Real routers (owner, stage 16):** `cargo run -p chervo-upnp --example upnp_probe -- identify|map|release` on the owner's router; vendor quirks.

## Not verified in this stage (write in report, do not claim)
- Error code values and IGD semantics marked [D] (standard documents not available offline; miniupnpd source not in the registry).
- That Windows applies `IP_TTL` set before `connect` to the SYN; that Windows Firewall passes unicast SSDP replies to our ephemeral port (default "unicast response to multicast" rule [D]).
- Real routers: HTTP/1.0 acceptance, control port equal to description port, localized descriptions, several IGD services, IGDv2 `AddAnyPortMapping`.
- Behaviour when the blocking thread is abandoned at runtime shutdown (bounded by `MAX_REFRESH`).
- **T16 residual (fix round 2):** a permanent mapping (lease 0, after 725 consent) of a router removed from the allowlist (or the list cleared) is deleted by `set_settings` with ONE confirmed `DeletePortMapping` (old allowlist, single candidate, same UDN + gateway address + service, `RELEASE_BUDGET`). If the router cannot be re-confirmed (other device at the same address, no answer, ambiguity), nothing is sent and the permanent entry stays on the router until the user removes it there; leased mappings are forgotten without sending and expire within 1 h. Same residual for `release()` of a permanent mapping at exit. `set_settings` returns `()`, so the unconfirmed case is not reported to the caller (no interface change in this round); the owner is told in the T16 text.
- Ambiguous backoff policy (fix round 2): both sources of `Ambiguous` (discovery conflict/limits/unevaluated responder, and two allowlisted candidates) use the spec policy of U0: `retry_after` 1800 s without doubling (before the fix discovery used the 60 s doubling failure backoff).

## Stop conditions
A fact above does not match the source; a new external package, `unsafe`, tokio in `chervo-upnp`, or a dependency `chervo-connect -> chervo-upnp` is needed; a socket2 call needs the `all` feature; a parser rule cannot be met without an XML library; a fake-IGD test unstable after two fix attempts; a criterion cannot be checked. Stop and report.

## Limit
At most 2 review-fix rounds, then report to the owner.

## Builder report (max 25 lines per call)
Changed files; criteria commands with last output lines; fuzz iterations; not done; deviations with reason; what was not runnable on Windows.

## Process and executors
1. Call 1 (U1), Call 2 (U0, U2), Call 3 (U3, U4): `combine-builder` sonnet/high. Conductor runs tests and clippy after each.
2. `combine-verifier` (sonnet/low): all criteria.
3. `combine-security` (opus/high), once on the full diff: scanner and extractors (every rule of U1), HTTP deadline loop, URL rules, responder/TTL rules (decision 4), allowlist and no-traffic-when-off, lease lifecycle and "ours" checks, error-code handling, engine `gateway.rs` stale-result rule, guards, texts. Review result -> THREAT_MODEL.
Critical: U1 (all except the `limits.rs` constants list), U2 `net.rs`, `mapper.rs`, U3 `gateway.rs`. Not critical: texts, example, U4 script.

## Requirements for other stages
- **16:** run U4 and `upnp_probe` on real routers; decide Q3 (chunked / control port) from evidence.
- **17:** libFuzzer targets for `scan`, `desc`, `soap`, `ssdp`, `http`; log policy: `UpnpError`/`MapStatus` only, never router bytes.
- **18:** settings screen ("открывать порт автоматически на этом роутере", `identify`, list of routers, `permanent_ok` after `NEED_PERMANENT_TEXT`), persist `UpnpSettings` via `RouterId::to_setting`; `attach_mapper`; call `release()` on exit; show `status_text` and `DOUBLE_NAT_TEXT`.
- **THREAT_MODEL (conductor, after acceptance):** new T16 "Враждебная локальная сеть и поддельный роутер" (decision 4 residuals, open UDP port visible from the internet but silent by the knock, LAN hosts see the mapping and the `udp` description); T1: M-SEARCH and SOAP are visible to the LAN and the router logs.

## For the owner (кратко, по-русски)
- Свой маленький клиент UPnP в отдельном крейте `chervo-upnp`: без XML-библиотек и без новых пакетов (только уже имеющийся `socket2`). Слой соединения про UPnP не знает: получает результат через общий интерфейс и по-прежнему не открывает сокетов.
- По умолчанию выключено: программа не шлёт в сеть ничего. Вы включаете кнопкой «открывать порт автоматически на этом роутере»; программа запоминает идентификатор роутера (UDN). В чужой сети (ноутбук в гостинице) порт не открывается: роутер не тот.
- Как отличаем настоящий роутер без системных таблиц маршрутов (их нельзя прочитать без небезопасного кода): поиск и все запросы идут с TTL 1, то есть только к устройствам в самой локальной сети; адрес описания должен совпадать с ответившим; если отвечают два «роутера», порт не открываем. Остаток риска: злоумышленник в вашей домашней сети, знающий идентификатор роутера, может выдать себя за роутер (подменить внешний адрес или сделать вид, что порт открыт). Против подмены ARP никакая проверка маршрута тоже не помогла бы. Вопрос 1.
- Разбор ответов: любые `<!` (DTD, комментарии, CDATA), неизвестные сущности, управляющие символы отвергаются; тело ≤ 64 КиБ, заголовки ≤ 8 КиБ, на каждый запрос 3 с всего, перенаправления не выполняются, адрес управления только на том же IP и порту. XML-бомба этапа 8 отвергается на первом `<!`. Fuzz-смоук 1 млн итераций.
- Порт: аренда 1 ч, продление на половине, проверка через GetSpecificPortMappingEntry, удаление при выходе и при смене сети, старый свой проброс убирается при запуске. Ошибка 725 (только бессрочно): спрашиваем вас. Внешний адрес роутера из диапазона CGNAT или частный даёт честный диагноз «CGNAT» или «двойной NAT».
- Проверяется на Windows и в CI: разборщики и поддельный роутер на локальной петле. Настоящий multicast, действие TTL 1, miniupnpd и реальные роутеры здесь проверить нельзя: скрипт netns для мини-ПК и пример `upnp_probe` для вашего роутера.

## Open questions for the owner
**Q1. Gateway identification.** (A) heuristic of decision 4 (TTL 1, LOCATION = responder, private address, exactly one IGD, allowlisted UDN); (B) additionally read the OS route table: `/proc/net/route` on Linux (file), `route.exe print` / `/sbin/route -n get default` on Windows/macOS (spawned process, localized output to parse, one more hostile-ish surface); (C) both. **Recommendation: A.** B adds process spawning and per-OS parsing, and does not stop an ARP-spoofing attacker, the only one that A leaves; it only helps when the real router is silent and an impostor knows its UDN.
**Q2. "Home network".** (A) allowlist of routers by UDN, enabled by an explicit button (decision 6); (B) one global switch "UPnP on/off", default off. **Recommendation: A** (a few lines more; a laptop that is sometimes at home gets UPnP at home and nothing elsewhere). Cost of A: with a non-empty list the laptop still sends 4 M-SEARCH datagrams and fetches ≤ 8 descriptions in foreign networks (no SOAP).
**Q3. HTTP/1.0 only (no chunked, control port = description port).** Some routers may need HTTP/1.1 chunked or a different control port [NP]. **Recommendation: keep strict in 13a**; relax only on evidence from real routers in stage 16 (a bounded chunked decoder would be a separate reviewed change).
