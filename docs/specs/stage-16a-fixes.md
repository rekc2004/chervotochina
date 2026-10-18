# SPEC 16a: Product fixes from the stage 16 stand (П1 = C20, П2 = C06)          criticality: CRITICAL (F1, F2, F4, П2a), NORMAL (F3, П2b, П2c, node16 field)

Author: combine-architect (opus), 2026-10-18, revision 1. Labels: [P] verified by me in the repository or registry source (file:line); [Ж] from the raw logs of the 8d9e279 run as quoted in the report; [V] architect's inference; [НП] not verified. **Nothing was run by me.** No new packages, no new wire formats (ADDR_INFO, knock, CHA1 token, friends file unchanged), no `unsafe`.

Basis: `docs/reports/NETTEST-2026-10-18.md` section 12 (12.1 C06/X01, 12.2 C20), `docs/specs/stage-16-nettest.md` section 20.3, TASK 16а, owner decisions 2026-10-18 (do 16а now; private friend entries live 24 h, accepted). Deviations from report 12.2 are marked **(dev.)** with the reason.

Read: this file; `crates/chervo-addr/src/{own,book,probe,lib}.rs`, `tests/{own,book}.rs`; `crates/chervo-connect/src/{engine,addrinfo,dispatch,watch,clock,config,plan}.rs`, `src/tests/{kit,addrinfo,watch,manual_token,src_guard}.rs`; `crates/chervo-transport-quinn/src/{lib,registry,client,knock,limits}.rs`, `src/tests/knock.rs`; `crates/chervo-transfer/examples/node16.rs`. Search nothing else.

## 0. Резюме для владельца (русский)
1. **C20 (важный).** Программа перестанет верить старому мнению друга, с которым нет связи: если хоть один друг сейчас подключён и уже сообщил, каким видит наш адрес, считаются только такие сообщения. Старые сообщения отключённых друзей работают как запас, только когда свежих нет (ноутбук без связи по-прежнему может выпустить токен с последним адресом).
2. Подключённые друзья говорят разное: адрес по-прежнему не рассылается (ваше решение 5). Но теперь лгущий друг, оставшийся единственным подключённым, может навязать нам подсказку адреса. Это уже допускалось решением Н6 («достаточно одного друга»); стук по чужому адресу ограничен как раньше.
3. Если внешний адрес изменился (так сказал подключённый друг), программа сама: повторный стук своим соединениям, рассылка нового адреса подключённым друзьям, событие «адрес изменился» (на этапе 18 подсказка «отправьте токен друзьям без белого IP»). Не чаще раза в 30 с. **Частого режима звонков и сброса пауз это не включает**: иначе лгущий друг держал бы нас в нём постоянно. Частый режим, как и раньше, только по вашим действиям (запуск, смена сети, «соединить», выдача или вставка токена).
4. Если друг сменил адрес посреди соединения, мы сразу сообщаем ему, как видим его теперь (F3, обязательно).
5. F4 (по желанию, отдельный шаг): если по соединению 15 с ничего не приходит, а звонили мы, программа повторяет стук, и соединение переживает смену IP роутера без обрыва. Где звонил друг, соединение всё равно оборвётся и восстановится заново: так устроен QUIC в quinn (проверено по исходнику).
6. **C06 (мелкий).** По частному пути другу уходит частный адрес именно этого пути, а не адрес домашней сети. Частные адреса друзей любого происхождения живут 24 ч (ваше решение); пока соединение по частному адресу живо, срок продлевается.
7. Следствие 24 ч (вопрос Q1): два компьютера в одной сети, не включавшиеся вместе больше суток, теряют частные адреса друг друга до нового приглашения или токена «мы в одной сети» (окончательно закроет поиск в сети, этап 13в). Рекомендую принять.
8. Проверка: юнит-тесты на модели сети (Windows и CI), затем на стенде строки C06, C20 и новая G7-REBIND.

## 1. Facts from the source
1. Own-address snapshot = route probe + listen addresses only (`chervo-connect/src/watch.rs:23-29`); `set_local` clears observations only when that snapshot changes (`chervo-addr/src/own.rs:200-211`). A NAT WAN change is invisible [P].
2. `live_v4` filters observations by TTL only (`own.rs:287-300`, TTL 1800 s `:16`); `nat_view` returns `Conflicting` if any two live IPs differ (`:330-336`); `observed_v4` only for `Unknown|Eim` (`:368-377`); step 2b uses `live_v4` too (`:424-429`) [P].
3. `PublishCtx::for_connection(remote)` sets `include_lan` for a private remote (`own.rs:148-153`); step 5 then publishes the **default-route** private v4 / ULA (`:440-452`) [P].
4. `merge_update` L1 keeps every non-hint `AddressUpdate` on a hints-only update (`chervo-addr/src/book.rs:44-76`); `dead()` gives non-hint, non-short-lived, non-Contact entries no TTL (`:132-137`); `CONTACT_TTL_SECS = 86_400`, `CONTACT_REFRESH_SECS = 3_600` (`:12-13`) [P].
5. `ours()` builds the set with `for_connection(remote)` under the state lock and re-sends the previous token when the set is unchanged (`chervo-connect/src/addrinfo.rs:89-112`); called from `send_addr_info` (`:152-172`) and `serve_addr_info` (`dispatch.rs:103-138`); `apply_peer_info` observes for any Active pair, without checking which connection delivered it (`addrinfo.rs:176-191`) [P].
6. Engine: `live.insert` (`engine.rs:477`), eviction over `max_live` (`:493-507`), `want_addr_info = is_initiator` (`:517`), `on_closed` (`:541-557`), `cleanup_inactive` with `forget_reporter` (`:376-398`), `shutdown_now` drains `live` (`:315-335`), `RemoteAddrChanged` only calls `note_contact` (`:816-823`), `tick` (`:764-787`), `connect_now` = reset_pair + fast window (`:1025-1048`) [P].
7. `on_own_change` = reknock, `limiter.reset_all`, global fast window, `want_addr_info` for all live, `gw.wake`, `OwnAddrsChanged` (`watch.rs:32-46`) [P].
8. Config: `addr_info_out_interval` 10 s, `addr_info_in_per_min` 4, `fast_window` 120 s, `min_redial` 30 s, `max_live` 64, `tick` 1 s (`config.rs:52-77`); receiving side `MIN_INBAND_UPDATE_INTERVAL_SECS = 10` (stage 13 fact 10) [P].
9. quinn adapter: per-connection monitor polls `remote_address()` every `addr_poll` (1 s), re-pins and emits `RemoteAddrChanged` (`chervo-transport-quinn/src/registry.rs:243-277`); `reknock_live` coalesced, knocks at 0, `resend`, `3*resend` to `registry.live_remotes()` (`client.rs:340-390`); `Gate::Closed` drops every non-knock datagram before quinn (`knock.rs:765-779`); defaults idle 30 s, keep-alive 10 s, `addr_poll` 1 s, `knock_admit_ttl` 10 s, `knock_resend_after` 1 s (`lib.rs:171-179`) [P].
10. quinn-proto 0.11.19: a **client** drops packets from an unrecognized remote; a server migrates if `migration` (`connection/mod.rs:1128-1132`, `:3825-3833`); server `migration` defaults to true (`config/mod.rs:244`); this repository never sets it (no `migration` in `chervo-transport-quinn/src`) [P]. Report 12.2 marked this [НП]; it is now verified by source: F4 can help only connections where we are the QUIC client.
11. `quinn::Connection::stats()` (`quinn-0.11.12/src/connection.rs:554`) returns `ConnectionStats { udp_rx: UdpStats { datagrams, .. }, .. }` (`quinn-proto-0.11.19/src/connection/stats.rs:10-12, :165-169`) [P]. Datagrams dropped by `KnockSocket` never reach quinn, so they are not counted [V].
12. Route probe `source_for(bind, target)`: bind, UDP `connect`, `local_addr`, loopback/unspecified -> None (`chervo-addr/src/probe.rs:31-39`) [P].
13. `node16` calls `connect_now` after issuing and after applying a token (`examples/node16.rs:738-742`, `:766-769`); `EVENT connected` has no role (`:576`); `STATE` has `nat_view` and `friend:<label>=[...]` (`:779-788`) [P]. Trait `Connection` has `conn_id()` and `is_initiator()` (`chervo-transport/src/lib.rs:129-131`) [P].

## 2. Decisions
1. **F1 "current observations" (required).** An observation is *current* iff its reporter is marked up and the observation was accepted after the latest `reporter_up` of that reporter. Ordering uses an internal counter in `OwnAddrs`, not `now_unix` **(dev.: report proposed `reporter_up(pair, now_unix)` with `obs.at >= up_since`; same-second ties and user clock jumps would misclassify)**. Effective v4 set = TTL-live v4 observations, restricted to current ones **if at least one current exists**, else all TTL-live (old behaviour). Everything that used `live_v4` uses the effective set: `nat_view` (Conflicting, DoubleNat vs WAN, ManualForward, Symmetric, Eim), `observed_v4`, step 2b. TASK wording "TTL only without connected friends" is implemented as "TTL only without current observations": a friend that has just reconnected but not yet reported must not make the hint disappear (an update without hint would remove our hint from every friend's book via `merge_update`, then reappear 10 s later).
2. **Observation only from the live connection.** `apply_peer_info` gets the `conn_id` of the connection that carried the exchange; the observation is passed to `observe` only if `live[pair].id == conn_id`. The signed update is applied as now (independent of the connection). Without this, a late exchange on a replaced connection would count as current.
3. **Decision 5 and Н6 kept.** Two current reporters disagreeing -> `Conflicting`, hint withheld (unchanged code path). Residual (accepted by Н6): a liar that is the only current reporter sets our hint; previously a disconnected honest friend contradicted it for up to 30 min. Bound on harm unchanged: hint dials by others go through their M1 limiter (hint 60 s base, 30 min cap).
4. **F2 "external address changed" (required).** Tracked value: `own.publishable(PublishCtx::default(), unix)` (the global set we would announce; covers observed hint, manual forward IP, port mapping). Evaluated once per scheduler `tick`. State: `ext_announced: Option<PublishSet>`, `ext_baseline: bool`, `ext_last: Option<Instant>`. Rules: set empty -> nothing; first non-empty set after engine start -> recorded silently (`ext_baseline = true`, no action); set non-empty and `Some(set) != ext_announced` and (`ext_last` none or `now - ext_last >= ext_announce_gap` = 30 s) -> **announce**, `ext_announced = Some(set)`, `ext_last = now`; inside the gap -> nothing now, re-evaluated every tick (so the final state is announced at the end of the gap, intermediate ones may be skipped). `on_own_change` additionally sets `ext_announced = Some(current set)`, `ext_baseline = true` (does not touch `ext_last`), so a route change is not announced twice, while a later observation in the new network is.
   **Announce** = `transport.reknock()`, `want_addr_info = true` for every live Active pair, `emit(OwnAddrsChanged)`. Observations are not cleared.
   **Own event? Decision (dev.):** an external change counts as an own event **only for re-announcement** (reknock to live authenticated peers, ADDR_INFO to live friends, event). It is **not** a fast-window trigger and does **not** reset the limiter, because it is friend-supplied: with report 12.2's variant a liar alternating Y/Z every 30 s would keep us in fast mode permanently and reset every backoff, breaking stage 13 decision 5 (victim address ≤ 1 dial per 10-30 min outside own fast windows). C20 does not need it: issuing or applying a token is a user action and `node16`/stage 18 call `connect_now` (fact 13), which opens the pair's fast window and resets its limiter.
   Bound under a liar: ≤ 2 announces/min (also ≤ 4 incoming ADDR_INFO/min/connection, `min_redial` 30 s); each announce = one coalesced reknock run (3 knocks × live remotes, all authenticated peers' current addresses) and ≤ 1 ADDR_INFO per live friend (≤ 1 token issue + friends-file write per friend per announce). No new destination of any packet.
5. **F3 "peer migrated" (required).** On `TransportEvent::RemoteAddrChanged { pair }` for a live Active pair: existing `note_contact` plus `want_addr_info = true`; sent by `collect_sends` (≤ 1 per `addr_info_out_interval` per pair). Not an own event: no reknock, no fast window, no limiter change, no `OwnAddrsChanged`. Required because it is cheap, bounded and the only way a peer that migrated without knowing it (NAT rebinding, F4) learns its new external address; without F3, F4 would keep connections alive with stale current observations (F1 would then publish the old address as current).
6. **F4 "stall reknock" (optional, recommended; own builder call 3; stage accepted without it).** Reasons for optional: C20 passes with F1-F3 via reconnect; F4 touches 9b (knock); it helps only connections where we are the QUIC client (fact 10). Reason to do it: dynamic ISP addresses of stationary PCs (owner's first target) then keep transfers without the 30 s idle + reconnect. Behaviour: per connection where **we are the QUIC client**, the monitor (fact 9) also reads `stats().udp_rx.datagrams` each poll; if unchanged for `stall_reknock_after` (15 s) it requests a reknock, then again every `stall_reknock_every` (10 s) while still stalled (≤ 2 requests before idle 30 s: at 15 and 25 s, so peers' 10 s admits cover [15 s, 38 s] and QUIC's doubling PTO probes land in an open window [V]); any received datagram resets the watch. Global gate: at most one stall-triggered `reknock_live` per `stall_reknock_every`; coalesced with other reknocks (`client.rs:340-373`). Active only if `knock_required` and `keep_alive < stall_reknock_after < idle_timeout` and `stall_reknock_every > 0`; otherwise silently off (no config error, existing tests keep their configs). Server-role connections never fire (our new-address packets are dropped by the peer's quinn client anyway), so we never knock a stalled peer's old address (it may belong to someone else after an ISP reassignment). Knock format, admit TTL and replay rules unchanged.
7. **П2a: path source on private paths (required).** For ADDR_INFO on a connection whose remote is `Private`, the engine asks the route probe for the source address towards `remote` (UDP `connect`, no packet, like fact 12) **before** taking the state lock, and step 5 publishes only that address (with our listen port of that family), and only if it is `Private` (v6: also not EUI-64) and the listen address of that family is unspecified or equal to it. Probe error -> no private address. The default-route private address is never published on a connection path. Manual token with `include_lan` (user choice "same network") and invite addresses stay as they are. The result is `local_addr` of our own socket: still only our own address (U6 v6). Residual [V]: a "private" remote reached through the default gateway (ISP using 10/8 internally) still yields our home LAN address; it now expires after 24 h (П2b).
8. **П2b: private friend entries 24 h (required, owner decision).** `dead()` also kills any entry whose normalized IP class is `Private` (RFC 1918, ULA) and `now >= last_seen + PRIVATE_TTL_SECS` (86 400 s), any source (Invite, AddressUpdate, Contact, others). L1 in `merge_update` keeps a previous non-hint `AddressUpdate` on a hints-only update **only if its address is `Global`**. `findability` unchanged (counts Global only).
9. **П2c: refresh while connected (required; my addition).** `run_expire` (every 60 s) calls `book.note_contact(pair, remote)` for every live Active connection whose remote is `Private`; `note_contact` itself writes at most once per `CONTACT_REFRESH_SECS` (1 h). Reason: an unchanged set re-sends the same token (`StaleSeq` at the friend, no refresh; fact 5, stage 13 decision 9), so without this, LAN-only friends with a connection older than 24 h would lose each other's LAN address. Refresh only on proof (live connection over that address), so the foreign-network risk the owner accepted does not grow.
10. **node16 role field (stand support).** `EVENT connected pair=<l> path=<p> role=client|server` from `engine.connection(&pair).map(|c| c.is_initiator())` (`unknown` if None). Startup line prints `stall_reknock=on|off` (from the effective F4 condition) so the stand knows which G7-REBIND variant applies.

## 3. Interface (exact)
All new types holding addresses or pairs: `Debug` prints `"TypeName(..)"`. No logging, no panics, saturating arithmetic.

### chervo-addr
```rust
// own.rs
pub const MAX_REPORTERS_UP: usize = 256;   // > ConnectConfig::max_live (64)
impl OwnAddrs {
    /// From now on `reporter` has a live connection; its earlier observations stop being current.
    /// Re-calling renews the mark. Over MAX_REPORTERS_UP the mark with the oldest sequence is dropped.
    pub fn reporter_up(&mut self, reporter: PairId);
    /// Connection gone: mark removed, observations kept (TTL fallback).
    pub fn reporter_down(&mut self, reporter: &PairId);
    /// Number of up marks (tests, invariants; no addresses).
    pub fn reporters_up(&self) -> usize;
    // forget_reporter: additionally removes the up mark.
    // set_local: unchanged (clears obs and gateway on change); up marks are kept.
}
// Obs gains `seq: u64`; OwnAddrs gains `seq: u64` (saturating) and `up: Vec<(PairId, u64)>`.
// observe() Accepted: seq += 1, obs.seq = seq. reporter_up: seq += 1, mark = seq.
// current(o) := up contains (o.reporter, m) with o.seq > m.
// effective_v4(now) := let live = TTL-live v4 (as live_v4 today);
//                      if live.any(current) { live.filter(current) } else { live }
// live_v4 is replaced by effective_v4 at every use (nat_view, observed_v4, publishable 2b).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishCtx { pub include_lan: bool, pub path_source: Option<IpAddr> }
impl PublishCtx {
    /// include_lan = false; path_source = source if normalize(remote) is Private and source is
    /// Private and of the same family, else None.
    pub fn for_connection(remote: SocketAddr, source: Option<IpAddr>) -> Self;
}
// publishable step 5: if let Some(src) = ctx.path_source -> push(src:port) under decision 7 rules,
// nothing else in step 5; else if ctx.include_lan -> unchanged.

// probe.rs (the only socket code, as now)
/// Source address towards `target` (normalized): bind unspecified of its family, UDP connect,
/// local_addr; loopback/unspecified/error -> None. Sends nothing.
pub fn route_source_for(target: SocketAddr) -> Option<IpAddr>;

// book.rs
pub const PRIVATE_TTL_SECS: u64 = 86_400;
```
`lib.rs` re-exports `route_source_for`, `PRIVATE_TTL_SECS`, `MAX_REPORTERS_UP`.

### chervo-connect
```rust
// clock.rs: trait RouteProbe gains a required method
fn source_for(&self, target: SocketAddr) -> Option<IpAddr>;   // SystemProbe -> chervo_addr::route_source_for
// config.rs
pub ext_announce_gap: Duration,   // default 30 s
// engine.rs State: ext_announced: Option<PublishSet>, ext_baseline: bool, ext_last: Option<Instant>
// addrinfo.rs
pub(crate) fn ours(&self, st, pair, remote: SocketAddr, path_source: Option<IpAddr>, unix) -> Option<IssuedAddrUpdate>;
pub(crate) fn apply_peer_info(&self, st, pair, conn_id: u64, info, now, unix);
```
Call sites: `reporter_up` right after `st.live.insert` in `on_connection`; `reporter_down` in `on_closed` (removed branch), for each `max_live` victim, for each pair drained in `shutdown_now`; `cleanup_inactive` keeps `forget_reporter`. `source_for` is called in `send_addr_info` and `serve_addr_info` before `self.lock()`, only for a Private remote. F2 check inside `tick` under the lock; `reknock()` and `emit` after the lock is released. F3 in `run_events`. П2c in `run_expire`.

### chervo-transport-quinn (call 3 only)
```rust
// QuinnConfig (defaults)
pub stall_reknock_after: Duration,   // 15 s; ZERO = off
pub stall_reknock_every: Duration,   // 10 s
// TransportStats
pub stall_reknocks: u64,             // stall-triggered reknock runs actually started
```
New module `stall.rs`: pure `StallWatch { last_rx: u64, last_progress: Instant, last_fire: Option<Instant> }` with `fn poll(&mut self, rx: u64, now: Instant, after: Duration, every: Duration) -> bool` and a global `StallGate` (`Mutex<Option<Instant>>` in `Inner`). The monitor in `registry.rs` uses them only for client-role connections.

## 4. Do (three builder calls, sonnet/high; verify each before the next, CORE 5)
- **Call 1, `chervo-addr`:** F1 API and effective set; `PublishCtx` field + `for_connection(remote, source)`; `route_source_for`; П2b (`dead`, L1). Update every `PublishCtx { include_lan }` literal and `for_connection` caller in the workspace (compile fix only). Tests T-A.
- **Call 2, `chervo-connect` + node16:** decisions 2, 4, 5, 7 wiring, 9, 10; kit: `FakeProbe::set_source(target, Option<IpAddr>)`, `FakeConn::set_remote` (remote behind a mutex), `FakeTransport::emit(TransportEvent)`. Tests T-C; `src_guard` extended.
- **Call 3, `chervo-transport-quinn` (optional, F4):** only after calls 1-2 pass review. Tests T-Q.
Existing tests that may change expectation, and only these: `merge_update_hint_only_keeps_previous_non_hint_updates` (only if it uses a private address: then switch it to a global one and add the private case to T-A), `for_connection_lan_rule`, `publish_lan_only_with_ctx` (signature). Any other existing test failing = stop condition.

## 5. Tests (exact names; deterministic; `#[tokio::test(start_paused = true)]` with the fake where time matters)
**T-A `chervo-addr/tests/own.rs`:** `current_overrides_disconnected` (report test 1, **corrected**: A, B, C up, all report X; B and C down; A up again and reports Y -> `nat_view` not Conflicting, `observed_v4 = Y`; report 12.2 kept B connected, which is Conflicting by decision 5), `current_disagree_conflicting_no_hint` (report 2: A reports Y, B reports X, both up -> Conflicting, `publishable` has no hint), `no_current_falls_back_to_ttl` (report 3: no `reporter_up` ever -> identical results to today on the same inputs), `obs_before_up_not_current` (report 4), `current_ttl_forget_symmetric` (report 5: TTL expiry of the only current obs -> fallback; `forget_reporter` drops mark; Symmetric judged on current only, a stale obs with another port ignored), `reporter_down_keeps_obs`, `set_local_change_keeps_up_marks`, `reporters_up_capped`, `manual_forward_uses_current`, `seq_saturates`; П2a: `publish_path_source_private_only` (route 192.168.1.5, source 10.99.0.1 -> 10.99.0.1:port present, 192.168.1.5 absent), `publish_path_source_non_private_ignored` (Global, Shared, LinkLocal, Loopback -> nothing in step 5), `publish_path_source_none_no_lan`, `publish_path_source_listen_mismatch` (listen 10.0.0.5:p, source 10.99.0.1 -> nothing), `publish_include_lan_manual_unchanged`, `for_connection_rules` (global remote -> no source; family mismatch -> None).
**T-A `chervo-addr/tests/book.rs`:** `hint_update_displaces_private_update` (report П2), `l1_keeps_global_non_hint_only`, `private_expires_24h_any_source` (Invite, AddressUpdate, Contact private: present at +86 399, gone at +86 400; global non-hint AddressUpdate stays), `private_ula_expires_24h`, `private_future_last_seen_not_expired`, `findability_ignores_private_ttl`. `chervo-addr` probe: `route_source_for_loopback_none`.
**T-C `chervo-connect/src/tests/`** (fake transport): `c20_model_token_new_hint_only` (report 6: friends W1, W2, P all report X over live connections; all closed; W1 back reporting Y; `issue_addr_update_text(P, false)` = Ok, decoded set contains hint Y, not X), `ext_change_announces_once` (report 7: baseline X silent; Y -> exactly 1 reknock, ADDR_INFO opened on every live conn, 1 `OwnAddrsChanged`, `reporters_up` and observations kept; Z at +10 s -> nothing until +30 s, then exactly 1 more reknock and event), `ext_first_observation_silent`, `ext_change_no_fast_window_no_limiter_reset` (liar alternates Y/Z every 15 s for 10 min: reknocks ≤ 21, `fast_global_until` never set, dials to a victim address in another friend's book keep the stage 13 backoff schedule), `own_change_then_observation_announced` (route change, then new observation 5 s later -> second announce allowed, no double announce of the route change), `connected_liar_conflicting_no_addresses` (report 8: honest Y and liar Z both live -> Conflicting, `issue_addr_update_text` = NoAddresses with private route only), `observation_only_from_live_conn` (exchange finished on a replaced conn: no observe; its signed update still applied), `reporter_marks_follow_live` (connect, close, `max_live` eviction, block (cleanup_inactive), shutdown: `reporters_up` equals live Active count after each), `remote_change_sends_addr_info` (report 9: `set_remote` + event -> 1 ADDR_INFO; 5 more events within 10 s -> still 1), `remote_change_not_own_event` (no reknock, no event, no fast window), `addrinfo_private_path_publishes_path_source` (report П2: source 10.99.0.1 vs default route 192.168.1.5), `addrinfo_private_path_probe_none_no_private`, `addrinfo_global_path_no_probe_call` (probe `source_for` not called), `private_contact_refreshed_while_live` (П2c: live private conn for 25 h of paused time -> Contact present; after close +24 h -> gone), `manual_token_include_lan_unchanged`. `src_guard`: `reporter_up(`/`reporter_down(` only in `engine.rs`; `route_source_for` only in `clock.rs`; previous rules unchanged.
**T-Q `chervo-transport-quinn`** (call 3): unit `stall_watch_fires_at_after_then_every` (fires at 15 s and 25 s, not 14.9 s, not twice in 10 s), `stall_watch_resets_on_rx`, `stall_gate_global_gap`, `stall_inactive_when_misconfigured` (after ≤ keep_alive, ≥ idle, ZERO, knock off); loopback (test config keep_alive 1 s, after 2 s, every 1.5 s, idle 6 s): `stall_reknock_recovers_silent_rebind` (A client of B; test-only `rebind_silent` swaps A's socket without reknock; B drops A's new address; A's `stall_reknocks` ≥ 1; B gets `RemoteAddrChanged`; a stream round trip works; same `conn_id`), `stall_no_reknock_when_healthy` (report 11: 10 s idle -> `stall_reknocks` = 0), `stall_server_role_never_fires` (B in the same scenario: 0). If the loopback test is flaky after 2 fix attempts: `#[ignore]` with reason in the report; the unit tests stay mandatory.

## 6. Stand rows after 16а (builder sonnet/medium for the stand; conductor runs on Linux)
- **C06 + X01:** rev 1 expectations (stage 16 spec 7, 12) with S1: connected, path SimultaneousOpen; guard on ha `other = 0`, `other_in = 0` (ICMP unreachable counted in `icmp_unreach_in`); X01 destinations ⊆ {WA, WB, NAT-B WAN, meet peer}, probe 0, DNS 0.
- **C20:** rev 1 expectations unchanged (stage 16 spec 9). Additional check: FAIL if any HA `token_failed error=NoAddresses` occurs later than 60 s after the WAN change [V: observers' stalled connections close by ~30 s, reconnect and report within ~10 s].
- **G7-REBIND (new, group g7, cap 600 s):** topology of G7-LAPTOP (HA behind NAT-A PR; WA, WB white); D20 on HA's and WA's endpoint ports in `i`. Setup: HA accepts invites from WA and WB; wait HA `STATE nat_view=Eim` (≤ 60 s, else INCONCLUSIVE "no observation"). Transfer HA -> WA, 256 MiB random, defaults. At receiver 30 %: NAT-A WAN `.10` -> `.11` with **the same stand function as C20** (no second implementation); new role label `NATA_WAN2` in the sanitizer map. Record: completed, cmp, sha256, connections (HA `connected` events for wa), `role` of the connection alive at the change, HA `stall_reknock` flag, paused/resumed, max_stall_s, `t_hint` = first WA `STATE` whose `friend:ha` list contains `NATA_WAN2:4433` (seconds after the change), HA `nat_view` of every STATE line after the change, guard on ha.
  **PASS iff all:** completed and cmp equal; `t_hint ≤ 60`; no HA `nat_view=Conflicting` from change+60 s to the end and final HA `nat_view` ∈ {Eim, Unknown}; guard `other = 0` (destinations ⊆ {WA, WB}); and if `stall_reknock=on` **and** role at the change = client: connections = 1, paused = 0, max_stall_s ≤ 45 [V]; otherwise connections ≥ 2 accepted (paused/resumed allowed). FAIL notes: `hint not refreshed within 60 s`, `conflicting after rebind`, `no migration (client role, F4 on)`. A transient Conflicting in the first 60 s is expected [V] (a still-stalled observer reports the old address until its connection closes or migrates).
- Stage 16 spec 20.3 is superseded by this row definition (conductor adds a pointer there).

## 7. Acceptance criteria (each as a command; output in report)
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'quinn|rustls'; test $? -eq 1`
- [ ] `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `for i in $(seq 20); do cargo test -q --locked -p chervo-connect -- ext_ current_ remote_change_ c20_ reporter_ || exit 1; done`
- [ ] call 3 only: `for i in $(seq 20); do cargo test -q --locked -p chervo-transport-quinn -- stall_ reknock_ || exit 1; done`
- [ ] `cargo build --release --locked -p chervo-transfer --example node16`
- [ ] CI 3 OS green. Stand: C06+X01, C20, G7-REBIND PASS on the Linux box (section 6).

## 8. Do not
- No change of ADDR_INFO, knock, CHA1, friends-file formats; no new package; no `unsafe`; no socket in `chervo-connect`.
- No fast window and no limiter reset from F2, F3 or F4.
- No packet to any destination outside `usable_known`, invite tokens and `registry.live_remotes()`; F4 never knocks from a server-role stall.
- Do not publish the default-route private address on a connection path; do not publish a friend's address (U6 v6).
- No logging of addresses, pairs, tokens.

## 9. Stop conditions
Spec contradicts code or a fact above does not match; a format change, new crate or `unsafe` would be needed; `quinn::Connection::stats()` lacks `udp_rx.datagrams` in the locked version; the fake cannot express a test without changing a public API beyond section 3; an existing test outside the list in section 4 changes expectation; a stage 12/13 bound number would have to change; a deterministic test unstable after 2 fix attempts (except the one loopback F4 test, see T-Q). Stop and report.

## 10. Security review (opus/high, once on the full diff; F4 diff separately if call 3 is done later)
Check: (1) U6 v6: `PublishSet` still only from own sources; `path_source` is our socket's `local_addr`, the friend only chooses the probe target; probe sends nothing. (2) U6 v5 / Н6 / decision 5: observe only Active over the live conn; conflict among current reporters withholds; assess the accepted residual (decision 3). (3) M1: F2/F3/F4 open no fast window, reset no limiter, add no destination; liar bounds of decision 4 (announces, reknocks, token issues and friends-file writes per minute). (4) Lock order and that `source_for` is outside the state lock. (5) П2b/П2c: no path makes a private entry immortal; refresh only from a live connection; L1 change cannot be abused by one friend against another friend's entries. (6) F4 vs 9b: knocks only to live client-role peers' current addresses, admit TTL/replay untouched, bound ≤ 1 run per 10 s, no knock to a stalled peer's old address. (7) Close the C06/X01 escalation: other_in = ICMP unreachable from the router (report 12.1), knocks carry no names or keys. (8) `Debug` redaction of new types.

## 11. Not verified in this stage
Real ISP address changes, real router NAT rebinding and timeouts; QUIC PTO timing under real loss vs the F4 windows [V]; migration where we are the QUIC server (not possible with quinn 0.11 client semantics, fact 10); WAN change while `PortMapped` (gateway info refresh is 13a's lease logic, F2 announces only when the gateway reports a new mapping).

## 12. Requirements for other stages
- **18:** `OwnAddrsChanged` now also means "external address changed" (≤ 1/30 s): show the hint "send your address token to friends without a white IP"; "send token" and "paste token" keep calling `connect_now`.
- **13в (mDNS):** closes the LAN-after-24 h gap of Q1.
- **17:** threat model T1 (stall reknock pattern: ≤ 6 knocks per stalled client connection), T2 (liar as the only current reporter; announce bound).
- **U25:** server-side migration (would need our own path handling in quinn) stays open.

## 13. Process and executors
1. Calls 1, 2 (and later 3): `combine-builder` sonnet/high; report ≤ 25 lines: changed files, criteria with last output lines, deviations, what was not runnable.
2. `combine-verifier` sonnet/low: section 7.
3. `combine-security` opus/high: section 10.
4. Stand builder sonnet/medium: G7-REBIND, C20 extra check, label `NATA_WAN2`; conductor reruns C06+X01, C20, G7-REBIND.
Limit: at most 2 review-fix rounds, then report to the owner.

## 14. Open questions (contested only)
**Q1. Consequence of 24 h for LAN addresses.** Owner accepted 24 h for all private entries (risk presented: knocking a stranger's device in a foreign network with the same subnet). Not presented then: two PCs in one LAN that are off or apart for more than 24 h lose each other's LAN address (П2c covers only live connections) and meet again only via hairpin to the shared public address [НП on real routers], a new invite/token with "same network", or mDNS (13в). Options: (A) 24 h for all sources, as decided; (B) entries from an explicit user choice (invite or token with "same network") live until replaced. **Recommendation: A.** B helps little (any applied in-band update already removes Invite entries, `book.rs:65-69`) and would make a laptop that was once invited at a friend's home knock that private address in every network indefinitely; 13в is the real fix.
