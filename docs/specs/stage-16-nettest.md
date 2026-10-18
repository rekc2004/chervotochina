# SPEC 16: Network tests (netns, nftables, tc netem)          criticality: P0 CRITICAL (token API), rest NORMAL (test stand)

Author: combine-architect (opus), 2026-10-18, revision 1; Rev. 2 addendum 2026-10-18 after the full run (section 20). Labels: [P] verified by me in the repository source (file:line); [C] confirmed by the conductor on the Linux box, not by me; [V] architect's inference from code; [NP] not verified. **Nothing was run by me.** No new external packages. One new internal dev-edge: `chervo-transfer` (dev) -> `chervo-upnp` (path crate).

Goal (TASK stage 16): netns/netem stand for the BRIEF section 10 scenario; the same NATs via rendezvous; speed table (LAN, IPv6, UPnP, hole punch) with CPU; generated report "which pairs did not connect and why"; separate line "not verified: real operators, TSPU".

## 0. Резюме для владельца (русский)
1. Один новый стенд `tools/netns/stage16.sh` (свой префикс `chv16-`, свежая топология на каждую строку), старые стенды 9/13/13а/14 не трогаем и не вызываем: у них другие топологии и форматы итогов.
2. Узел стенда: новый пример `node16` = `node14` (передача) + метки друзей, UPnP, токен обновления адреса CHA1, диагноз, замер CPU. Один бинарник на все строки.
3. **Нужна маленькая добавка в продукт (P0):** у движка нет вызова «выпустить токен обновления адреса для друга» (есть только внутри ADDR_INFO). Без него строки «оба за NAT» (PR-PR) и «смена IP + токен» не проверить. Добавка нужна и GUI (этап 18). Проверяет security. Вопрос В1 ниже.
4. Как два узла за NAT становятся друзьями: «встретились в одной сети» (временная прямая связка, приглашение с LAN-адресом), потом связку убираем; внешние адреса узнают через белых друзей-наблюдателей и обмениваются токенами CHA1, стенд играет роль мессенджера.
5. Типы NAT: full cone, restricted (по адресу), port-restricted, symmetric, CGNAT 100.64/10, двойной NAT, по точным правилам nft (разд. 6); тип каждого NAT проверяется отдельным зондом этапа 8 до строк.
6. Ожидания по каждой паре заданы заранее (разд. 7): кто соединится, кто нет и какую причину обязан назвать продукт. Несовпадение причины = MISMATCH на разбор архитектору, ожидания под результат не подгоняются.
7. Через посредника (13б отложен) и IPv6 (отложен): строки NOTRUN с причиной, без проектирования.
8. Скорости: справочные, 3 повтора, медиана и разброс, CPU процесса по `/proc/self/stat`; профили netem этапа 8 (R1-R4) плюс 50 Мбит/с при RTT 150 мс и потерях 1-3 %. Это эмуляция, не реальные операторы и не ТСПУ.
9. Отчёт `docs/reports/NETTEST-<дата>.md` генерируется скриптом, адреса заменены ролями, без имён хостов; скрипт отказывается писать отчёт, если в нём нашёлся IP-адрес.
10. Время: полный прогон до 3 ч (связность до 2 ч, скорости до 1 ч), быстрый прогон ~20 мин. Скорости нагружают 2-3 ядра из 4 машины с умным домом (вопрос В2).
11. Раздел 18: что проверить вам на реальных сетях (два стационарных ПК, затем ноутбук в чужой сети, затем CGNAT) и что записать в `docs/reports/REAL-NET-<дата>.md`.

## 1. Facts this spec relies on
- `node14` (crates/chervo-transfer/examples/node14.rs:149-221) has no `--forward`, `--udp-window`, no diagnosis/STATE output, sends only to "the single Active friend" (:470-474), keys in plain files (:45-127) [P]. `node13` prints `STATE ... nat_view=` and `EVENT unreachable reason= rendezvous_could_help=` (node13.rs:168-187, :276-283) but keeps keys in memory [P].
- No public engine call issues a manual `CHA1` for a friend: `FriendBook::issue_addr_update` needs a `PublishSet` (chervo-friends/src/book.rs:741), and `PublishSet` comes only from `OwnAddrs::publishable` held privately in the engine state (chervo-addr/src/own.rs:96-120, :383; chervo-connect/src/addrinfo.rs:37-46) [P]. Applying a pasted `CHA1` is already possible through `Engine::update_book(|b, s| b.apply_addr_update_text(s, text, now))` (book.rs:814; engine.rs:1012; used in tests/limiter.rs:260) [P].
- `src_guard` requires `issue_addr_update(` only in `addrinfo.rs` (chervo-connect/src/tests/src_guard.rs:110-112) [P]: the new API must live in `addrinfo.rs`.
- `publishable`: NAT host publishes its observed address only with `hint=true` and only when `nat_view` is `Unknown` or `Eim` (own.rs:368-377, :430-433); `BehindCgnat` when the route source is in 100.64/10 (own.rs:307-310); `Symmetric` when live observations differ in port (own.rs:345-349); `DoubleNat` only from gateway (UPnP) info (own.rs:312-319, :337-341) [P]. Consequence [V]: a CGNAT host and a symmetric host get `NoAddresses` when issuing a token; double NAT without UPnP looks like `Eim`.
- Diagnosis order: no entries -> `NeedToken|NoKnownAddress`; `BehindCgnat`, `DoubleNat`, `SymmetricNat` from own view; then `UdpBlockedSuspected`; then `NeedToken`; else `Unknown` (chervo-connect/src/diag.rs:105-152) [P]. Diagnosis describes only **our own** side.
- Defaults: `fast_window` 120 s, `fast_period` 5 s, `dial_base` 30 s, `hint_base` 60 s, `unreachable_after_fails` 3, `udp_blocked_window` 600 s, `udp_blocked_min_friends` 2 (chervo-connect/src/config.rs:48-79) [P]. Transfer defaults `streams` 4, `per_stream_window` 2, block 1-16 MiB (chervo-transfer/src/config.rs:56-60, layout.rs:12) [P]; quinn windows: stream 4 MiB, connection 16 MiB, send 16 MiB, idle 30 s, keep-alive 10 s (chervo-transport-quinn/src/lib.rs:167-172) [P].
- Engine has `attach_mapper`, `mapping_status` (gateway.rs:213-240); `chervo_upnp::UpnpMapper::new(UpnpSettings { routers: vec![AllowedRouter { id: RouterId::from_setting(udn)?, permanent_ok: false }] })` (chervo-upnp/src/mapper.rs:43, :55-71, :253) [P].
- Stage 8 NAT rules and NAT type probe (`spike8 natprobe`, `reflect`) passed 10/10 type controls in the cloud (SPIKE_TRANSPORT.md 9.5; spikes/transport/src/bin/spike8.rs:474-495) [P for the document and the code; run not by me].
- Linux box: Ubuntu 24.04, kernel 6.8, 4 cores, nftables 1.0.9, tc+netem working inside netns, tcpdump present, sudo without password, Rust 1.99.1 for the user only, root has no cargo, miniupnpd-nftables 2.3.4 unpackable from the .deb [C]. Presence of `ping`, `ethtool`, `conntrack`, `python3` on the box [NP] (preflight checks them).
- `tools/netns/logs/.gitignore` ignores everything except `summary.txt`, `result.txt`, `observe.txt` (tools/netns/logs/.gitignore) [P]. Stages 13/14 wrote logs to `tools/netns/logs13|14` (not ignored) [P].

## 2. Decisions
| # | Decision | Why |
|---|---|---|
| D1 | One new driver `tools/netns/stage16.sh` + `lib16.sh` (helpers copied from stage14.sh/13a.sh without change of meaning) + `report16.sh`. Old stands are not called. | Different topologies, prefixes and summary formats; root has no cargo and stage13.sh always builds. |
| D2 | **Fresh topology per row** (`teardown` + `setup` of all `chv16-*` at row start). | Fresh conntrack and nft sets without `conntrack -F` (tool not confirmed on the box); rows independent. ~3-5 s per row. |
| D3 | One node binary `node16` (new example in `chervo-transfer`, superset of node14). node14 stays unchanged. | Stage 14 stand stays reproducible; one binary for connect, tokens, UPnP, transfer, CPU. |
| D4 | NATed pairs befriend via a temporary **meet link** (direct veth `10.99.0.0/30`, invite with that LAN address on explicit choice), then the link is deleted. | Realistic ("added each other at home"); uniform for every NAT pair; invites between two NATed hosts are otherwise impossible (only the invitee dials). |
| D5 | NATed host learns its external address from **two white observer friends** (`wa`, `wb`), never from the stand. | Owner: one friend suffices for publishing; two are needed to see EDM (`Symmetric`) and `Eim` agreement (own.rs:345-356). |
| D6 | Addresses between NATed friends move only by `CHA1` tokens; **the stand is the messenger** (copies the token file). Needs P0. | BRIEF 4; covers PR-PR (stage 13 NOTRUN) and "IP change, restored via token" (BRIEF 10). |
| D7 | After issuing or applying a token the node calls `connect_now` (both are user actions). | Otherwise the issuer may sit in long backoff and APDF NATs never see overlapping packets [V]. Requirement for stage 18 GUI (section 17). |
| D8 | Diagnosis expectation is per side; outcome mismatch = FAIL, reason mismatch = MISMATCH (architect analysis). Expectations are not edited to match results. | Honest; diagnosis is own-side only. |
| D9 | NAT type control before rows with `spike8 natprobe` (stage 8 method); if not provided: NATCHECK INCONCLUSIVE, rows still run, report marks "NAT types not independently verified". | Rules must be proven to emulate the named type. |
| D10 | Speed numbers are reference only: 3 repeats, median (min-max), spread flag, host load recorded; netem controls (rate, RTT by ping, loss counters). | CORE 4; stage 8 method. |
| D11 | Logs under `tools/netns/logs/stage16/` (gitignored); only the generated report goes to `docs/reports/`; roles instead of addresses. | Stand prefix 11.0.0.0/24 is a real allocated block; public repository. |
| D12 | IPv6, mDNS, rendezvous rows are NOTRUN placeholders with reason. | Owner deferred 13b, 13c, IPv6 listening. |

## 3. P0: product API for manual address tokens (CRITICAL, security review)
In `crates/chervo-connect/src/addrinfo.rs` (src_guard), `impl<T, S> Engine<T, S>` with the same bounds as engine.rs:205-210:
```rust
/// User action "send address token to this friend". Active friends only. Addresses =
/// own.publishable(PublishCtx { include_lan }, now_unix) (LAN only by explicit choice).
/// seq is persisted before signing (FriendBook::issue_addr_update). Empty set: NoAddresses,
/// no seq consumed. Returns the CHA1 text; nothing is logged.
pub fn issue_addr_update_text(&self, pair: &PairId, include_lan: bool) -> Result<String, ConnectError>;
/// User action "paste address token". Text longer than 1024 bytes: Friends(BadAddrUpdate)
/// without decoding. Otherwise update_book(|b, s| b.apply_addr_update_text(s, text.trim(), now)).
/// Returns the pair. Does not dial (the caller calls connect_now).
pub fn apply_addr_update_text(&self, text: &str) -> Result<PairId, ConnectError>;
```
- `issue`: under the state lock like addrinfo.rs:37-46; `Shutdown`, `UnknownPair`, `NotActive` checks first; map `FriendsError::NoAddresses` to `ConnectError::NoAddresses`, others to `Friends(e)`. Must not touch the in-band `last_sent` record (in-band updates keep their own comparison; seq stays monotonic per pair).
- `apply`: must go through `update_book` (publication, `set_peers`) and must not trust anything before signature check (already in book.rs:814-840).
- Tests (engine level, new `src/tests/manual_token.rs`, real `chervo-friends` book, fake transport from `tests/kit.rs`): (1) issue on A -> apply on B -> B's book has the addresses with source `AddressUpdate`, hint flag preserved, returns A's pair; (2) same text again -> `Friends(StaleSeq)`; (3) A's token for pair P1 applied on an engine whose only friend is P2 -> `Friends(BadAddrUpdate)`; (4) unknown / non-Active pair -> `UnknownPair` / `NotActive`; (5) own view `BehindCgnat` and `Symmetric` -> `NoAddresses` and `addr_seq_out` unchanged; (6) `include_lan=false` never contains Private/ULA, `true` contains the private route v4; (7) 1025-byte input rejected, no decode (counter or by construction); (8) one byte flipped -> `BadAddrUpdate`.
- `src_guard.rs` is not edited; it must stay green (the new call is inside `addrinfo.rs`).

## 4. Node `node16` (crates/chervo-transfer/examples/node16.rs; dev-dep `chervo-upnp`)
Copy of node14 (FileStore keys, AskAlways, GeneratedNames) plus:
- **Labels:** friend created by the k-th `--invite-out` = `o<k>`, by the k-th `--invite-in` = `i<k>`; stored in `BOOKDIR/labels` (pair hex -> label, mode 600) so restarts keep labels. Output never prints pair ids, SAS, token text, file names.
- Flags (in addition to node14's): `--invite-lan` (`InviteAddrs::Auto { same_network: true }`), `--udp-window S` (`ConnectConfig.udp_blocked_window`), `--upnp-router UDN` (attach `UpnpMapper` with that router as confirmed by the user), `--token-to L --token-out F [--token-lan]` (each time `F.go` appears: delete it, `issue_addr_update_text`, retry each tick on `NoAddresses` for up to 30 s, write `F` atomically mode 600, then `connect_now(L)`), `--token-in F` (each time content changes: `apply_addr_update_text`, on Ok `connect_now(pair)`), `--send-to L` (with `--send`), `--stop-file F` (clean shutdown when F exists: transfers, engine, transport; releases UPnP), `--diag-every S` (default 5).
- Output (one line each, `t=<ms since start>` on every line): `EVENT started listen_port=`; `EVENT connected pair=L path=<PathKind>`; `EVENT disconnected pair=L`; `EVENT unreachable pair=L reason=R rendezvous_could_help=B`; `DIAG pair=L reason=R|none rendezvous_could_help=B` (every `--diag-every` for each Active friend, from `engine.diagnose`); `STATE connected=N nat_view=V mapping=<MapStatus|none> friend:L=[addr,...]` (every 2 s; addresses only here, stand logs only); `EVENT token_issued to=L` / `EVENT token_failed to=L error=E`; `EVENT token_applied pair=L` / `EVENT token_rejected error=E`; transfer events as node14 plus `EVENT cpu phase=start|end ticks=N` (Linux: `/proc/self/stat`, fields 14+15 counted after the last `)`; absent elsewhere) printed on `TransferEvent::Started` and `Completed`; receiver `RESULT xfer bytes=N ms=M` (Started -> Completed, includes final whole-file check) and node14's `RESULT received ... sha256=`.
- Exit codes as node14. Stand-only tool: keys in plain files, delete `book-dir` after use.

## 5. Stand files, safety, topology
Files: `tools/netns/lib16.sh` (state dir, binary checks, ns/veth helpers, nft guard, process helpers, verdict writer), `tools/netns/stage16.sh` (topology, NAT loads, rows, subcommands), `tools/netns/report16.sh` (renders the report, runs as normal user), `tools/netns/fixtures16/` (fake summary for the self-test).
Subcommands: `preflight | natcheck | conn | speed | g7 | extra | quick | all | <row id> | teardown`; `quick` = NATCHECK, C03, C06, C11, C13, C19, S-WHITE-N0 (1 repeat).
**Safety (all mandatory):**
- Only namespaces `chv16-*`; every `nft`, `sysctl`, `tc`, `ethtool`, `tcpdump` via `ip netns exec chv16-*`; `/etc/netns/chv16-<ns>/resolv.conf` stub (`nameserver 192.0.2.53`) created and removed per ns; never touch `/etc/netns` itself.
- STATE: `mktemp -d /tmp/chervo-stage16.XXXXXX`, mode 700; `CHV_STATE` accepted only if not a symlink and owned by the caller, checked before `mkdir`/`chmod` (copy stage14.sh:28-42).
- Binaries from env: `CHV_NODE16` (required), `CHV_SPIKE8` (NATCHECK), `CHV_MINIUPNPD` (C18, S-UPNP), `CHV_NODE16_LIAR` (X02, optional). Each: regular file, not a symlink, owner root or `SUDO_UID`, mode without group/other write, parent directory without group/other write; copied into `STATE/bin` (root-owned, 755) and executed only from there, only inside ns with `env -i PATH=...`.
- Host snapshot at start and end of every subcommand: `sha256` of host `nft list ruleset`, `ip -o link` lines not containing `chv16`, `ip netns list` without `chv16-`, host `sysctl net.ipv4.ip_forward net.ipv4.conf.all.forwarding`. Any difference: row `HOSTSAFE FAIL`, stop (section 16).
- `trap cleanup EXIT`: stop nodes, miniupnpd, tcpdump; teardown own ns; remove STATE unless `CHV_KEEP=1`.
Topology (`CORE=11.0.0`, interface names <= 15 chars, every host binds UDP 4433 on 0.0.0.0, default routes as stage13.sh:160-166):
| ns | Role (report label) | Addresses |
|---|---|---|
| i | internet bridge `core0`, netem points `p-<ns>` | CORE.254 |
| wa, wb | white PCs / observers (WA, WB) | CORE.50, CORE.51 |
| m | NATCHECK reflector (REFL) | CORE.100, CORE.101 |
| na | NAT-A, type per row | wan CORE.10, lan bridge 192.168.10.1/24 |
| ha, ha2 | hosts behind NAT-A (HA, HA2); ha has `eth1` to na2, down by default | 192.168.10.2, .3; eth1 192.168.12.2 |
| na2 | second network of the laptop (NAT-A2, PR) | wan CORE.12, lan 192.168.12.1/24 |
| nb, hb | NAT-B (type per row), HB | wan CORE.30, lan 192.168.30.1; hb .2 |
| nr, hr | UPnP router (NAT-R, PR + miniupnpd), HR | wan CORE.20, lan 192.168.20.1; hr .2 |
| cg, hc | ISP CGNAT (CGN-1, PR), modem host HC | wan CORE.40, inside bridge 100.64.0.1/10; hc 100.64.0.2 |
| nd, hd | home router behind CGN-1 (NAT-D, PR), HD | wan 100.64.0.3/10, lan 192.168.40.1; hd .2 |
| cg2, hc2 | second CGNAT (CGN-2, PR), HC2 | wan CORE.41, inside 100.64.0.1/10; hc2 100.64.0.2 |
| (meet) | temporary veth `meet0` between two hosts of a row | 10.99.0.1/30, 10.99.0.2/30 |
`net.ipv4.ip_forward=1` in NAT ns; `promote_secondaries=1` in wa, wb, na, nb (address change rows).

## 6. NAT types: exact nft rules
One template per NAT ns (`L` = inside subnet, `H` = the single inside host of that NAT):
```
table inet nat16 {
  set seen  { type ipv4_addr; flags dynamic,timeout; timeout 120s; }
  set fcmap { type inet_service; flags dynamic,timeout; timeout 120s; }
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    @PRE@
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "wan" ip saddr L @MASQ@
  }
  chain fwd16 {
    type filter hook forward priority filter; policy drop;
    @LANOUT@
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
    iifname "wan" ct status dnat accept
  }
  chain inp16 {
    type filter hook input priority filter; policy accept;
    iifname "wan" icmp type echo-request accept
    iifname "wan" drop
  }
}
```
| Type (report) | Mapping / filtering | @MASQ@ | @PRE@ | @LANOUT@ |
|---|---|---|---|---|
| FC full cone | EIM / EIF (after first outbound, per port) | `masquerade` | `iifname "wan" udp dport @fcmap dnat ip to H` | `iifname "lan" oifname "wan" meta l4proto udp update @fcmap { udp sport }` |
| AR restricted cone | EIM / ADF | `masquerade` | `iifname "wan" udp dport 4433 ip saddr @seen dnat ip to H` | `iifname "lan" oifname "wan" udp sport 4433 update @seen { ip daddr }` |
| PR port-restricted | EIM / APDF | `masquerade` | (empty) | (empty) |
| SYM symmetric | EDM / APDF | `masquerade fully-random` | (empty) | (empty) |
| CGN (cg, cg2) | EIM / APDF, L = 100.64.0.0/10 | `masquerade` | (empty) | (empty) |
| DNAT (nd behind cg) | two PR layers | nd: `masquerade`, L = 192.168.40.0/24 | (empty) | (empty) |
| UPnP (nr) | PR + miniupnpd chains | as PR | `jump prerouting_miniupnpd` | `jump miniupnpd` (first in fwd16) |
- nr: plus empty chains `miniupnpd`, `prerouting_miniupnpd`, `postrouting_miniupnpd` and `jump postrouting_miniupnpd` first in `post`; miniupnpd config exactly as stage13a.sh:346-367 (table `nat16`, `ext_ifname=wan`, `listening_ip=lan`, fixed `uuid`, NAT-PMP/PCP off, `secure_mode=yes`); miniupnpd rules appear as `th dport` (stage 13a finding).
- nftables 1.0.9 rules: no chain named `fwd`; a one-line chain needs `;` before `}`; FC and AR depend on port preservation (stand checks the observed port = 4433 in NATCHECK). FC here is per-host full cone (one inside host), not a general full cone [V]: say so in the report.
- Host guard (one host per row where stated): stage14.sh:167-209 `nft_guard` (output and input) with peers = the row's friend addresses (observers, peer NAT WAN, meet link), plus `ip protocol icmp icmp type destination-unreachable counter name "icmp_unreach" accept` (and the ICMPv6 equivalent if IPv6 is on) **before** `other`; kernel unreachables are reported separately, not as `other`. Pass: `dns = probe = other = other_in = 0`, `peer > 0`.

## 7. Connectivity matrix (`conn`)
Common flow for rows with NATed hosts: setup; each NATed host accepts invites from `wa` and `wb` (observers; `wa`/`wb` issue `--invite-out`); wait `STATE nat_view` not `Unknown` (<= 60 s; else INCONCLUSIVE "no observation"); meet link up, X issues `--invite-out --invite-addr 10.99.0.1:4433`, Y accepts, both `invite_finished` OK; meet link down; tokens as the row says (stand touches `X/tok.go`, waits `X/tok`, copies to `Y/tok-in`; log only `token delivered bytes=N`); observation window W = 240 s from the last token (or from meet-down if no token). Connected = `EVENT connected pair=<peer label>` on both sides within W. Reasons = last `EVENT unreachable` for that pair, else last `DIAG` at the end of W. Guard: on the host named in the row.
| ID | Pair X - Y | Addresses learned by | Expected connect | Expected reason X / Y (product diagnosis) | Theory (for "why") |
|---|---|---|---|---|---|
| C01 | HA - HA2 (same LAN) | invite `--invite-lan` | yes, path Lan | - / - | same segment (mDNS NOTRUN, 13c) |
| C02 | IPv6 | - | NOTRUN | - | IPv6 listening deferred by owner |
| C03 | WA - WB | invite | yes | - / - | both white |
| C04 | FC - PR (na FC, nb PR) | meet; token X->Y only | yes | - / - | EIF lets Y in without X knowing Y |
| C05 | AR - AR | meet; tokens both | yes | - / - | both EIM, both addresses known |
| C06 | PR - PR (guard on ha) | meet; tokens both | yes, path SimultaneousOpen | - / - | both EIM, simultaneous open |
| C07 | PR - PR | meet only, no token | no | NeedToken / NeedToken [V] | nobody knows the other's external address |
| C08 | SYM - WA,WB (na SYM) | invite; then `wa` killed | yes, then unreachable | SymmetricNat (after `wa` gone) | EDM seen by two observers |
| C09 | SYM - FC (na SYM, nb FC) | meet; token Y->X (X's token expected `token_failed NoAddresses`) | yes | - / - | SYM calls, EIF admits |
| C10 | SYM - AR | meet; token Y->X | no | SymmetricNat / NeedToken [V] | AR never sent to SYM's IP |
| C11 | SYM - PR | meet; token Y->X | no | SymmetricNat / NeedToken [V] | EDM vs APDF |
| C12 | SYM - SYM | meet; tokens both expected to fail | no | SymmetricNat / SymmetricNat | EDM both |
| C13 | HC (CGNAT) - WA (guard on hc) | invite; then `wa` killed | yes, then unreachable | BehindCgnat, rendezvous_could_help=true | outbound works, nobody reaches HC |
| C14 | HC - PR | meet; token Y->X (HC token `NoAddresses`) | no | BehindCgnat (rv=true) / NeedToken [V] | HC cannot publish an address |
| C15 | HC - HC2 (two CGNATs) | meet; tokens both fail | no | BehindCgnat / BehindCgnat | both behind CGNAT |
| C16 | HD (double NAT) - WA | invite | yes; `nat_view=Eim` [V] | - | DoubleNat not detectable without gateway info (own.rs:312-341); 13a: miniupnpd does not name a private WAN |
| C17 | HD - PR | meet; tokens both | yes [V] | - / - | both layers EIM with port preservation (G4 CG-EIM-PR) |
| C18 | HR (UPnP) - PR | HR invite with mapped address (`--upnp-router uuid:...`) | yes, path PortMapped; `nat_view=PortMapped` | - / - | port mapping; after HR `--stop-file`: no `th dport 4433` rule left in nr |
| C19 | HA - WA,WB, UDP dropped on ha (`--udp-window 60`) | invites | no (after block) | UdpBlockedSuspected | two white friends silent |
Rows C04-C17: NAT-A and NAT-B types are loaded per row from section 6; SYM always on the X side NAT.

## 8. Via rendezvous (placeholders)
| ID | Pair | Verdict | Reason | Expectation by theory (G4 sync, SPIKE 9.5) |
|---|---|---|---|---|
| V01 | CGNAT - PR | NOTRUN | stage 13b deferred by owner | yes (EIM both) |
| V02 | CGNAT - CGNAT | NOTRUN | same | depends on both CGNATs being EIM |
| V03 | SYM - PR | NOTRUN | same | no |
| V04 | SYM - SYM | NOTRUN | same | no |
| V05 | PR - PR without token | NOTRUN | same | yes |
The stand writes these lines; nothing else is built for them.

## 9. IP change mid-transfer and G7 with delay (`g7`)
Profile D20 on every row here: netem `delay 10ms rate 100mbit limit 500` on both endpoint ports in `i` (RTT 20 ms, stage 8 G7 spec). File 256 MiB random, defaults (4 streams, window 2), event when the receiver passes 30 % (`EVENT progress`). Record: completed, `cmp`, sha256, connections (count of `connected` events for the pair: 1 = migration, >= 2 = reconnect), `paused`/`resumed`, max stall (largest gap between increasing progress lines), total time vs G7-BASE.
| ID | Case | Expected |
|---|---|---|
| G7-BASE | WA -> WB, no event | completes, cmp equal |
| G7-CALLEE | WB changes IP (`.51` -> `.52`) | completes, cmp equal (stage 14 ADDRCHANGE with delay) |
| G7-LAPTOP | HA (behind NAT-A PR) -> WA; HA switches to `eth1`/NAT-A2 (stage 8 7.1) | completes, cmp equal |
| G7-DROP15 | WA -> WB; UDP dropped 15 s (stage14 drop_on) | paused, resumed, cmp equal |
| C20 | HA -> HB PR-PR via tokens; NAT-A WAN changes `.10` -> `.11` at 30 % | `paused`; HA learns new observed address from WA/WB (<= 120 s [V]); stand triggers HA's token, delivers it; `resumed`; cmp equal; then the stand re-delivers the **first** token: `token_rejected error=...StaleSeq` |
If HA never learns its new external address (observer connections survive by QUIC migration without a new observation [V]): C20 FAIL with reason `observed address not refreshed after NAT rebinding` (product finding for analysis, not a stand fix).

## 10. Speed table (`speed`)
Paths (sender -> receiver; netem on the `i` ports: data direction = receiver side port, ACK direction = sender side port; loss only on data direction):
| Path | Sender -> receiver | Profiles |
|---|---|---|
| LAN | HA -> HA2 (NAT-A LAN bridge) | N0 |
| WHITE | WA -> WB | N0, R1, R2, R2-W1, R3, R4, P1, P2, P3 |
| UPNP | WA -> HR (inbound through mapping) | N0, R1 |
| PUNCH | HA -> HB (PR-PR via tokens) | N0, R1 |
| IPV6 | - | NOTRUN (deferred) |
| Profile | netem on each port | RTT | Loss (data) | limit | File |
|---|---|---|---|---|---|
| N0 | none | ~0 | 0 | - | 1024 MiB |
| R1 | `delay 10ms rate 100mbit` | 20 | 0 | 500 | 128 MiB |
| R2 | `delay 40ms rate 100mbit` | 80 | 0 | 1700 | 128 MiB |
| R2-W1 | as R2, node `--streams 1 --window 1` | 80 | 0 | 1700 | 128 MiB |
| R3 | `delay 20ms rate 100mbit` | 40 | 0.5 % | 900 | 64 MiB (stage 8: 16 MiB, too small for 1 MiB blocks) |
| R4 | `delay 10ms rate 1gbit` | 20 | 0 | 4200 | 512 MiB |
| P1 | `delay 75ms rate 50mbit` | 150 | 0 | 1500 | 128 MiB |
| P2 | `delay 75ms rate 50mbit` | 150 | 1 % | 1500 | 64 MiB |
| P3 | `delay 25ms rate 50mbit` | 50 | 3 % | 800 | 64 MiB |
Method:
- Offloads off on netem ports and endpoint `wan`/`eth0` (`ethtool -K <if> gso off tso off gro off` in the ns); no `ethtool`: rows with loss INCONCLUSIVE "offload not disabled", others flagged.
- Per config: fresh topology, pair once, source from `/dev/urandom` in STATE, 3 repeats; per repeat start receiver then sender (keys persist), wait `RESULT xfer`, timeout 180 s (then "not finished": bytes done, no speed).
- Speed = bytes / `ms` of receiver `RESULT xfer` (Started -> Completed incl. final check); MiB/s and Mbit/s. Connect time (node start -> `connected`) reported separately.
- CPU: `EVENT cpu` ticks start/end per process, `CLK_TCK` from `getconf`; % of one core = delta_ticks / CLK_TCK / delta_wall * 100 (sender and receiver). Machine: `/proc/stat` before/after, busy cores = (1 - delta_idle/delta_total) * nproc. `/proc/loadavg` before each repeat; load1 > 1.5 marks "busy host".
- Integrity per repeat: `cmp` and receiver sha256 = `sha256sum` of source; any mismatch: section 16.
- Controls: `tc -s qdisc` before/after; speed <= 1.05 x rate; ping from `i` to each netem'd endpoint (`ping -c 5 -i 0.2`) within +-25 % (+1 ms) of that port's one-way delay (ICMP echo is allowed on NAT WAN by `inp16`); loss rows: dropped/sent on the data port within [0.5P, 2P]. A failed control marks the cell "control failed", the number stays with the flag.
- Table cell: median (min-max), spread = (max-min)/median, "unstable" if > 20 %. Window note per row: in flight <= min(16 MiB connection window, streams x window x block = 8 MiB by default, 1 MiB for R2-W1) [V]; so only R2-W1 is window-bound by design.

## 11. Controls before rows
- `preflight`: root; `ip`, `nft`, `tc`, `tcpdump`; netem qdisc on a throwaway veth in a `chv16-pf` ns; `ping`, `ethtool`, `getconf`, `sha256sum`, `cmp` presence (missing = listed, dependent rows flagged); env binaries pass section 5 checks; free space in STATE >= 4 GiB (else N0/R4 drop to 512/256 MiB, recorded); host snapshot taken.
- `natcheck` (NATCHECK): stage 8 method with `spike8 reflect --bind CORE.100:7001,CORE.100:7002,CORE.101:7001` in `m` and `spike8 natprobe --local 0.0.0.0:4433 ...` in the inside host, for FC@na, AR@na, PR@na, SYM@na, PR@nb, CGN@hc, DNAT@hd. Expected: FC EIM/EIF, AR EIM/ADF, PR EIM/APDF, SYM EDM/APDF, CGN EIM/APDF, DNAT EIM/APDF; ext port 4433 for all EIM. Two attempts; mismatch twice: that type INCONCLUSIVE in every row using it. Rules are never tuned to the result.

## 12. Extra rows (`extra`)
- X01 CAPTURE: during C06, `tcpdump -i any -w STATE/...pcap` in `ha`; summary of distinct destinations mapped to roles must be a subset of {WA, WB, NAT-B WAN, meet peer}; packets to 192.0.2.1 and 2001:db8::1 = 0 (stage 12 "probe sends nothing"); DNS = 0. The pcap is not kept.
- X02 LIAR (optional; stage 12 requirement): `stage16.sh build-liar` (run as the normal user) copies the repository to a `mktemp -d`, patches in `addrinfo.rs` the single expression that reports the observed address so it reports `CORE.66:4433` (victim ns `v`), aborts (row NOTRUN) unless exactly one replacement matched, builds `node16`. Flow: honest HA's only observer is the liar LW; HA in-band-publishes the hint to friend WB; HA is killed; victim `v` counts packets from WB for 300 s. Expected: bursts spaced >= 30 s, total bursts <= 11 (stage 13 statement "not more often than once per 30 s"); closer spacing = FAIL to security.

## 13. Output and report
- Raw: `tools/netns/logs/stage16/<row>/...` (gitignored), `summary16.tsv`: `id group verdict expected actual reason_x_exp reason_x_got reason_y_exp reason_y_got path t_connect_s note`; `speed16.tsv`: `path profile rep bytes ms mibps cpu_snd cpu_rcv sys_cores load1 cmp ctl_rate ctl_rtt ctl_loss`.
- Verdicts: PASS, MISMATCH (outcome as expected, reason differs), FAIL, INCONCLUSIVE (stand control failed / timeout), NOTRUN (with reason).
- `report16.sh LOGDIR OUT.md` (normal user) writes `docs/reports/NETTEST-<YYYY-MM-DD>.md` in Russian: (1) header: date, commit, `uname -r`, nproc, CPU model, virtualization, versions of nft/tc/iproute2/miniupnpd, rustc used for the build, line "Эмуляция netns, не реальные операторы и не ТСПУ"; (2) NATCHECK; (3) connectivity matrix with expected vs got; (4) **"Какие пары не соединились и почему"**: every row with connect = no, both reasons and the theory column; (5) via rendezvous (NOTRUN); (6) speed table with CPU, window note, controls; (7) G7 with delay; (8) X01/X02; (9) HOSTSAFE; (10) the separate line **"Не проверено: реальные операторы, ТСПУ."** followed by IPv6, mDNS, rendezvous, real routers, Windows/macOS stacks; (11) "Резюме для владельца" skeleton with numbers (architect writes conclusions afterwards).
- Sanitizer: addresses replaced by role labels from a fixed map; the generator refuses to write (exit 4) if the output matches an IPv4/IPv6 literal, `/home/`, `/tmp/chervo`, the value of `hostname`, or `$SUDO_USER`. `--self-test` uses `fixtures16/` with a positive and a negative control.

## 14. Time budget (hard caps; exceeded row = INCONCLUSIVE "timeout")
Row caps: yes-rows 300 s, no-rows 420 s, C20/G7 rows 600 s, speed config 15 min. Expected: preflight+natcheck 5 min, `conn` 60-110 min, `g7` 20 min, `speed` 35-60 min, `extra` 15 min; `all` <= 3 h; `quick` ~20 min. Rows run strictly one after another (CPU contention would distort speed).

## 15. Who does what; acceptance commands
1. builder (sonnet/high): P0 + tests + node16. Windows: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test --workspace --locked`; `for i in $(seq 20); do cargo test -q --locked -p chervo-connect manual_token || exit 1; done`; `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`; `cargo build --release --locked -p chervo-transfer --example node16`; two-process smoke on Windows: invite, connect, token issue/apply between two node16 (expected `token_failed NoAddresses` on loopback-only is acceptable and must be reported as such).
2. security (opus/high): P0 diff only.
3. builder (sonnet/medium): lib16/stage16/report16/fixtures16. `bash -n tools/netns/{lib16,stage16,report16}.sh`; `bash tools/netns/report16.sh --self-test`. Header comment: "not run on Linux by the builder".
4. conductor (Linux box), as the normal user: `cargo build --release --locked -p chervo-transfer --example node16`; `(cd spikes/transport && cargo build --release --locked --bin spike8)`; `d=$(mktemp -d); (cd "$d" && apt-get download miniupnpd-nftables && dpkg-deb -x miniupnpd-nftables_*.deb root)`; `chmod -R go-w` on the binaries. Then `sudo CHV_NODE16=... CHV_SPIKE8=... CHV_MINIUPNPD="$d/root/usr/sbin/miniupnpd" bash tools/netns/stage16.sh preflight`, then `quick`, then `all`; `bash tools/netns/report16.sh tools/netns/logs/stage16 docs/reports/NETTEST-$(date +%F).md`; check `ip netns list | grep -c '^chv16-'` = 0 and HOSTSAFE PASS; `rm -rf "$d"`.
5. builder fix rounds for stand-only defects (syntax, waits): at most 2; each fix names the line and keeps expectations unchanged.
6. architect: analysis section in the report (every FAIL/MISMATCH: product defect -> TASK item, or stand defect -> fixed and row rerun).
**Stage accepted when:** every row has a verdict; HOSTSAFE PASS; NATCHECK PASS (or INCONCLUSIVE with reason accepted by the conductor); no open FAIL in integrity (`cmp`) or guard (`other`/`other_in` > 0); every FAIL/MISMATCH has an analysis line; report passes the sanitizer and contains the not-verified line.

## 16. Stop conditions
- Preflight fails (not root, tools, binary checks, netem): exit 3, nothing runs.
- HOSTSAFE difference: stop at once, do not try to repair the host, report to the conductor.
- `cmp`/sha256 mismatch in any transfer: stop `speed`/`g7`, keep logs, escalate (integrity > speed, BRIEF 6).
- Guard: a host sends to a non-friend (`other` > 0, excluding `icmp_unreach`): row FAIL, continue, escalate to security.
- Spec contradicts code (e.g. P0 cannot live in `addrinfo.rs`, layout test forbids the dev-edge, `publishable` differs from section 1): builder stops and reports.
- A product defect found by a row is not fixed in this stage; it becomes a TASK item.

## 17. Not verified here; requirements for other stages
- Not verified (report must say): real operators, TSPU, mobile CGNAT port blocks, real router UDP timeouts and port allocation, hairpin, IPv6, mDNS, rendezvous, Windows/macOS network stacks, HDD, NAT-PMP/PCP.
- Stage 18: "send address token" and "paste token" call P0 and then `connect_now` on both sides (D7); show `NoAddresses` / `StaleSeq` / `BadAddrUpdate` texts (stage 12 spec line 310).
- Stage 13b: V01-V05 become real rows on this stand (add `rdv` ns).

## 18. Real network checks for the owner
Prepare: same commit on every machine; `cargo build --release --locked -p chervo-transfer --example node16`; test pairs only (plain-file keys), delete `book-dir` afterwards; logs contain real addresses: **never commit logs**, fill the report by hand. CPU on Windows: `(Get-Process node16).TotalProcessorTime` before and after a transfer. File: 1 GiB random (`fsutil` is not random; use `node16`-independent random data, e.g. PowerShell `[IO.File]::WriteAllBytes` with `RandomNumberGenerator`), sha256 by `Get-FileHash`.
1. **Two stationary PCs, different home ISPs.** PC-B: white IP, or manual port forward of UDP 4433, or UPnP (`cargo run --release -p chervo-upnp --example upnp_probe -- identify|map|release` on the home router first: stage 13a real-router check). B `--invite-out`, the invite text goes to A by messenger (it contains B's IP), A `--invite-in`. Record: `nat_view` both sides, connected y/n, path, time to connect; 3 transfers each direction: MiB/s, CPU, sha256 equal. Then change B's IP (router reconnect) with A offline: does A reconnect by in-band update or is a `CHA1` token needed (send it by messenger)?
2. **Laptop in a foreign network** (friend's Wi-Fi, cafe): connect to PC-B, transfer; mid-transfer switch Wi-Fi -> phone hotspot: paused/resumed, stall seconds, sha256 equal.
3. **CGNAT** (phone hotspot or mobile modem): `nat_view` (expected BehindCgnat for a modem with a 100.64 address; a phone hotspot usually shows double NAT as Eim/Symmetric), diagnosis text when B calls the laptop, outbound connect to B works or not, `UdpBlockedSuspected` seen or not; speed versus the home network (suspected QUIC/UDP throttling is recorded as a suspicion only).
4. IPv6: only record whether both sides have global IPv6 (product does not listen on IPv6 yet).
`docs/reports/REAL-NET-<YYYY-MM-DD>.md` (Russian), one row per test: date; commit; OS pair; access type each side (fiber/DSL/4G/Wi-Fi), ISP brand optional; router model optional; `nat_view` A/B; connected; path; time to connect; diagnosis text; MiB/s x3 (median); CPU s per GiB; sha256 equal; stall at network switch; notes. **Never write:** IP addresses, host names, MACs, router UDN/serials, SAS words, token or invite texts, precise location.

## 19. Open questions (contested only)
**В1. Add the product API P0 in stage 16?** Without it PR-PR, C20 and "IP change restored via token" (BRIEF 10) cannot run; the alternative is a temporary port forward during pairing (then C05/C06/C17 run without tokens, C20 and the token half of C04/C09-C11/C14 become NOTRUN). **Recommendation: add now** (two thin methods in `addrinfo.rs` over already reviewed stage 12 functions, needed by stage 18 anyway, one security review of a small diff).
**В2. CPU load on the smart-home box.** `speed` keeps 2-3 of 4 cores busy for 35-60 min; `nice` would distort the numbers. **Recommendation:** run `speed` when the smart home is idle (e.g. at night) at normal priority; if the owner prefers safety, `CHV_NICE=10` is applied to nodes and the report marks every speed number "under nice 10".

## 20. Rev. 2 addendum (2026-10-18, after the full run on 8d9e279)
Analysis: `docs/reports/NETTEST-2026-10-18.md` section 12. Rule D8 holds: an expectation changes here only where repository code contradicts rev 1, never because of a result. C06 and C20 expectations are **unchanged** (product defects, TASK 16а). The stand is not re-specified elsewhere.

**Резюме (русский).** Меняются ожидания трёх строк, которые я написал вопреки коду: C07 (связка сама передаёт подсказку внешнего адреса, поэтому соединение есть), C18 (вид пути зависит от того, кто победил в гонке), G7-DROP15 (15 с меньше простоя QUIC 30 с, паузы быть не может). Новые строки: C07H, G7-DROP45 и после 16а G7-REBIND. Две правки стенда: ICMP во входной цепи охраны и выключение UDP GSO для контроля потерь.

### 20.1 Expectation changes (code facts)
| Row | Rev 1 | Rev 2 | Code fact |
|---|---|---|---|
| C07 | meet after observation, no token: no, NeedToken / NeedToken | **C07H** = the rev 1 flow: yes, path SimultaneousOpen, reasons none. **C07** = new flow `meet_first`: meet up, invite over the meet link, both `invite_finished`, meet down, **then** observers (`obs_start`, invites, wait nat_view not Unknown), no token, W = 240 s: no, NeedToken / NeedToken | ADDR_INFO on the meet connection carries the own observed address as a hint (own.rs:368-377, :430-433; addrinfo.rs:89-112; engine.rs:517); hints live 24 h (chervo-addr/src/book.rs:11). With no observation at meet time nothing external is published. |
| C18 | path PortMapped | path PortMapped **or** SimultaneousOpen; still required: connected both, HR `nat_view=PortMapped`, mapping removed after stop | `path_kind` labels the winning connection; a `Contact` entry is deliberately not "stable" (chervo-connect/src/plan.rs:109-134, :124-128). Which dial wins is a race. Same as stage 13 FORWARD. |
| G7-DROP15 | paused, resumed, cmp equal | completes, cmp equal, connections=1, paused=0, max_stall_s <= 30 | idle 30 s, keep-alive 10 s (chervo-transport-quinn/src/lib.rs:171-172): a 15 s outage cannot close the connection. |
| G7-DROP45 (new) | - | D20, WA -> WB, UDP dropped 45 s at 30 %: paused, resumed, cmp equal | the outage now exceeds idle 30 s (stage 14 DROP, now with delay). |

### 20.2 Stand fixes (builder; expectations untouched)
- **S1 guard, input side.** In `nft_guard` input chain, before `other_in`: `ip protocol icmp icmp type destination-unreachable counter name "icmp_unreach_in" accept` (and the ICMPv6 equivalent). Add dynamic sets `other_d { type ipv4_addr . inet_service; flags dynamic; size 64; }` (output, `update @other_d { ip daddr . th dport }`, non-UDP/TCP: daddr only in a second set) and `other_s` (input, saddr); the report prints roles from the fixed map, never addresses. Pass rule unchanged.
- **S2 UDP GSO.** `offloads_off`: in addition to `gso off tso off gro off`, apply `tx-udp-segmentation off`, `rx-udp-gro-forwarding off`, `rx-gro-list off` on every stand interface except `lo` (each option separately, `fixed`/unsupported is not an error), then `ethtool -k` must show `tx-udp-segmentation: off` on the endpoint `wan`/`eth0` and the `p-*` ports; else loss rows INCONCLUSIVE "UDP GSO не отключается". Reason [V]: the measured loss ratio was a constant ~1/6 of the target in R3, P2 and P3; netem drops a whole GSO skb and counts one drop while `Sent pkt` counts segments. R3/P2/P3 numbers of 8d9e279 are discarded and rerun.
- **S3 rows.** Implement 20.1 (C07 `meet_first`, C07H, C18 path rule, G7-DROP15 expectation, G7-DROP45).

### 20.3 Rows after TASK 16а (product fixes П1, П2)
- **G7-REBIND (new):** D20, HA (behind NAT-A PR) -> WA, NAT-A WAN `.10` -> `.11` at 30 %. Expected: completes, cmp equal; HA `nat_view` not `Conflicting` within 60 s after the change; connections=1 if F4 is implemented, otherwise >= 2 accepted.
- **C06 / X01, C20:** rerun with rev 1 expectations (C06 guard `other = other_in = 0` after S1 and П2).

### 20.4 Acceptance
Rows of 20.1-20.2 rerun on the Linux box. Section 15 "no open FAIL in guard" stays: C06 and C20 close only after 16а, or the conductor carries them into 16а with the owner's consent.
