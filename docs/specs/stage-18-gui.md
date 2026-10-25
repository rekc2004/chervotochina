# SPEC 18: GUI, with its prerequisite "node in chervo-core"          criticality: 18a КРИТИЧНЫЙ; 18p gate; 18b обычный + targeted security review; 18c обычный

Author: combine-architect (opus), 2026-10-25, revision 1. Base: `80e1917`. Labels: [P] verified by me in the source or docs at the base (file:line); [S] from the scout facts file of 2026-10-25 (crates.io/GitHub pages, nothing built); [V] my inference; [NP] not verified. **Nothing was built or run by me.** Owner questions are in Russian at the end. Each sub-stage below is a separate SPEC in the format of `.claude/combine/SPEC.md`. Naming: 18a/18b/18c correspond to 18а/18б/18в in Russian text; the gate is 18p (probe), to avoid a clash with 18в.

## 0. Why stage 18 needs a prerequisite (facts)
1. `chervo_core::Node::start` always returns `CoreError::NotImplemented` (`crates/chervo-core/src/lib.rs:71-74`) [P]. No integrated node exists. A full node is assembled by hand only in the examples: `chervo-transfer/examples/node16.rs:434-879` (key store, `FriendBook`, `AllowSet`, `QuinnTransport::bind`, `Engine::start`, UPnP `attach_mapper`, `stream_inbox`, `Transfers::start`, event loop, ordered shutdown, `release()` of the port mapping) and `chervo-receive/examples/node15.rs:360-384` (`ReceiveConfig`, `ReceiveRoot::open`, `ReceivePlacement`, `ReceivePolicy`) [P]. Both examples use file key stores and `open_unanchored`; the product must not (`crates/chervo-core/tests/anchored_only.rs:84-95`) [P].
2. The GUI crate must depend only on `chervo-core` (`docs/PLAN_DRAFT.md:27`, TASK stage 18) [P].
3. The core manifest guard forbids the substrings `chervo-cli`, `iroh`, `quinn`, `rustls`, `tokio` (`crates/chervo-core/tests/layout.rs:35-41`) [P]. The core does not depend on `chervo-transport-quinn`, `chervo-upnp` or `chervo-timesync` today (`crates/chervo-core/Cargo.toml:8-21`) [P]. `Engine::start` must run inside a tokio runtime (`chervo-connect/src/engine.rs:1086-1088`) [P].
4. Hence the GUI cannot be built on the current core. Stage 18 is split: **18a** builds the node in `chervo-core`. **18p** is a short verification gate for the GUI framework. **18b** is the GUI. **18c** adds minimal CLI commands.

### Decision D1 (for the conductor, not the owner): the node lives in `chervo-core`, the core manifest guard is narrowed
- `chervo-core` gets direct dependencies `chervo-transport-quinn`, `chervo-upnp`, `chervo-timesync`, `tokio` (workspace features only: `rt, net, time, sync, macros`; no `rt-multi-thread`). `Node` becomes concrete (quinn), not generic.
- `layout.rs` changes from a substring test to an exact dependency-name test. Forbidden as **direct** core dependencies: `chervo-cli`, `chervo-gui`, `iroh`, `quinn`, `rustls`, `snow`, `ring`, and every GUI crate (`eframe`, `egui`, `winit`, `wgpu`, `glow`, `accesskit`). Allowed: the `chervo-*` crates listed above and `tokio`.
- Why: the transport choice is final (DECISION B, stage 7). Genericity stays where it is useful: `Engine<T, S>` in `chervo-connect` remains generic, so a TCP adapter (U7) is still a second adapter without rewriting the engine. quinn runs on mobile targets too [V], so later mobile shells are not blocked.
- Rejected alternative: a new composition crate (`chervo-node`) on top of a generic core. The core would still need tokio for the event pump. The owner-facing rule "GUI depends only on `chervo-core`" would have to be reworded. It adds a layer and buys nothing [V].
- Rejected alternative: the GUI depends on `chervo-core` and `chervo-transport-quinn`. This violates the stage 18 rule.

## 1. Sub-stages, executors, order
| Sub-stage | Criticality | Spec | Code | Review / acceptance | Depends on |
|---|---|---|---|---|---|
| 18a Node in `chervo-core` | КРИТИЧНЫЙ (key storage, network, untrusted input) | this file, §2 | `combine-builder` sonnet/**high**, 3-4 calls (A1-A4) | `combine-verifier` sonnet/low; conductor re-runs the key commands; `combine-security` opus/high by diff + §6 | stage 14b accepted (offers survive relink; the node must not wire the pre-14b behaviour) |
| 18p Framework verification gate | gate (decides the framework) | §3 | `combine-builder` sonnet/medium (throw-away spike outside the workspace + temporary CI job) | `combine-verifier` sonnet/low for CI output; **owner** for VM/screen-reader items; architect writes DECISION 2.x from the results (short, opus/high) | none (parallel with 18a) |
| 18b GUI crate | обычный, targeted security review | §4 | `combine-builder` sonnet/medium, 3-4 calls | verifier sonnet/low; `combine-security` opus/high on the §4.4 list only; owner runs the manual checklist §4.6 | 18a accepted, 18p PASS, owner answers Q1-Q4 |
| 18c CLI commands | обычный | §5 | `combine-builder` sonnet/medium, 1 call | verifier sonnet/low | 18a accepted (parallel with 18b) |

Limits per `pipeline.md`: at most 2 review-fix rounds per sub-stage, then report to the owner. No nested sub-agent calls. Report lengths: builder/verifier 25 lines, security 40.

---

## 2. SPEC 18a: node in `chervo-core`          criticality: КРИТИЧНЫЙ

Goal: one non-generic, thread-safe `chervo_core::Node` runs a complete node (OS key store, anchored friend list, quinn transport, engine, transfers, safe receive, UPnP only on user approval, clock correction only on button). GUI and CLI use only this API. No user-visible behaviour is invented here; every rule comes from an earlier stage.

Read: this file; `crates/chervo-core/src/{lib.rs,harden.rs}`, `crates/chervo-core/tests/*.rs`; `crates/chervo-transfer/examples/node16.rs`; `crates/chervo-receive/examples/node15.rs`; `crates/chervo-connect/src/{engine.rs:95-160,1069-1215, invite.rs:790-825, addrinfo.rs, gateway.rs:205-240, texts.rs, clock.rs}`; `crates/chervo-friends/src/{book.rs:196-360,480-500,650-960, error.rs}`; `crates/chervo-transfer/src/{api.rs, events.rs, policy.rs:35-60}`; `crates/chervo-receive/src/{lib.rs, root.rs, policy.rs, place.rs:240-270, accept.rs, trust.rs, texts.rs}`; `crates/chervo-identity/src/{os.rs, os_linux.rs:30-70, store.rs}`; `crates/chervo-upnp/src/mapper.rs:30-110,250-340`; `crates/chervo-timesync/src/lib.rs:50-130,300-320`; `docs/SECURITY_REVIEW.md` §8; `docs/THREAT_MODEL.md` T4, T5, T10, T11, T15, T16. Search nothing else, except the greps named below.

### 2.1 Do (one builder call per step; verify each step before the next, CORE 5)
- **A1. Profile, settings, lock, store.**
  1. Data dir. Without `NodeConfig::data_dir` it is computed by own code from env vars, with no new crate. Windows: `%LOCALAPPDATA%\Chervotochina`. macOS: `$HOME/Library/Application Support/Chervotochina`. Linux: `$XDG_DATA_HOME/chervotochina`, else `$HOME/.local/share/chervotochina`. A non-absolute value → `NodeError::DataDir`. Create the dir with mode 0700 on unix.
  2. Single instance: `std::fs::File::try_lock()` on `<data_dir>/instance.lock`. Keep the handle until `Node` is dropped. Lock taken → `NodeError::AlreadyRunning`. Before writing, check that `File::try_lock` is stable on toolchain 1.99.1 (compile it). If it is not, STOP and report. Do not add a crate. Why own code: the lock is per user (the data dir is per user) and the OS releases it on crash, so there is no stale PID file. The `single-instance` crate (2021, uses an abstract socket on Linux [S]) lets another local user hold the name and block us [V]. That crate is rejected.
  3. Settings file `<data_dir>/settings.v1`: own UTF-8 `key=value` format, one value per line. The first line is `chervo-settings 1`. Size ≤ 64 KiB, line ≤ 4 KiB, ≤ 16 receive roots, ≤ 16 UPnP routers. An unknown key, duplicate scalar, bad number, non-absolute path or over-length → `NodeError::SettingsCorrupt`. The file is never rewritten silently. Atomic write (tmp + rename + fsync), mode 0600 on unix. Contents: `port`, `receive_root`, `shared_root_confirmed`, `extra_root` (repeatable), `min_free_percent`, `invite_ttl_secs` (60..=86400, default 900, owner 2026-10-16), `manual_forward`, `upnp_router=<RouterId::to_setting>;<permanent_ok 0|1>`, `clock_offset_ms`, `clock_offset_at`, `ntp_server` (repeatable; default from `SyncConfig`). No friend names, no addresses, no keys.
  4. Key store: `OsKeyStore::open()` only. There is no file store and no mock in product code. Tests get a store through `#[doc(hidden)] pub fn open_with_store_for_tests(...)`. A new guard `crates/chervo-core/tests/test_store_guard.rs` (pattern of `anchored_only.rs`) fails if any `crates/*/src` outside `chervo-core/src/node/testing.rs` contains `open_with_store_for_tests`.
  5. `HardenReport` becomes sealed: a private field and no public `Default`, so outside `chervo-core` it can only be obtained from `harden_process()`. `Node::open` takes `&HardenReport` as proof that hardening ran first.
  6. First run = no settings file → `NodeError::FirstRun`. `Node::first_run_setup(cfg, &harden, receive_root, confirm_shared_root)` writes the settings. The port is random in 49152..=65535 and stays stable afterwards. The receive root is checked with `ReceiveRoot::open` (`OutsideProfile` → `NodeError::ReceiveRoot(RootError::OutsideProfile)` unless confirmed). Setup creates no keys. The list key appears only at the first book save caused by an explicit user action (`book.rs:399` [P]). Pair keys appear only in `create_invite` / `accept_invite`.
- **A2. Start, events, stop.**
  1. `Node::open`: lock → settings → store → `FriendBook::open_anchored(path, store, anchor)`. Map `RolledBack` → `NodeError::RolledBack`, `ListKeyMissing` → `NodeError::KeysLost`, `KeyStorageUnavailable`/locked → `NodeError::KeyStoreLocked` (one variant for "locked" and "unavailable", stage 11 H1). Then `QuinnTransport::bind(0.0.0.0:port)`; `AddrInUse` → `NodeError::PortInUse`. Then `SystemClock` with the stored offset applied, `Engine::start`, UPnP mapper attached **only if** the settings list ≥ 1 approved router, `stream_inbox`, `Transfers::start` with `ReceivePolicy` + `ReceivePlacement` as in node15. Finally `add_known_root` for `receive_root` and every `extra_root` (SECURITY_REVIEW §8).
  2. Explicit recovery entry points. Each is called only after the user has chosen it on screen: `Node::open_accept_older` (wraps `FriendBook::accept_older`), `Node::open_start_over` (wraps `start_over_anchored`; the old file is kept as `.unreadable-<t>`), `Node::reset_settings` (keeps a copy as `settings.v1.bad-<t>`), `Node::request_unlock` (Linux: `OsKeyStore::request_unlock`; other OS → `NodeError::Unsupported`).
  3. Runtime: one background thread with a tokio `current_thread` runtime. Node16 was measured on `current_thread` at ~157-160 MiB/s on the stand (TASK 16) [P], so no multi-thread runtime is needed. All public methods are synchronous and may block, for example up to ~12 s on Secret Service (SECURITY_REVIEW 17a (в)) [P]. They enter the runtime handle where the lower crate spawns. They never run on the caller's UI thread by design: the docs say "do not call from a UI thread", and 18b enforces this.
  4. Events: a pump task merges `EngineEvents` and `TransferEvents` into `NodeEvent` and sends them on a bounded `std::sync::mpsc::sync_channel(1024)` with `try_send`. When the channel is full the event is dropped and `NodeEvent::Lagged` is sent once, so the consumer re-reads the snapshots. After each send the pump calls the optional waker (`Box<dyn Fn() + Send + Sync>`; the GUI uses it to request a repaint).
  5. `Node::shutdown(self, deadline)`: `transfers.shutdown()` + `wait_stopped`, `engine.shutdown()`, `transport.shutdown()`, then `UpnpMapper::release()` with an 8 s timeout as in node16 `:867-878` [P]. Then the settings are flushed and the lock is released. `Drop` without `shutdown` does the same with the same bounds and never panics.
- **A3. Friends and tokens.** `create_invite(same_network, manual_addr)` (TTL from the settings), `accept_invite(text)`, `confirm_sas(invite, yes, name)`, `cancel_invite`, `rename`, `block`/`unblock`, `remove` → `Option<RevocationText>`, `rekey(friend)` → `RevocationText`, `rekey_all` → `Vec<(FriendRef, Result<RevocationText, NodeError>)>`, `retired()`, `forget_retired`, `apply_revocation_text`, `issue_addr_update_text(friend, same_network)`, `apply_addr_update_text`, `connect_now(friend)`. Every book mutation goes through `Engine::update_book`. Its doc says that publishes peers and drops live connections of non-Active pairs (`engine.rs:1146-1154`) [P]. **Anchor L3:** add `FriendsError::SavedAnchorStale`, returned only in the case of `book.rs:480-500` where the file was saved and the anchor write failed (S1 L3) [P: review text]. The engine passes it through. The node reports `Ok` plus `NodeEvent::Warning(AnchorNotUpdated)`. If that code path differs from the review text, STOP and report. `StaleInstance` → `NodeError::StaleInstance` ("restart the program").
- **A4. Transfers, receive, network, clock.**
  1. `send(friend, paths)`. Folders are expanded by own code: no symlink following (`symlink_metadata`), names relative with `/`, depth ≤ `ReceiveLimits::default()` depth, ≤ `MAX_FILES_PER_OFFER` (10 000, `chervo-transfer/src/limits.rs:11`) [P]. A non-UTF-8 name → `NodeError::BadName(count)`.
  2. `offer(transfer)` → `IncomingOffer` built from `plan_offer_for_root` + `classify` + `ReceivePolicy::space_check` (`policy.rs:93`) [P]. **Only planned (sanitized) names reach the API.** `UntrustedName` never leaves the core; the sanitizer already strips bidi, zero-width and BOM (`chervo-receive/src/name.rs:99-104`) [P]. Per file: display name, size, `FileKind` (safe / executable-like / unknown, as stage 15 classifies), `needs_question`. Per offer: friend, total, `SpaceView { needed, available, short }`.
  3. `accept(transfer)`, `accept_into(transfer, root)` (via `chervo_receive::accept_into`, then `add_known_root` and persist as `extra_root`), `decline`, `cancel`, `retry` (Stalled), `transfers()` snapshots.
  4. `enable_auto_accept(friend, TrustConfirmation)` / `disable_auto_accept`. `TrustConfirmation` is re-exported, and its doc names the exact question text the caller must have shown (owner 2026-10-18).
  5. `set_receive_root`, `set_min_free_percent`, `set_port` (takes effect at restart), `set_manual_forward`.
  6. `diagnose(friend)` → `Option<DiagnosisView { reason, text: &'static str (chervo_connect::user_text), rendezvous_could_help }>`, `nat_view()`, `mapping_status()`, `refresh_mapping()`.
  7. `upnp_identify()`, called only on a button. It passes the node's own IPv4 of the default route. Use the accessor the engine already has; if none is public, STOP and report (do not add a probe). It returns `RouterCandidate` (opaque `RouterId`). `upnp_allow(router, permanent_ok)` persists the router and attaches the mapper if it is not attached yet. `upnp_forget(router)`.
  8. `sync_clock()`, on a button only (owner 2026-10-16: no automatic NTP). It calls `chervo_timesync::sync_clock` on a blocking thread. If |offset| ≤ 5 min it is applied (`SystemClock::set_offset_ms`) and persisted. If larger it returns `ClockProposal` and applies nothing until `confirm_clock(proposal)` (SECURITY_REVIEW §8). `reset_clock()` sets 0 and persists.
  9. Tests: §2.4.

### 2.2 Interface (exact names; the builder may add private items only)
```rust
// chervo-core/src/lib.rs re-exports node::*; old Node<T>, CoreError::NotImplemented, tests/node.rs are removed.
pub struct NodeConfig { pub data_dir: Option<PathBuf>, pub receive_limits: ReceiveLimits, pub port_override: Option<u16> } // Debug hides paths (as today)
pub struct Node;            // !Clone, Send + Sync; all methods &self unless noted
pub struct NodeEvents;      // recv_timeout(Duration) -> Result<NodeEvent, RecvTimeoutError>; try_recv()
pub struct FriendRef(PairId);   // Copy, Eq, Hash; Debug = "FriendRef(..)"; no public accessor to PairId
pub struct TransferRef(TransferKey); // same rules
pub struct InviteRef(PairId);   // same rules
pub struct SasView;          // digits() -> String "1234 5678"; spoken() -> "1 2 3 4 5 6 7 8"; Debug redacted
pub struct RevocationText(String);  // as_str(); Debug redacted
pub struct AddrToken(String);       // as_str(); Debug redacted; carries the flag `reveals_ip: true`
impl Node {
  pub fn first_run_setup(cfg: &NodeConfig, h: &HardenReport, root: &Path, confirm_shared: bool) -> Result<(), NodeError>;
  pub fn open(cfg: NodeConfig, h: &HardenReport) -> Result<(Node, NodeEvents), NodeError>;
  pub fn open_accept_older(cfg: NodeConfig, h: &HardenReport) -> Result<(Node, NodeEvents), NodeError>;
  pub fn open_start_over(cfg: NodeConfig, h: &HardenReport) -> Result<(Node, NodeEvents), NodeError>;
  pub fn reset_settings(cfg: &NodeConfig, h: &HardenReport) -> Result<(), NodeError>;
  pub fn request_unlock(cfg: &NodeConfig, wait: Duration) -> Result<(), NodeError>;
  pub fn set_waker(&self, w: Box<dyn Fn() + Send + Sync>);
  pub fn shutdown(self, deadline: Duration);
  // friends / invites / tokens: §2.1 A3; transfers / receive / network / clock: §2.1 A4
  pub fn friends(&self) -> Vec<FriendView>;      // name, state, online, auto_accept, key_problem, last_path
  pub fn transfers(&self) -> Vec<TransferView>;  // side, state, done, total, pause reason, friend
  pub fn settings(&self) -> SettingsView;        // port, roots, min_free, ttl, routers, clock offset, key store kind
}
#[non_exhaustive] pub enum NodeEvent {
  FriendOnline { friend: FriendRef, path: PathKind }, FriendOffline { friend: FriendRef },
  InviteSas { invite: InviteRef, sas: SasView }, InviteFinished { invite: InviteRef, outcome: InviteOutcome },
  FriendKeyProblem { friend: FriendRef }, ClockSkewSuspected { friend: FriendRef },
  Unreachable { friend: FriendRef, diagnosis: DiagnosisView },
  OwnAddressChanged, MappingChanged { status: MapStatus },
  OfferIncoming { transfer: TransferRef }, OfferAutoAccepted { transfer: TransferRef },
  TransferChanged { transfer: TransferRef }, TransferFinished { transfer: TransferRef, result: TransferResult },
  Warning(NodeWarning), Internal, Lagged, Stopped,
} // Debug: variant name only
#[non_exhaustive] pub enum NodeError { FirstRun, AlreadyRunning, DataDir, SettingsCorrupt, KeyStoreLocked, KeysLost,
  RolledBack, StaleInstance, PortInUse, ReceiveRoot(RootError), BadName(usize), InputTooLong, Friends(FriendsError),
  Connect(ConnectError), Transfer(TransferError), Upnp(UpnpError), Clock(SyncError), Unsupported, Shutdown, Io }
// Display: fixed text, no paths, names, addresses or keys. Each variant has a Russian user text in node/texts.rs.
```

### 2.3 Invariants
1. No key is created without an explicit user action: pair keys only in `create_invite`/`accept_invite`, the list key only at the first save caused by such an action. `first_run_setup`, `open*`, `diagnose`, `sync_clock` and snapshots create none (test).
2. The book is opened only anchored (`anchored_only.rs` covers `chervo-core/src` and later `chervo-gui/src` automatically) [P: it walks `crates/*/src`].
3. Network only from user choices: no UPnP packet unless the router list is non-empty. `upnp_identify` and `connect_now` are never called by the node itself, except `connect_now` right after a user-pasted address token or invite, as node16 does. NTP only from `sync_clock`. No DNS except NTP names on that button.
4. No logging, no printing in `chervo-core/src` (`no_logger.rs`) [P]. Event, error and view `Debug` never contain SAS, tokens, names, paths, addresses or keys (extend `chervo-core/tests/redaction.rs`).
5. Untrusted text input (invite, address token, revocation text pasted from a messenger): trimmed; > 4096 bytes → `InputTooLong` before decoding. It goes only to the existing decoders, which are fuzzed [P: TASK 11, 16, 17]. Errors never echo the input.
6. Offer views contain only sanitized planned names (invariant tested by a hostile-name table: bidi U+202E, zero-width, `..`, `CON`, NUL-free over-long).
7. Shutdown always tries `release()` of a live mapping with a bound of 8 s. It never hangs longer than `deadline` + 8 s.
8. One process per data dir (lock). This also stops GUI and CLI from running on one profile at the same time.

### 2.4 Acceptance criteria (each by command; Windows dev box unless noted; CI = 3 OS)
- [ ] `cargo build --workspace --locked`
- [ ] `cargo test -p chervo-core --locked`: passes `layout` (new exact-name rule), `anchored_only`, `no_logger` (all 4), `redaction`, `harden`, `test_store_guard`, `settings_hostile_table` (≥ 25 rows: BOM, CRLF, duplicate scalar, unknown key, 64 KiB + 1, relative path, `port=0`, `port=70000`, 17 roots, NUL, non-UTF-8 bytes), `settings_roundtrip`, `instance_lock_second_open_refused`, `first_run_creates_no_keys` (store write counter = 0), `open_maps_rolled_back`, `open_maps_list_key_missing_to_keys_lost`, `accept_older_only_explicit`, `token_input_caps` (4097 bytes → `InputTooLong`, decoder not called), `offer_view_only_sanitized_names`, `clock_over_5_min_needs_confirm`, `clock_reset`, `events_debug_redacted`, `harden_report_sealed` (compile-fail doc test).
- [ ] `cargo test -p chervo-core --test node_net --locked -- --test-threads=1`: two nodes over loopback with the test store: invite (manual addr 127.0.0.1), SAS on both, confirm, `FriendOnline` both; send a folder (3 files, 1 nested, one `.exe`); offer shows the executable as `needs_question`; accept; SHA-256 equal; decline path; `rekey` → friend applies the revocation text → `RevokedByPeer`; block drops the live connection; `shutdown` within deadline. **20/20 runs**: `for i in $(seq 20); do cargo test -p chervo-core --test node_net --locked -q -- --test-threads=1 || break; done`.
- [ ] `cargo test -p chervo-core --test fuzz_smoke --release --locked` (settings parser, 1M iterations, no panic, parse∘write idempotent). Add a libFuzzer target `settings` to `fuzz/`. It runs 20 min on the owner's Linux machine before stage 19 (does not block 18a).
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --check`; `bash scripts/check-forbidden.sh`.
- [ ] `cargo deny check` and `cargo audit`: no new findings (no new external crates in 18a).
- [ ] CI green on 3 OS.
- [ ] Manual (owner; closes when 18c exists, does not block 18a code acceptance): the `os_*` tests are unchanged and still pass; one real `Node::open` with the OS store through the CLI: `chervo init`, then `chervo run`, invite to a second machine, file sent, `Ctrl+C` → the mapping is released (UPnP counters on the router, or the miniupnpd stand `stage13a.sh` RELEASE re-run against the node).

Do not: change wire formats, `chervo-connect` behaviour, the transfer protocol or the sanitizer. Add no external crate. Implement no mediator, local keys, mDNS or in-band revocation delivery. Do not auto-retry `connect_now`. Do not add a logger.
Untrusted input: tokens, offers (names via the core only), the local settings file (same user, strict parser), env vars for the data dir (absolute only).
Stop conditions: `File::try_lock` not available on 1.99.1; no public own-IPv4 accessor for `identify`; the L3 code path differs from the review; `ReceivePolicy` cannot give the decision for the offer view without API change; any need for a new crate. Then stop and report, do not work around.
Report (≤ 25 lines): changed files; commands and last lines of output; what was not done; deviations.

---

## 3. 18p: framework verification gate (before the builder commits to a framework)

Candidate after desk review: **eframe/egui 0.37.0** [S]. Reasons against the constraints:
| Constraint | eframe/egui | iced 0.14 | slint 1.18 | tauri 2 / dioxus 0.7 | gtk4-rs |
|---|---|---|---|---|---|
| Nothing to install (Win/macOS/Linux) | likely: pure Rust, system libs loaded at run time [V, check V3] | likely | likely | **no**: WebView2 on Windows, webkit2gtk on Linux [S] | **no**: GTK4 runtime on Win/macOS [S] |
| Licenses in `deny.toml` allow list | MIT OR Apache-2.0 [S]; bundled fonts unknown [NP, V1] | MIT [S] | **no**: GPL-3.0 or Royalty-free 2.0 with attribution duty [S] | — | — |
| Accessibility | AccessKit by default [S] | **none** [S] | AccessKit [S] | — | native |
| Software / GL fallback | wgpu: DX12 (WARP), Metal, Vulkan + GL; glow as option [V, check V4] | wgpu + tiny-skia CPU [S] | software renderer [S] | — | — |
| Activity | release 2026-10-15, commit 2026-10-21 [S] | last release 2025-12 [S] | active | — | — |
Conclusion: egui is the only candidate that meets all constraints on paper. iced is the fallback only if the owner does not need accessibility (Q1). Desk facts are not proof. The gate below must PASS first.

Do: a throw-away crate `spikes/gui-probe/` (not a workspace member, own `Cargo.lock`, like `spikes/transport`). eframe with `default-features = false` plus the features under test. Its window has: a Cyrillic label, a text field, a button, an 8-digit SAS in large monospace, a QR from a fixed 300-char string, a file-open button, a folder-open button, and drag-and-drop of a file. It displays the wgpu adapter name in the window only. It has `--render-check` (render 3 frames, exit 0) and no printing. Plus a temporary CI workflow `gui-probe.yml` on the 3 OS runners with toolchain 1.99.1. Each item gets PASS / FAIL with actual output:
- **V1 build + licenses + bans:** `cargo +1.99.1 build --release --locked` on 3 OS **without any apt install** on Linux; `cargo deny --manifest-path spikes/gui-probe/Cargo.toml check` with the project `deny.toml` (copy). Expected risks to report explicitly: the font licenses of `epaint_default_fonts` (OFL-1.1 / UFL-1.0?) [NP]; `accesskit_unix` and the `rfd` portal backend (`ashpd`) pulling zbus 5 / zvariant, which is banned (`deny.toml:12-19`) [NP]; advisories such as unmaintained crates in the wgpu/metal tree [NP].
- **V2 no telemetry / network code:** `cargo tree -e normal --target all` contains none of `reqwest hyper ureq curl h2 isahc surf sentry opentelemetry tokio`. Linux VM: the probe runs 60 s, and `ss -uptn` / tcpdump on all interfaces shows 0 packets and 0 sockets from the process. Windows: `Get-NetUDPEndpoint`/`Get-NetTCPConnection -OwningProcess <pid>` is empty.
- **V3 runtime libs:** Linux `readelf -d target/release/gui-probe | grep NEEDED` lists only glibc-family libs (libc, libm, libgcc_s, libdl, libpthread, ld-linux); X11/Wayland/EGL/Vulkan are dlopen'ed [V]. Windows: `dumpbin /dependents` (or `objdump -p`) shows no `VCRUNTIME140.dll`. If it is present, set `-C target-feature=+crt-static` for `x86_64-pc-windows-msvc` in `.cargo/config.toml` and re-check. Rust MSVC binaries link the VC runtime dynamically by default, and a clean Windows may lack it [V]. macOS: `otool -L` shows only `/System/Library` and `/usr/lib`. Run on a **fresh** Ubuntu 24.04 desktop VM and a fresh Windows 11 VM with nothing installed.
- **V4 GPU fallback:** start and render in (a) a Windows VM without a GPU driver (Basic Display / Hyper-V video), (b) a Linux VM on Mesa llvmpipe, (c) X11 and Wayland sessions, (d) an old GPU if the owner has one. Record the adapter. If (a) or (b) fails with wgpu, enable the eframe glow renderer as a second attempt (`run_native` with `Renderer::Wgpu`, on error `Renderer::Glow`) and re-test. If still failing: FAIL.
- **V5 Cyrillic and IME:** typing Russian with layout switching on 3 OS; `Ctrl+C/V/X/A` while the Russian layout is active (logical vs physical keys) [NP]; Cyrillic glyphs in the fonts; one IME (Windows Japanese or Chinese) composition commits text. Clipboard round trip with a 300-char token. Windows: can the copy be excluded from clipboard history (arboard `exclude_from_history` or equivalent) [NP]?
- **V6 accessibility:** Windows Narrator and macOS VoiceOver read the button labels and the SAS (with an `accesskit` label "1 2 3 4 5 6 7 8"). Tab/Shift+Tab/Enter/Space reach every control. Linux Orca only if V1 shows the Linux adapter is allowed.
- **V7 file selection:** Windows/macOS `rfd` native dialogs (check its deps in V1). Linux: if the `rfd` portal backend passes V1, use it. Otherwise use an in-app picker (crate `egui-file-dialog` if it passes V1 [NP], else own simple directory browser in 18b). Drag-and-drop on X11 / Wayland: record what works [NP].
- **V8 QR crate:** `qrcode` 0.14.1 (MIT OR Apache-2.0) and `fast_qr` 0.14.0 (MIT) [S], both `default-features = false`. Pick the one with zero normal transitive dependencies and no `build.rs`; on a tie, `qrcode` (dual licence, simpler encoder). Encode only; nothing is ever decoded.
- **V9 size/start:** release binary size and cold start time per OS. Recorded, no claims.
Gate rule: V1-V4 and V7 must PASS (V1 may pass with owner-approved exceptions, Q4). V5/V6 failures are reported to the owner with what fails. If egui fails V1-V4 in a way features cannot fix, stop and report. The architect then writes the alternatives (iced without accessibility, or a narrower platform set) as an owner question. Result: `docs/reports/GUI-PROBE-<date>.md` (verifier + owner items) and a short DECISION 2.x entry (architect): version, licence, features, renderer, no telemetry (V2 output), exceptions.

---

## 4. SPEC 18b: GUI crate          criticality: обычный (targeted security review)

Goal: `crates/chervo-gui` (binary `chervotochina`) is a desktop app on Windows, macOS and Linux over `chervo_core::Node` only. It covers the TASK 18 screens and the SECURITY_REVIEW §8 items.
Read: this file §2.2-2.3 and §4; `docs/reports/GUI-PROBE-<date>.md`; DECISION 2.x (framework); `crates/chervo-core/src/node/` (API from 18a); `crates/chervo-connect/src/texts.rs`; `crates/chervo-receive/src/texts.rs`; `crates/chervo-cli/tests/hardens_first.rs`.

### 4.1 Structure
`src/main.rs`: first statement `let _hardening = chervo_core::harden_process();`, the guard is copied as `tests/hardens_first.rs`; `#![windows_subsystem = "windows"]`. Plus `app.rs` (eframe App), `model.rs` (pure state machine of screens and dialogs, unit-tested without a window), `worker.rs` (one thread owning `Node`, executes `Command`s in order, posts `Outcome`s and `NodeEvent`s to the model, wakes the UI), `texts.rs` (every user string, Russian, one table so another language can be added), `screens/*.rs`, `qr.rs`, `picker.rs` (per V7). **The UI thread never calls `Node`** (methods may block, §2.1 A2.3). The guard `tests/ui_thread.rs` fails if `screens/` or `app.rs` contain `node.` or `Node::`. Persistence features of eframe are off: no app state file and no window-position file. The window title is the constant "Червоточина", never a friend or file name.

### 4.2 Screens (TASK 18 line plus SECURITY_REVIEW §8)
1. **Start / errors:** first run (receive folder; `OutsideProfile` warning with the explicit checkbox "других пользователей на этом ПК нет"; short text "ключи хранятся в хранилище ОС"); `AlreadyRunning` ("программа уже запущена", exit); `KeyStoreLocked` (one text for locked and unavailable; Linux: button "Разблокировать" → `request_unlock`, then retry; no automatic dialog, owner 17a Q2); Linux without Secret Service (text: install gnome-keyring/KWallet; the program installs nothing, owner 2026-10-09); `KeysLost` (text + explicit "Начать заново" → `open_start_over`, friends must be re-added); `RolledBack` (plain text + explicit "Принять старый список" → `open_accept_older`); `SettingsCorrupt` (reset with copy kept); `PortInUse` (change port).
2. **Friends:** list with name, state (active, blocked, revoked by friend, key lost/changed → "добавьте друга заново", retired), online and path. Actions: send, "Соединить" (`connect_now`, button only), diagnosis, rename, block/unblock, remove (shows the revocation text with copy and "send it to your friend"), "Пересоздать ключ" for one or all (text + then "create a new invitation for this friend"), auto-accept on/off (only after the exact trust question, owner 2026-10-18), address token "отправить свой адрес" (warning: the token contains your IP, whoever sees it learns it) and "вставить токен друга".
3. **Add friend:** tabs "Пригласить" (TTL from the settings, checkbox "мы в одной сети" → LAN addresses, owner 2026-10-16 Q3; optional manual address for a forwarded port; token text with Copy, QR per V8; IP warning; waiting state; cancel) and "Принять приглашение" (paste field capped at 4096 chars). **SAS screen on both sides:** 8 digits large, grouped 4+4, accessible label read digit by digit, buttons "Совпадает" / "Не совпадает", name field. Outcome texts include `PEER_UNREACHABLE_INVITE_TEXT`.
4. **Send:** choose files/folders (picker, drag-and-drop where V7 says it works), choose a friend, summary (count, total), progress of "Preparing" (hashing) and transfer.
5. **Incoming offer:** friend name, count, total size, list of the **planned** names with kind. Warning for executable-like/unknown kinds with the stage 15 question text. Space check (needed / available; on shortage the warning plus "Выбрать другую папку" → `accept_into`). Accept / decline. Auto-accepted offers appear as a notice. The window requests user attention (taskbar flash) and nothing more: no OS notification crate.
6. **Transfers:** progress, pause reason, "Повторить" for Stalled (`retry`), cancel, done/failed. The final location is shown as text with Copy. Nothing is opened or executed.
7. **Diagnosis:** per friend `DiagnosisView.text`; NAT view summary; CGNAT/double NAT/symmetric/UDP-blocked/need-token/no-IPv6 texts from `chervo_connect::texts` [P]. **Mediator: not in this version.** When `rendezvous_could_help`, show "Сервер-посредник мог бы помочь; он появится в следующей версии". There is no consent button, no server field and no code path to any server. `CGNAT_TEXT` already says this [P: texts.rs:7]. "Соединить" button.
8. **Settings:** receive folder(s) (with `OutsideProfile` flow), min free space %, port (restart) and manual port forward. UPnP: "Найти роутер" → `upnp_identify` (button only), then "Открывать порт на этом роутере?" yes/no, and the permanent-lease question if needed; the list of approved routers with forget. Clock: "Сверить часы" (button only), list of NTP servers, current offset; a proposal > 5 min needs confirmation; "Сбросить поправку". Keys: store kind (Credential Manager / Keychain / Secret Service); "Режим «локальные ключи» в этой версии недоступен" (no toggle, see §7); "Пересоздать все ключи"; retired revocation texts (copy, forget). About: version and the third-party licence list (generation of the list is stage 19; 18b shows a placeholder screen).
9. **Notices from events:** `ClockSkewSuspected` hint (offer "Сверить часы"); `FriendKeyProblem`; `Internal` ("не удалось обновить список разрешённых друзей", SECURITY_REVIEW §8); `Warning(AnchorNotUpdated)` as "сохранено; счётчик защиты от отката не обновлён, перезапустите программу" (not "не удалось", S1 L3); `MappingChanged` status text (`chervo_upnp::status_text` via core re-export); a LAN friend whose private address expired (24 h, owner 16a Q1) → hint "отправьте токен адреса с отметкой «мы в одной сети»".
10. **Close:** with active transfers, ask "передачи приостановятся и продолжатся при следующем запуске". Then `Node::shutdown(10 s)` with a "closing" state, after which the window closes. No tray, no autostart (Q6).

### 4.3 Dependencies (exact list; the manifest test enforces it)
`chervo-core` (path) and the framework crates fixed by DECISION 2.x (eframe; plus `rfd` and/or a picker crate per V7; one QR crate per V8; arboard only if V5 says it is needed for the history flag). Nothing else. Pins `=x.y.z`, `default-features = false`. Any extra crate means: stop and ask.

### 4.4 Security items (review list for `combine-security`)
harden first; anchored only (the existing guard covers `chervo-gui/src`); no UI-thread Node calls; only planned names displayed; `connect_now`, `upnp_identify`, `sync_clock` reachable only from button handlers; 4096-char paste cap; IP warning on invite and address tokens; executable/unknown question; space check shown; `OutsideProfile` confirmation; clock > 5 min confirmation; `release()` at exit (via `shutdown`); no logger, no print (existing guards); no network crate in the tree; no files written by the GUI itself (grep `std::fs::write|File::create` in `chervo-gui/src` = 0); clipboard history exclusion per V5.

### 4.5 Acceptance criteria
- [ ] `cargo build --workspace --locked` on 3 OS (CI), Linux without extra apt packages.
- [ ] `cargo test -p chervo-gui --locked`: passes `hardens_first`, `manifest_only_core` (the `[dependencies]` path deps = {chervo-core}; external = exactly the §4.3 list; no `[build-dependencies]`, no `build.rs`), `uses_node_api_only` (no `chervo_core::chervo_` in `src/`), `ui_thread`, `no_fs_writes`, model tests: `offer_with_executable_requires_choice`, `sas_requires_explicit_answer`, `rolled_back_needs_explicit_accept`, `keys_lost_needs_explicit_start_over`, `clock_proposal_over_5_min_needs_confirm`, `outside_profile_needs_checkbox`, `paste_over_4096_rejected`, `close_with_transfers_asks`.
- [ ] `cargo test -p chervo-core --locked` (guards `anchored_only`, `no_logger`, `layout` with `chervo-gui` added to the members list) green.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo fmt --check`, `bash scripts/check-forbidden.sh`, `cargo deny check`, `cargo audit`: clean, or each exception approved by the owner (Q4) and written with rationale.
- [ ] `chervotochina --render-check` exits 0 on the windows/macos runners and on ubuntu under `xvfb-run` with Mesa (apt only in CI, not for users). If a runner cannot create a window, record the failure as "CI cannot test this"; the item then falls to the manual checklist.
- [ ] V2/V3 repeated on the real binary (tree check, `readelf`/`dumpbin`/`otool`), output in the report.
- [ ] Manual checklist §4.6 passed by the owner and the results attached as `docs/reports/GUI-MANUAL-<date>.md`.

### 4.6 Manual checklist (owner; two machines, at least Windows + one other OS; a fresh VM for "clean system")
1. Fresh VM, copy only the binary: it starts with nothing installed (Windows 11; Ubuntu 24.04 desktop; macOS: Gatekeeper warning accepted, U18). macOS: note any Keychain "allow access" prompts after replacing the binary [NP; unsigned builds].
2. First run: folder outside the profile → warning + checkbox; inside → none.
3. A invites B (token by messenger; QR shown), B pastes, both see the **same** 8 digits; "Не совпадает" on one side → no friend on either side; repeat with "Совпадает" → friend on both, online.
4. Name with Cyrillic typed via layout switch; Ctrl+C/V in the Russian layout.
5. Send a folder (nested, a `.jpg`, a `.exe`, a `x.iso.gz`): B sees the planned names, the question for `.exe`/`.iso.gz`, the space line; accept; compare SHA-256 manually; decline a second offer.
6. Too little space (min free % raised): warning with numbers → "другая папка" → accepted there; restart B → the transfer into that folder still resumes.
7. Close A mid-transfer (confirm text), reopen → resumes. Start a second copy → "уже запущена".
8. Block B on A → B goes offline at once; unblock; remove → revocation text → B applies it → "друг отозвал".
9. Rekey one friend → text → re-invite with SAS works.
10. Diagnosis with UDP blocked (Windows firewall outbound UDP block for the app) → UDP text; with B off → unknown text; no mediator button anywhere.
11. UPnP: "Найти роутер" on the home router → approve → mapping status OK; exit → mapping gone in the router UI.
12. Clock: shift the system clock by +10 min → "Сверить часы" → confirmation shown; reset.
13. Narrator (Windows) reads the SAS digits and the accept/decline buttons; keyboard-only path through invite → SAS → accept.
14. VM without GPU: the app renders (V4).

Do not (18b): implement any backend logic, call lower crates, add a logger or tray, open received files or folders, or show raw offer names.
Stop conditions: a needed API is missing in `Node` (report; do not reach into lower crates); any extra crate; a gate item regresses on the real binary.
Report (≤ 25 lines): changed files; commands and last lines of output; what was not done; deviations.

---

## 5. SPEC 18c: CLI commands on the node          criticality: обычный
Why: (1) the owner's mini-PC has no desktop (OWNER_DECISIONS "Мини-сервер") [P], so a GUI cannot run there and the node must be usable over ssh; (2) release smoke tests (stage 19) need a scriptable node on 3 OS; (3) diagnosis when the GUI cannot render (V4).
Do: `chervo --version`; `chervo init --receive DIR [--shared-root-ok]`; `chervo unlock` (Linux); `chervo run`: a foreground interactive line REPL on stdin. Commands: `friends`, `invite [--lan] [--addr IP:PORT]`, `accept-invite` (reads one line), `sas yes|no NAME`, `send FRIEND PATH...`, `offers`, `accept N [--into DIR]`, `decline N`, `transfers`, `retry N`, `cancel N`, `diag FRIEND`, `connect FRIEND`, `token-for FRIEND [--lan]`, `apply-token` (one line), `revoke-text`, `apply-revocation` (one line), `rekey FRIEND`, `block|unblock|remove FRIEND`, `upnp find|allow|forget`, `clock sync|confirm|reset`, `quit`. Friends are referred to by local name or list index. Output goes to the user's terminal and may show friend names and planned file names (it is the UI). It never shows addresses, except the user's own token text when asked. On `Ctrl+C` / stdin EOF it calls `shutdown`. The guard `no_print_in_product_src_except_cli_stub` is widened from `chervo-cli/src/main.rs` to `chervo-cli/src/` (edit `no_logger.rs:320-338`; this is a guard change, note it in the report). `hardens_first` stays.
Acceptance: `cargo test -p chervo-cli --locked` incl. `repl_two_nodes_scripted` (two processes, loopback, scripted stdin: invite, SAS, send, accept, SHA-256 equal); `hardens_first`; clippy/fmt; CI 3 OS.
Do not: daemon mode, sockets for remote control, config flags that bypass the OS store, logging.
Report (≤ 25 lines): as above.

---

## 6. Threat model deltas (to THREAT_MODEL ред. 8, written by the architect after the 18a/18b reviews)
- **New T18 "Local application state and UI"** (same-user scope like T10):
  - (a) The settings file is plaintext. A same-user process can change the receive root, the approved routers or the port. Mitigation: strict parser, nothing secret in it. Residual: accepted, as T4 journals.
  - (b) Instance lock: a same-user process can hold it and keep the app from starting (DoS, T10 scope). Another local user cannot (per-user dir).
  - (c) Clipboard: invite and address tokens copied to the clipboard are readable by same-user apps and may go to OS clipboard history or cloud sync. Mitigation: history exclusion where V5 shows it works, plus the IP warning. Residual otherwise.
  - (d) Accessibility tree: SAS digits and planned names are exposed to AT clients of the same user (T10).
  - (e) Display spoofing of file names: mitigated by showing only sanitized planned names, from which the sanitizer has stripped bidi and zero-width characters [P], and by the kind-based question, which does not depend on display.
  - (f) GPU drivers / font rasterizer process untrusted text: only glyph lookup with our own fonts; no untrusted fonts or images are rendered [V].
- **T5:** the product path is `open_anchored` only; `accept_older` and `start_over` only on explicit user choice; `SavedAnchorStale` → warning, not failure (closes S1 L3 on the UI side).
- **T7:** still not implemented; the GUI shows no consent control and no server setting (§4.2 item 7).
- **T11:** still not implemented; the GUI states the mode is unavailable (§7).
- **T15:** confirmation for clock offsets > 5 min and a reset button are implemented in 18a/18b.
- **T16:** `identify()` only on a button; `release()` at exit with an 8 s bound.
- **T10 (macOS):** unsigned rebuilt binaries may trigger Keychain access prompts; users learn to click "allow" [V, NP]. Recorded; signing is U18/stage 19.
- Stage 17 must be repeated for the new surface (settings parser, node wiring) before stage 19. 18a's security review counts as that repeat if it covers §2.3.
- Notes for stage 19 found here [V]: Windows static CRT (V3); Linux glibc floor (building on ubuntu-latest = glibc 2.39 excludes older distros); third-party licence notices in About and in the release.

## 7. Features without a backend: what the GUI shows now
- **Mediator (13b):** no consent dialog. The diagnosis text says it will come in the next version. No address or server field. This deviates from TASK 18 "согласие на посредника"; the consent UI ships with 13b.
- **Local keys (U10c, T11):** not offered. A settings line says it is unavailable. This follows SECURITY_REVIEW §8 and T11 (both say "не предлагать") over the older TASK 18 wording "включение режима «локальные ключи»". The deviation is recorded here.
- **LAN discovery (13v) and IPv6 receive:** absent. The invite checkbox "мы в одной сети" and the 24 h hint cover LAN. `NO_IPV6_TEXT` is used for IPv6.
- **In-band revocation delivery:** absent (Q5). The revocation text is shown for manual sending, and the friend pastes it.

## 8. Decisions taken here (conductor may override; not owner questions)
D1 node in core (§0). D2 single instance = own `File::try_lock` in the data dir (§2.1 A1.2). D3 settings = own strict text format, no serde (§2.1 A1.3). D4 `current_thread` runtime on one background thread (§2.1 A2.3). D5 random stable port at first run (§2.1 A1.6). D6 QR display only, crate per V8. D7 no tray, no OS notifications, no autostart (pending Q6). D8 CLI REPL, not a daemon (§5).

---

## Вопросы владельцу
Решения только за вами. По каждому — мой рекомендуемый вариант и почему.

**Q1. Фреймворк GUI и уровень доступности.**
- (а) **egui (рекомендую):** ничего не нужно доустанавливать, лицензия MIT/Apache, есть поддержка экранного диктора (AccessKit). Окончательно — только после проверки 18p.
- (б) iced: тоже без доустановки, но доступности нет совсем.

Какой уровень доступности нужен в релизе 1?
- (1) **Клавиатура плюс диктор, проверено на Windows (Narrator), на macOS по возможности (рекомендую).**
- (2) Только клавиатура.
- (3) Не требуется.

Если (2) или (3), годится и iced.

**Q2. Язык интерфейса.**
- (а) **Только русский в релизе 1, все тексты в одной таблице, английский можно добавить позже (рекомендую).** Тексты ядра уже на русском.
- (б) Русский и английский сразу: больше работы и проверки.

**Q3. Вид проверочного кода (SAS) в релизе 1.**
- (а) **8 цифр группами 4+4 (рекомендую):** одинаково на всех ОС, диктор читает цифры, их легко сверить голосом по телефону.
- (б) Эмодзи или буквы: позже, после проверки отображения на трёх ОС (ваше решение от 2026-10-16).

**Q4. Лицензии сверх списка.** Проверка 18p может показать, что встроенные шрифты egui (нужны для кириллицы) идут под лицензиями OFL-1.1 или UFL-1.0. Их нет в `deny.toml`.
- **Рекомендую разрешить их точечно, только для пакета шрифтов.** Это лицензии шрифтов, они не накладывают ограничений на программу.
- Иначе придётся грузить системные шрифты, а на Linux это ненадёжно.

То же правило для предупреждений «пакет не сопровождается» в дереве wgpu: каждое исключение — с вашего «да».

**Q5. Уведомление друга при «пересоздать ключ» и удалении.**
- (а) **В релизе 1 вручную (рекомендую):** программа показывает текст отзыва, вы отправляете его другу любым способом, друг вставляет. Такой путь уже есть и проверен.
- (б) Ещё и автоматически по живому соединению. Это новый сетевой формат, отдельный критичный этап. Выигрыш только если друг в сети.

**Q6. Работа в фоне.**
- (а) **В релизе 1 программа принимает файлы, пока открыто окно (можно свернуть). Без значка в трее и без автозапуска (рекомендую).** Трей на Linux тянет GTK, а это противоречит правилу «ничего не доустанавливать».
- (б) Трей и автозапуск: отдельная проверка зависимостей.

**Q7. Что входит в релиз 1: посредник (13б) и поиск в LAN (13в).**
- **Рекомендую выпустить без обоих.** Посредник по вашему порядку разработки идёт после основы. GUI честно пишет, что его пока нет, и согласия не спрашивает.
- Поиск в LAN: два ПК в одной сети, которые не связывались больше 24 часов, теряют локальный адрес друг друга. Тогда нужен токен адреса «мы в одной сети». Если ваш главный сценарий — домашние ПК в одной сети, предлагаю сделать 13в сразу после релиза 1. Если сценарий другой, 13в можно отложить.
- Режим «локальные ключи» в релиз 1 тоже не входит (он разрешён, но не обязателен; T11).

**Q8. Консольная версия (18в) в релизе 1.**
- **Рекомендую да.** На мини-ПК без рабочего стола GUI не запустится, а консольная версия работает по ssh. Она же нужна для проверочных прогонов релиза на трёх ОС.

## Для владельца (кратко)
- Готового «узла» в ядре нет: всё собрано только в примерах для стенда. Поэтому этап 18 начинается с критичного 18а: настоящий узел в `chervo-core` (хранилище ключей ОС, список друзей с защитой от отката, сеть, передача, безопасный приём). GUI и консоль работают только через него.
- Ради этого я ослабляю старую техническую проверку: ядру разрешено зависеть от нашего транспорта на quinn и от tokio. Переделки транспорта это не требует. Решение технически за дирижёром, к вам вопросом не выносится.
- Выбор egui — пока вывод по документации, а не проверка. До начала GUI идёт короткая проверка 18p: сборка на трёх ОС, лицензии, отсутствие сетевого кода и телеметрии, запуск на чистой Windows и Linux в виртуальной машине без видеокарты, кириллица, диктор, выбор файлов. Часть пунктов можете проверить только вы (виртуальные машины, диктор).
- Риски, которые я вижу заранее (не проверено):
  - лицензии встроенных шрифтов;
  - доступность на Linux и системный выбор файлов могут затянуть старую версию D-Bus, которую мы запретили в 17а;
  - на чистой Windows может не хватить VC-рантайма (тогда собираем со статическим рантаймом).
- Посредника и «локальных ключей» в GUI не будет: показываются честные тексты, кнопок согласия нет. Это отклонение от строки этапа 18 в TASK, записано (§7).
- Новые угрозы — только локальные, от процессов под вашей учётной записью: файл настроек, буфер обмена, дерево доступности, блокировка второго экземпляра. Записаны как T18 для модели угроз ред. 8.
