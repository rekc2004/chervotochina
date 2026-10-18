# SECURITY REVIEW, STAGE 17, S1 (full review)

Reviewer: combine-security (opus/high), 2026-10-18. Commit 979b1a3. Read-only (recorded by the conductor from the reviewer's report).

## 1. Ran (Windows 11, Rust 1.99.1)
- `cargo test --workspace --locked`: 1056 passed, 0 failed, 11 ignored (manual/measurement/network tests). Stage-17 tests passed (set_peers concurrency, preauth limits, rollback ×9, retired ×5, no_leaks, no_logger ×3, hardening on Windows).
- `set_peers_concurrent` 20/20; check-forbidden ok; `cargo deny --offline check`: advisories/bans/licenses/sources ok (13 duplicate-version warnings).
- Not run: `cargo audit`, clippy/fmt, Linux/macOS tests, long fuzz/libFuzzer, stand 17, manual OS-store tests, CI/SBOM artifact.

## 2. Read
Full: chervo-identity; chervo-friends (book, plain, vault, types, error); transport-quinn lib/server/limits/knock; harden.rs, cli main; receive name/place/root; token revocation; CI/deny/audit/fuzz config. Partly: tls.rs; transfer fsio; connect engine publish/update_book; no_leaks/no_logger. Not re-read (rely on stage 9-16 reviews): rest of connect, transfer, upnp, token invite/addr/flow/sas, timesync, receive journal/classify/plan/policy, transport client/registry/conn.

## 3. Findings
No Critical/High in what was read.
- **M1 Medium.** Windows: no privacy check of the receive root / `.chervo-partial` (`chervo-receive/src/root.rs:110-119, 163-166` are Unix-only; `allow_shared_root=false` has no effect on Windows). Another local ACCOUNT (not the same user) may read `names`, forge `.dirs`/state, race placement if the root sits on a volume with permissive default ACLs (from memory). Owner decision: (a) accept; (b) refuse/warn outside `%USERPROFILE%` unless `allow_shared_root`; (c) protected DACL (needs unsafe or a new crate).
- **M2 Medium.** Rollback anchor is opt-in; unanchored `FriendBook::open`/`start_over` (`chervo-friends/src/book.rs:198-203, 273-279`) are public and used by every example. Fix: rename to `*_unanchored` behind `cfg(test)`/feature or doc(hidden), guard test that product src has no unanchored opens, stage 18 requirement.
- **M3 Medium.** libFuzzer knock target tests nothing: fixture uses our own kx key as the friend's (`transport-quinn/src/knock.rs:931-938`); `knock_keys` rejects equal keys (`identity/src/knock.rs:405-409`), table empty, `try_knock` exits at `table.get` (`knock.rs:623-625`). Stable smoke unaffected. Fix: two distinct pair keys, assert table has one key, positive control.
- **L1 Low.** Permission changes do not bump the epoch (`book.rs:655-707`): restoring an older file with AutoAccept on is not detected.
- **L2 Low.** A second app instance with stale data can overwrite a security change via plain `commit` (`book.rs:443-461`) until the next open.
- **L3 Low.** Anchor write failing after file save returns Err although applied (`book.rs:492-498`); transport is correct (`engine.rs:941-942`); GUI must not report failure.
- **L4 Low.** `actions/upload-artifact@v4` pinned by tag, spec 17 decision 9 says SHA.
- **L5 Low.** `fuzz/Cargo.toml` `libfuzzer-sys = "0.4"` unpinned, no `fuzz/Cargo.lock`, nightly date unverified, `tools/fuzz/logs` not gitignored.
- **L6 Low.** `#[doc(hidden)] pub` test/fuzz hooks in product crates (`fuzz_knock_admits` binds UDP and builds a runtime; `set_test_hook`, `with_space_probe`, `new_for_test`, upnp `fuzz_*`). Not network-reachable. Fix: `cfg(any(test, feature = "fuzzing"))`.
- **L7 Low.** THREAT_MODEL rev 4 stale: T9 says msg1_deadline 3 s (code 5 s); T5/T9/T10/T12/T15 still "не реализовано (17 B1/B3)".
- Info: C27 closed (knock not lost on WouldBlock, `knock.rs:579-602`). Linux `PR_SET_DUMPABLE=0` is the real protection; `RLIMIT_CORE=0` is not enforced with a pipe `core_pattern` (from memory).
- Owner acceptance missing: THREAT_MODEL «Спорное» п.4 (L3-13 knock not bound to destination; L5-13 knocks to loopback/LAN from an invite).

## 4. Stage-17 code checked by reading
set_peers under one `peers_update` lock (`lib.rs:451-480`), no lock inversion; pre-auth order knock → limiter check → per-key permit (RAII) → semaphore → charge, all refusals uniform, msg1 deadline `min(msg1, auth)`; Retired: sign → save Retired → delete key, keys of Retired deleted on open, Retired excluded from kx/usable; anchor `check_anchor` (`book.rs:157-176`); hardening reads every measure back, first line of CLI main.

## 5. BRIEF section 7
| Item | Status | Evidence | Residual |
|---|---|---|---|
| E2E encryption with FS | checked (reading + tests) | `tls.rs:86-88,109,136,239-240`; KK binding `kk.rs:126-132` | rustls KX groups not re-checked |
| Safe receive | partly | `name.rs:266-310`, `place.rs:437-493,580-662`, `root.rs:141-224`; tests (Windows) | M1; TOCTOU vs local writer |
| Pre-auth DoS, silence to strangers | partly | knock filter, server.rs, preauth tests | DOS1-3 (stand) — see SECURITY_REVIEW.md |
| Tokens (single use, TTL, replay) | checked (tests + reviews) | token/invite/addr tests | invite.rs/flow not re-read |
| No names/IPs/keys in logs | checked on Windows | no_logger, no_leaks, redaction tests | stage 18 must keep the rule |
| Signed releases, manual updates | not implemented | stage 19 | all |
| audit, SBOM, locks, fuzz | partly | deny ok, CI pins | audit/SBOM/libFuzzer not seen by S1; M3, L4, L5 |
| THREAT_MODEL | partly | rev 4 | L7 |
| No relay / no third parties / rendezvous | by reading / by reading / not implemented | src_guard; only owner-approved NTP hosts | — |

## 6. Threats
T1 partly (X02 stand, L3-13/L5-13 acceptance); T2 partly; T3 checked; T4 partly (M1); T5 partly (M2, L1, L2); T6 checked; T7 not implemented (13b); T8 partly; T9 partly; T10 partly (Windows/macOS dumps accepted); T11 not implemented; T12 partly (17a pending, RUSTSEC exception); T13 checked; T14 checked; T15 partly (M3); T16 implemented in 13a, not re-read.

## 7. Supply chain
RUSTSEC-2026-0370..0372 identical in audit.toml and deny.toml, until 17a, no later than 19. Bans present, none hit. CI tools pinned `--locked`. Third-party `unsafe` (file counts, not an audit): ring, quinn-proto/quinn-udp/quinn, curve25519-dalek, blake2, chacha20, zeroize, getrandom, rustix, fs4, socket2, tokio, windows-native-keyring-store, unicode-normalization; 0 in snow, x25519-dalek, ed25519-dalek, keyring-core, secret-service, chacha20poly1305, rustls-webpki; rustls forbids unsafe; zbus not checked.

## Резюме для владельца
- Критичных и высоких находок в прочитанном коде нет; 1056 тестов на Windows, `cargo deny` чист.
- Три средние: на Windows папка приёма не закрыта от других учётных записей (ваше решение); защита от отката включается только через `open_anchored`, примеры открывают книгу без неё; цель libFuzzer для стука ничего не проверяет.
- Мелкие: смена автоприёма не двигает счётчик отката; второй экземпляр программы может затереть блокировку; SBOM-действие закреплено тегом; fuzz без lock-файла.
- Ждут вашего решения: стук не привязан к адресу назначения; стук на LAN/loopback из приглашения.
