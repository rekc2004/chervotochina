# Test audit, 2026-10-27

Read-only audit at commit `262d272`, done by reading code. No cargo was run: nothing in this report was executed.
Every test was counted by grep of `#[test]`/`#[tokio::test]`/`#[ignore]`. Each test was classified by reading its name
and its file. All suspicious, guard, redaction, fuzz-smoke and ignored tests were read in full, but not every body in the
large files (`book.rs`, `place.rs`, `policy.rs`, `knock.rs`, `igd.rs`, `attacks.rs`), so the E/U split there is approximate (±5 per file).
Classification was done by four parallel reading passes and then spot-checked: `igd.rs` early returns, `flood.rs`, `transport.rs`,
the CLI tests, `harden.rs` and the ignore list were re-read by the auditor.

Categories:
- **E**: the test runs real product behaviour across components and asserts outcomes.
- **U**: a focused unit test of real logic.
- **G**: a guard that greps source, manifests or the lockfile.
- **T**: a trivial or tautological test.
- **I**: an `#[ignore]` test.

"E (mem)" means E over an in-memory fake link rather than a real socket.

## 1. Counts per crate

| crate | total | E | U | G | T | I | notes |
|---|---|---|---|---|---|---|---|
| chervo-identity | 144 | 0 | ~125 | 2 | 8 | 9 | the 42 Secret Service tests talk to an in-process fake D-Bus service |
| chervo-token | 90 | 5 (mem) | 79 | 0 | 6 | 0 | flows run over `memconn`, not a socket |
| chervo-timesync | 15 | 2 | 11 | 0 | 1 | 1 | E uses real UDP against local fake SNTP servers |
| chervo-transport | 2 | 0 | 0 | 0 | 2 | 0 | stub crate (`NullTransport`, `DenyAll`) |
| chervo-transport-quinn | ~141 | ~112 | ~18 | 3 | 3 | 5 | E is real QUIC on 127.0.0.1, the strongest suite |
| chervo-upnp | 123 | 47 | 72 | 2 | 1 | 1 | E runs against a fake in-process IGD on 127.0.0.N; on macOS these are ignored |
| chervo-addr | 68 | 0 | 65 | 2 | 1 | 0 | pure state machines |
| chervo-connect | 158 | 8 | 143 | 2 | 5 | 0 | 143 U on `FakeTransport` with paused time; only `tests/engine_net.rs` is real QUIC |
| chervo-transfer | 183 | 54 (7 real QUIC, 47 mem) | 124 | 2 | 2 | 1 | `src/tests` use the in-memory `FakeConn`; `tests/transfer_net.rs` is real QUIC with sha256 compare |
| chervo-receive | 125 | 23 | 98 | 0 | 4 | 0 | real filesystem; `receive_net.rs` (12) is real network |
| chervo-friends | 101 | 11 | 88 | 0 | 2 | 0 | `invite_net.rs` and `addr_net.rs` are real QUIC; the book uses a fake key store |
| chervo-core | 63 | 8 | 36 | 11 | 8 | 0 | about a third are guards or guard self-tests |
| chervo-cli | 15 | 6 | 6 | 1 | 2 | 0 | see section 2: no test runs the real `chervo` binary through a transfer |
| **workspace** | **~1228** | **~274** | **~865** | **25** | **47** | **17** | |
| spikes/transport (not in workspace) | 23 | 2 | 20 | 0 | 1 | 0 | never run by CI (`cargo test --workspace` excludes it) |

What the numbers mean:
- About 70% of the tests are focused unit tests. Most of them are good: parsers, codecs, state machines, adversarial input.
- Of the ~274 E tests, about 60 run over in-memory fakes (the token flows, the transfer `src/tests`). The rest use real sockets, but only on loopback.
- **G (25)** are regression fences, for example: no logger, no test store in product code, no unanchored `open`, Secret Service source rules. They do not prove behaviour. Keep them, but do not count them as "works".
- **T (47)** includes 4 guard self-tests: `anchored_only.rs:62`, `features_guard.rs:63`, `layout.rs:66`, `test_store_guard.rs:64`. These are positive controls for the guards, so they are T as behaviour evidence but worth keeping.
- **I (17)**, by what they need:

| ignored tests | needs | run anywhere? |
|---|---|---|
| `ss_live_roundtrip`, `ss_live_attributes_exact`, `ss_live_locked_bounded` (`chervo-identity/src/secret_service/tests.rs:1691,1725,1760`) | a real gnome-keyring | **Yes.** CI job `secret-service-live` runs them via `scripts/ci-secret-service.sh`. This is the only ignored group run automatically. |
| `os_store_roundtrip_manual`, `os_list_key_roundtrip_manual` (`chervo-identity/tests/identity.rs:938,992`) | the real OS key store | Manually, once, on Windows at stage 10 (PASS, `docs/SECURITY_REVIEW.md:12`). Never on macOS. |
| `os_epoch_roundtrip_manual`, `ss_migration_write_old`, `ss_migration_read_new` (`identity.rs:1032,1055,1072`) | the real OS store | No run recorded in the docs. |
| `kk_trial_cost` (`kk.rs:421`), `knock_table_cost`, `accept_cost_by_pairs`, `friend_latency_under_flood`, `knock_throughput_overhead` | benchmarks, release build | Once each in stage 9/10 reviews (`VERIFY-STAGE09.md`, `VERIFY-STAGE10B.md`). They have no thresholds, so they can never fail. |
| `stable_id_reuse_probe` (`chervo-transport-quinn/src/tests/race.rs:422`) | manual diagnostic for R2-2 | Not referenced anywhere since. **Delete candidate.** |
| `sync_real_servers` (`chervo-timesync/src/tests.rs:387`) | the internet | No run recorded. |
| `multicast_discovery_real_lan` (`chervo-upnp/src/tests/igd.rs:1234`) | a real LAN with multicast | No run recorded. |
| `net_big_file_manifest_hash_no_stall` (`chervo-transfer/tests/transfer_net.rs:1100`) | N GiB of disk | No run recorded. |

## 2. Trivial tests (T) and weak E/U tests

### T: delete or merge

| test | why it is trivial |
|---|---|
| `crates/chervo-transport/tests/transport.rs:17` `deny_all_denies` | asserts that a stub returns its constant |
| `crates/chervo-transport/tests/transport.rs:22` `null_transport_fails_closed` | asserts that a placeholder returns `NotImplemented` |
| `crates/chervo-identity/tests/identity.rs:226` `error_display_fixed_strings` | re-asserts string constants |
| `crates/chervo-identity/tests/identity.rs:333` `prologue_tag_distinct_from_sign_domains` | constants only; duplicates `knock.rs:109` |
| `crates/chervo-identity/tests/identity.rs:362` `secret_types_zeroize_on_drop` | a compile-time trait bound; also covers third-party types |
| `crates/chervo-identity/tests/kk.rs:83` `kk_types_are_send` | compile-time Send probe |
| `crates/chervo-identity/tests/kk.rs:91` `kx_peer_is_send_sync` | compile-time Send+Sync probe |
| `crates/chervo-token/tests/addr_flow.rs:720` `addr_flow_futures_are_send` | compile-time Send probe |
| `crates/chervo-core/src/node/tests.rs:973` `node_and_events_are_thread_safe` | compile-time Send/Sync probe |
| `crates/chervo-identity/tests/no_disk.rs:161` `scan_detects_planted_key` | tests the test helper `scan` |
| `crates/chervo-identity/tests/redaction.rs:113`, `crates/chervo-token/tests/redaction.rs:159`, `crates/chervo-timesync/tests/redaction.rs:58`, `crates/chervo-friends/tests/redaction.rs:154` (`*_errors_have_fixed_text`) | unit-variant errors that hold no data, so nothing can leak |
| `crates/chervo-identity/tests/redaction.rs:122`, `crates/chervo-token/tests/redaction.rs:146`, `crates/chervo-friends/tests/redaction.rs:145` (`*_have_no_debug` / `*_debug_is_known`) | a type-level "no Debug derive" probe; arguably G, not behaviour |
| `crates/chervo-token/tests/invite.rs:433` `error_display_fixed` | constant strings differ |
| `crates/chervo-token/tests/token.rs:496` `tags_distinct_from_identity_tags` | constants; duplicates the identity tag check |
| `crates/chervo-token/tests/token.rs:527` `token_enum_is_invite` | duplicates `invite_roundtrip` |
| `crates/chervo-connect/src/tests/texts.rs:15` `texts_present`, `:50` `revocation_io_text` | text constants are non-empty, Cyrillic, or equal their own literal |
| `crates/chervo-connect/tests/connect.rs:38` `path_and_reason_names_are_pinned`, `:69` `config_defaults_match_the_spec` | constants compared with literals copied into the test |
| `crates/chervo-connect/tests/connect.rs:111` `diagnosis_flag_and_debug_are_safe` | re-reads a field it just set; redaction is covered better in `tests/redaction.rs` |
| `crates/chervo-transport-quinn/tests/basic.rs:12` `config_defaults_match_spec` | ~25 constants against copies of themselves |
| `crates/chervo-transport-quinn/src/tests/preauth.rs:200` `s2_defaults` | two constants |
| `crates/chervo-transport-quinn/src/tests/tlsx.rs:70` `verifier_ed25519_only` | echoes a constant list |
| `crates/chervo-transport-quinn/src/tests/fuzz.rs:256` `fuzz_entry_fixture_has_one_key_and_real_knock_admits` | tests the fuzz fixture; the rest duplicates `fuzz_smoke` |
| `crates/chervo-upnp/src/tests/texts.rs:8`, `crates/chervo-addr/tests/book.rs:392` `texts_present` | UI text constants |
| `crates/chervo-transfer/src/tests/hashprog.rs:757` `preparing_text_has_no_placeholders` | a constant string check |
| `crates/chervo-transfer/tests/transfer.rs:4` `decode_message_bounds` | duplicates `src/tests/codec.rs` |
| `crates/chervo-core/tests/harden.rs:61` `harden_windows_applies_nothing` | asserts that nothing happens |
| `crates/chervo-core/tests/harden.rs:72` `harden_is_idempotent` | checks only no panic and `a == b` |
| `crates/chervo-core/tests/node_net.rs:142` `sha256_matches_known_vectors` | tests a helper defined in the test file, not the product |
| `crates/chervo-friends/tests/book.rs:295` `permission_default_ask` | a Default constant |
| `crates/chervo-receive/tests/receive.rs:43` `default_limits_valid` | default constants |
| `crates/chervo-receive/tests/place.rs:354` `windows_symlink_test_skips_if_unprivileged` | no assertion, only `println!` |
| `crates/chervo-receive/tests/plan.rs:267` `plan_long_path_flag` (non-Windows branch) | prints "skipped"; the real case runs only on Windows |
| `crates/chervo-receive/tests/no_leaks.rs:406` `scanner_detects_a_leaky_derive` | the scanner's self-test; keep as a positive control |
| `crates/chervo-cli/tests/cli.rs:14` `no_args_fails` | checks only `!success`, with no message or exit code |
| `crates/chervo-cli/tests/repl_two_nodes_scripted.rs:96` `host_child` | a re-exec helper that `cargo test` counts as a passing empty test |
| `spikes/transport/src/tlsb.rs:143` `client_tls_builds` | only `is_ok()` |

### Weak E/U: can pass while the feature is broken

**Pins a known bug or skips its own assertions**
- `crates/chervo-transport-quinn/tests/flood.rs:139` `friend_starved_documented` **pins a known defect.** It asserts that the friend *is rejected* under a stranger flood. It stays green while the bug exists and turns red when the bug is fixed.
- `crates/chervo-upnp/src/tests/igd.rs:444,457,476,488` (`igd_wan_*`): each test starts with `if st == Mapped { return; }`. If the mapper wrongly maps on a CGNAT, bogus or private WAN, the test silently passes. That wrong mapping is exactly the bug these tests exist to catch. In `igd_wan_bogus_rejected` the `return` sits inside the loop, so it also skips the remaining values.
- `crates/chervo-transfer/src/tests/dos.rs:209` `hard_link_placement_ok_even_if_unlink_fails`: the key assert is inside `if m == HardLink`, so on any other placement path it checks nothing.

**The CLI product path**
- `crates/chervo-cli/tests/repl_two_nodes_scripted.rs` is the only CLI transfer test, and it does not run the `chervo` binary. It re-execs the test exe with an in-memory `MemStore` through `Node::open_with_store_for_tests`. So the real binary's open path, the OS key store and argument parsing are never exercised in a transfer.
- `crates/chervo-cli/tests/cli.rs` spawns the real binary, but only for init, errors and recovery. No test sends a file with it.

**Real product parts mocked away or never reached**
- `crates/chervo-identity/tests/no_disk.rs:101` `key_bytes_not_written_to_data_dir` uses `MemStore`, which never touches disk. It would pass even if `OsKeyStore` wrote keys into files. It also changes the process cwd, which can race with other tests.
- `crates/chervo-identity/tests/identity.rs:211` `public_debug_redacted` accepts `Err(StorageUnavailable)` from `OsKeyStore`, so on a machine with no keyring it checks nothing.
- `crates/chervo-core/src/node/interrupt.rs:51,59` tests `forward()` with fake closures. The real Ctrl+C/SIGTERM subscription is never exercised.
- `repl_two_nodes_scripted.rs` `sigterm_shuts_the_node_down_in_order` is `cfg(unix)` and waits a fixed 500 ms.
- `crates/chervo-core/tests/harden.rs`: on Windows only the two T tests run, so hardening is unverified on the owner's main OS.
- `crates/chervo-transport-quinn/src/tests/race.rs:368` `events_lagged_reported` injects events straight into the channel; the real emitters are not used.

**Timing assertions with loose bounds**
- `crates/chervo-token/tests/flow.rs:388` `inviter_exchange_reads_clock_after_m1`: proves "not called" by waiting 100 ms.
- `crates/chervo-transfer/src/tests/flow.rs:87` `no_disk_write_before_accept`: proves "absent" by waiting 300 ms.
- `crates/chervo-transfer/src/tests/dos.rs:318` `trickling_sender_cannot_block_another_friend`: real-clock sleeps and a loose bound.
- `crates/chervo-transfer/src/tests/resume.rs:674` `buffer_budget_respected`: a 1 ms sampler can miss a short overrun.
- `crates/chervo-transport-quinn/tests/net.rs:13,28` `retry_before_handshake`, `per_ip_limit`: a 300 ms sleep, then lax `>=` counters.
- `crates/chervo-timesync/src/tests.rs:340` `sync_clock_loopback`: 300 ms tolerance against local fake servers.

**Asserts too little**
- `crates/chervo-transfer/tests/transfer_net.rs:842` `net_rebind_mid_transfer_completes` accepts either migration or resume, and never checks that the rebind happened.
- `crates/chervo-addr/tests/guard.rs:9` `probe_no_panic`: "any result allowed".
- `crates/chervo-core/src/node/tests.rs:464` `fuzz_entry_accepts_and_rejects_without_panic` ignores the return value.
- `crates/chervo-core/tests/fuzz_smoke.rs:160` `settings_parser_survives_noise` has an accept threshold of only 0.1%.
- `crates/chervo-transfer/src/tests/fuzz.rs:196` `fuzz_smoke_codec` compares only `is_ok`/`is_err` of two decoders, not the decoded values.
- `crates/chervo-transfer/tests/transfer.rs:27` checks only `is_ok`/`is_err`.
- `crates/chervo-transport-quinn/src/tests/misc.rs:306` `unrepresentable_idle_timeout_is_error`: a bare `is_err()`.
- `crates/chervo-transport-quinn/tests/net.rs:52` `debug_redacted` compares format strings and never checks that anything is hidden.
- `crates/chervo-receive/tests/policy.rs:370` `real_disk_space_probe` asserts only `total>0` and `avail<=total`.

## 3. One-off artifacts

| artifact | purpose (git log) | referenced by | recommendation | risk of deleting |
|---|---|---|---|---|
| `spikes/transport/` (859 tracked files, of which 840 are logs, ~1.3 MB) | stage 7-8 transport spike; decided A/B, gates G1-G12 | `docs/SPIKE_TRANSPORT.md`, `PLAN_DRAFT.md`, specs 07/08/09/13a/16/18, TASK | not in the workspace and never built by CI. **Move out of the release tree:** git tag `spike-transport-final`, then delete. | Low. The evidence links in `SPIKE_TRANSPORT.md` break unless they point to the tag. Its 23 tests are not run anywhere. |
| `spikes/gui-probe/` and `.github/workflows/gui-probe.yml` | stage 18p egui probe | `GUI-PROBE-*.md`, `stage-18-gui.md`; the workflow says "TEMPORARY … delete once DECISION 2.x is written" | delete after 18p closes (owner's VM checks and the DECISION entry) | None after 18p; before that, it loses the owner's test binaries |
| `crates/chervo-connect/examples/node13.rs` | stage 13 stand node | `tools/netns/stage13.sh` | keep while the stand is kept; otherwise delete with the script | Low; built in CI by `--all-targets`, so it costs compile time |
| `crates/chervo-transfer/examples/node14.rs` | stage 14 stand node | `tools/netns/stage14.sh` | same as node13. It is superseded by `node16`. | Low |
| `crates/chervo-receive/examples/node15.rs` (579 lines) | stage 15 example | docs only; **no stand script uses it**; a comment in `Cargo.toml:22` | **delete** | Low; also fix the `Cargo.toml` comment |
| `crates/chervo-transfer/examples/node16.rs` (880 lines) | stage 16-17 stand node (the full node) | `tools/netns/stage16.sh`, `stage17.sh` | keep until the stands use the real `chervo` CLI, then delete | High if deleted now: it is the only real-network harness for the NAT stands |
| `crates/chervo-transport-quinn/examples/netcheck.rs` | stage 9 stand tool | `tools/netns/stage9.sh` | keep with stage9, or retire both | Low |
| `crates/chervo-transport-quinn/examples/knockflood.rs` | stage 17 DoS stand | `tools/netns/stage17.sh` | keep (security evidence) | Medium |
| `crates/chervo-upnp/examples/upnp_probe.rs` | stage 13a stand against a real miniupnpd | `tools/netns/stage13a.sh` | keep; it is the only real-UPnP-daemon check | Medium |
| `fuzz/` (20 targets, corpus for 19) | stage 17 libFuzzer | `tools/fuzz/run17.sh`, `SECURITY_REVIEW.md` | keep. It ran once for 20 minutes on the owner's Linux box (stage 17) and is not in CI. The `settings` target (added in 18a) has **no corpus and no recorded run**. | High: security evidence |
| `docs/reports/FLAKE-NOLEAKS-2026-10-23.md` | analysis of the no_leaks flake | `OWNER_DECISIONS.md`, `SECURITY_REVIEW.md`, TASK, spec 14b | keep | Breaks references |
| `docs/reports/NETTEST-2026-10-18.md`, `STAND17-2026-10-18.md` | stand results | `SECURITY_REVIEW.md`, `THREAT_MODEL.md` | keep (release evidence), but note they are from 2026-10-18 and predate stages 17-18 code changes | Breaks references |
| `docs/reports/GUI-PROBE-2026-10-25.md`, `GUI-PROBE-MANUAL.md` | 18p | TASK (MANUAL is referenced by nothing) | archive together with the gui-probe workflow after 18p | Low |

## 4. Gaps: important behaviour with no real test

- **The product binary `chervo` never transfers a file in any test or stand.** The netns stands use `node13/14/16` examples. The CLI two-node test uses `MemStore` and the test exe.
- **OS key store end to end:**
  - macOS Keychain has never been exercised.
  - Windows Credential Manager was checked once by hand at stage 10, before the epoch and list-key changes. The `os_epoch` and migration manual tests have no recorded run.
  - Only Linux Secret Service runs in CI.
- **Real two machines, real Internet, real NAT/CGNAT:** none. NAT is only emulated in netns on the owner's Linux box (stages 9-17), run by hand, not since 2026-10-19, and not in CI.
- **Real home router UPnP:** none. There is a fake IGD in the tests and a miniupnpd run in netns once at stage 13a.
- **Real Ctrl+C/SIGTERM delivery:** not on Windows, and on Unix only via a timed sleep.
- **Hardening on Windows:** nothing is asserted.
- **Fuzzing:** not in CI and not re-run after stage 17 changes.
- **Large files (GiB) and the long-path flag:** the large-file test is ignored and has not been run; the long-path flag is Windows-only.
- **Installer, packaging, signing, update:** nothing exists yet, so nothing is tested.
- **GUI:** not started (18б).
- **Mediator (13б):** not implemented.

## 5. Для владельца

1. Тестов ~1230. Примерно 70% из них (~865) полезные модульные: разбор, кодеки, конечные автоматы, злой ввод. Сквозных ~274, но все только на петле 127.0.0.1, а ~60 из них вообще без сокетов (подменное соединение в памяти).
2. 25 тестов это стражи по исходникам (grep). Они не доказывают, что продукт работает, только что в код не вернули запрещённое. 47 тестов тривиальные: проверяют константы, тексты, Send/Sync на этапе компиляции или «ничего не делает».
3. Главное: настоящая программа `chervo` ни в одном тесте и ни на одном стенде не передаёт файл. Сквозной тест CLI идёт через тестовый бинарник с ключами в памяти. Стенды netns используют примеры node13/14/16.
4. Дальше по важности. Хранилище ключей macOS не проверялось никогда. Windows проверен вручную один раз, на этапе 10. Реальной сети между двумя машинами и реального роутера не было. NAT эмулировался в netns только вручную и до 19.10.
5. Опасные тесты, исправить:
   - `flood.rs:139 friend_starved_documented` закрепляет известный дефект: упадёт, когда дефект починят.
   - 4 теста `igd_wan_*` выходят без проверок, если отображение порта ошибочно создано, то есть ровно в том случае, который должны ловить.
6. Удалить, предложение (сам ничего не удалял): `chervo-transport/tests/transport.rs` (2 теста), `node15.rs`, `stable_id_reuse_probe`, тесты-дубли и тесты констант из таблицы T (кроме самопроверок стражей), `host_child` как отдельный тест.
7. После закрытия 18p удалить `spikes/gui-probe` и `gui-probe.yml`. `spikes/transport` (840 файлов логов) пометить git-тегом и убрать из дерева.
8. Оставить: стражи, fuzz/, сетевые тесты `*_net.rs`, примеры, на которых держатся стенды, пока стенды не переведены на настоящий `chervo`.
9. Перед релизом нужны: сквозной тест с бинарником `chervo` и настоящим хранилищем ОС на 3 ОС, ручной прогон на двух реальных машинах через NAT, корпус и прогон fuzz-цели `settings`.
10. Всё выше получено чтением кода. Ничего не запускалось, а разбивка E/U в больших файлах приблизительная.
