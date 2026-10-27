# fuzz/ (stage 17, libFuzzer, nightly only)

Separate crate (own `[workspace]`, own `Cargo.lock`, root `Cargo.toml` has `exclude = ["fuzz"]`). Product builds never touch it.
Run through `bash tools/fuzz/run17.sh` (never `cargo fuzz` directly on the owner box without `nice`).

Targets (each reuses the public entry point of the matching `fuzz_smoke_*` test):
`token_decode`, `addr_update`, `addr_info`, `transfer_codec`, `transfer_offer`, `transfer_state`, `transfer_names`,
`receive_sanitizer`, `receive_plan`, `sntp`.

Added in stage 17 (B6), once each owning crate got a `#[doc(hidden)] pub` entry point (no behaviour change, same
pattern as `decode_state`): `upnp_desc`, `upnp_http`, `upnp_ssdp`, `upnp_soap`, `upnp_url` (`chervo-upnp::fuzz_desc`/
`fuzz_http`/`fuzz_ssdp`/`fuzz_soap`/`fuzz_url`, reusing `scan`/`desc`/`soap`/`ssdp`/`http`); `knock_check`
(`chervo_transport_quinn::fuzz_knock_admits`, same property as `fuzz_smoke_knock_never_admits`: no datagram other
than the fixture's own secret knock ever admits); `receive_dirs`, `receive_placed`
(`chervo_receive::decode_dirs`/`parse_placed`, the `.dirs`/`.placed` journal); `transfer_names_file`
(`chervo_transfer::decode_names`, the `.names` state file bytes — distinct from `transfer_names`, which fuzzes
`UntrustedName` text, not the file).

Nothing left unreachable from this list (BRIEF/spec 17 decision 7, C04).

The nightly pin is in `rust-toolchain.toml` and is not verified. `libfuzzer-sys = "0.4"` resolves on the first run
(the conductor commits the resulting `fuzz/Cargo.lock`). Corpus (`fuzz/corpus/<target>/`, synthetic only, total <= 5 MiB) is
committed after `cargo fuzz cmin`; `run17.sh` works from a mktemp copy and never writes into the repo.

Stage 17 fix round 1 (S1 L6, M3): the entry points above exist only with the crate feature `fuzzing` (or in the crate's own unit tests); `fuzz/Cargo.toml` enables it for token, transfer, receive, upnp and transport-quinn, product builds never do. `knock_check` first asserts `fuzz_knock_ready()` (two distinct pair keys, one key in the table, positive control: a real knock of the other side admits) so a vacuous run is a crash. `libfuzzer-sys` is still unpinned (S1 L5): see the TODO in `Cargo.toml`.

Stage 19d: `update_http_response` (`chervo_update_check::fuzz_http_response`, feature `fuzzing` of `chervo-update-check`; HTTP response framing and `Location` of the update notice, same properties as `fuzz_smoke_update_http`).
Stage 18a: target `settings` (`chervo_core::fuzz_settings`, the node settings file parser; needs the core crate feature `fuzzing`, enabled in `fuzz/Cargo.toml`). It must run 20 minutes on the owner's Linux machine before stage 19 (`bash tools/fuzz/run17.sh SECS=1200 TARGETS=settings`); it does not block 18a code acceptance. `fuzz/Cargo.lock` was NOT regenerated here (no nightly and no network on the build machine): the first `cargo fuzz build` there refreshes it, the conductor commits the result.
