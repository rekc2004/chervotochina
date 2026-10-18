# fuzz/ (stage 17, libFuzzer, nightly only)

Separate crate (own `[workspace]`, own `Cargo.lock`, root `Cargo.toml` has `exclude = ["fuzz"]`). Product builds never touch it.
Run through `bash tools/fuzz/run17.sh` (never `cargo fuzz` directly on the owner box without `nice`).

Targets (each reuses the public entry point of the matching `fuzz_smoke_*` test):
`token_decode`, `addr_update`, `addr_info`, `transfer_codec`, `transfer_offer`, `transfer_state`, `transfer_names`,
`receive_sanitizer`, `receive_plan`, `sntp`.

Not reachable from outside the crates (private modules or `pub(crate)` functions), so no target yet:
UPnP parsers (`scan`, `desc`, `soap`, `ssdp`, `http`), knock datagram check (`chervo-transport-quinn/src/knock.rs`),
`.dirs`/`.placed` journal (`chervo-receive/src/journal.rs`), `decode_names` (`chervo-transfer/src/state.rs`).
They need a `#[doc(hidden)] pub` re-export (as `decode_state` already has) in the owning crate; that is a change in `crates/`
and is outside B4. The stable `fuzz_smoke_*` tests remain the only coverage for them.

The nightly pin is in `rust-toolchain.toml` and is not verified. `libfuzzer-sys = "0.4"` resolves on the first run
(the conductor commits the resulting `fuzz/Cargo.lock`). Corpus (`fuzz/corpus/<target>/`, synthetic only, total <= 5 MiB) is
committed after `cargo fuzz cmin`; `run17.sh` works from a mktemp copy and never writes into the repo.
