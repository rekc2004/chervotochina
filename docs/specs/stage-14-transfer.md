# SPEC 14: Transfer          criticality: CRITICAL (parts X1, X2, X3)

Author: combine-architect (opus), 2026-10-17, revision 1. Labels: [P] verified by me in the source (file:line); [V] architect's inference; [D] from memory, not re-checked; [NP] not verified. **Nothing was run.** No new packages: only path crates and crates already in `Cargo.lock` (`ring 0.17.14`, `getrandom 0.4.3`, `tokio 1.53.3`). New normal edges: `chervo-transfer -> {chervo-identity, chervo-transport, chervo-connect, chervo-friends, ring, getrandom, tokio}`. `chervo-transfer` never depends on quinn/rustls (U7). `chervo-receive` is not touched (stage 15).

Goal: files go from one friend to another over the live QUIC connection of stage 13, byte-identical (BRIEF 6, DECISION 2.8): sender offers (names, sizes), receiver accepts or declines, the receiver pulls blocks over parallel streams with a configurable window, checks every block against a per-block hash list bound by a whole-file root before writing it, re-fetches mismatches, re-checks the whole file on disk, and only then hands it to a placement step; transfers resume after disconnect, IP change and receiver restart, re-verifying what is already on disk. **Stage 14 never builds a filesystem path from an untrusted name** (boundary with stage 15, decision 10).

Read: this file; `docs/specs/stage-13-connect.md` ("Stream dispatch", "Connections"); `crates/chervo-transfer/*`; `crates/chervo-connect/src/{dispatch,engine,config,lib}.rs`, `src/tests/kit.rs`, `tests/engine_net.rs` (helpers); `crates/chervo-transport/src/lib.rs`; `crates/chervo-transport-quinn/src/{lib,tls,registry,conn}.rs`; `crates/chervo-token/tests/{flow,fuzz_smoke}.rs` (MemConn and fuzz pattern); `crates/chervo-friends/src/types.rs`. Search nothing else.

## Scope of this stage and what is deferred (with reason)
| Item of TASK 14 | Here | Reason |
|---|---|---|
| Length-bounded codec, fuzz target | yes (stable fuzz smoke; libFuzzer in 17 as for stages 11-13a) | |
| Offer, acceptance by the receiver (sender, size) | yes; decision via UI hook, **always ask** | auto-accept with limits and executable check need stage-15 name classification (decision 11) |
| Parallel QUIC streams, configurable window | yes | |
| Byte-identical delivery; per-block hash + whole-file hash; verify before write; re-fetch; final name only after match | yes | |
| Resume after disconnect / IP change / receiver restart with re-verification | yes | sender restart = start over (sessions in memory only, decision 9) |
| **Compression** | **wire field reserved, no codec -> open question Q1** | no codec crate in the lock; media is already compressed; every decoder is a new hostile-input surface |
| Path sanitizing, folders, reserved names, executable warning list, auto-accept | **no -> stage 15** | TASK 15 |
| Revocation delivered over the live connection (stage-13 spec, "Requirements for other stages") | **no -> stage 18 or a small later stage** | not in the TASK 14 criterion; it would add a second wire format here |

## Decisions (rationale)
1. **Receiver pulls.** The receiver asks for blocks (`GET_BLOCK`); the sender only answers. Re-fetch, resume and the window are then the receiver's local decisions; the sender needs no per-block state beyond counters. ARCH-REVIEW-STAGE08 Н9: schedule by blocks, not by fixed per-stream shares.
2. **Hash: SHA-256 from `ring 0.17.14`, two-level hash list (fact 10).** BLAKE3/`bao` are not in the local registry (fact 11) [NP]; adding them means new packages (CORE 1, 3). ring is already in the build and uses SHA-NI / ARMv8 SHA (fact 10). Construction (no new primitive, about 20 lines; the same shape as BitTorrent v1 pieces + info hash [D]):
   `leaf_i = SHA256("chervo-xfer-v1-block\0" || u32 i || u32 len_i || data_i)`;
   `root = SHA256("chervo-xfer-v1-file\0" || u64 size || u32 block_size || u32 block_count || leaf_0 || ... || leaf_{n-1})` (integers big-endian).
   The **whole-file hash is `root`**: it binds every byte through the leaves. What the hashes protect against (honest list): source file changed during or between sessions, receiver disk/write errors and offset bugs, partial data after a crash, resuming against a different file version. Wire tampering is already stopped by QUIC AEAD; a hostile sender can send any content it wants (it is its file).
3. **Block size is a function of file size, not a sender choice:** `block_size = clamp(next_pow2(ceil(size / 65536)), 1 MiB, 16 MiB)`, `block_count = ceil(size / block_size)`; `MAX_FILE_SIZE = 2^40` (1 TiB), so `block_count <= 65536` and the hash list `<= 2 MiB`. The receiver recomputes the layout and rejects any manifest that differs. Size 0: 1 MiB, 0 blocks.
4. **Sender hashes before sending (verified streaming needs the root first).** Hashing of all offered files starts in the background when the offer is sent (while the receiver decides) and overlaps with sending earlier files. On every read for sending, the sender recomputes the leaf and compares: mismatch -> `SourceChanged` for that file (otherwise a changed source would loop re-fetches). Cost: one extra full read of each file on the sender (noticeable on HDD) [V]; owner priority "integrity over speed" (DECISION 2.8).
5. **Write only verified blocks; final check from disk.** A block is read fully into a buffer, its leaf is checked, then it is written at its offset by the file's single writer. After the last block: `sync_all`, then (`verify_after_write = true`, default) the whole `.part` file is re-read and re-hashed per block; mismatching blocks are cleared and re-fetched; only an exact `root` match goes to placement. The page cache may serve this read, so it proves our own write path (offsets, lengths), not the platter [V].
6. **Re-fetch bounds.** A block failing its leaf is re-requested at most `max_block_refetch` (3) times, at most `max_refetch_per_transfer` (64) in total; beyond -> the file fails (`Damaged`), its partial data is deleted, no final file. Prevents endless loops (ARCH-08 Н10).
7. **Window and streams.** Receiver: `streams` data streams (default 4, 1..=8), each with up to `per_stream_window` (2, 1..=8) outstanding requests; all in-memory block buffers come from one byte budget (`recv_buffer_budget` 128 MiB, a `tokio::sync::Semaphore` in KiB), the sender likewise (`send_buffer_budget`). QUIC windows become configurable in the transport (fact 8-9): `stream_receive_window` 4 MiB, connection window after KK 16 MiB (today `VarInt::MAX`), `send_window` 16 MiB. The finite connection window also bounds what a hostile friend can make us buffer per connection [V]. ARCH-08: 4 streams on one connection did not use more cores; defaults are not tuned, measurement is stage 16.
8. **Resume.** Connection loss = pause, never cancel. The receiver opens a new control stream with `RESUME` when `Links::connection(pair)` returns a connection again (event or 5 s poll). In-process: missing blocks come from the in-memory bitmap, computed only after all tasks of the old connection have stopped (ARCH-08 Н11). After receiver restart: state file loaded, every block marked done is re-read and re-hashed from disk before use; the manifest of every unfinished file is fetched again and its `root` must equal the stored one, else that file restarts from zero. QUIC migration after an IP change keeps streams alive and needs nothing (stage 13 decision 10).
9. **Sender keeps sessions in memory only**, `resume_hold` (24 h) after the last disconnect; after a sender restart the receiver gets `CANCEL{Unknown}` and deletes the partial data. Sender-side persistence and "reuse partial data on a new offer of the same file" are not in this stage.
10. **Stage 14/15 boundary (exact).** Stage 14 creates, opens and deletes only paths `cfg.partial_dir.join(<generated>)`, where `<generated>` is hex or a fixed constant (`state`, `state.tmp`, `<i>.part`, `<i>.hashes`, `<i>.hashes.tmp`). Untrusted names live in `UntrustedName` (no `Display`, redacted `Debug`, no conversion to `Path`/`OsStr`) and are only stored, encoded and handed out. The final location is decided by an injected `Placement`. Stage 14 ships `GeneratedNames` (final name `chervo-<hex(key)>-<index>`, no untrusted byte, for tests and the example only) and the helper `place_no_clobber`. A source guard test enforces this. The partial directory must be on the volume of the destination (placement uses link/rename); choosing it is the caller's job (stage 15/18).
11. **Acceptance policy injected; stage 14 always asks.** `AcceptPolicy::decide` returns `Ask | Accept | Decline`; stage 14 ships `AskAlways` only, even for friends with `Permission::AutoAccept` (fact 14). Stage 15 implements auto-accept (per-offer limits of `AutoAcceptLimits`, a rolling per-friend quota, never with executable types) and the executable-type list (`chervo-receive`); stage 18 shows the warning. Reason: the list classifies untrusted names, which is stage 15's job (TASK 15 line).
12. **No-clobber placement without FFI.** `place_no_clobber(temp, final)`: `fs::hard_link(temp, final)` (atomic, fails with `AlreadyExists`) then `remove_file(temp)`; if linking fails with any other error (FAT/exFAT, some network shares [NP]): reserve with `OpenOptions::create_new(true)`, then `fs::rename(temp, final)` over the reservation (std rename replaces on all three OS [D]; rust-src is not installed, so proven only by test `place_no_clobber_*` on CI 3 OS). The fallback leaves a 0-byte file under the final name for the length of one rename (and after a crash in that gap); recorded in "Not verified". Unix: `File::open(parent)?.sync_all()` after placement (best effort); Windows: no directory sync (NTFS journal) [NP]. On Windows `PermissionDenied` from rename/remove (antivirus, indexer; stage-13 flake note) is retried 5 times, 100 ms apart.
13. **Disk full** is a pause, not a failure: `ErrorKind::StorageFull` or `raw_os_error()` in {28, 122 (Linux EDQUOT), 69 (macOS EDQUOT), 39, 112 (Windows)} -> `Paused{DiskFull}`; requests stop, verified data stays, `retry` continues. Any other write error -> `Paused{Io}`. A failed write leaves its block unmarked (re-fetched); free space is not pre-checked (std has no API; `unsafe` forbidden) [V].
14. **Engine integration without a dependency from connect to transfer.** `chervo-connect` gets a generic stream inbox (kinds registered at runtime), a second event subscriber and a connection hold that `max_live` eviction respects. The dispatcher stops reading kind bytes and answering ADDR_INFO inline (fact 4): today one silent stream stalls every other stream of that friend for up to 5 s.

## Facts from the source
1. `chervo-transfer` is a stub: `MAX_MESSAGE_LEN = 64 KiB`, `TransferId([u8;16])`, `BlockHash([u8;32])`, `FileEntry`, `Offer`, `Message`, `decode_message` never `Ok` (`src/lib.rs:6-67`); no dependencies (`Cargo.toml:8`); test `decode_message_bounds` (`tests/transfer.rs:4-18`) [P].
2. `chervo-receive`: `ReceiveLimits` default `max_files 10_000, max_depth 16, max_name_bytes 255, max_path_bytes 1024, max_total_bytes 64 GiB` and `sanitize_relative_path` stub (`src/lib.rs:8-61`) [P].
3. `chervo-core` depends on and re-exports both; layout test forbids `chervo-cli, iroh, quinn, rustls, tokio` in core's own manifest only (`chervo-core/tests/layout.rs:35-41`) [P].
4. Dispatcher: one loop per connection; `accept_bi`, then reads 1 byte under `addr_info_timeout` inline, then awaits `answer_addr_info` inline; every other kind is dropped (`chervo-connect/src/dispatch.rs:26-71`) [P].
5. `max_live` eviction closes the oldest live connection unconditionally; comment says no other stream kinds exist (`engine.rs:459-473`) [P]. `Engine::connection(pair)` (`engine.rs:1014-1016`); the only event receiver is created in `start` (`engine.rs:928`), no `subscribe` [P].
6. Stream traits: `SendStream { write_all, finish }`, `RecvStream { read -> Option<usize> }`; no reset/stop/priority (`chervo-transport/src/lib.rs:104-114`) [P]. ARCH-REVIEW-STAGE09 line 71 says the same.
7. `STREAM_ADDR_INFO = 0x21` (`chervo-token/src/lib.rs:68`); `PairId([u8;16])` (`chervo-identity/src/ids.rs:7`) [P].
8. quinn adapter: pre-auth `TransportConfig` sets bidi 1 (server) / 0 (client), uni 0, no datagrams, connection `receive_window = preauth_receive_window` (64 KiB), no stream window (`tls.rs:47-64`); after KK `set_max_concurrent_bi_streams(post_auth_bidi = 16)` and `set_receive_window(VarInt::MAX)` (`registry.rs:174-175`, `lib.rs:145`) [P].
9. quinn-proto 0.11.19 (lock): defaults `stream_receive_window = 1.25 MB`, `receive_window = VarInt::MAX`, `send_window = 10 MB` (`config/transport.rs:366-379`); setters `stream_receive_window` (`:114`), `send_window` (`:142`). quinn 0.11.12 `Connection::{set_send_window, set_receive_window, set_max_concurrent_bi_streams}` (`connection.rs:651-668`); no per-stream window setter after the handshake [P].
10. ring 0.17.14: `digest::Context::{update, finish}` (`digest.rs:187-260`), `digest::SHA256` (`:424`); SHA-256 uses SHA-NI on x86_64 and ARMv8 SHA on aarch64 when present (`digest/sha2/sha2_32.rs:29-57`); ring is a workspace dependency (`Cargo.toml:52`) [P].
11. Local registry (`index.crates.io-1949cf8c6b5b557f`): no `blake3`, `bao`, `zstd*`, `lz4*`, `ruzstd`; present but not in `Cargo.lock`: `miniz_oxide 0.8.9` (`#![forbid(unsafe_code)]`, `src/lib.rs:25`; `inflate::decompress_to_vec_with_limit`, `src/inflate/mod.rs:177`), `adler2 2.0.1`, `brotli 9.0.0` [P: directory listing].
12. tokio 1.53.3: `task::spawn_blocking` is under `cfg_rt!` (`src/task/blocking.rs:82, 220`) - available with the workspace features [P]. getrandom 0.4.3 `fill` (`src/lib.rs:87`) [P].
13. `Permission` defaults to `Ask`; `AutoAccept(AutoAcceptLimits { max_total_bytes, max_files })`; zero limits rejected (`chervo-friends/src/types.rs:4-16`, `book.rs:471-482`) [P].
14. In-memory `Connection` fakes exist: `MemConn` (`chervo-token/tests/flow.rs:70-75`, `addr_flow.rs:101-113`), `FakeConn` (`chervo-connect/src/tests/kit.rs:334`) [P]. Fuzz smoke pattern: `chervo-token/tests/fuzz_smoke.rs` (xorshift64*, `CHERVO_FUZZ_ITERS`) [P via stage 13a fact 12].

## Do (four builder calls; verify each step before the next, CORE 5)

### Call 1: builder sonnet/high. Part X0 (transport and engine hooks)
1. `cargo --version`, `rustc --version` (1.99.1); `BASE=$(git rev-parse HEAD)`.
2. `grep -rn "set_receive_window\|fn run_streams\|max_live" crates --include=*.rs` -> only files of facts 4, 5, 8 and their tests. Otherwise STOP.
3. X0 below; tests X0; criteria for changed crates; report.

### Call 2: builder sonnet/high. Part X1 (codec, hashing, state file)
4. `chervo-transfer` modules `limits, codec, wire_io, hash, layout, state, names`; tests X1 incl. fuzz smoke.

### Call 3: builder sonnet/high. Parts X2, X3 (sessions, writer, placement)
5. Modules `config, links, policy, placement, paths, sender, receiver, sched, writer, events, texts, api`; tests X2/X3 with an in-memory connection (pattern of fact 14) and a fake `Links`; source guard.

### Call 4: builder sonnet/medium. Part X4 (network tests, example, netns)
6. `tests/transfer_net.rs` (two engines + `QuinnTransport` on 127.0.0.1, helpers of `chervo-connect/tests/engine_net.rs` copied), `examples/node14.rs`, `tools/netns/stage14.sh` (**cannot run on this Windows host**: write, `bash -n`; the conductor runs it on the Linux box). All criteria; report.

## Interface (exact)
Lint block of `chervo-identity/src/lib.rs:6-13` in `chervo-transfer` (no unwrap/expect/indexing/panic, no print). No logging. All types holding names, paths or keys: `Debug` prints `"TypeName(..)"`, no `Display` of input. Integers on the wire big-endian.

### X0. chervo-transport-quinn and chervo-connect
```rust
// QuinnConfig (new fields; Default in brackets)
pub stream_receive_window: u32,      // [4 MiB]  applied in pre_auth_transport for both roles (bounded by the 64 KiB connection window before KK)
pub post_auth_receive_window: u32,   // [16 MiB] registry.rs promote: replaces VarInt::MAX
pub send_window: u64,                // [16 MiB] pre_auth_transport `send_window`
// QuinnTransport::new: 64 KiB <= stream_receive_window <= post_auth_receive_window, send_window >= 64 KiB, else the existing config error
```
```rust
// chervo-connect
pub struct IncomingStream<C: Connection> { pub pair: PairId, pub kind: u8, pub conn: C, pub tx: C::Tx, pub rx: C::Rx } // Debug redacted
pub struct StreamInbox<C: Connection> { /* tokio mpsc::Receiver */ }
impl<C: Connection> StreamInbox<C> { pub async fn recv(&mut self) -> Option<IncomingStream<C>>; }
pub struct ConnHold { /* Arc<Inner-ish> + pair + conn_id */ }  // Drop decrements; Debug "ConnHold(..)"
impl Engine<T, S> {
    /// Once per kind. Err(InvalidKind): 0, STREAM_ADDR_INFO, duplicates in `kinds`; Err(KindTaken): already registered.
    pub fn stream_inbox(&self, kinds: &[u8]) -> Result<StreamInbox<T::Conn>, ConnectError>;
    pub fn subscribe(&self) -> EngineEvents;
    /// None: no live connection. While any hold exists for the live conn_id, max_live never evicts it.
    pub fn hold(&self, pair: &PairId) -> Option<ConnHold>;
}
ConnectError += InvalidKind, KindTaken;           // #[non_exhaustive] already
ConnectConfig += extra_streams_in_per_min: u32 /*60, all registered kinds, per connection*/,
                 stream_inbox_capacity: usize /*32*/, max_pending_kind_reads: usize /*4 per connection*/;
```
Dispatcher (`run_streams`): `accept_bi`; acquire an owned permit of a per-connection semaphore (`max_pending_kind_reads`; waiting is back-pressure); spawn: read the kind byte under `addr_info_timeout`; `STREAM_ADDR_INFO` -> today's path (per-minute cap shared through a mutex) in this task; registered kind -> per-minute cap, then `book.is_active(pair)`, then `try_send` to the inbox (full -> drop both halves); anything else -> drop. Guest pairs never reach the dispatcher (unchanged). `max_live` eviction: candidates are live entries whose `conn_id` has no hold; if none, the new connection is kept and the limit is exceeded (bounded by the number of active transfers). Holds are stored in `State` as `pair -> (conn_id, count)`.

### X1. chervo-transfer: limits, codec, hash, state
```rust
pub const STREAM_TRANSFER_CTL: u8 = 0x31;  pub const STREAM_TRANSFER_DATA: u8 = 0x32;
pub const PROTO_VERSION: u8 = 1;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;          // frame body (type + fields)
pub const MAX_FILES_PER_OFFER: u32 = 10_000;           // = ReceiveLimits::default().max_files
pub const MAX_NAME_BYTES: usize = 1024;                // = ReceiveLimits max_path_bytes
pub const MAX_OFFER_BYTES: u32 = 2 * 1024 * 1024;      // sum of OFFER_FILES entry bytes
pub const MAX_FILE_SIZE: u64 = 1 << 40;
pub const MAX_OFFER_TOTAL: u64 = 1 << 44;              // 16 TiB
pub const MIN_BLOCK: u32 = 1 << 20; pub const MAX_BLOCK: u32 = 1 << 24; pub const MAX_BLOCKS: u32 = 1 << 16;
pub const MAX_STATE_LEN: u64 = 4 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct TransferId(pub [u8; 16]);   // random (getrandom::fill), chosen by the sender
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct TransferKey { pub pair: PairId, pub id: TransferId }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct BlockHash(pub [u8; 32]);
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct FileRoot(pub [u8; 32]);
#[derive(Clone, PartialEq, Eq)] pub struct UntrustedName(String);   // Debug "UntrustedName(..)"
impl UntrustedName { pub fn untrusted_str(&self) -> &str; pub fn len(&self) -> usize; }  // valid UTF-8, 1..=1024 bytes, no NUL; nothing else checked
#[derive(Clone)] pub struct OfferedFile { pub name: UntrustedName, pub size: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct Layout { pub block_size: u32, pub block_count: u32 }
pub fn layout(size: u64) -> Result<Layout, ProtocolError>;            // decision 3; size > MAX_FILE_SIZE -> TooLarge
pub fn block_len(size: u64, l: Layout, index: u32) -> Option<u32>;    // None: index >= count
pub fn leaf_hash(index: u32, data: &[u8]) -> BlockHash;               // decision 2
pub fn file_root(size: u64, l: Layout, leaves: &[BlockHash]) -> Result<FileRoot, ProtocolError>; // leaves.len() != count -> Malformed
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum ProtocolError { TooLong, Malformed, UnknownType, BadVersion, TooLarge, BadName, UnsupportedCodec, Unexpected, TimedOut, Closed }
pub enum Message { /* table below; no Debug */ }
pub fn encode(msg: &Message, out: &mut Vec<u8>) -> Result<(), ProtocolError>;   // appends u32 len + body
pub fn decode_message(body: &[u8]) -> Result<Message, ProtocolError>;          // body without the u32; > MAX_MESSAGE_LEN -> TooLong
/// Reads one frame: 4 bytes length (1..=MAX_MESSAGE_LEN checked before reading the body), then the body
/// within `deadline` from the first length byte. Ok(None): clean end of stream before a length byte.
pub async fn read_message<R: RecvStream>(rx: &mut R, buf: &mut Vec<u8>, deadline: Duration) -> Result<Option<Message>, ProtocolError>;
/// Exactly `n` raw bytes (manifest leaves, block payload) into `out[..n]`, progress-based stall deadline.
pub async fn read_exact<R: RecvStream>(rx: &mut R, out: &mut [u8], stall: Duration) -> Result<(), ProtocolError>;
```
**Wire format.** Stream: first byte = kind (consumed by the dispatcher on the accepting side), then frames. Frame = `len: u32` (1..=65536) + body; body = `type: u8` + fields; **fixed-size messages must have exactly the listed length**; every decoder rejects trailing bytes. Unknown `type` -> `UnknownType`; wrong stream or direction -> `Unexpected`; all are fatal for the stream (on CTL: `CANCEL{Protocol}` then close).

| type | name | stream, direction | fields (body length) |
|---|---|---|---|
| 0x01 | OFFER_HEAD | CTL S->R, first | ver u8 (=1), id [16], file_count u32 (1..=10000), total_size u64 (<= 2^44), offer_bytes u32 (1..=2 MiB) (34) |
| 0x02 | OFFER_FILES | CTL S->R | count u16 (>=1), then count × (size u64 (<= 2^40), name_len u16 (1..=1024), name: UTF-8 without NUL); entries never span frames |
| 0x03 | DECISION | CTL R->S | id [16], verdict u8: 1 Accept, 2 Decline, 3 Busy, 4 Expired, 5 Limits (18) |
| 0x04 | CANCEL | CTL both | id [16], reason u8: 1 User, 2 Unknown, 3 Protocol, 4 Limits (18) |
| 0x05 | FILE_ERROR | CTL both | index u32, code u8: 1 SourceChanged, 2 ReadError (S); 3 Damaged, 4 WriteError, 5 PlaceFailed (R) (6) |
| 0x06 | FILE_DONE | CTL R->S | index u32 (5) |
| 0x07 | DONE | CTL both | id [16] (17) |
| 0x08 | RESUME | CTL R->S, first | ver u8, id [16] (18) |
| 0x09 | RESUME_OK | CTL S->R | id [16], file_count u32, total_size u64 (29) |
| 0x10 | BIND | DATA R->S, first | ver u8, id [16] (18) |
| 0x11 | GET_MANIFEST | DATA R->S | index u32 (5) |
| 0x12 | MANIFEST | DATA S->R | index u32, block_size u32, block_count u32, root [32] (45); then exactly `block_count*32` raw bytes |
| 0x13 | GET_BLOCK | DATA R->S | index u32, block u32 (9) |
| 0x14 | BLOCK | DATA S->R | index u32, block u32, codec u8 (only 0 = raw), len u32 (== `block_len`) (14); then exactly `len` raw bytes |
| 0x15 | BLOCK_ERR | DATA S->R | index u32, block u32, code u8: 1 SourceChanged, 2 ReadError (10) |

Offer assembly (receiver): after OFFER_HEAD, OFFER_FILES frames until exactly `file_count` entries and exactly `offer_bytes` entry bytes (`8 + 2 + name_len` each) were read; sizes summed with `checked_add` must equal `total_size`; everything within `offer_read_timeout`. Any violation -> `DECISION{Limits}` and close. `BLOCK.len != block_len(...)` or `codec != 0` is rejected **before** reading the payload; `MANIFEST` fields must equal `layout(size)`; responses must answer the oldest outstanding request of that stream (in order).

**State file** `partial_dir/<hex16(SHA256(pair||id))>/state`, written as `state.tmp` + `sync_all` + rename (retry rule of decision 12): `magic "CHVXFR1\n"`, pair [16], id [16], created_unix u64, last_progress_unix u64, file_count u32, total_size u64, then per file: size u64, name_len u16, name, status u8 (0 Waiting, 1 InProgress, 2 Verified, 3 Placed, 4 Failed); InProgress adds block_size u32, block_count u32, root [32], bitmap `ceil(count/8)` bytes (unused high bits must be 0); Verified/Placed add root [32]; trailer SHA-256 of all preceding bytes. Length > `MAX_STATE_LEN` rejected before reading. The scheduler never has more than `streams` files InProgress, which bounds the state (< 3 MiB) [V]. `<i>.hashes` = exactly `block_count*32` bytes, written once after the manifest matched; on load it must reproduce `root`, else that file's progress is cleared. **Trusted from disk: nothing.** The state only says which blocks to re-hash; the hash list is re-checked against `root`; `root` is re-confirmed by a fresh MANIFEST from the sender; names stay `UntrustedName`; the pair in the state must equal the connection's `remote_pair()`.

```rust
pub fn encode_state(s: &RecvState) -> Vec<u8>;  pub fn decode_state(b: &[u8]) -> Result<RecvState, StateError>;  // RecvState pub(crate) fields, pub for fuzz via #[doc(hidden)]
```

### X2. chervo-transfer: sessions, API, events
```rust
pub struct TransferConfig {
    pub partial_dir: PathBuf,                // absolute, existing; created subdirs: generated names only
    pub streams: u8,                         // 4  (1..=8)
    pub per_stream_window: u8,               // 2  (1..=8)
    pub recv_buffer_budget: u64, pub send_buffer_budget: u64,   // 128 MiB each, >= MAX_BLOCK
    pub max_inbound_active: usize, pub max_outbound_active: usize,  // 4, 4 (1 per friend each way)
    pub max_pending_offers: usize,           // 8 (1 per friend)
    pub ctl_in_per_min: u32,                 // 6 CTL streams per friend per 60 s
    pub offer_read_timeout: Duration,        // 30 s
    pub msg_timeout: Duration,               // 10 s (body of one frame)
    pub offer_ttl: Duration,                 // 600 s unanswered -> DECISION{Expired}
    pub stall_timeout: Duration,             // 60 s without a byte on a stream with outstanding requests
    pub max_block_refetch: u8, pub max_refetch_per_transfer: u32,   // 3, 64
    pub max_serve_per_block: u8,             // 4 (sender: requests of one block per session)
    pub max_data_streams: u8,                // 8 (sender: BIND per session)
    pub resume_hold: Duration,               // 24 h
    pub partial_ttl: Duration,               // 7 days since last progress
    pub checkpoint_bytes: u64, pub checkpoint_interval: Duration,  // 64 MiB, 2 s
    pub verify_after_write: bool,            // true
    pub progress_interval: Duration,         // 250 ms
}   // impl TransferConfig { pub fn new(partial_dir: PathBuf) -> Self } with the values above; validate() at start
pub trait Links: Send + Sync + 'static {
    type Conn: Connection + Clone + 'static;
    fn connection(&self, pair: &PairId) -> Option<Self::Conn>;
    fn hold(&self, pair: &PairId) -> Option<ConnHold>;
    fn permission(&self, pair: &PairId) -> Option<Permission>;   // None: not an Active friend
    fn subscribe(&self) -> EngineEvents;
}
impl<T, S> Links for chervo_connect::Engine<T, S> where /* bounds of Engine */;
pub enum PolicyVerdict { Ask, Accept, Decline }
pub trait AcceptPolicy: Send + Sync { fn decide(&self, pair: &PairId, p: Permission, offer: &OfferView) -> PolicyVerdict; }
pub struct AskAlways;                                   // always Ask
pub struct OfferView { pub key: TransferKey, pub files: Vec<OfferedFile>, pub total_size: u64 }  // Debug redacted
pub struct CompletedFile { pub key: TransferKey, pub index: u32, pub name: UntrustedName, pub size: u64, pub root: FileRoot, /* temp: PathBuf */ }
impl CompletedFile { pub fn temp_path(&self) -> &Path; }
pub struct Placed { pub path: PathBuf }                 // Debug redacted
pub trait Placement: Send + Sync + 'static {
    /// Blocking thread, after the on-disk root matched. Must not overwrite anything; idempotent per (key, index):
    /// if the file was already placed, return its location without placing again.
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError>;
}
pub struct GeneratedNames { pub dest_dir: PathBuf }    // tests/example only; idempotence: existing final with equal root -> Ok
pub fn place_no_clobber(temp: &Path, final_path: &Path) -> io::Result<PlaceMethod>;  // decision 12; PlaceMethod { HardLink, ReserveRename }
pub struct SourceFile { pub path: PathBuf, pub name: String }   // our own file; name 1..=1024 bytes, no NUL
pub struct Transfers<L: Links> { /* Arc<Inner> */ }
impl<L: Links> Transfers<L> {
    /// Inside tokio. Sweeps partial_dir (decision "Startup"), loads states as Paused, spawns the inbox loop.
    pub fn start(links: Arc<L>, inbox: StreamInbox<L::Conn>, policy: Arc<dyn AcceptPolicy>,
                 placement: Arc<dyn Placement>, cfg: TransferConfig) -> Result<(Self, TransferEvents), TransferError>;
    pub fn send(&self, pair: &PairId, files: Vec<SourceFile>) -> Result<TransferKey, TransferError>;
    pub fn offer(&self, key: &TransferKey) -> Option<OfferView>;
    pub fn respond(&self, key: &TransferKey, accept: bool) -> Result<(), TransferError>;
    pub fn cancel(&self, key: &TransferKey) -> Result<(), TransferError>;
    pub fn retry(&self, key: &TransferKey) -> Result<(), TransferError>;     // after DiskFull / Io
    pub fn status(&self, key: &TransferKey) -> Option<TransferStatus>;
    pub fn shutdown(&self);                                                   // pause all, final checkpoint
}
#[non_exhaustive] pub enum TransferEvent {        // Clone, Debug (keys and numbers only)
    OfferReceived { key }, OfferAnswered { key, accepted: bool }, Started { key },
    Progress { key, done: u64, total: u64 },      // at most every progress_interval per key
    Verifying { key }, FileReceived { key, index: u32 }, FileDelivered { key, index: u32 },
    FileFailed { key, index: u32, reason: FileFailure }, Paused { key, reason: PauseReason }, Resumed { key },
    Completed { key }, Cancelled { key, by: Side }, Failed { key, reason: FailReason } }
pub enum PauseReason { Disconnected, DiskFull, Io, Stalled }
pub enum FileFailure { SourceChanged, SourceUnreadable, Damaged, WriteError, PlaceFailed }
pub enum FailReason { Declined, Expired, Busy, Limits, Protocol, PeerForgot, NotFriend }
pub enum TransferError { NotFriend, Busy, BadName, TooLarge, TooManyFiles, NoSuchTransfer, WrongState, Io, Shutdown }
```
`TransferEvents` = broadcast(256) like `EngineEvents`. `TransferStatus { side, state, done, total }`. Texts in `texts.rs` (Russian, no placeholders): `DISK_FULL_TEXT`, `DAMAGED_TEXT` ("Файл пришёл повреждённым несколько раз подряд и не сохранён."), `SOURCE_CHANGED_TEXT`, `PEER_CANCELLED_TEXT`, `PEER_FORGOT_TEXT` ("Друг перезапустил программу: передачу нужно начать заново."), `STALLED_TEXT`, `DECLINED_TEXT`, `EXPIRED_TEXT`.

### X3. Flow (both sides)
- **Send.** `send`: Active friend (`permission` is `Some`), ≤ 1 outbound per friend, global cap; names and sizes checked against X1 limits; files `metadata().is_file()` at call time. Open `hold`, `open_bi`, write kind `0x31`, OFFER_HEAD, OFFER_FILES; start background hashing (`spawn_blocking`, one file at a time, in offer order). Wait for DECISION up to `offer_ttl + 30 s`.
- **Receive offer.** Inbox loop: kind 0x31 -> per-friend cap `ctl_in_per_min`; first frame OFFER_HEAD -> new offer (pending per friend > 0 or global cap reached -> `DECISION{Busy}`; same key exists -> `Busy`), or RESUME -> resume path. Assemble (X1). `policy.decide` -> `Ask`: store in memory, emit `OfferReceived`; `Decline`: `DECISION{Decline}`; `Accept`: as `respond(true)`. No disk write before acceptance.
- **Accept.** Create `partial_dir/<hex>/`, write the state (all Waiting), send `DECISION{Accept}`, `hold`, open `streams` DATA streams (`0x32`, BIND). Sender accepts BIND only for its own session with this pair in state Accepted (other pair or unknown id -> drop stream; ARCH-08 Н8) and ≤ `max_data_streams`.
- **Scheduler (receiver).** Work queue in file order: for the next file (≤ `streams` InProgress) GET_MANIFEST, verify layout, read leaves, check `file_root == root`, write `<i>.hashes`, then GET_BLOCK for missing blocks. A stream sends a request only after taking `block_len` from the buffer budget; at most `per_stream_window` outstanding; reads BLOCK head, payload into the buffer, `leaf_hash` check: ok -> to the file writer; bad -> re-queue (decision 6). BLOCK_ERR / FILE_ERROR{SourceChanged|ReadError} -> file fails, partial data deleted. Stall -> drop the stream, re-queue its outstanding requests, open a new stream (counts toward `max_data_streams`). Size-0 files: no GETs, `.part` created empty.
- **Writer (receiver).** One blocking writer per transfer: open `<i>.part` (`create(true).write(true)`, never truncating an existing one on resume), seek + `write_all`; marks the block in the in-memory bitmap only after `write_all` returned; checkpoint every `checkpoint_bytes` or `checkpoint_interval`: `sync_data` of touched files, then the state file (so the state never claims an unsynced block).
- **Finalize file.** Bitmap full -> `sync_all` -> `Verifying` -> per-block re-hash from disk (`verify_after_write`) -> mismatches re-queued -> root match -> state Verified (checkpoint) -> `placement.place` (blocking) -> state Placed -> delete `<i>.hashes` -> `FILE_DONE` -> `FileReceived`. Place error -> `FILE_ERROR{PlaceFailed}`, `FileFailed`, temp kept until cancel/expiry. After every file Placed or Failed: `DONE`, both sides finish CTL, partial subdir removed, `Completed`.
- **Sender serving.** Per DATA stream: read up to `per_stream_window` requests ahead (more -> protocol error); GET_MANIFEST waits for that file's hashing; GET_BLOCK: index/block in range (else `CANCEL{Protocol}`), serve count ≤ `max_serve_per_block` (else `CANCEL{Limits}`), take budget, read the block (`spawn_blocking`), recompute the leaf: mismatch -> BLOCK_ERR + FILE_ERROR{SourceChanged}; read error -> BLOCK_ERR{ReadError}.
- **Cancel.** Local `cancel` or received CANCEL: stop, close streams, receiver deletes the partial subdir (generated names only), emit `Cancelled`. Cancel of a pending offer by the sender = CANCEL on CTL; the receiver drops the offer.
- **Disconnect / resume.** `closed()` of the held connection -> `Paused{Disconnected}`; the receiver waits until all old stream and writer tasks finished, then on a new connection opens CTL with RESUME; sender: session found within `resume_hold` -> drops the old session's streams first, `RESUME_OK` (receiver checks `file_count`, `total_size`) -> new DATA streams; unfinished files re-fetch their MANIFEST and compare `root` (mismatch -> that file restarts). Session unknown -> `CANCEL{Unknown}` -> receiver deletes partial data, `Failed{PeerForgot}`.
- **Startup (receiver).** For every entry of `partial_dir`: skip anything that is not a real directory (`symlink_metadata`, symlinks never followed) or not named 32 hex; invalid state or `last_progress` older than `partial_ttl` -> delete only files matching our name patterns, then `remove_dir` (non-empty stays); valid -> load as Paused, re-hash done blocks on first resume (`Verifying`), clear failures.
- **Friend no longer Active** (removed, blocked): its transfers are cancelled locally, partial data deleted.

## Do not
- No path from an `UntrustedName`; no `create_dir_all` of anything but `partial_dir/<hex>`; no `set_permissions`, no executable bits, no `std::process`/`Command`; nothing is opened or executed after receiving.
- No new crate, no `unsafe`, no compression codec (Q1), no change of KK, knock, ADDR_INFO, invite formats, friends file format.
- No socket in `chervo-transfer` (`UdpSocket`, `TcpStream`, `tokio::net`).
- No logging of names, paths, addresses, keys.

## Untrusted input
- Frames on CTL/DATA: codec with exact lengths and caps (X1); deadlines `msg_timeout`, `offer_read_timeout`, `stall_timeout`.
- Raw manifest leaves and block payloads: exact lengths decided by us from `layout(size)`, checked before reading.
- Names: opaque `UntrustedName`; only UTF-8/NUL/length checks here; meaning in stage 15.
- State and `.hashes` files: bounded, checksummed, re-verified (X1 "Trusted from disk: nothing").
- Stream kind byte: stage-13 rule plus the inbox caps (X0).

## DoS from an authenticated hostile friend (bounds)
Pending offers 1 per friend / 8 total, each ≤ 2 MiB of names; CTL streams 6/min per friend; kind reads 4 concurrent per connection; inbox 32; data streams ≤ 8 per session; memory for blocks ≤ the two budgets (128 MiB each); QUIC buffering ≤ 16 MiB per connection; disk ≤ the accepted sizes (blocks outside `layout(size)` are impossible); re-fetches ≤ 64 per transfer; serves ≤ 4 per block; sender hashing once per file per session; stalls cut after 60 s. A friend can still keep a transfer slot paused for `resume_hold` (24 h) and make us read our offered files up to 4 times each [V].

## Carried requirements (where each is met)
| Source | Requirement | Where |
|---|---|---|
| ARCH-08 Н7 | write only verified blocks, final name after whole-file hash | dec. 5, X3 finalize; `block_written_only_after_verify`, `final_name_only_after_root_match` |
| ARCH-08 Н8 | key (pair, id); only the same pair may bind/resume | `TransferKey`, X3 accept/resume; `bind_other_pairs_transfer_dropped` |
| ARCH-08 Н9 | on-disk log of verified blocks, re-verify after restart, schedule by blocks | state file, dec. 8; `receiver_restart_resumes_with_reverify` |
| ARCH-08 Н10 | out-of-range = protocol error, bounded retries | X3 serving, dec. 6; `out_of_range_get_is_protocol_error`, `serve_cap_per_block` |
| ARCH-08 Н11 | bitmap snapshot after old writers stopped | X3 resume; `resume_waits_for_old_writers` |
| ARCH-09 | 16 streams, window `VarInt::MAX`, stream window only before KK | X0 windows; `post_auth_window_caps_unread_data` |
| 13 spec | stream kinds through the engine; `max_live` must not cut busy connections | X0 inbox, holds |
| T2 | bounded codec, bomb protection, fuzz | X1; bombs: Q1 rules |
| U10a-2 p.2 / T10 | auto-accept off by default; executable warning | dec. 11 (always ask here; list and auto-accept in 15) |

## Tests (exact names)
X0 (`chervo-transport-quinn/src/tests/windows.rs`; `chervo-connect/src/tests/inbox.rs` with the fake of `kit.rs`): `config_rejects_bad_windows`, `post_auth_window_caps_unread_data` (peer writes on 8 accepted, unread streams: accepted bytes ≤ `post_auth_receive_window` + slack within 2 s), `stream_window_applied_preauth_still_capped` (before KK the 64 KiB connection window holds), `inbox_receives_registered_kind`, `inbox_kind_rules` (0, 0x21, duplicate, second registration), `unregistered_kind_dropped`, `inbox_full_drops_stream`, `inbox_per_min_cap`, `inbox_not_active_dropped`, `inbox_never_guest`, `slow_kind_byte_does_not_block_others` (4 silent streams; an ADDR_INFO stream answered after at most one `addr_info_timeout`), `addr_info_no_longer_blocks_accept`, `hold_prevents_max_live_eviction`, `hold_released_on_drop`, `hold_of_replaced_conn_ignored`, `subscribe_second_receiver_gets_events`.
X1 (`chervo-transfer/src/tests/{codec,hash,state,fuzz}.rs`): `roundtrip_every_message`, `fixed_messages_exact_length` (each: one byte shorter/longer -> Malformed), `frame_len_zero_rejected`, `frame_len_over_max_rejected_before_body` (counting reader: no body byte read), `unknown_type_rejected`, `wrong_version_rejected`, `trailing_bytes_rejected`, `offer_name_bounds` (0, 1, 1024, 1025), `offer_name_invalid_utf8_and_nul_rejected`, `offer_entry_across_frames_rejected`, `offer_totals_must_match` (count, bytes, size sum, `checked_add` overflow), `offer_caps` (10001 files, 2 MiB + 1, size 2^40 + 1, total 2^44 + 1), `block_len_mismatch_rejected_before_payload`, `codec_nonzero_rejected`, `manifest_layout_mismatch_rejected`, `read_message_deadline` (paused time), `read_message_clean_eof`; `sha256_known_answer` (ring: "abc" -> `ba7816bf...15ad`), `layout_table` (0, 1, 1 MiB, 1 MiB+1, 64 GiB, 1 TiB; 1 TiB+1 -> TooLarge; count ≤ 65536 everywhere), `leaf_binds_index_and_len`, `root_binds_size_layout_order` (swap two leaves, change size, change block_size -> different root), `root_matches_independent_computation` (manual buffer + `ring::digest::digest`); `state_roundtrip`, `state_checksum_mismatch_rejected`, `state_truncated_rejected`, `state_len_cap`, `state_bitmap_high_bits_rejected`, `state_inprogress_cap`, `hashes_file_mismatch_clears_progress`; fuzz smoke `fuzz_smoke_codec` (random and mutated valid frames through `decode_message` and `read_message`; no panic; every accepted message re-encodes to the same bytes), `fuzz_smoke_offer_assembly`, `fuzz_smoke_state`.
X2/X3 (`chervo-transfer/src/tests/*.rs`, in-memory connection pair + fake `Links`, `#[tokio::test(start_paused = true)]` where timing matters; hostile peers speak the wire directly through the pub codec): `offer_accept_transfer_identical` (files of 0, 1, 1 MiB, 1 MiB+1, 37 MiB random bytes; byte compare + root), `decline_writes_nothing` (partial_dir empty), `no_disk_write_before_accept`, `offer_expires_after_ttl`, `second_offer_same_friend_busy`, `pending_offers_global_cap`, `ctl_streams_per_min_cap`, `always_ask_even_with_auto_accept_permission`, `substituted_block_rejected_and_refetched` (hostile sender flips one byte of block 3 once; re-requested; every block written exactly once (writer counter); result identical), `persistent_bad_block_fails_file` (after 3 re-fetches: `FileFailed{Damaged}`, no final file, partial deleted), `refetch_cap_per_transfer`, `block_written_only_after_verify`, `block_len_lie_rejected_before_read`, `out_of_range_get_is_protocol_error`, `serve_cap_per_block`, `get_pipeline_cap`, `bind_unknown_transfer_dropped`, `bind_other_pairs_transfer_dropped`, `data_streams_cap`, `source_changed_detected_by_sender` (modify the source after hashing -> `FileFailed{SourceChanged}`, no final file), `disconnect_mid_transfer_resumes` (close at ~50 %; new connection; RESUME; identical; verified blocks not requested again), `resume_waits_for_old_writers`, `resume_root_mismatch_restarts_file`, `receiver_restart_resumes_with_reverify` (drop `Transfers` at ~50 %, flip a byte of one done block in `.part`, restart: `Verifying`, only that block re-fetched, identical), `checkpoint_order_sync_before_state` (writer hook records sync_data before every state write), `interrupted_file_not_visible_under_final_name` (interrupt at manifest, mid-blocks, before final check, before placement: `dest_dir` lists only previously placed files; partial data only under `partial_dir`), `final_check_mismatch_refetches_block` (corrupt `.part` after the last write, before the final re-read), `final_name_only_after_root_match` (placement hook called only after the on-disk root matched), `disk_full_pauses_and_retry_resumes` (writer hook returns `StorageFull`), `cancel_by_receiver_cleans_partial`, `cancel_by_sender_cleans_partial`, `cancel_pending_offer`, `resume_unknown_session_peer_forgot`, `sender_drops_session_after_resume_hold`, `stall_timeout_requeues`, `buffer_budget_respected`, `friend_blocked_cancels_transfers`, `two_way_simultaneous`, `place_no_clobber_existing_kept` (final exists: `AlreadyExists`, content unchanged, temp kept), `place_no_clobber_fallback_path` (forced fallback), `generated_names_idempotent`, `startup_sweep_deletes_only_ours` (foreign file in a subdir survives; `#[cfg(unix)]`: symlinked dir not followed), `partial_ttl_expiry`, `progress_rate_limited`, `src_guard` (CRLF normalized scan of `src/` excluding `src/tests/`: `untrusted_str(` only in `names.rs`, `codec.rs`, `state.rs`; `Path::new(`, `PathBuf::from(`, `.join(` only in `paths.rs`, `placement.rs`, `config.rs`; absent: `set_permissions`, `PermissionsExt`, `std::process`, `Command::new`, `tokio::net`, `UdpSocket`, `TcpStream`, `remove_dir_all`).
X4 (`chervo-transfer/tests/transfer_net.rs`, two `Engine` + `QuinnTransport` on 127.0.0.1, Windows included): `net_media_samples_identical` (generated in test code, no downloaded files: JPEG with an EXIF APP1 segment, PNG with tEXt, HEIC-like `ftypheic` ISO-BMFF, MP4 and MOV (`ftyp`/`moov`/`mdat` with 40 MiB random), WAV RIFF 10 MiB, FLAC header + random, MP3 with an ID3v2 tag, one 200 MiB random file; byte compare and SHA-256 equal, sizes equal, no extra files), `net_disconnect_mid_transfer_resumes` (receiver transport rebuilt on the same port at ~40 %), `net_rebind_mid_transfer_completes` (receiver `rebind` to a new local port: migration or resume, identical), `net_receiver_restart_resumes`, `net_streams_1_and_8_identical`, `net_two_way_simultaneous`. `examples/node14.rs` (two processes on one Windows machine or two machines; `--port`, `--book-dir`, `--invite-out/--invite-in`, `--sas-auto-confirm`, `--send FILE...`, `--dest DIR`, `--accept` (explicit flag: answers the UI hook with accept), prints only progress numbers and final SHA-256 of received files, never names or addresses).
netns (`tools/netns/stage14.sh`, Linux + root, reuse helpers of `stage13.sh`; **not run here**): XFER (white-white, 1 GiB random, `cmp`), DROP (nft drop 45 s at ~30 %, longer than idle 30 s -> new connection, resume, `cmp`), ADDRCHANGE (receiver `ip addr del/add` mid-transfer, `cmp`), KILLRECV (`kill -9` receiver at ~50 %, restart, re-verify, `cmp`), TBF (tc tbf 50 Mbit/s: MB/s recorded as information only), CAPTURE (nft counters: packets only between the two nodes).

## Acceptance criteria (each as a command; output in report)
- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked` (all names above except `#[ignore]`)
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`
- [ ] `cargo tree -p chervo-transfer -e normal | grep -E 'quinn|rustls|miniz|zstd|lz4|brotli'; test $? -eq 1`
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'chervo-transfer|quinn|rustls'; test $? -eq 1`
- [ ] `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-transfer fuzz_smoke -- --nocapture` (iterations per target in output)
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-transfer --test transfer_net || exit 1; done` (on Windows locally)
- [ ] `for i in $(seq 20); do cargo test -q --locked -p chervo-transfer -- resume_ disconnect_ substituted_ interrupted_ || exit 1; done`
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-connect --test engine_net || exit 1; done` (no regression from X0)
- [ ] `bash -n tools/netns/stage14.sh`
- [ ] Manual (conductor, Windows): two `node14` processes, a real photo/video/audio file of the owner's choice, `certutil -hashfile <f> SHA256` equal on both sides (write the command output, not a summary).
- [ ] CI: all jobs green (3 OS, supply-chain).

## Where verified
- **Windows locally and CI (3 OS):** X0-X3 (in-memory, paused time), X4 on loopback, placement on NTFS/ext4/APFS.
- **Linux netns (conductor's Linux box), not here:** XFER, DROP, ADDRCHANGE, KILLRECV, TBF, CAPTURE.
- **Real networks and disks (stage 16):** speed, CPU, HDD cost of pre-hashing, ТСПУ.

## Not verified in this stage (write in report, do not claim)
- Any speed; whether 4 streams beat 1 on one connection (ARCH-08: no gain in emulation).
- std `rename` replace semantics and `hard_link` errors on FAT/exFAT/network shares (only the forced-fallback test); the 0-byte window of the fallback.
- Durability: macOS `sync_all` (F_FULLFSYNC or not) [D], no directory sync on Windows, what survives a real power cut.
- That quinn's connection window really bounds memory for unread streams beyond the X0 test.
- `ErrorKind::StorageFull` and raw OS codes per OS (only the injected test).
- That synthetic media samples represent real files (format-agnostic by design; the manual run covers one real file).

## Stop conditions
Spec contradicts code; a fact above does not match the source; a new crate, `unsafe`, or a change of KK/knock/ADDR_INFO/invite/friends formats is needed; `chervo-connect` would need to depend on `chervo-transfer`; a test needs a path built from an untrusted name; a criterion cannot be checked; a resume or net test is unstable after two fix attempts. Stop and report.

## Limit
At most 2 review-fix rounds, then report to the owner.

## Builder report (max 25 lines per call)
Changed files; criteria commands with last output lines; fuzz iterations; not done; deviations with reason; what was not runnable on Windows.

## Process and executors
1. Call 1 (X0): `combine-builder` sonnet/high. 2. Call 2 (X1): sonnet/high. 3. Call 3 (X2, X3): sonnet/high. 4. Call 4 (X4): sonnet/medium.
5. `combine-verifier` (sonnet/low): all criteria. 6. `combine-security` (opus/high) once on the full diff: codec and offer assembly, read-before-check order, state file trust, re-fetch and serve caps, budgets, inbox caps and dispatcher concurrency, holds vs `max_live`, placement and the path boundary guard, cancel/cleanup deleting only our files, resume binding to the pair.
Critical: X0 dispatcher/inbox/windows, X1 entirely, X2/X3 receiver, writer, finalize, placement, resume, cleanup. Not critical: texts, events, example, netns script.

## Requirements for other stages (not implemented here)
- **15:** `chervo-receive` implements `Placement` (sanitized relative path inside the chosen root, folders, collisions -> new name, idempotent per (key, index), same-volume partial dir or verified copy) and `AcceptPolicy` (auto-accept only with `AutoAcceptLimits`, plus a rolling per-friend byte/file quota per day, never when any name is an executable type, sanitizer failure -> Ask); the executable-type list; decide Windows Mark-of-the-Web (`file:Zone.Identifier` stream, possible with std) and macOS quarantine (needs xattr, i.e. FFI or a crate) for executables; display-safe rendering of names (bidi/control characters) for the UI.
- **16:** speed table by streams/window; HDD pre-hash cost; DROP/ADDRCHANGE on real networks.
- **17:** libFuzzer for `decode_message`, offer assembly, `decode_state`; check that no name/path reaches logs; `Debug` redaction.
- **18:** screens from `TransferEvent`; incoming offer with friend name (from the book), file count, total size, executable warning (stage 15); progress; `retry` after disk full; cancel; revocation over the live connection (stage-13 carry, deferred here).
- **THREAT_MODEL (conductor, after acceptance):** T2 bounds of "DoS from an authenticated hostile friend"; T4: the partial state stores offered file names in plain form inside the receive folder until done or expired.

## For the owner (кратко, по-русски)
- Передача: отправитель предлагает файлы (имена, размеры), получатель **всегда сам** нажимает «принять» или «отклонить»; автоприём с лимитами и предупреждение об исполняемых файлах — этап 15. До принятия на диск ничего не пишется.
- Получатель сам запрашивает блоки по нескольким параллельным потокам (по умолчанию 4, окно настраивается); каждый блок сверяется с хэшем (SHA-256 из уже используемой библиотеки ring) до записи на диск; несовпавший запрашивается снова (не больше 3 раз, потом файл помечается повреждённым и не сохраняется). После последнего блока весь файл перечитывается с диска и сверяется с хэшем всего файла; только потом он получает итоговое имя. Недокачанный файл лежит только во временной папке под служебным именем.
- Файлы не перекодируются и не меняются: байты идут как есть. Цена: отправитель один раз читает файл заранее, чтобы посчитать хэши (на HDD это заметно для больших видео).
- Обрыв связи и смена IP — пауза, затем докачка с того же места; перезапуск получателя — тоже докачка, но сначала уже принятое перепроверяется с диска. Перезапуск отправителя — передачу нужно начать заново.
- Злой друг ограничен: одно ожидающее предложение, лимиты потоков, памяти, повторов; на диск не больше принятого размера.
- Сжатия в этом этапе нет (вопрос 1).
- Проверяется на Windows и в CI (локальная петля), стенд netns — на Linux-машине. Скорость не заявляется.

## Open questions for the owner
**Q1. Compression.** Options: (A) **defer**: the wire already has a per-block `codec` byte (only 0 = raw accepted); photos (JPEG/HEIC), video (H.264/H.265 in MP4/MOV) and MP3/AAC are already compressed, so the win is near zero; only WAV, uncompressed RAW/TIFF and text would gain; (B) deflate via `miniz_oxide 0.8.9` (pure Rust, `forbid(unsafe_code)`, bounded `decompress_to_vec_with_limit`; adds 2 packages `miniz_oxide` + `adler2`, both in the local registry, not in the lock); deflate compresses slowly [D, not measured] and could become the bottleneck on fast links; (C) zstd: C library (`zstd-sys` via `cc`), not in the local registry [NP]. Bomb rules for any later codec (binding): compressed payload `len < block_len`; output buffer exactly `block_len` with a hard cap, output length must equal `block_len`; the leaf hash is checked on the decompressed bytes; the sender sends compressed only if it saves ≥ 1/16 of the block and stops trying for a file after 4 blocks without gain. **Recommendation: A** (owner priority: byte identity and integrity; no new hostile decoder); revisit after the stage-16 speed table if WAV/RAW transfers matter.

## Rev. 2 addendum (combine-architect, 2026-10-17, after build at 3efa281)
Labels as above. **Nothing was run by me**; the numbers below are the builder's measurements or marked as assumptions. Overrides revision 1 where they differ. Executor: `combine-builder` sonnet/high, one call, R2-2 first (smaller, unblocks the net criteria), then R2-1; `combine-security` re-checks both (critical: wire change, receiver deadlines, connection identity).

### R2-1. Large files: the receiver waits for hashing by progress, not by a fixed stall
**Problem** [P]. The receiver reads the MANIFEST answer under `stall_timeout` (`rstream.rs:340-345`). The sender answers GET_MANIFEST only after `wait_hash` (`sender.rs:854-859`); hashing starts in the background at offer time, one file after another in offer order (`sender.rs:466-474`, `376-401`), and sends nothing while it runs. If hashing of a file (and of all files before it in the offer) is not finished `stall_timeout` after the request, the stream stalls; after `3 × streams` stalls in a row the transfer pauses `Stalled` (`rstream.rs:190-216`) until `retry`. Builder: 4 GiB on warm SSD hashes in 2.8 s. Extrapolated limit: ≈ 87 GiB on warm SSD, ≈ 9 GB on a cold HDD at ~150 MB/s [V, assumption, not measured].

**Rejected.** Hashing before OFFER: the offer would appear minutes to hours late, and the receiver's decision time would no longer overlap with hashing. A larger fixed GET_MANIFEST deadline: it does not detect liveness, so it is either too short for large files on HDD or too long for a dead sender. Streaming leaves before the root: blocks would be accepted before the root binds them, which changes the trust model of decision 2. Keepalive frames on DATA streams: every one of `streams` streams would need it, and every stream would keep a timer running during the wait.

**Decision.** The sender reports hashing progress on CTL. The receiver does not request a file's manifest until progress covers that file. While waiting, liveness = progress within `stall_timeout`, plus a minimum average hashing rate.

**Wire** (added to the X1 table; no version bump, because PROTO_VERSION 1 has not been released [V: the conductor confirms nothing was shipped]):

| type | name | stream, direction | fields (body length) |
|---|---|---|---|
| 0x0A | HASH_PROGRESS | CTL S->R, only after DECISION{Accept} or RESUME_OK | hashed u64 (9) |

`hashed` = bytes of the offer hashed so far, in offer order; `prefix(i) = size_0 + ... + size_i`. A file whose hashing failed counts with its full size; its FILE_ERROR is queued on CTL before the HASH_PROGRESS that covers it.

**Sender.**
- `SendSession.hashed: AtomicU64`. `hash_source` (`fsio.rs:38`) gets `progress: &AtomicU64` and adds each block's length after hashing it; `hash_all` does `fetch_max(prefix(i))` after `send_replace` of file i (Ready or Failed).
- Per attempt, entering Accepted (after DECISION{Accept} in `ctl_reader`, `sender.rs:576`; right after RESUME_OK in `handle_resume`, `sender.rs:706-718`): one ticker task (`spawn_att`). It sends HASH_PROGRESS{current} immediately, then every `HASH_PROGRESS_INTERVAL` (const 1 s) only if the value grew, and immediately when the value reaches `total`. It ends after the `total` frame or when the attempt stops. Never sent in Offering. At most `duration / 1 s + 2` frames per attempt.
- `wait_hash` in `serve_one` stays. It covers the short race in which the counter reaches `prefix(i)` before the watch is set.

**Receiver.**
- `RecvSession.hashed: u64`, kept in memory only (0 after restart; not in the state file).
- `ctl_reader` (`rstream.rs:107-145`) accepts HASH_PROGRESS. The first frame of an attempt must be `>=` the session value; later frames must be `>` the previous one; every frame must be `<= total`. A frame after `total` was reached in this attempt, a frame before acceptance (offer phase), or any other violation -> `CANCEL{Protocol}` (`protocol_fail`). On an accepted frame: store the value, `wake.notify_waiters()`, emit `Preparing` (rate-limited by `progress_interval`; the final value is always emitted).
- Scheduler: `Work::Manifest{file}` is issued only if `prefix(file) <= hashed`. Otherwise the scheduler returns `Wait` for that file (size-0 files unchanged). The existing `stall_timeout` around the MANIFEST read stays.
- Hash watchdog: one task per attempt, stopped with the attempt. It is active while an unfinished non-empty file has `prefix(file) > hashed`. It ends the attempt with `End::Pause(PauseReason::Stalled)` when either (a) no HASH_PROGRESS was accepted for `stall_timeout` (the first wait counts from attempt start), or (b) time since attempt start exceeds `stall_timeout + (total - h0) / min_hash_rate`, where `h0` = the first value of the attempt. `retry` starts a new attempt with new deadlines; sender hashing is per session, not per attempt, so it continues.
- `TransferConfig.min_hash_rate: u64` = 8 MiB/s; `validate()`: `>= 1 MiB/s`. `TransferEvent::Preparing { key, hashed: u64, total: u64 }` on both sides (the sender emits from its own counter, same rate limit). `PREPARING_TEXT` = "Отправитель готовит файлы к передаче: считает контрольные суммы."

**Bounds** (add to "DoS from an authenticated hostile friend"). A friend that pretends to hash holds, per attempt: one inbound slot (1 per friend), one CTL stream and up to `streams` idle DATA streams, with no buffer budget and no data on disk except the state file. It can do this for at most `stall_timeout + total / min_hash_rate`: about 36.4 h for 1 TiB; for the 16 TiB offer cap, about 24 days. Then the transfer pauses `Stalled`; the user can cancel at any time. The bound is proportional to the size the user accepted. Honest senders whose average rate is below 8 MiB/s (network shares, USB 2 under load) will also pause `Stalled` and need `retry` [V]. **Residual of the same class, not changed here (for combine-security):** `read_exact` resets its deadline on every chunk, so a hostile sender can already trickle a BLOCK payload at about 1 byte per < 60 s and hold the slot indefinitely. A rate floor for payload reads needs a separate decision.

**Tests.** Codec: HASH_PROGRESS in `roundtrip_every_message`, `fixed_messages_exact_length`, `fuzz_smoke_codec`. In-memory, paused time. New hook point `HookPoint::HashBlock { file, block }`, called in `hash_source` before each block; tests gate it.
- `manifest_waits_for_hash_progress`: raw sender through the pub codec, 2 files. No GET_MANIFEST for file 1 on any DATA stream before HASH_PROGRESS `>= prefix(1)`; after it, the request is seen.
- `slow_hash_longer_than_stall_completes`: 37 MiB file, one hash block released every `stall_timeout / 2`, total hashing ≈ 10 × `stall_timeout`. Result identical, no `Paused`, `Preparing` values increase.
- `hash_progress_silence_pauses_stalled`: one frame, then silence. `Paused{Stalled}` exactly `stall_timeout` after the frame, not one tick earlier.
- `hash_progress_trickle_capped`: +1 byte every `stall_timeout / 2`, with `min_hash_rate = 1 MiB/s` and total 64 MiB. `Paused{Stalled}` no later than `stall_timeout + 64 s + 1 s`.
- `hash_progress_rules`: decrease, repeat within an attempt, `> total`, after `total`, before DECISION, 8- and 10-byte body. Each -> `CANCEL{Protocol}` (body length -> `Malformed`).
- `hash_progress_across_resume`: disconnect while the hash gate is held; resume; the first frame is `>=` the previous value; every source block is hashed exactly once (hook counter); result identical.
- `sender_hash_progress_frames_bounded`: 4 s of hashing (paused time) -> at most 6 frames; the `total` frame is sent without waiting for the next tick.
- Manual (`--ignored`, in the report): the existing big test with `CHERVO_BIG_GIB=4 CHERVO_BIG_STALL_MS=200` now completes without `Stalled`.

### R2-2. Flaky `net_disconnect_mid_transfer_resumes`: connection ids are reused (product bug)
**Root cause** (confidence high, about 85%; from the source, not reproduced by me): `crates/chervo-transport-quinn/src/conn.rs:160-162` returns `quinn::Connection::stable_id()` as `conn_id()`. In quinn 0.11.12 `stable_id` is the heap address of the connection state (`connection.rs:934-936`), and its documentation promises only that it is "fixed for the lifetime of the connection" (`:598-603`). Once the old connection and all its clones are dropped, the allocator can give the same address to the next connection, so a **new** connection gets the **old** id. This breaks the trait contract (`chervo-transport/src/lib.rs:127`).

**Evidence from the failure.** The entry with `old_x` reported `closed x=false`, but the test had called `close()` on `old_x`. quinn sets `error` synchronously in `close` (`connection.rs:435-437, 1248-1251, 1228-1229`), and `closed()` returns immediately once `error` is set (`:376-381`). So the entry is not the old connection; it is a live new one with a recycled id. The engine does not keep a stale connection: the live entry holds a clone, and the `closed()` watcher keeps one until `on_closed` has run (`engine.rs:477-484, 528-531, 541-557`), so the address cannot be reused while the old entry exists. `closed_now` (`engine.rs:247-251, 462-467`) and simultaneous-open selection are not involved.

**Why this is a product bug, not only a test artifact.** Everything that keeps an id after its connection is gone misreads a recycled one:
1. `chervo-transfer/src/receiver.rs:602-604`, with `dead` from `:637`: the receiver ignores a live new connection whose id equals the dead one and never resumes over it while it lives (with keepalive, possibly for hours). This is the reconnect / IP-change resume path.
2. `chervo-connect/src/engine.rs:486`: the old connection's hold is kept for the new one with the same id, and its later `release` (`inbox.rs:98-107`) decrements the new connection's count, so `max_live` can evict a busy connection.
3. The test's `wait_new_conn` (`tests/transfer_net.rs:482-511`) waits for a different id. This is the observed message.

Not explained: the builder's "both sides dial, offer never arrived within 30 s" variant. Run it 20× after the fix and report; if it still fails, it needs a separate investigation (stop condition).

**Fix.**
1. Contract, `chervo-transport/src/lib.rs:127`: "unique within the process and never reused, also after the connection was dropped; equal for clones". The fakes (`chervo-connect/src/tests/kit.rs`, `chervo-transfer/src/tests/{fake,kit}.rs`, `chervo-token/tests/*`) keep or get a monotonic counter.
2. quinn adapter: `static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1)` (`fetch_add(1, Relaxed)`). Registry `Entry` (`registry.rs:22-31`) gets `id: u64`, assigned in `admit` when the entry is inserted. `QuinnConn` gets `id: u64`, and `conn_id()` returns it. `Verdict::Lose` (`registry.rs:39-42`) carries the winner's id, so `Promoted::Lost` (`:211-215`) has the same id as the `Winner` the engine already holds; the early return at `engine.rs:455-457` depends on this. `Registry::remove` (`:146-154`, called at `:253`) uses this id. After the change, `grep -n stable_id crates/chervo-transport-quinn/src --include=*.rs` may match only tests.
3. Defense in depth, receiver: `wait_conn` (`receiver.rs:590-615`) drops the `dead` filter. A connection is usable iff `connection(pair)` is `Some` and `!is_closed`. `Outcome::Disconnected` loses its id. This also fixes `receiver.rs:936-937`: after a lost DONE echo on a still-live connection, the receiver now sends RESUME over that connection (the sender answers DONE within `resume_hold`) instead of waiting for another one. No hot loop: a failed handshake on a live connection returns `Retry`, which sleeps `poll`.
4. `transfer_net.rs`: no change needed; comparing ids becomes valid with the fix.

**Tests.**
- Step 0, before the fix; report the number: `#[ignore]` probe `stable_id_reuse_probe` in `chervo-transport-quinn/src/tests/race.rs`. 64 cycles of connect, close both ends, drop all clones, `wait_idle`; count repeated `stable_id` values; 3 runs on Windows. If the count is 0 in all runs, the hypothesis is weaker: still apply the fix (the contract requires it), report this, and keep the flake open.
- `conn_id_never_reused` (quinn, loopback, same cycles): ids strictly increase and are all distinct.
- `lost_duplicate_returns_winner_id`: on simultaneous open, `Lost.conn_id() == Winner.conn_id()`; extend `race.rs:392-401`.
- `resume_over_new_conn_with_reused_id` (`chervo-transfer/src/tests/resume.rs`, fake Links, paused time): connection A (id 7) closed at ~50 %, connection B (also id 7) becomes live; `Resumed` within `poll + msg_timeout`; result identical. It must fail deterministically on 3efa281 (`wait_conn` skips id 7); the builder shows it failing before fix step 3 and passing after.
- `resume_after_lost_done_echo_same_conn`: the fake drops the DONE echo, the connection stays live; the receiver resumes over the same connection, gets DONE, emits `Completed`.
- `hold_not_inherited_by_new_conn` (connect fake): hold on conn 1; conn 1 closed and removed; conn 2 live; dropping the old hold leaves conn 2's hold count unchanged.
- Criterion (Windows): `for i in $(seq 100); do cargo test -q --locked -p chervo-transfer --test transfer_net net_disconnect_mid_transfer_resumes || exit 1; done`. At the observed rate of 1 in 14-40 runs, 100 clean runs leave about a 3 % chance that the flake is still there [V]. All stage criteria still apply.

### Для владельца (кратко, по-русски)
- **Большие файлы.** Перед отдачей файла отправитель считает его контрольные суммы. Сейчас получатель ждёт ответа не дольше 60 с, и для очень больших файлов передача встаёт на паузу. По оценке (это не замер), такое начинается примерно с 9 ГБ на медленном HDD и с 87 ГБ на SSD. Решение: отправитель раз в секунду сообщает, сколько уже посчитано, а получатель ждёт, пока счёт идёт, и показывает «отправитель готовит файлы». Пауза с кнопкой «повторить» будет, только если счёт стоит 60 с или в среднем идёт медленнее 8 МБ/с. Злой друг может так держать одну передачу занятой, но не дольше этого предела, и её всегда можно отменить. Памяти и места на диске это не занимает.
- **Плавающий тест.** Это настоящая ошибка, а не ошибка теста. Номером соединения служил адрес в памяти, и новое соединение могло получить номер старого. Тогда получатель мог не продолжать докачку по новому соединению, пока оно живо. Исправление: номера соединений выдаёт счётчик, и они никогда не повторяются; кроме того, получатель проверяет, живо ли соединение, а не сравнивает номер. Добавляются тесты, которые воспроизводят ошибку без сети.
- Порог 8 МБ/с можно менять в настройке. Он важен, только если вы отправляете с сетевых папок или медленных флешек.
