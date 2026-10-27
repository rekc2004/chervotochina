# SPEC 14б: offer survives replacement or loss of the connection          criticality: КРИТИЧНЫЙ (parts R1, R2, S1)

Author: combine-architect (opus), 2026-10-23, revision 1. Labels: [P] verified by me in the source at 7f78727 (file:line); [V] my inference; [NP] not verified. **Nothing was run by me.** No new crates, no wire-format change (no new message type, no version bump), no change to `chervo-connect`.

Goal: an offer that is waiting for the receiver's answer survives the loss or replacement of the connection. The sender re-sends the same offer (same `TransferId`, same content) on the next working connection, with bounded tries and time. The receiver keeps the pending offer (and the decision UI state) and re-attaches it only to an identical re-offer from the same pair. When the offer finally cannot be delivered, the reason is `FailReason::Disconnected`, never `Protocol`. `no_leaks` waits for a stable connection before sending.

Read: this file; `docs/reports/FLAKE-NOLEAKS-2026-10-23.md`; `docs/specs/stage-14-transfer.md` (X1 table, X3 "Receive offer", "Disconnect / resume", Rev. 2 R2-2, Rev. 4 N1); `crates/chervo-transfer/src/{sender.rs,api.rs,receiver.rs,inner.rs,events.rs,config.rs,limits.rs,texts.rs}`; `crates/chervo-transfer/src/tests/{kit.rs,fake.rs,resume.rs,flow.rs}`; `crates/chervo-receive/tests/no_leaks.rs`. Search nothing else, except the greps listed in "Do".

## Facts from the source
1. Sender, loss while `Offering`: `attempt_lost` calls `finish_send(Failed(Protocol))` (`sender.rs:380-381`) [P]. `sender_main` does the same when `open_bi` fails or times out (`:556-560`) or the offer write fails (`:565-569`) [P]. There is no retry.
2. Sender TTL task (offer_ttl + 30 s) is spawned per attempt through `spawn_att`, ended by `s.stop` (`sender.rs:583-598`) [P]. `hash_all` is spawned once, after the first successful write (`:572-580`) [P].
3. Sender `handle_resume` answers `CANCEL{Unknown}` when the session is `Offering` (`sender.rs:789-797`) [P]. Otherwise it stops the old attempt, installs a new one, writes RESUME_OK, sets `Accepted`, emits `Resumed` only if it was `Paused` (`:798-830`) [P].
4. Receiver, new offer: after assembly the receiver answers `Busy` if `reg.inb` already has the key, has any session of that pair, or has `max_pending_offers` pending (`api.rs:452-470`) [P]. A pending offer is served by `pending_task` with the CTL of the first connection (`api.rs:507-576`).
5. Receiver, loss while pending: in `pending_task` EOF, read error, a non-CANCEL message other than HASH_PROGRESS, and `conn.closed()` all give `Pending::Lost`. That path removes the session and emits `Cancelled{by: Sender}` (`api.rs:518-528, 567-574`) [P]. This is variant B of the report.
6. `offer_ttl` on the receiver is a sleep inside `pending_task`, counted from its start (`api.rs:520`) [P].
7. `accept_flow` claims a slot, creates the session dir, persists, then runs `recv_supervisor(inner, s, Some(FirstCtl{..}))` (`api.rs:579-653`) [P]. `recv_supervisor` also accepts `None` and then waits for a link and sends RESUME (`receiver.rs:1008-1024`) [P]. `wait_conn` considers a connection usable iff `connection(pair)` is `Some` and not closed, waking on `inner.conn_gen` or every `inner.poll` (`receiver.rs:982-1005`) [P]. `poll` = 5 s in `start` (`api.rs:74`), 200 ms in tests (`tests/kit.rs:831`) [P].
8. Engine: `on_connection` inserts the connection into `live` at once (`engine.rs:560-567`). `on_closed` removes it later, from a task that awaits `closed()` (`engine.rs:614-619, 629-646`) [P]. An already closed connection is not published (`engine.rs:545-550`) [P].
9. `FailReason` is a plain `pub enum` without `#[non_exhaustive]` (`events.rs:34-43`) [P]. It is used in `crates/chervo-receive/tests/receive_net.rs` and `crates/chervo-transfer/tests/redaction.rs` [P: grep].
10. `no_leaks`: `wait_conn` returns at the first `connection(pair).is_some()` (`no_leaks.rs:340-349`). The send follows right after (`:517-518, 562-570`) [P].
11. Test rig: real `Engine` over `FakeTransport`/`FakeConn` with chosen ids (`tests/kit.rs:338-394, 462-504`). Raw wire peer `Fake` speaks the pub codec (`tests/fake.rs:116-202`) [P].

## Decisions (rationale)
1. **No engine change; the transfer layer tolerates link replacement.** Holding a link back "until the duplicate is resolved" is not possible in general. When the first connection of a pair comes up, the engine cannot know that the friend's own dial is still in flight. The only option would be a fixed settle delay on every new connection. That adds latency to every connection and still races on WAN, where the second dial can come later than any fixed delay [V]. The transfer layer has to survive loss of the link during the offer anyway: the report's wider case is a real disconnect while the user is still deciding. Keeping `chervo-connect` out of the change also keeps the critical diff small. The engine's `live` stays "best current link, may already be dying". Consumers must check `is_closed` and handle a failed stream, as `wait_conn` already does (fact 7).
2. **Same `TransferId`, same content, plain OFFER_HEAD + OFFER_FILES.** There is no new message type. The receiver tells a re-offer apart from a new offer by its `TransferKey` (pair from the authenticated connection, id from the frame). The `TransferId` is a 128-bit random value chosen by the sender. Only an authenticated connection of that pair can produce that key, and QUIC stops replay on the network [V]. So the "replay" a re-offer can produce comes only from the friend itself, and the rules below bound it.
3. **Consent is never derived from a re-offer.** A re-offer can only re-attach to the existing pending state. `DECISION{Accept}` is written only after `respond(true)` or after the policy's `Accept` for the first arrival (unchanged). A re-offer for an already accepted key is answered with `DECISION{Accept}`, which only restates the existing consent for identical content. The names the user saw always come from the first assembly. The receiver never replaces stored names with re-sent ones.
4. **Identical or fatal.** The re-offer must match the stored offer exactly: `file_count`, `total_size`, `offer_bytes`, and every `(name, size)` in order (`UntrustedName: PartialEq`; frame boundaries are ignored). An honest sender's `offer_frames` is a pure function of the immutable `SendSession.files` [P `sender.rs:512-546`], so a mismatch is a violation by the friend. The session ends with `Failed{Protocol}` and a tombstone, whether pending or accepted.
5. **Accepting while detached = accept with a lost DECISION.** `respond(true)` while no CTL is attached runs `accept_flow` without a first CTL: `recv_supervisor(None)`, which sends RESUME when the link is back. The sender therefore accepts RESUME in `Offering` as acceptance. RESUME comes only from the receiver of that key over that pair's connection. A hostile receiver gains nothing it could not get with `DECISION{Accept}`. This one rule also covers "receiver accepted, DECISION lost with the link".
6. **Tombstones make answers sticky.** A final answer to a pending offer that the sender may not have received (Decline, Expired, Busy, Limits, Protocol) is kept as `(key, verdict)` for `offer_relink_grace + 30 s`. A re-offer of that key gets the stored verdict and no new prompt. The table is bounded. If an entry is evicted early, the only effect is that the user is asked again, which is fail-safe.
7. **Bounds.** `offer_relink_grace` (120 s) limits time without a working CTL on both sides. `MAX_OFFER_RELINKS` (8) caps both the sender's tries and the receiver's re-attachments per offer. The absolute offer TTL is counted from the first arrival and never extended by a re-offer. A detached pending offer still counts toward "1 per friend / `max_pending_offers` total".

## Do (one builder call, sonnet/high; verify each step before the next, CORE 5)
0. `BASE=$(git rev-parse HEAD)` (expect 7f78727). `grep -rn "FailReason::" crates --include=*.rs` and `grep -rn "TransferConfig {" crates examples --include=*.rs`: list exhaustive matches and struct literals that the new variant or field breaks. Fix only those.
1. **Red first.** Write `offer_survives_link_closed_before_open` and `pending_offer_survives_link_loss` (see Tests) using only pre-existing API. Run both on BASE (src unchanged), and put the failing lines in the report. If either passes on BASE, STOP and report (the reproduction is wrong).
2. R1, R2, S1 below, plus the API additions. Remaining tests. no_leaks fix (T1).
3. All criteria. Report.

### Interface (exact)
```rust
// events.rs
pub enum FailReason { Declined, Expired, Busy, Limits, Protocol, PeerForgot, NotFriend, Disconnected }
// Disconnected: the offer could not be delivered or answered because there was no working
// connection within `offer_relink_grace`, or MAX_OFFER_RELINKS was reached.
// config.rs (TransferConfig, new field; TransferConfig::new default in brackets)
pub offer_relink_grace: Duration,   // [120 s]; validate(): >= 1 s and <= offer_ttl
// limits.rs
pub const MAX_OFFER_RELINKS: u8 = 8;
// texts.rs
pub const DISCONNECTED_TEXT: &str = "Связь с другом пропала, пока предложение ждало ответа. Отправьте файлы ещё раз, когда друг будет на связи.";
```
Nothing else public changes. Wire: unchanged. Semantics added: (a) OFFER_HEAD with a key the receiver knows; (b) RESUME for a sender session in `Offering`.

### S1. Sender (`sender.rs`) [critical: state machine]
- `SCore` += `relinks: u8`, `lost_at: Option<tokio::time::Instant>`, `relinking: bool`.
- `sender_main`: spawn `hash_all` once per session **before** the first `open_bi`. Spawn the TTL task once per session on `s.sh` (not through `spawn_att`). When the TTL fires: if `phase == Offering` and an attempt is attached -> existing `CANCEL{User}` + `Failed{Expired}`; if `Offering` and detached -> `Failed{Disconnected}`. A failure of `open_bi` or of the offer write -> `enter_relink` (not `Failed{Protocol}`). A failure of `offer_frames` stays `Failed{Limits}`.
- `attempt_lost`, branch `Offering`: `enter_relink` instead of `finish_send(Protocol)`.
- `enter_relink(inner, s)`: under `core` lock, if `relinking` already, return. Otherwise set `relinking = true`, `lost_at = now`, and spawn `relink_offer` on `s.sh` (ends with `s.stop`/shutdown).
- `relink_offer` loop:
  1. If `phase != Offering`, clear `relinking` and return.
  2. If `relinks >= MAX_OFFER_RELINKS` or `now >= lost_at + offer_relink_grace`: `finish_send(Failed{Disconnected})`.
  3. Wait for a usable link: `links.connection(pair)` is `Some` and not closed (the same rule as `wait_conn`, fact 7; **no comparison with the old id**). Wake on `inner.conn_gen`, `inner.poll`, the grace deadline, `s.stop`, or shutdown.
  4. One try: `relinks += 1`; `hold`; `open_bi` under `msg_timeout`; write `offer_frames` under `offer_read_timeout`.
  5. On success, under `core` lock install the new `SAttempt` **only if** `phase == Offering && att.is_none()`; else drop the stream. Then `relinking = false`, `start_attempt_tasks`, return. A later loss enters the loop again with a new `lost_at`; `relinks` keeps counting.
  6. On failure: wait for a `conn_gen` change or `poll` (no hot loop), then go to step 1.
- `handle_resume`, phase `Offering`: treat as acceptance. Take and stop the old attempt if any. Install the new attempt and write RESUME_OK as on the `Paused` path. `phase.send_replace(Accepted)`; if it was `Offering`, emit `OfferAnswered{accepted: true}` and `Started` (not `Resumed`). Start `hash_ticker`. The relink loop exits at step 1 or 5.
- Grep check: `FailReason::Protocol` appears in `sender.rs` only inside `protocol_fail`.

### R1. Receiver pending offer (`api.rs`, `inner.rs`) [critical: untrusted input, consent]
- `RecvSession` (or `RCore`) += `offer_deadline: tokio::time::Instant` (= first arrival + `offer_ttl`), `relinks: u8`. `Inner<L>` += `relink: Mutex<HashMap<TransferKey, mpsc::Sender<FirstCtl<L::Conn>>>>` (capacity 1 per entry; the entry exists only while the pending loop runs). Tombstones go in `Inner` too, see R2.
- `pending_task` becomes a loop over `cur: Option<attached CTL>`:
  - Branches: answer; `offer_deadline`; message on the attached CTL; `conn.closed()` of the attached connection; re-attach channel; grace timer (only when detached: `detached_at + offer_relink_grace`); shutdown.
  - **Cancellation rule.** A frame read in progress must never be dropped and then continued on the same stream. Keep the read as one future that owns `rx` and `buf` across loop iterations, for example a boxed future that returns `(result, rx, buf)`. Drop it only together with its CTL or when leaving the loop.
  - Attached CTL events: `CANCEL{id}` -> `SenderCancelled` (unchanged). `HASH_PROGRESS` -> `Protocol` (unchanged). Clean EOF, `Closed`, `TimedOut`, or `conn.closed()` -> **detach** (drop the CTL, `detached_at = now`; no event). Any other decode error or message -> `Protocol` (CANCEL{Protocol}, `Failed{Protocol}`, tombstone).
  - Re-attach `new` (connection `cn`) while `cur` is on connection `co`: no `cur`, or `co` closed -> attach `new`. `cn` closed -> drop `new`, keep `cur`. Both alive -> attach `new` and drop `cur` (an honest sender has abandoned `cur`).
  - Grace expiry while detached: remove, tombstone `Expired`, emit `Failed{Disconnected}`.
  - Deadline: attached -> unchanged (`DECISION{Expired}`, `Failed{Expired}`). Detached -> tombstone `Expired`, `Failed{Expired}`.
  - Answer `false`: tombstone `Decline` **in the same `reg` lock** as `remove_inb`. Then, if attached, write `DECISION{Decline}`. Emit `OfferAnswered{false}`.
  - Answer `true`: attached -> `accept_flow` as today. Detached -> `accept_flow` with no first CTL (no DECISION write; `recv_supervisor(None)`). Every `accept_flow` failure (`claim_slot` -> Busy, dir/prepare -> Limits) also writes the tombstone.
- `offer(key)` returns the view while detached. `respond` works while detached. `status` stays `AwaitingUser`.
- `receive_offer` with a key it already knows. Assemble with the **same** `OfferAssembler` caps and deadline, then decide under the `reg` lock, in this order:
  1. Tombstone for the key -> write its verdict (`DECISION{Decline|Expired|Busy|Limits}`, or `CANCEL{Protocol}` for Protocol) and finish. No prompt.
  2. `inb[key]` pending, not answered: mismatch (decision 4) -> end with `Protocol` (`CANCEL{Protocol}` on the new stream, `Failed{Protocol}`, tombstone). Otherwise `relinks += 1`; if `relinks > MAX_OFFER_RELINKS` -> end with `DECISION{Limits}`, `Failed{Limits}`, tombstone. Otherwise `try_send` the CTL to the session's re-attach channel; if it is full or closed, drop the stream. **No `policy.decide`, no `OfferReceived`.**
  3. `inb[key]` answered but `accept_flow` not finished (phase still Pending) -> drop the stream silently. The sender retries, or the RESUME settles it.
  4. `inb[key]` accepted (`Active` or `Paused(_)`): mismatch -> the session ends `Failed{Protocol}`, partial data removed (existing `finish_session`), `CANCEL{Protocol}` on the stream. Match -> write `DECISION{Accept}`, finish the stream, `inner.bump()`.
  5. Otherwise -> the existing new-offer path (fact 4).
- An assembly error on a re-offer for a known key: `Closed`, `TimedOut`, or EOF -> drop the stream only. Any other violation -> handled as a mismatch (step 2 or 4). For unknown keys the behaviour is unchanged (`DECISION{Limits}`).
- `UntrustedName` is compared with `==`, so there is no new `untrusted_str(` call (`src_guard`).

### R2. Tombstones (`inner.rs`) [critical: bounded memory]
`Inner.tombs: Mutex<VecDeque<(TransferKey, Tomb, tokio::time::Instant)>>` with `enum Tomb { Decline, Expired, Busy, Limits, Protocol }`. At most `max_pending_offers` entries; inserting into a full table evicts the oldest. An entry is valid for `offer_relink_grace + 30 s` and is purged on access. A key has at most one entry.

### T1. no_leaks (`crates/chervo-receive/tests/no_leaks.rs`) [not critical]
- `wait_stable_conn(engine, pair, secs)`: `connection(pair)` is `Some`, not closed, and the same `conn_id` is seen on every 50 ms poll for 1.5 s. Use it for both sides instead of `wait_conn` before sending.
- `CHERVO_NOLEAKS_NO_SETTLE=1` skips the 1.5 s window (first `Some` only, today's behaviour). This is the product-fix check on the real stack. Nothing else changes in the test; the leak scan is unaffected.

## Do not
- No change to `chervo-connect`, `chervo-transport*`, codec, state file, wire format, or `PROTO_VERSION`. No new crate, no `unsafe`, no logging.
- Do not reset `offer_deadline` on re-offer or re-attach. Do not emit a second `OfferReceived` for a re-attach. Do not run `policy.decide` on a re-offer.
- Do not compare connection ids to decide whether a link is usable (R2-2 lesson).
- No disk write for a pending offer (unchanged).

## Untrusted input
Re-offer frames: same caps and deadlines as a first offer (X1), checked before any comparison. The key's pair comes only from the authenticated connection. Every violation for a known key is fatal for that key and is answered once. Stream loss during assembly is not a violation.

## DoS from an authenticated hostile friend (additions to stage 14 bounds)
Per pending offer: at most `MAX_OFFER_RELINKS` (8) re-attachments; lifetime never longer than `offer_ttl` from first arrival. Detached pending offers occupy the same 1-per-friend / 8-total slots. Each re-offer assembly is ≤ 2 MiB under `offer_read_timeout` and counts toward `ctl_in_per_min` (6/min per friend) and `max_pending_kind_reads`. Tombstones: ≤ `max_pending_offers` entries of ~64 B. A hostile *receiver* makes an honest sender try at most 1 + 8 times, for at most `offer_ttl + 30 s` [V].

## Tests (exact names; `chervo-transfer/src/tests/relink.rs`; real `Engine` + `FakeConn` rig and raw `Fake` peer; `#[tokio::test(start_paused = true)]` where timing matters; every test asserts exact event sequences, no sleeps for luck)
- `offer_survives_link_closed_before_open` (variant A). Close the sender's live conn A and call `send` with no `.await` in between (current-thread runtime, so the engine's `on_closed` has not run). Alternative: a `Links` wrapper that returns a closed conn on the first `connection()` call. Then push conn B. Expect: exactly one `OfferReceived` at B, `respond(true)`, `Completed` on both sides, bytes identical, no `Failed` anywhere.
- `pending_offer_survives_link_loss` (variant B + A2). After `OfferReceived`, close conn A. `offer(key)` is still `Some` immediately afterwards. Push conn B. The sender re-offers with the same id; no second `OfferReceived`; accept; `Completed` on both; no `Cancelled`/`Failed`.
- `pending_offer_survives_receiver_side_close` (receiver closes its end, as in duplicate resolution). Same expectations.
- `accept_while_detached_completes_via_resume`. `respond(true)` with no link; then the link returns. The receiver sends RESUME; the sender emits `OfferAnswered{true}`, `Started`, no `Resumed`; `Completed`.
- `decline_while_detached_answered_on_relink`. The re-offer gets `DECISION{Decline}`; sender `Failed{Declined}`; one `OfferReceived` total.
- `reoffer_for_accepted_key_gets_accept` (raw `Fake`). Re-offer after accept -> `DECISION{Accept}`; a RESUME afterwards works.
- `reoffer_mismatch_ends_pending`. Cases: one name byte, one size, swapped order, extra file, different `total_size`. Each: `CANCEL{Protocol}`, receiver `Failed{Protocol}`, `offer` = `None`, `respond` = `Err`, `partial_dir` empty. Then an identical re-offer gets `CANCEL{Protocol}` from the tombstone and no prompt.
- `reoffer_mismatch_after_accept_fails_transfer`: `Failed{Protocol}`, partial dir removed.
- `reoffer_never_accepts_by_itself`: 8 re-offers, no answer; no `DECISION{Accept}`, no `Started`, nothing on disk.
- `reoffer_does_not_extend_ttl`: re-offer at `offer_ttl - 1 s`; `DECISION{Expired}` exactly at the original deadline.
- `reoffer_cap`: the 9th re-attach -> `DECISION{Limits}`, `Failed{Limits}`.
- `detached_pending_ends_after_grace`: `Failed{Disconnected}` at exactly `offer_relink_grace`, not one tick earlier.
- `sender_without_link_fails_disconnected_after_grace`: never `Protocol`.
- `sender_relink_tries_capped`: links that die right after `open_bi`; at most 9 OFFER_HEADs seen; `Failed{Disconnected}`.
- `reoffer_on_closed_conn_does_not_replace_live`: the attach rule.
- `tombstones_bounded`: `max_pending_offers + 1` tombstones; the evicted key re-offered -> a fresh `OfferReceived` (fail-safe).
- `same_id_from_other_pair_is_separate`: another friend uses the same id; it gets its own key and its own prompt; the first offer is untouched.
- `relink_hashes_once`: the `HashBlock` hook count equals the block count once.
- Existing tests unchanged and green, in particular `cancel_pending_offer`, `second_offer_same_friend_busy`, `pending_offers_global_cap`, `hash_progress_rules`, `resume_unknown_session_peer_forgot`.

## Acceptance criteria (each as a command; output in the report)
- [ ] Step 1 red output on BASE for the two reproduction tests.
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`; `git diff --stat $BASE -- crates/chervo-connect crates/chervo-transport crates/chervo-transport-quinn` is empty
- [ ] `bash scripts/check-forbidden.sh`; `cargo test -p chervo-core --test layout`
- [ ] `grep -n "FailReason::Protocol" crates/chervo-transfer/src/sender.rs` -> only inside `protocol_fail`
- [ ] `for i in $(seq 50); do cargo test -q --locked -p chervo-transfer relink || exit 1; done`
- [ ] Windows, real stack, product fix alone. `BIN` = the `no_leaks` test executable from `cargo test --locked -p chervo-receive --test no_leaks --no-run`. Run 6 parallel workers × 50 runs of `CHERVO_NOLEAKS_NO_SETTLE=1 "$BIN" no_leaks_full_scenario`, print `FAIL w i` on a non-zero exit. Required: 300 runs, 0 FAIL. Before the fix this setup failed 4 of 75.
- [ ] The same 6 × 50 without the env var (test fix + product fix): 0 FAIL.
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-transfer --test transfer_net || exit 1; done` (no regression)
- [ ] Conductor, on the Linux box (not here): 3 parallel × 150 runs with `CHERVO_NOLEAKS_NO_SETTLE=1` during a workspace build: 0 failures (the report's 11/450 setup).
- [ ] CI: all jobs green on 3 OS.

## Not verified by this stage (write in the report, do not claim)
Behaviour on real WAN reconnects. Probability bounds come from the loops only: if the flake were still at the measured 2 %, 300 clean runs would happen by chance with probability ≈ 0.2 % [V]. UI for "waiting for the link" is not designed here (stage 18).

## Stop conditions
The spec contradicts the code; a reproduction test passes on BASE; a fix needs a wire change, a new crate, or an engine change; a loop criterion fails after two fix rounds. Stop and report.

## Limit and report
At most 2 review-fix rounds. Builder report ≤ 25 lines: changed files, red output, criteria commands with last lines, loop counts, deviations.

## Process
`combine-builder` sonnet/high (one call, steps 0-3) -> `combine-verifier` sonnet/low (all criteria; the conductor re-runs the 6×50 loop) -> `combine-security` opus/high on the diff. Focus areas: re-attach and attach rule, mismatch check before any state change, tombstone lock ordering against answer and accept races, no consent path from a re-offer, RESUME in `Offering`, TTL not extended, cancellation rule for CTL reads, bounds. Critical: S1, R1, R2. Not critical: texts, T1.
After acceptance, the conductor updates THREAT_MODEL: T2 bounds (section "DoS ... additions") and the T2 measure "offer survives replacement of the connection, consent only by the user".

## Open question for the owner (does not block; the builder uses the recommendation)
**Q1. How long an offer waits for the link to return:** (A) **120 s on both sides (recommended)**: the sender learns quickly that the friend is unreachable, and the pending window on the receiver stays short; (B) the whole offer lifetime (10 min): fewer lost offers on bad links, but the sender sees no result for up to 10 min.

## Для владельца (кратко, по-русски)
- Если связь пропала или заменилась, пока друг решает, принять ли файлы, отправитель сам повторяет то же предложение (тот же номер, то же содержимое) по новому соединению: не больше 8 раз и не дольше 2 минут без связи. У получателя окно «принять или отклонить» остаётся открытым, второй раз оно не появляется.
- Принять файл может только сам получатель. Повтор предложения ничего не принимает сам. Если повтор отличается хоть одним именем или размером, это считается нарушением: предложение закрывается, ничего не принимается.
- Если вы приняли или отклонили предложение без связи, ответ дойдёт до отправителя, когда связь вернётся.
- Если связь так и не вернулась, причина будет «нет связи», а не «ошибка протокола».
- Движок соединений не меняется: заранее узнать, что соединение окажется дублем, нельзя.
- Тест утечек теперь ждёт устойчивого соединения. Отдельно проверяем, что и без этого ожидания он проходит 300 раз из 300 (раньше на Windows падал 4 раза из 75).
- Вопрос Q1: сколько ждать возврата связи. Рекомендую 2 минуты.
