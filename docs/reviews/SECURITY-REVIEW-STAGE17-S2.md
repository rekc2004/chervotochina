# SECURITY REVIEW, STAGE 17, S2 (independent, fresh context)

Reviewer: combine-security (opus/high), 2026-10-18. Commit c927328. S1 read only after own findings. Recorded by the conductor.

## Ran
Windows 11, Rust 1.99.1, `--locked --offline`: chervo-friends, token, identity, addr tests pass; transport-quinn, connect, receive: 393 passed, 0 failed, 5 ignored.

## Findings
No Critical/High.
- **M1 Medium.** Invite-sourced addresses skip the X02a 30 s floor and never expire: `chervo-connect/src/plan.rs:90-96` (`is_strict` excludes `AddrSource::Invite`), `invite.rs:728` (invitee stores token addresses), `chervo-addr/src/book.rs:140-147` (global IPv4 Invite entry has no TTL). The repo's own `x02a_control_invite_addresses_keep_fast_window` asserts a gap < 30 s. A hostile inviter lists V1..V7; in every fast window of the invitee (start, network change, connect_now, token) and whenever the inviter is offline, V1..V7 are dialled ~every 15 s. Fix: Invite entries of an established friend are strict; fast mode only for Contact-confirmed addresses; optional TTL after first contact; stand row X02c (lying inviter); mirror test.
- **L1 Low.** Strict floor is per IP:port, not per IP (`limiter.rs:88-103`, `plan.rs:112-123`): many ports of one victim IP -> up to `per_ip_dials` 4/10 s. Fix: per-IP floor for strict candidates.
- **L2 Low.** Knock admission attempt consumed before limiter/per-key/semaphore checks (`server.rs:26-30` vs `:34-57`): refused Incomings burn an honest friend's 2 attempts. Fix: consume only when the slot is granted.
- **L3 Low (inference).** One hostile friend with ≥ 11 limiter keys (cheap IPv6 /64s) can hold ~21 of 32 pre-auth slots (2 attempts × 32 knocks per window, held up to `auth_deadline` 10 s by valid msg1 without msg3); ~double with a clock offset (extra windows, `knock.rs:125-139`). Fix: cap unfinished connections per admitting pair (`AdmitTable` entry pair) and a short msg3 deadline.
- **L4 Low.** Failed publish after a security change leaves the transport stale without retry (`engine.rs:941-965`): removed friend still passes knock and KK until the next book change (engine still closes the connection, `engine.rs:460-464`). Fix: dirty flag + retry on tick, or drop removed pairs without loading keys.
- Info: accepted in-band updates rewrite the friends file (up to every 10 s per friend); plain v3 `name` not zeroized.

## Checked by reading, holds
Knock MAC/replay/quotas/window_life, GRO strip, Retry -> consume, pin; limiter, per-key permits, msg1 deadline, uniform refusal; set_peers single lock, registry triple check, conn_id; TLS (raw public keys, no resumption/0-RTT/NEW_TOKEN); KK (prologue = exporter, no early exit, reflection check); X25519 validation; vault AEAD, strict plain v1-v3, Retired order, check_anchor/StaleInstance, revocation matching; invite commit/SAS/one-shot; address-update signature bound to signer+recipient; ADDR_INFO bounded; no path for a friend to learn another friend's address; transfer hash check + re-read before placement, `.part -> .placing -> hard link/create_new`, sanitizer, plan collisions, journals; Windows profile check (`root.rs:241-265`); overflow on untrusted arithmetic (release overflow-checks on).

## Not checked
UPnP, timesync, sender side, CI/SBOM/deny/audit, fuzz harness/libFuzzer, stand scripts, Linux/macOS, OS keychains, tokio semaphore fairness, clippy/fmt.

## Comparison with S1
Agree: no Critical/High; S1 M1, M2, L1, L2 fixed in c927328 (read); L3 matches the code comment; L7 TM now 5 s. Not verified by S2: S1 M3, L4, L5. New in S2: M1, L1-L4 (S1 did not read connect limiter/plan or the invite flow). Mild disagreement: pre-auth order — S2 rates attempt-before-limits Low (L2).

## Резюме для владельца
1. Критичных и высоких нет; тесты прошли на Windows.
2. Средняя M1: адреса из приглашения не подчиняются «не чаще раза в 30 с» и не устаревают — злой пригласивший может заставить стучать на 7 чужих адресов примерно раз в 15 с после каждого запуска или смены сети.
3. Мелкие: предел 30 с на адрес, а не на IP; попытка стука тратится раньше проверки лимитов.
4. Ещё мелкие: злой друг со многими IPv6 может занять ~2/3 мест до аутентификации; при сбое хранилища заблокированный друг до следующего изменения книги проходит стук и KK.
5. Не проверял: UPnP, синхронизацию времени, CI, фаззинг, Linux и macOS.
