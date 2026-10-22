# SPEC 17a: own Secret Service client (Linux)          criticality: CRITICAL

Goal: on Linux, `OsKeyStore` talks to the Secret Service over D-Bus with our own minimal client on zbus 6.0.0, behind the same traits (`SecretStore`, `ListKeyStore`, `EpochStore`); entries written by the old client are read unchanged; `secret-service`, `zbus-secret-service-keyring-store`, zbus 5 and zvariant 5 leave `Cargo.lock`; the RUSTSEC-2026-0370/0371/0372 exception is removed.

Owner decision: `docs/OWNER_DECISIONS.md:134` (Q3, 2026-10-18). Task line: `docs/TASK.md:96`.

Read (nothing else needs searching): this file; `crates/chervo-identity/src/{os.rs,store.rs,lib.rs,error.rs,ids.rs}`; `crates/chervo-identity/tests/identity.rs:205-223, 934-1028`; `Cargo.toml` (workspace deps); `.cargo/audit.toml`; `deny.toml`; `.github/workflows/ci.yml`; zbus 6.0.0 sources in `~/.cargo/registry/src/*/zbus-6.0.0` only where this spec cites them.

---

## 0. Owner summary (Russian)

**Что делаем.** На Linux заменяем библиотеки `secret-service` + `zbus-secret-service-keyring-store` (zbus 5, «не сопровождается») своим маленьким клиентом на zbus 6. Остальной код не меняется: те же трейты хранилища, те же ошибки. Windows и macOS не трогаем.

**Совместимость.** Новый клиент ищет и пишет записи ровно так же, как старый: атрибуты `service` и `username`, коллекция по псевдониму `default`, метка `keyring:<имя записи>@<сервис>`, секрет хранится как есть (сырые байты). Записи, созданные старой версией, читаются новой. Проверка: тест записи на коммите со старым клиентом и тест чтения на новом, на вашей Linux-машине.

**Шифрование сеанса D-Bus: выбираю `plain` (без DH).** Шифрование сеанса защищает секрет только по пути через шину D-Bus. Подслушать шину может только процесс того же пользователя или root, а они и так могут просто попросить секрет у gnome-keyring (у него нет разрешений по приложениям; угроза T10 вами принята). DH-1024 из старой библиотеки был с переменным временем и требовал бы собрать протокол из четырёх примитивов у нас в коде. Минус `plain`: открытый секрет на короткое время лежит в буферах сообщений zbus, которые мы не можем обнулить (тот же класс остатка, что snow, B2). Это можно переиграть: вариант DH описан в приложении B (вопрос В1).

**Блокировка.** Чтение, запись и удаление **никогда не показывают окно пароля** и никогда не висят: если коллекция заблокирована, сразу ошибка «заблокировано». Окно разблокировки вызывается только отдельным явным методом `request_unlock` (для кнопки в GUI, этап 18) с ограничением по времени. На мини-ПК без рабочего стола окно показать нельзя: разблокировка по ssh, как вы решили в U10c (вопрос В2).

**Никогда не висим.** У каждого вызова D-Bus есть тайм-аут (5 с), у операции целиком 10 с, вызывающий ждёт не дольше 12 с. Старый клиент мог ждать окно пароля бесконечно.

**«Нет записи» говорим только тогда, когда точно знаем.** Если поиск пуст, но коллекция по умолчанию заблокирована, ответ «заблокировано», а не «нет записи».

**Проверки.** Тесты протокола на поддельном сервисе (работают в CI без gnome-keyring), отдельная задача CI с настоящим gnome-keyring, ручные тесты на вашей Linux-машине (в том числе без рабочего стола и после перезагрузки). Затем два ревью безопасности.

**Вопросы к вам:** В1 (plain или DH), В2 (окно разблокировки только по кнопке). Рекомендации в разделе 9.

---

## 1. Facts (verified from source unless marked)

Markers: [П] verified by reading source; [В] inferred; [НП] not verified.

F1 [П] Today Linux uses `zbus_secret_service_keyring_store::Store::new()` (`crates/chervo-identity/src/os.rs:39-44`) and builds entries with `build(service, account, None)` (`os.rs:86-96`, no modifiers on Linux).

F2 [П] Old attribute schema: exactly `{"service": <service>, "username": <account>}`; `target` only if a modifier was given (`zbus-secret-service-keyring-store-1.0.1/src/cred.rs:102-110`), and we give none. Label when no modifier: `keyring:{user}@{service}` (`cred.rs:45-48`).

F3 [П] Old write: search for a unique existing item; if found, `Item.SetSecret` on it (`cred.rs:115-121`, `service.rs:107-115`); if none, `CreateItem` in the collection with alias `default` (`cred.rs:123`, `service.rs:52-78`, alias lookup `secret-service-5.2.0/src/blocking/mod.rs:88-107`) with `replace = true`, content type `"application/octet-stream"` (`service.rs:68-76`). If the default collection is locked it calls `Unlock` and runs the prompt (`service.rs:216-218`).

F4 [П] Old read/delete: `org.freedesktop.Secret.Service.SearchItems` over all collections (`service.rs:30-50`); if any matching item is locked it calls `Unlock` and waits for the prompt's `Completed` signal **without a timeout** (`blocking/mod.rs:189-198`, `util.rs:121-135`). More than one match: `Ambiguous` (`cred.rs:85-97`), mapped to `StorageInconsistent` (`os.rs:51`).

F5 [П] Old session: `EncryptionType::Dh` (`service.rs:26`) with RustCrypto (`Cargo.toml:51`, feature `crypto-rust`): RFC 2409 1024-bit group (`session.rs:31-43`), BigUint `powm` with variable time (`session.rs:218-232`), HKDF-SHA256 with no salt and empty info to a 16-byte key (`session.rs:81-100, 123-132`), AES-128-CBC PKCS#7 with a random IV in `parameters` (`session.rs:234-254`, `util.rs:64-99`).

F6 [П] Secret encoding: the value bytes are the caller's bytes, no base64 or text (`util.rs:64-99`; read `blocking/item.rs:101-119`). The daemon decrypts the transport encryption and stores plaintext bytes. So the stored secret does not depend on the session algorithm [В from the protocol; checked by manual test M1].

F7 [П] Old error mapping: `Locked`, `NoResult`, `Prompt` → `NoStorageAccess` (`errors.rs:11-18`) → `StorageLocked` (`os.rs:50`); no service or bus → `Unavailable` → `PlatformFailure` (`util.rs:151-159`) → `StorageUnavailable` (`os.rs:60`).

F8 [П] D-Bus names and signatures used: bus name `org.freedesktop.secrets`, path `/org/freedesktop/secrets` (`ss.rs:4`, `proxy/service.rs:13-17`); algorithms `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7` (`ss.rs:11-12`); item property keys `org.freedesktop.Secret.Item.Label`, `org.freedesktop.Secret.Item.Attributes` (`ss.rs:7-8`); Secret struct `(oayays)` = session, parameters, value, content_type (`proxy/mod.rs:9-15`); method signatures in `proxy/service.rs:18-44`, `proxy/collection.rs:18-29`, `proxy/item.rs:15-21`, `proxy/prompt.rs:14-21`. The freedesktop specification itself was **not** opened (no web tool here) [НП]: see step P0.

F9 [П] zbus 6.0.0 has **no blocking API**: `src/lib.rs:56-150` has no `blocking` module. `zbus::block_on` with the `tokio` feature **panics inside a Tokio task** (`src/utils.rs:148-151`). Without `default-rt`, a connection built where no Tokio runtime is current fails with `Error::Unsupported` (`src/runtime/mod.rs:80-93`, `src/connection/builder.rs:487-492`).

F10 [П] Our store traits are synchronous, and `chervo-connect` calls them from async code (for example `crates/chervo-connect/src/engine.rs:423, 598`). So the new client must not call `block_on` on the caller's thread. Decision D2 follows from this.

F11 [П] zbus 6 features (`zbus-6.0.0/Cargo.toml.orig:16-99`): `default = [default-rt, proxy, service, object-manager, tracing]`; `tokio = [comms, dep:tokio]`; `comms` pulls `zruntime` with `broadcast`, `lock`, `unblock` only (`:37-58`); `tracing` is a separate feature (`:82`); `p2p` (`:97`). The tokio requirement is `1.53.3` with `rt, net, time, sync` (`Cargo.toml:276-284`), the same pin as our workspace (`Cargo.toml:56`). Licences: zbus, zbus_macros, zbus_utils, zruntime, zcheapstr are all MIT [П, their `Cargo.toml`].

F12 [П] zbus 6 API this spec relies on: `connection::Builder::{session, unix_stream, p2p, server, method_timeout, build}` (`src/connection/builder.rs:110, 225, 295, 314, 473, 508`). `method_timeout` applies to `call_method` only, not to connect or authentication (`src/connection/mod.rs:281-317`). Other items: `Message::{method_return, error, signal}` (`src/message/mod.rs:90-122`); `MessageStream::for_match_rule` (`src/message_stream.rs:157`); `Error` variants including `MethodError(name, desc, msg)`, `FDO(Box<fdo::Error>)`, `InputOutput`, `Connection`, `Address`, `Handshake`, `Unsupported` (`src/error.rs:19-114`). zvariant's `Value` is now `Variant`/`OwnedVariant` (`src/wire/variant.rs:77`, `src/lib.rs:61-65`). zbus's own tests use p2p over `UnixStream::pair()` (`tests/e2e.rs:62-66`).

F13 [П] Cargo.lock today: zbus 5.19.0 (`Cargo.lock:1943-1975`), secret-service 5.2.0 (`:1377-1393`). `zcheapstr 1.1.0` (`:2015`), `syn 3.0.6` (`:1547`), `bitflags 2.13.2`, `socket2 0.6.5`, `uuid`, `winnow 1.0.4`, `endi`, `futures-core 0.3.34`, `futures-io`, `ordered-stream`, `async-trait`, `serde_repr`, `rustix`, `uds_windows` and `windows-sys 0.61.2` are already present.

F14 [П] CI pins cargo-audit 0.22.2 and cargo-deny 0.20.2 (`.github/workflows/ci.yml:38-41`). The exception is in `.cargo/audit.toml:7` and `deny.toml:8`. Bans use the `{ name = "..." }` form (`deny.toml:13-17`).

F15 [П] `public_debug_redacted` accepts only `Ok` or `Err(StorageUnavailable)` from `OsKeyStore::open_with_service` on Linux (`tests/identity.rs:215-222`).

F16 [П, count only, not an audit] The token `unsafe ` appears 71 times in 15 files of `zbus-6.0.0/src` (26 in `win32.rs`, not built on Linux), and 42 times in 13 files of `zruntime-0.2.0/src`. Our crate stays `unsafe_code = "forbid"`.

---

## 2. Decisions

D1. **Session algorithm: `plain`.** Reasons:
- The transport encryption only protects the hop through the session bus. Reading that hop needs the same uid or root. Both can call `GetSecret` themselves on an unlocked collection, because gnome-keyring has no per-application ACL (T10 accepted; `THREAT_MODEL.md:181, 184`).
- No DH-1024 or variable-time bignum code in our tree, and no protocol assembled from four primitives in our crate.
- `aes`, `cbc`, `hkdf`, `hmac`, `num*` leave the lockfile (expected; the builder confirms by lock diff).

Cost: plaintext also sits in the zbus incoming and outgoing message buffers, which we cannot zeroize without `unsafe`. It also sits in dbus-daemon buffers. This is the same class as residual B2 (snow) and old L1, where the old library did not zeroize at all. The owner may override (Q1); the DH variant is in Appendix B.

D2. **Execution model.** Each `OsKeyStore` on Linux owns one dedicated OS thread named `chervo-secret-service`. The thread runs its own `tokio::runtime::Builder::new_current_thread().enable_io().enable_time()` runtime and one cached zbus connection plus session.
- Callers send jobs over a bounded `tokio::sync::mpsc` channel (capacity 8) with `try_send`, which never blocks and never panics in a runtime.
- Replies come back over `std::sync::mpsc::sync_channel(1)` with `recv_timeout`. That is a plain blocking wait, safe from any thread including Tokio workers.
- The thread runs `rt.block_on(async { while let Some(job) = rx.recv().await { handle(job).await } })`. Jobs run one at a time.
- `zbus::block_on` is never used. The zbus `tokio` feature is on, `default-rt` is off: no second runtime (zruntime) and no helper threads.

D3. **zbus features.** Normal build: `zbus = { version = "=6.0.0", default-features = false, features = ["tokio"] }`. The client uses `Connection::call_method` and `MessageStream` directly, so it needs no `proxy`/`service` macros. `tracing`, `unixexec`, `ibus`, `p2p` and `object-manager` stay off. Dev only (Linux): `features = ["p2p"]`, for the fake service in tests.

D4. **Compatibility contract (exact, must not change):**
- attributes `{"service": service, "username": account}`, nothing else;
- label `format!("keyring:{account}@{service}")`;
- content type `"application/octet-stream"`;
- new items go to the collection that alias `default` points to, created with `replace = true`;
- existing items are updated in place with `Item.SetSecret`;
- read, write and delete search with `Service.SearchItems` over all collections, as the old client did (F2-F4).

D5. **No implicit prompt.** `get`, `set` and `delete` never call `Prompt.Prompt` and never call `Unlock`. A prompt object returned by `CreateItem` or `Item.Delete` is dismissed (`Prompt.Dismiss`, best effort, its result ignored) and the operation returns `StorageLocked`. Unlocking is a separate explicit method `OsKeyStore::request_unlock(wait)` (Linux only), for a user action in the GUI (stage 18). This changes behaviour on purpose: the old client could pop a dialog and wait forever (F4).

D6. **`None` only when certain.** `read` returns `Ok(None)` only if `SearchItems` returned zero items AND (alias `default` is `/` OR the default collection's `Locked` property is `false`). Zero items with a locked default collection → `StorageLocked`.

D7. **No collection creation, no fallback.** We never call `CreateCollection` (it prompts) and never use any other storage. No default collection on write → `StorageUnavailable`.

D8. **Timeouts.** `CALL_TIMEOUT = 5 s` (connection `method_timeout`), `OP_TIMEOUT = 10 s` (`tokio::time::timeout` around the whole job in the worker, connect and retry included), `CALLER_TIMEOUT = 12 s` (`recv_timeout`). Unlock wait is given by the caller and clamped to `1..=300 s`; the caller waits `wait + 2 s`. Tests inject smaller values through a `pub(crate) Timeouts` struct.

D9. **Reconnect.** The connection and session are cached. On a connection-level error (`InputOutput`, `Connection`, connection closed) or the D-Bus error `org.freedesktop.Secret.Error.NoSession`, drop both, reconnect, and restart the job from the beginning **once**. A second failure → `StorageUnavailable`.

D10. **keyring-core** moves to `cfg(any(target_os = "macos", target_os = "windows"))`. The Linux build does not link it.

---

## 3. D-Bus subset (exact)

Destination `org.freedesktop.secrets` for every call. `Variant` means zbus 6 `zbus::Variant`.

| Call | Path | Interface.Member | In | Out |
|---|---|---|---|---|
| open session | `/org/freedesktop/secrets` | `org.freedesktop.Secret.Service.OpenSession` | `(s "plain", v <s "">)` | `(v output, o session)`; output ignored |
| search | same | `...Service.SearchItems` | `a{ss}` = D4 attributes | `(ao unlocked, ao locked)` |
| default alias | same | `...Service.ReadAlias` | `s "default"` | `o` (`/` = none) |
| unlock (only `request_unlock`) | same | `...Service.Unlock` | `ao [default]` | `(ao unlocked, o prompt)` |
| locked? | collection path | `org.freedesktop.DBus.Properties.Get` | `(s "org.freedesktop.Secret.Collection", s "Locked")` | `v <b>` |
| create | collection path | `org.freedesktop.Secret.Collection.CreateItem` | `(a{sv} {Label: v<s>, Attributes: v<a{ss}>}, (oayays) (session, [], value, "application/octet-stream"), b true)` | `(o item, o prompt)` |
| get | item path | `org.freedesktop.Secret.Item.GetSecret` | `o session` | `((oayays))` |
| set | item path | `...Item.SetSecret` | `((oayays))` | `()` |
| delete | item path | `...Item.Delete` | `()` | `o prompt` |
| prompt (only `request_unlock`) | prompt path | `org.freedesktop.Secret.Prompt.Prompt` | `s ""` | `()`; then signal `Completed(b dismissed, v result)` |
| dismiss | prompt path | `...Prompt.Dismiss` | `()` | `()` |

Property keys inside `CreateItem`: `org.freedesktop.Secret.Item.Label`, `org.freedesktop.Secret.Item.Attributes` (F8).

Error names from the spec (from memory; P0 confirms): `org.freedesktop.Secret.Error.IsLocked`, `.NoSession`, `.NoSuchObject`.

---

## 4. Algorithms

Common first step S (all three operations): ensure connection and session (connect with `Builder::session().method_timeout(CALL_TIMEOUT)`, then `OpenSession`), then `SearchItems`. Let `n = unlocked.len() + locked.len()`.

**get(service, account) → Option<Zeroizing<Vec<u8>>>**
1. `n > 1` → `StorageInconsistent`.
2. `n == 0` → `ReadAlias("default")`: `/` → `Ok(None)`; else `Locked` on it: `true` → `StorageLocked`, `false` → `Ok(None)`.
3. `locked.len() == 1` → `StorageLocked`.
4. `GetSecret(session)` on `unlocked[0]`. Wrap `value` in `Zeroizing` **before** any check. Then: `parameters` not empty → `StorageInconsistent`; `value.len() > MAX_SECRET_LEN` (4096) → `StorageInconsistent`. Content type and the returned session path are ignored.
5. Item errors: `IsLocked` → `StorageLocked`; `NoSuchObject` → `StorageInconsistent` (raced with a delete; never `None`).

**set(service, account, secret)**
1. `n > 1` → `StorageInconsistent`; `locked.len() == 1` → `StorageLocked`.
2. `unlocked.len() == 1` → `SetSecret` on it (`IsLocked` → Locked; `NoSuchObject` → Inconsistent).
3. `n == 0` → `ReadAlias("default")`: `/` → `StorageUnavailable`. `Locked` → `StorageLocked`. Otherwise `CreateItem` (D4). Results:
   - `prompt != "/"` → `Dismiss`, then `StorageLocked`;
   - `item == "/"` and `prompt == "/"` → `StorageUnavailable`;
   - otherwise `Ok`.

**delete(service, account)**
1. `n == 0` → `Ok(())`; `n > 1` → `StorageInconsistent`; `locked.len() == 1` → `StorageLocked`.
2. `Item.Delete`: prompt `/` → `Ok`; otherwise `Dismiss`, then `StorageLocked`; `NoSuchObject` → `Ok`.

**request_unlock(wait)** (Linux-only inherent method; the only place where `Unlock` and `Prompt` are called)
1. `ReadAlias("default")`: `/` → `StorageUnavailable`. Not locked → `Ok`.
2. `Unlock([alias])`: alias in `unlocked` → `Ok`. If `prompt == "/"`, re-read `Locked` and map it.
3. **Before** calling `Prompt("")`, subscribe with `MessageStream::for_match_rule` (signal, path = prompt, interface `org.freedesktop.Secret.Prompt`, member `Completed`). Then wait with `tokio::time::timeout(wait)`. Outcomes:
   - timeout → `Dismiss`, then `StorageLocked`;
   - stream ended → `StorageUnavailable`;
   - `dismissed == true` → `StorageLocked`;
   - otherwise re-read `Locked` on the alias: `false` → `Ok`, `true` → `StorageLocked`.

   The decision rests on the `Locked` property, never on the signal alone, so a forged `Completed` from another same-user process changes nothing.
4. While an unlock runs, the worker is busy. Other jobs wait in the queue and may hit `CALLER_TIMEOUT` → `StorageUnavailable`. Accepted: stage 11 Н1 shows locked and unavailable the same way.

**Error mapping (all paths; zbus errors are never formatted, stored or propagated):**

| Cause | Result |
|---|---|
| no bus address, connect/auth failure, `Handshake`, `InputOutput`, `Connection`, op/caller timeout, queue full, worker gone | `StorageUnavailable` |
| FDO `ServiceUnknown`, `NameHasNoOwner`, `NoReply`, `Timeout`, `TimedOut`, `Disconnected`, `NotSupported` (plain refused), `UnknownMethod`, `UnknownObject`, `UnknownInterface`, `SpawnFailed`/`Spawn*` | `StorageUnavailable` |
| FDO `AccessDenied`, `Secret.Error.IsLocked`, any prompt outside `request_unlock` | `StorageLocked` |
| reply of wrong signature or undecodable | `StorageUnavailable` |
| `>1` match, oversized secret, non-empty parameters, `NoSuchObject` on get/set | `StorageInconsistent` |
| `Secret.Error.NoSession` | reconnect once (D9), then `StorageUnavailable` |
| any other `MethodError` | `StorageUnavailable` |

`open_with_service`: rejects an empty service name, more than 255 bytes, or any `'\0'` (`StorageUnavailable`). It spawns the worker and runs a `Ping` job (connect + `OpenSession`) within `CALLER_TIMEOUT`. Any failure → `Err(StorageUnavailable)` (keeps F15). Thread spawn or runtime build failure → `StorageUnavailable`. `Drop` drops the sender only and never joins.

---

## 5. Interface (exact)

Public API unchanged except one Linux-only method:
```rust
// crates/chervo-identity/src/os_linux.rs, re-exported as today: pub use os_linux::OsKeyStore (cfg linux)
impl OsKeyStore {
    pub fn open() -> Result<Self, IdentityError>;
    pub fn open_with_service(service: &str) -> Result<Self, IdentityError>;
    /// Explicit user action only (GUI). Never called by read/write/delete. Blocks up to wait + 2 s.
    pub fn request_unlock(&self, wait: std::time::Duration) -> Result<(), IdentityError>;
}
impl fmt::Debug for OsKeyStore { /* "OsKeyStore(..)" */ }
impl SecretStore + ListKeyStore + EpochStore for OsKeyStore // accounts: pair.account_name(), LIST_KEY_ACCOUNT, EPOCH_ACCOUNT; epoch = 8 bytes BE, other length -> StorageInconsistent (as os.rs:143-163)
```
Internal layout (Linux only):
- `src/secret_service/mod.rs`: `pub(crate) struct SsClient`, `pub(crate) struct Timeouts { call, op, caller }`, methods `connect_session(Timeouts)`, `#[cfg(test)] connect_p2p(UnixStream, Timeouts)`, `get`, `set`, `delete`, `request_unlock`.
- `proto.rs`: names and constants from section 3, `MAX_SECRET_LEN = 4096`, `QUEUE = 8`, `LABEL_PREFIX = "keyring:"`, `CONTENT_TYPE`.
- `worker.rs`: thread, runtime, job loop, reconnect.
- `errors.rs`: zbus error → `IdentityError`.
- `tests.rs`: fake service and unit tests.

`os.rs` becomes `cfg(any(windows, macos))` and its keyring-core Linux branch (`os.rs:39-44`) is deleted. Jobs carry `Zeroizing<Vec<u8>>` for secrets. Replies carry `Result<Option<Zeroizing<Vec<u8>>>, IdentityError>`.

Do not do:
- no change to the store traits, `store.rs`, Windows/macOS behaviour, or other crates;
- no new dependency beyond section 6;
- no `zbus::block_on`;
- no `#[derive(Debug)]` on any type that holds a secret, service or account string;
- no `std::fs` in `secret_service/`;
- no logging; no `CreateCollection`; no `Lock` in product code (tests only).

Untrusted input: replies from whoever owns `org.freedesktop.secrets` on the session bus are attacker-reachable (a same-user process can claim the name; T10). Rules: decode only into the exact expected types; cap the secret length; treat counts and paths as data; never panic (the crate lints deny `unwrap`/`expect`/indexing/`panic`); every await is bounded.

---

## 6. Dependencies and Cargo.lock

Workspace `Cargo.toml`:
- remove `zbus-secret-service-keyring-store`;
- add `zbus = { version = "=6.0.0", default-features = false, features = ["tokio"] }`;
- add `futures-core = { version = "=0.3.34", default-features = false }` (for polling `MessageStream`; already in the lock).

`chervo-identity/Cargo.toml`: keyring-core under macOS/Windows; Linux deps `zbus`, `tokio`, `futures-core`; Linux dev-dep `zbus` with `features = ["p2p"]`.

Expected **new** packages: `zbus 6.0.0`, `zbus_macros 6.0.0`, `zbus_utils 6.0.0`, `zruntime 0.2.0`. Anything else new → stop.

**Must disappear** (hard criterion): `zbus 5.*`, `zbus_macros 5.*`, `zbus_names`, `zvariant`, `zvariant_derive`, `zvariant_utils`, `secret-service`, `zbus-secret-service-keyring-store`.

Expected to disappear (report the actual diff, not a criterion): `aes`, `cbc`, `hkdf`, `hmac 0.13`, `num`, `num-*`, `async-io`, `async-executor`, `async-broadcast`, `async-lock`, `async-process`, `async-signal`, `async-task`, `async-recursion`, `blocking`, `enumflags2*`, `event-listener*`, `futures-lite`, `piper`, `polling`, `proc-macro-crate` and its tree.

`deny.toml`:
- remove the three RUSTSEC ignores and their comment;
- add to `[bans] deny`: `{ name = "secret-service" }`, `{ name = "zbus-secret-service-keyring-store" }`, `{ name = "zvariant" }`, `{ name = "zvariant_derive" }`, `{ name = "zvariant_utils" }`, `{ name = "zbus_names" }`. These are enough to keep zbus 5 out, because it requires zvariant.

`.cargo/audit.toml`: remove the ignore list (delete the file if it becomes empty).

---

## 7. Work split

P0 (`combine-scout`, web, medium, ≤30 lines): open the freedesktop Secret Service API spec (latest) and confirm, with quotes, every row of section 3:
- error names;
- `plain` input is an empty-string variant;
- `CreateItem`/`Delete`/`Unlock` return semantics for `/`;
- `SearchItems` puts items of locked collections in `locked`;
- prompt `Completed` signature.

Any difference → stop, architect revises.

B0 (`combine-builder`, sonnet/medium; **before** B1, on the old client):
- add `#[ignore]` tests `ss_migration_write_old` and `os_epoch_roundtrip_manual` (Linux-only, `tests/identity.rs`). The write test uses service `chervotochina-migration-17a`, pair `PairId::from_bytes([0x17; 16])` with blob `[2] + [0x11; 128]`, list key `[0x5A; 32]`, epoch `0x1717`, written through the trait methods; no cleanup;
- commit separately. The commit hash goes into TASK.md for M1.

B1 (builder, sonnet/high):
- Cargo changes (section 6);
- `secret_service/` get/set/delete with worker, reconnect and errors;
- Linux `OsKeyStore`;
- fake service and unit tests T1-T22;
- `ss_migration_read_new`;
- source guard T23.

B2 (builder, sonnet/high):
- `request_unlock` with T24-T27;
- live tests L1-L3;
- `scripts/ci-secret-service.sh` and a CI job `secret-service-live` (ubuntu-latest: `sudo apt-get install -y --no-install-recommends gnome-keyring dbus-daemon`, which is required by TASK line 96, then `dbus-run-session -- bash scripts/ci-secret-service.sh`). The script runs `printf '%s' 'ci-not-a-secret' | gnome-keyring-daemon --unlock --components=secrets`, then `cargo test -p chervo-identity --locked -- --ignored ss_live_`. Actions are pinned by SHA like the rest of `ci.yml`.

B3 (builder, sonnet/medium): supply chain (section 6 deny/audit), lock diff report, `cargo tree` facts.

Then: `combine-security` ×2 (independent, fresh context) on the B1+B2+B3 diff against section 10. After review: the dirigent or architect updates THREAT_MODEL T12 rows 181-187 (plain session, residual buffers, no implicit prompt, timeouts) and SECURITY_REVIEW T12.

## 8. Tests and acceptance

Fake service (unit, `#[cfg(all(test, target_os = "linux"))]`):
- a raw `MessageStream` loop on the server end of `UnixStream::pair()` (`Builder::unix_stream(s0).server(Guid::generate()).p2p()`), replying with `Message::method_return`/`Message::error`;
- in-memory collections and items with fault knobs and call counters (records every member called);
- the server runs on its own thread and current-thread runtime;
- if zbus rejects the `destination` header on p2p, the client sends `destination: None` only under `cfg(test)`; report it as a deviation.

Test timeouts: call 200 ms, op 500 ms, caller 800 ms. Bounds are asserted as elapsed < 2 s.

T1 `ss_fake_roundtrip` (set/get/overwrite/delete/get=None) · T2 `ss_fake_create_exact_props` (attributes == exactly D4, label, content type, `replace = true`, collection = alias target) · T3 `ss_fake_existing_uses_setsecret` (no `CreateItem`) · T4 `ss_fake_two_matches_inconsistent` (get/set/delete) · T5 `ss_fake_locked_item_locked_no_prompt` (get/set/delete → Locked; counters: `Unlock` = `Prompt` = 0) · T6 `ss_fake_empty_default_locked_is_locked` · T7 `ss_fake_no_default_alias` (get → None, set → Unavailable) · T8 `ss_fake_create_prompt_dismissed` (Dismiss = 1, Prompt = 0, Locked) · T9 `ss_fake_delete_prompt_locked` · T10 `ss_fake_is_locked_and_access_denied_map_locked` · T11 `ss_fake_service_unknown_unavailable` · T12 `ss_fake_plain_not_supported_unavailable` · T13 `ss_fake_never_replies_bounded` · T14 `ss_fake_silent_peer_no_auth_bounded` (raw socket, never writes) · T15 `ss_fake_bad_signature_unavailable` · T16 `ss_fake_oversized_secret_inconsistent` · T17 `ss_fake_nonempty_parameters_inconsistent` · T18 `ss_fake_no_session_reconnects_once` (once OK; twice → Unavailable) · T19 `ss_fake_item_vanished` (get → Inconsistent, delete → Ok) · T20 `ss_fake_queue_full_unavailable` (immediate) · T21 `ss_fake_server_gone_unavailable_bounded` · T22 `ss_fake_osstore_list_key_and_epoch` (through `OsKeyStore` over the fake; epoch with a 7-byte value → Inconsistent) · T23 `ss_src_guard` (in `src/secret_service/`: no `std::fs`/`File::`/`OpenOptions`, no `block_on`; member strings `"Prompt"`/`"Unlock"` only in the unlock function's file; no `derive(Debug)`) · T24 `ss_fake_unlock_ok` · T25 `ss_fake_unlock_dismissed_locked` · T26 `ss_fake_unlock_timeout_dismisses_bounded` · T27 `ss_fake_unlock_forged_completed_rechecks` (signal says not dismissed, collection still locked → Locked).

Live (ignored, CI job `secret-service-live` only): L1 `ss_live_roundtrip` (pair, list key, epoch, delete) · L2 `ss_live_attributes_exact` (read back `Attributes`/`Label` via a `cfg(test)` helper; allowed extra key only `xdg:schema` if the daemon adds it [НП]) · L3 `ss_live_locked_bounded` (test helper calls `Service.Lock` on default; get/set/delete → Locked < 2 s each; `request_unlock(2 s)` → Locked < 5 s; runs last).

Acceptance (each by command, actual output in the report):
- [ ] Windows: `cargo build --workspace --locked`; `cargo test --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`.
- [ ] Linux type check from Windows, only if the target is already installed (installing it is the owner's call): `cargo clippy -p chervo-identity --target x86_64-unknown-linux-gnu --all-targets --locked -- -D warnings`.
- [ ] CI `test (ubuntu-latest)`: T1-T27 pass, `public_debug_redacted` passes. CI `test (windows, macos)` green and unchanged.
- [ ] CI `secret-service-live`: L1-L3 pass (log excerpt).
- [ ] `cargo audit --deny warnings` and `cargo deny check advisories bans licenses sources` with the exception removed.
- [ ] `cargo tree --locked -i <name>` reports "did not match" for each must-disappear name. `Cargo.lock` has exactly one `name = "zbus"` (6.0.0). `cargo tree -p chervo-identity --target x86_64-unknown-linux-gnu -e features -i zbus` shows no `tracing`/`default-rt`/`unixexec`/`ibus` in the normal tree.
- [ ] `cargo test -p chervo-core --test no_logger` green.

Manual tests on the owner's Linux machine (`combine-verifier` or the dirigent runs them; never name the host in the repo):
- M1, migration. At the B0 commit: `cargo test -p chervo-identity --locked -- --ignored ss_migration_write_old`. At the final commit: `-- --ignored ss_migration_read_new` (byte-exact read of all three entries, then delete, then get → None). **Release-blocking.**
- M2, headless roundtrip over ssh with gnome-keyring unlocked: `os_store_roundtrip_manual`, `os_list_key_roundtrip_manual`, `os_epoch_roundtrip_manual`.
- M3, locked after reboot (or daemon replaced without unlock): any op → `StorageLocked` within 12 s, no dialog, no hang. Then unlock over ssh with the candidate procedure [НП]: `loginctl enable-linger $USER` once; after login `read -rs P; printf '%s' "$P" | gnome-keyring-daemon --replace --unlock --components=secrets >/dev/null; unset P`. Repeat M2. Record which command actually worked.
- M4: `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent cargo test ... -- --ignored os_store_roundtrip_manual` fails fast with `StorageUnavailable` (no hang).

Stop conditions: P0 contradicts section 3; a zbus 6 API cited here differs; a new package other than the four in section 6; `unsafe` needed; gnome-keyring in CI has no `default` alias or does not report locked items in `locked`; M1 fails; any timeout bound cannot be met. Stop and report, do not work around. Limit: 2 rounds of "fix after review", then report.

Report (≤25 lines per builder part): files changed; commands with their last output lines; lock diff (added/removed names); what was not done; deviations.

## 9. Open questions for the owner (with recommendation)

Q1. Session `plain` (D1) or DH as before? **Recommend `plain`.** DH protects against no attacker in our model (same uid or root can ask the keyring directly). It adds variable-time 1024-bit DH and protocol code in our crate. Its only gain is that the plaintext key is not left in zbus/dbus buffers for the short life of a message. If you choose DH, Appendix B applies and `aes`/`cbc`/`hkdf`/`sha2`/`num-bigint` stay.

Q2. Read/write never show a password dialog; unlocking only by an explicit button (D5)? **Recommend yes.** The old client could freeze the program waiting for a dialog that cannot appear on a headless box. On the mini-PC, unlocking is over ssh (U10c).

## 10. Security review checklist (`combine-security`, ×2)

1. No fallback storage on any path; no `std::fs` in `secret_service/`.
2. `Ok(None)` only per D6. Every other branch is an error; no branch turns Locked or Unavailable into `None`.
3. `Prompt`/`Unlock` only in `request_unlock`; returned prompts elsewhere are dismissed and give Locked; unlock success is decided by the `Locked` property.
4. Every await is bounded (call/op/caller). No `block_on` on caller threads. The queue is bounded with `try_send`. Worker death or panic → Unavailable, no hang. `Drop` does not block.
5. Zeroization: secrets live only in `Zeroizing` (job, reply, decoded value wrapped before checks); no `clone`/`to_vec` outside `Zeroizing`. Residual documented: zbus/dbus-daemon buffers.
6. Redaction: no Debug or Display of secrets, service, account or zbus errors; `OsKeyStore` Debug is `OsKeyStore(..)`.
7. Compatibility contract D4 exact; one entry per pair; no friend name or keys in attributes or label.
8. Hostile replies (wrong types, sizes, counts, `/` paths, forged signals, silence) → fixed errors, no panic.
9. Features: zbus without default features and without `tracing`; `p2p` only in dev; no child process spawning (`unixexec`/`ibus` off).
10. Supply chain: lock diff matches section 6; exception removed; bans present; licences MIT; `unsafe` counts in zbus 6 and zruntime recorded (F16).
11. Consistency with T10/T12; THREAT_MODEL rows to update listed.

---

## Appendix B. DH variant (only if Q1 = DH)

Crates already in the lock: `num-bigint 0.4.8`, `hkdf 0.13.0`, `sha2 0.11.0`, `aes 0.9.3`, `cbc 0.2.1`, all MIT/Apache.
- Group: RFC 2409 Oakley group 2, `g = 2` (prime at `secret-service-5.2.0/src/session.rs:31-43`).
- Private key: 128 bytes from `getrandom`. Public key: `g^x mod p` as big-endian bytes.
- Validate the server key `1 < Y < p-1`; otherwise Unavailable.
- Shared secret: left-padded to 128 bytes.
- AES key: `HKDF-SHA256(salt = none, ikm = shared, info = []) → 16 bytes`.
- Secrets: AES-128-CBC with PKCS#7; a random 16-byte IV in `parameters`; a padding error → Inconsistent.
- Zeroize the private key bytes, the shared secret bytes and the AES key (`BigUint` cannot be zeroized: residual).
- `modpow` is variable time (residual, as THREAT_MODEL L4).
