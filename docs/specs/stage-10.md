# SPEC 10: Идентичность          критичность: КРИТИЧНЫЙ

Автор: combine-architect, 2026-10-09. Исполнитель: combine-builder (sonnet/high), приёмка combine-verifier, ревью combine-security. Ничего из этого не запускалось. [НП] = не проверено, проверить по исходнику выбранной версии; [В] = вывод архитектора.

Цель: у устройства есть постоянный ключ Ed25519, созданный библиотекой, хранимый только в хранилище ОС (за трейтом), в памяти обнуляемый при освобождении и никогда не пишущийся на диск в открытом виде.
Прочитать: этот файл; `docs/BRIEF.md` разд. 2, 3, 7; `docs/OPEN_QUESTIONS.md` U10; `crates/chervo-identity/*`; корневой `Cargo.toml`; `deny.toml`; `.github/workflows/ci.yml`. Больше ничего не искать.

Сделать (по порядку, каждый шаг проверить до следующего, CORE п.5):
1. Среда: `cargo --version`, `rustc --version`. Команда не найдена → СТОП (см. стоп-условия), код не писать.
2. Версии [НП]: для `ed25519-dalek`, `getrandom`, `zeroize`, `keyring` взять последнюю стабильную версию с crates.io, совместимую с `rust-version = 1.97` (`cargo search <имя> --limit 1`; вывод в отчёт). В DECISION упомянут `keyring` 4.2.0 (данные разведчиков, не проверено). Номера и дату записать в отчёт и в сообщение коммита.
3. Исходник, до первой строки кода (CORE п.3), в `~/.cargo/registry/src/*/<крейт>-<версия>/` (после `cargo fetch`) проверить и записать с файлом:строкой:
   а) `ed25519-dalek`: имена фич (`zeroize`, `std`, `fast`, а также `rand_core`, `serde`, `pkcs8`, `pem`, `hazmat`); реализует ли `SigningKey` `ZeroizeOnDrop` при включённой `zeroize`; есть ли `SigningKey::from_bytes(&[u8;32])`, `VerifyingKey::from_bytes`, `VerifyingKey::is_weak`, `verify_strict`.
   б) `getrandom`: функция заполнения буфера с `Result` без паники (`fill` или `getrandom`, зависит от версии).
   в) `keyring` и крейты хранилищ, которые он тянет на каждой ОС: API записи/чтения байтов секрета и удаления, ошибка «записи нет». Ответ на U10, по пунктам:
      macOS: какой API ключницы (старая файловая ключница или data protection keychain), ставится ли `kSecAttrSynchronizable` (синхронизация iCloud), можно ли запретить её и задать доступность «только это устройство»;
      Windows: Credential Manager или иное; значение `Persist` в `CredWriteW` (LOCAL_MACHINE или ENTERPRISE, который перемещается с перемещаемым профилем); предел размера секрета;
      Linux: бэкенд по умолчанию; хранит ли он постоянно (Secret Service) или до перезагрузки (keyutils); что происходит без запущенного Secret Service (ошибка или молчаливая замена); нужны ли системные библиотеки при сборке (libdbus).
      Записать в `docs/OPEN_QUESTIONS.md` под U10 подпункт «Статус (этап 10)»: версия, ответы с метками [П] (исходник, файл:строка) / [НП]. «Попадает ли в бэкап ОС» исходником не решается: так и написать.
4. Зависимости. Корень `[workspace.dependencies]`, в крейте `<имя>.workspace = true`:
   `ed25519-dalek` (`default-features = false`, фичи только `std`, `zeroize` и при наличии `fast`): генерация из seed, подпись, проверка. `getrandom`: случайный seed из CSPRNG ОС. `zeroize`: `Zeroizing<..>` для буферов и маркер `ZeroizeOnDrop`. `keyring`: хранилище ОС, только под `cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))`, фичи по итогам шага 3в (постоянное хранилище, по возможности чистый Rust).
   Других зависимостей и dev-зависимостей не добавлять. После `cargo build` закоммитить обновлённый `Cargo.lock`.
5. Реализовать API ниже в `src/lib.rs` (допустимо разбить на модули `src/*.rs`), обновить `tests/identity.rs`, добавить `tests/no_disk.rs`.
6. Прогнать все критерии приёмки и выложить хвосты вывода.

Интерфейс (точно). Публичный API после этапа:
```rust
pub const KEY_BLOB_VERSION: u8 = 1;   // формат записи в хранилище: [версия][seed 32 байта]
pub const KEY_BLOB_LEN: usize = 33;
pub struct DeviceId([u8; 32]);        // без изменений: derive Clone, Copy, PartialEq, Eq, Hash; Debug = "DeviceId(..)"
impl DeviceId {
    pub const fn from_bytes(b: [u8; 32]) -> Self;            // без изменений, НЕ проверяет; doc: для недоверенного ввода try_from_slice
    pub const fn as_bytes(&self) -> &[u8; 32];               // без изменений
    pub fn try_from_slice(b: &[u8]) -> Result<Self, IdentityError>;            // новое
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), IdentityError>; // новое, verify_strict
}
pub struct DeviceKey { /* ed25519_dalek::SigningKey */ }  // новое; НЕ Clone, нет Display, нет serde
impl DeviceKey {
    pub fn generate() -> Result<Self, IdentityError>;     // seed: Zeroizing<[u8;32]> из getrandom -> SigningKey::from_bytes
    pub fn device_id(&self) -> DeviceId;
    pub fn sign(&self, msg: &[u8]) -> [u8; 64];
}
impl fmt::Debug for DeviceKey  // ровно "DeviceKey(..)"
impl zeroize::ZeroizeOnDrop for DeviceKey {}  // маркер; допустим, только если SigningKey: ZeroizeOnDrop (шаг 3а)
pub trait SecretKeyStore: Send + Sync {                    // ИЗМЕНЕНО: было load_or_create/delete
    fn read(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, IdentityError>; // Ok(None) = записи нет
    fn write(&self, blob: &[u8]) -> Result<(), IdentityError>;                     // перезапись
    fn delete(&self) -> Result<(), IdentityError>;                                 // записи нет = Ok(())
}
pub fn load_or_create<S: SecretKeyStore + ?Sized>(store: &S) -> Result<DeviceKey, IdentityError>; // новое
pub struct UnavailableKeyStore;   // без изменений по смыслу: read/write/delete -> Err(NotImplemented)
pub struct MemoryKeyStore { /* Mutex<Option<Zeroizing<Vec<u8>>>> */ } // новое; new(), Default; Debug = "MemoryKeyStore(..)"
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub struct OsKeyStore { /* service, account */ }          // новое; Debug = "OsKeyStore(..)"
impl OsKeyStore { pub fn new(service: &str, account: &str) -> Self; }
pub const DEFAULT_SERVICE: &str = "chervotochina";
pub const DEFAULT_ACCOUNT: &str = "device-key-v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    NotImplemented,        // "not implemented" (было)
    StorageUnavailable,    // "key storage unavailable" (было): любая ошибка ОС/keyring, отравленный Mutex
    CorruptKey,            // "stored key is corrupt": длина записи != KEY_BLOB_LEN
    UnsupportedKeyVersion, // "unsupported stored key version": байт 0 != KEY_BLOB_VERSION
    StorageInconsistent,   // "key storage inconsistent": прочитанное после записи не совпало
    RandomUnavailable,     // "os random source unavailable"
    InvalidPublicKey,      // "invalid public key": длина != 32, не точка, малый порядок (is_weak)
    BadSignature,          // "bad signature"
}
```
Семантика `load_or_create`: `read`; `Some(blob)` → разобрать (длина, затем версия) и вернуть ключ; ошибка разбора → вернуть ошибку, запись НЕ перезаписывать и новый ключ НЕ создавать (смена ключа только явным `delete`, BRIEF разд. 3 «потеря устройства»). `None` → `generate`, собрать blob в `Zeroizing`, `write`, затем `read` и сверить: не совпало или `None` → `StorageInconsistent`. `OsKeyStore`: ошибка keyring «записи нет» → `Ok(None)`, любая другая → `StorageUnavailable` без подробностей.
Изменения публичного API (ломающие): методы трейта `SecretKeyStore` заменены (`load_or_create` стал свободной функцией и возвращает `DeviceKey`, не `DeviceId`); `IdentityError` получил `#[non_exhaustive]` и новые варианты. Вне `chervo-identity` трейт и `load_or_create` не используются (проверено grep по дереву), остальные крейты правок не требуют.

Не делать:
- Не трогать другие крейты, `deny.toml`, `ci.yml`, `rust-toolchain.toml`, workspace-линты (`unsafe_code = "forbid"` остаётся), документы кроме U10 в `docs/OPEN_QUESTIONS.md`.
- Никакой своей криптографии: никаких операций над байтами ключа, кроме копирования seed в blob и обратно; генерация, подпись и проверка только вызовами `ed25519-dalek`/`getrandom`.
- Не писать ключ (seed, blob, hex) в файлы, переменные окружения, аргументы процессов, логи, `println!`. Никакого «запасного» файлового хранилища, даже зашифрованного.
- Не давать `DeviceKey` методов, возвращающих seed; передача ключа транспорту (iroh/rustls) это отдельный этап.
- Не включать фичи `serde`, `pkcs8`, `pem`, `rand_core`, `hazmat`, `legacy_compatibility`. Не трогать iroh/quinn.

Недоверенный ввод: байты из хранилища (любая длина от 0 до мегабайт, любой первый байт) и байты публичного ключа в `try_from_slice`/`verify`. Порядок проверок: длина, затем версия, затем библиотечный разбор. Все ошибки через `IdentityError`, без `unwrap`/`expect`/индексации, способной паниковать, в `src/`. Сообщения ошибок не содержат байтов ввода.

Тесты (имена точно). `tests/identity.rs` (свои тестовые хранилища реализовать в файле теста через публичный трейт: `FixedStore(Vec<u8>)`, `LossyStore` — `write` Ok, `read` всегда None, `FailingStore` — всё `StorageUnavailable`):
- позитивные: `device_id_roundtrip` (как было), `debug_does_not_leak_key` (обновить вызов на `load_or_create(&UnavailableKeyStore)`), `generate_gives_distinct_keys`, `load_or_create_creates_then_reloads_same_id`, `sign_verify_roundtrip`, `delete_then_create_gives_new_id`, `try_from_slice_accepts_generated_key`, `device_key_debug_redacted` (ровно "DeviceKey(..)", нет hex seed), `store_debug_redacted`, `secret_types_zeroize_on_drop` (проверка на этапе компиляции: `fn f<T: zeroize::ZeroizeOnDrop>() {}` для `DeviceKey`, `ed25519_dalek::SigningKey`, `Zeroizing<Vec<u8>>`), `src_has_no_filesystem_io` (читает `src/**/*.rs` через `env!("CARGO_MANIFEST_DIR")`; нет `std::fs`, `File::`, `OpenOptions`, `set_var`, `println!`, `eprintln!`, `dbg!`);
- негативные: `unavailable_store_fails_closed`, `blob_empty_rejected`, `blob_too_short_rejected` (32 байта), `blob_too_long_rejected` (34 байта и 1 МиБ), `blob_unknown_version_rejected` (0x00, 0x02, 0xFF; длина 33), `corrupt_blob_not_overwritten` (после ошибки содержимое хранилища прежнее), `lossy_store_detected` (`StorageInconsistent`), `failing_store_propagates`, `try_from_slice_rejects_wrong_length` (0, 31, 33), `try_from_slice_rejects_weak_key` (кодировка единичной точки: 0x01 и 31 нулевой байт), `verify_rejects_modified_message`, `verify_rejects_modified_signature`, `verify_rejects_other_key`;
- `os_store_roundtrip_manual` с `#[ignore]`: реальное хранилище, сервис `chervotochina-test`, в конце `delete`. В CI не запускается.
`tests/no_disk.rs` (отдельный бинарь, потому что меняет текущий каталог процесса):
- `key_bytes_not_written_to_data_dir`: уникальный каталог D под `std::env::temp_dir()`, `set_current_dir(D)`, полный цикл (`load_or_create` на `MemoryKeyStore`, `sign`, drop), seed взять из `store.read()`; рекурсивно просканировать D на сырые 32 байта, hex в нижнем и верхнем регистре; не найдено; D удалить.
- `scan_detects_planted_key`: положительный контроль, тот же сканер находит seed, специально записанный в отдельный каталог D2 (без смены текущего каталога).

Критерии приёмки (каждый проверяется командой, вывод в отчёт):
- [ ] `cargo build -p chervo-identity --locked` и `cargo build --workspace --locked`
- [ ] `cargo test -p chervo-identity --locked`: проходят все тесты из перечня выше (включая негативные), `os_store_roundtrip_manual` в статусе ignored
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `bash scripts/check-forbidden.sh` и `bash scripts/check-forbidden.sh --self-test`
- [ ] `cargo tree -p chervo-identity -e normal --depth 1`: прямые зависимости ровно из шага 4
- [ ] `cargo deny check licenses sources` и `cargo audit --deny warnings`, если установлены; если нет, так и написать «не запускался»
- [ ] `docs/OPEN_QUESTIONS.md` U10 содержит «Статус (этап 10)» с ответами шага 3в и метками

НЕ проверяется на этапе (записать в отчёт, не заявлять):
- CI-матрица 3 ОС: проверяет дирижёр после пуша (статус прогона GitHub Actions), не builder локально.
- Поведение реальных хранилищ Windows/macOS/Linux (`os_store_roundtrip_manual` выключен): сохранность, синхронизация в iCloud, перемещаемый профиль, бэкапы, запросы разблокировки. Только чтение исходника (шаг 3в).
- Отсутствие копий секрета в памяти: `zeroize` обнуляет при drop, но не копии от перемещений, буферы ОС/keyring и аварийное завершение процесса [В]; тест это не доказывает.
- Отсутствие записи ключа вне каталога D (своп, дампы, журналы ОС).

Стоп-условия: противоречие спецификации и кода, нужна новая зависимость или критерий непроверяем: остановиться и доложить, не обходить. Дополнительно:
- нет `cargo`/`rustc` в среде → остановиться сразу, код не писать вслепую, ничего не устанавливать;
- API или фичи из шага 3 устроены иначе, чем здесь (например, `SigningKey` не `ZeroizeOnDrop`) → записать факт и остановиться;
- шаг 3в: на macOS нельзя выключить синхронизацию iCloud, на Windows `Persist` = ENTERPRISE без настройки, на Linux бэкенд непостоянный или молча подменяется, сборка требует системных пакетов или правки `ci.yml` → записать U10 и не писать `OsKeyStore`; шаги 4-6 без `keyring` можно завершить, отклонение указать в отчёте;
- лицензия любой новой зависимости вне `deny.toml` → остановиться, `deny.toml` не править.
Лимит: не более 2 кругов «правка по ревью», затем доложить.
Отчёт (до 25 строк): изменённые файлы; версии зависимостей и откуда; команды приёмки и последние строки их вывода; что не сделано; отклонения от спецификации.

Для владельца (кратко): ключ хранится только в хранилище ОС, без запасного файла; повреждённая запись не перезаписывается молча; `DeviceId::from_bytes` оставлен непроверяющим ради совместимости (проверка через `try_from_slice`); реальное хранилище в CI не тестируется (`#[ignore]`), только сборка.
