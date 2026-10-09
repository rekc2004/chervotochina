# SPEC 10: Идентичность (ключи пар)          критичность: КРИТИЧНЫЙ

Автор: combine-architect, 2026-10-09, редакция 3 (редакция 2: учтены 15 замечаний `docs/exp/SECURITY-REVIEW-SPEC10.md` и решение владельца U10a-2; редакция 3: по ревью дирижёра `DeviceId` остаётся заглушкой, т.к. используется другими крейтами; факт по supply-chain). Метки: [П] проверено мной по исходнику крейта с crates.io (файл:строка, версия ниже); [НП] не проверено, проверяется командой из критериев или остаётся в «НЕ проверяется»; [В] вывод архитектора. Ничего из спецификации не запускалось.

Основание: действует только раздел «U10a-2» в `docs/OWNER_DECISIONS.md`; «U10a, первая редакция» отменена и не применяется. Ключ создаётся на каждую пару друзей (U10a-2 п.3), не один на устройство. Вопросы совместимости с DECISION/BRIEF вынесены в `docs/OPEN_QUESTIONS.md` U10b; этот этап от ответа на U10b не зависит.

Цель: крейт `chervo-identity` умеет явно создать, загрузить с проверкой, пересоздать и удалить ключ Ed25519 одной пары друзей в хранилище ОС (Windows, macOS, Linux); ключ никогда не создаётся молча; «записи нет» отличается от «хранилище недоступно/заблокировано»; подпись только с разделением доменов; приватный ключ не покидает хранилище ОС и память процесса средствами приложения.

Прочитать: этот файл; `docs/BRIEF.md` разд. 2, 3, 7; `docs/OWNER_DECISIONS.md` раздел U10a-2; `docs/OPEN_QUESTIONS.md` U10, U10b; `crates/chervo-identity/*`; корневой `Cargo.toml`; `deny.toml`; `.github/workflows/ci.yml`; `scripts/check-forbidden.sh`. Больше ничего не искать.

## Модель (что хранится и как адресуется)
- **Пара** идентифицируется `PairId`: 16 случайных байт из CSPRNG ОС, локальный несекретный дескриптор. Не выводится из ключей и не содержит имени друга. Хранится в списке друзей (этап 11). Пойдёт ли он в сеть, решает U10b / этап 9.
- **В хранилище ОС** на каждую пару одна запись: service = `chervotochina` (`DEFAULT_SERVICE`), account = `pair-v1-` + 32 строчные hex-цифры `PairId`. Число записей = число друзей + незавершённые приглашения. Других записей нет. В service/account/метку записи не попадают имя друга, его ключ или наш публичный ключ: их видят интерфейсы ОС и журналы keyring-core (`debug!` с service/user: keyring-core `src/lib.rs:131,166,282` [П]).
- **Секрет записи** (blob, 65 байт): `[0x01][seed 32][публичный ключ 32]`. Публичная часть нужна для контроля целостности (замечание 5): при загрузке ключ выводится из seed и сверяется с ней.
- **Несекретная метка** рядом с данными приложения: наш публичный ключ пары (32 байта), его хранит список друзей (этап 11) и передаёт в `load` как `expected`. Отпечаток для показа человеку делает этап 11.
- **Кто подписывает приглашение до появления пары:** новый ключ пары, созданный явным `create` в момент «добавить друга» (U10a-2 п.5). Подпись в приглашении доказывает только владение ключом; подлинность даёт SAS (BRIEF разд. 3, без изменений) [В].
- **Токен обновления адреса** подписывается ключом той пары, которой он адресован (домен `AddressUpdate`): один токен на друга (следствие записано в U10b) [В].
- **Выбор ключа сервером в TLS** до того, как известен клиент: не в этом этапе, см. U10b (варианты: идентификатор пары в первом пакете/SNI, отдельный транспортный ключ, endpoint на пару). Этап 10 не передаёт ключ транспорту и не даёт метода, возвращающего seed; API для транспорта добавит этап 9 по ответу на U10b.
- **`DeviceId` (заглушка скелета)** остаётся без изменений: его используют `chervo-friends`, `chervo-transport`, `chervo-token`, тесты `chervo-transport` и `chervo-connect` (grep дирижёра), а другие крейты этот этап не трогает. Это несекретный 32-байтный идентификатор без проверки, не ключ и не связан с ключами пар; новый API его не принимает и не возвращает. Заменить или удалить его решают этапы 9/11 по ответу на U10b [В].

## Факты по исходникам (версии для этапа)
Версии: `ed25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0 (транзитивно), `zeroize` 1.9.1, `getrandom` 0.4.3, `keyring-core` 1.0.0, `apple-native-keyring-store` 1.0.2, `windows-native-keyring-store` 1.1.0, `zbus-secret-service-keyring-store` 1.0.1. Все MSRV ≤ 1.88 (`rust-version` в их `Cargo.toml`) ≤ наш 1.97 [П].
1. **Мета-крейт `keyring` 4.2.0 не брать.** Его фича `v1` (по умолчанию) сама выбирает хранилище и ставит глобальное хранилище по умолчанию (`keyring-4.2.0/src/v1.rs:107-129`, `Cargo.toml:61-66`); автор сам советует приложениям, которым нужен контроль, брать `keyring-core` и конкретные хранилища (`src/lib.rs:17-27`) [П]. Берём `keyring-core` + по одному хранилищу на ОС и вызываем `CredentialStoreApi::build` у явно созданного хранилища (`keyring-core-1.0.0/src/api.rs:204-209`) [П].
2. **Подмена mock (замечание 2):** в keyring-core хранилище по умолчанию изначально `None` и `Entry::new` без него даёт `NoDefaultStore` (`src/lib.rs:52-53,105-108`); `mock` ставится только явным `set_default_store` (`src/mock.rs:13,29`); `sample` за необязательной фичей без умолчаний (`Cargo.toml:41-49`) [П]. Молчаливой подмены в 4.x нет; мы глобальное хранилище не используем вообще (grep в критериях).
3. **Ошибки keyring-core** (`src/error.rs:24-74`, `#[non_exhaustive]`) [П]: `NoEntry` = записи нет; `NoStorageAccess` = заблокировано/нет доступа; `Ambiguous` = несколько записей; `BadEncoding(Vec<u8>)` и `BadDataFormat(Vec<u8>, _)` **несут сырые байты секрета** (`:44,50`): при отображении в нашу ошибку обнулить. `Debug`/`Display` ошибок keyring не выводить никуда.
4. **macOS** (`apple-native-keyring-store`, фича `keychain`; без фичи на macOS `compile_error`, `src/lib.rs:36-43`) [П]: `keychain::Store::new()` = пользовательская (login) файловая ключница (`src/keychain.rs:181-183`); запись через `set_generic_password` без атрибута синхронизации (`:71-75`); чтение копирует секрет в `Vec` (`:79-84`); `errSecItemNotFound` → `NoEntry`, ошибки доступа/блокировки → `NoStorageAccess` (`:367-377`). Хранилище «protected data» требует подписи с provisioning profile (`src/protected.rs:8-10`), синхронизация iCloud там включается только явно (`:13-19`): в v1 не используем. Синхронизируется ли старая файловая ключница через iCloud [НП]; по U10a-2 п.1 это не требование.
5. **Windows** (`windows-native-keyring-store`) [П]: Credential Manager, generic credential, target = `{user}.{service}` при `Store::new()` (`src/store.rs:35-40`, `src/cred.rs:52-58`); `Persist` по умолчанию **Enterprise** (`src/store.rs:116-121`), модификатор `persistence` = `Local` даёт `CRED_PERSIST_LOCAL_MACHINE` (`src/utils.rs:23-55`). Берём `Local` как консервативный вариант (перемещаемый профиль по U10a-2 п.1 не запрещён, но приложению он не нужен). Копия секрета при записи и буфер ОС при чтении обнуляются (`src/utils.rs:141,173,248-251`), но возвращается обычный `Vec` (`:300-307`). `ERROR_NOT_FOUND` → `NoEntry`, `ERROR_NO_SUCH_LOGON_SESSION` → `NoStorageAccess` (`:394-399`). Фича по умолчанию `search` тянет `regex` (`Cargo.toml:40-42`): выключить. Предел размера секрета `CRED_MAX_CREDENTIAL_BLOB_SIZE` проверяется (`src/utils.rs:96-104`), его значение [НП], 65 байт заведомо меньше [В].
6. **Linux** (`zbus-secret-service-keyring-store`, фича `crypto-rust`) [П]: Secret Service по D-Bus (zbus, чистый Rust); сессия с шифрованием `EncryptionType::Dh` (`src/service.rs:26`); криптография сессии выбирается фичей `crypto-rust` или `crypto-openssl`, по умолчанию ни одна (`Cargo.toml:41-47`); без демона `Store::new()` возвращает ошибку `PlatformFailure`, запасного хранилища нет (`src/service.rs:24-27`, `src/store.rs:48-62`); заблокированные записи разблокируются запросом, отказ → `NoStorageAccess` (`src/service.rs:39-42`, `src/errors.rs:11-18`); при отсутствии записи создаётся в коллекции по умолчанию (`src/cred.rs:115-126`); несколько совпадений → `Ambiguous` (`:83-98`); метка записи по умолчанию `keyring:{user}@{service}` (`:45-48`). `persistence()` не переопределён → «до удаления» (`keyring-core src/api.rs:235-237`). Поведение без фичи шифрования и внутренности крейта `secret-service` 5 [НП]. Нужна ли libdbus при сборке: по манифестам нет (zbus) [В], проверяется `cargo tree`. `linux-keyutils-keyring-store` не берём: хранит до перезагрузки (`src/store.rs:139-141`) [П].
7. **ed25519-dalek 3.0.0** [П]: фичи `alloc, batch, digest, fast, hazmat, legacy_compatibility, pem, pkcs8, rand_core, serde, zeroize`, по умолчанию `fast, zeroize`; **фичи `std` нет** (`Cargo.toml:62-102`). `SigningKey::from_bytes(&[u8;32])` (`src/signing.rs:115-121`); `SigningKey` derive `Clone` (`:76`), обнуляет seed в `Drop` и `ZeroizeOnDrop` при фиче `zeroize` (`:718-726`); `ExpandedSecretKey` обнуляется в `Drop` (`src/hazmat.rs:67-76`), но временные массивы в `ExpandedSecretKey::from_bytes` (`:86-89`) и выход SHA-512 в `From<&SecretKey>` (`src/signing.rs:866`) не обнуляются: остаток внутри библиотеки, без своей криптографии не исправить. Подпись: `Signer::try_sign` (`src/signing.rs:598-610`, трейт реэкспортирован `src/lib.rs:294`), всегда `Ok`. `VerifyingKey::from_bytes` проверяет по правилам ZIP-215 и **не отвергает неканоническую кодировку** (`src/verifying.rs:142-143,175-182`; `curve25519-dalek-5.0.0/src/edwards.rs:211-219,229`); `to_bytes()` возвращает исходные байты ввода (`src/verifying.rs:130-131,176`), поэтому сравнение `to_bytes() == input` бесполезно; каноничность проверять перекодированием `VerifyingKey::from(vk.to_edwards()).to_bytes()` (`:113-119,489`). `is_weak` = малый порядок (`:200-202`); `verify_strict` отвергает малый порядок ключа и R (`:367-390`). `Debug` у `VerifyingKey` печатает байты (`:76-80`). Конструкция `Signature` из `[u8;64]` и `to_bytes()` в крейте `ed25519` 3 [НП]: проверить в `~/.cargo/registry/src` после `cargo fetch`.
8. **getrandom 0.4.3** [П]: `getrandom::fill(&mut [u8]) -> Result<(), Error>` (`src/lib.rs:87`), фич по умолчанию нет (`Cargo.toml:55-61`).
9. **zeroize 1.9.1** [П]: `Zeroizing<Z>` реализует `ZeroizeOnDrop` (`src/lib.rs:599,695`), массивы `[u8;N]` поддержаны (`:340`); обнуление `Vec` «по возможности», прежние буферы после переаллокации не обнуляются (`:512-532`); фича по умолчанию `alloc` (`Cargo.toml:55`).

## Сила защиты хранилища по ОС (U10a-2 п.2)
| ОС, хранилище | Вредонос под тем же пользователем | Украденный ноутбук | Синхронизация/бэкап средствами пользователя |
|---|---|---|---|
| Windows, Credential Manager, `Persist=Local` | читает без запроса через `CredReadW` [НП]: защиты нет [В] | зависит от пароля входа и шифрования диска (DPAPI) [НП] | `Local` не перемещается с профилем [НП]; бэкап пользователя допустим (U10a-2 п.1) |
| macOS, login keychain (старая файловая) | другому приложению ОС показывает запрос доступа [НП]; пользователь может разрешить «всегда» [НП]: слабая защита | ключница зашифрована паролем входа [НП] | атрибута синхронизации не ставим [П keychain.rs:71-75]; iCloud для старой ключницы [НП]; допустимо (п.1) |
| Linux, Secret Service (gnome-keyring, KWallet) | открытую коллекцию читает любой процесс сессии D-Bus без запроса [НП]: защиты нет [В] | коллекция зашифрована паролем входа [НП] | файлы коллекции попадают в бэкап домашнего каталога [НП]; допустимо (п.1) |
Вывод [В]: от вредоноса под тем же пользователем хранилище ОС не защищает (кроме, возможно, запроса на macOS). Меры по U10a-2 п.2: функция `rekey` (этот этап), автоприём выключен и уведомление друзей (этапы 11/12/15, ниже). Привязка к железу (TPM, Secure Enclave) в v1 не входит (п.4).

## Сделать (по порядку, каждый шаг проверить до следующего, CORE п.5)
1. Среда: `cargo --version`, `rustc --version`. Нет команды → СТОП.
2. Использование удаляемого API вне крейта: `grep -rnE "SecretKeyStore|load_or_create" crates --include=*.rs | grep -v "^crates/chervo-identity/"`. Непусто → СТОП (другие крейты не трогаем, решает architect). `DeviceId` в grep не входит: он остаётся (см. «Интерфейс»), его использование другими крейтами ожидаемо.
3. Версии: `cargo search <имя> --limit 1` для восьми крейтов из «Фактов». В спецификацию вписаны версии выше; если на crates.io новее, **не переходить**, записать в отчёт (ссылки файл:строка верны только для этих версий).
4. Зависимости. В корне `[workspace.dependencies]` с точными версиями (`"=X.Y.Z"`):
   `ed25519-dalek = { version = "=3.0.0", default-features = false, features = ["zeroize", "fast"] }`; `getrandom = { version = "=0.4.3", default-features = false }`; `zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }`; `keyring-core = { version = "=1.0.0", default-features = false }`; `apple-native-keyring-store = { version = "=1.0.2", default-features = false, features = ["keychain"] }`; `windows-native-keyring-store = { version = "=1.1.0", default-features = false }`; `zbus-secret-service-keyring-store = { version = "=1.0.1", default-features = false, features = ["crypto-rust"] }`.
   В крейте: первые четыре в `[dependencies]`; хранилища в `[target.'cfg(target_os = "macos")'.dependencies]`, `[target.'cfg(target_os = "windows")'.dependencies]`, `[target.'cfg(target_os = "linux")'.dependencies]` через `.workspace = true`. Больше ничего (и никаких dev-зависимостей). После `cargo build` закоммитить `Cargo.lock`.
5. `cargo fetch`, затем сверить с исходником в `~/.cargo/registry/src/*/`: конструкцию и `to_bytes` у `ed25519::Signature` (факт 7, [НП]); что строки из «Фактов» совпадают (выборочно 3-4 ссылки). Расхождение → СТОП.
6. Реализовать API ниже в `src/` (модули `src/*.rs` допустимы), заменить `tests/identity.rs`, добавить `tests/common/mod.rs`, `tests/no_disk.rs`.
7. В `docs/OPEN_QUESTIONS.md` под U10 добавить подпункт «Статус (этап 10)»: решение заменено U10a-2; ответы по хранилищам в `docs/specs/stage-10.md` («Факты», таблица ОС), что подтверждено шагом 5. Других документов не менять.
8. Прогнать все критерии приёмки и выложить хвосты вывода.

## Интерфейс (точно)
```rust
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic,
        clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro, clippy::todo)]  // в src/lib.rs

pub const KEY_BLOB_VERSION: u8 = 1;
pub const KEY_BLOB_LEN: usize = 65;          // [версия][seed 32][публичный ключ 32]
pub const DEFAULT_SERVICE: &str = "chervotochina";
pub const ACCOUNT_PREFIX: &str = "pair-v1-";

// Заглушка скелета, оставить как есть (используется другими крейтами; решение по U10b, этапы 9/11).
// Сигнатуры, derive и Debug не менять. Не ключ: байты не проверяются, к ключам пар не относится.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);               // Debug = "DeviceId(..)" (как сейчас)
impl DeviceId {
    pub const fn from_bytes(b: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
// Doc-комментарий DeviceId заменить на: «Временный несекретный идентификатор-заглушка для других
// крейтов. Не публичный ключ: байты не проверяются. Не используется API ключей пар. Будет заменён
// или удалён по решению U10b (этапы 9/11).» Упоминание «проверка точки появится в этапе 10» убрать.

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairId([u8; 16]);                 // несекретный; Debug = "PairId(..)"
impl PairId {
    pub fn generate() -> Result<Self, IdentityError>;      // getrandom::fill; ошибка -> RandomUnavailable
    pub const fn from_bytes(b: [u8; 16]) -> Self;          // любые 16 байт допустимы (из списка друзей)
    pub const fn as_bytes(&self) -> &[u8; 16];
    pub fn account_name(&self) -> String;                  // "pair-v1-" + 32 строчные hex, без паник
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);  // только проверенный; Debug = "PublicKey(..)"
impl PublicKey {
    pub fn try_from_slice(b: &[u8]) -> Result<Self, IdentityError>; // см. «Недоверенный ввод»
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn verify(&self, domain: SignDomain, msg: &[u8], sig: &[u8]) -> Result<(), IdentityError>;
        // sig.len() != 64 -> BadSignature; verify_strict над tag||msg; любая ошибка -> BadSignature
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignDomain { Invite, AddressUpdate, KeyRevocation }
impl SignDomain {
    pub const ALL: &'static [SignDomain];
    pub const fn tag(self) -> &'static [u8];
    // Invite        => b"chervotochina/v1/invite\0"
    // AddressUpdate => b"chervotochina/v1/address-update\0"
    // KeyRevocation => b"chervotochina/v1/key-revocation\0"
}

pub struct PairKey { /* ed25519_dalek::SigningKey */ }
// НЕТ: Clone, Copy, PartialEq, Eq, Hash, AsRef, Deref, Display, serde, методов, отдающих seed/blob.
impl PairKey {
    pub fn public_key(&self) -> PublicKey;
    pub fn sign(&self, domain: SignDomain, msg: &[u8]) -> Result<[u8; 64], IdentityError>;
        // Signer::try_sign над tag||msg (msg не секрет, буфер Vec допустим); Err -> SigningFailed
}
impl fmt::Debug for PairKey   // ровно "PairKey(..)"
impl zeroize::ZeroizeOnDrop for PairKey {}  // маркер: единственное поле SigningKey обнуляется само (факт 7)

pub trait SecretStore: Send + Sync {
    fn read(&self, pair: &PairId) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, IdentityError>; // None = записи нет
    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError>;                    // перезапись
    fn delete(&self, pair: &PairId) -> Result<(), IdentityError>;                                // записи нет = Ok(())
}
pub fn create<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError>;
pub fn load<S: SecretStore + ?Sized>(store: &S, pair: &PairId, expected: &PublicKey) -> Result<PairKey, IdentityError>;
pub fn rekey<S: SecretStore + ?Sized>(store: &S, pair: &PairId) -> Result<PairKey, IdentityError>;

pub struct UnavailableKeyStore;   // read/write/delete -> Err(NotImplemented)
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub struct OsKeyStore { /* Arc<keyring_core::CredentialStore>, service: String */ } // Debug = "OsKeyStore(..)"
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl OsKeyStore {
    pub fn open() -> Result<Self, IdentityError>;                       // service = DEFAULT_SERVICE
    pub fn open_with_service(service: &str) -> Result<Self, IdentityError>; // для ручного теста; пустой -> StorageUnavailable
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {          // Display: строка в кавычках, без байтов ввода
    NotImplemented,       // "not implemented"
    StorageUnavailable,   // "key storage unavailable"
    StorageLocked,        // "key storage locked or access denied"
    StorageInconsistent,  // "key storage inconsistent"
    KeyMissing,           // "pair key missing"
    KeyAlreadyExists,     // "pair key already exists"
    KeyMismatch,          // "pair key does not match expected public key"
    CorruptKey,           // "stored key is corrupt"
    UnsupportedKeyVersion,// "unsupported stored key version"
    RandomUnavailable,    // "os random source unavailable"
    InvalidPublicKey,     // "invalid public key"
    BadSignature,         // "bad signature"
    SigningFailed,        // "signing failed"
}
```
Удаляется: трейт `SecretKeyStore` с `load_or_create` (шаг 2 подтверждает, что вне крейта их нет; `UnavailableKeyStore` теперь реализует `SecretStore`). `DeviceId` **остаётся** без изменений сигнатур (см. выше; вне крейта `IdentityError` и `UnavailableKeyStore` не используются, поэтому `#[non_exhaustive]` и новые варианты другие крейты не ломают, по grep дирижёра). `MemoryKeyStore` в библиотеке **нет** (замечание 14): тестовые хранилища живут в `tests/common/mod.rs`.

Семантика (точно):
- `create`: `read(pair)`; `Some(_)` (даже испорченная) → `KeyAlreadyExists`, запись не трогать. `None` → seed в `Zeroizing<[u8; 32]>`, заполнить `getrandom::fill` на месте (ошибка → `RandomUnavailable`); `SigningKey::from_bytes(&seed)`; blob в `Zeroizing<[u8; KEY_BLOB_LEN]>` копированием в подсрезы (без `Vec::push/extend`); `write`; `read` и сверить с blob: `None` или не совпало → `StorageInconsistent`.
- `load`: `read`; `None` → `KeyMissing` (ничего не создавать). `Some(blob)`: пустой → `CorruptKey`; первый байт ≠ 1 → `UnsupportedKeyVersion`; длина ≠ 65 → `CorruptKey`; seed в `Zeroizing<[u8;32]>` через `copy_from_slice` из `blob.get(1..33)`; ключ из seed; его публичный ключ ≠ `blob[33..65]` → `CorruptKey`; ≠ `expected` → `KeyMismatch`. Ошибка разбора запись не перезаписывает.
- `rekey` (кнопка «пересоздать ключ»): `read`; `None` → `KeyMissing` (явное создание только `create`); `Some(_)` (в том числе испорченная) → новый ключ как в `create`, `write` поверх, `read`-сверка → `StorageInconsistent` при расхождении. Возвращает новый ключ; новый публичный ключ вызывающий сохраняет как метку (этап 11).
- `OsKeyStore`: хранилище создаётся явно конструктором конкретного крейта (`keychain::Store::new()`, `windows_native_keyring_store::Store::new()`, `zbus_secret_service_keyring_store::Store::new()`), запись строится `store.build(service, &pair.account_name(), mods)`, где `mods` = `{"persistence": "Local"}` на Windows и `None` иначе. Отображение ошибок: `NoEntry` → `Ok(None)` в `read`, `Ok(())` в `delete`; `NoStorageAccess` → `StorageLocked`; `Ambiguous` → `StorageInconsistent`; `BadEncoding(v)`/`BadDataFormat(v, _)` → обнулить `v`, затем `StorageUnavailable`; всё остальное (включая ошибку конструктора) → `StorageUnavailable`. Результат `get_secret` сразу обернуть в `Zeroizing`. Никогда не вызывать `set_default_store`, `Entry::new`, `mock`.

## Требования к другим этапам (не реализуются здесь)
- Этапы 11 и 15: автоприём файлов выключен по умолчанию; приём только с явным подтверждением; предупреждение об исполняемых типах (U10a-2 п.2).
- Этапы 11/12: уведомление друзей о смене ключа = отзыв, подписанный старым ключом пары (домен `KeyRevocation`); новый ключ принимается только через повторное добавление со SAS, иначе укравший старый ключ подменит новый [В].
- Этап 11: список друзей хранит `PairId` и наш публичный ключ пары (метка); при `KeyMissing`/`KeyMismatch` показать ошибку «ключ для этого друга пропал или изменён, добавьте друга заново»; ключи незавершённых приглашений удалять по истечении TTL; «пересоздать ключ устройства» = `rekey` для всех пар из списка + отзыв + повторное добавление.
- Этап 18 (или ядро): один экземпляр приложения на пользователя (блокировка), иначе гонка `rekey` двух процессов (замечание 4).
- Этап 6: в `THREAT_MODEL.md` сценарии «вредонос под тем же пользователем», «украденный ноутбук», «бэкап связки средствами пользователя (допустим, U10a-2 п.1)», таблица силы защиты выше.
- Этап 9: выбор ключа в TLS и передача ключа пары транспорту (U10b).
- Этапы 9/11 (по ответу U10b): заменить заглушку `DeviceId` в `chervo-friends`, `chervo-transport`, `chervo-token` и тестах `chervo-transport`/`chervo-connect` на проверенный `PublicKey`/`PairId` (или иной тип по U10b) и удалить её из `chervo-identity`. До этого байты, пришедшие из сети или от друга, через `DeviceId::from_bytes` за ключ не принимать: проверка ключа только `PublicKey::try_from_slice`.

- По итогам ревью реализации (`docs/exp/ARCH-REVIEW-STAGE10.md`, `docs/exp/SECURITY-REVIEW-STAGE10.md`), дописано дирижёром:
  - Этап 11: `StorageLocked` и `StorageUnavailable` показывать пользователю одинаково (на macOS отказ доступа даёт `PlatformFailure` → `StorageUnavailable`, Н1); хранить `PairId` до `create` и вызывать `delete` при ошибке `create` (Н2); при `UnsupportedKeyVersion` перед `rekey` спрашивать пользователя (откат формата, L5).
  - Этап 9 / U10b: ключ пары в TLS только при TLS 1.3 (QUIC), иначе отдельный транспортный ключ: теги доменов не отделены от подписи TLS 1.2 (Н3).
  - Этап журналов: фильтр `keyring_core`, `zbus`, `secret_service` не ниже info: на debug/trace видны имена записей `pair-v1-<hex>` (L3).
  - Этап 6: DH сессии Secret Service (группа 1024 бит, переменное время) записать в модель угроз (L4).

## Не делать
- Не трогать другие крейты, `deny.toml`, `ci.yml`, `rust-toolchain.toml`, workspace-линты, документы (кроме подпункта U10 из шага 7).
- Не менять и не удалять `DeviceId` (кроме doc-комментария, см. «Интерфейс»); не использовать его в новом API.
- Никакой своей криптографии: генерация, подпись, проверка, разбор точек только вызовами `ed25519-dalek`/`getrandom`. Байты ключа только копировать.
- Не писать seed/blob/hex/base64 в файлы, переменные окружения, аргументы процессов, логи, stdout/stderr. Никакого запасного файлового хранилища, даже зашифрованного. Не экспортировать и не копировать ключ никуда, кроме хранилища ОС (U10a-2 п.1).
- Не включать фичи `serde`, `pkcs8`, `pem`, `rand_core`, `hazmat`, `legacy_compatibility`, `batch`, `digest` у ed25519-dalek; `sample` у keyring-core; `search` у windows-store; `crypto-openssl` у zbus-store. Не брать крейты `keyring`, `linux-keyutils-keyring-store`, `dbus-secret-service-keyring-store`.
- Тесты не трогают запись с `DEFAULT_SERVICE`.

## Недоверенный ввод
- Байты из хранилища (любая длина 0..МиБ, любой первый байт): порядок проверок как в `load`. Без копирования до проверки длины.
- `PublicKey::try_from_slice`: длина ≠ 32 → `InvalidPublicKey`; `VerifyingKey::from_bytes` ошибка → `InvalidPublicKey`; `is_weak()` → `InvalidPublicKey`; `VerifyingKey::from(vk.to_edwards()).to_bytes() != input` (неканоническая кодировка) → `InvalidPublicKey`.
- `DeviceId::from_bytes` ничего не проверяет и проверкой ключа не является; в новом API недоверенные байты ключа принимает только `PublicKey::try_from_slice`.
- Подпись в `verify`: любая длина; ≠ 64 → `BadSignature`.
- Без `unwrap`/`expect`/`panic!`/индексации в `src/` (lint-атрибут выше). Сообщения ошибок без байтов ввода. Паника возможна только внутри keyring-core/zbus-store на отравленном Mutex (`zbus-secret-service-keyring-store src/service.rs:34-37`, `.expect`) [П]: записать в отчёт, не обходить.

## Тесты (имена точно)
`tests/common/mod.rs`: `MemStore` (Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>, метод `raw(&PairId) -> Option<Vec<u8>>` только для тестов), `FixedStore(Vec<u8>)`, `LossyStore` (write Ok, read None), `FailingStore(IdentityError)` (всё возвращает заданную ошибку).

`tests/identity.rs`:
- заглушка `DeviceId` (сохранить существующие имена): `device_id_roundtrip` (как сейчас: `from_bytes([7;32]).as_bytes() == &[7;32]`), `debug_does_not_leak_key` (ровно "DeviceId(..)" для `from_bytes([0xAB;32])`; проверку `UnavailableKeyStore.load_or_create()` из него убрать, её заменяет `unavailable_store_fails_closed`).
- позитивные: `pair_id_generate_distinct`, `account_name_format` (префикс, 40 символов, только `[0-9a-f]` после префикса), `create_then_load_same_key`, `rekey_replaces_key` (новый публичный ≠ старого; `load` со старым expected → `KeyMismatch`, с новым → Ok), `sign_verify_roundtrip` (все `SignDomain::ALL`), `public_key_roundtrip`, `delete_missing_is_ok`, `pair_key_debug_redacted` (ровно "PairKey(..)"), `public_debug_redacted` ("PublicKey(..)", "PairId(..)", "OsKeyStore(..)" под cfg), `error_display_fixed_strings`, `domain_tags_prefix_free` (теги попарно различны, ни один не префикс другого, каждый оканчивается единственным 0x00, ни один не начинается с 0x20), `secret_types_zeroize_on_drop` (компиляция `fn f<T: ZeroizeOnDrop>()` для `PairKey`, `ed25519_dalek::SigningKey`, `Zeroizing<Vec<u8>>`; для `PairKey` тавтология, маркер ручной), `src_has_no_io_or_default_store` (читает `src/**/*.rs` через `env!("CARGO_MANIFEST_DIR")`; нет вхождений `std::fs`, `\bfs\b`, `File`, `OpenOptions`, `set_var`, `env::var`, `print!`, `println!`, `eprint`, `dbg!`, `stdout`, `stderr`, `log::`, `tracing`, `Command`, `set_default_store`, `get_default_store`, `mock`, `Entry::new(`, `keyring::`, `.sign(` (только `try_sign`)).
- негативные: `load_missing_is_key_missing` (хранилище после вызова пусто), `create_refuses_existing_record` (`KeyAlreadyExists`, байты записи прежние), `load_expected_mismatch_rejected`, `locked_store_not_missing` (`FailingStore(StorageLocked)`: `load`/`create`/`rekey` дают `StorageLocked`, не `KeyMissing`), `failing_store_propagates` (`StorageUnavailable`), `lossy_store_detected` (`create` → `StorageInconsistent`), `rekey_missing_is_key_missing`, `delete_then_load_is_key_missing`, `unavailable_store_fails_closed`, `blob_empty_rejected`, `blob_wrong_length_rejected` (64, 66, 1 МиБ с первым байтом 1), `blob_unknown_version_rejected` (0x00, 0x02, 0xFF при длинах 65 и 10), `blob_public_part_mismatch_rejected` (инвертирован бит в байте 40 → `CorruptKey`), `blob_seed_bit_flip_rejected` (инвертирован бит в байте 5 → `CorruptKey`), `corrupt_blob_not_overwritten`, `blob_exhaustive_lengths_and_versions` (длины 0..=130 с первым байтом 1 и все 256 значений первого байта при длине 65: нет паники, ошибки по правилам `load`), `public_key_rejects_wrong_length` (0, 31, 33), `public_key_rejects_weak` (`01 00..00`; `EC FF..FF 7F` (y = -1); `01 00..00 80`), `public_key_rejects_noncanonical` (y = p + k, k = 0..=18, бит знака 0 и 1: все → `InvalidPublicKey`; положительный контроль: хотя бы одна из этих кодировок принимается `ed25519_dalek::VerifyingKey::from_bytes` и не `is_weak`, иначе тест падает с сообщением «нет положительного контроля»), `verify_rejects_other_domain`, `verify_rejects_modified_message`, `verify_rejects_modified_signature`, `verify_rejects_other_key`, `verify_rejects_wrong_sig_length` (0, 63, 65).
- `os_store_roundtrip_manual` с `#[ignore]`: `OsKeyStore::open_with_service("chervotochina-test-" + hex случайных 8 байт)`; Drop-guard удаляет запись даже при панике; `assert_ne!(service, DEFAULT_SERVICE)`; `create`, затем **новый экземпляр** `OsKeyStore` и `load` с тем же expected; `rekey`; `delete`; `load` → `KeyMissing`. Запускает владелец вручную; в CI не запускается.

Doc-тесты `compile_fail` в документации `PairKey` (4 шт.): `PairKey: Clone`, `PartialEq`, `std::hash::Hash`, `std::ops::Deref`.

`tests/no_disk.rs` (отдельный бинарь, меняет текущий каталог):
- `key_bytes_not_written_to_data_dir`: уникальный каталог D под `std::env::temp_dir()`, `set_current_dir(D)`, цикл `create`/`load`/`sign`/`rekey`/drop на `MemStore`; секреты взять из `MemStore::raw`; рекурсивно просканировать D на: seed (32 байта) и blob (65 байт) сырыми, hex нижним и верхним регистром, base64 standard и url-safe (с паддингом и без; кодер в файле теста, не в `src/`); не найдено; D удалить.
- `scan_detects_planted_key`: положительный контроль, тот же сканер находит каждую форму, записанную в отдельный каталог D2.

## Критерии приёмки (каждый командой, вывод в отчёт)
- [ ] `cargo build -p chervo-identity --locked` и `cargo build --workspace --locked`
- [ ] `cargo test -p chervo-identity --locked`: проходят все тесты из перечня (включая негативные и два теста `DeviceId`), `os_store_roundtrip_manual` ignored; `cargo test -p chervo-identity --locked -- --list --include-ignored` содержит каждое имя (сверить grep по списку)
- [ ] `cargo test --doc -p chervo-identity --locked`: 4 строки `compile fail ... ok`
- [ ] `cargo test --workspace --locked` (в том числе тесты других крейтов, использующие `DeviceId`)
- [ ] `git diff --stat <база этапа> -- crates | grep -v "crates/chervo-identity/"` пусто (другие крейты не тронуты)
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `bash scripts/check-forbidden.sh` и `bash scripts/check-forbidden.sh --self-test`
- [ ] `grep -n "deny(clippy::unwrap_used" crates/chervo-identity/src/lib.rs` непусто
- [ ] `grep -rnE "set_default_store|get_default_store|mock::|Entry::new\(|keyring::" crates/chervo-identity/src` пусто
- [ ] `cargo tree -p chervo-identity -e normal --depth 1 --target all`: ровно `ed25519-dalek`, `getrandom`, `zeroize`, `keyring-core`, `apple-native-keyring-store`, `windows-native-keyring-store`, `zbus-secret-service-keyring-store` (если `--target all` не поддерживается, три прогона с `--target x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`)
- [ ] `cargo tree -p chervo-identity -e features -i ed25519-dalek`: фичи только `zeroize`, `fast` (нет `default`, `serde`, `pkcs8`, `pem`, `rand_core`, `hazmat`, `legacy_compatibility`, `batch`)
- [ ] `cargo tree -p chervo-identity --target all -e features -i secret-service | grep -c crypto-rust` ≥ 1 и `... | grep -ci openssl` = 0
- [ ] `cargo tree -p chervo-identity --target all -e normal | grep -Ei "openssl|libdbus|dbus-sys|keyutils|regex"` пусто; `cargo tree -p chervo-identity --target all -e features -i keyring-core | grep sample` пусто
- [ ] Supply-chain (`cargo deny check licenses sources`, `cargo audit --deny warnings`). Факт: локально `cargo deny` и `cargo audit` не установлены (`error: no such command`, по проверке дирижёра); `.github/workflows/ci.yml` запускается на любой `push` и `pull_request` (`:2-4`) и содержит job `supply-chain` с этими двумя командами (`:32-42`) [П]. Поэтому пункт проверяется статусом job `supply-chain` в прогоне CI на коммите этапа: дирижёр приводит ссылку на прогон и его статус. Нет зелёного прогона → этап не принят по этому пункту (замечание 12); локально ничего не устанавливать без разрешения владельца
- [ ] `docs/OPEN_QUESTIONS.md` U10 содержит «Статус (этап 10)»

## НЕ проверяется на этапе (записать в отчёт, не заявлять)
- CI-матрица 3 ОС (сборка Windows/macOS): дирижёр после пуша по статусу GitHub Actions; локально только Linux.
- Поведение реальных хранилищ (ручной тест выключен): сохранность после перезагрузки, запросы доступа macOS, блокировка Secret Service, `Persist=Local`, синхронизация iCloud, все [НП] из таблицы ОС.
- Обнуление: копии от перемещений, буферы ОС, security-framework и `secret-service` [НП], временные массивы внутри ed25519-dalek (факт 7), дампы при аварии [В]. Тест `secret_types_zeroize_on_drop` для `PairKey` тавтологичен.
- `no_disk` покрывает только путь через память (`MemStore`), не бэкенды ОС, своп и журналы.
- grep-тест обходится макросами и псевдонимами; вторая линия: lint-атрибуты.
- Как другие крейты используют `DeviceId` (принимают ли его из сети без проверки): вне этапа, этапы 9/11.
- secret-service 5.2.0 не обнуляет память (расшифрованный секрет, ключ сессии) [П, ревью security L1]; данные внутри `PlatformFailure(Box<dyn Error>)` уничтожаются без обнуления [НП].
- Паника вместо ошибки возможна в `OsKeyStore::open` на Linux: `.expect` на Mutex в zbus-store и `expect("platform RNG failed")` в secret-service session.rs:70 (L2); не обходится.

## Стоп-условия
Противоречие спецификации и кода, нужна новая зависимость или критерий непроверяем: остановиться и доложить, не обходить. Дополнительно:
- нет `cargo`/`rustc`; шаг 2 непуст; API из «Фактов» устроено иначе (шаг 5);
- сборка требует системных пакетов, правки `ci.yml` или openssl/libdbus;
- лицензия любой новой зависимости вне `deny.toml` (`deny.toml` не править);
- `public_key_rejects_noncanonical` без положительного контроля;
- сборка или тесты другого крейта требуют изменений в нём (например, из-за `IdentityError` или `DeviceId`).

## Процесс и исполнители
1. Исполнитель: `combine-builder`, effort high (критичный этап: не ниже Sonnet строго по спецификации, OWNER_DECISIONS «Принцип распределения»). Effort high, а не модель выше: спецификация закрывает решения, остаётся аккуратная реализация.
2. Приёмка: `combine-verifier` сам запускает все команды из критериев и прикладывает вывод.
3. Ревью дирижёра (основная сессия): соответствие спецификации, CI-матрица.
4. Ревью `combine-architect` (OWNER_DECISIONS: сначала architect, затем security): семантика `create/load/rekey`, отображение ошибок keyring, разделение доменов, каноничность ключей.
5. `combine-security`: повторная проверка критичного.
Лимит: не более 2 кругов «правка по ревью», затем доложить.
Отчёт (до 25 строк): изменённые файлы; версии и `cargo search`; результат шага 5; команды приёмки и последние строки вывода; что не сделано; отклонения.

## Учёт замечаний SECURITY-REVIEW-SPEC10
| № | Как учтено |
|---|---|
| 1 | Снято решением владельца U10a-2 п.1 (копии средствами пользователя допустимы). Остаётся: приложение не копирует и не экспортирует ключ («Не делать»), API без выдачи seed; угрозы в THREAT_MODEL как требование к этапу 6; сила защиты по ОС в таблице с [П]/[НП] |
| 2 | Мета-крейт `keyring` не берём; хранилище создаётся явно конструктором платформенного крейта; mock/default store в keyring-core только явно [П факт 2]; grep и `cargo tree` в критериях; ручной тест проверяет сохранность новым экземпляром |
| 3 | `crypto-rust` обязательна, openssl запрещён (критерий `cargo tree`); сессия DH [П факт 6]; поведение без фичи [НП] |
| 4 | Раздельные `load` (с `expected`) и явные `create`/`rekey`; `KeyMissing` ≠ `StorageLocked` ≠ `StorageUnavailable`; `create` не перезаписывает; случайный `PairId` убирает гонку создания; требование одного экземпляра к этапу 18 |
| 5 | Формат 65 байт с публичной частью, сверка при загрузке, тесты на порчу seed и публичной части |
| 6 | `DeviceId::from_bytes` остаётся только у заглушки `DeviceId` (её используют другие крейты; не ключ, в новом API не участвует; замена/удаление на этапах 9/11 по U10b, требование записано). Недоверенные байты ключа идут только через `PublicKey::try_from_slice`: проверка длины, точки, `is_weak` и каноничности перекодированием (сравнение `to_bytes()` с вводом бесполезно [П]); тесты на слабые и неканонические ключи с положительным контролем. Остаточный риск до этапов 9/11: другой крейт может принять сетевые байты как `DeviceId` без проверки [В] |
| 7 | Seed и blob в `Zeroizing<[u8;N]>` без `push`; результат хранилища сразу в `Zeroizing`; обнуление байтов в ошибках keyring; остатки в библиотеках и тавтологичность теста записаны |
| 8 | `sign/verify` только с `SignDomain`, теги без префиксов друг друга и отличны от контекста TLS (0x20) |
| 9 | Lint-атрибуты `deny(unwrap_used, expect_used, indexing_slicing, panic, print_*)`; расширенный grep; ограничение записано |
| 10 | Сканер ищет blob, hex, base64 (оба алфавита, с паддингом и без); ограничение «только память» в «НЕ проверяется» |
| 11 | Drop-guard, запрет `DEFAULT_SERVICE`, случайный service; запуск вручную владельцем (U10 решён U10a-2) |
| 12 | Критерий `cargo tree -e features -i ed25519-dalek`; версия 3.0.0 (≥ 2); supply-chain: локально инструментов нет, проверяется зелёным job `supply-chain` CI на коммите этапа, иначе не принят |
| 13 | `blob_exhaustive_lengths_and_versions` без новых зависимостей; фаззинг токенов на этапе 11 |
| 14 | `PairKey` без Clone/PartialEq/Hash/Deref (doc-тесты `compile_fail`); `MemoryKeyStore` убран из библиотеки в тесты |
| 15 | Раздел «Процесс»: ревью architect перед security; исполнитель builder (effort high) вместо «ведёт architect» из TASK.md по OWNER_DECISIONS и указанию дирижёра |

## Для владельца (кратко)
- Ключ теперь на каждую пару друзей: одна запись в хранилище ОС на друга, адрес записи `chervotochina` / `pair-v1-<случайный id>`, без имён и ключей в названии.
- Ключ никогда не создаётся сам: только `create` (добавление друга) и `rekey` («пересоздать ключ»). Пропал ключ → ошибка `KeyMissing` и повторное добавление друга; заблокированное хранилище даёт другую ошибку.
- От вредоноса под вашим пользователем хранилище ОС на Windows и Linux не защищает (на macOS возможен запрос) [не проверено в работе]. Поэтому: пересоздание ключа, автоприём выключен, уведомление друзей (этапы 11, 12, 15).
- Старый тип `DeviceId` пока остаётся заглушкой (им пользуются другие части программы); это не ключ, его заменят на этапах 9/11 после вашего ответа на U10b. Этап 10 другие части не трогает.
- Вопрос вам: U10b в `docs/OPEN_QUESTIONS.md` (как сервер выбирает ключ пары в TLS, токен адреса на каждого друга, влияние на выбор iroh/quinn). Этап 10 от ответа не зависит.
