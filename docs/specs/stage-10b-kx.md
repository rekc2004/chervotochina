# SPEC 10б: ключ обмена пары (X25519) и Noise KK в chervo-identity          критичность: КРИТИЧНЫЙ

Автор: combine-architect, 2026-10-15, редакция 1. Основание: `docs/OWNER_DECISIONS.md` «Решения 2026-10-15» (Noise KK: делаем; своей криптографии нет), U10a-2, U10b; `docs/reviews/SECURITY-REVIEW-STAGE07.md` High 1, Low 6; `docs/reviews/ARCH-REVIEW-STAGE07.md` Н5, Н10; `docs/THREAT_MODEL.md` T13, T14. Этап 9 (`docs/specs/stage-09-transport.md`) **зависит от этого этапа** и начинается только после его приёмки.
Метки: [П] сверено мной по исходнику крейта (файл:строка, версии ниже, каталог исходников дирижёра); [НП] не проверено, проверяется командой из критериев или остаётся в «НЕ проверяется»; [В] вывод архитектора; [Д] память, опереться нельзя. Ничего не запускалось.

Цель: у каждой пары, кроме ключа Ed25519, есть свой статический ключ X25519 в той же записи хранилища ОС; `chervo-identity` даёт готовую к транспорту аутентификацию соединения Noise KK (snow), привязанную к каналу TLS, при которой первое сообщение звонящего требует секрета пары, а вызываемый перебирает пары без раннего выхода.

Прочитать: этот файл; `docs/specs/stage-10.md` (разделы «Модель», «Интерфейс», «Семантика», «Не делать», «Недоверенный ввод»: всё, что здесь не изменено, остаётся в силе); `crates/chervo-identity/**`; корневой `Cargo.toml`; `deny.toml`; `.github/workflows/ci.yml`; `scripts/check-forbidden.sh`. Больше ничего не искать.

## Решения (обоснование)
1. **Отдельный случайный ключ X25519 на пару, в той же записи, что Ed25519 (формат записи v2).** Вывод X25519 из Ed25519 (`SigningKey::to_scalar_bytes`, `VerifyingKey::to_montgomery`) библиотечно возможен, но авторы ed25519-dalek прямо не рекомендуют: «We do NOT recommend using a signing/verifying key for encryption… If you can help it, use a separate key» (`ed25519-dalek-3.0.0/src/signing.rs:512-516`, `src/verifying.rs:477-479`) [П]; кроме того `to_scalar_bytes` возвращает необнуляемую копию (`signing.rs:526-529`) [П]. Отдельный ключ даёт чистое разделение доменов без опоры на доказательства совместной стойкости [В]. Одна запись на пару (U10a-2) сохраняется: оба ключа пишутся и читаются атомарно, частичного состояния нет [В].
2. **Миграции v1 нет.** Запись v1 (65 байт, только Ed25519) при `load` даёт `UnsupportedKeyVersion` (как сейчас для любой чужой версии), запись не трогается, ключ X25519 молча не добавляется (U10a-2 п.5 «никогда молча»). Добавить X25519 к старой записи бесполезно: друг должен получить наш X25519 по аутентифицированному каналу, то есть через повторное добавление со SAS (этап 11). Записей v1 «в поле» нет: этап 11 (друзья) ещё не сделан, ручной тест этапа 10 удаляет свою запись [В]. Путь пользователя: этап 11 правило L5 (спросить перед `rekey`), затем повторное добавление.
3. **Подписи Ed25519 в аутентификации соединения не нужны** (решение для этапа 9, интерфейс здесь). Noise KK с prologue = экспортёр TLS и обязательным третьим сообщением звонящего даёт взаимную аутентификацию, привязку к каналу и стойкость к KCI для обеих сторон [В, по таблице свойств полезной нагрузки спецификации Noise rev. 34 п. 7.7 для KK: сообщение 1 «источник 1», ответ «источник 2», первое транспортное сообщение звонящего «источник 2»; текст спецификации не сверял, НП]. Подписи поверх KK ничего не добавляют: оба ключа пары лежат в одной записи и крадутся вместе (T10) [В]. Ed25519 остаётся для приглашения, обновления адреса и отзыва (`SignDomain` без изменений; домен `ConnAuth` из Н10 ревью 7 **не добавляется**). Это меняет букву U10b («обе стороны подписывают экспортёр»): см. «Для владельца».
4. **Noise-обёртка живёт в `chervo-identity`, а не в транспорте.** Иначе крейту транспорта нужен метод, отдающий секрет X25519, что ломает инвариант этапа 10 «API не отдаёт секрет» [В]. Транспорт (этап 9, позже TCP по U7) только переносит байты: логика проверки подлинности в одном месте (мотив владельца в U10b) [В].
5. **Набор Noise: `Noise_KK_25519_ChaChaPoly_BLAKE2s`.** ChaChaPoly и BLAKE2s программные, без зависимости от AES-NI [В]. Фичи snow минимальные, без `std` (иначе `std` тянет `ring/std` и включает зависимость `ring`, `snow-0.10.0/Cargo.toml:79-86`) [П].

## Факты по исходникам (версии для этапа)
Новые зависимости: `snow` 0.10.0, `x25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0 (уже транзитивно через ed25519-dalek 3.0.0). Остальное как в `stage-10.md`.
1. **snow 0.10.0** [П]. MSRV 1.85, лицензия «Apache-2.0 OR MIT» (`Cargo.toml:14,37`). Фичи по умолчанию `default-resolver`, `default-resolver-crypto`, `std` (`:50-54`); `use-*` включают `default-resolver` (`:87-124`). Зависит от `curve25519-dalek` **4.1.3** и `getrandom` **0.3** (`:169-176`): в дереве будут две версии каждого (у нас 5.0.0 и 0.4.3). Без `std` крейт `no_std` + `alloc` (`src/lib.rs:122-125`). Неверный набор примитивов при `default-resolver` даёт `compile_error` (`src/lib.rs:128-141`). Крипто-трейты `Random`, `Dh`, `Cipher`, `Hash` объявлены `Send + Sync` (`src/types.rs:9,18,56,94`), поэтому состояние рукопожатия можно держать через `.await` в задаче tokio [В].
   - Builder: `local_private_key(&[u8])`, `prologue(&[u8])`, `remote_public_key(&[u8])` возвращают `Result<Self, Error>` (`src/builder.rs:127-169`). **Паники на длинах:** `rs_buf[..v.len()]` при `remote_public_key` длиннее `MAXDHLEN` (`:243-250`); `copy_slices!` (`src/lib.rs:143-147`) в `Dh25519::set` при приватном ключе длиннее 32 (`src/resolvers/default.rs:220-225`); `assert!(pubkey.len() >= 32)` в `dh` (`:243-246`). Короче 32 удалённый ключ **молча дополняется нулями** (`builder.rs:243-250`). Поэтому в snow передавать только `&[u8; 32]`.
   - `Dh25519` хранит ключи в обычных массивах (`default.rs:128-132`), DH = `mul_clamped` без проверки нулевого результата (`:243-250`). Обнуления в snow нет вообще: в `src/` нет `zeroize` и `impl Drop` (grep) [П]. `Builder::generate_keypair` отдаёт `Vec` без обнуления (`builder.rs:177-188`): не использовать.
   - KK = `[E, Es, Ss]`, `[E, Ee, Se]`, обе статические в предсообщениях (`src/params/patterns.rs:361-365`); prologue и статические ключи подмешиваются в хэш в `HandshakeState::new` (`src/handshakestate.rs:80-131`). `read_message`: длина > 65535 → `Error::Input` (`:352-353`), ошибка откатывает симметричное состояние (`:336-349`); расшифровка проверяет длину до вычитания тега (`src/cipherstate.rs:56-58`). Транспортные сообщения: `TransportState::write_message`/`read_message` (`src/transportstate.rs:57-90`).
   - Ошибки подробные, автор просит не выводить `Debug` пользователю (`src/error.rs:5-20`). `expect`/`unwrap` внутри шифрования (`default.rs:335,387`) срабатывают только при внутреннем сбое [В].
2. **x25519-dalek 3.0.0** [П]. Фичи по умолчанию `precomputed-tables`, `zeroize`; нужны `static_secrets` и `zeroize` (`Cargo.toml:65-81`); зависит от `curve25519-dalek` 5.0.0 и обязательно от `rand_core` 0.10 (`:96-106`). `StaticSecret([u8;32])` derive `Clone` (`src/x25519.rs:203-206`), `From<[u8;32]>` (`:247-252`), `PublicKey::from(&StaticSecret)` (`:255-260`), обнуление в `Drop` (`:271-277`), `ZeroizeOnDrop` (`:279-280`). `StaticSecret::random()` при фиче `getrandom` содержит `expect` (`:225-231`): фичу не включать.
3. **curve25519-dalek 5.0.0** [П]. `MontgomeryPoint(pub [u8;32])`, равенство по модулю p (`src/montgomery.rs:87-113`); `to_edwards(sign)` = `None` для точек кручения, в том числе u = −1 (`:239-258`); `EdwardsPoint::is_small_order` (`src/edwards.rs:1405`), `to_montgomery` (`:580`); `constants::EIGHT_TORSION` (все точки малого порядка, используется в тестах крейта `src/edwards.rs:2179-2180`).
4. **ed25519-dalek 3.0.0** без изменений (факт 7 `stage-10.md`). Фичу `pkcs8` и прочие не включать: объединение фич в workspace сломает критерий этапа 10 [В].

## Сделать (по порядку; каждый шаг проверить до следующего, CORE п.5)
1. Среда: `cargo --version`, `rustc --version`. Нет → СТОП.
2. Кто вне крейта использует меняемое: `grep -rnE "KEY_BLOB_(LEN|VERSION)|PairKey|chervo_identity::(load|create|rekey)" crates --include=*.rs | grep -v "^crates/chervo-identity/"` → пусто, иначе СТОП.
3. `cargo search snow --limit 1`, то же для `x25519-dalek`, `curve25519-dalek`. Новее, чем в спецификации: **не переходить**, записать в отчёт (ссылки файл:строка верны только для этих версий; дата последнего релиза snow со слов дирижёра 2025-07-19 [НП], записать, что показал `cargo search`/`cargo info`).
4. В корневой `[workspace.dependencies]`:
   `snow = { version = "=0.10.0", default-features = false, features = ["use-curve25519", "use-chacha20poly1305", "use-blake2", "use-getrandom"] }`;
   `x25519-dalek = { version = "=3.0.0", default-features = false, features = ["static_secrets", "zeroize"] }`;
   `curve25519-dalek = { version = "=5.0.0", default-features = false }`.
   В `crates/chervo-identity/Cargo.toml` в `[dependencies]` все три через `.workspace = true`. Больше ничего, dev-зависимостей нет. `cargo build`, закоммитить `Cargo.lock`.
5. `cargo fetch`; сверить с `~/.cargo/registry/src/*/` 4-5 ссылок из «Фактов» (обязательно: `builder.rs:243-250`, `default.rs:220-250`, `patterns.rs:361-365`, `x25519.rs:271-277`, `montgomery.rs:239-258`). Расхождение → СТОП.
6. Реализовать интерфейс ниже (новые модули `src/kx.rs`, `src/kk.rs`; правки `keys.rs`, `store.rs`, `error.rs`, `lib.rs`). Обновить `tests/identity.rs`, `tests/no_disk.rs`, `tests/common/mod.rs` (при необходимости), добавить `tests/kk.rs`.
7. Прогнать все критерии, выложить хвосты вывода; выполнить замер `kk_trial_cost` и привести таблицу.

## Интерфейс (точно)
Всё из `stage-10.md` «Интерфейс» остаётся, кроме перечисленного. Lint-атрибуты в `src/lib.rs` без изменений.
```rust
pub const KEY_BLOB_VERSION: u8 = 2;
pub const KEY_BLOB_LEN: usize = 129;   // [2][ed seed 32][ed pub 32][x25519 secret 32][x25519 pub 32]
// ACCOUNT_PREFIX = "pair-v1-" НЕ менять (это версия имени записи, не формата; смена спрятала бы старые записи молча).

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KxPublicKey([u8; 32]);       // проверенный X25519; Debug = "KxPublicKey(..)"
impl KxPublicKey {
    pub fn try_from_slice(b: &[u8]) -> Result<Self, IdentityError>; // см. «Недоверенный ввод»
    pub fn to_bytes(&self) -> [u8; 32];
}

pub struct PairKey { /* SigningKey, x25519_dalek::StaticSecret, KxPublicKey */ }
// По-прежнему НЕТ: Clone, Copy, PartialEq, Eq, Hash, AsRef, Deref, Display, serde, методов, отдающих секреты.
impl PairKey {
    pub fn public_key(&self) -> PublicKey;                 // как было
    pub fn kx_public(&self) -> KxPublicKey;                // новое
    pub fn sign(&self, domain: SignDomain, msg: &[u8]) -> Result<[u8; 64], IdentityError>; // как было
    pub fn into_kx(self) -> PairKx;                        // часть Ed25519 уничтожается (обнуляется)
}
pub struct PairKx { /* StaticSecret, KxPublicKey */ }      // нет Clone/PartialEq/Hash/Deref; Debug = "PairKx(..)"
impl PairKx { pub fn public(&self) -> KxPublicKey; }
impl zeroize::ZeroizeOnDrop for PairKx {}                  // маркер: поле StaticSecret обнуляется само (факт 2)

// модуль kk (реэкспорт из корня крейта)
pub const NOISE_PARAMS: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
pub const KK_PROLOGUE_TAG: &[u8] = b"chervotochina/v1/conn-kk\0";
pub const KK_KIND_V1: u8 = 0x01;
pub const KK_MSG1_LEN: usize = 49;     // [KK_KIND_V1][e 32][тег 16], полезная нагрузка пустая
pub const KK_MSG2_LEN: usize = 48;     // [e 32][тег 16]
pub const KK_MSG3_LEN: usize = 16;     // транспортное сообщение звонящего с пустой нагрузкой (подтверждение)
pub const BINDING_LEN: usize = 32;

#[derive(Clone, Copy)]
pub struct ChannelBinding([u8; BINDING_LEN]);   // значение экспортёра TLS; Debug = "ChannelBinding(..)"
impl ChannelBinding { pub const fn from_bytes(b: [u8; BINDING_LEN]) -> Self; }

pub struct KxPeer { /* PairId, PairKx (наш), KxPublicKey (друга) */ }  // нет Clone; Debug = "KxPeer(..)"
impl KxPeer {
    pub fn new(pair: PairId, ours: PairKx, theirs: KxPublicKey) -> Self;
    pub fn pair(&self) -> PairId;
    pub fn ours_public(&self) -> KxPublicKey;
    pub fn theirs(&self) -> KxPublicKey;
}
pub struct KkInitiator { /* snow::HandshakeState */ }   // нет Clone; Send; Debug = "KkInitiator(..)"
pub struct KkResponder { /* snow::HandshakeState, PairId */ } // нет Clone; Send; Debug = "KkResponder(..)"

pub fn kk_initiate(peer: &KxPeer, binding: &ChannelBinding)
    -> Result<(KkInitiator, [u8; KK_MSG1_LEN]), IdentityError>;
impl KkInitiator {
    /// Проверяет msg2 (подлинность вызываемого) и возвращает msg3.
    pub fn finish(self, msg2: &[u8]) -> Result<[u8; KK_MSG3_LEN], IdentityError>;
}
/// Перебирает ВСЕ `peers` без раннего выхода; первый совпавший побеждает.
pub fn kk_respond(peers: &[&KxPeer], binding: &ChannelBinding, msg1: &[u8])
    -> Result<(KkResponder, [u8; KK_MSG2_LEN]), IdentityError>;
impl KkResponder {
    /// Проверяет msg3. Только здесь пара считается подтверждённой.
    pub fn finish(self, msg3: &[u8]) -> Result<PairId, IdentityError>;
}

// IdentityError: добавить (Display фиксированный, без байтов ввода)
InvalidKxPublicKey,   // "invalid key-exchange public key"
AuthFailed,           // "connection authentication failed"
```
Семантика (точно):
- **prologue** = `KK_PROLOGUE_TAG || [KK_KIND_V1] || binding` (25 + 1 + 32 = 58 байт). Байт вида входит в prologue: так версия сообщения 1 связана с рукопожатием (закрывает Low 6 ревью 7).
- **Сборка snow** только так: `snow::Builder::new(NOISE_PARAMS.parse()?)` → `.local_private_key(ours.secret.as_bytes())` (ровно 32) → `.remote_public_key(&theirs.to_bytes())` (ровно 32) → `.prologue(&prologue)` → `build_initiator()`/`build_responder()`. Любая ошибка snow отображается в `AuthFailed`, кроме `snow::Error::Rng` → `RandomUnavailable`. `Debug`/`Display` ошибок snow никуда не выводить.
- `kk_initiate`: `write_message(&[], &mut buf[1..])` даёт ровно 48 байт, иначе `AuthFailed`; `buf[0] = KK_KIND_V1`.
- `KkInitiator::finish`: `msg2.len() != 48` → `AuthFailed`; `read_message(msg2, &mut [])` ошибка → `AuthFailed`; `into_transport_mode()`; `write_message(&[], &mut [0;16])` ровно 16 → msg3.
- `kk_respond`: `msg1.len() != 49` или `msg1[0] != KK_KIND_V1` → `AuthFailed` сразу (перебор не начинается); `peers` пуст → `AuthFailed`. Иначе для **каждого** `peers[i]`: собрать responder, `read_message(&msg1[1..], &mut [])`; результат запомнить, если он первый успешный; ошибки сборки и чтения внутри цикла = «не совпало» (без `?`, без `break`, без `return` в цикле). После цикла: нет совпадения → `AuthFailed`; есть → `write_message(&[], &mut out)` ровно 48 → `(KkResponder{hs, pair}, msg2)`.
- `KkResponder::finish`: `msg3.len() != 16` → `AuthFailed`; `into_transport_mode()`; `read_message(msg3, &mut [])` ошибка → `AuthFailed`; иначе `Ok(pair)`.
- **Формат записи v2.** `create`/`rekey`: два отдельных `getrandom::fill` в `Zeroizing<[u8;32]>` (seed Ed25519 и секрет X25519); `StaticSecret::from(*x)`, `PublicKey::from(&secret)`; запись в `Zeroizing<[u8; 129]>` копированием в подсрезы; запись и сверка чтением как в этапе 10.
- `load` (порядок проверок): `None` → `KeyMissing`; пусто → `CorruptKey`; первый байт ≠ 2 (в том числе 1) → `UnsupportedKeyVersion`; длина ≠ 129 → `CorruptKey`; публичный Ed25519 из seed ≠ `blob[33..65]` → `CorruptKey`; публичный X25519 из секрета ≠ `blob[97..129]` → `CorruptKey`; `KxPublicKey::try_from_slice(blob[97..129])` ошибка → `CorruptKey`; публичный Ed25519 ≠ `expected` → `KeyMismatch`. Ошибка разбора запись не перезаписывает. Сигнатуры `create`/`load`/`rekey` не меняются.
- `rekey` по-прежнему заменяет любую существующую запись (в том числе v1): это явное действие пользователя (этап 11, L5).

## Что этап 10б даёт этапу 11 (приглашение) и другим
- Приглашение несёт **оба** публичных ключа новой пары (Ed25519 и X25519, +32 байта к токену и QR); подпись Ed25519 (домен `Invite`) покрывает и X25519, чем связывает их; подлинность по-прежнему даёт SAS. Принимающая сторона разбирает ключ друга только через `PublicKey::try_from_slice` и `KxPublicKey::try_from_slice`.
- Список друзей хранит на пару: `PairId`, Ed25519 и X25519 друга, наш Ed25519 как метку (метка X25519 не нужна: запись атомарна и сверяется целиком).
- Соединение для самого приглашения (до дружбы ключей KK нет) проектирует этап 11; байт вида `0x02` в первом сообщении зарезервирован для него, этап 10б его не реализует.
- `rekey` меняет оба ключа сразу; новый ключ X25519 друг получает только повторным добавлением со SAS (как Ed25519).
- Этап 9: `kk_initiate`/`kk_respond`, `KxPeer`, `ChannelBinding`, сообщения фиксированной длины 49/48/16. Вызываемый держит набор `KxPeer` (секреты X25519 всех пар) в памяти процесса: читать хранилище ОС на каждое входящее соединение нельзя (N обращений к связке на незнакомца, запросы доступа macOS) [В]; часть Ed25519 при этом сбрасывается через `into_kx`.

## Не делать
- Не трогать другие крейты, `deny.toml`, `ci.yml`, `rust-toolchain.toml`, workspace-линты, документы.
- Не выводить X25519 из Ed25519 и обратно; не вызывать `to_scalar_bytes`, `to_scalar`, `VerifyingKey::to_montgomery`.
- Не использовать `snow::Builder::generate_keypair`, `fixed_ephemeral_key_for_testing_only`, фичи snow `std`, `ring-resolver`, `ring-accelerated`, `use-aes-gcm`, `use-sha2`, `use-p256`, `use-xchacha20poly1305`, `hfs`, `risky-raw-split`, `vector-tests`; фичи x25519-dalek `getrandom`, `serde`, `reusable_secrets`, `precomputed-tables`.
- Не передавать в snow срезы, длина которых не задана типом `[u8; 32]`.
- Не добавлять домен подписи для соединения; `SignDomain` не менять.
- Никакого способа получить секрет X25519 или seed наружу (ни метода, ни `AsRef`, ни `Debug`).
- Не добавлять миграцию v1 → v2 и не менять `ACCOUNT_PREFIX`.
- Своей криптографии нет: DH, AEAD, хэш, разбор точек только вызовами snow, x25519-dalek, curve25519-dalek.

## Недоверенный ввод
- `KxPublicKey::try_from_slice` (ключ друга из приглашения, этап 11): длина ≠ 32 → `InvalidKxPublicKey`; `MontgomeryPoint(arr).to_edwards(0)` = `None` (кручение, u = −1) → `InvalidKxPublicKey`; `is_small_order()` → `InvalidKxPublicKey`; `edwards.to_montgomery().to_bytes() != arr` (старший бит, u ≥ p) → `InvalidKxPublicKey`. Только вызовы curve25519-dalek, без своей арифметики.
- Сообщения KK из сети: любые длины 0..МиБ; проверка длины и байта вида до любых вызовов snow; никаких паник (lint-атрибуты крейта, тесты ниже).
- Байты из хранилища: порядок проверок `load` выше; без копирования до проверки длины.

## Тесты (имена точно)
`tests/identity.rs` (обновить существующие, новые добавить; прочие имена этапа 10 сохраняются):
- изменить: `blob_wrong_length_rejected` (128, 130, 65 с первым байтом 2, 1 МиБ с первым байтом 2 → `CorruptKey`); `blob_unknown_version_rejected` (0x00, 0x01, 0x03, 0xFF при длинах 129, 65 и 10 → `UnsupportedKeyVersion`); `blob_exhaustive_lengths_and_versions` (длины 0..=260 с первым байтом 2; все 256 значений первого байта при длине 129; нет паники, ошибки по порядку `load`); `blob_public_part_mismatch_rejected` (бит в байте 40) и `blob_seed_bit_flip_rejected` (байт 5) как были; `secret_types_zeroize_on_drop` (+ `PairKx`, `x25519_dalek::StaticSecret`); `src_has_no_io_or_default_store` (дополнительно запрещены: `generate_keypair`, `fixed_ephemeral`, `risky`, `dangerously`, `to_scalar_bytes`, `.to_scalar(`, `StaticSecret::random`); `error_display_fixed_strings` (+ 2 новые строки).
- новые позитивные: `create_then_load_same_kx`, `rekey_replaces_kx` (новый X25519 ≠ старого), `kx_public_roundtrip`, `into_kx_keeps_public`, `kx_debug_redacted` ("KxPublicKey(..)", "PairKx(..)", "KxPeer(..)", "ChannelBinding(..)", "KkInitiator(..)", "KkResponder(..)"), `prologue_tag_distinct_from_sign_domains` (`KK_PROLOGUE_TAG` не равен и не префикс ни одного тега `SignDomain::ALL` и наоборот, оканчивается единственным 0x00).
- новые негативные: `blob_kx_secret_bit_flip_rejected` (бит в байте 70 → `CorruptKey`), `blob_kx_public_mismatch_rejected` (бит в байте 100 → `CorruptKey`), `v1_record_not_migrated` (корректная запись v1 из 65 байт, собранная тестом: `load` → `UnsupportedKeyVersion`, байты записи прежние; `create` → `KeyAlreadyExists`; `rekey` → новая запись v2 длиной 129), `kx_public_rejects_wrong_length` (0, 31, 33), `kx_public_rejects_small_order` (все 8 `EIGHT_TORSION[i].to_montgomery().to_bytes()`), `kx_public_rejects_twist` (u = p − 1 и первое u ≥ 2, для которого `to_edwards(0)` = `None`; найти циклом в тесте), `kx_public_rejects_noncanonical` (кодировки p + k для k = 0..=18 и базовая точка 9 с выставленным битом 255; положительный контроль: базовая точка `[9, 0, ..]` и `kx_public()` созданного ключа принимаются, иначе тест падает с сообщением «нет положительного контроля»).
- `os_store_roundtrip_manual` (`#[ignore]`): как в этапе 10, плюс `load` после нового экземпляра даёт тот же `kx_public()`.

`tests/kk.rs` (ключи создаются через `create` на `MemStore`; хелпер строит `KxPeer` с двух сторон):
- `kk_roundtrip_ok` (N = 1: `kk_initiate` → `kk_respond` → `finish` → `finish` = верный `PairId`), `kk_message_sizes` (49/48/16), `kk_match_any_position` (N = 5, совпадение на позиции 0, 2, 4 → верный `PairId`), `kk_types_are_send` (компиляция `fn f<T: Send>()` для `KkInitiator`, `KkResponder`, `KxPeer`).
- `kk_rejects_stranger` (звонящий с ключами не из набора), `kk_rejects_public_keys_only` (атакующий знает оба публичных X25519 и Ed25519: строит инициатора snow со своим случайным статическим ключом и `remote` = ключ вызываемого; а также msg1 = `[1] ++ 48 случайных байт`), `kk_rejects_other_binding` (binding у сторон различаются, как MITM из двух TLS-сессий), `kk_rejects_replay_other_binding` (msg1, созданный для binding A, подан ответчику с binding B), `kk_rejects_reflection` (msg1, созданный стороной X как звонящим для пары P, подан самой X как ответчику с её `KxPeer` для P и тем же binding), `kk_rejects_bad_msg2` (инвертирован бит → `KkInitiator::finish` = `AuthFailed`), `kk_rejects_bad_msg3` (инвертирован бит), `kk_rejects_msg3_from_other_session` (msg3 другой пары сессий), `kk_rejects_wrong_lengths` (msg1 длины 0..=100 кроме 49; msg1 длины 49 со всеми 255 значениями вида ≠ 1; msg2 длины 0..=100 кроме 48; msg3 0..=64 кроме 16; всё → `AuthFailed`, без паники), `kk_empty_peer_set_fails`.
- `kk_trial_cost` (`#[ignore]`, запускается в `--release`): для N = 1, 10, 50, 200 медиана из 50 повторов времени `kk_respond` для «нет совпадения», «совпадение первым», «совпадение последним»; печатает таблицу и отношение max/min по позициям для каждого N. Порога нет (владелец не задавал), цифры идут в отчёт.
Модульный тест в `src/kk.rs`: `trial_visits_all_candidates` (внутренний счётчик попыток через внутреннюю функцию с замыканием; при совпадении первым, в середине, последним и без совпадения число попыток = N).
Doc-тесты `compile_fail`: 4 существующих для `PairKey`; 4 для `PairKx` (`Clone`, `PartialEq`, `Hash`, `Deref`); `KkInitiator: Clone`, `KkResponder: Clone` (итого 10).
`tests/no_disk.rs`: сканер дополнительно ищет секрет X25519 (32 байта) и запись v2 (129 байт) во всех формах (сырые, hex обоих регистров, base64 обоих алфавитов с паддингом и без); `scan_detects_planted_key` положительный контроль на новых формах.

## Критерии приёмки (каждый командой, вывод в отчёт)
- [ ] `cargo build -p chervo-identity --locked` и `cargo build --workspace --locked`
- [ ] `cargo test -p chervo-identity --locked`: проходят все тесты из перечня, `os_store_roundtrip_manual` и `kk_trial_cost` ignored; `cargo test -p chervo-identity --locked -- --list --include-ignored` содержит каждое имя из раздела «Тесты» (сверка grep по списку)
- [ ] `cargo test --doc -p chervo-identity --locked`: 10 строк `compile fail ... ok`
- [ ] `cargo test -p chervo-identity --release --locked --test kk -- --ignored kk_trial_cost --nocapture`: таблица в отчёте
- [ ] `cargo test --workspace --locked`
- [ ] `git diff --stat <база этапа> -- crates | grep -v "crates/chervo-identity/"` пусто
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `bash scripts/check-forbidden.sh` и `bash scripts/check-forbidden.sh --self-test`
- [ ] `cargo tree -p chervo-identity -e normal --depth 1 --target all`: ровно `ed25519-dalek`, `getrandom`, `zeroize`, `keyring-core`, `apple-native-keyring-store`, `windows-native-keyring-store`, `zbus-secret-service-keyring-store`, `snow`, `x25519-dalek`, `curve25519-dalek`
- [ ] `cargo tree -p chervo-identity -e features -i snow`: фичи только `use-curve25519`, `use-chacha20poly1305`, `use-blake2`, `use-getrandom`, `default-resolver` (нет `std`, `default`, `ring*`, `use-aes-gcm`, `use-sha2`, `hfs`, `risky-raw-split`)
- [ ] `cargo tree -p chervo-identity -e features -i x25519-dalek`: только `static_secrets`, `zeroize`
- [ ] `cargo tree -p chervo-identity -e features -i ed25519-dalek`: по-прежнему только `zeroize`, `fast`
- [ ] `cargo tree -p chervo-identity --target all -i ring`: пусто или `error: package ID specification ... did not match`
- [ ] `cargo tree -p chervo-identity -d --target all`: вывод в отчёт; ожидаемые дубликаты `curve25519-dalek` 4/5 и `getrandom` 0.3/0.4; любой иной дубликат крипто-крейта перечислить отдельно
- [ ] Прежние критерии `stage-10.md` по `cargo tree` (openssl, libdbus, keyutils, regex, `sample`, `crypto-rust`) остаются зелёными
- [ ] Supply-chain: зелёный job `supply-chain` CI на коммите этапа (ссылку на прогон приводит дирижёр); `cargo deny` с текущим `deny.toml` (лицензии snow «Apache-2.0 OR MIT», x25519-dalek «BSD-3-Clause» в списке)

## НЕ проверяется на этапе (записать в отчёт, не заявлять)
- Обнуление внутри snow: статический ключ копируется в `Dh25519` и в состояние рукопожатия и освобождается без обнуления [П: в snow нет zeroize]; при переборе N пар на каждое входящее соединение в куче остаются N копий наших секретов X25519 [В]. Свою обёртку-резолвер с обнулением не пишем (это код в крипто-пути); решение за владельцем.
- Свойства Noise KK по спецификации Noise (п. 7.7) [НП, текст не сверял]; совместимость с другой реализацией Noise (тестовых векторов второй реализации нет).
- Постоянство времени перебора: проверяется только «все N кандидатов посещены» и замер; утечка числа друзей по времени отказа остаётся (T14) [В].
- Сопровождение snow (последний релиз 2025-07-19 со слов дирижёра [НП]); `cargo audit` в CI ловит только известные уязвимости.
- CI-матрица 3 ОС: по статусу GitHub Actions после пуша.

## Стоп-условия
Противоречие спецификации и кода, нужна зависимость или фича сверх перечисленных, критерий непроверяем: остановиться и доложить, не обходить. Дополнительно:
- шаг 2 непуст; API в шаге 5 устроено иначе;
- snow без фичи `std` не собирается или требует `ring`;
- объединение фич меняет набор фич `ed25519-dalek`;
- размеры сообщений KK не 49/48/16;
- `cargo deny` падает на лицензии новой зависимости (`deny.toml` не править);
- тест или сборка другого крейта требует правки в нём.

## Процесс и исполнители
1. Исполнитель: `combine-builder`, Sonnet, effort high, строго по спецификации.
2. Приёмка: `combine-verifier` сам запускает все команды критериев и прикладывает вывод.
3. Ревью дирижёра по diff и критериям.
4. Ревью `combine-architect`: семантика KK (prologue, порядок, отсутствие раннего выхода), формат v2, проверка `KxPublicKey`.
5. `combine-security`: независимое ревью крипто-пути и злых входов.
Лимит: не более 2 кругов «правка по ревью», затем доложить.
Отчёт (до 25 строк): изменённые файлы; версии и `cargo search`; результат шага 5; команды приёмки и последние строки вывода; таблица `kk_trial_cost`; что не сделано; отклонения.

## Для владельца (кратко)
- К каждой паре добавлен второй ключ (X25519) для «рукопожатия Noise KK». Он хранится в той же записи хранилища ОС, что и ключ подписи; выводить его из ключа подписи не стали: авторы библиотеки это прямо не советуют.
- Первое сообщение звонящего теперь нельзя составить без секрета пары: тот, кто видел только токен приглашения (публичные ключи), не узнает по соединению, кто с кем (закрывает High 1 и T14).
- Подписи в проверке соединения больше не нужны: KK сам доказывает обеим сторонам владение ключами и привязан к шифрованному каналу. Это отходит от буквы U10b («обе стороны подписывают»), но не от её смысла; нужно ваше подтверждение.
- Старые записи ключей (формат v1) не дополняются молча: такая пара потребует повторного добавления друга (в поле таких записей пока нет).
- Риски: библиотека snow давно не выпускалась и не стирает ключи из памяти после работы; программа держит ключи обмена всех пар в памяти, пока работает.
