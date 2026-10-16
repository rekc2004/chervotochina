# SPEC 11: Токены приглашения, SAS, друзья          критичность: КРИТИЧНЫЙ (части К1-К4), обычный (часть О1)

Автор: combine-architect (opus/high), 2026-10-16, редакция 1. Метки: [П] проверено мной по исходнику (файл:строка, версия ниже); [В] вывод архитектора; [НП] не проверено. **Ничего не запускалось.** Новых зависимостей нет (только уже объявленные в `[workspace.dependencies]` и уже присутствующие в `Cargo.lock`), поэтому проверка новых крейтов по docs.rs не требуется.

Цель: два пользователя добавляют друг друга по токену (текст или данные для QR) через одно соединение с проверкой SAS на обоих экранах; дружба создаётся только при совпадении SAS и подтверждении обеих сторон; список друзей хранится на диске зашифрованным; удаление, блокировка, отзыв и смена ключа рвут живые соединения пары.

Прочитать: этот файл; `docs/specs/stage-10.md` (разделы «Интерфейс», «Требования к другим этапам»); `docs/specs/stage-10b-kx.md` («Интерфейс», «Что этап 10б даёт этапу 11»); `crates/chervo-identity/src/{lib,keys,kx,kk,knock,store,os,ids,error}.rs`; `crates/chervo-transport/src/lib.rs`; `crates/chervo-transport-quinn/src/{lib,registry,server,client,conn}.rs`; `crates/chervo-transport-quinn/src/tests/kit.rs`; `crates/chervo-token/*`, `crates/chervo-friends/*`, `crates/chervo-addr/src/lib.rs`, `crates/chervo-core/{src/lib.rs,tests/layout.rs}`; корневой `Cargo.toml`. Больше ничего не искать.

## Решения (обоснование)
1. **Источник SAS: не экспортёр TLS, а «обязательство-раскрытие» (меняет строку этапа 11 в TASK).** Экспортёр TLS (и хэш рукопожатия Noise) зависит от ключевого обмена, в котором MITM в каждой из двух своих сессий выбирает свой вклад **после** того, как увидел вклад честной стороны (TLS-сервер выбирает key_share после ClientHello; ответчик Noise выбирает `e` после `msg1`). SAS разумной длины (8 цифр, ~26,6 бита) он подберёт перебором своего ключа за время рукопожатия: ~10^8 операций X25519 [В; порядок «секунды-минуты на одной машине» по памяти, Д]. Поэтому SAS считается **только** из значений, которые каждая сторона фиксирует раньше, чем видит вклад другой:
   - пригласивший A кладёт в токен обязательство `c_A = BLAKE2s-256(COMMIT_TAG || r_A)` (32 случайных байта `r_A` знает только A);
   - приглашённый B первым сообщением M1 шлёт свои ключи и случайные `r_B`;
   - A раскрывает `r_A` в M2 только после M1; B проверяет `c_A`;
   - `SAS = первые 8 байт BLAKE2s-256(SAS_TAG || token_hash || A_ed || A_x || B_ed || B_x || r_A || r_B)`, 8 десятичных цифр.
   MITM, подменивший токен, зафиксировал свой `c_M` до того, как увидел `r_B`; в сессии с A он фиксирует свой M1 до того, как увидит `r_A`. Поэтому SAS двух сессий совпадают с вероятностью 10^-8 на одну сверку, без возможности перебора [В]. Схема того же класса, что hash commitment в ZRTP (RFC 6189) и numeric comparison в Bluetooth [В по памяти; тексты не сверял, НП]. Своей криптографии нет: только BLAKE2s (`blake2` 0.10.6), Ed25519 и X25519 через `chervo-identity`; композицию проверяет `combine-security`.
2. **Соединение приглашения идёт по существующей схеме (стук + QUIC/TLS 1.3 + Noise KK с экспортёром в prologue, U10b), без изменений транспорта и KK.** Для этого токен несёт одноразовый **гостевой секрет X25519** `g` (32 случайных байта), созданный A. Обе стороны строят `KxPeer` гостевой пары: у A `(наш X25519 пары, публичный G)`, у B `(g, X25519 пары A из токена)`. Стук и KK работают как для друга [В]. Следствия: (а) без токена до A не достучаться (стук требует `ss`) [В]; (б) MITM без подмены токена не проходит KK, потому что B проверяет ключ A из токена [В]; (в) держатель токена (в том числе читатель мессенджера) во время TTL может пройти стук и KK как гость, это и есть T5 «гонка приглашения»; SAS его не пропускает [В]; (г) байт вида `0x02`, зарезервированный в 10б, не используется. Токен поэтому секретен как пароль до использования (текст в этапе 18).
3. **Владение ключами.** A доказывает владение Ed25519 подписью токена (домен `Invite`, покрывает и X25519, и `c_A`, и `G`), владение X25519 — проходя KK. B доказывает владение Ed25519 подписью M1 в новом домене `InviteAccept` (покрывает `token_hash`, свои ключи и `r_B`); владение X25519 B на этом соединении не доказывается (B проходит KK гостевым ключом): неверный X25519 вредит только самому B — его KK с A потом не пройдёт [В].
4. **Одноразовость и лимиты (сторона A).** На приглашение не больше `MAX_INVITE_SESSIONS = 3` сессий (соединений гостевой пары, дошедших до приложения); M1 принимается ровно один раз; после этого и по истечении TTL (по часам A) приглашение мертво. Новое соединение гостевой пары вытесняет старое правилом одного соединения на пару (`registry.rs:38-77`): держатель токена может сорвать сессию B — отказ в обслуживании класса T5, принят [В]. B проверяет время токена мягко (допуск `CLOCK_TOLERANCE_SECS = 600`), решает время A.
5. **Подтверждение.** После показа SAS каждая сторона шлёт решение (подтвердил / отказ). Дружба создаётся у стороны, только если подтвердила она сама **и** пришло подтверждение собеседника. Обрыв после отправки своего подтверждения = отказ. Остаток (две армии): A получил подтверждение B и создал друга, а B не получил подтверждение A и удалил пару; у A «друг» недоступен до удаления вручную (вопрос владельцу 4) [В].
6. **«Пересоздать ключ» = отзыв + удаление старой пары + новое приглашение (новый `PairId`).** `identity::rekey` на этапе 11 не используется: новый ключ всё равно доставляется только повторным добавлением со SAS, а новая пара не смешивает записи [В]. Отзыв подписывается старым ключом пары (домен `KeyRevocation`) до удаления ключа и выдаётся текстом (`CHR1…`); доставка по живому соединению — этап 14.
7. **Ключ списка друзей:** отдельная запись в хранилище ОС, account `friends-key-v1` (не начинается с `pair-v1-`), 32 случайных байта; новый трейт `ListKeyStore`, `SecretStore` не меняется. Создаётся только при первой записи списка, когда нет ни файла, ни ключа. Файл есть, ключа нет: ошибка, ключ молча не создаётся (U10a-2 п.5 по аналогии). Число записей в хранилище = пары + незавершённые приглашения + 1 (отклонение от модели этапа 10 «других записей нет»; закрывает T4 «где ключ списка» [В]).
8. **AEAD файла списка:** `ring` 0.17.14, ChaCha20-Poly1305, `LessSafeKey`, nonce 12 случайных байт на каждую запись, AAD = заголовок. `ring` уже прямая зависимость workspace (`chervo-transport-quinn`) [П: корневой `Cargo.toml:50`]. Случайный 96-битный nonce: при ~10^5 сохранений за жизнь вероятность повтора ~10^10/2^97, пренебрежимо [В].
9. **Текстовое кодирование:** префикс `CHV1` (приглашение) или `CHR1` (отзыв) + base32 RFC 4648 (алфавит `A-Z2-7`, без `=`), заглавные: укладывается в алфавитно-цифровой режим QR [В]. Кодек base32 пишется свой (не криптография, ~60 строк, строгий и с fuzz-смоуком) вместо новой зависимости; символ `1` не входит в алфавит, поэтому префикс однозначен.
10. **Заглушка `DeviceId` удаляется** из `chervo-identity`, `chervo-token`, `chervo-friends` и тестов (требование `stage-10.md`).
11. **Отзыв друга и смена набора пар рвут живые соединения (требование TASK, этап 9):** `QuinnTransport::set_peers` закрывает каждое живое соединение, чья тройка `(PairId, наш X25519, X25519 собеседника)` отсутствует в новом наборе; `promote` проверяет членство под тем же замком, что и `set_peers`, поэтому KK, начатый со старым снимком и завершившийся после замены, не проходит [В]. Блокировка = исключить пару из набора; переход гость → настоящий ключ при завершении приглашения тоже закрывает гостевое соединение (так и задумано).
12. **Ревью architect после builder не планируется:** формат, протокол и правила зафиксированы здесь до кода; соответствие и криптографию проверяет `combine-security`.

## Факты по исходникам (версии для этапа)
1. **ring 0.17.14** [П]: `UnboundKey::new(&'static Algorithm, &[u8]) -> Result<_, Unspecified>`, ошибка при неверной длине ключа (`src/aead/unbound_key.rs:32-44`); `LessSafeKey::new(UnboundKey)` (`src/aead/less_safe_key.rs:32`); `seal_in_place_append_tag(nonce, aad, &mut Vec<u8>)` дописывает тег (`:123-135`); `open_in_place(nonce, aad, &mut [u8]) -> Result<&mut [u8], _>`, длина < 16 → ошибка (`:78-116`); `Nonce::assume_unique_for_key([u8; 12])` (`src/aead/nonce.rs:39`); `CHACHA20_POLY1305` (`src/aead/algorithm.rs:222`). В `src/aead/` нет `impl Drop` и `zeroize` (grep): расписание ключа AEAD в памяти не обнуляется — остаток класса В2.
2. **blake2 0.10.6** [П]: `Blake2s256` (`src/lib.rs:167`), `Blake2sMac256` (`:172`); уже зависимость `chervo-identity`.
3. **x25519-dalek 3.0.0** [П]: `StaticSecret::as_bytes(&self) -> &[u8; 32]` (`src/x25519.rs:241`), `to_bytes` возвращает копию без обнуления (`:235`): копировать только из `as_bytes` в `Zeroizing`.
4. **chervo-identity** [П]: `KxPublicKey::try_from_slice` отвергает малый порядок и ключи вне подгруппы (`src/kx.rs:25`); `PairKx::new` — `pub(crate)` (`src/kx.rs:86`); `KxPeer::knock_keys` отвергает `ours == theirs` и невкладной DH (`src/knock.rs:123-136`).
5. **chervo-transport-quinn** [П]: `set_peers` меняет снимок, живые соединения не трогает (`src/lib.rs:318-326`); запись реестра хранит только `caller_pub` (`src/registry.rs:14-20`); `promote` членство не проверяет (`src/registry.rs:109-152`); снимок берут `client.rs:23,145`, `server.rs:144`.
6. **Скелет** [П]: `chervo-token` и `chervo-friends` — заглушки с `DeviceId` (`chervo-token/src/lib.rs:7-20`, `chervo-friends/src/lib.rs:6-50`); `chervo-core` реэкспортирует оба (`src/lib.rs:8,11`); тест `layout` запрещает `quinn`, `tokio`, `rustls` в манифесте core.

## Сделать (два вызова builder; каждый шаг проверить до следующего, CORE п.5)

### Вызов 1: критичная часть (builder sonnet/high). Части К1-К4
1. Среда: `cargo --version`, `rustc --version`; записать `BASE=$(git rev-parse HEAD)`.
2. `grep -rn "DeviceId\|FriendStore\|UnavailableFriendStore\|chervo_token::\|chervo_friends::" crates --include=*.rs` → ожидаются только файлы, перечисленные в факте 6 и тестах этих крейтов, `chervo-identity/src/{ids,lib}.rs`, `chervo-identity/tests/identity.rs`. Иное → СТОП.
3. Сверить факты 1-3 с `~/.cargo/registry/src/*/` (строки). Расхождение → СТОП.
4. **К1 `chervo-identity`:** `SignDomain::InviteAccept`; модуль `guest.rs` (`GuestSecret`); `ListKeyStore` с реализацией для `OsKeyStore` (то же отображение ошибок и `mods`, что у пар, account `LIST_KEY_ACCOUNT`) и `UnavailableKeyStore`; удалить `DeviceId`. Тесты К1.
5. **К2 `chervo-token`:** формат и текст токена приглашения и отзыва, `decode`, `issue_invite`, `issue_revocation`, `PendingInvite`, `InviteeSession`, `Sas`, решения, модуль `flow` (обмен по `chervo_transport::Connection`). Тесты К2 и fuzz-смоук.
6. **К3 `chervo-friends`:** типы записи, кодек открытого текста, `vault::seal/open`. Тесты К3 (модульные в `src/tests/`), fuzz-смоук кодека. `FriendStore`/`UnavailableFriendStore` удалить (книгу делает вызов 2).
7. **К4 `chervo-transport-quinn`:** членство в `set_peers` и `promote` (решение 11), событие `PeerRemoved`, счётчик `removed_closed`. Тесты К4.
8. Критерии 1-8 ниже для изменённых крейтов; отчёт.

### Вызов 2: обычная часть (builder sonnet/medium). Часть О1
9. **О1 `chervo-friends`:** `FriendBook` (открытие, атомарная запись, ключ списка, незавершённые пары, CRUD, права, блокировка, удаление, смена ключа, приём отзыва, `kx_peers`). Только вызовы API К1-К3, никакой своей криптографии.
10. Сетевые сквозные тесты `crates/chervo-friends/tests/invite_net.rs` (dev-зависимости `chervo-transport`, `chervo-transport-quinn`, `tokio` из workspace).
11. Все критерии; отчёт.

## Интерфейс (точно)
Lint-атрибуты как в `chervo-identity/src/lib.rs` (`deny` unwrap/expect/indexing_slicing/panic/print_*/dbg/todo) добавить в `src/lib.rs` крейтов `chervo-token` и `chervo-friends`.

### К1. chervo-identity (дополнения; остальное без изменений)
```rust
// keys.rs
pub enum SignDomain { Invite, AddressUpdate, KeyRevocation, InviteAccept } // #[non_exhaustive] как было
//   InviteAccept => b"chervotochina/v1/invite-accept\0"; SignDomain::ALL включает его.

// guest.rs: одноразовый секрет гостевой пары приглашения. НЕ ключ пары: по замыслу уходит в токен.
pub struct GuestSecret { /* StaticSecret, KxPublicKey */ }
// Нет Clone/Copy/PartialEq/Eq/Hash/Deref/AsRef/Display; Debug = "GuestSecret(..)"; impl ZeroizeOnDrop (маркер).
impl GuestSecret {
    pub fn generate() -> Result<Self, IdentityError>;          // getrandom::fill в Zeroizing<[u8;32]>; ошибка -> RandomUnavailable
    pub fn from_bytes(b: &[u8]) -> Result<Self, IdentityError>; // len != 32 -> InvalidGuestSecret; публичный через
                                                                // KxPublicKey::try_from_slice, ошибка -> InvalidGuestSecret
    pub fn public(&self) -> KxPublicKey;
    pub fn to_token_bytes(&self) -> zeroize::Zeroizing<[u8; 32]>; // копия из as_bytes(); только для токена
    pub fn into_kx(self) -> PairKx;                              // через PairKx::new (pub(crate))
}

pub const LIST_KEY_ACCOUNT: &str = "friends-key-v1";
pub const LIST_KEY_LEN: usize = 32;
pub trait ListKeyStore: Send + Sync {
    fn read_list_key(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, IdentityError>; // None = записи нет
    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError>;
    fn delete_list_key(&self) -> Result<(), IdentityError>;                                 // нет записи = Ok(())
}
// impl ListKeyStore for OsKeyStore; impl ListKeyStore for UnavailableKeyStore (всё -> NotImplemented)

// IdentityError: добавить InvalidGuestSecret  // "invalid invite secret"
// Удалить: DeviceId и его реэкспорт.
```

### К2. chervo-token
Зависимости: `chervo-identity`, `chervo-transport`, `blake2`, `getrandom`, `zeroize` (все `.workspace = true`). Никаких часов внутри: время передаёт вызывающий (`now_unix`, секунды UTC с учётом поправки часов).
```rust
pub const MAX_TOKEN_TEXT_LEN: usize = 2048;   // байты входной строки, проверка до всего
pub const INVITE_PREFIX: &str = "CHV1";
pub const REVOCATION_PREFIX: &str = "CHR1";
pub const TOKEN_VERSION: u8 = 0x01;
pub const KIND_INVITE: u8 = 0x01;
pub const KIND_REVOCATION: u8 = 0x02;
pub const MAX_INVITE_ADDRS: usize = 8;
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 86_400;
pub const DEFAULT_TTL_SECS: u64 = 900;
pub const CLOCK_TOLERANCE_SECS: u64 = 600;
pub const MAX_INVITE_SESSIONS: u32 = 3;
pub const TOKEN_HASH_TAG: &[u8] = b"chervotochina/v1/invite-token-hash\0";
pub const COMMIT_TAG: &[u8] = b"chervotochina/v1/invite-commit\0";
pub const SAS_TAG: &[u8] = b"chervotochina/v1/invite-sas\0";
pub const PROTO_V1: u8 = 0x01;
pub const MSG_M1: u8 = 0x11;  pub const M1_LEN: usize = 194;
pub const MSG_M2: u8 = 0x12;  pub const M2_LEN: usize = 34;
pub const MSG_DECISION: u8 = 0x13; pub const DECISION_LEN: usize = 3;
pub const SAS_DIGITS: usize = 8;

/// Разобранный и проверенный (подпись, длины, адреса, TTL) токен. Нет Debug, нет Clone.
pub struct InviteToken { /* поля ниже, guest в Zeroizing<[u8;32]>, hash: [u8;32] */ }
impl InviteToken {
    pub fn issued_at(&self) -> u64;
    pub fn expires_at(&self) -> u64;
    pub fn inviter_ed(&self) -> PublicKey;
    pub fn inviter_x(&self) -> KxPublicKey;
    pub fn addrs(&self) -> &[SocketAddr];
    pub fn guest_secret(&self) -> Result<GuestSecret, TokenError>;  // GuestSecret::from_bytes
    pub fn check_time(&self, now_unix: u64) -> Result<(), TokenError>;
    // now + CLOCK_TOLERANCE_SECS < issued_at -> NotYetValid; now > expires_at + CLOCK_TOLERANCE_SECS -> Expired
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum RevocationReason { Rekey, Removed }            // байт 1, 2
#[derive(Clone, Copy, PartialEq, Eq)]                     // Debug = "RevocationNotice(..)"
pub struct RevocationNotice { pub revoked_ed: PublicKey, pub revoked_x: KxPublicKey,
                              pub reason: RevocationReason, pub issued_at: u64 }

#[non_exhaustive] pub enum Token { Invite(InviteToken), Revocation(RevocationNotice) } // без Debug
pub fn decode(text: &str) -> Result<Token, TokenError>;   // подпись проверяется внутри

pub struct InviteDraft { pub issued_at: u64, pub ttl_secs: u64, pub addrs: Vec<SocketAddr> } // без Debug
/// Сторона A. Возвращает состояние приглашения и текст токена (`CHV1…`).
pub fn issue_invite(draft: &InviteDraft, key: &PairKey) -> Result<(PendingInvite, String), TokenError>;
pub fn issue_revocation(key: &PairKey, reason: RevocationReason, issued_at: u64) -> Result<String, TokenError>;

/// Состояние A: r_A (Zeroizing), token_hash, ключи A, G (публичный), expires_at, sessions, used.
/// Нет Clone; Debug = "PendingInvite(..)". Гостевой секрет после выпуска токена не хранится.
pub struct PendingInvite { .. }
impl PendingInvite {
    pub fn expires_at(&self) -> u64;
    pub fn guest_public(&self) -> KxPublicKey;
    /// Вызывать на каждое соединение гостевой пары до `flow::inviter_exchange`.
    pub fn begin_session(&mut self, now_unix: u64) -> Result<(), InviteError>;
    // used -> Used; now >= expires_at -> Expired; sessions >= MAX_INVITE_SESSIONS -> TooManySessions; иначе sessions += 1
    pub fn on_m1(&mut self, m1: &[u8]) -> Result<([u8; M2_LEN], Sas, InviteeKeys), InviteError>;
}
#[derive(Clone, Copy, PartialEq, Eq)] pub struct InviteeKeys { pub ed: PublicKey, pub x: KxPublicKey } // Debug "InviteeKeys(..)"

/// Сторона B. `key` — новый ключ пары B (create на шаге «принять приглашение»).
pub struct InviteeSession { .. }    // нет Clone; Debug = "InviteeSession(..)"
impl InviteeSession {
    pub fn start(token: &InviteToken, key: &PairKey) -> Result<(Self, [u8; M1_LEN]), InviteError>;
    pub fn on_m2(self, m2: &[u8]) -> Result<Sas, InviteError>;
}

#[derive(Clone, Copy, PartialEq, Eq)] pub struct Sas([u8; 8]);   // Debug = "Sas(..)"
impl Sas { pub fn digits(&self) -> String; }   // u64::from_be_bytes % 100_000_000, формат "{:04} {:04}"
pub fn encode_decision(confirm: bool) -> [u8; DECISION_LEN];   // [MSG_DECISION, PROTO_V1, 1|0]
pub fn decode_decision(b: &[u8]) -> Result<bool, InviteError>;  // только ровно эти 3 байта, байт 0/1

pub mod flow {   // generic по chervo_transport::{Connection, SendStream, RecvStream}; без tokio
    pub struct InviteChannel<C: Connection> { /* C::Tx, C::Rx */ }
    /// A: accept_bi, прочитать ровно M1_LEN, pending.on_m1, записать M2.
    pub async fn inviter_exchange<C: Connection>(conn: &C, pending: &mut PendingInvite)
        -> Result<(InviteChannel<C>, Sas, InviteeKeys), FlowError>;
    /// B: open_bi, записать m1, прочитать ровно M2_LEN, session.on_m2.
    pub async fn invitee_exchange<C: Connection>(conn: &C, session: InviteeSession, m1: &[u8; M1_LEN])
        -> Result<(InviteChannel<C>, Sas), FlowError>;
    /// Записать своё решение, finish(), прочитать ровно DECISION_LEN, вернуть решение собеседника.
    pub async fn exchange_decision<C: Connection>(ch: &mut InviteChannel<C>, confirm: bool) -> Result<bool, FlowError>;
}
// Чтение ровно N байт: цикл read; Ok(None) или Ok(Some(0)) до N -> FlowError::Truncated. Буферы только фиксированной длины.

#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum TokenError { TooLong, BadEncoding, BadPrefix, UnsupportedVersion, BadKind, Malformed, BadAddress,
                      BadTtl, BadKey, BadSignature, Expired, NotYetValid, RandomUnavailable, SigningFailed }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum InviteError { Malformed, WrongToken, BadKey, BadSignature, CommitMismatch, Expired,
                       TooManySessions, Used, NoSession, RandomUnavailable, SigningFailed }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum FlowError { Transport(TransportError), Invite(InviteError), Truncated }
// Display у всех: фиксированные строки без байтов ввода.
```
Удалить: `AddressUpdateToken`, вариант `Token::AddressUpdate`, `TokenError::NotImplemented` (этап 12 добавит свои).

**Двоичный формат приглашения** (все числа big-endian; подпись `inviter_ed.sign(Invite, байты[0..L-64])`):
```
[0]      TOKEN_VERSION (0x01)          [1]      KIND_INVITE (0x01)
[2..10]  issued_at u64                 [10..18] expires_at u64
[18..50] A_ed (Ed25519)                [50..82] A_x (X25519)
[82..114] g (гостевой секрет)          [114..146] c_A = BLAKE2s-256(COMMIT_TAG || r_A)
[146]    n адресов, 1..=8
далее n раз: [семейство 0x04|0x06][IP 4|16][порт u16]
[L-64..L] подпись Ed25519 (64)
```
Длина 218..=363 байта. `token_hash = BLAKE2s-256(TOKEN_HASH_TAG || все L байт)`.
`issue_invite`: `ttl_secs` в `[MIN_TTL_SECS, MAX_TTL_SECS]`, `expires_at = issued_at + ttl` (checked_add), иначе `BadTtl`; адреса по правилам «Недоверенный ввод» (иначе `BadAddress`); `GuestSecret::generate`, повторить один раз, если `G == A_x`, затем `BadKey`; `r_A` через `getrandom::fill` в `Zeroizing<[u8;32]>`.

**Двоичный формат отзыва:** `[0x01][0x02][issued_at u64][revoked_ed 32][revoked_x 32][reason u8: 1|2][подпись 64]` = 139 байт; подпись `revoked_ed` в домене `KeyRevocation` над первыми 75 байтами; `decode` проверяет подпись ключом из самого отзыва (сопоставление с другом делает О1).

**Протокол на первом двунаправленном потоке соединения гостевой пары** (после KK, открывает B):
- M1 (B→A, 194): `[MSG_M1][PROTO_V1][token_hash 32][B_ed 32][B_x 32][r_B 32][sig 64]`, `sig = B_ed.sign(InviteAccept, M1[0..130])`.
- M2 (A→B, 34): `[MSG_M2][PROTO_V1][r_A 32]`.
- Решение (обе стороны, 3): `[MSG_DECISION][PROTO_V1][0x01 подтвердил | 0x00 отказ]`.
- `on_m1` по порядку: `sessions == 0` → `NoSession`; `used` → `Used`; длина ≠ 194 или байты 0-1 ≠ `[MSG_M1, PROTO_V1]` → `Malformed`; `token_hash` ≠ своему → `WrongToken`; `PublicKey::try_from_slice(B_ed)`, `KxPublicKey::try_from_slice(B_x)` ошибка → `BadKey`; `B_x == A_x`, `B_x == G`, `B_ed == A_ed` → `BadKey`; подпись → `BadSignature`; затем `used = true`, SAS, M2. Ошибка `used` не ставит.
- `InviteeSession::start`: `B_x == A_x`, `B_x == G`, `B_ed == A_ed` → `BadKey`; `r_B` из `getrandom`.
- `on_m2`: длина ≠ 34 или заголовок → `Malformed`; `BLAKE2s-256(COMMIT_TAG || r_A) != c_A` → `CommitMismatch`; иначе SAS. Сравнения хэшей обычным `==` допустимы: все сравниваемые значения публичны в момент сравнения [В].
- SAS обеих сторон: `BLAKE2s-256(SAS_TAG || token_hash || A_ed || A_x || B_ed || B_x || r_A || r_B)`, первые 8 байт. В SAS **не входят** экспортёр, хэш рукопожатия и эфемерные ключи (решение 1).

### К3. chervo-friends: типы и хранилище-контейнер
Зависимости: `chervo-identity`, `chervo-addr`, `chervo-token`, `ring`, `getrandom`, `zeroize`.
```rust
pub const MAX_FRIENDS: usize = 1024;  pub const MAX_PENDING: usize = 64;
pub const MAX_NAME_BYTES: usize = 64; pub const MAX_ADDRS_PER_FRIEND: usize = 16;
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const FILE_MAGIC: &[u8; 4] = b"CHFL"; pub const FILE_VERSION: u8 = 0x01;
pub const KEY_LOST_TEXT: &str = "Ключ для этого друга пропал или изменён. Добавьте друга заново.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct AutoAcceptLimits { pub max_total_bytes: u64, pub max_files: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum Permission { #[default] Ask, AutoAccept(AutoAcceptLimits) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum FriendState { Active, Blocked, RevokedByPeer }
#[derive(Clone)] pub struct Friend {          // без Debug
    pub pair: PairId, pub name: String,
    pub friend_ed: PublicKey, pub friend_x: KxPublicKey,
    pub our_ed: PublicKey,                    // метка нашего ключа пары (expected для identity::load)
    pub state: FriendState, pub permission: Permission,
    pub known_addrs: Vec<KnownAddr>, pub last_addr_seq: u64, pub added_at_unix: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum PendingRole { Inviter, Invitee }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct PendingEntry { pub pair: PairId, pub role: PendingRole, pub expires_at_unix: u64 }
#[derive(Clone, Default)] pub struct BookData { pub friends: Vec<Friend>, pub pending: Vec<PendingEntry> }

pub mod vault {
    /// [FILE_MAGIC][FILE_VERSION][nonce 12][шифртекст || тег 16]; AAD = первые 5 байт.
    pub fn seal(key: &[u8; 32], data: &BookData) -> Result<Vec<u8>, FriendsError>;
    pub fn open(key: &[u8; 32], file: &[u8]) -> Result<BookData, FriendsError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum FriendsError { KeyStorageUnavailable, ListKeyMissing, Corrupt, UnsupportedVersion, Io, LimitExceeded,
    InvalidName, InvalidLimits, UnknownPair, AlreadyExists, KeyMissingOrChanged, KeyNeedsDecision,
    RandomUnavailable, BadRevocation }
```
**Открытый текст v1** (внутри AEAD; big-endian): `[0x01][n_friends u16]` + на друга `[pair 16][name_len u8][name][friend_ed 32][friend_x 32][our_ed 32][state u8 0|1|2][perm u8 0|1 (+ max_total_bytes u64 + max_files u32 при 1)][last_addr_seq u64][added_at u64][n_addrs u8]` + на адрес `[семейство 0x04|0x06][IP][порт u16][source u8 0..=5 в порядке AddrSource][last_seen u64][short_lived u8 0|1]`; затем `[n_pending u16]` + `[pair 16][role u8 0|1][expires_at u64]`. Буферы открытого текста в `Zeroizing<Vec<u8>>`.
`vault::open`: длина < 33 или > `MAX_FILE_BYTES`, неверная магия → `Corrupt`; версия ≠ 1 → `UnsupportedVersion`; ошибка `open_in_place` (неверный ключ или порча) → `Corrupt`; ошибка разбора → `Corrupt`. `seal`: nonce `getrandom::fill` на каждый вызов, ошибка → `RandomUnavailable`.

### К4. chervo-transport-quinn
```rust
TransportEvent::PeerRemoved { pair: PairId }   // новое: живое соединение закрыто из-за set_peers
TransportStats::removed_closed: u64            // новое
```
- Запись реестра хранит `ours_pub: [u8;32]` и `theirs_pub: [u8;32]` (X25519 этой стороны и собеседника; `caller_pub` остаётся для правила дубликатов). `promote` получает их от вызывающего (`KxPeer::ours_public()`/`theirs()` совпавшей пары).
- Порядок замков везде: замок реестра → замок `peers`. `set_peers`: (1) `gate.set_min_burst`, `knock.set_peers` как сейчас; (2) под замком реестра: заменить снимок и собрать живые записи, чьей тройки `(pair, ours_pub, theirs_pub)` нет в новом наборе; (3) после снятия замка закрыть их кодом `CLOSE_REFUSED` с пустой причиной, увеличить `removed_closed`, послать `PeerRemoved`.
- `promote`: под замком реестра проверить, что тройка есть в текущем снимке; нет → закрыть `CLOSE_REFUSED` (пустая причина), вызывающему `connect` вернуть `TransportError::PeerNotAllowed`, у вызываемого — молча (как прочие отказы после TLS).
- Для детерминированного теста гонки: крюк `#[cfg(test)]` перед `promote` (например `tokio::sync::Notify` в `Inner`), в обычной сборке отсутствует.

### О1. chervo-friends: книга друзей (вызов 2)
```rust
pub struct FriendBook { /* path, key: Option<Zeroizing<[u8;32]>>, data: BookData */ }  // Debug = "FriendBook(..)"
pub struct NewFriend { pub name: String, pub friend_ed: PublicKey, pub friend_x: KxPublicKey,
                       pub our_ed: PublicKey, pub our_x: KxPublicKey, pub addrs: Vec<KnownAddr>, pub now_unix: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum KeyStatus { MissingOrChanged, NeedsDecision }
impl FriendBook {
    /// Файла нет: пустая книга (ключ читается, если есть). Файл есть, ключа нет: ListKeyMissing, файл не трогается.
    pub fn open<K: ListKeyStore + ?Sized>(path: &Path, keys: &K) -> Result<Self, FriendsError>;
    /// Явно: переименовать нечитаемый файл в "<path>.unreadable-<now>" и начать пустую книгу.
    pub fn start_over<K: ListKeyStore + ?Sized>(path: &Path, keys: &K, now_unix: u64) -> Result<Self, FriendsError>;
    pub fn friends(&self) -> &[Friend];
    pub fn get(&self, pair: &PairId) -> Option<&Friend>;
    pub fn pending(&self) -> &[PendingEntry];
    pub fn begin_pair<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, role: PendingRole,
        expires_at_unix: u64) -> Result<(PairId, PairKey), FriendsError>;
    pub fn abort_pair<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, pair: &PairId) -> Result<(), FriendsError>;
    pub fn expire<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, now_unix: u64) -> Result<usize, FriendsError>;
    pub fn drop_all_pending<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S) -> Result<usize, FriendsError>;
    pub fn finish_pair<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, pair: &PairId, f: NewFriend) -> Result<(), FriendsError>;
    pub fn rename<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId, name: &str) -> Result<(), FriendsError>;
    pub fn set_permission<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId, p: Permission) -> Result<(), FriendsError>;
    pub fn block<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId) -> Result<(), FriendsError>;
    pub fn unblock<K: ListKeyStore + ?Sized>(&mut self, keys: &K, pair: &PairId) -> Result<(), FriendsError>;
    /// Отзыв (Removed), если ключ загрузился; затем удалить ключ и запись. Текст отзыва или None.
    pub fn remove<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, pair: &PairId, now_unix: u64) -> Result<Option<String>, FriendsError>;
    /// «Пересоздать ключ» (решение 6): отзыв (Rekey) старым ключом, удалить ключ и запись. Ключ не загрузился -> ошибка, ничего не удалено.
    pub fn rekey<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, pair: &PairId, now_unix: u64) -> Result<String, FriendsError>;
    /// Отзыв от друга: decode; друг с friend_ed == revoked_ed и friend_x == revoked_x и state != RevokedByPeer
    /// -> state = RevokedByPeer, удалить наш ключ пары, сохранить -> Some(pair). Иначе Ok(None).
    pub fn apply_revocation<S: SecretStore + ListKeyStore + ?Sized>(&mut self, store: &S, text: &str) -> Result<Option<PairId>, FriendsError>;
    /// Только Active: identity::load(store, pair, our_ed)?.into_kx() -> KxPeer::new(pair, kx, friend_x).
    pub fn kx_peers<S: SecretStore + ?Sized>(&self, store: &S) -> Result<(Vec<KxPeer>, Vec<(PairId, KeyStatus)>), FriendsError>;
}
```
Семантика О1 (точно):
- Каждое изменяющее действие сохраняет файл: `vault::seal` → запись в `"<path>.tmp"` → `sync_all` → `rename` поверх `path`; ошибка → `Io`, состояние в памяти откатывается к прежнему.
- Ключ списка: при записи, если ключа в памяти нет: `read_list_key`; `None` и файла нет → 32 байта `getrandom` → `write_list_key` → `read_list_key` и сравнить (иначе `KeyStorageUnavailable`); `None` и файл есть → `ListKeyMissing`. Длина прочитанного ключа ≠ 32 → `Corrupt`.
- Ошибки хранилища: `StorageLocked` и `StorageUnavailable` → `KeyStorageUnavailable` одинаково (Н1); `RandomUnavailable` → `RandomUnavailable`.
- `begin_pair` (Н2): `PairId::generate` → добавить `PendingEntry` и **сохранить** → `identity::create`; ошибка → `store.delete(pair)` (результат игнорировать), убрать запись, сохранить, вернуть ошибку. Больше `MAX_PENDING` → `LimitExceeded`.
- `abort_pair`: `store.delete(pair)`; ошибка хранилища → вернуть её, запись остаётся (повтор позже); иначе убрать запись, сохранить. `expire`: `abort_pair` для `expires_at_unix <= now`. `drop_all_pending`: для всех (вызывать при старте: секреты незавершённых сессий жили только в памяти).
- `finish_pair`: записи `pair` в `pending` нет → `UnknownPair`; имя: непусто, ≤ 64 байт, без `char::is_control` → иначе `InvalidName`; `friend_ed == our_ed` или `friend_x == our_x` → `KeyMissingOrChanged`; друг с тем же `pair` уже есть → `AlreadyExists`; `known_addrs` обрезать до 16; добавить друга `Active`, `Permission::Ask`, `last_addr_seq = 0`; убрать pending; сохранить. Больше `MAX_FRIENDS` → `LimitExceeded`.
- `set_permission`: `AutoAccept` с `max_files == 0` или `max_total_bytes == 0` → `InvalidLimits`. По умолчанию всегда `Ask` (автоприём только явно).
- `block`: `Active` → `Blocked`; `unblock`: `Blocked` → `Active`; иначе `UnknownPair`. Вызывающий после любых изменений делает `transport.set_peers(kx_peers + гостевые пары)`: живые соединения исключённых пар рвутся (К4).
- `kx_peers`: `KeyMissing`, `KeyMismatch`, `CorruptKey` → `(pair, MissingOrChanged)` (показать `KEY_LOST_TEXT`, ключ молча не создаётся); `UnsupportedKeyVersion` → `(pair, NeedsDecision)` (L5: спросить пользователя, автоматически ничего не делать); `StorageLocked`/`StorageUnavailable` → вся операция `KeyStorageUnavailable`.

**Порядок приложения (документировать в doc-комментарии модуля и проверить сетевым тестом):**
A: `begin_pair(Inviter, now + ttl)` → запомнить `key.public_key()`, `key.kx_public()` → `issue_invite` → `set_peers(+ KxPeer(pair, key.into_kx(), pending.guest_public()))` → на соединение гостевой пары `begin_session` → `inviter_exchange` → показать SAS → `exchange_decision` → оба подтвердили: `conn.close()`, `finish_pair(B_ed, B_x, …)`, `set_peers(kx_peers)`; иначе `abort_pair`, `set_peers` без гостя.
B: `decode` → `check_time` → `begin_pair(Invitee, token.expires_at() + CLOCK_TOLERANCE_SECS)` → `InviteeSession::start` → `set_peers(+ KxPeer(pair, token.guest_secret()?.into_kx(), token.inviter_x()))` → `connect(PeerAddr{pair, token.addrs()})` → `invitee_exchange` → SAS → `exchange_decision` → оба подтвердили: `finish_pair(A_ed, A_x, …)`, `set_peers(kx_peers)`; иначе `abort_pair`.

## Не делать
- Никаких новых крейтов в `Cargo.lock` (новые рёбра между уже имеющимися допустимы). Нужен новый крейт → СТОП.
- Не менять: KK, стук, формат записи ключа, `SecretStore`, `ACCOUNT_PREFIX`, `chervo-timesync`, `chervo-connect`, `chervo-transfer`, `chervo-receive`, CI, `deny.toml`. В транспорте только К4.
- Не использовать `identity::rekey` в этапе 11; не выводить X25519 из Ed25519; не писать свою криптографию (хэши, AEAD, подписи, DH только через `blake2`, `ring`, `chervo-identity`).
- Не включать в SAS экспортёр, хэш рукопожатия, эфемерные ключи; не показывать SAS до успешных `on_m1`/`on_m2`.
- Не логировать и не печатать текст токена, гостевой секрет, `r_A`/`r_B`, SAS, имена друзей, адреса, ключи (нет `Debug` с содержимым; lint-атрибуты).
- Никакого GUI, QR-картинок, фоновых задач, таймеров внутри крейтов; сроки сессии — у вызывающего.
- Не создавать ключ пары или ключ списка молча; не перезаписывать нечитаемый файл.

## Недоверенный ввод
- **Текст токена** (мессенджер, QR): длина строки > 2048 байт → `TooLong` до любой обработки. Не-ASCII → `BadEncoding`. Пробел, `\t`, `\r`, `\n` удаляются, строчные буквы поднимаются. Первые 4 символа: `CHV1`/`CHR1`, иначе `BadPrefix`. Остаток: только `A-Z2-7`, длина по модулю 8 ∈ {0, 2, 4, 5, 7}, неиспользуемые хвостовые биты равны 0 (каноничность), иначе `BadEncoding`. Байт версии ≠ 1 → `UnsupportedVersion`; вид не совпал с префиксом → `BadKind`.
- **Двоичное приглашение:** точная длина `147 + Σ(7|19) + 64`, иначе `Malformed` (лишние и недостающие байты); `n` вне 1..=8 → `Malformed`; адрес: семейство не 4/6, порт 0, неуказанный, multicast, IPv4 широковещательный `255.255.255.255`, IPv6 вида `::ffff:a.b.c.d`, повтор адреса → `BadAddress`; `expires_at <= issued_at` или TTL вне `[60, 86400]` → `BadTtl`; `PublicKey::try_from_slice(A_ed)`, `KxPublicKey::try_from_slice(A_x)`, `GuestSecret::from_bytes(g)` ошибка или `G == A_x` → `BadKey`; подпись (`verify` с доменом `Invite`) → `BadSignature`. Порядок: длина и структура → ключи → подпись.
- **Отзыв:** длина ровно 139, `reason` ∈ {1,2}, ключи как выше, подпись `KeyRevocation`.
- **M1, M2, решение:** только фиксированные длины (читаются ровно N байт, без выделения памяти по длине от собеседника); правила в «Интерфейс».
- **Файл списка:** локальный, но после порчи или подмены считается недоверенным: проверки `vault::open` и разбора (лимиты, `u16`/`u8` счётчики против остатка буфера, дубликаты `pair` в друзьях и в pending → `Corrupt`, неизвестные значения перечислений → `Corrupt`, имя по правилам `finish_pair`, ключи через `try_from_slice`, лишние байты в конце → `Corrupt`).
- Ни одной паники на любом вводе (lint-атрибуты + fuzz-смоук).

## Тесты (имена точно)
К1 (`crates/chervo-identity/tests/identity.rs`, `tests/kk.rs`): `guest_generate_public_valid`, `guest_from_bytes_roundtrip`, `guest_from_bytes_bad_len`, `guest_debug_redacted`, `guest_into_kx_knock_and_kk_work` (A: `KxPeer(pair, pair_kx, G)`, B: `KxPeer(pair, guest.into_kx(), A_x)`: `make` B проходит проверку по `recv_id` A, KK `kk_initiate`/`kk_respond`/`finish` проходит), `sign_domains_pairwise_not_prefix` (все `SignDomain::ALL`, `KK_PROLOGUE_TAG`, `KNOCK_*_LABEL`), `invite_accept_domain_separated` (подпись `Invite` не проходит как `InviteAccept` и наоборот), `unavailable_list_key_store`, `os_list_key_roundtrip_manual` (`#[ignore]`).
К2 (`crates/chervo-token/tests/{token,invite,revocation,fuzz_smoke}.rs`): `invite_roundtrip`, `invite_text_canonical`, `invite_text_whitespace_and_case`, `invite_any_byte_flip_rejected` (каждый байт двоичного токена, перекодированного в текст), `invite_every_truncation_rejected`, `invite_trailing_bytes_rejected`, `invite_bad_base32` (чужой символ, `=`, длина mod 8 ∈ {1,3,6}, ненулевые хвостовые биты), `invite_wrong_prefix`, `invite_kind_mismatch`, `invite_unknown_version`, `invite_too_long_text`, `invite_bad_signature`, `invite_other_domain_signature_rejected`, `invite_bad_keys` (малый порядок X, невалидный Ed, `G == A_x`), `invite_addr_rules` (0 и 9 адресов, порт 0, `0.0.0.0`, `::`, multicast, broadcast, v4-mapped, дубликат), `invite_ttl_rules`, `invite_check_time` (границы `±CLOCK_TOLERANCE_SECS`), `invite_max_size_fits_limit` (8 адресов IPv6 ≤ 2048 символов), `tags_distinct_from_identity_tags` (`TOKEN_HASH_TAG`, `COMMIT_TAG`, `SAS_TAG` против тегов identity: не равны и не префиксы), `sas_equal_honest`, `sas_digits_format`, `sas_mitm_substituted_token_differs` (A↔M с настоящим токеном, M↔B с токеном M: SAS A ≠ SAS B; M1 B не принимается A: `WrongToken`), `m1_wrong_token_hash`, `m1_bad_signature`, `m1_bad_keys` (`B_x == A_x`, `B_x == G`, `B_ed == A_ed`, малый порядок), `m1_every_wrong_length` (0..=400, кроме 194), `m1_accepted_once` (второй → `Used`), `m1_without_session` (`NoSession`), `session_limits` (`Expired` по `now >= expires_at`, `TooManySessions` на 4-й), `m2_commit_mismatch`, `m2_every_wrong_length`, `decision_only_exact`, `revocation_roundtrip`, `revocation_bad_signature`, `revocation_other_domain`, `revocation_bad_reason`, `fuzz_smoke_decode`, `fuzz_smoke_m1`, `fuzz_smoke_m2`, `fuzz_smoke_revocation`.
Fuzz-смоук (на stable, без зависимостей): свой xorshift64* с фиксированным зерном в `tests/common`; число итераций из `CHERVO_FUZZ_ITERS` (по умолчанию 20 000); входы: случайные байты, случайные строки из алфавита base32 с префиксами, мутации (переворот бита, вставка, удаление, обрезка) валидного токена/сообщения; свойство: нет паники; каждый `Ok` после `decode` перекодируется в тот же канонический текст (для приглашения — через функцию кодирования, доступную тесту как `#[doc(hidden)] pub fn encode_invite_bytes`).
К3 (`crates/chervo-friends/src/tests/*.rs`): `vault_roundtrip`, `vault_wrong_key_rejected`, `vault_any_byte_flip_rejected`, `vault_every_truncation_rejected`, `vault_header_bound_by_aad` (смена байта версии/магии → ошибка, не `Ok`), `vault_nonce_fresh`, `plain_limits` (1025 друзей, 65 записей pending, имя 65 байт, управляющий символ, 17 адресов), `plain_rejects_duplicates`, `plain_rejects_bad_keys`, `plain_rejects_unknown_enums`, `plain_rejects_trailing`, `fuzz_smoke_vault_plain`.
К4 (`crates/chervo-transport-quinn/src/tests/peers.rs`, через `QuinnTransport::connect` со стуком): `set_peers_removal_closes_live`, `set_peers_key_change_closes_live` (тот же `PairId`, другой `theirs`), `set_peers_unchanged_keeps_live`, `set_peers_closed_with_refused_empty_reason`, `removed_during_kk_refused` (крюк cfg(test): `set_peers` без пары между концом KK и `promote` → у звонящего `PeerNotAllowed`, у вызываемого нет соединения в `accept`), `removed_peer_cannot_reconnect`, `peer_removed_event_and_counter`.
О1 (`crates/chervo-friends/tests/book.rs`, тестовые хранилища в `tests/common/mod.rs`: `MemStore` (SecretStore + ListKeyStore), `FailingCreateStore`, `LockedStore`, `UnavailableStore`): `open_missing_file_empty`, `list_key_created_on_first_save_only`, `file_without_key_is_error_and_untouched`, `start_over_renames`, `begin_pair_saves_pending_before_create`, `begin_pair_create_error_cleans_up`, `expire_deletes_key_and_pending`, `drop_all_pending_on_start`, `finish_pair_creates_active_ask`, `finish_pair_rules` (имя, ключи, дубликат, нет pending), `locked_and_unavailable_same_error`, `kx_peers_reports_missing_and_mismatch`, `kx_peers_unsupported_version_needs_decision` (запись v1 → `NeedsDecision`, запись не тронута), `kx_peers_excludes_blocked_and_revoked`, `permission_default_ask`, `autoaccept_requires_limits`, `block_unblock`, `remove_returns_revocation_and_deletes_key`, `rekey_returns_revocation_and_deletes_key`, `rekey_key_missing_keeps_record`, `apply_revocation_marks_and_deletes_key`, `apply_revocation_unknown_ignored`, `apply_revocation_forged_rejected`, `save_overwrites_existing` (на 3 ОС в CI), `no_plaintext_on_disk` (в файле нет байтов имени, ключей друга, адресов; ни сырыми, ни hex, ни base64).
О1 сеть (`crates/chervo-friends/tests/invite_net.rs`, loopback, две `QuinnTransport` со стуком): `invite_end_to_end_quinn` (SAS равны; после `set_peers` гостевое соединение закрыто; новое соединение настоящими ключами проходит KK, `remote_pair` верный), `invite_reject_creates_nothing` (B отказал: у обоих нет друга, ключи пар удалены), `invite_expired_refused`, `invite_token_holder_after_m1_gets_nothing` (третий держатель токена после принятого M1 B: `on_m1` → `Used`, M2 ему не отправлен, друга для него нет), `invite_wrong_token_never_connects` (токен подписан другим ключом пары с адресами A: стук не опознан, `connect` → `TimedOut`, A не получил ни одного соединения), `blocked_friend_live_conn_closed`, `revocation_end_to_end`.

## Критерии приёмки (каждый командой; вывод в отчёт)
- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked`: проходят все, включая перечисленные в «Тесты» (кроме `#[ignore]`).
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-token -p chervo-friends fuzz_smoke -- --nocapture`: все проходят, в выводе число итераций каждой цели.
- [ ] `grep -rn "DeviceId" crates/; test $? -eq 1`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1` (новых пакетов нет)
- [ ] `cargo tree -p chervo-token -p chervo-friends -e normal | grep -E 'quinn|tokio|rustls'; test $? -eq 1`
- [ ] `cargo test -p chervo-core --test layout`; `bash scripts/check-forbidden.sh`
- [ ] Гонки: `for i in $(seq 20); do cargo test -q --locked -p chervo-transport-quinn -- set_peers_ removed_ || exit 1; done` и `for i in $(seq 10); do cargo test -q --locked -p chervo-friends --test invite_net || exit 1; done`
- [ ] CI: все job зелёные (3 ОС, supply-chain `cargo audit`/`cargo deny`).

## НЕ проверяется на этапе (записать в отчёт, не заявлять)
- Стойкость композиции SAS (обязательство-раскрытие) формально (без Tamarin/ProVerif): только рассуждение п.1 и ревью security.
- Запись `friends-key-v1` в настоящих хранилищах ОС (ручной `os_list_key_roundtrip_manual`).
- Удобство и надёжность сверки 8 цифр людьми; QR-картинки; реальные мессенджеры (переносы строк, автозамены).
- Атомарность `rename` и сохранность при отключении питания (кроме теста перезаписи на CI); откат файла списка старой копией AEAD не ловит (T5).
- Обнуление ключа AEAD внутри ring (факт 1) и копий в snow (В2).
- Соединение через реальные NAT (этапы 13, 16).

## Стоп-условия
Противоречие спецификации и кода; нужен новый крейт или изменение KK/стука/`SecretStore`; факт 1-3 не сходится с исходником; критерий непроверяем; тест гонки нестабилен после двух попыток исправления. Остановиться и доложить, не обходить.

## Лимит
Не более 2 кругов «правка по ревью» на этап, затем доложить владельцу.

## Отчёт builder (до 25 строк на вызов)
Изменённые файлы; команды критериев и последние строки вывода; итерации fuzz-смоука; что не сделано; отклонения от спецификации с причиной.

## Процесс и исполнители
1. Вызов 1 (К1-К4, критичное): `combine-builder` sonnet/high. Дирижёр после него сам запускает `cargo test` изменённых крейтов и clippy (по фактическому выводу).
2. Вызов 2 (О1 + сетевые тесты): `combine-builder` sonnet/medium.
3. `combine-verifier` (sonnet/low): все критерии.
4. `combine-security` (opus/high), один раз по полному diff этапа: решения 1-4 и 11, формат и разбор токена, протокол M1/M2/решение, SAS, `GuestSecret`, `vault`, К4 (замки, гонка), порядок О1 при ошибках хранилища. Отдельного ревью architect нет (решение 12).

## Требования к другим этапам (не реализуются здесь)
- Этап 12: адреса B для A после аутентификации (обмен адресами); фильтр EUI-64 и выбор адресов для токена; `last_addr_seq` начинает с 0.
- Этап 13: диспетчер соединений: соединение пары из `pending` → поток приглашения, из друзей → обычный; `PeerFilter` = активные друзья + гостевые пары незавершённых приглашений; `set_peers` после каждого изменения книги; срок сессии приглашения у вызывающего (предложение 300 с на сверку SAS); `drop_all_pending` при старте и `expire` раз в минуту.
- Этап 14: сообщение «отзыв» по живому соединению до удаления ключа; приём → `apply_revocation`.
- Этап 15: автоприём только по `Permission::AutoAccept` с лимитами.
- Этап 17: журналы без текста токена, гостевого секрета, SAS, имён, адресов; цели libFuzzer для `decode`, M1/M2, открытого текста списка (если нет nightly, так и записать); `PR_SET_DUMPABLE`/core dump (секреты приглашения в памяти).
- Этап 18: SAS на обоих экранах и явное подтверждение; текст «токен — как пароль, не публикуйте, действует N минут»; при неудаче соединения по приглашению подсказка «синхронизируйте время» (стук требует часов в пределах ~1 мин); QR в алфавитно-цифровом режиме; выбор «мы в одной сети» для LAN-адресов; кнопка «пересоздать ключ» = `rekey` + новое приглашение; показ `KEY_LOST_TEXT`.

## Для владельца (кратко)
- Добавление друга: вы отправляете токен (текст или QR), друг подключается к вам напрямую, у обоих появляются 8 цифр; совпали и оба нажали «подтвердить» — дружба создана, иначе ничего не сохраняется.
- Отличие от прежнего плана: цифры считаются не из «отпечатка» шифрованного соединения (его злоумышленник посередине может подогнать перебором), а по схеме «сначала спрятанное обещание в токене, потом раскрытие»: подогнать цифры нельзя, шанс угадать 1 к 100 миллионам.
- Токен содержит одноразовый секрет: кто его увидел до друга, может занять приглашение (не пройдёт сверку цифр, но сорвёт добавление). Поэтому срок жизни короткий и не больше 3 попыток.
- Список друзей на диске зашифрован; ключ от него лежит в хранилище ОС отдельной записью. Удаление, блокировка или отзыв друга сразу рвут его живое соединение.
- «Пересоздать ключ» = уведомление другу (подписано старым ключом) + удаление старой пары + новое добавление со сверкой цифр.

## Вопросы владельцу (не блокируют; спецификация идёт по рекомендованному)
1. **Формат SAS.** Рекомендую 8 цифр («1234 5678», шанс подгонки 10^-8). Варианты: 6 цифр (проще, 10^-6); слова или эмодзи (этап 18, тот же расчёт).
2. **Срок жизни приглашения.** Рекомендую 15 минут по умолчанию, настраиваемо от 1 минуты до 24 часов. Короче — меньше окно для перехватившего токен; длиннее — удобнее через мессенджер.
3. **LAN-адреса в токене.** Рекомендую класть только при явном выборе «мы в одной сети / QR при встрече»; иначе только внешние адреса (меньше утечки топологии, T8).
4. **Обрыв на последнем подтверждении.** Рекомендую принять остаток: у одной стороны друг может появиться, у другой нет; приложение покажет «друг недоступен, добавьте заново». Полностью исключить это нельзя без третьей стороны.
5. **Фаззинг.** Рекомендую на этапе 11 fuzz-смоук на stable без новых зависимостей (1 млн итераций в приёмке), а libFuzzer (nightly, крейт `libfuzzer-sys`, версия и docs.rs [НП]) — на этапе 17.
