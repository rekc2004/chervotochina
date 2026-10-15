# SPEC 9: адаптер транспорта quinn и аутентификация соединения (U10b + Noise KK)          критичность: КРИТИЧНЫЙ

Автор: combine-architect, 2026-10-15, редакция 2. Основание: `docs/OWNER_DECISIONS.md` U7, U10b, «Решения 2026-10-15» (Noise KK, IPv6 позже, посредник позже); `docs/DECISION.md` 2.5-2.7; `docs/THREAT_MODEL.md` T1, T9, T10, T13, T14; ревью `docs/reviews/{ARCH,SECURITY}-REVIEW-STAGE07.md` и `{ARCH,SECURITY}-REVIEW-STAGE08.md`; `docs/SPIKE_TRANSPORT.md` разд. 3, 4B, 5, 6, 9.9. Редакция 2 по ревью 10б (`docs/reviews/ARCH-REVIEW-STAGE10B.md` разд. 5, `docs/reviews/SECURITY-REVIEW-STAGE10B.md` Medium и Low): ворота перебора KK (семафор и бюджет до `spawn_blocking`), один отказ на все причины, уникальность экспортёра, копии секретов X25519 и запрет core dump.
**Порядок: этап 9 начинается только после приёмки этапа 10б** (`docs/specs/stage-10b-kx.md`): нужны `KxPeer`, `ChannelBinding`, `kk_initiate`, `kk_respond`.
Метки: [П] сверено мной по исходнику крейта (файл:строка, версии ниже) или по коду/логу спайка; [НП] не проверено, проверяется шагом или командой; [В] вывод; [Д] память. Ничего не запускалось.
Открытые вопросы владельцу (В1-В3, см. «Для владельца»): текст ниже написан под вариант (а) каждого, места помечены «до ответа владельца».

Цель: крейт `chervo-transport-quinn` реализует `chervo_transport::Transport` на одном UDP-гнезде (сервер и клиент), с одноразовым ключом TLS 1.3 на каждое соединение, аутентификацией Noise KK, привязанной к экспортёру TLS, без метки пары в сети, с лимитами до аутентификации и одинаковым отказом; `chervo-core` не меняется.

Прочитать: этот файл; `docs/specs/stage-10b-kx.md` (раздел «Интерфейс»); `crates/chervo-transport/**`; `crates/chervo-connect/tests/connect.rs`; `crates/chervo-core/tests/layout.rs`; `crates/chervo-identity/src/lib.rs`; корневой `Cargo.toml`; `deny.toml`; `.github/workflows/ci.yml`; `scripts/check-forbidden.sh`; `spikes/transport/src/tlsb.rs` (образец TLS); `spikes/transport/run.sh` строки 43-121, 123-176, 204-297 (стенд для netns); `spikes/transport/analyze_g1.sh`; `spikes/transport/src/bin/g12-observe.rs` (только интерфейс командной строки). Больше ничего не искать.

## Решения (обоснование)
1. **Аутентификация: только Noise KK, без подписей Ed25519** (обоснование в `stage-10b-kx.md` «Решения» п.3; В1, до ответа владельца действует вариант (а) «только KK + msg3»). Схема на первом двунаправленном потоке, открытом звонящим:
   - звонящий → `msg1` (49 байт: байт вида 0x01 и сообщение KK), поток не закрывает;
   - вызываемый читает ровно 49 байт, перебирает **все** разрешённые пары без раннего выхода (`kk_respond`) внутри ворот перебора (п.12); совпало → пишет `msg2` (48 байт) и закрывает свою сторону потока; не совпало → закрывает соединение, не записав ни байта;
   - звонящий читает ровно 48 байт и конец потока, проверяет (`KkInitiator::finish`), пишет `msg3` (16 байт) и закрывает свою сторону;
   - вызываемый читает ровно 16 байт и конец потока, проверяет (`KkResponder::finish`). Только теперь пара подтверждена.
   prologue = тег || байт вида || экспортёр TLS (32 байта, метка ниже, пустой контекст). Метка пары по сети не идёт (T14). MITM из двух TLS-сессий даёт разные экспортёры, KK не сходится (T13) [В]. `msg1` нельзя составить без секрета пары (DH `ss`), знание публичных ключей из токена не помогает (High 1 ревью 7) [В]. Повтор `msg1` в другом соединении не проходит (другой экспортёр), отражение не проходит (роли KK различны) [В; тесты 10б и ниже]. Защита от повтора держится **только** на уникальности экспортёра (ревью security 10б): см. п.14.
2. **Вызываемый молчит до проверки `msg1`** (BRIEF разд. 7, DECISION 2.6 п.5). Звонящий не шлёт прикладных данных до проверки `msg2` и записи `msg3`; вызываемый не принимает второй поток до проверки `msg3` (лимит потоков до аутентификации = 1).
3. **Одноразовый ключ TLS**: на каждое `Incoming` новый `rustls::ServerConfig` с новым ключом Ed25519 через `Incoming::accept_with` (G9/G11 спайка, `quinn-0.11.12/src/incoming.rs:35-41`) [П]. Базовый конфиг гнезда (обязателен для `Endpoint`) **закрыт по умолчанию**: его резолвер ключа сервера всегда возвращает `None`, поэтому случайный вызов `Incoming::accept()` (`incoming.rs:27-30`, берёт базовый конфиг) даёт провал рукопожатия, а не постоянный ключ (`ARCH-REVIEW-STAGE07.md`, раздел «Не переносить») [В].
4. **Ключ TLS генерирует `ring`** (`Ed25519KeyPair::generate_pkcs8`), а не ed25519-dalek с фичей `pkcs8`: объединение фич в workspace изменило бы набор фич ed25519-dalek, проверяемый этапами 10/10б [В]. `ring` уже в дереве через rustls/quinn (0.17.14 в `spikes/transport/Cargo.lock`) [П].
5. **Одно гнездо** (требование ревью 8 к этапу 9): один `quinn::Endpoint` с базовым серверным конфигом, клиентские соединения через `connect_with` на том же `Endpoint` (`quinn-0.11.12/src/endpoint.rs:208-237`) [П]; своё гнездо через `Endpoint::new(..., std::net::UdpSocket, runtime)` (`endpoint.rs:119-127`) [П], смена гнезда через `Endpoint::rebind` (`:243-270`) [П].
6. **Трейт `chervo_transport` правится минимально**: заглушка `DeviceId` заменяется на `PairId` (требование TASK этапа 9 «заглушка заменена проверенным типом»), метод `remote_id` переименован в `remote_pair`, `TransportError` дополнен. `chervo-core` не меняется (тест layout). `DeviceId` в `chervo-friends` и `chervo-token` не трогаем: их заменит этап 11. DECISION 2.5 («трейт отдаёт экспортёр») пересмотрен: аутентификация общая для всех адаптеров и живёт в `chervo-identity`, адаптер (позже и TCP по U7) только переносит байты, поэтому трейт отдаёт уже аутентифицированные соединения, как и сказано в скелете (`crates/chervo-transport/src/lib.rs:37,67`) [П]. Экспортёр в трейт не выносится до этапа 11 (SAS), если он там понадобится.
7. **Правило одного соединения на пару** (Н5 ревью 8): при втором аутентифицированном соединении той же пары, пока первое живо: одно направление → оставить новое; встречные → оставить то, где звонящий имеет лексикографически меньший публичный X25519 пары; проигравшее закрыть кодом `CLOSE_DUPLICATE`. Обе стороны решают одинаково, потому что знают оба ключа [В]. Остаток: если «старое» встречное соединение уже мертво, но ещё не закрыто по idle, новое закроется, и слой соединения (этап 13) переподключится после idle [В].
8. **Событие смены адреса**: в quinn 0.11.12 нет публичного события миграции (grep `migrat` по `src/` даёт только комментарий `connection.rs:524`) [П]. Адаптер опрашивает `Connection::remote_address()` (`connection.rs:526-528`) [П] с периодом `addr_poll` и шлёт `TransportEvent::RemoteAddrChanged { pair }` (без адреса в событии).
9. **ALPN = `b"chervo/1"`** (Н6 ревью 7: решение, а не перенос `chervo-spike/1`). Одинаков у всех установок; приложение по нему опознаваемо (T1, остаток уже принят; маскировка под чужой трафик запрещена BRIEF разд. 2 п.7). SNI выключен, имя сервера `chervo.invalid` в сеть не уходит [П G12 спайка].
10. **Метка экспортёра** `b"EXPERIMENTAL-chervotochina-conn-kk-v1"`, контекст пустой, 32 байта. Префикс `EXPERIMENTAL` для частного использования без регистрации [В по RFC 5705 п.4, текст не сверял, НП]. quinn передаёт контекст как `Some(context)` (`quinn-proto-0.11.19/src/crypto/rustls.rs:201-211`) [П].
11. **Значения лимитов и таймаутов** (ниже, `QuinnConfig::default`) выбраны мной [В], не замерены. Keep-alive и idle влияют на паттерн трафика и NAT; уточнит этап 13 на реальных роутерах (список «реальные машины» ревью 8).
12. **Ворота перебора KK** (ревью 10б: architect разд. 5, security Medium). Перебор стоит ~160 мкс на кандидата [НП, замер builder 10б], при N = 200 около 32 мс CPU на незнакомца против долей миллисекунды у него; при `max_preauth` = 32 до 32 переборов шли бы параллельно [В]. Поэтому `kk_respond` вызывается только через одни ворота: (1) отдельный семафор `max_kk_trials` (по умолчанию 1, всегда ≤ `max_preauth`), ожидание внутри `auth_deadline`; (2) глобальное ведро токенов в **кандидатах** (`kk_budget_per_sec`, `kk_budget_burst`), стоимость перебора = N (число пар после `PeerFilter`), поэтому цена атаки в CPU не зависит от N [В]. Разрешение семафора и токены берутся **до** `spawn_blocking`; разрешение перемещается в замыкание и освобождается только по окончании перебора, поэтому истёкший дедлайн асинхронной задачи не освобождает слот, пока CPU ещё занят [В]. Значения бюджета выбраны мной без замеров [В] и окончательно выбираются владельцем по замеру `friend_latency_under_flood`. Остаток: под атакой друзья стоят в той же очереди (до KK их не отличить), это отказ в обслуживании, не утечка (T9).
13. **Один отказ на все причины** (security 10б Medium, Low 7 ревью 7). Любая неудача после TLS (ошибка или таймаут чтения, неверный вид, отказ ворот по бюджету или дедлайну, `kk_respond` → `AuthFailed` или `RandomUnavailable`, паника или отмена блокирующей задачи, `finish` → ошибка, `PeerFilter`) идёт в одну функцию `refuse(conn)`: `close(CLOSE_REFUSED, b"")`, ни одного записанного байта. Адаптер не сопоставляет варианты `IdentityError`: любой `Err(_)` обрабатывается одной веткой. Различаются только локальные счётчики `stats()`. Различие по времени отказа остаётся (T14, В3).
14. **Уникальность экспортёра** (security 10б: повтор `msg1` закрывается только ею). Экспортёр берётся одной функцией `binding(&quinn::Connection)` из `export_keying_material` **этого** соединения после завершения рукопожатия; других источников `ChannelBinding` в `src/` нет. Уникальность обеспечивают свежие случайные числа и эфемерный обмен TLS 1.3 у честной стороны и отсутствие возобновления и 0-RTT (п.3, «TLS сервера/клиента») [В]. Проверка: `ekm_unique_per_connection`, `replay_msg1_other_connection_rejected`, `src_guard`.
15. **Копии секретов X25519 и core dump** (security 10б, уточнение В2). snow на каждый кандидат копирует наш секрет X25519 в `Dh25519` и освобождает без обнуления (В2: принято дирижёром до ответа владельца, вариант (а) «своей обёртки не пишем»). Ворота п.12 ограничивают число таких копий в секунду бюджетом. Запрет core dump это политика процесса, а не библиотеки транспорта, и требует системного вызова, тогда как workspace запрещает `unsafe_code` (`Cargo.toml:45`) [П]. Поэтому на этапе 9 он не делается, а записан требованием к этапу 17 (раздел «Требования к другим этапам») [В].

## Факты по исходникам (версии для этапа)
Версии: `quinn` 0.11.12, `quinn-proto` 0.11.19, `quinn-udp` 0.5.16, `rustls` 0.23.46, `rustls-webpki` 0.103.15, `ring` 0.17.14, `tokio` 1.53.3 (последние четыре из `spikes/transport/Cargo.lock`) [П]; `snow` 0.10.0 и прочее через `chervo-identity` (этап 10б).
1. **quinn** [П]: фичи по умолчанию `log, platform-verifier, runtime-tokio, rustls-ring, bloom` (`Cargo.toml:54-60`); нужны только `runtime-tokio`, `rustls-ring` (`:78-102`). `tracing` обязательная зависимость (`:191-194`). Реэкспорт `NoneTokenLog`, `NoneTokenStore`, `ValidationTokenConfig`, `TransportConfig`, `crypto` (`src/lib.rs:62-70`). `Incoming`: `accept` (`incoming.rs:27-30`), `accept_with` (`:35-41`), `refuse` (`:44-47`), `retry` (`:52-60`), `ignore` (`:63-66`), `remote_address_validated` (`:85-87`), `RetryError::into_incoming` (`:123-127`). `Connection`: `closed` (`connection.rs:376`), `close_reason` (`:400`), `side` (`:518`), `remote_address` (`:526`), `export_keying_material` (`:625-637`), `set_max_concurrent_uni_streams`/`set_receive_window`/`set_max_concurrent_bi_streams` (`:643-673`); `Connecting::into_0rtt` (`:126`).
2. **quinn-proto** [П]: `ServerConfig::new` по умолчанию `migration=true`, `max_incoming=65536`, буферы 10 МиБ / 100 МиБ (`config/mod.rs:233-257`); сеттеры (`:283-359`); `with_crypto` создаёт случайный ключ токенов (`:396-409`); `ValidationTokenConfig` `log`/`sent`, по умолчанию `sent=2` при `bloom` (`:507-535`); `ClientConfig` по умолчанию `TokenMemoryCache` (`:576`), `token_store` (`:609-612`). Лимиты `max_incoming` и буферов берутся из **базового** конфига гнезда (`endpoint.rs:226-235`, `:445-465`). `QuicServerConfig::new` ставит `max_early_data_size = u32::MAX` (`crypto/rustls.rs:487`), `try_from(Arc<rustls::ServerConfig>)` значение не трогает (`:500-510`). `TransportConfig`: `max_concurrent_bidi_streams` (`config/transport.rs:68`), `max_concurrent_uni_streams` (`:74`), `max_idle_timeout` (`:101`), `stream_receive_window` (`:114`), `receive_window` (`:125`), `keep_alive_interval` (`:266`), `datagram_receive_buffer_size` (`:294`). Сеттера `stream_receive_window` у живого соединения нет (список методов `connection.rs`) [П], поэтому до аутентификации ограничивается окно соединения, а не потока.
3. **rustls** [П]: `max_early_data_size` (`server/server_conn.rs:366`), `send_tls13_tickets` (`:399`), `enable_sni` (`client/client_conn.rs:213`), `enable_early_data` (`:227`), `Resumption::disabled` (`:513`), `AlwaysResolvesServerRawPublicKeys` (`server/handy.rs:187`), `verify_tls13_signature_with_raw_key` берёт первый алгоритм из отображения схемы (`webpki/verify.rs:213-230`); набор ring по умолчанию содержит ECDSA и RSA (`crypto/ring/mod.rs:107-166`) → Low 5 закрывается проверкой схемы в нашем верификаторе.
4. **Спайк** [П]: `tlsb.rs:35-58` (одноразовый сервер), `:62-112` (верификатор RPK без пиннинга), `:114-128` (клиент) переносятся по смыслу с правками ниже; `auth.rs` **не переносится** (формат с `pair_id`, подписи сырым dalek; Н5, Н10).
5. **Не проверено, сверить в шаге 4**: `ring::signature::Ed25519KeyPair::generate_pkcs8` и `from_pkcs8`/`public_key` в ring 0.17.14; трейт `rustls::server::ResolvesServerCert` (сигнатура `resolve`, метод `only_raw_public_keys`) и трейт хранилища сессий клиента (для теста тикетов) в rustls 0.23.46; в tokio 1.53.3 `Semaphore::acquire_owned` и `OwnedSemaphorePermit: Send` (для перемещения в `spawn_blocking`), справедливость очереди семафора (выдача в порядке запроса: по памяти так [Д], сверить текст `src/sync/semaphore.rs`), и что `spawn_blocking` продолжает замыкание после отмены `JoinHandle` (тогда освобождение разрешения в замыкании обязательно). Иначе → СТОП.

## Сделать (по порядку; каждый шаг проверить до следующего)
1. Среда: `cargo --version`, `rustc --version`; этап 10б принят (`grep -rn "pub fn kk_respond" crates/chervo-identity/src` непусто). Нет → СТОП.
2. `grep -rn "DeviceId" crates/chervo-transport crates/chervo-connect crates/chervo-core` → только известные места (`chervo-transport/src/lib.rs`, `chervo-transport/tests/transport.rs`, `chervo-connect/tests/connect.rs`); иное → СТОП.
3. Зависимости в корне `[workspace.dependencies]`: `quinn = { version = "=0.11.12", default-features = false, features = ["runtime-tokio", "rustls-ring"] }`; `rustls = { version = "=0.23.46", default-features = false, features = ["ring", "std"] }`; `ring = { version = "=0.17.14", default-features = false, features = ["alloc"] }` (если без `std` нет `generate_pkcs8` → `["alloc", "std"]`, записать); `tokio = { version = "=1.53.3", default-features = false, features = ["rt", "net", "time", "sync", "macros"] }`. Члены workspace: добавить `crates/chervo-transport-quinn`. Крейт: `chervo-identity`, `chervo-transport`, `quinn`, `rustls`, `ring`, `tokio`, `zeroize` (workspace); dev: `tokio` с `rt-multi-thread`. После сборки закрепить транзитивные: `cargo update -p quinn-proto --precise 0.11.19`, `-p quinn-udp --precise 0.5.16`, `-p rustls-webpki --precise 0.103.15` (если не выходит → записать фактические версии в отчёт: ссылки файл:строка верны только для указанных). Закоммитить `Cargo.lock`.
4. `cargo fetch`; сверить факт 5 и выборочно 4 ссылки из фактов 1-3. Расхождение → СТОП.
5. Правка `chervo-transport` (интерфейс ниже), обновление `crates/chervo-transport/tests/transport.rs` и `crates/chervo-connect/tests/connect.rs` под `PairId`.
6. Крейт `crates/chervo-transport-quinn`: модули `tls.rs`, `limits.rs` (лимитер по IP, ворота перебора KK), `server.rs`, `client.rs`, `conn.rs` (в том числе `binding` и `refuse`), `registry.rs`, `lib.rs`. Тесты: `tests/` и модульные в `src/` там, где нужен доступ к внутреннему (MITM, базовый конфиг, лимитер, ворота, экспортёр).
7. Инструмент стенда: `crates/chervo-transport-quinn/examples/netcheck.rs` и `tools/netns/stage9.sh` (ниже).
8. Прогнать критерии; G1 и G12 в netns; выложить хвосты вывода.

## Интерфейс (точно)
`chervo-transport` (изменения):
```rust
use chervo_identity::PairId;
#[derive(Clone)] pub struct PeerAddr { pub pair: PairId, pub addrs: Vec<SocketAddr> }   // без Debug (как было)
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum TransportError { NotImplemented, PeerNotAllowed, Closed, AuthFailed, TimedOut, UnknownPair, Io, Duplicate }
// Display: "not implemented", "peer not allowed", "connection closed", "authentication failed",
//          "timed out", "unknown pair", "i/o error", "duplicate connection"
pub trait PeerFilter: Send + Sync { fn is_allowed(&self, pair: &PairId) -> bool; }
pub trait Connection: Send + Sync {
    /// Пара, подтверждённая Noise KK внутри канала; никогда не со слов собеседника.
    fn remote_pair(&self) -> PairId;      // было remote_id() -> DeviceId
    // остальное без изменений
}
// Transport, SendStream, RecvStream, DenyAll, Null* без изменений по смыслу (Null* под новые типы).
```
`chervo-transport-quinn`:
```rust
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic,
        clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro, clippy::todo)]
pub const ALPN: &[u8] = b"chervo/1";
pub const SERVER_NAME: &str = "chervo.invalid";
pub const EKM_LABEL: &[u8] = b"EXPERIMENTAL-chervotochina-conn-kk-v1";
pub const EKM_CONTEXT: &[u8] = b"";
pub const CLOSE_REFUSED: u32 = 0;      // любой отказ и обычное закрытие; reason всегда пустой
pub const CLOSE_DUPLICATE: u32 = 1;    // только аутентифицированному собеседнику

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuinnConfig {
    pub auth_deadline: Duration,          // 10 с: от Incoming (вызываемый) или от connect (звонящий) до конца KK
    pub per_ip_max: u32,                  // 5 рукопожатий
    pub per_ip_window: Duration,          // за 10 с; ключ: IPv4 целиком, IPv6 по /64, v4-mapped как IPv4
    pub limiter_capacity: usize,          // 4096 ключей, при переполнении вытесняется давний
    pub max_preauth: usize,               // 32 соединения в работе до конца KK (семафор)
    pub max_kk_trials: usize,             // 1 перебор KK одновременно; при использовании ограничивается [1, max_preauth]
    pub kk_budget_per_sec: u32,           // 2000 кандидатов в секунду (глобально; до решения владельца)
    pub kk_budget_burst: u32,             // 2000 кандидатов в ведре; при использовании не меньше 1
    pub max_incoming: usize,              // 128 (базовый конфиг)
    pub incoming_buffer: u64,             // 16 КиБ
    pub incoming_buffer_total: u64,       // 1 МиБ
    pub preauth_receive_window: u32,      // 64 КиБ окно соединения до KK
    pub post_auth_bidi: u32,              // 16 потоков после KK (uni всегда 0, датаграммы выключены)
    pub idle_timeout: Duration,           // 30 с
    pub keep_alive: Duration,             // 10 с
    pub accept_queue: usize,              // 16 готовых соединений; переполнено → закрыть новое
    pub addr_poll: Duration,              // 1 с
}
impl Default for QuinnConfig;             // значения выше; тест сверяет

pub struct QuinnTransport { .. }          // Debug = "QuinnTransport(..)"
impl QuinnTransport {
    /// Требует работающий tokio runtime. Одно гнездо для приёма и звонков.
    pub fn bind(addr: SocketAddr, cfg: QuinnConfig, filter: Arc<dyn PeerFilter>) -> Result<Self, TransportError>;
    pub fn from_socket(sock: std::net::UdpSocket, cfg: QuinnConfig, filter: Arc<dyn PeerFilter>) -> Result<Self, TransportError>;
    pub fn set_peers(&self, peers: Vec<KxPeer>);              // атомарная замена набора пар
    pub fn rebind(&self, sock: std::net::UdpSocket) -> Result<(), TransportError>;
    pub fn events(&self) -> tokio::sync::broadcast::Receiver<TransportEvent>;
    pub fn stats(&self) -> TransportStats;
    pub fn shutdown(&self);
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] #[non_exhaustive]
pub enum TransportEvent { RemoteAddrChanged { pair: PairId }, ConnectionReplaced { pair: PairId } }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats { pub retry_sent: u64, pub ignored_rate: u64, pub ignored_busy: u64,
    pub auth_ok: u64, pub auth_failed: u64, pub auth_timeout: u64, pub duplicates_closed: u64, pub queue_full: u64,
    pub kk_trials: u64,        // запущенные переборы (замыкание начало работу)
    pub kk_candidates: u64,    // сумма списанных токенов (стоимость после ограничения burst)
    pub kk_trials_peak: u64,   // максимум одновременно идущих переборов (счётчик внутри замыкания)
    pub kk_denied: u64 }       // отказы ворот: бюджет или дедлайн до старта перебора
impl chervo_transport::Transport for QuinnTransport { type Conn = QuinnConn; .. }

#[derive(Clone)] pub struct QuinnConn { .. }   // Debug = "QuinnConn(..)"
impl chervo_transport::Connection for QuinnConn { .. }
impl QuinnConn { pub fn is_initiator(&self) -> bool; }
```
Семантика (точно):
- **Приём** (одна функция `admit`, единственное место, где потребляется `Incoming`): (1) `!remote_address_validated()` → `retry()`, ошибка → `into_incoming().ignore()`; `retry_sent += 1`; (2) лимит по IP исчерпан → `ignore()`, `ignored_rate += 1`; (3) нет разрешения семафора → `ignore()`, `ignored_busy += 1`; (4) новый одноразовый конфиг, ошибка → `ignore()`; (5) `accept_with(cfg)`; далее задача с общим дедлайном `auth_deadline` держит разрешение семафора до конца KK. `refuse()` не используется (одинаковое молчание на все отказы до TLS).
- **Экспортёр**: одна функция `binding(&quinn::Connection) -> Result<ChannelBinding, ()>` в `conn.rs`: `export_keying_material(&mut Zeroizing<[u8;32]>, EKM_LABEL, EKM_CONTEXT)` этого соединения → `ChannelBinding::from_bytes`. Вызывается обеими сторонами после завершения TLS и до KK; единственное место в `src/`, где появляются `export_keying_material(` и `ChannelBinding::from_bytes(`. Ошибка → `refuse`.
- **Вызываемый после TLS**: `binding`; `accept_bi()`; чтение ровно 49 байт; `msg1[0] != KK_KIND_V1` → `refuse` без ворот (бюджет не тратится; этап 11 добавит здесь разбор вида 0x02); снимок пар, отфильтрованный `PeerFilter` (заблокированная пара = незнакомец), N = его длина, N = 0 → `refuse` без ворот; **ворота перебора** (ниже), внутри них `kk_respond` в `tokio::task::spawn_blocking` (снимок `Arc` и разрешение семафора перемещаются в замыкание); запись 48 байт и `finish()`; чтение ровно 16 байт и конец потока; `finish` → пара; повторная проверка `PeerFilter`; поднять лимиты (`set_max_concurrent_bi_streams(post_auth_bidi)`, `set_receive_window(VarInt::MAX)`); правило одного соединения; в очередь `accept`. Любая ошибка, лишний байт, таймаут: `refuse`, ни одного записанного байта до успешного `msg1`; счётчик `auth_failed` или `auth_timeout`.
- **Ворота перебора KK** (`limits.rs`, одна функция, единственный вызов `kk_respond` и `spawn_blocking` в `src/`): (1) `acquire_owned` семафора на `clamp(max_kk_trials, 1, max_preauth)` разрешений с ожиданием до остатка `auth_deadline`; не дождались → `kk_denied += 1`, `refuse`. (2) Стоимость `c = min(N, max(kk_budget_burst, 1))`; ведро (ёмкость `max(burst, 1)`, пополнение `kk_budget_per_sec` в секунду по `tokio::time::Instant`, старт полным): токенов ≥ c → списать; иначе время ожидания `w = (c − токены) / rate`; `rate = 0` или `сейчас + w` позже дедлайна → `kk_denied += 1`, `refuse` немедленно; иначе ждать `w`, держа разрешение (очередь остаётся по порядку прихода), затем списать. `kk_candidates += c`. (3) `spawn_blocking(move || { let _permit = permit; счётчик активных +1, kk_trials_peak = max(..), kk_trials += 1; kk_respond(..); счётчик −1 })`. (4) Ожидание `JoinHandle` до остатка дедлайна; таймаут, `JoinError` или `Err(_)` → `refuse`. Ни шаг (1), ни (2) не запускают перебор после отказа.
- **Отказ** (одна функция `refuse(&quinn::Connection)`): `close(CLOSE_REFUSED, b"")`. Вызывается на любую неудачу до подтверждения пары у обеих ролей; в `src/` нет сопоставления вариантов `IdentityError` (`IdentityError::` встречается только в виде `Err(_)`-ветки, см. `src_guard`).
- **Звонящий** (`connect`): `PeerFilter` запрещает → `PeerNotAllowed` без сети; пары нет в наборе → `UnknownPair` без сети; пустой список адресов → `Io`; адреса пробуются по порядку списка, по одному, каждый со своим `auth_deadline` (выбор пути и параллельность делает этап 13); `connect_with` → `binding` → `kk_initiate` → `open_bi` → запись 49 байт → чтение ровно 48 байт и конца потока (не больше 49 байт читать) → `finish` → запись 16 байт и `finish()` → поднять лимиты → правило одного соединения → вернуть победителя. Ошибка: `refuse`, `AuthFailed`/`TimedOut`/`Io` (любая ошибка `chervo-identity` → `AuthFailed`); ни одного прикладного байта.
- **TLS сервера** (на каждое `Incoming`): ключ ring Ed25519 (PKCS#8 в `Zeroizing`), SPKI, `CertifiedKey`, `AlwaysResolvesServerRawPublicKeys`; `builder_with_provider(ring)`, `with_protocol_versions(&[&TLS13])`, `with_no_client_auth`; `alpn_protocols = [ALPN]`, `max_early_data_size = 0`, `send_tls13_tickets = 0`, `session_storage = NoServerSessionStorage`; `QuicServerConfig::try_from` (не `new`); `quinn::ServerConfig::with_crypto`; `validation_token_config` с `sent(0)` и `log(NoneTokenLog)`; транспорт до KK (сервер): bidi = 1, uni = 0, датаграммы `None`, `receive_window = preauth_receive_window`, idle, keep-alive.
- **Базовый конфиг гнезда**: то же, но резолвер ключа сервера всегда `None`; плюс `max_incoming`, `incoming_buffer_size`, `incoming_buffer_size_total`.
- **TLS клиента**: как `tlsb.rs:114-128` (TLS 1.3 only, `enable_sni=false`, `enable_early_data=false`, `Resumption::disabled()`, ALPN); верификатор: цепочка не пуста → ошибка; `supported_verify_schemes = [ED25519]`; в `verify_tls13_signature` схема ≠ `ED25519` → ошибка до вызова `verify_tls13_signature_with_raw_key`; TLS 1.2 → ошибка; `requires_raw_public_keys = true`. `quinn::ClientConfig`: `token_store(NoneTokenStore)`, транспорт до KK (клиент): bidi = 0, uni = 0, датаграммы `None`, `receive_window = preauth_receive_window`.
- **Правило одного соединения**: см. «Решения» п.7. Новое проиграло: `accept` его не отдаёт (`duplicates_closed += 1`), `connect` возвращает живого победителя. Новое выиграло: старое закрыть `CLOSE_DUPLICATE`, событие `ConnectionReplaced`.
- **Смена адреса**: на каждое аутентифицированное соединение задача опроса `remote_address()` раз в `addr_poll` до `closed()`; изменилось → `RemoteAddrChanged { pair }`.
- **Журналы**: адаптер ничего не пишет в журналы и stdout (ни IP, ни экспортёр, ни ключи, ни `PairId`, ни тексты ошибок библиотек); вместо журналов `stats()`. `Debug` своих типов замаскирован.

## Не делать
- Не менять `chervo-core`, `chervo-identity`, `chervo-friends`, `chervo-token`, `chervo-addr`, `chervo-transfer`, `chervo-receive`, `chervo-cli`, исходники `chervo-connect` (только его тест), `deny.toml`, `ci.yml`, `spikes/**`.
- Не включать фичи quinn `bloom`, `platform-verifier`, `log`, `rustls-log`, `qlog`; rustls `tls12`, `logging`, `aws_lc_rs`; не брать `iroh`, `igd-next`, `rcgen`, `snow` напрямую (только через `chervo-identity`).
- Не вызывать `Incoming::accept()` и `Incoming::refuse()`; не использовать `QuicServerConfig::new`; не включать 0-RTT, тикеты, NEW_TOKEN, датаграммы.
- Не передавать `PairId`, публичные ключи и любую метку пары в сеть; не добавлять полезную нагрузку в сообщения KK.
- Не подписывать ничего ключом Ed25519 в адаптере; не добавлять домен подписи.
- Не вызывать `kk_respond` мимо ворот; не брать бюджет после `spawn_blocking`; не освобождать разрешение ворот в асинхронной задаче (только в замыкании).
- Не различать причины отказа в сети (код, причина, байты, оповещение); не сопоставлять варианты `IdentityError`.
- Не строить `ChannelBinding` ни из чего, кроме экспортёра этого соединения (ни константы, ни кэша, ни значения другого соединения).
- Не ставить запрет core dump и прочую политику процесса в адаптере (требование к этапу 17).
- Не делать IPv6 dual-stack, UPnP, пробивание, посредника, выбор пути, TCP (этапы 12-13б; IPv6 отложен владельцем).
- Не логировать; не печатать адреса и ключи даже в инструменте стенда (только события без значений, см. ниже).
- Своей криптографии нет: TLS, экспортёр, ключ TLS, KK только вызовами rustls/ring/quinn/chervo-identity.

## Недоверенный ввод
- Всё, что приходит до конца KK: пакеты QUIC (разбирает quinn), байты первого потока. Чтение строго ограничено: 49 байт у вызываемого, затем 16 байт и конец потока; 48 байт и конец потока у звонящего (буфер не больше 49). Лишний байт, ранний конец, второй поток, датаграмма, uni-поток: отказ.
- Общий дедлайн на каждую сторону (Medium 2 ревью 7: звонящий тоже не ждёт вечно `open_bi`/`write_all` у злого сервера с нулевыми лимитами).
- Ресурсы до KK: Retry, лимит по IP с ограниченной картой (Н9), семафор, `max_incoming`, буферы, 1 поток, окно 64 КиБ (Medium 3, Н4).
- CPU перебора KK: `msg1` любого незнакомца с верным видом стоит N кандидатов; ограничено воротами (семафор `max_kk_trials`, бюджет кандидатов в секунду), бюджет списывается до `spawn_blocking`; число копий секретов X25519 в куче snow в секунду ограничено тем же бюджетом [В].
- Отказы одинаковы: до TLS `ignore`, после TLS `CLOSE_REFUSED` с пустой причиной без единого байта (Low 7), для всех причин, включая отказ ворот и `RandomUnavailable`. Различия на уровне TLS (например оповещение при чужом ALPN) это поведение rustls, записать как остаток.

## Тесты (имена точно)
Петлевые (127.0.0.1, в CI на 3 ОС), в тестах укороченные дедлайны через `QuinnConfig`; ключи через `chervo_identity::create` на тестовом `MemStore` (копия из тестов `chervo-identity`). Все соединения теста с одного IP: в тестах ворот `per_ip_max` поднят (1000), чтобы лимитер по IP не маскировал ворота.
- Позитивные: `config_defaults_match_spec`, `connect_accept_echo` (оба знают пару: `remote_pair` верен с двух сторон, эхо 1 МиБ побайтно), `many_pairs_right_one` (у вызываемого 20 пар, звонящий из 13-й: верный `PairId`), `single_socket_both_roles` (A и B на одном гнезде каждый: A звонит B, затем B звонит A; `local_addrs` у каждого один и тот же порт), `post_auth_streams_raised` (после KK открываются 8 потоков параллельно).
- Матрица атак (повтор G10 спайка, без подписей): `stranger_rejected` (ключи не из набора), `public_keys_only_attacker_rejected` (знает оба публичных ключа пары, своего секрета пары нет), `wrong_own_key_rejected` (свой ключ другой пары, ключ друга верный), `blocked_pair_treated_as_stranger` (`PeerFilter` запрещает: у звонящего `AuthFailed`, у вызываемого ни одного записанного байта), `mitm_two_tls_sessions_rejected` (посредник в тесте: принимает звонящего своим TLS, звонит вызываемому, пересылает байты потока; обе стороны отказ, прикладных байт 0), `replay_msg1_other_connection_rejected` (сырой клиент: `msg1` снят с **успешного** соединения настоящего друга и подан в новом TLS-соединении к тому же вызываемому; отказ, 0 байт; положительный контроль: исходное соединение прошло), `reflection_rejected` (msg1 звонящего A возвращён на приём самого A), `bad_msg2_rejected` (злой вызываемый портит бит: звонящий не пишет msg3 и прикладных данных), `bad_msg3_rejected`, `unknown_kind_rejected` (байт вида 0x00, 0x02, 0xFF; `kk_trials` и `kk_candidates` не растут), `wrong_lengths_rejected` (msg1 0, 1, 48, 50, 4096 байт; msg3 15, 17 байт; лишний байт после msg3), `silent_caller_times_out` (TLS есть, потока нет: закрытие у дедлайна, `auth_timeout += 1`), `silent_callee_times_out` (Medium 2: злой сервер не отвечает; `connect` → `TimedOut` не позже дедлайна + 1 с), `zero_stream_limit_callee_times_out` (злой сервер с bidi = 0), `early_streams_blocked_before_auth` (Н4, модульный: до KK второй `open_bi` у звонящего не завершается, `send_datagram` ошибка, попытка записать 4 МиБ в первый поток не завершается, у вызываемого `quinn::Connection::stats().udp_rx.bytes` меньше 512 КиБ; закрытие у дедлайна).
- Экспортёр и отказ: `ekm_unique_per_connection` (модульный: 5 соединений между теми же сторонами; в каждом `binding` звонящего == `binding` вызываемого; 5 значений попарно различны; ни одно не равно 32 нулям), `refusals_indistinguishable` (сырой клиент для каждой причины: незнакомец, вид 0x02, `PeerFilter` запрещает, бюджет исчерпан (`kk_budget_per_sec = 0`, `kk_budget_burst = N`, первый незнакомец съедает ведро), ворота заняты до дедлайна (`max_kk_trials = 1`, `kk_budget_burst` большой, 200 пар, короткий дедлайн, параллельные незнакомцы), неверный `msg3`. У всех причин, кроме `msg3`, из потока прочитано 0 байт; у причины `msg3` прочитаны ровно 48 байт `msg2` и больше ничего. У всех: ошибка соединения `ApplicationClosed` с кодом `CLOSE_REFUSED` и пустой причиной, других кадров закрытия нет. Положительный контроль: по каждой причине вырос свой локальный счётчик (`auth_failed`, `kk_denied`, `auth_timeout`), иначе тест падает «причина не воспроизведена»). `RandomUnavailable` не инжектируется (ГСЧ берёт snow): одинаковость для него обеспечивает единая ветка `Err(_)`, проверка в `src_guard`.
- Ворота перебора: `kk_gate_serializes` (модульный, `limits.rs`; ворота с подменяемым замыканием вместо `kk_respond`: при `max_kk_trials = 1` первое замыкание ждёт `std::sync::Barrier`, второе за 300 мс не стартовало (флаг), после отпуска первого стартует; `kk_trials_peak == 1`; положительный контроль: при `max_kk_trials = 2` оба стартуют и `peak == 2`), `kk_gate_budget` (модульный: `rate = 0, burst = 10` — запрос стоимостью 10 проходит, следующий стоимостью 1 отклонён сразу, не дожидаясь дедлайна, замыкание не вызвано; `rate = 100, burst = 10` после исчерпания запрос стоимостью 10 проходит через 50-1000 мс при дедлайне 2 с и отклоняется сразу при дедлайне 50 мс; стоимость 50 при `burst = 10` списывает 10; `kk_candidates` растёт до старта замыкания), `kk_permit_held_after_deadline` (модульный: замыкание дольше дедлайна; асинхронная сторона получила таймаут, а новое замыкание не стартует, пока первое не кончилось), `kk_trials_bounded_under_strangers` (петля: 50 пар, `max_kk_trials = 1`, `kk_budget_per_sec = 1000`, `kk_budget_burst = 200`, `max_preauth = 64`, дедлайн 10 с; 30 незнакомцев параллельно шлют `msg1` вида 1 со случайными байтами; после закрытия всех: `kk_trials_peak == 1`; `kk_candidates ≤ 200 + 1000·t + 50`, где t = время от первого соединения до последнего закрытия в секундах; `kk_candidates == 50·kk_trials`; у каждого незнакомца 0 байт и `CLOSE_REFUSED`), `friend_admitted_under_strangers` (те же настройки, но 10 пар; сначала `t0` = медиана 3 соединений друга без нагрузки; затем 20 незнакомцев параллельно и через 50 мс звонок друга из 7-й пары: `connect` успешен за время ≤ X, где X = (20·10 − 200)/1000 с + 20·t0 + 1 с; в отчёт: X и фактическое время), `friend_starved_documented` (фиксирует остаток T9: `kk_budget_per_sec = 0`, `kk_budget_burst = 10·N`, 10 незнакомцев съедают ведро, затем друг получает `AuthFailed` или `TimedOut`, а вызываемый `kk_denied ≥ 1`; тест проходит, когда друг **отвергнут**).
- TLS: `server_key_fresh_per_connection` (3 соединения → 3 разных SPKI сервера у клиента; G11), `peer_identity_none` (сервер не получает клиентского сертификата), `verifier_ed25519_only` (схемы `[ED25519]`; подпись со схемой ECDSA_NISTP256_SHA256 отвергнута), `base_config_refuses_handshake` (модульный: `Incoming::accept()` с базовым конфигом → рукопожатие не проходит), `no_tickets_no_0rtt` (Н2: сырой клиент с возобновлением и `enable_early_data=true` дважды: тикетов 0, `into_0rtt` = `Err`), `no_new_token` (Н3: сырой клиент со своим `TokenStore`, считающим вставки: 0).
- Лимиты: `retry_before_handshake` (каждое первое соединение получает Retry: `retry_sent` ≥ числа соединений), `per_ip_limit` (`per_ip_max = 2`: третье за окно молча не обслуживается, `ignored_rate ≥ 1`), `limiter_bounded` (модульный: 10 000 разных IPv6 /64 и IPv4 → размер карты ≤ `limiter_capacity`; адреса одного /64 считаются одним ключом), `preauth_semaphore` (`max_preauth = 1`: молчащий клиент держит слот, второй не обслуживается, `ignored_busy ≥ 1`; после дедлайна второй проходит).
- Остальное: `simultaneous_connect_keeps_one` (20 повторов: A и B звонят друг другу одновременно; через 1 с у каждой стороны ровно одно живое соединение пары, `A.is_initiator() != B.is_initiator()`, звонящий у оставшегося = сторона с меньшим публичным X25519), `same_direction_reconnect_replaces` (второй звонок той же стороны: старое закрыто `CLOSE_DUPLICATE`, событие `ConnectionReplaced`), `remote_addr_change_event` (звонящий делает `rebind` на новое гнездо: у вызываемого `RemoteAddrChanged` за ≤ 3 с, `remote_addr()` с новым портом, эхо продолжается), `unknown_pair_no_network` и `peer_not_allowed_no_network` (на гнездо назначения не пришло ни одного пакета: проверка через отдельное UDP-гнездо-приманку), `accept_queue_full_closes` (`accept_queue = 1`, никто не вызывает `accept`: третье соединение закрыто, `queue_full ≥ 1`), `debug_redacted` ("QuinnTransport(..)", "QuinnConn(..)").
- Статика: `src_guard` (читает `src/**/*.rs`: нет `tracing`, `log::`, `println!`, `eprintln!`, `print!`, `dbg!`, `DeviceId`, `QuicServerConfig::new`, `.refuse(`, `into_0rtt`, `send_datagram`, `IdentityError::`; `accept_with(` ровно одно вхождение; `kk_respond(`, `spawn_blocking(`, `export_keying_material(`, `ChannelBinding::from_bytes(` ровно по одному вхождению; `CLOSE_REFUSED` используется только в функции `refuse`; `\.accept\(\)` только в виде `endpoint.accept()`; `dangerous()` только в `src/tls.rs`).
- Замер (без порога): `accept_cost_by_pairs` (`#[ignore]`, release): время от `connect` до готового соединения на петле при 1, 10, 50, 200 парах у вызываемого, медиана из 20; таблица в отчёт (дополняет `kk_trial_cost` этапа 10б). `friend_latency_under_flood` (`#[ignore]`, release): N = 10, 50, 200; число незнакомцев 0, 10, 50; `kk_budget_per_sec` = 500, 2000, 8000 (burst равен rate); медиана из 5 времени соединения друга, `kk_denied` и `kk_candidates` в секунду (CPU процесса не меряется: нужен `unsafe` или новая зависимость); таблица в отчёт для выбора бюджета владельцем.

## Стенд netns (повтор G1 и G12 на адаптере)
- `examples/netcheck.rs` (только инструмент, не продукт): подкоманды `keygen --dir D` (две стороны, записи через `chervo_identity::create` в файловом `SecretStore` примера, файлы `0600` в каталоге стенда вне репозитория; это допустимо только в инструменте), `listen --dir D --listen ADDR` (эхо), `connect --dir D --to ADDR --bytes N --duration S --idle-s S --change-addr-at S`. Печатает только строки `EVENT <имя> key=value` без IP, ключей, `PairId`, экспортёра: `bound`, `auth_ok side=c|s`, `app_ok bytes=N echo_eq=0|1`, `after_idle conn_alive=0|1 probe_ok=0|1`, `addr_change_mark t=MS`, `addr_changed` (сервер, по событию адаптера), `client_result ok|err kind=<вариант TransportError>`.
- `tools/netns/stage9.sh <g1|g12|all|teardown>`: копия функций `do_teardown`, `veth`, `addr4`, `addr6`, `route6`, `do_setup`, `nft_router`, `nft_host`, `bg_start`, `bg_stop`, `cap_start`, `cap_stop`, `gate_begin`, `gate_end`, `cnt`, `evl`, `evn`, `kv`, `net_fail`, `peer_zero`, `verdict` из `spikes/transport/run.sh` (в шапке: «скопировано из spikes/transport/run.sh@<коммит>»); `spikes/transport/analyze_g1.sh` и `g12-observe` вызываются как есть, `spikes/**` не правится. Логи в `tools/netns/logs/` (в git только `summary.txt` и `result.txt`/`observe.txt`, без pcap).
- G1: как `g1_run` спайка (60 с передачи, 30 с простоя, смена адреса клиента на 30-й секунде). PASS: `dns=0`, `other=0`, `portmap=0`, `fwd_drop=0`, кортежи вне списка пусты, `peer>0` у обеих сторон, `auth_ok side=c`, `app_ok echo_eq=1`, `after_idle conn_alive=1 probe_ok=1`, у сервера `addr_changed ≥ 1`.
- G12: захват на маршрутизаторе, два соединения двух пар; иглы: все `PairId`, публичные Ed25519 и X25519 обеих сторон обеих пар, `chervo.invalid`; положительный контроль ALPN `chervo/1`. PASS = `RESULT PASS` у `g12-observe`.
- Нет root, netns или nftables → вердикт INCONCLUSIVE с причиной, этап по этому пункту не принят, доложить (не подменять).

## Критерии приёмки (каждый командой, вывод в отчёт)
- [ ] `cargo build --workspace --locked`
- [ ] `cargo test --workspace --locked` (в том числе `chervo-core` `workspace_layout` и обновлённые тесты `chervo-transport`, `chervo-connect`)
- [ ] `cargo test -p chervo-transport-quinn --locked -- --list --include-ignored` содержит каждое имя из «Тесты»; все неигнорируемые проходят
- [ ] `cargo test -p chervo-transport-quinn --locked -- kk_gate kk_permit kk_trials_bounded friend_ refusals_indistinguishable ekm_unique replay_msg1 --nocapture`: все `ok`; в выводе `friend_admitted_under_strangers` значения X и фактического времени
- [ ] `cargo test -p chervo-transport-quinn --release --locked -- --ignored accept_cost_by_pairs --nocapture`: таблица в отчёте
- [ ] `cargo test -p chervo-transport-quinn --release --locked -- --ignored friend_latency_under_flood --nocapture`: таблица в отчёте
- [ ] `grep -rnE "kk_respond\(|spawn_blocking\(" crates/chervo-transport-quinn/src`: ровно две строки, обе в `limits.rs` (дублирует `src_guard` для глаз дирижёра)
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `bash scripts/check-forbidden.sh` и `--self-test`
- [ ] `git diff --stat <база этапа> -- crates | grep -vE "crates/chervo-transport-quinn/|crates/chervo-transport/|crates/chervo-connect/tests/"` пусто
- [ ] `git diff <база этапа> -- crates/chervo-core` пусто
- [ ] `grep -rn "DeviceId" crates/chervo-transport crates/chervo-transport-quinn crates/chervo-connect` пусто
- [ ] `cargo tree -p chervo-transport-quinn -e features -i rustls | grep -E "tls12|logging|aws"` пусто; `cargo tree -p chervo-transport-quinn -e features -i quinn | grep -E "bloom|platform-verifier|qlog"` пусто; `cargo tree -p chervo-transport-quinn -e features -i quinn-proto | grep bloom` пусто
- [ ] `cargo tree -p chervo-transport-quinn -e features -i ed25519-dalek`: только `zeroize`, `fast`
- [ ] `cargo tree -p chervo-transport-quinn -e normal | grep -Ei "iroh|igd|openssl|aws-lc|rcgen|webpki-roots|platform-verifier"` пусто
- [ ] `cargo tree -p chervo-transport-quinn -d`: вывод в отчёт (дубликаты крипто-крейтов перечислить)
- [ ] `sudo bash tools/netns/stage9.sh all`: в `tools/netns/logs/summary.txt` строки `G1 PASS` и `G12 PASS` (или INCONCLUSIVE с причиной → этап не принят по пункту)
- [ ] Supply-chain: зелёный job `supply-chain` CI на коммите этапа; CI-матрица 3 ОС зелёная (ссылки на прогоны приводит дирижёр)
- [ ] Запрет core dump: [НП] на этапе 9, не делается (политика процесса, `unsafe_code = "forbid"`); проверка требования в разделе «Требования к другим этапам», в отчёте одной строкой «не делалось»

## НЕ проверяется на этапе (записать в отчёт, не заявлять)
- Реальные сети, NAT, операторы, ТСПУ; IPv6 (отложен владельцем); посредник; UPnP.
- Стойкость к распределённому потоку с многих IP (T9): лимиты ограничивают ресурс, но не отличают незнакомца от друга до KK. Под атакой друзья ждут в той же очереди ворот и могут не уложиться в дедлайн (тест `friend_starved_documented` фиксирует это как остаток, а не как защиту).
- Время отказа после `msg1` растёт с числом пар: незнакомец, прошедший TLS, может оценить число друзей (T14, остаток; В3, до ответа владельца вариант (а): остаток принят, фиктивных попыток нет) [В]. Ожидание в воротах добавляет шум, но мерой не считается.
- Отпечаток ClientHello и оповещения TLS (ALPN `chervo/1`, RPK, Ed25519, без SNI) опознают приложение пассивно и активно (T1, Н6; маскировка запрещена).
- Копии секретов X25519 в куче snow без обнуления (10б; В2, принято дирижёром до ответа владельца): N копий на каждый перебор, число переборов задаёт атакующий в пределах бюджета; попадание в своп, дамп и файл гибернации [В]; ключ TLS и PKCS#8 внутри ring/rustls без обнуления [НП].
- Запрет core dump и защита от чтения памяти процесса: не делается на этапе 9 (требование к этапу 17).
- Журналы quinn/quinn-proto/rustls на уровне debug/trace (идентификаторы соединений и, возможно, адреса) [НП]: требование к этапу журналов — фильтр `quinn`, `quinn_proto`, `quinn_udp`, `rustls`, `snow` не ниже `warn`.
- Размер `SO_RCVBUF`/`SO_SNDBUF` (ревью 8 Н3): значение выбирает этап 14 по замеру, адаптер принимает готовое гнездо (`from_socket`).
- Значения лимитов, idle, keep-alive и бюджета перебора не замерены [В]; справедливость семафора tokio сверяется только по исходнику (шаг 4).

## Требования к другим этапам (из этапа 9)
- **Этап 17 (укрепление процесса), запрет core dump** (security 10б, уточнение В2). Вызывать в точке входа бинарника до загрузки ключей; workspace запрещает `unsafe_code`, поэтому через безопасную обёртку из проверенного крейта (выбор крейта и его ревью на этапе 17) [В].
  - Linux: `RLIMIT_CORE = 0` и `PR_SET_DUMPABLE = 0` (второе также мешает `ptrace` процесса тем же пользователем при `ptrace_scope = 0`) [Д, по памяти о man-страницах, сверить]. Проверка: `grep "Max core file size" /proc/<pid>/limits` → `0 0`; `stat -c %U /proc/<pid>/mem` → `root` у недампуемого процесса [Д, сверить с man proc]; аварийное завершение `kill -SEGV <pid>` при `ulimit -c unlimited` не оставляет файла ядра. [НП]
  - macOS: `RLIMIT_CORE = 0`; проверка тем же `kill -SEGV` и отсутствием файла в `/cores` [НП].
  - Windows: WER LocalDumps по умолчанию выключены, но включаются политикой машины; управление из приложения [НП], решение этапа 17.
  - Своп и гибернацию не закрывает ни одна из этих мер (копии snow в куче не закрепить `mlock` без своего аллокатора) [В]: остаток T9/T10.
- **Этап 11**: разбор вида 0x02 (приглашение) встраивается до ворот перебора; длина первого сообщения приглашения может отличаться от 49 (ревью architect 10б разд. 6). Ключ друга, равный нашему X25519, отвергать (security 10б Low), если этого не сделал круг правок 10б.
- **Этап 17 (DoS)**: проверка под потоком с многих IP, значения бюджета по решению владельца.

## Стоп-условия
Противоречие спецификации и кода, нужна зависимость или фича сверх перечисленных, критерий непроверяем: остановиться и доложить, не обходить. Дополнительно:
- этап 10б не принят; шаг 2 или 4 дал расхождение;
- quinn или rustls не дают закрыть базовый конфиг (резолвер `None`) или выключить NEW_TOKEN/тикеты указанным способом;
- семафор tokio не отдаёт разрешения по порядку запроса или `OwnedSemaphorePermit` нельзя переместить в `spawn_blocking`;
- правка `chervo-transport` ломает сборку крейта, который по спецификации не трогаем;
- `cargo deny` падает на лицензии (`deny.toml` не править);
- тест требует печати IP, ключей или `PairId`;
- стенд netns недоступен (вердикт INCONCLUSIVE, доложить).

## Процесс и исполнители
1. Исполнитель: `combine-builder`, Sonnet, effort high, строго по спецификации.
2. Приёмка: `combine-verifier` запускает все критерии, включая стенд, и прикладывает вывод; дирижёр сам перезапускает `cargo test -p chervo-transport-quinn --locked` и G1.
3. Ревью `combine-architect`: соответствие решению U10b+KK, порядок сообщений, отсутствие байтов до проверки, лимиты, ворота перебора (порядок: семафор, бюджет, затем `spawn_blocking`), единый отказ, источник экспортёра, правило одного соединения.
4. `combine-security`: ревью по diff и модели угроз (T1, T9, T10, T13, T14), злые входы, журналы.
Лимит: не более 2 кругов «правка по ревью», затем доложить.
Отчёт (до 25 строк): изменённые файлы; версии (в том числе фактические транзитивные); результат шага 4; команды приёмки и последние строки вывода; таблицы `accept_cost_by_pairs` и `friend_latency_under_flood`; X и факт `friend_admitted_under_strangers`; G1/G12; что не сделано; отклонения.

## Учёт требований ревью
| Откуда | Требование | Где закрыто |
|---|---|---|
| Ревью 7 sec High 1, arch Н5, T14 | первое сообщение требует секрета; метки пары нет; перебор без раннего выхода | Решения п.1; `kk_respond` (10б); тесты матрицы |
| sec Medium 2 | дедлайн звонящего | `auth_deadline`, `silent_callee_times_out`, `zero_stream_limit_callee_times_out` |
| sec Medium 3, arch Н4, Н9 | семафор, `max_incoming`, буферы, 1 поток и малое окно до KK, ограниченный лимитер /64 | `QuinnConfig`, `admit`, тесты лимитов |
| sec Medium 4 | нет журналов с EKM, ключами, pair_id, IP | «Журналы», `src_guard` |
| sec Low 5 | только Ed25519 в верификаторе | `verifier_ed25519_only` |
| sec Low 6 | версия в аутентифицированных данных | байт вида в prologue (10б) |
| sec Low 7 | одинаковый отказ | `ignore` до TLS, `CLOSE_REFUSED` без байтов после |
| arch Н2, Н3 | 0-RTT/тикеты проверены на сервере; NEW_TOKEN явно | `no_tickets_no_0rtt`, `no_new_token` |
| arch «Не переносить» | нет `Incoming::accept()` с постоянным ключом | базовый конфиг закрыт, `base_config_refuses_handshake`, `src_guard` |
| arch Н6 | ALPN решением | Решения п.9 |
| arch Н10 | не подписывать сырым dalek | подписей нет, KK в `chervo-identity` |
| Ревью 8 к этапу 9 | одно гнездо, своё гнездо, адрес пира и события смены | Решения п.5, 8; `single_socket_both_roles`, `remote_addr_change_event` |
| Ревью 8 Н5 | одно соединение на пару | Решения п.7; `simultaneous_connect_keeps_one` |
| TASK 9 | G1 и G12 на адаптере, `DeviceId` заменён | стенд netns; критерии grep |
| Ревью 10б arch разд. 5 п.1-3, sec Medium | семафор `max_kk_trials` 1-2; глобальный бюджет; бюджет до `spawn_blocking`; тест | Решения п.12; «Ворота перебора KK»; `kk_gate_serializes`, `kk_gate_budget`, `kk_permit_held_after_deadline`, `kk_trials_bounded_under_strangers`, `friend_admitted_under_strangers`, `friend_latency_under_flood` |
| Ревью 10б arch разд. 5 п.4, sec Medium | друзья в той же очереди под атакой | T9 остаток; «НЕ проверяется»; `friend_starved_documented` |
| Ревью 10б sec Medium | молча закрывать, не различая `AuthFailed` и `RandomUnavailable` | Решения п.13; функция `refuse`; `refusals_indistinguishable`; `src_guard` (`IdentityError::`) |
| Ревью 10б sec (повтор msg1) | уникальность EKM | Решения п.14; функция `binding`; `ekm_unique_per_connection`, `replay_msg1_other_connection_rejected`, `src_guard` |
| Ревью 10б sec Medium (В2) | N копий секретов X25519 без обнуления; запрет core dump | Решения п.15; бюджет ограничивает число копий; T9/T10; «Требования к другим этапам» (этап 17) |
| Ревью 10б sec Low | T9, T13, T14 описывают подписи и метку | `docs/THREAT_MODEL.md` редакция 2 |
| Ревью 10б arch разд. 6 | вид 0x02 и длина первого сообщения приглашения | «Требования к другим этапам» (этап 11) |

## Для владельца (кратко)
- Программа слушает и звонит через одно UDP-гнездо. Каждое соединение шифруется TLS 1.3 на новом одноразовом ключе; кто есть кто, стороны выясняют внутри канала через Noise KK ключами пары, привязанными к этому соединению.
- Звонящий ничего не называет: ни метки пары, ни ключа. Принимающий молчит, пока звонящий не докажет секрет пары, и перебирает всех друзей одинаково долго. Посторонний на старом адресе ничего не узнаёт о паре.
- Подписей в проверке соединения нет (их заменил KK): нужна ваша отметка, что такая замена буквы U10b вас устраивает (вопрос В1; до ответа делаем вариант (а) «только KK и третье сообщение»).
- До проверки незнакомцу почти ничего не дают: проверка адреса QUIC, лимит попыток с IP, общий предел, один поток и малое окно, дедлайн 10 с; на любой отказ одинаковая реакция, по сети нельзя различить, почему отказали.
- Новое: проверка «кто звонит» стоит процессора пропорционально числу друзей (при 200 друзьях около 32 мс на попытку, цифра builder, не перепроверена). Поэтому такие проверки идут по одной и в пределах общего бюджета «кандидатов в секунду» (предварительно 2000, по оценке около трети одного ядра). Нужен ваш выбор бюджета после замера этапа 9.
- Цена бюджета: под атакой ваши друзья стоят в той же очереди, что и чужие, и могут не дозвониться, пока атака идёт. Это отказ в обслуживании, не утечка.
- Если оба звонят друг другу одновременно, остаётся одно соединение (обе стороны выбирают одно и то же по ключам).
- Остатки: приложение опознаётся по рукопожатию (маскировка запрещена); незнакомец может грубо оценить число ваших друзей по времени отказа (вопрос В3, до ответа принимаем как остаток); библиотека snow оставляет в памяти копии ключей обмена (В2); запрет дампов памяти отложен до этапа 17; лимиты и таймауты выбраны без замеров.
- Проверка «нет трафика к третьим сторонам» и «что видит наблюдатель» повторяется на самом адаптере в эмуляции; реальные сети и IPv6 не проверяются.
