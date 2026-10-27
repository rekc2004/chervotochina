# SPEC 9б: «стук» — порт молчит для чужих          критичность: КРИТИЧНЫЙ

Автор: combine-architect, 2026-10-16, редакция 1. Основание: `docs/OWNER_DECISIONS.md` «Порт молчит для чужих: «стук»» (с уточнениями 2026-10-16: NTP только по кнопке); `docs/specs/stage-09-transport.md` ред. 2 (всё, что здесь не изменено, в силе); `docs/specs/stage-10b-kx.md`; `docs/THREAT_MODEL.md` T1, T9, T13, T14. Начинать после приёмки этапа 9.
Метки: [П] сверено мной по исходнику (файл:строка); [НП] не проверено; [В] вывод; [Д] память. Ничего не запускалось.

Цель: до верного «стука» адрес не получает от гнезда ни одного пакета (ни Retry, ни TLS, ни отпечатка QUIC); друг стучит автоматически внутри `connect` и соединяется как на этапе 9; поправку часов пользователь получает по кнопке из списка NTP.

Прочитать: этот файл; `stage-09-transport.md` («Интерфейс», «Семантика», «Тесты»); `crates/chervo-transport-quinn/src/**`, `tests/**`, `examples/netcheck.rs`; `crates/chervo-identity/src/{kk,kx,lib}.rs`; `tools/netns/stage9.sh`; корневой `Cargo.toml`, `Cargo.lock`. Больше ничего не искать.

## Решения (обоснование)
1. **Ключ стука из секрета пары, отдельный домен.** `ss = StaticSecret::diffie_hellman(&their)` (`x25519-dalek-3.0.0/src/x25519.rs:212`, `SharedSecret` обнуляется `:348-356`, `was_contributory` `:335`) [П]; ключ направления `K(S→R) = BLAKE2s-MAC-256(key = ss, KNOCK_KDF_LABEL || pub_S || pub_R)`. Ключевой BLAKE2s (RFC 7693) из `blake2` 0.10.6 (`Blake2sMac256`, `src/lib.rs:169-172`; `KeyInit::new_from_slice` `src/macros.rs:329-347`; `Mac::verify_truncated_left` с `ct_eq` в `digest-0.10.7/src/mac.rs:198-206`) [П]. **Новой зависимости нет**: blake2 0.10.6 уже в дереве через snow (`Cargo.lock:187`, snow `default-features = false`, `snow-0.10.0/Cargo.toml:159-162`) [П]; добавляется прямой связью в `chervo-identity`. Ключи KK не переиспользуются: в KK `ss` идёт сообщением в HKDF Noise, здесь ключом ключевого хэша с отдельной меткой [В]. Отдельный случайный «секрет стука» отвергнут: требует формата записи v3 и смены приглашения (этап 11) [В]. Ключ направленный (`send = K(ours→theirs)`, `recv = K(theirs→ours)`): свой стук, отражённый себе, не проходит. Код живёт в `chervo-identity` (секрет X25519 наружу не отдаётся, инвариант этапа 10). blake2 не обнуляет внутреннее состояние (grep `zeroize` по `src/` пуст) [П] — остаток того же класса, что snow.
2. **Формат: ровно 48 байт** `id(16) || nonce(16) || tag(16)`; `w` = номер окна (u64, big-endian в MAC); `id = first16(MAC(K, KNOCK_ID_LABEL || w))`; `nonce` = 16 байт `getrandom`; `tag = first16(MAC(K, KNOCK_TAG_LABEL || w || id || nonce))`. Магических байтов, версии и `PairId` нет; все поля псевдослучайны [В]. Адресов в метке нет: при пробросе порта адрес назначения у звонящего (WAN) и у вызываемого (LAN) различны, свой адрес за NAT звонящий не знает [В]. `id` детерминирован в окне: вызываемый находит кандидата поиском в таблице за O(1) вместо N·W MAC на каждый пакет. **Отступление от «без раннего выхода»**: на стук ничего не отправляется, время проверки наружу не наблюдаемо [В]; цена — стуки одной пары в одном окне связываемы наблюдателем (30 с). Альтернатива (перебор всех пар, бюджет проверок) хуже по DoS: см. «Для владельца».
3. **Окно и повтор.** `KNOCK_WINDOW_SECS = 30`; принимаются окна `w−1..=w+1` по исправленному времени **и** по системному (если поправка ≠ 0): гарантированный допуск расхождения часов 30 с [В]. Кэш виденных `(пара, nonce)` с жизнью 120 с (4 окна) и ёмкостью `replay_capacity`; повторный nonce с любого адреса не допускает и не продлевает. В кэш попадают только стуки с верным `tag` (подделать нельзя), поэтому размер ограничен частотой стуков друзей; переполнение → отказ (закрыто по умолчанию). Наблюдатель на пути, успевший переслать стук раньше оригинала, получает допуск к Retry/TLS (видит то, что и так видел бы у друга) и упирается в KK; оригинал друга отвергнут как повтор, `connect` шлёт новый стук (п.4) [В].
4. **Допуск.** Ключ — точный `SocketAddr` источника стука (IPv4; v4-mapped как IPv4). Верный стук → допуск на `knock_admit_ttl` (10 с) и не более `knock_admit_attempts` (2) **подтверждённых** `Incoming` (после Retry; Initial до Retry не считается, Retry без состояния). Источник стука = источник QUIC: одно гнездо, одно отображение NAT [В]. Закрепления (пины, RAII): исходящий `connect` к X держит пин X на время попытки (ответы X проходят, но новое `Incoming` от X без своего стука не принимается: попыток 0); `serve` держит пин адреса до конца KK; аутентифицированное соединение держит пин своего `remote_address` до закрытия (задача опроса адреса перепинивает). Одновременное открытие: обе стороны стучат друг другу, правило одного соединения этапа 9 без изменений; стук звонящего попутно открывает отображение его NAT [В]. Миграция: адрес собеседника, не прошедший стук, отбрасывается; после своего `rebind` адаптер шлёт стук по каждому живому соединению с нового гнезда, и путь подтверждается штатно; смена отображения NAT у собеседника без `rebind` рвёт соединение по idle и даёт переподключение со стуком (остаток до U25).
5. **Стоимость и флуд.** Пакет с недопущенного адреса длиной ≠ 48 — отброс без вычислений; 48 байт — поиск `id` в таблице; MAC только при совпадении `id` (то есть на повтор чужого стука). Таблица `id → (пара, окно, вид)` пересобирается при смене окна, поправки или набора пар: `(2·KNOCK_HINT_SPAN+1 + 3)·N` MAC (N = 200 → ~5000 MAC раз в 30 с) [В, замер `knock_table_cost`]. Отдельный бюджет стуков не нужен [В]; лимиты этапа 9 (лимитер по IP, семафоры, ворота KK) остаются страховкой после допуска. Цикл фильтра не держит поток: после 16 опросов без пропущенных пакетов `wake_by_ref` и `Pending`.
6. **Часы.** Время — `SystemTime` от эпохи UNIX (UTC). Исправленное = системное + `clock_offset_ms`. Поправка задаётся **только** вызовом `set_clock_offset` (значение из кнопки «синхронизировать время», п.10). Звонящий шлёт стуки в моменты 0, `knock_resend_after`, 3·`knock_resend_after` (пока QUIC-рукопожатие не завершилось, в пределах `auth_deadline`); третий стук при ненулевой поправке — по системному времени (на случай, если поправка устарела после включения синхронизации ОС). Признак для ядра: вызываемый держит в таблице также окна `w±2..=w±KNOCK_HINT_SPAN` (10, ±5 мин) вида «подсказка»: стук пары с верным `tag` в таком окне **не допускается**, а даёт `knock_skewed += 1` и событие `ClockSkewSuspected { pair }` (не чаще раза в минуту на пару). Звонящему: счётчик `connect_silent` (попытка без единого ответного пакета). Напоминание пользователю — интерфейс этапа 18, необязательно.
7. **UPnP, проброс, NAT.** Метка не зависит от адресов, поэтому стук проходит через проброс и UPnP; открытый пробросом порт молчит для сканеров. За NAT без проброса входящий порт и так закрыт; стук играет роль пробивного пакета при одновременном открытии (этап 13). Закрытый порт отвечает ICMP, открытый молчащий — нет, поэтому сканер видит «open|filtered», как у межсетевого экрана [В].
8. **Этап 9 меняется так:** порядок `стук → допуск → Retry → TLS → KK`. Гнездо оборачивается своим `AsyncUdpSocket` (`quinn-0.11.12/src/runtime.rs:42-89`) поверх `TokioRuntime::wrap_udp_socket` (`runtime/tokio.rs:30-35`) и передаётся в `Endpoint::new_with_abstract_socket` (`endpoint.rs:133-166`); `rebind` → `rebind_abstract` (`:253-270`) [П]. quinn вызывает `poll_recv` и разбирает только отданные пакеты (`endpoint.rs:794-833`), поэтому отброшенное не порождает ни Retry, ни сброса, ни согласования версии [П по коду цикла]. GRO: один `RecvMeta` = один источник, сегменты по `stride` (`quinn-udp-0.5.16/src/lib.rs:96-117`) [П]; проходит или отбрасывается весь `RecvMeta`, стуком считается каждый сегмент длиной 48. Отправка стука — `try_send` с `Transmit` (`quinn-udp lib.rs:135-146`, реэкспорт `quinn::udp` `quinn lib.rs:75`) [П], при `WouldBlock` ожидание `create_io_poller().poll_writable`. **Трейт `chervo_transport` не меняется**; меняются `QuinnConfig`, `TransportStats`, `TransportEvent`, `QuinnTransport` (ниже).
9. **NTP по кнопке: свой минимальный SNTP-клиент** (новый крейт `chervo-timesync`, только `std` + `getrandom` workspace). Причина: ответ — фиксированные 48 байт, разбор короче и проверяемее, чем ревью чужого крейта и его дерева; крейт `sntpc` и др. не сверялись [НП]. Защита от ложного ответа: случайный «transmit timestamp» запроса (не раскрывает наше время, сервер обязан вернуть его в «originate»), `connect` UDP-гнезда к адресу сервера, проверки полей, медиана по ≥2 серверам с разбросом ≤1 с, предел |поправки| ≤ 7 суток. Подменить ответы всех серверов может только наблюдатель на пути; цена — отказ стуков (DoS, он и так может резать пакеты) и, при откате часов назад, повтор старых перехваченных стуков = допуск к TLS без прохода KK [В].
10. **Хранение поправки:** `(offset_ms, measured_at_unix_s)` в файле настроек приложения (несекретно; подмена требует доступа к профилю пользователя); применяется при старте через `set_clock_offset`; заменяется только следующим нажатием. Устаревание закрывают допуск по системному времени (п.3) и третий стук (п.6) [В]. Файл настроек — этап 15/18 (требование ниже); здесь — API и `netcheck --clock-offset-ms`.

## Интерфейс (точно)
`chervo-identity`, модуль `knock` (реэкспорт из корня):
```rust
pub const KNOCK_LEN: usize = 48;
pub const KNOCK_KDF_LABEL: &[u8] = b"chervotochina/v1/knock-key\0";
pub const KNOCK_ID_LABEL: &[u8] = b"chervotochina/v1/knock-id\0";
pub const KNOCK_TAG_LABEL: &[u8] = b"chervotochina/v1/knock-tag\0";
pub struct KnockKeys { /* send, recv: Zeroizing<[u8;32]> */ } // нет Clone/PartialEq/Hash/Deref; Debug = "KnockKeys(..)"; ZeroizeOnDrop
impl KxPeer { pub fn knock_keys(&self) -> Result<KnockKeys, IdentityError>; } // theirs == ours или !was_contributory → AuthFailed
impl KnockKeys {
    pub fn make(&self, window: u64) -> Result<[u8; KNOCK_LEN], IdentityError>; // ключ send; ГСЧ → RandomUnavailable
    pub fn recv_id(&self, window: u64) -> [u8; 16];                           // ключ recv
    pub fn verify(&self, window: u64, knock: &[u8]) -> bool;                  // len ≠ 48 → false; id и tag через verify_truncated_left
}
```
`chervo-transport-quinn` (добавления):
```rust
pub const KNOCK_WINDOW_SECS: u64 = 30; pub const KNOCK_ACCEPT_SPAN: u64 = 1; pub const KNOCK_HINT_SPAN: u64 = 10;
// QuinnConfig += knock_required: bool (true; false только в тестах и src/tests),
//   knock_admit_ttl: Duration (10 с), knock_admit_attempts: u32 (2), knock_lead: Duration (30 мс),
//   knock_resend_after: Duration (1 с), admit_capacity: usize (1024), replay_capacity: usize (4096)
// TransportStats += knock_ok, knock_bad, knock_replay, knock_skewed, dropped_unadmitted,
//   admit_full, admit_exhausted, connect_silent
// TransportEvent += ClockSkewSuspected { pair: PairId }
impl QuinnTransport { pub fn set_clock_offset(&self, offset_ms: i64); pub fn clock_offset_ms(&self) -> i64; }
pub fn window_at(unix_ms: i64) -> u64;   // floor(unix_ms / 30000), отрицательное → 0
```
Модули: `src/knock.rs` (обёртка гнезда `KnockSocket`, таблица, кэш повторов, `AdmitTable` с пинами-RAII, отправка стука). `connect`: пин → стук → `knock_lead` → `connect_with` → досылка стуков (п.6) → далее как этап 9. `admit`: после проверки `remote_address_validated()` списать попытку допуска; нет → `ignore`, `admit_exhausted += 1`. `set_peers`: пересобрать `KnockKeys` (ошибка → пара вне таблицы) и таблицу. Проверка `PeerFilter` до допуска (заблокированная пара = незнакомец).
`chervo-timesync`:
```rust
pub const DEFAULT_SERVERS: &[&str] = &["0.ru.pool.ntp.org", "1.ru.pool.ntp.org", "2.ru.pool.ntp.org", "3.ru.pool.ntp.org", "ntp1.vniiftri.ru", "ntp2.vniiftri.ru", "ntp3.vniiftri.ru", "ntp4.vniiftri.ru", "ntp21.vniiftri.ru"]; // pool.ntp.org ru: [П] по ntppool.org/zone/ru; vniiftri: [НП], проверить на реальной машине (решение владельца 2026-10-16)
pub struct SyncConfig { pub servers: Vec<String>, pub timeout: Duration /*2 с*/, pub min_valid: usize /*2*/,
                        pub max_spread: Duration /*1 с*/, pub max_abs_offset: Duration /*7 сут*/ } // Default
pub struct ClockOffset { pub offset_ms: i64, pub valid: u8, pub queried: u8 }
#[non_exhaustive] pub enum SyncError { NoServers, TooFewValid, Disagree, TooLarge }  // Display фиксированный
pub fn sync_clock(cfg: &SyncConfig) -> Result<ClockOffset, SyncError>; // блокирующая; потоки thread::scope; первый IPv4 каждого имени
pub fn parse_response(buf: &[u8], origin: [u8; 8], t1: u64, t4: u64) -> Result<i64, ()>; // t1, t4: NTP 32.32 по SystemTime
```
Запрос: 48 байт, байт 0 = `0x23` (LI 0, VN 4, mode 3), байты 40..48 = 8 случайных. Ответ: длина 48..=1024 (читаются первые 48); LI ≠ 3; VN ∈ {3,4}; mode = 4; stratum 1..=15; байты 24..32 == `origin`; transmit ≠ 0; root delay и root dispersion (16.16) ≤ 1 с; RTT по `Instant` ≤ `timeout`. Поправка = `((T2−T1) + (T3−T4)) / 2` в обёрточной (wrapping) арифметике i64 над 32.32 (без эр 1900/2036) → мс. Агрегат: допустимые ≥ `min(min_valid, число имён)` и ≥ 1; медиана; в пределах `max_spread` от медианы ≥ того же порога, иначе `Disagree`; |медиана| > `max_abs_offset` → `TooLarge`.

## Сделать (по порядку, проверять каждый шаг)
0. (Дирижёр через scout, до builder) сверить `DEFAULT_SERVERS` по сайту ВНИИФТРИ; иначе builder пишет список как есть с комментарием `[Д]` и докладывает.
1. Среда; этап 9 принят (`grep -n "fn admit" crates/chervo-transport-quinn/src/server.rs`). Сверить [П]-ссылки п.1 и п.8 (5 шт.). Расхождение → СТОП.
2. `blake2 = { version = "=0.10.6", default-features = false }` в workspace и `chervo-identity`; `cargo build --locked` не добавляет `[[package]]` в `Cargo.lock` (diff). Иначе → СТОП.
3. `knock.rs` в `chervo-identity`, тесты. 4. `chervo-transport-quinn`: `src/knock.rs`, правки `lib.rs`, `server.rs`, `client.rs`, `registry.rs` (пины, повторный стук после `rebind`). Тесты этапа 9 с сырыми клиентами — `knock_required: false` (их предмет — слой после стука); тесты через `QuinnTransport::connect` — с `true`. 5. Крейт `crates/chervo-timesync`. 6. `netcheck`: `--clock-offset-ms`, `timesync`, `probe --mode noise|stranger|stale|replay|flood`. 7. `stage9.sh knock`.

## Не делать
- Не менять трейт `chervo_transport`, `chervo-core`, прочие крейты кроме `chervo-identity` (модуль `knock`, `lib.rs`, `Cargo.toml`, тесты), `chervo-transport-quinn`, нового `chervo-timesync`.
- Не отвечать ничем на недопущенный адрес; не передавать в quinn стук и пакеты недопущенных адресов; не использовать `Endpoint::new` и `Endpoint::rebind` (только `_abstract`).
- Не включать в стук `PairId`, адреса, версию, постоянные байты; не выводить ключ стука из Ed25519; не передавать `ss` наружу `chervo-identity`.
- Никаких автоматических, фоновых, по расписанию или при соединении запросов NTP; `chervo-timesync` не зависит от транспорта и не вызывается из него; системные часы не менять.
- Не добавлять зависимости сверх `blake2` (уже в дереве); фичи blake2 `std`, `simd*`, `reset` не включать.
- Не логировать адреса, `id`, nonce, ключи, поправку.

## Недоверенный ввод
- Любой UDP-датаграмм с недопущенного адреса: длина 0..64 КиБ, GRO-пачки; разбор только «длина == 48 → поиск `id`»; без паник (lint-атрибуты крейта; `indexing_slicing` запрещён).
- Ответ NTP: только с подключённого адреса; длина и все поля проверяются до арифметики; переполнения — только wrapping/checked.
- Имена серверов из настроек: только `ToSocketAddrs`, ≤ 16 имён, длина имени ≤ 253.

## Тесты (имена точно)
`chervo-identity` `tests/knock.rs`: `knock_roundtrip`, `knock_fresh_nonce` (два стука в окне: `id` равен, nonce и tag различны), `knock_directional` (стук A→B не проходит `verify` у A; `send` ≠ `recv`), `knock_wrong_window` (w±1 не проходит в `verify(w)`), `knock_other_pair`, `knock_all_bit_flips` (384 инверсии → false), `knock_wrong_lengths` (0..=100 кроме 48), `knock_self_key_rejected`, `knock_labels_distinct` (метки не равны и не префиксы друг друга, `KK_PROLOGUE_TAG`, тегов `SignDomain::ALL`), `knock_debug_redacted`; doc-тест `compile_fail` `KnockKeys: Clone`.
`chervo-transport-quinn` (сырое гнездо-атакующий: «0 пакетов» = `recv_from` с таймаутом 2 с не получил ничего; у каждого теста положительный контроль: тот же приём при `knock_required: false` получает Retry, иначе тест падает «нет контроля»):
- `silent_to_noise` (2000 датаграмм длин 1..=1500, в том числе 300 по 48 байт), `silent_to_initial_without_knock` (сырой клиент quinn), `silent_to_stranger_knock` (верный формат, пара не в наборе), `silent_to_stale_window` (w−2 и w+3: 0 пакетов, `knock_skewed ≥ 1`, событие `ClockSkewSuspected`), `silent_to_replayed_knock` (копия верного стука с другого гнезда, затем Initial: 0 пакетов, `knock_replay ≥ 1`), `silent_to_blocked_pair`, `silent_after_admit_expired` (ttl 300 мс, Initial через 600 мс), `admit_attempts_bounded` (attempts = 1: второе подтверждённое рукопожатие — `admit_exhausted ≥ 1`), `outbound_pin_no_incoming` (пока A звонит X, новое соединение от X без стука не принимается).
- `friend_connects_with_knock`, `flood_knocks_friend_passes` (4 гнезда × 25 000 случайных 48-байтных; друг соединяется до `auth_deadline`; гнёзда флуда 0 пакетов), `clock_skew_within_tolerance` (поправка звонящего ±25 с: успех), `clock_skew_outside_tolerance` (±120 с: `TimedOut`, у вызываемого `knock_skewed ≥ 1`), `stale_offset_raw_fallback` (у звонящего поправка +300 с при верных системных часах: успех третьим стуком), `simultaneous_knock_connect` (10 повторов, одно соединение), `rebind_reknock` (= `remote_addr_change_event` при `knock_required: true`), `filter_yields_under_flood` (модульный: 10 000 мусорных пакетов подряд — `poll_recv` возвращает `Pending` не позже 16 опросов).
- Статика `src_guard` (дополнить): `try_send(` только в `src/knock.rs`; нет `Endpoint::new(`, `.rebind(`, `chervo_timesync`, `println!`; `knock_required: false` нет в `src/` вне `src/tests/`.
- Замеры (`#[ignore]`, release, без порога): `knock_table_cost` (N = 10, 200, 1000: пересборка и проверка 48 случайных байт), `knock_throughput_overhead` (эхо 64 МиБ, стук вкл/выкл, отношение).
- Все тесты этапа 9 проходят.
`chervo-timesync`: `parse_valid_vector`, `parse_rejects_each_field` (LI 3, VN 2 и 5, mode ≠ 4, stratum 0 и 16, чужой origin, transmit 0, root delay 2 с, длины 0..=47), `parse_never_panics` (100 000 случайных буферов 0..=1100 байт; ни одного `Ok` при неверном origin), `offset_math_wraps` (T вблизи 2036 и разность ±10 суток), `aggregate_median`, `aggregate_disagree`, `aggregate_too_large`, `aggregate_single_server`, `sync_no_servers`; `sync_real_servers` (`#[ignore]`, сеть) — локальный UDP-сервер в тесте для `sync_clock_loopback` (адрес `127.0.0.1:порт` в списке).

## Стенд netns
`tools/netns/stage9.sh knock`: сервер в ns b (`listen`, стук обязателен); из ns a по очереди `netcheck probe` во всех режимах, на каждый режим отдельный захват на veth b: `tcpdump -r cap -nn 'udp and src host <B>'` → 0 строк; затем друг `connect` → `auth_ok side=c`, `app_ok echo_eq=1`. Вердикт `KNOCK PASS` в `summary.txt`. `all` включает `knock`; G1 и G12 повторяются со стуком (в G1 `dns=0`: NTP не вызывается).

## Критерии приёмки (каждый командой, вывод в отчёт)
- [ ] `cargo build --workspace --locked`; `git diff <база> -- Cargo.lock | grep '^+name'` → только `chervo-timesync`
- [ ] `cargo test --workspace --locked`; `cargo test --doc -p chervo-identity --locked`
- [ ] `cargo test -p chervo-transport-quinn --locked -- --list --include-ignored` и то же для `chervo-identity`, `chervo-timesync` содержат каждое имя из «Тесты»
- [ ] `cargo test -p chervo-transport-quinn --locked -- silent_ flood_ clock_skew stale_offset admit_ outbound_pin rebind_reknock --nocapture`: все `ok`
- [ ] `cargo test -p chervo-transport-quinn --release --locked -- --ignored knock_ --nocapture`: таблицы в отчёт
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`; `bash scripts/check-forbidden.sh` и `--self-test`
- [ ] `cargo tree -p chervo-identity -e features -i blake2`: нет `std`, `simd`, `reset`; `cargo tree -p chervo-timesync -e normal --depth 1`: только `getrandom`
- [ ] `grep -rnE "sync_clock\(" crates --include=*.rs | grep -vE "chervo-timesync/|examples/"` пусто
- [ ] `git diff --stat <база> -- crates | grep -vE "chervo-transport-quinn/|chervo-identity/|chervo-timesync/"` пусто
- [ ] `sudo bash tools/netns/stage9.sh all`: `G1 PASS`, `G12 PASS`, `KNOCK PASS` (иначе INCONCLUSIVE с причиной — не принято)
- [ ] CI 3 ОС и `supply-chain` зелёные (ссылки — дирижёр)

## НЕ проверяется (в отчёт, не заявлять)
Реальные NAT, UPnP, ТСПУ; IPv6; настоящие NTP-серверы (стенд без интернета; список [Д]); распределённый флуд с многих IP на реальном канале; смена отображения NAT у собеседника (рвёт соединение, U25); связываемость стуков одной пары в окне 30 с; отпечаток «48 байт UDP, затем QUIC с того же порта» (T1); стойкость при откате часов ложным NTP (повтор старых стуков даёт допуск к TLS, не к паре).

## Требования к другим этапам
- Этап 15/18: хранение `(offset_ms, measured_at)` в настройках, кнопка «синхронизировать время», вызов `set_clock_offset` при старте; подсказка по `ClockSkewSuspected`/`connect_silent` (необязательна).
- Этап 13: стук как пробивной пакет при одновременном открытии; выбор пути учитывает `connect_silent`.
- Дирижёру: обновить `THREAT_MODEL.md` T9, T14 (до KK доходят только знающие ключ пары; утечка числа друзей по времени отказа — только для них), T1 (новый признак), новая угроза «ложный NTP».

## Стоп-условия
Противоречие с кодом; [П]-ссылка не сходится; `blake2` тянет новый пакет; quinn шлёт хоть один пакет недопущенному адресу при обёртке (тогда не обходить — доложить); тест требует печати адресов/ключей; стенд недоступен.

## Процесс
Исполнитель `combine-builder` (Sonnet, high); приёмка `combine-verifier` (все критерии, стенд); дирижёр сам перезапускает `silent_` и `stage9.sh knock`; ревью `combine-architect` (формат, домены, допуск и пины, порядок фильтра), затем `combine-security` (крипто-путь стука, злые датаграммы, SNTP-разбор). Не более 2 кругов правок. Отчёт до 25 строк: файлы; результат шагов 1-2; хвосты команд; таблицы замеров; вердикты стенда; отклонения.

## Для владельца (кратко)
- Перед звонком программа шлёт один короткий пакет-«стук» (48 байт, похож на случайный шум). Без верного стука ваш порт не отвечает вообще ничем: сканер не отличит его от закрытого межсетевым экраном.
- Стук вычисляется из общего секрета пары (своего у каждой пары) и номера 30-секундного окна времени библиотечным ключевым хэшем BLAKE2s; новых библиотек нет.
- Повтор перехваченного стука не проходит; даже если бы прошёл, дальше всё равно нужен ключ пары (Noise KK).
- Часы: допускается расхождение примерно до 30 с без всякой синхронизации. Кнопка «синхронизировать время» спрашивает несколько серверов точного времени (по умолчанию российские, адреса ещё сверяем), берёт медиану и сохраняет поправку до следующего нажатия. Сами по себе запросы времени не делаются никогда; системные часы не меняются.
- Если поправка устарела, программа пробует стук и по системным часам. Если стук друга приходит «не в то время», программа отмечает «у кого-то сбиты часы» (подсказка, по желанию).
- Решение на ваше подтверждение (В1): стук содержит метку, одинаковую для пары в пределах 30 с. Это делает проверку почти бесплатной даже под флудом, но наблюдатель может связать два стука одной пары внутри одного окна. Вариант (б): без такой метки — проверка перебором всех друзей на каждый пакет, нужен лимит проверок, под флудом друзья могут не достучаться. Предлагаю (а).
- Остатки: при смене адреса у собеседника из-за его роутера соединение рвётся и переустанавливается; «стук перед QUIC» сам по себе — признак программы для DPI (как и раньше ALPN).
