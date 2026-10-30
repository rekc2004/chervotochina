# SPEC 13г: приём по IPv6 (двойной сокет)          критичность: КРИТИЧНЫЙ (L1-L3; L4 стенд обычный)

Автор: combine-architect (opus/high), 2026-10-29, редакция 1. Метки: **[П]** проверено мной по исходнику (файл:строка, рабочее дерево `claude/stage-13g-ipv6` от 06ca9b7); **[В]** вывод; **[Д]** память или догадка, опереться нельзя, у каждого есть тест или строка стенда; **[НП]** не проверено. **Ничего не запускалось.** Веба не было: всё про RFC и поведение ОС помечено [Д].

Цель: узел слушает один UDP-сокет `[::]:port` с `IPV6_V6ONLY = 0`, принимает и набирает друзей по IPv4 и IPv6 через тот же стук, QUIC и Noise KK; адрес v4-mapped везде считается IPv4; IPv6 через туннели и трансляторы третьих сторон (Teredo, 6to4, NAT64) не используется ни на приём, ни на набор; входящие через межсетевой экран роутера идут одновременным открытием, как PR-PR в IPv4.

Прочитать: этот файл; `docs/specs/stage-13-connect.md` (таблица охвата стр. 19, факты 7, 13; «Candidates», «Limiter», «Diagnosis»); `docs/specs/stage-09b-knock.md` (порядок проверок); `docs/specs/stage-12-addr.md` реш. 6, 11 и таблица IPv6 стр. 63; `docs/specs/stage-16-nettest.md` D4, D11, стр. 138, 227; `crates/chervo-addr/src/{class.rs,own.rs:464-561,probe.rs,lib.rs:30}`; `crates/chervo-connect/src/{plan.rs,limiter.rs:34-150,diag.rs:103-153,texts.rs,gateway.rs:65-82,lan.rs:46-60,engine.rs:555-580,755-790}`; `crates/chervo-transport-quinn/src/{lib.rs:371-520,596-598,knock.rs:53-61,551-579,753-899,client.rs:56-83,limits.rs:88-103,registry.rs:130-145,254-280,conn.rs:130-145}`, `tests/src_guard.rs:40-120`; `crates/chervo-core/src/node/mod.rs:143-170,436-480`, `tests/layout.rs`; `crates/chervo-lan/src/net.rs:60-115` (образец socket2); `crates/chervo-transfer/examples/node16.rs:480-510`; `tools/netns/lib16.sh`, `tools/netns/stage16.sh`. Больше ничего не искать.

## Охват
| Пункт | Здесь | Примечание |
|---|---|---|
| Двойной сокет узла, запасной путь «только IPv4» | да | L2, L3 |
| Канонический вид адреса (v4-mapped → V4, `flowinfo`/`scope_id` = 0) во всех таблицах и сравнениях | да | L1, L2 |
| Фильтр класса источника IPv6 до таблицы допуска стука | да | L2 |
| Правила набора IPv6 (`family_ok`, `dialable`), ограничитель на /64 | да | L3 |
| Публикация глобального IPv6 (временные, не EUI-64) | да, кода почти нет (реш. 6) | L1 тесты |
| Новый текст `NO_IPV6_TEXT` и условие `NoIpv6` | да | L3 |
| Стенд netns: IPv6 белый, за экраном роутера, смешанный, повтор G1/G2 для IPv6, повтор IPv4-стендов | да | L4 |
| Маяк LAN по `ff02::1`, link-local IPv6 со scope id | **нет** | 13в остаётся IPv4; link-local не набирается и не принимается (реш. 5) |
| Открытие отверстия в экране роутера (UPnP IGDv2 `WANIPv6FirewallControl`, PCP) | **нет** | новый протокол к роутеру; отдельный этап, если стенд/практика покажут нужду |
| Перебор интерфейсов ОС, выбор «стабильный или временный» адрес | **нет** | без `unsafe` нельзя (корень `Cargo.toml`, `unsafe_code = "forbid"`, спец. 13в доп. 1 факт 1 [П по спецификации]) |
| Настройка «выключить IPv6» | **нет** | не просили; запасной путь закрывает ОС без IPv6 |
| Смена `OwnAddrs::set_local` (сброс наблюдений IPv4 при смене только IPv6) | **нет** | поведение уже есть сегодня (маршрут v6 и сейчас входит в снимок, `own.rs:230-241` [П]) |

## Решения (обоснование)
1. **Двойной сокет, а не два сокета.** Один `[::]:port`, `set_only_v6(false)` до `bind`, после `bind` обратное чтение `only_v6() == Ok(false)`. Один сокет = одна таблица допуска стука, один лимитер, один порт для пробросов и маяка, quinn сам отображает V4 в v4-mapped (`quinn-0.11.12/src/endpoint.rs:218-225` [П]), quinn-udp поддерживает двойной сокет на Unix и Windows (`quinn-udp-0.5.16/src/unix.rs:117`, `windows.rs:46-61` [П]). Два сокета потребовали бы двух `Endpoint`, раздвоения реестра соединений и стука [В].
2. **Если ОС не даёт двойной сокет: запасной путь, не стоп.** Владелец: IPv6 редок и не должен блокировать (`OWNER_DECISIONS.md:70` [П]); стоп в продукте значил бы «программа не запускается» на машинах с выключенным IPv6. Правило (единственное):
   - `Socket::new(Domain::IPV6, ..)` ошибка, `set_only_v6(false)` ошибка, ошибка `bind` кроме «порт занят», обратное чтение не `Ok(false)` → сокет закрывается, узел биндится как сегодня на `0.0.0.0:port`, режим `V4Only`;
   - ошибка `bind` вида `AddrInUse` или `PermissionDenied` на двойном сокете → `PortInUse` **без** запасного пути (порт занят хотя бы одной половиной; молча уйти в IPv4, пока чужая программа держит `[::]:port`, нельзя: друзья стучали бы в неё по IPv6);
   - запасной путь не пишет предупреждений: если друг известен только по IPv6, диагноз `NoIpv6` с новым текстом (реш. 9) говорит то же.
   Безопасность запасного пути: это ровно сегодняшнее поведение [В].
3. **`local_addrs()` двойного сокета = `[0.0.0.0:p, [::]:p]`.** Семантика «семейства, которыми пользуется транспорт». Тогда без изменений работают `family_ok`, `publishable` (порты p4/p6 по семейству, `own.rs:476-485` [П]), UPnP (`gateway.rs:65-82` берёт V4-порт [П]) и LAN 13в (`lan.rs:46-60` [П]). Режим определяется в `from_socket` по факту сокета (`local_addr` V4 → `V4Only`; V6 неуказанный и `only_v6() == Ok(false)` → `DualStack`; иначе `V6Only`), поэтому старые тесты с `bind("127.0.0.1:0")` не меняются.
4. **Канонический адрес.** Один канон на всё: `chervo_addr::normalize` (v4-mapped → V4 с тем же портом; любой `SocketAddrV6` → `flowinfo = 0`, `scope_id = 0`). `knock::canon` становится вызовом `normalize`. Причины: quinn-udp отдаёт `sin6_flowinfo` и `sin6_scope_id` как есть (`unix.rs:781-790`, Windows `windows.rs:222` [П]); `SocketAddrV6` сравнивается со всеми четырьмя полями [Д, тест `std_v6_eq_includes_flowinfo`]; quinn-proto сравнивает адрес целиком и во время рукопожатия выбрасывает пакеты с «другого» адреса (`quinn-proto-0.11.19/src/connection/mod.rs:2294-2297`, миграция `:3043` [П]). Поэтому:
   - `KnockSocket` перед передачей quinn переписывает `meta.addr` каждой пропущенной записи: для V6 `flowinfo = 0`, `scope_id = 0`, вид v4-mapped сохраняется (quinn на V6-сокете работает с ним);
   - `QuinnConn::remote_addr()`, `established_addr()`, список живых адресов реестра (`registry.rs:140`) и сравнение в мониторе смены адреса (`registry.rs:268-269`) идут через `normalize`; событие `RemoteAddrChanged` только при смене канонического адреса;
   - таблица допуска, закрепления, кэш, лимитер транспорта (`ip_key`, уже v4-mapped → V4, `limits.rs:95-103` [П]) и ограничитель движка получают только канонические адреса.
   Шли ли бы ненулевые `flowinfo` на практике, не знаю [Д: Linux для UDP, по памяти, обнуляет `sin6_flowinfo`]; канон дешевле, чем выяснять по трём ОС.
5. **Классы IPv6 (одна функция на приём и набор).** В `chervo-addr` добавить `v6_peer_ok(ip) = classify ∈ {Global, Private (ULA), Loopback}`. Всё прочее (link-local, Teredo `2001::/32` и `2001::/23`, 6to4 `2002::/16`, NAT64 `64:ff9b::/96` и `64:ff9b:1::/48`, v4-compatible `::/96`, site-local, `100::/64`, документация, multicast, `::`, всё вне `2000::/3`) не набирается и не принимается. Обоснование: Teredo и 6to4 идут через ретрансляторы третьих сторон (BRIEF разд. 2 п.1-2) [В]; link-local без надёжного scope id неоднозначен, а LAN покрывают ULA, IPv4 и маяк 13в [В]; NAT64 мы сами не синтезируем (DNS нет) [В]. Таблица классов уже такова (`class.rs:70-111` [П]), менять её не нужно.
6. **Публикация.** `publishable` уже кладёт маршрутный глобальный IPv6 без EUI-64 с флагом `short_lived` (`own.rs:466-470, 525-530` [П]); до сих пор не срабатывало, потому что не было V6-порта прослушивания. Реш. 3 включает это без кода. Временный это адрес или стабильный (RFC 7217), выбирает ОС [Д: по RFC 6724 правило 7 ОС с включёнными временными адресами берёт временный]; различить их без API ОС нельзя (спец. 12 реш. 6 [П]), поэтому каждый IPv6 короткоживущий (24 ч у получателя). EUI-64 никогда (T8). Источник маршрута класса не Global (Teredo, 6to4, документация) не публикуется (условие `classify == Global` уже есть [П]).
7. **Набор IPv6 только при собственном выходе в IPv6.** `v6_egress_ok(route_v6) = route_v6` есть и класс `Global` или `Private` (ULA за NAT66). Глобальные IPv6-кандидаты набираются только при `v6_egress_ok`; ULA и `::1` — при одном лишь V6 в `local_addrs`. Иначе машина с одним Teredo слала бы друзьям трафик через ретранслятор Microsoft [В], а машина без маршрута IPv6 тратила бы ограничитель на заведомо неудачные адреса.
8. **Ограничитель движка: ключ жертвы IPv4 /32, IPv6 /64** (`ip_log`, `strict_ip`; как `ip_key` транспорта). Иначе лгущий друг, назвав 8 разных адресов одной чужой /64 в каждом обновлении, обходил бы предел «1 строгий набор в 32 с на жертву» (T1) [В]. Цена: в один набор попадает не больше одного строгого адреса из одной /64, остальные — в следующие наборы через 32 с; у друга обычно один опубликованный IPv6 [В]. Два друга в одной домашней /64 (ULA) делят предел 4 набора за 10 с [В].
9. **Текст и условие `NoIpv6`.** Условие: у друга есть записи, все IPv6, и ни одна не проходит `family_ok` (нет V6 в `local_addrs` или нет `v6_egress_ok` для глобальных). Текст:
   `NO_IPV6_TEXT = "Для друга известны только адреса IPv6, а у вас сейчас нет связи по IPv6: её не даёт провайдер или роутер, либо IPv6 выключен на компьютере. Попросите друга прислать токен обновления адреса с адресом IPv4 или подключитесь к сети с IPv6."`
10. **Входящие за межсетевым экраном роутера.** Нового кода нет: экран с состоянием пропускает ответный трафик на (наш адрес, наш порт) от (адрес, порт) друга, после того как мы сами туда что-то послали [Д: RFC 6092 и поведение conntrack]; движок и так периодически набирает друзей без живого соединения с того же сокета (спец. 13 реш. 6 [П по спецификации]), а в IPv6 нет трансляции порта, так что адрес и порт известны точно. Ограничение: оба набора должны попасть в срок записи экрана (Linux conntrack для UDP без ответа ~30 с [Д], роутеры 30-180 с [Д]); при разошедшихся расписаниях (один в отступе до 10 мин) соединение ждёт совпадения. Это та же картина, что PR-PR в IPv4, стенд меряет (L4 G6-4).
11. **Без новых пакетов.** `socket2 =0.6.5` уже в `Cargo.lock` (одна версия, у `chervo-lan`, `chervo-upnp`, quinn-udp, tokio [П]), нужные `only_v6`/`set_only_v6` (`socket2-0.6.5/src/socket.rs:2065-2089`, блок `impl Socket` с `:1759` без `cfg(feature = "all")` [П]) и `SockRef::from` (`sockref.rs:81-111` [П]) не за возможностью `all`. Новые рёбра: `chervo-transport-quinn → socket2` (`version = "=0.6.5", default-features = false`, как у `chervo-lan`) и `chervo-transport-quinn → chervo-addr` (путь; `chervo-addr` зависит только от `chervo-identity` [П], цикла нет). `unsafe` нет: `SockRef` безопасный API.

## Факты из исходника [П]
1. Узел: `UdpSocket::bind((0.0.0.0, port))` → `QuinnTransport::from_socket` (`chervo-core/src/node/mod.rs:451-457`); `pick_port` проверяет только IPv4 (`:162-170`); `map_bind`: `AddrInUse|AddrNotAvailable|PermissionDenied → PortInUse` (`:143-149`).
2. Транспорт: `from_socket` (`lib.rs:382-454`), `local_addrs = endpoint.local_addr()` (`:596-598`), `rebind` (`:508-519`); кандидаты по `endpoint.local_addr().is_ipv4()` (`client.rs:56-83`).
3. Стук: `canon` только v4-mapped (`knock.rs:53-61`); `pin`/`peek_admission`/`consume_attempt`/`filter_batch` вызывают `canon` (`:552, 565, 574, 766`); `filter_batch` меняет у `meta` только `len` (`:775-788`); при `!required` записи идут в quinn сырыми (`:865-867`); отправка стука на двойном сокете отображает V4 (`family_for`, `:818-826`).
4. Реестр: монитор сравнивает сырой `remote_address()` (`registry.rs:257-273`); `QuinnConn::remote_addr` сырой (`conn.rs:138-140`).
5. `chervo-connect`: `dialable` для IPv6 пропускает Reserved, LinkLocal, Documentation (`plan.rs:45-54`); `family_ok` по `is_ipv4` (`:57-59`); `only_unusable_v6` (`:120-125`) проверяется в `diagnose_locked` до истории набора (`diag.rs:129-131`); ограничитель по `IpAddr` (`limiter.rs:50-53, 93-150`); `path_kind` нормализует (`plan.rs:149`); `engine.rs:772, 785` нормализуют.
6. `addr_flow` нормализует адрес соединения перед ADDR_INFO (`chervo-token/src/addr_flow.rs:244, 250, 269`); токены обновления: только Global|Private (`class.rs:165-168`); приглашение отвергает только неуказанный, multicast, широковещательный, v4-mapped (`chervo-token/src/invite.rs:46-56`) — link-local, Teredo и пр. в приглашение пройдут, но набирать их не будем (реш. 5), формат токена не меняется.
7. `NO_IPV6_TEXT` определён один раз (`chervo-connect/src/texts.rs:11-12`), ядро переэкспортирует (`chervo-core/src/node/texts.rs:14-18`), в GUI свой только `PATH_IPV6` (`chervo-gui/src/texts.rs:102`).
8. Охрана транспорта запрещает `Endpoint::new(`, `.rebind(`, `try_send(` вне `knock.rs` и т.д. (`tests/src_guard.rs:51-119`), про `socket2` правил нет; охрана ядра запрещает только `quinn`, `rustls`, `snow`, `ring`, оболочки и GUI (`chervo-core/tests/layout.rs:11-26`).
9. Стендовый узел биндится на `0.0.0.0` через `QuinnTransport::bind` (`chervo-transfer/examples/node16.rs:496-504`).
10. В отчётах стенда IPv6-литералы запрещены санитайзером, префиксы стенда реальные (спец. 16 D11, стр. 227 [П по спецификации]).

## Сделать (три вызова builder; после каждого дирижёр перезапускает тесты и clippy, CORE 5)

### Вызов 1 (sonnet/high): L1 `chervo-addr`, L2 транспорт
1. `cargo --version`; `BASE=$(git rev-parse HEAD)`. Сверить факты 2-4, 8 и `socket2-0.6.5/src/{socket.rs:2060-2090,sockref.rs:79-111}`; расхождение → СТОП.
2. **L1** `chervo-addr/src/class.rs`: `normalize` по реш. 4 (doc-комментарий обновить; спец. 12 стр. 59 «else unchanged» больше не верно для `flowinfo`/`scope_id`); новые `pub fn v6_peer_ok(ip: &Ipv6Addr) -> bool` (реш. 5) и `pub fn v6_egress_ok(route_v6: Option<Ipv6Addr>) -> bool` (реш. 7); реэкспорт в `lib.rs:30`. Таблицу классов не менять.
3. **L2** транспорт:
   - `Cargo.toml`: `chervo-addr.workspace = true`, `socket2 = { version = "=0.6.5", default-features = false }`.
   - новый `src/bind.rs` — единственный пользователь `socket2` в крейте: `ListenMode`, `BindError`, `bind_listen` (интерфейс ниже), чистая `pub(crate) fn choose(dual: Result<UdpSocket, DualFail>, v4: impl FnOnce() -> io::Result<UdpSocket>) -> Result<(UdpSocket, ListenMode), BindError>` по реш. 2 (для тестов без ОС).
   - `from_socket`/`rebind`: определить и хранить режим (реш. 3); `local_addrs` по режиму; `candidates`: `V4Only` пропускает IPv6, `V6Only` пропускает IPv4, `DualStack` ничего.
   - `knock.rs`: `canon` = `chervo_addr::normalize`; в `filter_batch` первым шагом для каждой записи: если канон V6 и `!v6_peer_ok` → запись выбрасывается без разбора и без поиска в таблице, счётчик `dropped_src_class`; затем как сейчас; у пропущенных записей `meta.addr` переписать по реш. 4. Путь `!required` проходит через ту же функцию фильтра класса и переписывания (без стука). IPv4-источники фильтром класса не трогать.
   - `conn.rs`, `registry.rs`: канон по реш. 4.
   - Тесты L1, L2 (ниже). Критерии для изменённых крейтов; отчёт.

### Вызов 2 (sonnet/high): L3 `chervo-connect`, `chervo-core`, стендовый пример
4. `plan.rs`: `pub(crate) struct Families { v4: bool, v6: bool, v6_egress: bool }`, `pub(crate) fn families(local: &[SocketAddr], route_v6: Option<Ipv6Addr>) -> Families`; `family_ok(addr, &Families)`: V4 → `v4`; V6 → `v6 && v6_peer_ok && (classify != Global || v6_egress)`; `dialable` дополнительно для V6 требует `v6_peer_ok`; `build`, `friend_plan`, `friend_plan_confirmed`, `guest_plan`, `only_unusable_v6` принимают `&Families` (реш. 9); вызывающие в `engine.rs`/`diag.rs` берут `route_v6` из `own.local()`.
5. `limiter.rs`: ключ жертвы (реш. 8) для `ip_log` и `strict_ip`; `entries` остаются по каноническому `SocketAddr`.
6. `texts.rs`: новый `NO_IPV6_TEXT` (реш. 9), дословно.
7. `chervo-core/src/node/mod.rs`: `build_core` и `pick_port` через `chervo_transport_quinn::bind_listen`; `BindError::PortInUse → NodeError::PortInUse`, `Io → NodeError::Io`; `map_bind` остаётся для прочих мест, если они есть.
8. `node16.rs`: флаг `--listen v4|dual`, по умолчанию `dual` (`bind_listen`), `v4` = прежний `bind(0.0.0.0)`; строка `EVENT started` добавляет `listen=dual|v4|v6`.
9. Тесты L3 (ниже). Критерии; отчёт.

### Вызов 3 (sonnet/medium; скрипт стенда обычной критичности): L4 `tools/netns/stage13g.sh`
10. На основе `lib16.sh`/`stage16.sh` (охрана хоста, захват, санитайзер с картой ролей и для IPv6). Строки ниже. На Windows: `bash -n`, shellcheck если есть; запуск на Linux-машине владельца.

## Интерфейс (точно)
```rust
// chervo-addr
pub fn normalize(a: SocketAddr) -> SocketAddr;            // v4-mapped -> V4; V6: flowinfo = 0, scope_id = 0
pub fn v6_peer_ok(ip: &Ipv6Addr) -> bool;                  // classify ∈ {Global, Private, Loopback}
pub fn v6_egress_ok(route_v6: Option<Ipv6Addr>) -> bool;   // Some и classify ∈ {Global, Private}

// chervo-transport-quinn (src/bind.rs, реэкспорт из lib.rs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenMode { V4Only, V6Only, DualStack }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError { PortInUse, Io }
/// `[::]:port`, IPV6_V6ONLY = 0 до bind, обратное чтение; запасной путь `0.0.0.0:port` по реш. 2.
pub fn bind_listen(port: u16) -> Result<(std::net::UdpSocket, ListenMode), BindError>;
pub(crate) enum DualFail { Unavailable, PortInUse }
impl QuinnTransport { pub fn listen_mode(&self) -> ListenMode; }
// Counters: + dropped_src_class
```
`from_socket`, `bind`, `rebind` — сигнатуры прежние. `Debug` новых типов без адресов. Без паник (линт-блок крейта), без журналов.

## Не делать
- Маяк по `ff02::1`, приём/набор link-local, scope id; UPnP IGDv2/PCP для IPv6; перебор интерфейсов; `unsafe`; возможность `socket2` `all`; новые пакеты; настройку «IPv6 вкл/выкл».
- Не менять: `chervo-lan` (ни строки), формат стука, KK, ADDR_INFO, токенов (приглашение, CHA1), файла друзей; валидаторы токенов; таблицу классов; `OwnAddrs::set_local`, `findability`, `stable_reachable`; фильтрацию IPv4-источников.
- Не печатать адреса; `Display` для адресов не добавлять.

## Недоверенный ввод
Всё, что приходит на двойной сокет (любой IPv6-источник, IPv4 как v4-mapped), и адреса-кандидаты из книги, приглашения, обновлений, подсказок, LAN. Порядок на приёме: канон → класс источника (O(1), без разбора) → таблица допуска/стук (как 9б) → quinn. Решение по каждому виду:

| Адрес / вход | Приём (источник) | Набор (цель) | Публикация своего | Примечание |
|---|---|---|---|---|
| `::ffff:a.b.c.d` (v4-mapped) | канон → V4, дальше правила IPv4 (допуск по V4, лимитер /32) | канон → V4 | нет | в токенах отвергается (без изменений); LAN 13в на своих IPv4-сокетах его не видит, разбор маяка отвергает (без изменений) |
| пакет IPv6 с источником `::ffff:x` на проводе | если ОС доставит [Д], равен подделке IPv4-источника: новых возможностей нет [В] | — | — | кода нет |
| `::a.b.c.d` (v4-compatible), `::` | выброс, `dropped_src_class` | нет | нет | |
| `::1` | принимается | да (как 127.0.0.1, L5-13 принято) | нет | нужен тестам и «в одной сети» |
| `fe80::/10` с любым scope id | выброс | нет | нет | реш. 5 |
| ULA `fc00::/7` | принимается | да при V6 в `local_addrs` | только `include_lan`/`path_source` (как сейчас) | частный срок 24 ч (как сейчас) |
| `fec0::/10`, `100::/64`, вне `2000::/3` | выброс | нет | нет | Reserved |
| multicast `ff00::/8` (в т.ч. `ff02::1`) | выброс | нет | нет | |
| NAT64 `64:ff9b::/96`, `64:ff9b:1::/48` | выброс | нет | нет | реш. 5 |
| 6to4 `2002::/16`, Teredo `2001::/32` (и весь `2001::/23`) | выброс | нет | нет | третьи стороны, BRIEF 2 |
| документация `2001:db8::/32`, `3fff::/20` | выброс | нет | нет | стенд проверяет 0 пакетов к `2001:db8::1` |
| глобальный EUI-64 (`ff:fe` в байтах 11-12) | принимается | да (адрес друга) | **никогда** (T8) | свой исходящий источник может быть EUI-64: вопрос В1 |
| прочий глобальный `2000::/3` | принимается | да при `v6_egress_ok` | да, `short_lived` | |
| `flowinfo ≠ 0`, `scope_id ≠ 0` у любого V6 | обнуляются до любой таблицы и до quinn | обнуляются | — | реш. 4 |
| много источников из одной /64 | лимитер транспорта и места до KK по /64 (есть), допуск только по верному стуку | ограничитель движка по /64 (реш. 8) | — | |
| свой маршрут v6: нет, link-local, Teredo, 6to4, документация | — | глобальные IPv6 не набираются | не публикуется | реш. 6, 7 |

## Тесты (точные имена)
Тесты на `::1` начинают с проверки `UdpSocket::bind("[::1]:0")`; при неудаче печатают `SKIP ipv6 <имя>` и завершаются успехом. На Windows-машине дирижёра и в CI `SKIP ipv6` недопустим (критерий).

L1 (`chervo-addr/tests/class.rs`, `tests/own.rs`): `std_v6_eq_includes_flowinfo` (фиксирует факт [Д] реш. 4), `normalize_v6_zeroes_flowinfo_and_scope`, `normalize_v4_mapped_to_v4_keeps_port`, `normalize_idempotent` (10 000 случайных), `v6_peer_ok_table` (каждая строка таблицы выше), `v6_egress_ok_table` (None, Global, ULA, link-local, Teredo `2001:0:4136:e378::1`, 6to4, документация), `publishable_dual_listen_v4_and_v6` (listen `[0.0.0.0:p, [::]:p]`, маршрут v4 глобальный, v6 глобальный не EUI-64 → оба, v6 `short_lived`), `publishable_v6_eui64_never`, `publishable_v6_reserved_route_never` (Teredo, 6to4, NAT64, документация), `publishable_v4_only_listen_no_v6`, `publishable_path_source_ula_on_dual`.

L2 (`chervo-transport-quinn/src/tests/dual.rs`, петля): `bind_listen_dual_on_this_os` (режим `DualStack`, `local_addrs == [0.0.0.0:p, [::]:p]`), `bind_listen_conflicts_with_v4_holder` (держим `0.0.0.0:p` → `PortInUse`), `bind_listen_conflicts_with_v6_holder` (держим `[::]:p` c v6only → `PortInUse`), `choose_unavailable_falls_back_to_v4`, `choose_port_in_use_no_fallback`, `choose_v4_error_mapping`, `listen_mode_detected_v4_v6only_dual` (std `bind("127.0.0.1:0")` → `V4Only`; `bind("[::1]:0")` → `V6Only`; `bind_listen(0)` → `DualStack`), `rebind_recomputes_mode`, `dual_v6_loopback_race_and_knock` (A и B двойные; A звонит на `[::1]:pB`; у B `knock_ok` +1, соединение, обмен), `dual_v4_peer_admitted_as_v4` (A V4Only на 127.0.0.1 звонит B двойному на 127.0.0.1; у B `remote_addr()` = V4 127.0.0.1, допуск по V4), `dual_dials_v4_only_peer`, `dual_mixed_race_one_auth` (адреса `[::1]:pB`, `127.0.0.1:pB` → одно KK, `duplicates_closed` 0), `v6only_endpoint_skips_v4_candidates` (существующий `connect_v6_on_v4_endpoint_skipped` без изменений), `admit_v4_mapped_equals_v4` (допуск открыт с `::ffff:127.0.0.1`, найден по `127.0.0.1` и наоборот), `src_filter_drops_hostile_v6_sources` (синтетические `RecvMeta` с источниками `fe80::1%3`, `2002::1`, `2001:0::1`, `64:ff9b::1`, `::1.2.3.4`, `ff02::1`, `::`, `2001:db8::1`, `fec0::1`; в данных верный стук допущенной пары → 0 пропущено, `dropped_src_class` +9, `knock_ok` 0), `src_filter_keeps_global_ula_loopback_and_all_v4`, `recv_meta_canonicalized_for_quinn` (глобальный V6 c `flowinfo` 7, `scope_id` 3, допущен → `meta.addr` с нулями; v4-mapped остаётся v4-mapped), `remote_addr_canonical`, `monitor_ignores_flowinfo_only_change`, `stranger_v6_silence` (сырой сокет `[::1]` шлёт 1000 случайных датаграмм и QUIC-подобный Initial двойному B: 0 ответов за 2 с, `dropped_unadmitted` растёт), `fuzz_smoke_src_canon` (случайные 16 байт + `flowinfo` + `scope_id` + порт: без паники, канон идемпотентен, решение фильтра совпадает с `v6_peer_ok`); `src_guard` += `socket2` только в `bind.rs`, `set_only_v6(` ровно одно вхождение.

L3 (`chervo-connect/src/tests/{plan,limiter,diag}.rs`, `tests/engine_net.rs`; `chervo-core` тесты узла): `plan_dual_accepts_v4_and_v6`, `plan_v6_global_needs_egress` (route v6 None, link-local, Teredo → глобальные v6 пропущены, ULA и `::1` остаются), `plan_v6_hostile_targets_skipped` (все строки «нет» таблицы), `plan_v4_mapped_target_normalized_and_deduped`, `guest_plan_same_v6_rules`, `limiter_v6_strict_per_64`, `limiter_v6_per_ip_cap_per_64`, `limiter_v4_mapped_same_key_as_v4`, `limiter_v4_unchanged` (существующие `limiter_*` без правок проходят), `diag_no_ipv6_v4_only_transport`, `diag_no_ipv6_no_v6_egress`, `diag_not_no_ipv6_dual_with_egress`, `texts_no_ipv6_new_wording` (равен константе реш. 9, нет подстроки «только по IPv4»), `lan_local_dual_listen` (порт из V4-записи), `gateway_request_dual_listen`, `engine_v6_loopback_friends_connect` (два движка на `bind_listen(0)`, приглашение `Manual([::1]:p)` → `Added`, `Connected` ≤ 15 с), `engine_v4_only_friend_to_dual` (у двойной стороны в книге `Contact` V4, не v4-mapped); ядро: `node_binds_dual_stack`, `node_port_in_use_v4_holder`, `pick_port_dual_free`; `layout`, `features_guard` без правок проходят.

## Критерии приёмки (каждый командой; вывод в отчёт)
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1` (новых пакетов нет); `cargo tree -p chervo-transport-quinn -e normal --depth 1 | grep -E 'socket2 v0\.6\.5|chervo-addr'` — две строки; `cargo tree -i socket2 --workspace -e normal | grep -c '^socket2 v'` = 1
- [ ] `cargo tree -p chervo-connect -e normal | grep -E 'chervo-lan|chervo-upnp|socket2|quinn|rustls'; test $? -eq 1` (критерий 13в держится)
- [ ] `git diff --stat $BASE -- crates/chervo-lan` пусто; `cargo test -p chervo-lan --locked wire_` проходят (`wire_src_class_table`, `wire_v6_src_dropped`)
- [ ] `cargo test -p chervo-transport-quinn --locked dual -- --nocapture 2>&1 | grep -c 'SKIP ipv6'` = 0 на Windows-машине дирижёра (дирижёр перезапускает сам) и в логах CI трёх ОС
- [ ] `CHERVO_FUZZ_ITERS=1000000 cargo test --release --locked -p chervo-transport-quinn fuzz_smoke_src_canon -- --nocapture` (число итераций в выводе)
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-transport-quinn dual_ || exit 1; done`; то же для `-p chervo-connect --test engine_net engine_v6_`
- [ ] `grep -rn 'unsafe' crates/chervo-transport-quinn/src crates/chervo-addr/src; test $? -eq 1`; `cargo deny check`; `bash scripts/check-forbidden.sh --self-test && bash scripts/check-forbidden.sh`
- [ ] `fuzz/Cargo.lock`: `cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null` обновил только списки зависимостей; `git diff $BASE -- fuzz/Cargo.lock | grep -E '^\+(name|version) = '; test $? -eq 1`
- [ ] `bash -n tools/netns/stage13g.sh`; CI зелёный (3 ОС, supply-chain)
- [ ] Linux-машина владельца: `sudo tools/netns/stage13g.sh` все строки PASS; повтор `sudo tools/netns/stage16.sh` и `sudo tools/netns/stage13v.sh` с узлом по умолчанию (`--listen dual`) — вердикты как в последних прогонах (16: `docs/reports/NETTEST-2026-10-18.md` + 16а; 13в: 838894c). Блокирует выпуск, не приёмку кода.

## Стенд L4 (`tools/netns/stage13g.sh`)
Префиксы: глобальные по нашей таблице (не `2001:db8::/32`, не `3fff::/20`, не `2001::/23`, не `2002::/16`), например `2001:db9:13::/48` [В: вне спецблоков таблицы, но это реальный блок → как D11 спец. 16: только в netns, в отчёте роли, санитайзер отвергает IPv6-литералы]. Экран роутера: netns-маршрутизатор, `nft` `ip6` forward: `ct state established,related accept; icmpv6 accept; iifname "wan" ct state new drop`. Захват на хосте A по всем строкам: `udp` наружу ⊆ адреса друзей строки, DNS (53/853, оба семейства) = 0, к `2001:db8::1` и `192.0.2.1` = 0, UDP к `ff00::/8` от узла = 0 (ICMPv6 ND/MLD ядра не считаются).
| Строка | Что | PASS |
|---|---|---|
| G6-1 WHITE6 | A, B только глобальный IPv6, без экрана | `Connected{Ipv6}` ≤ 15 с, передача 64 МиБ, хэш совпал |
| G6-2 FW6 | оба за экраном; дружба через временную связь D4 (ULA), затем связь удалена, адреса глобальные из ADDR_INFO | `Connected{Ipv6}` ≤ 60 с от удаления связи |
| G6-3 FW6-ONE | A за экраном, B открыт | соединение ≤ 30 с |
| G6-4 FW6-LATE | оба за экраном; B перезапущен, когда A уже в отступе | соединение ≤ 12 мин; время в отчёт (информативно) |
| G6-5 MIX-V4 | A двойной (IPv4 за NAT + IPv6), B только IPv4 белый | `Connected` по IPv4; к B ни одного IPv6-пакета |
| G6-6 MIX-V6 | A двойной, B только IPv6 | `Connected{Ipv6}` |
| G6-7 MIX-SYM | оба двойные, IPv4 за симметричным NAT, IPv6 открыт | `Connected{Ipv6}` (IPv6 обходит NAT) |
| G6-8 SIL6 | посторонний с глобальным IPv6: 1000 случайных датаграмм и Initial на порт A (`knockflood` с привязкой к `[::]`, флаг добавить при отсутствии) | 0 ответов, включая ICMPv6 port unreachable |
| G6-9 SRC6 | на A датаграммы и повтор верного стука с источников `fe80::/10` (тот же сегмент), `2002::/16`, `2001:0::/32` | 0 ответов |
| G6-10 TEMP6 | у A новый IPv6, старому `preferred_lft 0`, затем удалён, посреди соединения | соединение живо или переподключение ≤ 15 с; B получил новый IPv6 в ADDR_INFO |
| G6-11 EUI64 | единственный глобальный IPv6 A — EUI-64 | в приглашении и ADDR_INFO от A его нет (книга B: только `Contact` после звонка A); IPv4 работает |
| G6-12 NOV6 | у A `net.ipv6.conf.all.disable_ipv6=1`; у B для A известен только IPv6 | A стартует; у A для B причина `NoIpv6` с новым текстом |
| G6-13 G1-6 | захват по G6-1, G6-2, G6-7 | нарушений захвата 0 (повтор G1 для IPv6) |
| G6-14 G2-6 | соединение только по IPv6-литералу приглашения | DNS 0, соединение есть (закрывает IPv6-часть G2, `DECISION.md:90` [П]) |

## Где проверяется / Не проверено
- Windows-машина и CI: L1-L3 (петля `::1`, `127.0.0.1`, синтетические записи). Linux-машина владельца: L4.
- **Не проверено (писать в отчёте):** реальные домашние роутеры (экран IPv6, сроки записей, роутеры без экрана), реальные IPv6 провайдеров РФ, временные адреса и выбор источника на Windows/macOS/Linux [Д], брандмауэр Windows для двойного сокета [Д], Teredo на Windows, macOS ECN на двойном сокете (quinn-udp отключает `IP_RECVTOS`, `unix.rs:114-123` [П], влияние [НП]), доставка ОС пакетов с v4-mapped источником [Д].

## Стоп-условия
Факт выше не совпал; нужен новый пакет, возможность `socket2` `all` или `unsafe`; `bind_listen_dual_on_this_os` не даёт `DualStack` на Windows-машине дирижёра; `bind_listen_conflicts_with_v4_holder` на какой-либо ОС CI не даёт `PortInUse` (двойной сокет разделил бы IPv4 с чужой программой) — СТОП, решает дирижёр; `::1` недоступен на Windows-машине; охрана (layout, src_guard, deny) запрещает новые рёбра; любой существующий IPv4-тест меняет результат; quinn не отображает V4 на двойном сокете или входящий IPv4 приходит не v4-mapped; понадобилось менять формат стука, KK, ADDR_INFO, токенов, файла друзей или `chervo-lan`; тест нестабилен после двух попыток; критерий непроверяем. Остановиться и доложить, не обходить.

## Лимит
Не более 2 кругов «правка по ревью», затем доклад владельцу.

## Отчёт builder (до 25 строк на вызов)
Изменённые файлы; команды критериев и последние строки вывода; число `SKIP ipv6`; итерации fuzz; что не сделано; отклонения с причиной.

## Исполнители
Вызовы 1-2: `combine-builder` sonnet/high; вызов 3: sonnet/medium. Дирижёр после каждого вызова перезапускает тесты и clippy, на критичном сам `cargo test -p chervo-transport-quinn dual -- --nocapture`. `combine-verifier` sonnet/low: все критерии. `combine-security` opus/high один раз по полному diff: `bind.rs` (запасной путь, «порт занят», обратное чтение), канон и переписывание `meta.addr`, фильтр класса до таблицы допуска, путь `!required`, реестр и `remote_addr`, `family_ok`/`dialable`/`v6_egress_ok`, ключ /64 ограничителя, текст. Критично: L1 `class.rs`, L2 целиком, L3 `plan.rs`, `limiter.rs`, `diag.rs`, `node/mod.rs`. Не критично: текст, пример, скрипт стенда.

## Дельта THREAT_MODEL (дирижёр после приёмки)
- **Новая T21. IPv6: источники, туннели, экран роутера.** Шаг Ш1, Ш2. *Актив:* правило «без третьих сторон» (BRIEF 2), тишина порта, несвязываемость адреса. *Атакующие:* сканер и зонд в интернете (порт виден по IPv6 без NAT); хост с адресом туннеля (Teredo, 6to4) или link-local; лгущий друг, называющий адреса одной чужой /64. *Меры (эт. 13г):* один двойной сокет, все адреса в каноническом виде (v4-mapped как IPv4, без flowinfo и scope id) до таблиц и quinn; источники IPv6 вне глобальных, ULA и `::1` выбрасываются до стука; такие же адреса не набираются; IPv6 набирается только при своём глобальном или ULA-источнике маршрута; ограничитель набора по /64; при недоступном IPv6 узел работает только по IPv4. *Остаётся:* порт на глобальном IPv6 без экрана роутера открыт интернету так же, как на белом IPv4, защищает стук [В]; за экраном роутера входящие только одновременным открытием, при разошедшихся расписаниях ожидание до ~12 мин (стенд G6-4); оператор видит IPv6 и порт так же, как IPv4; постоянный номер порта связывает смену временных адресов для наблюдателя на пути [В]; поведение реальных роутеров и ОС не проверено.
- **T1:** в «Куда мы сами шлём» добавить: «IPv6 (эт. 13г): предел строгого набора и 4 за 10 с считаются на /64; Teredo, 6to4, NAT64, link-local, документация не набираются». Строку статуса дополнить «13г».
- **T8:** «Мера»: «глобальный IPv6 публикуется (эт. 13г), всегда короткоживущий, EUI-64 никогда; временный или стабильный — выбор ОС». «Остаётся»: «приглашения и токены обновления теперь несут IPv6 (их видит мессенджер); стабильный адрес RFC 7217 связывает устройство в пределах одной сети; исходящий источник EUI-64 виден друзьям (решение В1)». Статус: «частично (11, 12, 13г)».
- **T9:** «Остаётся» += «по IPv6 порт достижим без NAT; распределённый поток с одной /48 упирается в стук и ключ /64 лимитера» [В].
- «Что модель угроз НЕ покрывает»: убрать «приём по IPv6».

## Спорное для владельца
**В1. Свой адрес IPv6 вида EUI-64 (выдаёт MAC) как источник исходящих соединений.** Правило T8 «EUI-64 никогда» касается токенов, и оно соблюдается. Но если ОС сама использует такой адрес (бывает на Linux-серверах [Д], возможно и на вашем мини-ПК), то при звонке другу по IPv6 друг и его провайдер видят этот адрес, и друг запоминает его как адрес контакта. (а) Разрешить: этот же адрес ОС и так показывает всем сайтам; в токены он не попадает; IPv6 на такой машине работает частично (друг дозвонится только по запомненному контакту). (б) Не пользоваться IPv6 вовсе, если наш адрес EUI-64: такая машина живёт только по IPv4. **Рекомендую (а).** До ответа builder делает (а); (б) — одна правка в `v6_egress_ok` и один тест.
Других вопросов нет: публикация IPv6 в токенах решена BRIEF разд. 3 и спец. 12 реш. 6; выбор «временный или стабильный» без `unsafe` невозможен; поведение при ОС без IPv6 — запасной путь (реш. 2).

## Для владельца (кратко)
- Программа слушает один порт сразу по IPv4 и IPv6. Друзья соединяются по тому пути, что сработал первым; стук, проверка ключа и всё остальное те же.
- Если на компьютере IPv6 нет или он выключен, программа работает как раньше, только по IPv4. Если друг известен только по IPv6, а у вас его нет, программа так и скажет (новый текст).
- IPv6 через туннели чужих серверов (Teredo, 6to4) и служебные адреса не используются ни на приём, ни на звонок: это были бы третьи стороны.
- В токены и другу уходит только адрес IPv6, который выбрала ОС (обычно временный); адрес, выдающий MAC, никогда. Все адреса IPv6 у друга живут сутки.
- За роутером с защитой IPv6 соединение идёт встречными звонками, как сейчас между двумя домашними сетями IPv4. Если оба давно не на связи, первое соединение может ждать до ~12 минут.
- Проверка: Windows и CI на петле; настоящий IPv6, экран роутера, повтор старых стендов IPv4 — стенд на вашей Linux-машине. Реальные роутеры и провайдеры не проверены.

---

## Дополнение 1 (редакция 2, 2026-10-30): IPv6 на петле машины дирижёра; разделение порта на Windows

Автор: combine-architect (opus/high). Повод: стоп-условия Вызова 1 (коммит e79121b). Метки как выше. Мной ничего не запускалось; Д1-1 и Д1-2 — замеры дирижёра и builder, переданные в задании. **Где Дополнение расходится с текстом выше, действует Дополнение.**

### Факты
- **Д1-1** [замер дирижёра, Python и std, вне песочницы]. На Windows-машине дирижёра UDP `127.0.0.1→127.0.0.1` доставляется, `[::1]→[::1]` нет (send успешен, recv по таймауту) даже у обычного сокета. На машине VPN-клиенты (sing-box TUN, outline-tap), IPv6 на физическом Ethernet выключен. Причина, вероятно, фильтр VPN-клиента [Д]. Настройки VPN владельца не трогаем.
- **Д1-2** [замер builder]. Windows: двойной `[::]:p` (`only_v6=false`) биндится, пока чужой сокет держит `0.0.0.0:p`, и наоборот; двойной и v6only `[::]:p` тоже сосуществуют.
- **Д1-3** [П]. В `socket2-0.6.5/src` нет `SO_EXCLUSIVEADDRUSE` (поиск по всему `src`); есть только `set_reuse_address` (`socket.rs:1120-1134`), он делу не помогает. Свой `setsockopt` требует `unsafe`, значит путь `SO_EXCLUSIVEADDRUSE` закрыт ограничениями «без `unsafe`, без новых пакетов».
- **Д1-4** [НП]. Исходников std (rust-src) локально нет, документации Microsoft о совместном использовании портов локально нет. Неизвестно: (1) кто получает IPv4-датаграмму, когда `0.0.0.0:p` (AF_INET) и двойной `[::]:p` держат разные сокеты; (2) может ли Windows выдать такой порт как эфемерный новому AF_INET-сокету. По памяти [Д]: одноадресная датаграмма идёт одному сокету, правило выбора не помню. Отвечают замеры М1, М2 (Р2).
- **Д1-5** [П]. Порт узла берётся из 49152-65535 (`chervo-core/src/node/mod.rs:151-159`). Это и эфемерный диапазон Windows по умолчанию [Д].
- **Д1-6** [П]. CI: задание `test`, матрица ubuntu/windows/macos, `cargo test --workspace --locked` (`.github/workflows/ci.yml:32-50`). Образец теста, сверяющего `ci.yml`: `chervo-lan/src/tests/svc.rs:767-773`.

### Р1. IPv6 на петле: проверка доставки; на CI пропуск запрещён переменной, а не грепом
1. В `src/tests/dual.rs` вместо `v6_loopback` две функции (только std, без socket2):
   - `v6_bind(name) -> bool`: `UdpSocket::bind("[::1]:0")`; неудача → печать `SKIP ipv6-bind <name>`, `false`.
   - `v6_delivery(name) -> bool`: сначала как `v6_bind`; затем два сокета на `[::1]:0`, у приёмника `set_read_timeout(500 мс)`, до 3 попыток `send_to` 16 байт с маркером; успех = принято то же содержимое с адреса отправителя. Иначе печать `SKIP ipv6-delivery <name>`, `false`.
   - Обе: если `std::env::var("CHERVO_REQUIRE_IPV6") == Ok("1")`, вместо печати SKIP `panic!` с текстом `IPv6 на петле обязателен: bind` или `...: delivery`. Строка `SKIP ipv6 <имя>` из старого текста больше не используется.
2. Кто что вызывает:
   - `v6_bind`: `listen_mode_detected_v4_v6only_dual`, `v6only_endpoint_skips_v4_candidates` (им нужен только bind).
   - `v6_delivery`: `dual_v6_loopback_race_and_knock`, `dual_mixed_race_one_auth` (без доставки по `::1` он проходит по IPv4 и ничего не доказывает про гонку двух живых путей), `stranger_v6_silence`, IPv6-часть `share_later_binder_report` (Р2). Вызов 2: `engine_v6_loopback_friends_connect` и любой тест движка или ядра, который звонит на `::1`: та же функция, копией в тестовом модуле своего крейта (общий тестовый крейт не заводить).
   - Остальные тесты (синтетические `RecvMeta`, IPv4 на двойном гнезде) без проверки.
3. CI отличается от машины дирижёра явной переменной: в `ci.yml`, задание `test`, на уровне задания `env:` с `CHERVO_REQUIRE_IPV6: "1"` (все 3 ОС). Признаки среды (`CI`, `GITHUB_ACTIONS`) в коде не читать. На CI пропуск невозможен: тест падает.
4. Охрана от тихого удаления переменной: тест `ci_requires_ipv6` в `crates/chervo-transport-quinn/tests/src_guard.rs` читает `CARGO_MANIFEST_DIR/../../.github/workflows/ci.yml` (как Д1-6) и проверяет, что между строкой `  test:` и следующим заданием верхнего уровня есть `CHERVO_REQUIRE_IPV6: "1"` и шаг `share_` (Р2).
5. Не проверено на машине дирижёра (так и писать в отчёте): доставка IPv6 по петле и всё, что на ней стоит. Это проверяет только CI (Windows, Linux, macOS).

### Р2. Чужой держатель половины порта: пробные захваты до двойного bind
`dual(port)` в `bind.rs` (сейчас `:54-68`) заменить алгоритмом ниже. Интерфейс (`bind_listen`, `choose`, `BindError`, `DualFail`, `mode_of`) не меняется. Создание и bind двойного сокета вынести в одну функцию (её вызывают шаг 3 и повторный bind).
1. `g4 = UdpSocket::bind((0.0.0.0, port))` (std). Ошибка `AddrInUse|PermissionDenied|AddrNotAvailable` → `DualFail::PortInUse`, иная → `Unavailable`. `p = g4.local_addr()?.port()` (при `port = 0` это и есть выбор порта; ошибка `local_addr` → `Unavailable`).
2. `g6`: socket2 `Domain::IPV6`, `set_only_v6(true)`, `bind([::]:p)`. Ошибка `Socket::new` или `set_only_v6` → `Unavailable` (IPv6 нет). Ошибка `bind`: `AddrInUse|PermissionDenied` → `PortInUse`, иная → `Unavailable`.
3. `d`: socket2 `Domain::IPV6`, `set_only_v6(false)`, `bind([::]:p)`, **пока `g4` и `g6` открыты**:
   - `Ok`: ОС не закрепляет половины за двойным гнездом (Windows, Д1-2). Закрыть `g4`, `g6`; к шагу 4.
   - `AddrInUse|PermissionDenied`: ОС закрепляет половины (ожидается Linux, macOS [Д]), конфликт с нашими же пробами. Закрыть `d`, `g4`, `g6`; сразу новый двойной сокет той же функцией. Его `AddrInUse|PermissionDenied` → `PortInUse`, иная ошибка → `Unavailable`.
   - иная ошибка → `Unavailable`.
4. Обратное чтение `only_v6() == Ok(false)`, иначе `Unavailable` (как было).
- `port = 0`: при `DualFail::PortInUse` на любом шаге всё заново с шага 1, всего не больше 8 попыток, затем `PortInUse`. При `port ≠ 0` повторов нет.
- При `Unavailable` все пробы уже закрыты; `v4()` в `choose` биндит заново (при `port = 0` порт будет другим, это допустимо).
- Пробы ничего не читают и не пишут, живут только внутри `dual`. Никаких `SO_REUSEADDR`, никаких `cfg(windows)` в `bind.rs`: ветка выбирается по ответу ОС на шаге 3 [В].

Гонки и остаток:
- **Linux/macOS.** Между закрытием проб и вторым `bind` (микросекунды) чужая программа может занять половину. Тогда `bind` двойного гнезда падает → `PortInUse`, тихого разделения нет. После `bind` двойное гнездо держит обе половины само [Д; утверждается в М1 на Linux].
- **Windows, момент запуска.** Во время `bind` двойного гнезда обе половины держим мы, значит чужого держателя в этот момент нет. Чужой сокет с `SO_REUSEADDR` тоже виден: наша проба без этого флага получит `AddrInUse` [Д: по памяти о семантике Windows; `bind_listen_conflicts_*` проверяют держателя без флага, с флагом не проверяется].
- **Windows, после запуска (остаток).** После закрытия проб другая программа на этом компьютере может занять `0.0.0.0:p` или v6only `[::]:p`: явно, или случайно, если Windows выдаёт такой порт как эфемерный (Д1-4, Д1-5). Что тогда с нашими входящими, покажет М1. Без `SO_EXCLUSIVEADDRUSE` остаток не убрать [В]. Держать `g4` всё время жизни нельзя: если Windows отдаёт IPv4 сокету AF_INET, узел оглохнет по IPv4 [В]. Последствие для нас: отказ приёма по IPv4 до перезапуска, а не раскрытие: трафик зашифрован, стук привязан к паре, подменить узел чужая программа не может [В]. Сегодняшний IPv4-узел на Windows тоже можно перехватить программой того же пользователя с `SO_REUSEADDR` [Д]. Новое только в возможной случайной коллизии (М2).

Замеры (информативные; код от их итога не ветвится):
- **М1** `share_later_binder_report` (`dual.rs`): `bind_listen(0)` → `DualStack`, порт p.
  - (а) `UdpSocket::bind(0.0.0.0:p)`. На Linux (`cfg!(target_os = "linux")`) утверждать `AddrInUse`. На прочих печатать `INFO share later_v4_bind=refused|accepted`. Если `accepted`: 5 датаграмм с `127.0.0.1:0` на `127.0.0.1:p`, приём на обоих сокетах с таймаутом 500 мс, печать `INFO share later_v4_rx dual=<n> other=<n>`.
  - (б) то же для v6only `[::]:p` (socket2 в тесте) с `[::1]`, только при `v6_delivery`: `INFO share later_v6_bind=...`, `INFO share later_v6_rx dual=<n> other=<n>`. На Linux тоже утверждать `AddrInUse`.
  - Тест падает только на утверждениях Linux и паниках подготовки. Адресов не печатать.
- **М2** `share_ephemeral_v4_scan` (`#[ignore]`): двойное гнездо на p; открывать `UdpSocket::bind("0.0.0.0:0")` подряд, не закрывая, до 20 000 штук или первой ошибки; печать `INFO share ephemeral scanned=<n> hit=<true|false> stop=<limit|ErrorKind>` (`hit` = какой-то сокет получил p).
- **CI:** в задании `test` после `cargo test --workspace --locked` шаг `cargo test -p chervo-transport-quinn --locked share_ -- --nocapture --include-ignored` (3 ОС). Дирижёр запускает ту же команду на Windows-машине. Все строки `INFO share` из четырёх мест идут в отчёт.

Тесты Р2 (`dual.rs`):
- `bind_listen_conflicts_with_v4_holder`, `bind_listen_conflicts_with_v6_holder`: без изменений, должны пройти на всех ОС.
- `bind_listen_twice_port_in_use`: `bind_listen(0)` → p; пока он открыт, `bind_listen(p)` → `PortInUse` (на Windows проходит ветку «конфликт при пробах» до конца).
- `bind_listen_releases_probes`: `bind_listen(p)` → `DualStack`, закрыть; затем `UdpSocket::bind(0.0.0.0:p)` и v6only `[::]:p` оба успешны (пробы не утекли).
- `dual_v4_peer_admitted_as_v4`, `remote_addr_canonical`, `dual_dials_v4_only_peer` (через `bind_dual`) подтверждают на каждой ОС, что после закрытия проб двойное гнездо получает IPv4.
- Предел в 8 попыток при `port = 0` модульным тестом не проверяется: только чтением кода (`combine-security`).
- `src_guard` (заменяет «`set_only_v6(` ровно одно вхождение»): в `src/` ровно один `set_only_v6(false)` и ровно один `set_only_v6(true)`, оба в `bind.rs`; других `set_only_v6(` в `src/` нет.

### Изменения критериев (заменяют строку про `SKIP ipv6` выше)
- [ ] Машина дирижёра: `cargo test -p chervo-transport-quinn --locked dual -- --nocapture 2>&1 | grep 'SKIP ipv6-'`: нет ни одной `SKIP ipv6-bind`; `SKIP ipv6-delivery` только у `dual_v6_loopback_race_and_knock`, `dual_mixed_race_one_auth`, `stranger_v6_silence`, `share_later_binder_report` (фильтр `dual` ловит весь модуль `tests::dual`).
- [ ] Машина дирижёра: `CHERVO_REQUIRE_IPV6=1 cargo test -p chervo-transport-quinn --locked dual_v6_loopback_race_and_knock` падает с текстом `delivery` (доказывает, что пропуск из-за среды, а не прячет другой сбой).
- [ ] CI: задание `test` зелёное на 3 ОС с `CHERVO_REQUIRE_IPV6=1`; шаг `share_` прошёл на 3 ОС; `ci_requires_ipv6` проходит.
- [ ] Отчёт: строки `INFO share` с Windows-машины дирижёра и трёх ОС CI.
- Критерий «10 прогонов `dual_`»: на машине дирижёра допустим тот же набор `SKIP ipv6-delivery`.

### Изменения стоп-условий
- Убрать «`::1` недоступен на Windows-машине».
- Добавить СТОП: `SKIP ipv6-bind` на машине дирижёра; любой тест падает из-за `CHERVO_REQUIRE_IPV6` на CI (переменную не снимать, SKIP не вводить); на Linux поздний `bind` `0.0.0.0:p` или v6only `[::]:p` успешен; `bind_listen_conflicts_*` или `bind_listen_twice_port_in_use` красные на любой ОС; после закрытия проб двойное гнездо не получает IPv4 (красные `dual_v4_*`, `remote_addr_canonical`).
- Не СТОП: итоги М1, М2 на Windows и macOS. Дирижёр передаёт их владельцу (В2) и в THREAT_MODEL.

### Не делать (дополнительно)
Держать пробы после возврата из `dual`; `SO_REUSEADDR` на любом сокете; `cfg(windows)` или чтение переменных среды в `bind.rs`; печать адресов в строках `INFO`.

### Дельта THREAT_MODEL (дополнение к T21 «Остаётся»)
«Windows (и macOS, если М1 покажет то же): ОС не закрепляет за двойным гнездом IPv4-половину порта. При запуске занятость проверяется пробами. После запуска программа на том же компьютере может занять тот же порт IPv4 (явно или, по М2, случайно) и, по М1, перехватить входящие IPv4 до перезапуска: отказ в обслуживании, не раскрытие. `SO_EXCLUSIVEADDRUSE` без `unsafe` недоступен.»

`combine-security` дополнительно смотрит в `bind.rs`: порядок проб, закрытие всех проб на каждом пути выхода, отображение ошибок, предел повторов, отсутствие запасного пути при `PortInUse`.

### Спорное для владельца
**В2. Windows: порт IPv4 не закреплён за программой после запуска.** На Windows система не закрепляет за нашим двойным (IPv4+IPv6) сокетом IPv4-часть номера порта. При запуске мы проверяем, что порт свободен, и отказываемся работать на занятом. Но после запуска другая программа на этом же компьютере может занять тот же номер для IPv4: намеренно или, если Windows так раздаёт порты автоматически (замер М2), случайно. Тогда, в зависимости от замера М1, входящие по IPv4 могут уходить ей: друзья не дозвонятся по IPv4 до перезапуска. Содержимое зашифровано, выдать себя за вас она не может.
- (а) Принять: IPv6 на Windows работает.
- (б) На такой ОС слушать только IPv4: на Windows IPv6 пока не будет.
**Рекомендую (а)**, если М1 показал `other=0` или М2 показал `hit=false`. **Рекомендую (б)**, если одновременно `other>0` и `hit=true`: случайные отказы IPv4 хуже, чем отсутствие редкого IPv6. До ответа builder делает (а). Переход на (б) — одна ветка на шаге 3 Р2 (`Ok` при пробах → закрыть `d`, вернуть `Unavailable`) и один тест.

### Для владельца (кратко, Дополнение 1)
- На вашем Windows-компьютере IPv6 внутри самого компьютера не проходит, вероятно из-за VPN-клиента. Настройки VPN не трогаем: тесты IPv6 на нём честно пишут «пропущено», а обязательно и без пропусков они идут на CI (Windows, Linux, macOS). Пропуск на CI невозможен: там тест падает.
- Windows не закрепляет за программой IPv4-часть порта так строго, как Linux. При запуске программа теперь проверяет обе части и не стартует на занятом порте. Что бывает, если порт займут позже, покажут два замера; по их итогу ваш выбор В2.

## Дополнение 2 (дирижёр, 2026-10-30): правки по ревью security 13г, круг 1
Главнее основного текста и Дополнения 1 там, где расходится.
1. **M (ULA через Teredo).** IPv6-кандидат, кроме `::1`, набирается, только если источник маршрута ОС именно к этому адресу (`chervo_addr::probe::route_source_for`, пакетов не шлёт) класса Global или ULA (та же проверка, что `v6_egress_ok(Some(src))`). `None`, link-local, Teredo, 6to4 и прочий Reserved дают «не набирать». Для глобальных целей прежнее условие `v6_egress` остаётся. Проверка делается при построении плана (`build`) через функцию маршрута в `Families` (по умолчанию `route_source_for`; тесты подставляют оракул). Диагноз (`only_unusable_v6`) использует ту же функцию. Тесты: `plan_ula_via_teredo_source_dropped`, `plan_ula_via_ula_source_kept`, `plan_ula_no_route_dropped`, `plan_loopback_v6_no_route_check`.
2. **L (NoIpv6).** `NoIpv6` выдаётся, только если хотя бы одна IPv6-запись проходит `v6_peer_ok`; если все IPv6-записи враждебного класса, диагноз прежний для «нет пригодных адресов» (как до 13г для таких записей). Тест `diag_hostile_v6_only_not_no_ipv6` (книга из `fe80::` и Teredo при `v6_egress = true`).
3. **Info (защита в глубину).** `chervo-transport-quinn` `client.rs` `candidates`: IPv6 с `!v6_peer_ok` выбрасывается. Тест `candidates_drop_hostile_v6`.
4. **Info (стенд).** В шапке `tools/netns/stage13g.sh` пометка: рабочий каталог лежит под домашним каталогом пользователя sudo, и процесс этого пользователя может подменить `$STATE/bin`; это не шире `bin_import`.
5. **Info (T21).** Дирижёр при закрытии дописывает в T21: ULA туннеля VPN считается своим выходом в IPv6, и глобальные IPv6 тогда идут через VPN владельца, как и IPv4.

---

## Дополнение 3 (combine-architect, 2026-10-30): удержание записи экрана IPv6 («дыра») для друзей не на связи

Автор: combine-architect (opus/high). Повод: G6-4 (запись пакетов стенда, переданная дирижёром) и решение владельца `OWNER_DECISIONS.md:192`. Третий круг правок разрешён этим решением. Метки как выше. Мной ничего не запускалось. **Где расходится с текстом выше, действует это Дополнение.** Исполнитель: один вызов `combine-builder` sonnet/high (ниже «Порядок»).

### Факты
- **Д3-1** [стенд, передано дирижёром]. Оба за `ct state new` drop, UDP без ответа живёт ~30 с. A набирает B с шагом 32 с, затем 600 с; B после перезапуска — каждые 32 с 120 с, затем отступ. Ближайшие встречные наборы расходятся на 53 и ~70 с, разность фаз не сходится: за 750 с соединения нет, и не будет.
- **Д3-2** [П]. Расписание без разброса: `config.rs:60-64` (120/5/30/600/30), `limiter.rs:71-75` (`backoff`), `:247-269` (`failed`), строгий пол `dial_base + 2 с` на /64 (`:80, 109-116`).
- **Д3-3** [П]. Стук уходит с гнезда прослушивания через `KnockState::send` (`knock.rs:603-626`); `Transmit` несёт только `destination, ecn, contents, segment_size, src_ip` (`:607-613`): предела хопов на пакет нет. Единственное `try_send(` крейта в `knock.rs` (`knock.rs:5`, `src_guard`).
- **Д3-4** [П]. Приёмник: `filter_batch` (`knock.rs:760-841`): класс источника → `classify` таблицы допуска (`:794-800`), который у открытой или закреплённой записи увеличивает `rx` (`:346-348`); `rx` читает `Pin::heard` (`:446-448`). При `Gate::Open|Pass` датаграмма не длины `KNOCK_LEN` (48, `chervo-identity/src/knock.rs:19`) уходит в quinn (`:805-815`); при `Gate::Closed` — выброс, `dropped_unadmitted` (`:816-829`).
- **Д3-5** [П]. quinn-proto 0.11.19 `endpoint.rs`: неразобранный заголовок — выброс без ответа (`:212-215`); согласование версии только для датаграмм ≥ `MIN_INITIAL_SIZE` (`:184-187`); stateless reset только если длина − 16 > 5 (`:296-304`), то есть датаграмма ≤ 21 байта никогда не вызывает ответа quinn.
- **Д3-6** [П]. quinn-udp 0.5.16 `unix.rs:390-395` (путь `apple_fast`): `segment_size = contents.len()`, затем `chunks(segment_size)`; при пустом `contents` это `chunks(0)`, паника [В: по поведению std, не сверял]. Пустая датаграмма поэтому не годится.
- **Д3-7** [П]. Реализации `ManagedTransport`: `chervo-transport-quinn/src/lib.rs:600`, `chervo-connect/src/tests/kit.rs:697`, `chervo-transfer/src/tests/kit.rs:521`.
- **Д3-8** [П]. Порт узла хранится в настройках (`chervo-core/src/node/mod.rs:229-241`): после перезапуска он прежний, и запись экрана (наш адрес, порт → адрес, порт друга) остаётся годной.
- **Д3-9** [П]. Пробы маршрута уже собирают IPv6-цели всех действующих друзей без соединения и без идущего набора (`routes.rs:93-148`), `tick` берёт `RouteMap` до планировщика (`engine.rs:913-916`); `on_closed` (`engine.rs:653-670`) знает момент конца живого соединения. Запись `KnownAddr` IPv6 живёт 24 ч от `last_seen_unix` (`book.rs:10, 145-153`).

### Р3-1. Что слать: одна датаграмма из одного нулевого байта, не стук
`HOLE_DATAGRAM: [u8; 1] = [0x00]`, с того же гнезда (тот же порт), через `KnockState`. Почему не стук:
- Верный стук на старый адрес друга — свежий одноразовый пропуск пары: держатель адреса или наблюдатель на пути может повторить его с другого адреса на настоящий адрес друга и открыть себе допуск (до TLS и KK он не пройдёт, но тишина порта друга для него нарушена) [В]. При удержании раз в 10 с таких пропусков стало бы в 60 раз больше, чем при наборе на потолке 600 с.
- Стук несёт идентификатор пары в окне: два адреса друга, получившие стук в одном окне, связываются наблюдателем [В]. Нулевой байт не несёт ничего, кроме того, что и так видно из заголовков: наш адрес и порт.
- Стук тратит кэш повторов получателя (`REPLAY_PER_WINDOW`) и открывает запись допуска; нулевой байт — ничего (Р3-5).
Отвергнуто: пустая датаграмма (Д3-6); малый предел хопов, чтобы пакет умирал за своим роутером (нет поля в `Transmit`, Д3-3; общий `IPV6_UNICAST_HOPS` на гнезде гонялся бы с quinn; число хопов до роутера неизвестно); случайный байт (без генератора в крейте; признак «1 байт раз в 10 с» остаётся всё равно).

### Р3-2. Кому
Только друзья: запись в книге, `is_active`, нет в `key_problems`, нет живого соединения (`st.live`), нет идущего набора (`st.inflight`: набор сам шлёт стук). Гости нет (сессия 300 с, адреса — слова неизвестного приглашающего). Адрес друга годен, если всё сразу:
1. из `usable_known` (не истёк), `normalize`, IPv6, `!hint`, источник `AddressUpdate` или `Contact` (не `Invite`: только подписанное другом обновление или проверенное соединение);
2. `classify == Global` (ULA нет: ULA — своя площадка или VPN, экрана с состоянием между ними обычно нет [Д]; меньше трафика);
3. `family_ok(addr, &fam)` с `Families` этого такта, то есть с `RouteMap` (источник маршрута Global или ULA, `v6_egress`, Дополнение 2 п.1); цели нет в карте → в этот круг не шлём;
4. возраст (Р3-3) меньше `hole_max_age`.
Порядок друзей: самый свежий `basis` первым, при равенстве порядок книги. Порядок адресов друга — порядок `usable_known`.
**Пределы:** `HOLE_MAX_FRIENDS = 16`, `HOLE_ADDRS_PER_FRIEND = 2`, `HOLE_PER_64 = 4` (ключ `victim_key`, по всем друзьям: два-три ПК друзей в одной домашней /64), всего ≤ 32. Транспорт дополнительно режет до `HOLE_MAX_TARGETS = 32` (Р3-4).
**Ограничитель набора:** не через него. Удержание не набор: на него не отвечает ни узел (Р3-5), ни quinn (Д3-5). Через `take` дыры съедали бы окно 4 за 10 с и строгий пол на /64 и сдвигали бы настоящие наборы. Свой бюджет: пределы выше и частота Р3-3. Худший случай для жертвы, которую назвал лгущий друг: ≤ 4 адреса её /64 × 1 датаграмма в 10 с, 49 байт на проводе (40 IPv6 + 8 UDP + 1), до суток [В]; это меньше одного строгого набора (стук и Initial 1200 байт каждые 32 с, T1).

### Р3-3. Частота, сроки, остановка, бюджет
- `ConnectConfig::hole_period = 10 с` (новое поле). Запись UDP без ответа у Linux 30 с, роутеры 30-180 с [Д]; каждое исходящее продлевает запись [Д: conntrack]. 10 с дают три датаграммы на срок 30 с, одна потеря не закрывает дыру. `hole_period == 0` — удержание выключено (тесты, стенд). Круг один на все цели: `State.hole_next_at: Option<Instant>`; в `tick`, если `None` или наступил, цели считаются под замком, `hole_next_at = now + hole_period`, после снятия замка `transport.hold_open(targets)` (если не пусто). Разброса не нужно: получатель не отвечает.
- `ConnectConfig::hole_max_age = 24 ч` (новое поле; **до ответа владельца на В3**). Возраст адреса: `now_unix − basis`, где `basis = max(k.last_seen_unix, end_unix)`, а `end_unix` берётся, только если адрес есть в `FriendRt.hole_end` (ниже). Адрес годен, если `basis <= now_unix + 60` (`last_seen` из будущего — часы назад — не продлевает дыру: не шлём) и `now_unix < basis.saturating_add(max_age)`. Вся арифметика насыщающая.
- `FriendRt.hole_end: Option<(u64, Vec<SocketAddr>)>` (только память): в `on_closed`, когда живое соединение друга (не гостя) действительно снято, записать `(clock.now_unix(), адреса)`: нормализованный адрес закрытого соединения первым, если он IPv6 Global, затем годные по Р3-2 п.1-2 адреса книги, всего ≤ 4, без повторов. Смысл: «на этих адресах друг был в последний раз, когда мы его видели». После перезапуска нашего узла записи нет, действует `last_seen_unix` книги.
- Остановка: друг на связи или идёт набор → его нет в круге; удалён, заблокирован, проблема ключа → нет; адрес истёк в книге или по `hole_max_age` → нет; свой маршрут IPv6 пропал или сменился (кэш маршрутов сбрасывается, Дополнение 2) → `family_ok` решает заново каждый круг; транспорт `V4Only` → ничего; `shutdown` → такта нет, гнездо закрыто, `try_send` даёт ошибку, она глотается.
- Бюджет (проверяется чтением кода, `combine-security`): ≤ 32 датаграммы в 10 с = 3,2 пакета/с, ≤ 157 байт/с на проводе; обычный случай (один друг, один адрес) 0,1 пакета/с, ~420 КБ в сутки.

### Р3-4. Транспорт
```rust
// chervo-transport, trait ManagedTransport (метод обязательный, без реализации по умолчанию)
/// Удержание записи экрана роутера: по одной датаграмме удержания на каждый адрес, с гнезда
/// прослушивания. Ответа не ждёт, состояния у получателя не создаёт. Вызывать без замков.
fn hold_open(&self, dests: Vec<SocketAddr>);

// chervo-transport-quinn
pub(crate) const HOLE_DATAGRAM: [u8; 1] = [0x00];   // только в knock.rs
pub const HOLE_MAX_TARGETS: usize = 32;
pub(crate) fn hole_dests(dests: Vec<SocketAddr>) -> Vec<SocketAddr>; // normalize; V6 и classify == Global; без повторов; ≤ 32
impl KnockState { pub(crate) async fn send_hole(&self, dest: SocketAddr); } // общий закрытый send_bytes с send(); try_send( остаётся одно
// Counters: + holes_sent, hole_skipped, dropped_hole
```
`QuinnTransport::hold_open`: режим `V4Only` → возврат; `hole_dests`; пусто → возврат; если задача прошлого круга ещё идёт (`AtomicBool` в `Inner`) → `hole_skipped` +1, возврат (задачи не копятся); иначе одна задача на `inner.rt`: по каждому адресу `send_hole`, `holes_sent` +1 на отправку; флаг снимается в конце задачи. Без журналов, без адресов в `Debug`. Реализации в `kit.rs` обоих крейтов: `chervo-connect` записывает вызовы (для тестов), `chervo-transfer` — пустая.

### Р3-5. Получатель (экран открыт или запись есть)
В `filter_batch` сразу после фильтра класса источника и переписывания `meta.addr`, **до** проверки `required` и до `classify` таблицы допуска: запись с `m.len == HOLE_DATAGRAM.len()` (целая датаграмма из одного байта, любое содержимое) выбрасывается, `dropped_hole` +1. Следствия: ответа нет (ни узла, ни quinn, ни ICMP от нас — гнездо открыто); записи допуска, кэша повторов, лимитера транспорта не создаются; `rx` не растёт, `Pin::heard` у набирающего нас друга не меняется. Корректных пакетов QUIC и стуков длиной 1 байт не бывает (стук 48; пакету QUIC нужны заголовок, номер, образец защиты заголовка и тег 16) [В]. Узел без живого слушателя на хосте без экрана ответит ICMPv6 «порт недоступен» силами ОС: так же, как сегодня на набор по мёртвому адресу [В].

### Р3-6. Что видит посторонний
- Держатель устаревшего адреса друга (префикс провайдера ушёл другому абоненту) до `hole_max_age`: датаграммы в 1 нулевой байт с нашего адреса и порта раз в 10 с. Наш адрес и порт он видел бы и по обычным наборам; нового — только частота и признак «1 байт раз в 10 с». Ни идентификатора пары, ни пригодного к повтору пропуска. Его входящие к нам упираются в стук (тишина порта нашего узла не меняется). Наш экран пропускает к нашему порту только пакеты с (адрес, порт) друга — и, у роутеров с фильтрацией, независимой от адреса, от кого угодно на наш порт [Д]; в обоих случаях дальше — стук.
- Наблюдатель на пути: видит поток к адресу друга, пока тот не на связи (как и наборы на потолке, но чаще); 1-байтовая датаграмма — отличительный признак для DPI [В].

### Р3-7. IPv4
Не в этом этапе. Строгий NAT IPv4 и PR-PR остаются этапом 13б (решение владельца там же, где G6-4). Там же решать, нужно ли удерживать отображения NAT тем же механизмом. `hole_dests` пропускает только глобальный IPv6.

### Интерфейс chervo-connect (новый `src/hole.rs`)
```rust
pub(crate) const HOLE_MAX_FRIENDS: usize = 16;
pub(crate) const HOLE_ADDRS_PER_FRIEND: usize = 2;
pub(crate) const HOLE_PER_64: usize = 4;
pub(crate) const HOLE_END_ADDRS: usize = 4;
pub(crate) struct HoleCand<'a> { pub(crate) known: &'a [KnownAddr], pub(crate) end: Option<(u64, &'a [SocketAddr])> }
/// Чистая функция Р3-2, Р3-3: порядок, пределы, возраст, family_ok по `fam`.
pub(crate) fn hole_targets(cands: &[HoleCand<'_>], fam: &Families<'_>, now_unix: u64, max_age_secs: u64) -> Vec<SocketAddr>;
pub(crate) fn hole_end_addrs(closed: SocketAddr, known: &[KnownAddr]) -> Vec<SocketAddr>; // для on_closed
```
`ConnectConfig`: `hole_period`, `hole_max_age` (с doc-комментариями). `node16.rs`: флаги `--hole-period <с>` и `--hole-max-age <с>` (по умолчанию значения `Default`); строка `EVENT started` добавляет `hole=<period>/<max_age>`.

### Не делать
Стук, KK, ADDR_INFO, токены, файл друзей, `chervo-lan`, `chervo-identity`, `chervo-token`, `chervo-friends` — без изменений. Не трогать `Limiter` и расписание наборов (разброс не вводить). Не менять `IPV6_UNICAST_HOPS` и другие опции гнезда. Не слать на IPv4, ULA, `::1`, гостям. Новых пакетов и `unsafe` нет.

### Тесты (точные имена)
L2 `chervo-transport-quinn/src/tests/hole.rs`: `send_hole_wire_bytes` (транспорт на `127.0.0.1`, сырой приёмник получает ровно `[0x00]` с порта транспорта; `send_hole` без фильтра класса), `hole_dests_filter_table` (глобальный V6 — да; ULA, `::1`, `fe80::1`, Teredo, 6to4, документация, V4, v4-mapped — нет; повторы схлопнуты; 40 глобальных → 32), `hold_open_v4only_noop` (`holes_sent` 0), `hold_open_coalesces` (current_thread: два вызова подряд без уступки → `hole_skipped` +1), `hole_receiver_drops_before_admission` (синтетические `RecvMeta` по образцу `src_filter_*`: 1 байт с закреплённого и с недопущенного адреса → пропущено 0, `dropped_hole` +2, `dropped_unadmitted` без изменений, `Pin::heard() == false`, размер таблицы допуска прежний), `hole_receiver_not_required_path` (`required = false`: тоже выброс), `hole_receiver_silent_loopback` (сырой сокет шлёт 100 × `[0x00]` на транспорт `127.0.0.1`: 0 ответов за 2 с, `dropped_hole` > 0, `knock_ok` 0), `hole_two_bytes_not_hole` (датаграмма из 2 байт с закреплённого адреса идёт прежним путём). `src_guard`: `HOLE_DATAGRAM` встречается только в `knock.rs`; `try_send(` — как было.
L3 `chervo-connect/src/tests/hole.rs` (часы на паузе, оракул маршрутов): `hole_targets_global_v6_only`, `hole_targets_need_route_and_egress` (нет в `RouteMap`, источник Teredo, `v6_egress = false` → нет), `hole_targets_age_limit` (граница `max_age` ±1 с; `last_seen` из будущего > 60 с → нет; `end` продлевает только перечисленные адреса), `hole_targets_caps` (20 друзей × 3 адреса → ≤ 16 друзей, ≤ 2 на друга, ≤ 32; 6 друзей в одной /64 → 4), `hole_targets_order_freshest_first`, `hole_end_addrs_closed_first`, `engine_hole_for_offline_friend` (вызовы `hold_open` каждые 10 ± 1 с с адресом друга), `engine_hole_stops_when_live`, `engine_hole_not_while_inflight`, `engine_hole_stops_after_max_age`, `engine_hole_live_end_basis` (`last_seen` старше `max_age`, но `on_closed` недавно → удерживается), `engine_hole_not_for_guest`, `engine_hole_not_for_removed_or_blocked`, `engine_hole_v4only_none`, `engine_hole_period_zero_off`, `engine_hole_does_not_touch_limiter` (два движка с удержанием и без: моменты наборов и `entries_len` ограничителя совпадают за 2 ч модельного времени). Существующие тесты без правок проходят (кроме добавления метода в `kit.rs`).

### Критерии приёмки (команды; вывод в отчёт)
- [ ] `cargo build --workspace --all-targets --locked`; `cargo test --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`
- [ ] `cargo test -p chervo-transport-quinn --locked hole_ -- --nocapture`; `cargo test -p chervo-connect --locked hole_`
- [ ] `for i in $(seq 10); do cargo test -q --locked -p chervo-connect engine_hole_ || exit 1; done`
- [ ] `git diff $BASE -- Cargo.lock | grep -E '^\+name = '; test $? -eq 1`; `git diff --stat $BASE -- crates/chervo-identity crates/chervo-token crates/chervo-friends crates/chervo-lan` пусто; `git diff $BASE -- crates/chervo-connect/src/limiter.rs` пусто
- [ ] `grep -rn 'HOLE_DATAGRAM' crates/chervo-transport-quinn/src | grep -v 'src/knock.rs' | grep -v 'src/tests/'; test $? -eq 1`; `grep -rn 'unsafe\|set_unicast_hops' crates/chervo-transport-quinn/src crates/chervo-connect/src; test $? -eq 1`
- [ ] `grep -c 'cx > 0 && cy > 0 && bx > 0 && el <= limit' tools/netns/stage13g.sh` = 1; `awk '/^row_fw_both\(\)/,/^}/' tools/netns/stage13g.sh | grep -c 'v6 PASS'` = 1; `bash -n tools/netns/stage13g.sh`
- [ ] CI зелёный (3 ОС, `CHERVO_REQUIRE_IPV6=1`, supply-chain)
- [ ] Linux-машина владельца: `sudo tools/netns/stage13g.sh` все строки PASS, включая G6-4, G6-15, G6-16. Блокирует выпуск, не приёмку кода.

### Стенд (изменения `tools/netns/stage13g.sh`)
- **G6-4 FW6-LATE (исправление).** `G64_LIMIT` по умолчанию 60 (было 720). В `row_fw_both` единственная ветка PASS: `(( cx > 0 && cy > 0 && bx > 0 && el <= limit ))` для обеих строк; `el > limit` → FAIL «через ${el} с (> ${limit})». Время перестаёт быть «информативным». В примечание: число 1-байтовых датаграмм A→адрес B в захвате на стороне A за время отступа (должно быть > 0).
- **G6-15 FW6-CAP (новая).** Как G6-4, но B выключен `G615_RETREAT=1200` с (A на потолке 600 с, Д3-2). PASS: `Connected{Ipv6}` ≤ `G64_LIMIT` от перезапуска B. Предел строки 1800 с.
- **G6-16 HOLE-STALE (новая).** Дружба как в G6-2; A запущен с `--hole-max-age 120`. B остановлен (момент закрытия у A — по журналу A), экран `nb` снят, хост `hb` со старым адресом B остаётся без узла; захват на `hb`, 120 + 60 с. PASS, если всё: (1) каждая датаграмма A→hb с полезной нагрузкой 1 байт равна `00`, медиана интервалов 9-11 с; (2) ни одной 1-байтовой позже `t_close_A + 120 + 15` с; (3) прочие датаграммы A→hb только длины 48 (стук) или ≥ 1200; (4) узел A жив, в журнале A нет `Internal`. Число ICMPv6 от hb к A — в отчёт (информативно).
- Охрана захвата всех строк: 1-байтовые датаграммы от A только к глобальным IPv6 друзей строки; в G6-5 (B только IPv4) и G6-12 (NOV6) их 0. В отчёте адресов нет (санитайзер), только роли.

### Стоп-условия (дополнительно)
`send_hole_wire_bytes` красный на любой ОС CI (1-байтовая датаграмма не уходит через quinn-udp); любая существующая проверка шлёт или ждёт датаграмму в 1 байт; понадобилось менять ограничитель, расписание, формат стука, KK, ADDR_INFO, токены, файл друзей, опции гнезда, новый пакет или `unsafe`; на стенде G6-4 или G6-15 > 60 с при работающем удержании — СТОП: предел не поднимать, приложить захват обеих сторон.

### Порядок работы builder (один вызов, sonnet/high)
1. `BASE=$(git rev-parse HEAD)`; сверить Д3-2…Д3-9 по указанным строкам; расхождение → СТОП.
2. `chervo-transport`: метод `hold_open`. `chervo-transport-quinn`: `HOLE_DATAGRAM`, `send_bytes`/`send_hole`, фильтр Р3-5, `hole_dests`, `hold_open`, счётчики; тесты L2; критерии для крейта.
3. `chervo-connect`: поля конфигурации, `hole.rs`, `FriendRt.hole_end`, `on_closed`, `State.hole_next_at`, круг в `tick`; `kit.rs` обоих крейтов; тесты L3; критерии.
4. `node16.rs`: флаги.
5. `stage13g.sh`: G6-4, G6-15, G6-16, охрана захвата; `bash -n`.
6. Все критерии; отчёт до 25 строк.
Дирижёр после вызова сам: `cargo test -p chervo-transport-quinn --locked hole_ -- --nocapture` и `cargo test -p chervo-connect --locked engine_hole_`.

### combine-security смотрит
Место фильтра 1-байтовых в `filter_batch` (после класса, до `required` и таблицы допуска; `rx` не растёт); `hole_dests` (только Global, ≤ 32, нормализация); объединение задач `hold_open`; что `try_send(` одно и удержание не обходит `family_ok`/`RouteMap`; пределы 16/2/4/32 и возраст (`basis` из будущего, насыщение, `hole_end` только по факту снятия живого); удержание не трогает `Limiter`; гости, удалённые, заблокированные исключены; утечки адресов в `Debug`/журналы нет.

### Дельта THREAT_MODEL (дирижёр после приёмки; к T21)
- *Меры (эт. 13г, доп. 3):* пока друг не на связи, узел раз в 10 с шлёт на его глобальные IPv6 (≤ 2 на друга, ≤ 16 друзей, ≤ 4 на /64, ≤ 32) датаграмму в 1 нулевой байт, чтобы экран своего роутера пропустил встречный набор; только адреса из подписанного обновления или проверенного соединения, прошедшие маршрут и `family_ok`; не дольше `hole_max_age` от последнего подтверждения адреса; получатель выбрасывает такие датаграммы до таблицы допуска, без ответа; ограничитель набора не затрагивается.
- *Остаётся:* держатель устаревшего адреса друга видит наш адрес и порт и поток 1-байтовых датаграмм до `hole_max_age`; периодическая 1-байтовая датаграмма — признак для DPI; при смене порта друга или выборе ОС иного источника, чем знает друг, дыра не помогает [Д]; поведение реальных роутеров (сроки записей, фильтрация, независимая от адреса) не проверено; IPv4 — этап 13б. Строку «ожидание до ~12 мин (G6-4)» заменить на «встречный набор после перезапуска друга ≤ 60 с на стенде (G6-4, G6-15)».

### Спорное для владельца
**В3. Сколько держать дыру к адресу друга, пока он не на связи.** Пока держим, перезапущенный друг соединяется сразу; после — соединение может не случиться вовсе, пока кто-то из вас не перезапустится или не сменит адрес (расписания не сходятся, Д3-1). Цена: адрес друга мог перейти к другому абоненту провайдера, и тот получает от вас пустяковый пакет раз в 10 с (ваш адрес и порт, больше ничего). (а) 24 ч — ровно столько, сколько адрес IPv6 и так живёт в книге и набирается. (б) 12 ч — покрывает выключенный на ночь компьютер. (в) 2 ч. **Рекомендую (а):** иначе между концом дыры и смертью адреса остаётся окно, где соединения не будет никогда; посторонний обычно не видит этих пакетов, их режет его же роутер [В]. До ответа builder делает (а); смена — одна константа в `ConnectConfig::default`.

### Для владельца (кратко, Дополнение 3)
- Пока друг по IPv6 не на связи, программа раз в 10 секунд шлёт на его адрес пакет в один пустой байт. Это держит открытой «дверь» в вашем роутере, и когда друг включится, его звонок сразу пройдёт.
- Пакет не стук и ничего не говорит о вас и друге, кроме вашего адреса и порта; у получателя он молча выбрасывается и ничего не меняет.
- Пределы: до 16 друзей, до 2 адресов на друга, всего не больше 32 пакетов за 10 секунд (около 150 байт в секунду в худшем случае); только глобальные IPv6, только друзья (не гости); перестаёт, как только друг на связи, удалён или адрес устарел (В3).
- Расписание звонков не меняется. IPv4 не трогаем (этап 13б).
- Проверка: тесты на Windows и CI; на стенде перезапуск друга через 3 и 20 минут — соединение не дольше 60 секунд; отдельная строка проверяет, что посторонний на старом адресе видит только эти однобайтовые пакеты и что они прекращаются по сроку. Реальные роутеры не проверены.
