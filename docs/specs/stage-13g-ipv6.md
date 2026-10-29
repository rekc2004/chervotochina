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
