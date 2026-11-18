# SPEC 13д: эхо-сервер, внешний адрес в приглашении, помощник «доступ из интернета»          критичность: КРИТИЧНЫЙ

Автор: combine-architect (opus/high).
- Ред. 1 (2026-11-17): файл назывался `stage-13v-echo.md`.
- Ред. 2 (2026-11-18): ответы В1-В7; адрес попадает в приглашение сам; требования к текстам; подсказка для приглашения, вставленного не в то поле.
- Ред. 3 (2026-11-18): ответы Н1-Н5 (Н4 отклонён: кнопка «Получить свой IP» остаётся); новый помощник открытия доступа через роутер с проверкой (Р10), протокол дополнен проверкой доступа (Р1).
- **Ред. 4 (2026-11-18):** П1-П5 приняты по рекомендациям. 13д строится поверх 18б (Р0). Ошибки и тексты для «не того поля вставки» убраны: их заменяет единое поле 18б. Добавлены В4, В5, С8 из ревью GUI, которые 18б передал в 13д. Версия sing-box владельца — в шаге 0. Новый вопрос П6.

Рабочее дерево `.claude/worktrees/stage-13v`. Ничего не запускалось.
Метки: **[П]** проверено мной по исходнику этого дерева; **[В]** вывод; **[Д]** догадка или память, опираться нельзя; **[НП]** не проверено.
**Документацию ОС, sing-box и RFC я не открывал (веб-инструмента нет):** всё о них помечено [Д] и проверяется шагом 0.

Цель:
1. «Добавить друга» → «Пригласить» → «Создать приглашение» само вписывает в приглашение адрес в интернете, если указан сервер.
2. Кнопка «Получить свой IP» показывает этот адрес с «Копировать».
3. Если похоже на VPN, программа заметно предупреждает и вписывает адрес только по явной кнопке.
4. Помощник «Открыть доступ из интернета» работает так:
   - сначала, после одного «Разрешить» на роутер, открывает доступ через UPnP;
   - если не вышло, показывает пошаговую инструкцию с готовыми значениями и «Копировать» у каждого;
   - кнопка «Проверить» проверяет то, что реально можно проверить.
5. Сервер — маленькая отдельная программа.

Прочитать:
- этот файл;
- `docs/specs/stage-18b-ux.md`: п.2 (единое поле «Друг прислал мне текст», `apply_friend_text`), п.3 (единые имена), п.8 (правило формулировок; В4, В5, С8 переданы сюда);
- `docs/reviews/REVIEW-GUI-UX.md`: В4, В5, С8;
- `docs/OWNER_DECISIONS.md`: разделы «Этап 13а: UPnP» и «Этап 13д»;
- `docs/specs/stage-13v-lan.md`, «Дополнение 1» (включая абзац про 13а);
- `docs/THREAT_MODEL.md`: T1, T7, T8, T16;
- код (номера строк по дереву до 18б; после 18б сверить):
  - `crates/chervo-transport-quinn/src/knock.rs:597-624, 734-815`;
  - `crates/chervo-connect/src/engine.rs:95-102`, `invite.rs:334-366`;
  - `crates/chervo-token/src/invite.rs:48-76, 226-291`;
  - `crates/chervo-upnp/src/mapper.rs:326-346`, `texts.rs:1-40`;
  - `crates/chervo-core/src/node/friends.rs:111-126`, `network.rs`, `transfers.rs:330-340`, `settings.rs:1-130`, `runtime.rs:76-88`, `texts.rs:33, 59-60`;
  - `crates/chervo-gui/src/screens/add_friend.rs`, `screens/settings.rs:186-252`, `screens/diagnosis.rs`, `model.rs:33-147`, `texts.rs`, `tests/gated_node_actions.rs`;
  - `crates/chervo-lan/src/lib.rs:44-60`, `ifaces.rs`.

Больше ничего не искать.

---

## 0. Проверенные факты

1. Основной сокет узла только IPv4: `UdpSocket::bind((0.0.0.0, port))` (`chervo-core/src/node/mod.rs:451-453`) [П].
2. `KnockSocket` отбрасывает датаграммы недопущенных адресов до quinn (`knock.rs:790-804`) [П].
3. Своя отправка в сокет: `KnockState::send` (`knock.rs:597-620`). `try_send(` разрешён только в `knock.rs` (`tests/src_guard.rs:107-110`) [П].
4. `quinn-udp 0.5.16` задаёт адрес источника для одного пакета через `Transmit.src_ip`:
   - Windows: `IN_PKTINFO.ipi_addr` (`windows.rs:353-364`);
   - Linux: `ipi_spec_dst` (`unix.rs:643-653`);
   - macOS: `IP_RECVDSTADDR`, только у сокета на `0.0.0.0` (`unix.rs:654-661, 307-314`).

   [П]
5. В `socket2 0.6.5` привязка к интерфейсу есть только с feature `all` (`sys/unix.rs:1964-1968, 2009-2036`). Для Windows нет ни `IP_UNICAST_IF`, ни PKTINFO [П]. `all` запрещена с 13а; `unsafe_code = "forbid"` (`Cargo.toml:77`) [П].
6. Адаптеры без `unsafe` FFI не перечислить (13в, Дополнение 1). Частные адреса компьютера даёт опрос маршрутов `chervo_lan::sweep_report` (`chervo-lan/src/lib.rs:44-60`), пакетов он не шлёт [П].
7. Фактический порт: `Transport::local_addrs()` (`chervo-transport-quinn/src/lib.rs:596-598`), транспорт в `Core.transport` (`core.rs:110`) [П].
8. Синхронный вызов асинхронного кода идёт через `runtime::run_timeout` (`runtime.rs:76-88`) [П].
9. **Приглашение** несёт 1..=8 подписанных адресов (`chervo-token/src/invite.rs:58-76, 270-288`). Внешний адрес — обычная запись: формат, подпись и совместимость не меняются [П/В]. Меняется только источник адресов в `chervo-connect` (`engine.rs:95-102`) [П].
10. **Поля вставки текста от друга — забота 18б.** Там все тексты (приглашение, новый адрес, уведомление об удалении) вставляются в одно поле «Друг прислал мне текст», вид определяет ядро (`Node::apply_friend_text`) (`stage-18b-ux.md` п.2). 13д полей вставки не меняет и своих ошибок «не то поле» не вводит [П по документу].
11. Названия в GUI (`chervo-gui/src/texts.rs`, дерево до 18б) [П]:
    - вкладки: «Добавить друга», «Настройки», «Друзья» (`:36-42`);
    - вкладки окна приглашения: «Пригласить», «Принять приглашение»; кнопка «Создать приглашение» (`:115-118`);
    - раздел настроек «Проброс порта на роутере» и кнопка «Найти роутер» (`:197-198`);
    - строка настроек «Порт UDP (вступит в силу после перезапуска)» (`:193`).

    18б меняет формулировки (п.3, п.8). Тексты 13д ссылаются на названия **после 18б**; при расхождении — названия из 18б.
12. При VPN, который держит маршрут по умолчанию, ответы сокета `0.0.0.0` уходят в туннель (`stage-13v-lan.md:292`) [В]. Ни внешний адрес, ни проброс другу не помогут, пока VPN включён.
13. Многие роутеры пропускают обратно только тех, кому мы писали сами [Д: распространённость не проверена]. Внешний адрес в приглашении без проброса тогда не помогает. Пригласивший заранее адреса друга не знает (TASK 13, ограничение 1) [П по документу].
14. **UPnP (13а) и согласие.** Решения владельца:
    - «свой роутер» подтверждает пользователь; ответ хранится по UDN;
    - **пустой список — ни одного пакета UPnP**;
    - `identify()` вызывается только по кнопке (TASK 13а, «Остатки»; `network.rs:108-118`).

    `identify(own_ip)` делает один поиск SSDP и одно описание. Возвращает только `RouterId` (UDN), адрес роутера наружу не отдаёт (`mapper.rs:326-338`, `url.rs:11-24`: `GatewayAddr` с `pub(crate)`) [П]. Текст вопроса `ENABLE_ON_ROUTER_TEXT` содержит предупреждение «только в своей сети» (`chervo-upnp/src/texts.rs:7`) [П]. Разрешение — `upnp_allow` (`network.rs:122-142`), статус — `mapping_status()` [П].
15. **Шлюз по умолчанию.** std не отдаёт таблицу маршрутов. Без `unsafe` FFI (`GetIpForwardTable2`, `GetBestRoute2` и аналоги) адрес шлюза не узнать [П по фактам 5, 6 и списку функций в `stage-13v-lan.md:244`]. Проба маршрутов отвечает только «через какой мой адрес», а не «через какой шлюз» [П, `probe.rs:44-51`].

    Точный адрес роутера есть только в одном случае: роутер ответил на поиск UPnP. Тогда это адрес из LOCATION, проверенный кодом 13а [П по `url.rs`].

    Иначе остаётся догадка `a.b.c.1` по домашнему адресу `a.b.c.d` [Д: обычная настройка роутеров] и наклейка на роутере. **Решение П1 = (а):** точного определения нет, `/proc/net/route` не читаем.
16. Ручной проброс уже поддержан: `Node::set_manual_forward(Option<u16>)` (`transfers.rs:330`). При нём `NatView::ManualForward`; IP до сих пор брался со слов друга (`chervo-addr/src/own.rs:80-82`) [П].
17. **Находки ревью GUI, переданные в 13д** (`stage-18b-ux.md` п.8) [П по `REVIEW-GUI-UX.md:236-243, 261`]:
    - **В4:** первое приглашение у домашнего пользователя не создаётся (`NoAddresses`), а текст ошибки `NO_ADDRESS_TEXT` (`core/texts.rs:59-60`) не говорит, что делать;
    - **В5:** поле «Свой адрес с пробросом порта» требует знать внешний IP и порт;
    - **С8:** «Найти роутер» спрятан в настройках, и ни приглашение, ни диагностика туда не ведут.

## 1. Решения

### Р0. Основа: 18б
- 13д делается в той же ветке **после слияния 18б**. Предусловие вызова 1: коммит 18б в ветке, `cargo test --workspace --locked` зелёный.
- От 18б берутся без изменений:
  - `apply_friend_text` и единое поле вставки;
  - имена «приглашение», «новый адрес», «уведомление об удалении»;
  - правило формулировок (без «токен», NAT, UDP, SAS, LAN там, где не нужно);
  - охрана, которую 18б добавил в `gated_node_actions`.
- Если 18б и 13д расходятся в общем файле (`texts.rs`, `add_friend.rs`, `gated_node_actions.rs`), верх берёт 18б. Тексты 13д приводятся к его названиям, расхождение — в отчёт.
- В4, В5 и С8 закрываются здесь: Р7.6, Р8, П6.

### Р1. Протокол (`chervo-rendezvous-wire`, без зависимостей). В1 = без подписи
Общий заголовок: магия `b"CHRV"`, версия `1`, тип, флаги u16 BE = 0. Типы `0x10..=0x7F` оставлены за 13б.

| тип | имя | длина | содержимое после заголовка (байты 8..) |
|---|---|---|---|
| `0x01` | `ECHO_REQUEST` | 64 | 8..24 nonce; 24..64 нули |
| `0x02` | `ECHO_RESPONSE` | 48 | 8..24 nonce; 24 семейство (4 или 6); 25 = 0; 26..28 порт XOR `nonce[0..2]`; 28..44 адрес (v4: XOR `nonce[2..6]`, затем 12 нулей; v6: XOR `nonce[0..16]`); **44..46 порт проверки сервера, u16 BE (0 = проверки нет)**; 46..48 нули |
| `0x03` | `REACH_REQUEST` | 64 | 8..24 nonce; **24..26 проверяемый порт, u16 BE, ≠ 0**; 26..64 нули |
| `0x04` | `REACH_RESPONSE` | 48 | как `0x02`, байты 44..46 = 0 |

- XOR по образцу RFC 8489 §14.2 [Д]. Ответ всегда короче запроса: `const _: () = assert!(RESPONSE_LEN < REQUEST_LEN);`. Неизвестные версию, тип и флаги сервер молча отбрасывает.
- **Проверка доступа (П2 = а).** Сервер получает `REACH_REQUEST` на основной порт. Ответ `REACH_RESPONSE` он шлёт **со второго сокета** (порт проверки, тот же IP) на `(IP источника запроса, проверяемый порт)`.

  Если ответ дошёл до компьютера, роутер пропускает входящие от отправителя, которому мы сами не писали: порт другой, а при пробросе и адрес назначения может быть другим. Это признак работающего проброса или «пропускающего всех» роутера.

  Ложные «работает» возможны на роутере, который фильтрует только по IP без порта [Д]. Это сказано в тексте `ACC_CHECK_LIMIT`. Ответ уходит только на IP источника; цель только порт, ≠ 0. Лимиты общие с эхо (Р4) [В].
- Клиент: до 3 запросов на путь (0, 1, 2 с), срок 3 с, свой nonce на путь, RFC 8085 §3.1.3 [Д]. Клиент v1 только IPv4.
- В1 = без подписи. Подделка вне пути требует угадать nonce (2^-128). Тот, кто на пути, может пропустить запрос через свой NAT, и подписью это не закрывается [В]. Последствия ложного ответа — в разделе 6.

### Р2. Сокет и обход VPN (В2 = а, В3 = а)
- Запросы идут с **основного сокета QUIC**: сервер видит то же отображение NAT, что и друзья (DECISION 3.4). Ответы забираются в `KnockSocket` по IP сервера и nonce; допуск не открывается, мы ничего не отвечаем.
- Обход VPN: адрес источника на один пакет (факт 4). Пути:
  - `d = route_source_for(server)`;
  - `S = chervo_lan::private_sources(d)`;
  - кандидаты `C = (S \ {d})[..3]`;
  - всего путей `[по умолчанию] + C`, не больше 4.

  Различаем по результату.
- Ожидания [Д, проверяются шагом 0 и вручную]:

  | ОС | Ожидание |
  |---|---|
  | Windows | работает (модель «сильного хоста»); у владельца sing-box 1.14.4 через v2rayN 7.25.6 |
  | Linux | обычно не работает («слабый хост», fwmark у wg-quick, `strict_route` sing-box) |
  | macOS | неизвестно |

### Р3. Вердикт пробы (чистая функция `echo_verdict(paths, default_class, strong_host)`)
Проверяется по порядку:
1. Нет ответов: `NoAnswer`.
2. Любой ответный IP не `Global`: `ServerSeesPrivate`.
3. Кандидат дал IP, отличный от пути по умолчанию, или путь по умолчанию не ответил: `Bypassed { real }`.
4. Путь по умолчанию ответил и выполнено хотя бы одно:
   - класс `d` равен `Benchmark` или `Shared`;
   - кандидаты есть, но ни один не ответил;
   - `!strong_host`, кандидаты есть и все дали тот же IP.

   Тогда `MaybeVpn`.
5. Иначе: `Single`.

`strong_host = cfg!(windows)`. Ложные тревоги на Linux, macOS и при адаптерах ВМ приняты (Н3 = а).

### Р4. Сервер `chervo-rendezvous-server`, бинарь `chervo-rendezvous` (В5 = а)
- Зависимости только `chervo-rendezvous-wire` и `chervo-addr` (`classify`). Новых внешних пакетов нет, tokio нет.
- `chervo-rendezvous --listen IP:PORT [--listen IP6:PORT] [--reach-port N] [--allow-private] [--report-secs N]`.
  - `--reach-port`: второй сокет на том же IP для каждого `--listen`. Номер порта сервер сообщает в `ECHO_RESPONSE`. Без флага `REACH_REQUEST` отбрасывается.
  - Портов по умолчанию нет.
  - Коды выхода: 2 — аргументы, 1 — bind.
- Ответы:
  - `send_to(` в коде ровно два: ответ эхо и ответ проверки;
  - адресат — только IP источника запроса; для проверки порт берётся из запроса, `≠ 0`;
  - источник с портом 0, неуказанный, multicast или broadcast отбрасывается;
  - по умолчанию отвечаем только адресам `Global`.
- Лимиты:
  - на ключ (IPv4 /32, IPv6 /64) общий счёт эхо и проверок: 16 ответов за 10 с;
  - таблица до 65 536 ключей; когда полна, новый ключ сразу считается превысившим лимит;
  - всего не больше 1000 ответов в секунду.
- Приём: буфер 2048 байт, таймаут 500 мс, ошибки `recv` только считаются.
- Журнал:
  - на диск ничего не пишется;
  - в stderr две строки: строка старта (версия и свои адреса) и строка счётчиков раз в `--report-secs` (по умолчанию 600, от 60 до 86400);
  - IP клиентов не печатаются.
- Секретов у сервера нет.
- `docs/ECHO_SERVER.md` (≤ 40 строк): сборка, запуск с `--reach-port`, брандмауэр (оба порта UDP), юнит systemd с `DynamicUser=yes`.
- Упаковка в выпуск вне объёма.

### Р5. Транспорт и LAN
- **`chervo-lan`:** `pub fn private_sources(default: Ipv4Addr) -> Vec<Ipv4Addr>`, логика `sweep_report` без счётчика.
- **`chervo-transport-quinn`** (новая зависимость `chervo-rendezvous-wire`, путь), модуль `src/echo.rs`:
  - ожидание: IP сервера, его основной порт, вид (`Echo` или `Reach`), до 4 слотов `(Nonce, Option<..>)`, `Notify`;
  - в `KnockState`: `echo: Mutex<Option<EchoWait>>`, `echo_active: AtomicBool`.
- **`filter_batch`.** Проверка идёт до классификации допуска, при `echo_active`, только сегменты по 48 байт.
  - Вид `Echo`: источник равен `ip:основной порт` сервера.
  - Вид `Reach`: IP сервера с любым портом, кроме основного; тип `0x04`.
  - Совпал nonce: сегмент записывается и вырезается. Иначе он идёт обычным путём.
- **Отправка:** `KnockState::send_echo(dest, &[u8; 64], src: Option<Ipv4Addr>)` в `knock.rs`, вызывается только из `echo.rs`.
- **Nonce:** `ring::rand::SystemRandom`. Сбой генератора: `EchoError::Random`, ничего не отправлено.

### Р6. Ядро
- **Настройки.**
  - Строка `echo=`, поле `Settings.echo_server: Option<String>`, по умолчанию `None`.
  - Проверка: `хост:порт`, литерал IPv4 или имя по правилу имён NTP. Отвергаются IPv6, `://`, пробелы, длина больше 259.
  - Комментарий `settings.rs:5` уточнить.
  - Старая версия на строке `echo=` выдаст `SettingsCorrupt`. Сделать так же, как для `lan=` из 13в [В].
- **`echo_probe()`**:
  - нет сервера: `NotConfigured`, без сети;
  - уже идёт: `Busy`;
  - меньше 10 с с прошлой пробы: сохранённый отчёт;
  - DNS: не больше 8 адресов, первый IPv4; ошибки `NoIpv4` и `Resolve`;
  - адрес неуказанный, multicast или broadcast: `BadAddress`;
  - дальше пути (Р2), `run_timeout(.., 3 с + 1 с)`, вердикт (Р3);
  - сохраняется `reach_port` сервера из ответа.
- **`plan_invite_external(report, nat, manual_forward)`**, по порядку:
  - `NoAnswer`: `Skip(NoAnswer)`;
  - `ServerSeesPrivate`: `Skip(ServerLocal)`;
  - `nat == Symmetric`: `Skip(Symmetric)`;
  - `MaybeVpn`: `AskVpn{addrs}`;
  - иначе `Add{addrs, vpn_on: Bypassed}`.

  `addrs` = наблюдённый адрес, плюс `ip:manual_forward`, если порт другой.
- **`create_invite_ext(same_network, extra)`**: через новый `InviteAddrs::AutoWith { same_network, extra }` в `chervo-connect`. `extra` идут первыми, повторы убираются, всего не больше 8. При пустом собственном списке и непустом `extra` ошибки `NoAddresses` нет.
- **Поддержание адреса (Н1 = а).**
  - Пока ждёт приглашение с внешним адресом (до SAS, отмены или срока), раз в 25 с один `ECHO_REQUEST` тем же путём.
  - Изменился адрес: `NodeEvent::InviteAddressChanged`.
  - Без ответа поддержание продолжается до срока; трёх ответов подряд нет — событие.
- **Поля вставки:** не меняются, работают по 18б (`apply_friend_text`).
- **В4:** текст `NO_ADDRESS_TEXT` заменяется на `NO_ADDRESS_TEXT` из Р8, с путями «что сделать». Сама ошибка и место её выдачи прежние.
- **Помощник доступа (Р10):** `forward_help()`, `reach_check()`, `confirm_manual_forward()`, а также `upnp_identify` возвращает адрес роутера (Р10.1).

### Р7. GUI: приглашение и «Получить свой IP»
1. **Настройки, раздел «Связь через интернет»:** одна строка с примером в подписи, «Сохранить», «Очистить», подсказка.
2. **«Создать приглашение».**
   - Задан ручной адрес (только если П6 = б): всё как сейчас, без пробы.
   - Нет сервера: приглашение как сейчас, плюс `INV_EXT_NOT_SET`.
   - Есть сервер: на время пробы `INV_EXT_CHECKING`, дальше по плану:
     - `Add`: мелко `INV_EXT_ADDED`, затем `INV_EXT_FRIEND_TIP` с кнопкой `BTN_OPEN_ACCESS` (открывает помощник Р10). При `vpn_on` заметно `INV_VPN_ON_*`;
     - `AskVpn`: приглашение ещё не создано. Заметно `INV_MAYBE_VPN_*`, кнопки `BTN_INV_WITHOUT_ADDR` и `BTN_INV_WITH_ADDR`. Без второй кнопки адрес не вписывается;
     - `Skip`: приглашение как сейчас, плюс строка причины.
   - Ошибка `NoAddresses` (В4): текст Р8 и под ним кнопка `BTN_OPEN_ACCESS`.
3. **«Получить свой IP» (Н4 отклонён владельцем: кнопка остаётся).**
   - Где: вкладка «Добавить друга» → «Пригласить», рядом с «Создать приглашение».
   - Нет сервера: кнопка недоступна, рядом `GETIP_NO_SERVER`.
   - Результат: `GETIP_RESULT`, затем `copy_box` с `ip:порт`.
   - Пометки: при `MaybeVpn` заметно `GETIP_MAYBE_VPN`, при `Bypassed` — `GETIP_VPN_ON`. Прочие исходы: `GETIP_NO_ANSWER`, `INV_EXT_SERVER_LOCAL`, `INV_EXT_SYMMETRIC`.
   - Повтор в течение 10 с показывает тот же результат.
4. **Команды и охрана.**
   - `Command::EchoProbe` создаётся только в ветке `I::GetIp`.
   - `Command::CreateInvite { .., external: ExternalMode::{Probe, Use(..), Without} }`: `Probe` создаётся только в ветке `I::AddCreate`, `Use` и `Without` — только в ветках ответа о VPN.
   - `node.echo_probe(` разрешён **ровно в двух ветках** `worker_ops.rs`: `Command::EchoProbe` и `Command::CreateInvite`, и только при `Probe`.
   - Изменения стража — в Р11.
5. **Понятность.** Каждый текст с действием называет вкладку, раздел и кнопку. Слова «токен», «NAT», «эхо», «порт» не используются там, где человеку не нужно о них думать (правило 18б п.8). Исключение: значения в инструкции Р10, где роутер сам спрашивает «порт» и «UDP».
6. **С8 и В5.**
   - Кнопка `BTN_OPEN_ACCESS` стоит в трёх местах:
     - на вкладке «Добавить друга» → «Пригласить», постоянно, под «Создать приглашение» и «Получить свой IP»;
     - на вкладке «Диагностика» у друга с причиной из `chervo_connect::texts`: NAT, CGNAT, двойной NAT, нужен адрес;
     - в разделе настроек «Доступ из интернета» (П4).

     Сеть по-прежнему только по нажатию внутри помощника.
   - **В5** (поле «Свой адрес с пробросом порта») — по ответу П6. По рекомендации (а) поле убирается с экрана приглашения:
     - ручной проброс записывает помощник (Р10.3, П3);
     - строка `SET_MANUAL_FORWARD` в «Настройки» → «Доступ из интернета» остаётся и подписывается `ACC_MANUAL_FORWARD_LABEL`, для тех, у кого правило с другим внешним номером;
     - IP при этом берётся из эхо (Р6), вводить его не нужно.

### Р8. Тексты (полный список новых и заменённых)
GUI — `crates/chervo-gui/src/texts.rs`, ядро — `crates/chervo-core/src/node/texts.rs`. Подстановки `{..}` делает модель.

**Настройки, «Связь через интернет» (GUI):**
- `SET_TITLE_EXTERNAL = "Связь через интернет"`
- `EXT_SERVER_LABEL = "Адрес вашего сервера, например 203.0.113.5:45900"`
- `BTN_CLEAR = "Очистить"` (если такой константы нет)
- `EXT_SERVER_HINT = "Нужен, когда друг подключается не из вашей домашней сети. Сервер подсказывает программе ваш адрес в интернете, и программа сама впишет его в приглашение. Сервер — это программа chervo-rendezvous на компьютере, который всегда доступен из интернета (ваш или знакомого). Адрес для этой строки даст тот, кто запустил сервер. Пока строка пустая, программа ни к какому серверу не обращается."`
- `EXT_SERVER_SAVED = "Сохранено. Теперь «Создать приглашение» само впишет ваш адрес в интернете."`
- `EXT_SERVER_CLEARED = "Адрес сервера удалён. Приглашения создаются без адреса в интернете."`

**Ошибки (ядро):**
- `ECHO_BAD_ADDRESS_TEXT = "Адрес сервера не распознан. Впишите его так, как дал владелец сервера, например 203.0.113.5:45900 или server.example:45900."`
- `ECHO_RESOLVE_TEXT = "Не удалось найти сервер по этому имени. Проверьте строку «Адрес вашего сервера» на вкладке «Настройки», раздел «Связь через интернет»."`
- `ECHO_NO_IPV4_TEXT = "У этого сервера нет подходящего адреса. Попросите у владельца сервера адрес из цифр, например 203.0.113.5:45900."`
- `ECHO_BUSY_TEXT = "Программа уже узнаёт ваш адрес, подождите несколько секунд."`
- `NO_ADDRESS_TEXT` (**заменяет** прежний, В4) `= "Приглашение не создано: программа пока не знает адреса, по которому друг сможет к вам подключиться. Что сделать: если друг в той же сети, что и вы, отметьте «мы в одной сети» и снова нажмите «Создать приглашение»; если в другой — нажмите «Открыть доступ из интернета» или впишите адрес своего сервера (вкладка «Настройки», раздел «Связь через интернет»); можно и наоборот: пусть приглашение создаст друг."` Подпись галочки «мы в одной сети» — по 18б, если он её переименует.

**«Добавить друга» → «Пригласить» (GUI):**
- `BTN_GET_IP = "Получить свой IP"`
- `GETIP_RESULT = "Ваш адрес в интернете (IP и порт):"`
- `GETIP_NO_SERVER = "Чтобы узнать адрес, впишите адрес своего сервера: вкладка «Настройки», раздел «Связь через интернет», строка «Адрес вашего сервера»."`
- `GETIP_NO_ANSWER = "Сервер не ответил. Проверьте, что он включён и что адрес на вкладке «Настройки», раздел «Связь через интернет», верный. Затем снова нажмите «Получить свой IP»."`
- `GETIP_MAYBE_VPN = "Похоже, включён VPN: это может быть адрес VPN, а не ваш. Выключите VPN или добавьте Червоточину в исключения VPN и снова нажмите «Получить свой IP»."` (заметно)
- `GETIP_VPN_ON = "Включён VPN. Это ваш настоящий адрес, но, пока VPN работает, друг по нему не подключится."` (заметно)
- `INV_EXT_CHECKING = "Узнаём ваш адрес в интернете…"`
- `INV_EXT_ADDED = "В приглашение вписан ваш адрес в интернете: {addr}"` (мелко)
- `INV_EXT_FRIEND_TIP = "Если друг не подключится за минуту, нажмите «Открыть доступ из интернета»: программа поможет настроить роутер."` (**заменяет** прежний совет)
- `INV_EXT_NOT_SET = "Друг в другой сети? Впишите адрес своего сервера: вкладка «Настройки», раздел «Связь через интернет». Тогда программа сама добавит в приглашение ваш адрес в интернете. Без этого приглашение сработает, только если друг в той же сети, что и вы, или ваш компьютер уже доступен из интернета."`
- `INV_EXT_NO_ANSWER = "Сервер не ответил, поэтому ваш адрес в интернете в приглашение не вписан. Проверьте, что сервер включён и адрес на вкладке «Настройки», раздел «Связь через интернет», верный, затем снова нажмите «Создать приглашение»."`
- `INV_EXT_SERVER_LOCAL = "Сервер стоит в той же сети, что и вы, поэтому ваш адрес в интернете не узнать. Нужен сервер вне вашей сети."`
- `INV_EXT_SYMMETRIC = "Ваш роутер выдаёт каждому собеседнику свой адрес, поэтому адрес от сервера другу не подойдёт и не вписан. Нажмите «Открыть доступ из интернета»: программа поможет настроить роутер."`
- `INV_MAYBE_VPN_TITLE = "Похоже, включён VPN"` (заметно)
- `INV_MAYBE_VPN_TEXT = "Программа узнала адрес, но, возможно, это адрес VPN, а не ваш. По адресу VPN друг к вам не подключится. Выключите VPN или добавьте Червоточину в исключения VPN (в настройках VPN это называется «исключения» или «раздельное туннелирование»), затем снова нажмите «Создать приглашение»."`
- `BTN_INV_WITHOUT_ADDR = "Создать приглашение без этого адреса"`
- `BTN_INV_WITH_ADDR = "VPN выключен, вписать адрес"`
- `INV_VPN_ON_TITLE = "Включён VPN"`
- `INV_VPN_ON_TEXT = "Ваш настоящий адрес вписан в приглашение, но, пока VPN включён, друг к вам не подключится. Выключите VPN или добавьте Червоточину в исключения VPN."`
- `INV_ADDR_CHANGED = "Ваш адрес в интернете изменился. Это приглашение может не сработать: нажмите «Отмена» и создайте новое."`

**Помощник «Открыть доступ из интернета» (GUI, Р10):**
- `BTN_OPEN_ACCESS = "Открыть доступ из интернета"`
- `ACC_TITLE = "Доступ к этому компьютеру из интернета"`
- `ACC_INTRO = "Чтобы друг из другой сети мог подключиться, роутер должен пропускать его к этому компьютеру. Сначала программа попробует договориться с роутером сама."`
- `ACC_VPN = "Включён VPN: пока он работает, настройка роутера другу не поможет. Выключите VPN или добавьте Червоточину в исключения VPN."` (заметно, если последняя проба дала `Bypassed` или `MaybeVpn`)
- `ACC_CGNAT = "Ваш провайдер выдаёт один адрес в интернете сразу многим абонентам, поэтому настройка роутера не поможет. Можно попросить у провайдера «белый» (постоянный) IP-адрес."` (если `nat_view` равен `BehindCgnat` или `DoubleNat`)
- `BTN_ACC_AUTO = "Попробовать автоматически"`
- `ACC_SEARCHING = "Ищем роутер…"`
- `ACC_ASK_ROUTER = "Найден роутер. Разрешить программе открывать на нём доступ для Червоточины? Делайте это только дома: в чужой сети (гостиница, офис) другое устройство может выдать себя за роутер. Ответ запомнится для этого роутера; при выходе из программы доступ закрывается."` (**заменяет** `ENABLE_ON_ROUTER_TEXT` в `chervo-upnp/src/texts.rs:7`, смысл предупреждения сохранён, П4)
- `BTN_ACC_ALLOW = "Разрешить"`, `BTN_ACC_DENY = "Не разрешать"`
- `ACC_AUTO_WAIT = "Договариваемся с роутером…"`
- `ACC_AUTO_OK = "Готово: роутер открыл доступ."` (далее, если есть проверка, она запускается сама; иначе `ACC_CHECK_NO_SERVER`)
- `ACC_AUTO_FAILED = "Автоматически не получилось: роутер не ответил или не разрешил. Это можно сделать вручную за несколько минут — по шагам ниже."` (под ним мелко прежний `status_text`, если он есть)
- `ACC_MANUAL_TITLE = "Как открыть доступ вручную"`
- `ACC_STEP1 = "1. Откройте в браузере страницу роутера:"` + `copy_box("http://{gw}")`
- `ACC_GW_FOUND = "Этот адрес сообщил сам роутер."` / `ACC_GW_GUESS = "Обычно страница роутера открывается по этому адресу. Если не открывается, посмотрите адрес на наклейке снизу роутера."`
- `ACC_STEP2 = "2. Войдите. Логин и пароль часто написаны на той же наклейке."`
- `ACC_STEP3 = "3. Найдите раздел «Переадресация портов». Он может называться «Port Forwarding», «Виртуальный сервер» или «Virtual Server»; обычно он лежит в разделе «Интернет», «WAN» или «Дополнительно»."`
- `ACC_STEP4 = "4. Добавьте правило и перенесите в него эти значения (кнопка «Копировать» у каждого):"`
  - `ACC_F_NAME = "Название (если спрашивают)"` → `Chervotochina`
  - `ACC_F_PROTO = "Протокол"` → `UDP`
  - `ACC_F_EXT_PORT = "Внешний порт (может называться «порт WAN»)"` → `{port}`
  - `ACC_F_INT_IP = "Внутренний IP-адрес (адрес этого компьютера)"` → `{ip}`
  - `ACC_F_INT_PORT = "Внутренний порт"` → `{port}`
- `ACC_RANGE_NOTE = "Если роутер просит начальный и конечный порт, впишите одно и то же число в оба поля."`
- `ACC_INT_IP_MANY = "У компьютера несколько адресов в домашней сети. Нужен тот, у которого первые три числа совпадают с адресом страницы роутера из шага 1."` (если адресов больше одного)
- `ACC_STEP5 = "5. Сохраните правило и нажмите «Проверить»."`
- `ACC_KEEP_NOTE = "Если после перезагрузки роутера доступ пропадёт, закрепите в настройках роутера адрес за этим компьютером (часто называется «Резервирование адреса» или «Static DHCP») и повторите проверку."`
- `ACC_PORT_NOTE = "Не меняйте после этого номер в строке «Порт» на вкладке «Настройки»: правило в роутере перестанет подходить."` (название строки — по 18б)
- `BTN_ACC_CHECK = "Проверить"`
- `ACC_CHECKING = "Проверяем…"`
- `ACC_CHECK_OK = "Похоже, работает: проверочный ответ сервера дошёл через роутер до этого компьютера. Программа будет вписывать этот доступ в приглашения."`
- `ACC_CHECK_FAIL = "Проверочный ответ не дошёл. Проверьте в правиле: протокол UDP, оба порта {port}, адрес компьютера {ip}, правило сохранено и включено. Затем снова нажмите «Проверить»."`
- `ACC_CHECK_LIMIT = "Проверка не даёт полной гарантии: некоторые роутеры пропускают ответ сервера, но не пропускают других. Окончательная проверка — подключение друга."` (мелко, при любом исходе)
- `ACC_CHECK_NO_SERVER = "Проверить автоматически можно только с вашим сервером, если он поддерживает проверку доступа (вкладка «Настройки», раздел «Связь через интернет»). Без этого нажмите «Правило создано» и попросите друга подключиться."`
- `BTN_ACC_DONE = "Правило создано"`
- `ACC_DONE = "Запомнили. Программа будет вписывать этот доступ в приглашения."`
- `ACC_MANUAL_FORWARD_LABEL = "Внешний номер, если правило в роутере вы создали сами с другим числом (обычно не нужно)"` (подпись строки `manual_forward` в настройках, только при П6 = а)
- Раздел настроек: `SET_TITLE_UPNP` переименовать в **«Доступ из интернета»** (П4). В начало раздела добавить кнопку `BTN_OPEN_ACCESS`. Список разрешённых роутеров и «Забыть» остаются.

Прочие тексты не меняются. `IP_WARNING` уже стоит на экране ожидания (`add_friend.rs:116`) [П]; по 18б его формулировка может измениться.

### Р9. Частота и согласие
- Сеть трогается только по «Создать приглашение», «Получить свой IP», «Попробовать автоматически» (только UPnP, по правилам 13а) и «Проверить». Без сохранённого сервера к серверу ни одного пакета.
- Исключение — поддержание адреса (Н1) у ждущего приглашения. Проб при запуске и по таймеру нет.
- Одна проба — не больше 12 датаграмм по 64 байта. Проверка доступа — не больше 3 запросов.

### Р10. Помощник «Открыть доступ из интернета»
1. **Автоматически (UPnP, условия 13а сохранены; П5 = а: кнопка остаётся).**
   - «Попробовать автоматически» вызывает `upnp_identify`. Это явное действие, поиск SSDP идёт только после нажатия.
   - Нашёлся роутер: вопрос `ACC_ASK_ROUTER`. «Разрешить» → `upnp_allow`. Без «Разрешить» ничего не открывается, пустой список по-прежнему значит «ни одного пакета UPnP».
   - Роутер уже разрешён: вопрос не задаётся, `refresh_mapping`.
   - Затем ожидание статуса до 10 с:
     - `Mapped` или `MappedPermanent`: `ACC_AUTO_OK`, затем автоматически «Проверить», если проверка есть;
     - `NeedPermanentConsent`: прежний вопрос 13а (`NEED_PERMANENT_TEXT`);
     - иначе `ACC_AUTO_FAILED` и ручные шаги.
   - Изменение `identify` (только читающее): `UpnpMapper::identify` возвращает `Identified { id: RouterId, lan_ip: Ipv4Addr }`; `lan_ip` — хост из проверенного LOCATION. `RouterCandidate` в ядре получает `pub fn lan_ip(&self) -> Ipv4Addr`.

     Тест редактирования 13а (`tests/redaction.rs`) продолжает требовать, чтобы IP роутера не попадал в `Debug` и тексты ошибок. Показ в помощнике — явный вывод по просьбе пользователя.
2. **Значения для ручных шагов (`Node::forward_help() -> ForwardHelp`, без сети):**
   - `port` = `listen_port()`;
   - `home`: домашние адреса этого компьютера, по порядку:
     - если последний `identify` дал `lan_ip`: `route_source_for(lan_ip:1)`, это точно;
     - иначе, если последняя проба дала `Bypassed` через кандидата `c`: `c`;
     - иначе: `private_sources(d)` без `d`, если `d` похож на туннель (класс не `Private`, или последняя проба `MaybeVpn`), иначе `[d] + остальные`;
     - не больше 4;
   - `gw`: `lan_ip` последнего `identify` (`exact = true`), иначе `a.b.c.1` по первому `home` (`exact = false`) [Д] — П1 = (а). Если `home` пуст — шаг 1 показывает только `ACC_GW_GUESS` без адреса;
   - `vpn` (последняя проба `Bypassed` или `MaybeVpn`) и `cgnat` (`nat_view`) — для пометок.

   Порт по умолчанию не меняется. Если `port_override` использован после `PortInUse`, показывается фактический порт (`ACC_PORT_NOTE`).
3. **«Проверить» (`Node::reach_check() -> Result<ReachResult, NodeError>`).**
   - Нужны сервер и известный порт проверки: при необходимости сначала `echo_probe`, порт проверки — из ответа.
   - Проверяемый порт: внешний порт UPnP-отображения, если статус `Mapped*`; иначе `manual_forward`; иначе `listen_port`.
   - Путь — как у последнего удачного эхо: по умолчанию или через кандидата.
   - Итоги:
     - `Reachable`: если проверяли порт ручного правила — `set_manual_forward(Some(port))` (П3 = а), затем `ACC_CHECK_OK`;
     - `NotReachable`: `ACC_CHECK_FAIL`;
     - `NoServer` или `ServerNoReach`: `ACC_CHECK_NO_SERVER`.
   - «Правило создано» → `confirm_manual_forward()` = `set_manual_forward(Some(listen_port))` (П3 = а).

   После этого приглашения содержат `ip:порт`: внешний IP от эхо и порт ручного правила (Р6, `plan_invite_external`).

### Р11. Охрана `gated_node_actions.rs` (поверх формы после 18б)
- Структура `Gate { command, intent_arms: &'static [&'static str], node_call, command_arms: &'static [&'static str] }`:
  - модель: `command` создаётся ровно в одном месте внутри каждой ветки из `intent_arms`, и больше нигде;
  - `worker_ops.rs`: `node_call` встречается только внутри веток из `command_arms`, по одному разу в каждой.
- Существующие элементы, включая добавленные 18б, переходят на массивы из одного элемента. Исключение — `UpnpIdentify`: `intent_arms = ["S::UpnpFind", "A::AccessAuto"]`.
- Новые элементы:
  - `{ "Command::EchoProbe", ["I::GetIp"], "echo_probe(", ["Command::EchoProbe", "Command::CreateInvite"] }`;
  - `{ "ExternalMode::Probe", ["I::AddCreate"], "echo_probe(", [..те же..] }` (один `node_call` на два элемента разрешён);
  - `{ "Command::ReachCheck", ["A::AccessCheck"], "reach_check(", ["Command::ReachCheck"] }`;
  - `{ "Command::ConfirmForward", ["A::AccessDone"], "confirm_manual_forward(", ["Command::ConfirmForward"] }`.
- Внутри ветки `Command::CreateInvite` вызов `echo_probe(` стоит только под `ExternalMode::Probe`. Это проверка по тексту ветки.
- Контрольный тест стража (`control_*_guard_can_fail`) дополняется:
  - лишний `echo_probe(` в третьей ветке ловится;
  - `Command::EchoProbe` вне `I::GetIp` ловится.

---

## 2. Интерфейс (точно)

```rust
// chervo-rendezvous-wire
pub const MAGIC: [u8; 4] = *b"CHRV"; pub const VERSION: u8 = 1;
pub const T_ECHO_REQUEST: u8 = 0x01; pub const T_ECHO_RESPONSE: u8 = 0x02;
pub const T_REACH_REQUEST: u8 = 0x03; pub const T_REACH_RESPONSE: u8 = 0x04;
pub const NONCE_LEN: usize = 16; pub const REQUEST_LEN: usize = 64; pub const RESPONSE_LEN: usize = 48;
#[derive(Clone, Copy, PartialEq, Eq)] pub struct Nonce(pub [u8; NONCE_LEN]); // Debug: "Nonce(..)"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError { Length, Magic, Version, Type, Flags, Padding, Nonce, Family, Port, Address }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request { Echo(Nonce), Reach { nonce: Nonce, target_port: u16 } } // Debug без nonce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response { pub observed: SocketAddr, pub reach_port: u16, pub reach: bool }
pub fn encode_echo_request(nonce: &Nonce) -> [u8; REQUEST_LEN];
pub fn encode_reach_request(nonce: &Nonce, target_port: u16) -> [u8; REQUEST_LEN];
pub fn parse_request(buf: &[u8]) -> Result<Request, WireError>;
pub fn encode_echo_response(nonce: &Nonce, observed: SocketAddr, reach_port: u16) -> [u8; RESPONSE_LEN];
pub fn encode_reach_response(nonce: &Nonce, observed: SocketAddr) -> [u8; RESPONSE_LEN];
pub fn parse_response(buf: &[u8], expected: &Nonce) -> Result<Response, WireError>;

// chervo-rendezvous-server
pub const PER_IP_BURST: u32 = 16; pub const PER_IP_WINDOW: Duration = Duration::from_secs(10);
pub const MAX_TRACKED: usize = 65_536; pub const GLOBAL_PER_SEC: u32 = 1000;
pub struct ServerConfig { pub listen: Vec<SocketAddr>, pub reach_port: Option<u16>, pub allow_private: bool, pub report_every: Duration }
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters { pub requests: u64, pub replies: u64, pub reach_replies: u64, pub malformed: u64, pub limited: u64, pub refused_source: u64, pub recv_errors: u64 }
pub fn serve(cfg: ServerConfig, stop: Arc<AtomicBool>, bound: impl FnOnce(Vec<SocketAddr>), report: impl FnMut(&Counters) + Send) -> io::Result<()>;
pub fn report_line(c: &Counters) -> String;
pub fn start_line(version: &str, listen: &[SocketAddr]) -> String;

// chervo-transport-quinn
pub const ECHO_MAX_PATHS: usize = 4; pub const ECHO_TRIES: u32 = 3;
pub const ECHO_RETRY: Duration = Duration::from_secs(1); pub const ECHO_DEADLINE: Duration = Duration::from_secs(3);
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum EchoError { Busy, BadServer, TooManyPaths, SocketFamily, Random }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum EchoPathResult { Observed { addr: SocketAddrV4, reach_port: u16 }, NoAnswer, SendFailed }
impl QuinnTransport {
    pub async fn echo_probe(&self, server: SocketAddrV4, sources: &[Option<Ipv4Addr>]) -> Result<Vec<EchoPathResult>, EchoError>;
    /// true: ответ проверки пришёл с IP сервера (порт ≠ server.port) за ECHO_DEADLINE.
    pub async fn reach_probe(&self, server: SocketAddrV4, source: Option<Ipv4Addr>, target_port: u16) -> Result<bool, EchoError>;
}

// chervo-connect
pub enum InviteAddrs { Auto { same_network: bool }, Manual(Vec<SocketAddr>), AutoWith { same_network: bool, extra: Vec<SocketAddr> } }

// chervo-upnp
pub struct Identified { pub id: RouterId, pub lan_ip: Ipv4Addr } // Debug: "Identified(..)"
impl UpnpMapper { pub fn identify(&self, own_ip: Ipv4Addr) -> Result<Identified, UpnpError>; }

// chervo-core (pub)
pub const ECHO_COOLDOWN: Duration = Duration::from_secs(10);
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(25);
pub enum EchoFailure { NotConfigured, BadAddress, Resolve, NoIpv4, Busy, Internal }
// NodeError += Echo(EchoFailure)
// NodeEvent += InviteAddressChanged { invite: InviteRef }
pub enum EchoVia { DefaultRoute, Interface(Ipv4Addr) }
pub enum EchoResult { Observed(SocketAddrV4), NoAnswer, SendFailed }
pub struct EchoPath { pub via: EchoVia, pub result: EchoResult }
pub enum EchoVerdict { Bypassed { real: SocketAddrV4 }, Single, MaybeVpn, ServerSeesPrivate, NoAnswer }
pub struct EchoReport { pub local_port: u16, pub paths: Vec<EchoPath>, pub verdict: EchoVerdict, pub reach_port: u16 }
pub enum SkipReason { NoAnswer, ServerLocal, Symmetric }
pub enum ExternalPlan { Add { addrs: Vec<SocketAddr>, vpn_on: bool }, AskVpn { addrs: Vec<SocketAddr> }, Skip(SkipReason) }
pub fn plan_invite_external(r: &EchoReport, nat: NatView, manual_forward: Option<u16>) -> ExternalPlan;
pub struct ForwardHelp { pub port: u16, pub home: Vec<Ipv4Addr>, pub gw: Option<Ipv4Addr>, pub gw_exact: bool, pub vpn: bool, pub cgnat: bool }
pub enum ReachResult { Reachable { port: u16 }, NotReachable { port: u16 }, NoServer, ServerNoReach }
impl RouterCandidate { pub fn lan_ip(&self) -> Ipv4Addr; }
impl Node {
    pub fn listen_port(&self) -> Option<u16>;
    pub fn set_echo_server(&self, server: Option<&str>) -> Result<(), NodeError>; // без сети
    pub fn echo_probe(&self) -> Result<EchoReport, NodeError>;
    pub fn create_invite_ext(&self, same_network: bool, extra: &[SocketAddr]) -> Result<(InviteRef, AddrToken), NodeError>;
    pub fn forward_help(&self) -> ForwardHelp;                                 // без сети
    pub fn reach_check(&self) -> Result<ReachResult, NodeError>;               // ≤ ~8 с
    pub fn confirm_manual_forward(&self) -> Result<(), NodeError>;
}
pub(crate) fn echo_verdict(paths: &[EchoPath], default_class: Option<AddrClass>, strong_host: bool) -> EchoVerdict;
```
Все новые публичные типы ядра имеют `Debug` без адресов (`"EchoReport(..)"` и т.п.), как прочие views. `apply_friend_text` и его типы — из 18б, здесь не меняются.

## 3. Сделать
**Шаг 0** (scout, web, medium, до кода). Отчёт до 30 строк дописать в конец этого файла, раздел «Сверка шага 0». Записать версию или дату и цитату. Если для Windows шаг опровергнет, что `ipi_addr` задаёт источник или ограничивает маршрут, — стоп.
1. https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg и https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
2. Microsoft, «Strong and Weak Host Models» (The Cable Guy): поиск по заголовку, URL мне неизвестен [Д].
3. https://man7.org/linux/man-pages/man7/ip.7.html и https://man7.org/linux/man-pages/man7/socket.7.html
4. sing-box: https://sing-box.sagernet.org/configuration/inbound/tun/ (`auto_route`, `strict_route`, что они делают на Windows). **У владельца sing-box 1.14.4, запускается через v2rayN 7.25.6 (Windows).** Сверить, что страница описывает ветку 1.14 (иначе журнал изменений 1.14: https://sing-box.sagernet.org/changelog/ ). По исходникам или документации v2rayN 7.25.6 (https://github.com/2dust/v2rayN) выяснить, включает ли v2rayN `strict_route` в своём шаблоне TUN по умолчанию. Если сведений нет — пометить, а владелец посмотрит в Р-2.
5. https://www.rfc-editor.org/rfc/rfc8489#section-14.2 , https://www.rfc-editor.org/rfc/rfc8085 , https://www.rfc-editor.org/rfc/rfc4787 (фильтрация и время жизни отображений: факт 13, Н1, ложный успех Р1).
6. https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4 и https://github.com/apple-oss-distributions/xnu (macOS). Отсутствие сведений — не стоп.

**Предусловие вызовов 1-3:** 18б слит в эту ветку (Р0).

**Вызов 1** (builder sonnet/high): Р1 и Р4.
- Крейты, их тесты, `fuzz_smoke`, `src_guard` сервера.
- Fuzz-цели `rdv_request` и `rdv_response` в `fuzz/`.
- `docs/ECHO_SERVER.md`.
- `members`, `workspace_layout`; `chervo-rendezvous-server` добавить в `FORBIDDEN` ядра (`[&str; 15]`).

**Вызов 2** (builder sonnet/high): Р5; `src_guard` транспорта; `AutoWith`; изменение `identify` в `chervo-upnp`; ядро по Р6 и Р10.2-3 с тестами; замена `NO_ADDRESS_TEXT`. Сервер подключается к тестам ядра только как dev-dependency.

**Вызов 3** (builder sonnet/medium): GUI по Р7, Р8, Р10, охрана Р11, модельные тесты.

**Затем:** ревью дирижёра по diff; `combine-security` (opus/high) по diff и разделу 6. Дирижёр сам перезапускает `cargo test -p chervo-transport-quinn --locked echo` и `cargo test -p chervo-core --locked --test echo_net`.

## 4. Не делать
- Не задавать сервер по умолчанию. В текстах допустимы только документационные адреса 203.0.113.5 и 198.51.100.7 (RFC 5737 [Д]).
- Не обращаться к серверу и к роутеру вне действий из Р9.
- Не делать UPnP без «Разрешить» и без кнопки: условия 13а неизменны.
- Не передавать результат эхо в `OwnAddrs`, `nat_view`, книгу, новый адрес друга, `AddressUpdate`, `ADDR_INFO`, ограничитель. Он идёт только в приглашение (Р6) и `manual_forward` (Р10.3).
- Не добавлять внешние пакеты и features. Без `unsafe`, без опций на весь сокет, без перечисления адаптеров и таблицы маршрутов, без `/proc`, `/sys`, без запуска `route`, `ipconfig`, `netsh` (П1 = а).
- Не открывать допуск адресу сервера и не отвечать ему.
- Не менять формат, подпись и лимиты приглашения.
- Не трогать поля вставки и `apply_friend_text` (18б).
- Не трогать `release.yml`, `assemble.sh`, установщики, CLI и `chervo-gui/Cargo.toml`. `create_invite(..)` оставить как есть.
- Сервер: не писать на диск, не печатать IP, не хранить адреса дольше окна лимита. Слать только ответ на IP источника. Без tokio и логгера.
- В коде не должно быть строк из `check-forbidden.sh`.

## 5. Недоверенный ввод
- **Сервер:** любое отклонение формата или длина, отличная от 64, — молча отбросить (`malformed += 1`). Порядок проверок: источник, затем лимит, затем формат. Для проверки доступа целевой порт ≠ 0, адресат — только IP источника.
- **Клиент:** только 48-байтные сегменты во время пробы. Для эхо — с точного `ip:порт` сервера, для проверки — с IP сервера и другого порта; в обоих случаях с nonce текущей пробы. Наблюдаемый адрес: IPv4, порт ≠ 0, допустимый класс. `reach_port` из ответа используется только как признак (0 — нет) и не служит адресатом: наш запрос проверки идёт на основной порт сервера.
- **Настройки** разбираются строго. Поле адреса не длиннее 259 символов.
- **DNS:** не больше 8 адресов, первый IPv4.
- **`lan_ip` роутера** получен из уже проверенного LOCATION (13а) и только показывается.
- **Fuzz:** `fuzz_smoke_request` и `fuzz_smoke_response` по 1M итераций. Цели libFuzzer — на Linux-машине владельца, до прогона «не проверено».

## 6. Модель угроз: T22 «Эхо-сервер, внешний адрес в приглашении, помощник доступа» (внести при закрытии)
- **Меры:**
  - ложный адрес от сервера или с пути попадает в приглашение. Приглашённый стучит по нему: не больше 4 раз за 10 с на IP, пока жив токен; после дружбы адрес строгий, 32 с, 30 суток (T1). KK не пройдёт, итог — только отказ соединения [В];
  - подделка ответа вне пути требует nonce;
  - ответ меньше запроса, лимиты Р4, по умолчанию отвечаем только публичным адресам;
  - во время пробы забираются только точные ответы, допуска нет (`echo_does_not_admit`);
  - при `MaybeVpn` адрес VPN без кнопки в приглашение не попадает;
  - UPnP — только с «Разрешить» (T16 без изменений).
- **Проверка доступа:**
  - сервер шлёт 48 байт на IP источника и порт из запроса. Подделывателю источника это даёт не больше, чем обычное эхо: тот же лимит на IP, ответ меньше запроса [В];
  - ложный «работает» (лгущий сервер или роутер, фильтрующий только по IP) ведёт к записи `manual_forward`. Итог — лишний адрес в приглашениях и отказ соединения, если друг не дойдёт [В].
- **Остаётся:**
  - сервер видит настоящий IP, время и факт работы программы;
  - при обходе VPN настоящий IP видят провайдер и любой, кто увидит приглашение (T8);
  - резолвер видит имя сервера;
  - адрес сервера хранится в `settings.v1`;
  - эвристика VPN ошибается;
  - при VPN (факт 12) и при фильтрующем роутере без проброса (факт 13) внешний адрес не помогает;
  - открытый вручную порт остаётся открытым, пока человек сам не удалит правило в роутере, но молчит для чужих (стук, T1);
  - DoS таблицы лимитов сервера.

## 7. Критерии приёмки (каждый проверяется командой)
- [ ] Предусловие: `git log --oneline` содержит слитый 18б; `cargo test --workspace --locked` зелёный до начала 13д.
- [ ] `cargo build --workspace --locked`
- [ ] `cargo test -p chervo-rendezvous-wire --locked`. Проходят:
  - кругооборот: `echo_request_roundtrip`, `reach_request_roundtrip`, `echo_response_roundtrip_v4`, `echo_response_roundtrip_v6`, `reach_response_roundtrip`, `mapped_v6_encoded_as_v4`;
  - `response_shorter_than_request`, `xor_hides_plain_address`;
  - отказы: `request_rejects_each_field` (длины 0, 63, 65; магия; версии 0 и 2; тип; флаги; паддинг; `target_port` 0), `response_rejects_each_field` (чужой nonce, семейство 5, порт 0, адреса 0.0.0.0, 224.0.0.1, 255.255.255.255, ненулевой хвост);
  - `fuzz_smoke_request`, `fuzz_smoke_response`.
- [ ] `cargo test -p chervo-rendezvous-server --locked`. Проходят:
  - `answers_valid_request`, `echo_response_announces_reach_port`;
  - `reach_reply_from_second_port_to_target_port`, `reach_without_flag_dropped`, `reach_target_port_zero_dropped`;
  - `refuses_private_source_by_default`, `allow_private_answers_loopback`, `drops_malformed`;
  - лимиты: `rate_limit_per_ip_shared_echo_and_reach` (17 → 16), `global_limit`, `tracked_cap_new_key_limited`, `ipv6_key_is_slash64`;
  - `report_line_has_no_addresses`, `args_reject_unknown`;
  - `src_guard`: нет `fs::`, `File::`, `OpenOptions`, `log::`, `tracing`, `process::Command`, `TcpListener`, `TcpStream`, `to_socket_addrs`, `tokio`; ровно 2 вызова `send_to(`; печать только в `main.rs` через `start_line(`, `report_line(` и `USAGE`.
- [ ] `cargo test -p chervo-transport-quinn --locked echo`. Проходят:
  - `echo_loopback_default_path`, `echo_loopback_src_ip`;
  - отбраковка: `echo_wrong_nonce_ignored`, `echo_wrong_source_port_ignored`, `echo_malformed_replies_ignored`;
  - сроки и повторы: `echo_retries_until_answer`, `echo_no_answer_within_deadline` (≤ 3,1 с);
  - `echo_busy`, `echo_bad_server`, `echo_does_not_admit`, `echo_during_friend_connection`;
  - проверка доступа: `reach_probe_loopback_ok`, `reach_probe_reply_from_main_port_rejected`, `reach_probe_other_ip_rejected`;
  - `src_guard`: `encode_echo_request(`, `encode_reach_request(` и `parse_response(` только в `echo.rs`; `send_echo(` объявлен в `knock.rs` и вызывается только из `echo.rs`; `try_send(` только в `knock.rs`.
- [ ] `cargo test -p chervo-lan --locked private_sources_matches_sweep`
- [ ] `cargo test -p chervo-upnp --locked`: `identify_returns_lan_ip_of_location`, прежние тесты, включая `redaction`, зелёные.
- [ ] `cargo test -p chervo-connect --locked`: `invite_auto_with_extra_first_dedup_cap`, прежние зелёные.
- [ ] `cargo test -p chervo-core --locked`. Проходят:
  - настройки и проба: `settings_echo_roundtrip`, `echo_server_default_none`, `set_echo_server_validation`, `echo_verdict_table`, `echo_not_configured_sends_nothing`, `echo_cooldown_returns_cached`, `listen_port_is_actual`;
  - приглашение: `plan_invite_external_table`, `create_invite_ext_puts_extra_first`, `keepalive_stops_on_sas_cancel_expiry`, `keepalive_change_emits_event`, `no_address_text_names_actions` (В4: в тексте есть «Открыть доступ из интернета» и «Связь через интернет»);
  - помощник: `forward_help_values` (с `lan_ip`, с `Bypassed`, без; угадывание `a.b.c.1`), `reach_check_sets_manual_forward_on_success`, `reach_check_no_server`, `confirm_manual_forward_sets_listen_port`;
  - `tests/echo_net.rs`: `node_echo_probe_loopback`, `node_invite_with_external_loopback`, `node_reach_check_loopback`;
  - стражи `layout`, `anchored_only`, `no_logger`; тесты 18б по `apply_friend_text` по-прежнему зелёные.
- [ ] `cargo test -p chervo-gui --locked`. Проходят:
  - стражи: `gated_node_actions` (форма Р11 поверх 18б, контрольные случаи), `uses_node_api_only`, `manifest_only_core`, `no_fs_writes`, `ui_thread`;
  - модель приглашения: `invite_without_server_creates_plain_and_hints`, `invite_probe_only_from_create_button`, `invite_add_shows_small_address_and_tip`, `invite_vpn_on_warns`, `invite_maybe_vpn_needs_explicit_answer`, `invite_skip_reasons_texts`, `invite_no_addresses_shows_open_access`;
  - «Получить свой IP»: `get_ip_button_disabled_without_server_and_hint`, `get_ip_shows_copy_and_vpn_marks`;
  - помощник: `access_auto_asks_before_allow` (без «Разрешить» нет `UpnpAllow`), `access_manual_steps_have_copy_values`, `access_check_texts`, `access_done_only_from_button`;
  - С8 и В5: `open_access_on_invite_and_diagnosis` (кнопка на «Пригласить» и у друга с причиной NAT/CGNAT в «Диагностика»); при П6 = а — `invite_form_has_no_manual_field`;
  - `echo_server_save_and_clear`;
  - `texts_name_tab_and_button`: каждый текст Р8 с действием содержит название вкладки, раздела или кнопки; ни один не содержит «токен», «NAT», «эхо»; слова «порт» и «UDP» только в `ACC_*`, `GETIP_RESULT` и примерах.
- [ ] Проверка 18б п.8 после 13д: `grep -rn "токен\|Токен" crates/chervo-gui/src/texts.rs crates/chervo-core/src/node/texts.rs` — 13д не добавил ни одного вхождения.
- [ ] `cargo test --workspace --locked`: 0 failed.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --check`; `bash scripts/check-forbidden.sh` и `--self-test`.
- [ ] Новых внешних пакетов нет:
  - `git diff <база> -- Cargo.lock | grep '^+name'` — только два новых крейта;
  - `cargo tree -p chervo-rendezvous-wire -e normal --depth 1` — пусто;
  - `cargo tree -p chervo-rendezvous-server -e normal --depth 1` — `chervo-rendezvous-wire`, `chervo-addr`;
  - `cargo tree -e normal -i chervo-rendezvous-server` для `-p chervo-core` и `-p chervo-gui` — не найдено.
- [ ] CI на 3 ОС, включая supply-chain, зелёный. `cargo fuzz build` двух целей на Linux-машине владельца: до прогона «не проверено».

**Ручные проверки (владелец, одним заходом):**
- **Р-1.** Сервер с `--reach-port` на хосте с белым IP вне сети клиента. Windows без VPN: в приглашении внешний IP, совпадает с WAN-адресом роутера. Друг из другой сети подключается (записать, с пробросом или без).
- **Р-2.** Windows, v2rayN 7.25.6 с sing-box 1.14.4 в режиме TUN: `Bypassed`, предупреждения на месте. `pktmon` показывает запрос в Ethernet. Записать значение `strict_route` в настройках TUN v2rayN. После исключения программы в v2rayN друг подключается.
- **Р-3.** Linux с VPN: `MaybeVpn`.
- **Р-4.** macOS: записать результат.
- **Р-5.** Журнал сервера без IP клиентов.
- **Р-6.** Помощник на домашнем роутере.
  - (а) UPnP включён: «Попробовать автоматически» → «Разрешить» → «Готово» → «Проверить» = работает.
  - (б) UPnP выключен: ручные шаги со значениями программы → «Проверить» = работает; удалить правило → «Проверить» = не дошёл.
  - Записать, совпал ли угаданный адрес страницы роутера.
- **Р-7.** Владелец читает все тексты Р8 на экране и подтверждает, что понятно, куда нажимать.
- Стенд netns по желанию: `MaybeVpn` при двух маршрутах по умолчанию. Проверка доступа: с пробросом DNAT — работает; без него, при фильтрации conntrack, — не дошёл.

**Стоп-условия:**
- противоречие спецификации и коду или 18б;
- 18б не слит;
- шаг 0 опроверг поведение Windows;
- нужен новый пакет, feature, `unsafe`, опция на весь сокет или таблица маршрутов;
- `echo_loopback_src_ip` падает на ОС CI (не прятать за `cfg`);
- ломаются тесты стука, 13а или 18б;
- понадобилось менять формат приглашения;
- критерий непроверяем.

**Лимит:** 2 круга правок.

**Отчёт:** до 25 строк: файлы; команды и последние строки вывода; что не сделано; отклонения.

---

## Для владельца (кратко)
- Один раз впишите адрес сервера: «Настройки» → «Связь через интернет». Дальше «Создать приглашение» само вписывает ваш адрес в интернете. Кнопка «Получить свой IP» показывает его с «Копировать».
- Кнопка «Открыть доступ из интернета» есть на экране приглашения, в «Диагностике» и в настройках. Она ведёт к помощнику:
  - сначала программа просит роутер сама: вы один раз нажимаете «Разрешить», без вашего «да» к роутеру ничего не идёт;
  - если роутер не согласился, вы видите пять шагов: все значения программа подставляет сама, у каждого кнопка «Копировать»;
  - «Проверить» работает с вашим сервером и честно говорит, что полной гарантии нет.
- Адрес страницы роутера точно известен, только если роутер ответил на автоматическую попытку. Иначе программа показывает обычный адрес и подсказывает посмотреть наклейку.
- VPN: пока он включён, друг не подключится. Программа говорит это прямо.

## Решения владельца по спорным местам (2026-11-18)
- **П1 = (а):** адрес страницы роутера без ответа UPnP — обычный `a.b.c.1` с подсказкой про наклейку; таблицу маршрутов не читаем.
- **П2 = (а):** проверка доступа вторым портом сервера (`--reach-port`), с честным текстом про возможный ложный успех.
- **П3 = (а):** после удачной проверки или «Правило создано» программа сама запоминает ручной проброс.
- **П4 = (а):** раздел «Проброс порта на роутере» переименован в «Доступ из интернета», вопрос о роутере упрощён с прежним предупреждением.
- **П5 = (а):** автоматическая попытка — по кнопке «Попробовать автоматически» и одному «Разрешить» на роутер; решение 13а не меняется.

## Спорное для владельца
**П6. Поле «Свой адрес с пробросом порта» на экране приглашения (В5 из ревью GUI).**
- (а) Убрать с экрана приглашения. IP программа берёт у сервера, ручной проброс записывает помощник. Для редкого случая «моё правило в роутере с другим внешним номером» остаётся одна строка в «Настройки» → «Доступ из интернета».
- (б) Оставить поле. Рядом показывать номер программы и адреса домашней сети с «Копировать»; если вписан только IP, номер подставлять самому.

**Рекомендую (а):** с помощником и сервером человеку не нужно ничего вписывать, а поле — главный источник непонятности (жалоба владельца, В5).

## Сверка шага 0 (2026-11-18, агент с вебом, только чтение)
Итог: Windows не опровергнута, но и не подтверждена прямо; стоп-условие не сработало. Решает замер Р-2 на машине владельца.
- [П] Windows `in_pktinfo`: ipi_addr — «local source IPv4 address to set in the IP header»; ipi_ifindex — «The interface on which the packet should be sent» (learn.microsoft.com, ws2ipdef/ns-ws2ipdef-in_pktinfo, upd. 2024-02-22). WSASendMsg (upd. 2024-02-22) — то же.
- [П] `IP_UNICAST_IF` — «Gets or sets the outgoing interface for sending IPv4 traffic»; индекс в сетевом порядке байт (winsock/ipproto-ip-socket-options, upd. 2026-05-07). Документированная альтернатива; builder: предусмотреть как запасной путь, если замер Р-2 покажет, что ipi_addr не уводит пакет мимо tun.
- [П] Strong host по умолчанию на Vista+ (WeakHostSend = FALSE), «route lookup is restricted to the interface of the source IP address» (windows-hardware/drivers/network/mib-ipinterface-row, 2022-10-25). Применимость к WSASendMsg — вывод, не прямой текст. Оригинал статьи Cable Guy не открылся (404) [НП].
- [НП] Перехват пакета драйвером tun/WFP sing-box после выбора маршрута — в документации нет; только замер.
- [П] Linux `in_pktinfo(2type)` (man-pages 6.19): при sendmsg источник задаёт ipi_spec_dst, ipi_addr игнорируется; ненулевой ipi_ifindex выбирает интерфейс. Builder: проверить, какое поле заполняет quinn-udp 0.5.16 при отправке.
- socket(7) (6.19): про CAP_NET_RAW для SO_BINDTODEVICE текста нет — права не доказаны ни в одну сторону.
- [П] sing-box tun (страница без явной метки 1.14): auto_route ставит маршрут по умолчанию в tun; strict_route (изм. 1.13.3) на Windows закрывает неподдерживаемые сети. exclude_process в tun нет; исключение по процессу — в route rules (на уровне маршрутизации sing-box). Включает ли v2rayN strict_route — не выяснено.
- [П] RFC 4787 REQ-1 (EIM), REQ-5 (не меньше 2 мин, рекоменд. 5 мин), REQ-6 (исходящие обновляют привязку), §5 EIF/ADF. RFC 8085 §3.5: keepalive не чаще раза в 15 с — интервал 25 с (Н1) допустим. RFC 8489 §14.2: XOR «obfuscated»; причина (ALG) — догадка.
- macOS: FreeBSD ip(4) IP_SENDSRCADDR [П]; Apple ip(4) не открылся; IP_BOUND_IF [НП].
