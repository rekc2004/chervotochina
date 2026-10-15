# SPIKE_TRANSPORT: спайк транспорта, этап 7 (вариант A и вариант B)

Спецификация: `docs/specs/stage-07-spike.md`. Код: `spikes/transport/` (одноразовый, не член workspace). Часть 1: вариант A (iroh 1.3.0), часть 2: вариант B (quinn 0.11.12 + rustls 0.23.46).
Метки: [П] проверено запуском в нашем стенде; [П-ч] проверено чтением исходника; [НП] не проверено.

## 1. Шапка
- Дата: прогоны A 2026-10-14/15, прогоны B 2026-10-15. Код спайка: A `7ddf7fa`, B `b01ccea` (spike-b), `1528c43` (run.sh для B и логи прогона B); ветка `claude/hopeful-hawking-2sacz9`, база `664d4bd`.
- `rustc 1.97.0 (2d8144b78 2026-07-07)`, `uname -r`: `6.18.44-fc-v114`, `tcpdump 4.99.4`, `nftables v1.0.9`.
- Версии: iroh 1.3.0, noq 1.3.0, quinn 0.11.12, quinn-proto 0.11.19, ed25519-dalek 3.0.0, getrandom 0.4.3. `cargo tree --locked -i rustls`: одна версия `rustls v0.23.46` (её тянут iroh, noq, quinn и сам спайк). `cargo tree -d`: дубликаты только вспомогательных крейтов (base64 0.22.1/0.23.1, cpufeatures 0.2.17/0.3.1 и подобные), на крипто-путь не влияют. Полный вывод обеих команд: `spikes/transport/logs/versions.txt`.
- **Эмуляция netns, не реальные операторы и не ТСПУ.**
- **Ограничение стенда: в ядре выключен IPv6** (`ipv6.disable=1` в командной строке, нет `/proc/net/if_inet6`, `ip addr add fd77::..` даёт `Operation not supported`). Все IPv6-части стенда и ворот пропущены (см. G2 и разд. 6).
- Захваты `cap-*.pcap` лежат локально в `spikes/transport/logs/<a|b>/<ворота>/` и не коммитятся (кроме `g12-a.pcap` 70 КБ и `g12-b.pcap` 54 КБ). Полные `server.log` G3 (до 12 тыс. строк) тоже не коммитятся: сводка в `g3/incoming-stats.txt`.

## 2. Сводка по воротам
| Ворота | A (iroh 1.3.0) | B (quinn 0.11.12 + rustls) | доказательство |
|---|---|---|---|
| G1 нет трафика третьим сторонам | PASS | PASS | `spikes/transport/logs/{a/g1/{nopm,pm},b/g1/main}/result.txt` |
| G2 только адрес (id/Ip у A; Ip у B) | INCONCLUSIVE (IPv4 2/2 ok; IPv6 не запускался) | INCONCLUSIVE (IPv4 2/2 ok; IPv6 не запускался) | `spikes/transport/logs/{a,b}/g2/result.txt` |
| G3 пиннинг/лимит/CPU | PASS | PASS | `spikes/transport/logs/{a,b}/g3/` |
| G9 (только B) | не применимо | PASS | `spikes/transport/logs/b/g9/p{1..5}.txt` |
| G10 экспортёр и аутентификация | PASS | PASS | `spikes/transport/logs/{a,b}/g10/part{1,2,3,4}.txt` |
| G11 одноразовый ключ сервера | **FAIL** | PASS | `spikes/transport/logs/a/g11/evidence.txt`, `spikes/transport/logs/b/g9/p1.txt` |
| G12 что видит наблюдатель | PASS | PASS | `spikes/transport/logs/{a,b}/g12/observe.txt` |

Итоги скрипта (`spikes/transport/logs/{a,b}/summary.txt`) совпадают с таблицей. Оговорка по G2 в обоих столбцах: INCONCLUSIVE только из-за выключенного в ядре стенда IPv6 (см. разд. 6); IPv4-часть пройдена полностью.

## 3. Решение
**DECISION B** (вывод `bash spikes/transport/run.sh decide a` и `decide b`): у A провален G11 (FAIL), поэтому по DECISION 2.4 и U23 выполнен автоматический переход на вариант B без вопроса владельцу; у B нет ни одного FAIL, G1, G3, G9, G10, G11, G12 дали PASS. G2 у обоих вариантов INCONCLUSIVE только из-за выключенного IPv6 в стенде: по решению дирижёра это фиксируется и переход/выбор не блокирует (в `decide` INCONCLUSIVE с причиной "IPv6 в ядре" не считается блокирующим; любой иной INCONCLUSIVE блокировал бы). Вариант B выбран; IPv6-часть G2 для B остаётся непроверенной (разд. 6).

## 4. Ворота подробно
Прогоны A: `bash spikes/transport/run.sh all a` (код возврата 0), затем `g3` повторён отдельно после добавления сводки `incoming-stats.txt`. Прогоны B: разд. 4B ниже. Время `t=` в мс от старта процесса.

## 4A. Вариант A (iroh 1.3.0)

### G11 (A): одноразовый ключ сервера. Вердикт FAIL
Команда: `run.sh g11 a`. Критерий: PASS только если в публичном API iroh 1.3.0 найден путь без форка, где на одном сокете каждое соединение получает новый ключ сервера и клиент подключается, не зная его заранее.
- Статика (`g11/pub_fn.txt`, 104 `pub fn` в `endpoint/quic.rs` и `endpoint.rs`). Методы про крипто/ключи (15 штук в `g11/candidates.txt`): `secret_key` (один ключ endpoint на всё время жизни), `crypto_provider` (набор алгоритмов rustls, не ключ), `tls_config` (геттер клиентского конфига), `ca_tls_config`, `keylog`, `max_tls_tickets`, `set_token_key` (ключ токенов Retry), `create_server_config_builder`, `peer_identity`, `export_keying_material`, `dns_resolver`, `crypto_buffer_size`. Неизвестных кандидатов нет (`candidates-unknown.txt` пуст). У `ServerConfigBuilder` только `set_transport_config`, `set_validation_token_config`, `set_token_key`, `set_retry_token_lifetime`, `set_max_incoming`, `set_incoming_buffer_size[_total]`, `set_time_source`: сеттера крипто-ключа нет. Резолвер сервера строится один раз при `bind` из `SecretKey` endpoint (`tls.rs:61`, `tls/resolver.rs`) [П-ч].
- (2) Клиент с верным адресом и чужим валидным `EndpointId`: `client_result hs_error err="...invalid peer certificate: UnknownIssuer"`, на сервере `hs_done` от этого адреса 0 [П]. Значит клиент обязан знать ключ сервера заранее.
- (3) Второй `server` на тот же порт: `ERROR Failed to bind sockets`, код выхода 2 [П]. Одноразовый endpoint на соединение означал бы новый сокет, то есть новый порт, которого клиент не знает.
- Вердикт FAIL подтверждает факт 4 спецификации. Форк/патч iroh не делались.
Выдержка (`g11/evidence.txt`): `second_server_exit_code=2 bind_error=1 stderr: ERROR Failed to bind sockets`; `g3a_server_hs_done_from_a: 0`.

### G1 (A): нет трафика к третьим сторонам. Вердикт PASS
Команда: `run.sh g1 a`: два прогона по 60 с + 30 с простоя; сборка без фичи (`PortmapperConfig::Disabled`) и `--features iroh-portmapper`. На 30-й секунде в `chv-a` добавлен 10.77.1.3/24 и удалён 10.77.1.2/24. Критерий: `dns=0`, `other=0`, без порт-маппера `portmap=0`, `fwd_drop=0`, кортежи вне списка пусты (`analyze_g1.sh`), `peer>0`.
```
nopm: nft a: dns=0 peer=4724 nd=0 mcast_kernel=0 portmap=0 other=0 | b: dns=0 peer=4015 ... portmap=0 other=0 | r: fwd_ok=8739 fwd_drop=0
      analysis a: VIOLATIONS 0   analysis b: VIOLATIONS 0
pm:   nft a: dns=0 peer=4752 ... portmap=1 other=0 | b: dns=0 peer=4008 ... portmap=1 other=0 | r: fwd_ok=8760 fwd_drop=0
      analysis a/b: VIOLATIONS 0 (разрешены SSDP 239.255.255.250:1900 и шлюз:5351)
client: EVENT app_ok t=60091 bytes=38731776 echo_eq=1
        EVENT after_idle t=90105 conn_alive=1 probe_ok=1
```
С порт-маппером наблюдается один пакет SSDP на сторону (`10.77.1.2 > 239.255.255.250.1900` в a, аналогично в b), он входит в разрешённый список. DNS-запросов нет ни в одном прогоне (в том числе в системный резолвер из `/etc/netns/chv-*/resolv.conf`). [П]

### G2 (A): прямое соединение только по `EndpointAddr{id, Ip}`. Вердикт INCONCLUSIVE
Команда: `run.sh g2 a`. Критерий: 4 соединения (LAN v4/v6, routed v4/v6) `auth_ok` и `app_ok echo_eq=1`, нет ошибок lookup/discovery/relay, счётчики как в G1.
```
ok=2 из 2 запущенных; пропущено: lan6 routed6 (IPv6 в ядре выключен)
-- lan4:    app_ok bytes=1048576 echo_eq=1  client_result ok
-- routed4: app_ok bytes=1048576 echo_eq=1  client_result ok
nft a: dns=0 peer=242 other=0 | b: dns=0 peer=223 other=0 | r: fwd_ok=465 fwd_drop=0 ; net_fail=[] lookup_errs=[]
```
IPv4-часть пройдена и чиста, две IPv6-части не запускались: IPv6 в ядре стенда выключен. По спецификации это INCONCLUSIVE (не PASS), решение за дирижёром (разд. 6, 8).

### G3 (A): пиннинг, лимит, CPU. Вердикт PASS
Команда: `run.sh g3 a`. 
- (а) Верный адрес, чужой валидный id: `hs_error ... UnknownIssuer`, `hs_done` от адреса клиента на сервере 0. (б) Закрытие до прикладных байт засчитано в G10.
- (в) Лимит 5 рукопожатий за 10 с на IP; `flood` из `chv-c` (10.77.3.10-12, 20 попыток/с на IP, 30 с, знает id сервера), одновременно друг `--repeat 5`:
```
сервер: retry=1799, ignore=~10.5 тыс. событий incoming (повторы Initial у отброшенных)
hs_done по IP за 30 с: 10.77.3.10=15, .11=17, .12=20; макс. в окне 10 с: 5, 6, 5 (порог ≤6)
друг: auth_ok conn=1..5, dur_ms = 32, 31, 30, 30, 30 (порог ≤2000)
```
CPU сервера (тики процесса за 30 с, CLK_TCK=100, порога нет, числа не оценивались): простой 0 тиков (0.00% ядра); флуд с лимитом 136 тиков (4.53%); флуд `--no-limit` 312 тиков (10.40%), принято 1803 рукопожатия (`g3/cpu.txt`; в предыдущем прогоне того же сценария было 146 и 331 тик, один замер на режим, разброс не оценивался). [П]

### G10 (A): экспортёр TLS и аутентификация после рукопожатия. Вердикт PASS
Команда: `run.sh g10 a` (сервер `--no-limit`, чтобы лимит G3 не мешал частым подключениям).
1. `ok` дважды: `ekm` клиента и сервера совпали в обоих соединениях (`da92637a...` и `0be7a99b...`), между соединениями различны (`g10/part1.txt`).
2. Режимы, сервер `auth_fail ... app_bytes_read=0`, клиент `app_bytes_received=0`:
```
bad-sig reason=sig | wrong-pair reason=pair | wrong-key reason=sig | other-conn reason=sig
wrong-role reason=role | timeout reason=timeout (5 с) | too-long reason=len | early-app reason=timeout (app_bytes_sent=256 клиентом)
```
3. Сервер `--bad-auth2`: клиент `auth_fail reason=peer_sig app_bytes_sent=0`.
4. MITM в 10.77.3.20: `mitm ekm down=0d28fce9... up=4e65566c...` (различны), сервер `auth_fail reason=sig app_bytes_read=0`, клиент `app_bytes_received=0 app_bytes_sent=0`.
`app_bytes_read=0` печатается сервером по построению: до успеха auth второй поток не принимается и не читается. Проверка "ни байта" клиентской стороной даёт `early-app`: 256 байт во второй поток, сервер их не принимает (причина `timeout`).
Первый полный прогон дал FAIL именно по `early-app` (`reason=closed` вместо `timeout`): клиент закрыл соединение по своему 5-секундному ожиданию одновременно с серверным таймаутом (гонка стенда). Ожидание клиента в `early-app` поднято до 12 с, как в `timeout`; критерий не менялся. После правки 3 отдельных прогона `g10` на старой сборке и итоговый `all a` на новой: PASS.

### G12 (A): что видит наблюдатель. Вердикт PASS
Команда: `run.sh g12 a`: захват `tcpdump -i rb -s 0 udp` в `chv-r`, клиент `ok` дважды (пары 1 и 2), сервер с лимитом (есть Retry). `g12-observe --pcap g12-a.pcap --needles needles.txt --alpn chervo-spike/1 --version 1`:
```
OBSERVE datagrams=95 quic_initial=8 client_decrypted=6 server_decrypted=2 skips=0
QUIC versions=[1] client_dcid_lens=[8, 20] client_scid_lens=[8] alpn_found=1
CONN 0 client_scid=cb38f465ff662f12 first_dcid=9b2a4c3f1544525d97d5afd4365a7a0311fd17ae
CONN 1 client_scid=d902837031d84666 first_dcid=973238457f8c86d2e1f063d4e1b31731ecf600db
RESULT PASS совпадений нет; положительные контроли выполнены
```
Иглы: публичные ключи пар (звонящий и вызываемый, обе пары), pair_id обеих пар, `EndpointId` сервера, клиента и MITM, строка `iroh.invalid`; в сыром UDP всех пакетов и в расшифрованных Initial обоих направлений совпадений нет. QUIC v1; клиентский начальный DCID 20 байт, SCID 8 байт, CID сервера 8 байт; ALPN `chervo-spike/1` найден в расшифрованном Initial клиента (положительный контроль); AEAD прошёл для 2 Initial сервера. Handshake-пакеты пассивно не расшифровать [В]. Игла `uname -n` (`vm`, 2 байта) слишком коротка для осмысленного поиска, пропущена со `SKIP reason=needle_too_short` (разд. 6).

## 4B. Вариант B (quinn 0.11.12 + rustls 0.23.46)
Прогон: `bash spikes/transport/run.sh all b` (код возврата 0), порядок G1, G2, G3, G9, G10, G12; G11 считается внутри `g9`. Устройство B (`src/bin/spike-b.rs`, `src/tlsb.rs`): TLS 1.3 только, голые публичные ключи (RFC 7250), `enable_sni=false`, `Resumption::disabled()`, `enable_early_data=false`, сервер `max_early_data_size=0`, `send_tls13_tickets=0`, `NoServerSessionStorage`. На каждое входящее: новый seed (`getrandom`) → `ed25519_dalek::SigningKey` → `to_pkcs8_der` → `ring::sign::any_eddsa_type` → новый `rustls::ServerConfig` → `quinn::Incoming::accept_with`. Клиент без пиннинга: `dangerous().with_custom_certificate_verifier`, подпись рукопожатия проверяет `verify_tls13_signature_with_raw_key`. [П] ring принял PKCS#8 от dalek (стоп-условие не сработало); экспортёр `export_keying_material` с меткой и пустым контекстом работает на обеих сторонах (юнит-тест `b_loopback_ekm_equal_and_server_keys_differ` и G10). Тот же `auth.rs`, что в A.

### G11 и G9 (B): одноразовый ключ сервера. Вердикты G11 PASS, G9 PASS
Команда: `run.sh g9 b`. Критерий G9: (1) 3 соединения дают 3 разных `server_spki`; (2) `peer_identity none` на сервере; (3) `--tls-key-mismatch` (SPKI от K2, подпись K1) даёт `hs_error`; (4) повторное соединение: `into_0rtt` даёт `zero_rtt refused`; (5) `with_protocol_versions(&[&rustls::version::TLS13])` в коде обеих сторон. G11 для B = пункты 1-2.
```
(1) клиент увидел SPKI (последние 4 байта): ...f9af2bce, ...9cd7f904, ...1c26b44 -> 3 разных (итоговый прогон);
    все три есть среди server_spki_issued на сервере; всего выдано 5 разных SPKI (3 + 2 соединения zrtt), один сокет :4433
(2) EVENT peer_identity ... none conn=1..3 (none=3, some=0)
(3) EVENT client_result hs_error err="the cryptographic handshake failed: error 51: invalid peer certificate: BadSignature"
(4) EVENT zero_rtt t=304 refused why=no_0rtt_keys   (into_0rtt вернул Err: ключей 0-RTT нет)
(5) src/tlsb.rs:49 и :118 с with_protocol_versions(&[&rustls::version::TLS13]): 2 (сервер, клиент)
```
Ключ сервера на соединение реально разный (проверено по SPKI на обеих сторонах). Вердикт G11 для B: на одном сокете (один `Endpoint`, одно `quinn::Endpoint::server`) каждое соединение получило новый ключ сервера, клиент подключался, не зная его заранее. Значения выше из итогового прогона; полные выдержки в `g9/p1.txt`..`p5.txt`. [П]

### G1 (B): нет трафика к третьим сторонам. Вердикт PASS
Команда: `run.sh g1 b`, один прогон: 60 с передача по 64 КиБ каждые 100 мс, 30 с простоя, на 30-й секунде в `chv-a` 10.77.1.2 → 10.77.1.3. Критерий как у A (порт-маппера в B нет, `portmap=0`).
```
nft a: dns=0 peer=4740 nd=0 mcast_kernel=0 portmap=0 other=0 | b: dns=0 peer=3967 ... portmap=0 other=0 | r: fwd_ok=8707 fwd_drop=0
analysis a: VIOLATIONS 0   analysis b: VIOLATIONS 0
client: EVENT app_ok t=60004 bytes=38731776 echo_eq=1
        EVENT after_idle t=90017 conn_alive=1 probe_ok=1
```
DNS-запросов нет (quinn не создаёт резолвер; адрес сервера подаётся числом). [П]

### G2 (B): Вердикт INCONCLUSIVE
Команда: `run.sh g2 b`. Критерий: 4 соединения (LAN v4/v6, routed v4/v6) `auth_ok` и `app_ok echo_eq=1`, счётчики как в G1.
```
ok=2 из 2 запущенных; пропущено: lan6 routed6 (IPv6 в ядре выключен)
-- lan4:    app_ok bytes=1048576 echo_eq=1  client_result ok
-- routed4: app_ok bytes=1048576 echo_eq=1  client_result ok
nft a: dns=0 peer=201 other=0 | b: dns=0 peer=189 other=0 | r: fwd_ok=390 fwd_drop=0 ; net_fail=[] peer_zero=[] lookup_errs=[]
```
IPv4-часть пройдена и чиста; IPv6 не запускался (нет IPv6 в ядре). Вердикт INCONCLUSIVE, как у A. [П для IPv4; IPv6 не проверено]

### G3 (B): лимит, CPU. Вердикт PASS
Команда: `run.sh g3 b`. (а) для B не применимо (id сервера нет; ключ сервера одноразовый). (б) отказы до прикладных байт засчитаны в G10. (в) лимит 5 рукопожатий за 10 с на IP; `flood` из `chv-c` (10.77.3.10-12, 20/с на IP, 30 с), одновременно друг `--repeat 5`:
```
сервер: retry=1794, ignore=7003 событий incoming
hs_done по IP за 30 с: 10.77.3.10=17, .11=16, .12=17; макс. в окне 10 с: 5, 5, 5 (порог ≤6)
друг: auth_ok conn=1..5, dur_ms = 2, 2, 2, 2, 2 (порог ≤2000)
flood: attempts=1789 connected=50 failed=1739 skipped=14 (с лимитом); без лимита attempts=1803 connected=1803
```
CPU сервера (тики за 30 с, CLK_TCK=100, порога нет, числа не оценивались): простой 0 тиков (0.00% ядра); флуд с лимитом 55 тиков (1.83%); флуд `--no-limit` 201 тик (6.70%), принято 1803 рукопожатия (`g3/cpu.txt`). Один замер на режим; сравнение с A (4.53% и 10.40%) условно: сценарий тот же, но в B каждое рукопожатие ещё создаёт ключ Ed25519, а в A нет. [П]

### G10 (B): экспортёр TLS и аутентификация после рукопожатия. Вердикт PASS
Команда: `run.sh g10 b` (сервер `--no-limit`).
1. `ok` дважды: `ekm` клиента и сервера совпали в обоих соединениях (`ce7384d9...`, `86a6514a...`), между соединениями различны.
2. Режимы, сервер `auth_fail ... app_bytes_read=0`, клиент `app_bytes_received=0`:
```
bad-sig reason=sig | wrong-pair reason=pair | wrong-key reason=sig | other-conn reason=sig
wrong-role reason=role | timeout reason=timeout | too-long reason=len | early-app reason=timeout (клиент отправил 256 байт во второй поток)
```
3. Сервер `--bad-auth2`: `auth_fail reason=peer_sig`, `app_bytes_sent=0`.
4. MITM в 10.77.3.20 (клиент B не пиннит и принимает чужой одноразовый ключ MITM): `mitm ekm down=a1b65b54... up=9dddc51f...` (различны), сервер `auth_fail reason=sig app_bytes_read=0`, клиент `app_bytes_received=0 app_bytes_sent=0`. Значит защиту от MITM в B даёт именно подпись над экспортёром, а не ключ сервера TLS. [П]

### G12 (B): что видит наблюдатель. Вердикт PASS
Команда: `run.sh g12 b`: захват `tcpdump -i rb -s 0 udp` в `chv-r`, клиент `ok` дважды (пары 1 и 2), сервер с лимитом (есть Retry). Иглы: публичные ключи и pair_id обеих пар, строка `chervo.invalid`, и (добавлено для B) два публичных ключа одноразовых серверных ключей из `server_spki_issued`.
```
OBSERVE datagrams=62 quic_initial=8 client_decrypted=6 server_decrypted=2 skips=0
QUIC versions=[1] client_dcid_lens=[8, 20] client_scid_lens=[8] alpn_found=1
CONN 0 client_scid=4461f12dc3ef973c first_dcid=57835443028faad14c1e2c8c85166086c8b1d1ad
CONN 1 client_scid=5101502d31058dce first_dcid=eb64720c51314d0e3941c96a7aee9634b1a423a0
RESULT PASS совпадений нет; положительные контроли выполнены
```
QUIC v1, ALPN `chervo-spike/1` найден в расшифрованном Initial клиента; AEAD прошёл для 2 Initial сервера; CID двух соединений различны. Handshake-пакеты пассивно не расшифровать [В]: ключ сервера и SPKI в них, в Initial их нет. Игла `uname -n` (2 байта) пропущена (`SKIP reason=needle_too_short`).

## 5. Наблюдения вне ворот
- **O1 (0-RTT и тикеты в A) [П-ч].** Клиент iroh: `enable_early_data = true`, хранилище тикетов (`tls.rs:87-89`; на нашем клиенте `max_tls_tickets(0)`). Сервер: `max_early_data_size = u32::MAX` (`tls.rs:125`), `send_tls13_tickets: 2` по умолчанию rustls, публичной настройки для сервера в iroh нет. То есть сервер iroh принимает 0-RTT от клиента с тикетом, выключить это на сервере нельзя. Влияет на U11 и этап 9 (требование "0-RTT и тикеты выключены"). Запуском не проверялось.
- **CPU из G3:** A: простой 0.00%, флуд с лимитом 4.53%, без лимита 10.40% одного ядра; B: 0.00%, 1.83%, 6.70%. Один замер на режим, эмуляция, порога нет.
- **Смена адреса в G1 (B):** при смене 10.77.1.2 → 10.77.1.3 на 30-й секунде передача 38.7 МБ дошла до конца с эхо-проверкой (`echo_eq=1`), после 30 с простоя (keep-alive 5 с) соединение живо и новый поток работает (`conn_alive=1 probe_ok=1`); это G7, в вердикт G1 не входит [П]. Для B у клиента сокет на `0.0.0.0`, сервер видит миграцию клиента средствами quinn.
- **Смена адреса в G1 (A):** при смене адреса клиента 10.77.1.2 → 10.77.1.3 на 30-й секунде передача 38.7 МБ с эхо-проверкой дошла до конца (`echo_eq=1`), после 30 с простоя соединение живо и новый поток работает (`conn_alive=1 probe_ok=1`) в обоих прогонах; это G7, в вердикт G1 не входит [П].
- **Новое для B (из G9).** `Incoming::accept_with` с новым `rustls::ServerConfig` на каждое входящее работает штатно (в том числе вместе с `retry()`: токен Retry проверяется конфигом сокета, а ключ сервера берётся из конфига `accept_with`). 0-RTT в B отсутствует по построению (`into_0rtt` вернул `Err`), в отличие от A (O1). Серверный конфиг сокета `Endpoint::server` обязателен, но его ключ в рукопожатиях не используется: каждое входящее идёт через `accept_with`. [П]
- iroh сам зондирует адреса пира, полученные внутри QUIC: при подключении по routed-адресу 10.77.2.2 клиент шлёт пакеты и на LAN-адрес сервера 10.77.0.3 (20 пакетов в прогоне `nopm`), а повторные соединения того же клиента с тем же id шли с LAN-адреса 10.77.0.2. Всё это адреса пира, G1 это допускает. Важно для этапа 13: выбор пути частично происходит внутри транспорта (U25).
- iroh с `default-features = false, features = ["tls-ring"]` всё равно компилирует код relay/reqwest/hyper (в `cargo tree`), но в работе трафика к ним нет (`dns=0`, `other=0`). Строки `iroh.link` и `n0_dns` есть в бинарнике из-за библиотеки; страж `check-forbidden.sh` не срабатывает на каталог `target/`, а бинарники спайка лежат в `spikes/transport/target/spike-bin/`.
- Отброшенные лимитом попытки флуда повторяют Initial, поэтому событий `incoming ... ignore` ~10.5 тыс. при ~1800 попыток; нагрузка на сервер от них видна в CPU.

## 6. Не проверено
- IPv6 целиком (LAN v6, routed v6 в G2; v6 в G1/G12): в ядре стенда нет IPv6. Нужен стенд с IPv6 либо явное решение владельца.
- Вариант B: IPv6 (см. выше) и IPv6-прослушивание `--listen` с двумя адресами (код с `tokio::select!` по двум `Endpoint` написан, но не запускался: нет IPv6). Ключи сервера в B одноразовые, но на повторяемость и разброс прогоны не размножались (по одному на ворота).
- Для B не проверялись миграция/смена пути как ворота (G7), NAT, реальные операторы; 0-RTT проверен только по отказу клиента `into_0rtt` (G9(4)), а не попыткой сервера принять ранние данные.
- Handshake-пакеты наблюдателем; восстановление номера пакета в расшифровке Initial упрощено (номер пакета берётся как усечённый, подходит для малых номеров Initial).
- Игла `uname -n` (2 байта) не искалась; другие иглы и ALPN искались.
- Повторяемость и разброс: каждый прогон выполнен один раз (G10 несколько раз на старой сборке), кроме G3 (дважды), без статистики.
- Реальные операторы, ТСПУ, NAT (G4-G8), Retry/ignore за NAT, текст RFC 5705 про метки `EXPERIMENTAL`, 0-RTT и тикеты запуском (O1 из исходника).
- Порог CPU не задан владельцем и не придумывался.

## 7. Отклонения от спецификации
1. IPv6 в стенде пропущен (нет в ядре): шаги `addr6`, `ip6` в nft и IPv6-соединения G2 условны; G2 из-за этого INCONCLUSIVE.
2. `ping` в среде нет: проверка связности стенда убрана из `setup`, связность проверяют сами ворота (`peer>0`, иначе INCONCLUSIVE).
3. `.gitignore` расширен: `logs/**/cap-*.txt`, `logs/**/*.pid`, `logs/**/g3/server*.log`, `target/` (большие/служебные файлы). Бинарники для запуска копируются в `target/spike-bin/`, чтобы страж `check-forbidden.sh` их не сканировал (в бинарниках есть строки из зависимости iroh).
4. Тип `BytesMut` для `PacketKey::decrypt` нельзя назвать без крейта `bytes` (не в списке зависимостей); он выводится выводом типов (`let mut p = From::from(payload)`), зависимость не добавлена.
5. `--change-addr-at S` в клиенте только печатает метку `addr_change_mark`; адрес меняет скрипт по этой метке (как в спецификации "скрипт в chv-a"). Добавлены необязательные ключи `--idle-s`, `--chunk-ms`; перед смещением адреса включён `promote_secondaries=1` в `chv-a`, без него удаление основного адреса сносит вторичный.
6. Для A "случайный `--id`" в G3(а) и G11(2) заменён чужим валидным ключом (`mitm_ep.id`): 32 случайных байта не являются точкой Ed25519, и ошибка возникала бы до сети, а не в рукопожатии (первый прогон G11 показал именно это, переделан).
7. Серверы в G10 запускаются с `--no-limit` (лимит проверяется в G3).
8. Ожидание клиента в `early-app` увеличено до 12 с (см. G10). Причина отказа `early-app` определена как `timeout`: спецификация причину не называла.
9. `run.sh decide a` при FAIL у A и отсутствии прогона B печатает `DECISION B-PENDING` (в спецификации только A|B|STOP, потому что B в части 1 не запускается).
10. G11 для вердикта FAIL требует не только статики, но и подтверждающих (2) и (3); при неизвестных кандидатах или расхождении скрипт даёт INCONCLUSIVE.
11. (часть 2) `run.sh decide` изменён: при FAIL у A и отсутствии прогона B печатает `DECISION B-PENDING`, при наличии `logs/b/summary.txt` печатает `DECISION B`, если у B нет блокирующих результатов, иначе `DECISION STOP` с причиной. INCONCLUSIVE, причина которого содержит "IPv6 в ядре", не блокирует (решение дирижёра); любой иной INCONCLUSIVE блокирует. Та же поправка действует и в ветке A без FAIL.
12. (часть 2) G2 B: IPv6-шаги пропущены так же, как у A; вердикт INCONCLUSIVE по IPv4-части (решение дирижёра).
13. (часть 2) G11 для B вычисляется внутри `g9` (`run.sh g11 b` вызывает `g9`), по пунктам 1-2 G9; в `summary.txt` B есть строки G9 и G11.
14. (часть 2) Добавлено сверх интерфейса спецификации: подкоманда `spike-b zrtt --connect` (для G9(4)), событие `server_spki_issued` на сервере (сверка с клиентским `server_spki`), метод `Conn::server_spki` с реализацией по умолчанию `None` в `auth.rs` (A не затронут), иглы эфемерных публичных ключей сервера в G12 для B.
15. (часть 2) Для B заданы `keep_alive_interval = 5 с` (как HEARTBEAT_INTERVAL у iroh) и стандартный простой 30 с, иначе 30 с простоя в G1 закрыли бы соединение; для A это делает сам iroh. Спецификация это не оговаривала.
16. (часть 2) Первый прогон `all b` показал G9 FAIL (`client_spki_not_issued_by_server`) из-за ошибки скрипта (`kv` берёт только первую строку, из-за чего список выданных сервером SPKI сравнивался по одному ключу), а не продукта; ошибка исправлена, в логах (`p1.txt`) видны все три SPKI. Итоговый `all b` выполнен заново целиком (код 0); остальные ворота в первом и втором прогоне дали одинаковые вердикты. Критерии не менялись.
17. (часть 2) Для B `bound` печатает `id=-`; имя сервера `chervo.invalid` не уходит в сеть (`enable_sni=false`), проверено иглой в G12.

## 8. Резюме для владельца
1. Решение: вариант B (quinn + rustls). Вариант A (iroh) провалил G11: в iroh 1.3.0 нельзя без форка выдавать новый ключ сервера на каждое соединение на одном порту, клиент обязан знать ключ сервера заранее. По U23 это автоматический переход на B.
2. B прошёл G1, G3, G9, G10, G11, G12. На одном порту сервер выдаёт каждому входящему новый одноразовый ключ (3 из 3 разные, проверено на обеих сторонах), клиент без пиннинга проверяет подпись рукопожатия; клиентский сертификат не запрашивается; 0-RTT и тикеты выключены; TLS 1.3 только.
3. Защита от MITM и чужих клиентов у B держится на подписи ключом пары над экспортёром TLS (G10: все 8 плохих режимов и MITM отсечены до первого прикладного байта); лимит по IP и Retry держат флуд, друг подключается за миллисекунды (G3).
4. G2 не завершён ни у A, ни у B: в тестовой среде выключен IPv6, IPv6-соединения не запускались (IPv4 работает). Нужен стенд с IPv6 либо ваше явное решение принять G2 по IPv4; пока это зафиксировано как INCONCLUSIVE и выбор не блокирует (так решил дирижёр).
5. Всё получено в эмуляции (netns), не на реальных операторах и не на ТСПУ. Побочно: у A сервер принимает 0-RTT и выдаёт тикеты без возможности отключить (из исходника, запуском не проверялось); в B этого нет.
