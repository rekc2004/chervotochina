# Приёмка этапа 9б (combine-verifier, Sonnet/low + дирижёр), 2026-10-16

HEAD e3aa14f, база b76a7a4. Verifier (без стенда): все критерии `docs/specs/stage-09b-knock.md`, проверяемые командой, выполнены — сборка, новый пакет в Cargo.lock только `chervo-timesync`; `cargo test --workspace --locked` дважды без флейков (quinn 57 + 1 ignored); doc-тесты identity; все имена тестов из спецификации в трёх крейтах; адресный прогон стук-тестов 17 passed; clippy `-D warnings`, fmt, `check-forbidden.sh`; blake2 без std/simd/reset; timesync зависит только от getrandom; `sync_clock(` вне timesync/examples нет; diff вне трёх крейтов пуст. Замеры (release): проверка стука 48 Б ~0.18-0.19 мкс при N=10/200/1000; set_peers 0.5/15.8/70.5 мс; пропускная способность вкл/выкл 1.011.

Оговорка verifier: `examples/netcheck.rs` изменён ~2 мин позже закоммиченных логов стенда. **Дирижёр перепрогнал стенд на текущем коде** (`CHV_LOGS` в scratchpad, закоммиченные логи не тронуты): `stage9.sh all` rc=0; G1 PASS, G12 PASS, KNOCK PASS; захват на veth b: noise/stranger/stale/replay/flood — `b_packets=0`; друг 25 пакетов, auth_ok, echo_eq=1; контроль `--no-knock` 22 пакета. Вердикты совпали с закоммиченными.

Замечание дирижёра: `stage9.sh all` не вызывает уборку в конце — netns `chv-*` остаются после прогона (были и до него, от прогонов builder); `stage9.sh teardown` убирает корректно. В круг правок.
Не проверено: CI на 3 ОС и supply-chain (по прогону CI); реальные NTP-серверы; пункты «НЕ проверяется» спецификации.
