# Приёмка этапа 7 (combine-verifier, Sonnet/low), 2026-10-15

HEAD 16d0e2a. Все критерии `docs/specs/stage-07-spike.md` выполнены фактическим запуском: обе сборки, clippy `-D warnings`, `cargo test` спайка (13 + 1), `check-forbidden.sh` (спайк и весь репозиторий), `workspace_root` = `spikes/transport`, корневые файлы не тронуты, корневые `cargo build/test --workspace`, `run.sh decide b` → `DECISION B` (rc=0), netns `chv-*` и `/etc/netns/chv-*` после прогона пусты, разделы 1-8 `docs/SPIKE_TRANSPORT.md` на месте.

Независимый перезапуск `run.sh all b`: вердикты совпали с закоммиченными (G1, G3, G9, G10, G11, G12 PASS; G2 INCONCLUSIVE только из-за IPv6). Отличаются только замеры (например `retry` 1796 против 1794). Код выхода прогона не снят (шёл в фоне). Вариант A не перезапускался (по решению дирижёра), проверено содержимое `logs/a/summary.txt`.

Перезапуск перезаписал `spikes/transport/logs/b/**` в рабочем дереве (причина замечания Б1 в `ARCH-REVIEW-STAGE07.md`: ревью шло параллельно с прогоном). Дирижёр вернул логи к закоммиченному прогону (`git checkout`), на нём построен `docs/SPIKE_TRANSPORT.md`; `run.sh decide b` по ним даёт `DECISION B`. Б1 закрыт.

Не проверено: IPv6 (выключен в ядре среды, `ipv6.disable=1`), точность выдержек в тексте отчёта (проверено наличие разделов).
