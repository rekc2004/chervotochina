# REPORT-1: этапы 2-5 (разведка, план, скелет, приёмка)

Ветка `claude/stage-0-skeleton`. Остановка по правилу TASK.md после этапа 5.

## 1. Что сделано и чем проверено
- Этап 2: `docs/DECISION.md`, `docs/OPEN_QUESTIONS.md` (U1-U19). Выбор предварительный: сборка с нуля; вариант A iroh 1.3.0 через `Builder::empty()` за своим трейтом транспорта, запасной B quinn+rustls RPK; ворота G1-G9. Проверено только чтением исходников (iroh 1.3.0 с static.crates.io), ни один сетевой эксперимент не запускался.
- Этап 3: этапы 6-19 в `docs/TASK.md`, спецификация скелета в `docs/PLAN_DRAFT.md`.
- Этап 4: workspace из 10 крейтов `crates/chervo-*`, только std, заглушки возвращают `Err(NotImplemented)`, CI, `deny.toml`, `scripts/check-forbidden.sh`.
- Этап 5, приёмку выполнила основная сессия сама, повторным запуском (не по отчёту агента), все команды с `--locked`, exit 0:
  - `cargo build --workspace` Finished;
  - `cargo test --workspace`: 15 тестов `ok`, 0 failed (workspace_layout, version_prints_and_succeeds, no_args_fails, connect_direct_fails_closed, node_start_not_implemented, null_transport_fails_closed, debug_does_not_leak_key, device_id_roundtrip, evil_paths_never_ok, oversize_rejected, decode_message_bounds и др.);
  - `cargo clippy --workspace --all-targets -- -D warnings` Finished; `cargo fmt --all -- --check` чисто;
  - `scripts/check-forbidden.sh`: `forbidden-strings: ok`, `--self-test`: `self-test: ok`;
  - `Cargo.lock`: только `chervo-*`; `unsafe`, `todo!`, `unimplemented!` в crates/ нет.
- Отступление от плана, принятое осознанно: заглушки возвращают `Err`, а не паникуют (решение architect, паника на враждебном входе = DoS).

## 2. Что НЕ проверено
- Любая сеть, NAT, UPnP, hole punching, скорость, реальные операторы и ТСПУ. Работоспособность варианта A (iroh без relay и discovery) только прочитана в коде.
- CI на GitHub (YAML не парсился и не запускался), `cargo audit`, `cargo deny`, схема `deny.toml` и `.cargo/audit.toml`, версии cargo-audit/cargo-deny (не закреплены), `actions/checkout@v4`.
- Windows и macOS (сборка только Linux).
- Аналоги по первоисточникам: проверены только iroh (через исходники), magic-wormhole и croc частично (PyPI/Go proxy). Blip, AltSendme, LocalSend, fsend, AlterSend и лицензии/коммиты/дефолтные серверы остальных не проверены (GitHub и сайты 403). Сведения BRIEF раздел 8 остаются непроверенным пересказом.
- Не прочитаны: noq, iroh-relay, portmapper, iroh-mdns-address-lookup, пример incoming-filter. Телеметрия iroh, RFC 7250 поверх QUIC, hole punching без relay: не проверены.
- Нет netns/tc проверки доступности (U19).

## 3. Расход
Вызовов субагентов: этап 2 = 4 (scout x3, architect x1), этап 3 = 1 (architect), этап 4 = 1 (skeleton); этап 5 субагентов не использовал. Лимит 6 на этап не превышен. Модели по frontmatter `.claude/agents/`: scout haiku-5-5/low, architect opus-5-5/high, skeleton haiku-5-5/medium; фактически обслуживающую модель агентов не проверял. Основная сессия: Sonnet 5.5.

## 4. Проверка самого Комбайна в облаке
- Хук `state`: сработал, `docs/TASK.md` был виден в контексте на старте.
- `guard`: опасных команд не встретилось, блокировок не видел (нарочно не пробовал).
- Python: `python3` доступен (использовал для правки TASK.md).
- Субагенты `combine-*` доступны и вызвались: scout (3), architect (2), skeleton (1). Security и builder не вызывались.
- Веб: из прокси открыты crates.io, static.crates.io, index.crates.io, PyPI, Go proxy. Закрыты (403): github.com и api.github.com для всех репозиториев кроме репозитория сессии, docs.rs, iroh.computer, blip.net, localsend.org. add_repo не использовал (нужно решение владельца). Это главное, что помешало этапу 2.
- Мелкое: субагенты-разведчики в отчётах помечают непроверенное честно; один раз разведчик скачал файл в /tmp вне scratchpad (удалён), architect оставил пустой noop.txt в scratchpad.
- Расхождение веток: сессия назначала `claude/hopeful-hawking-2sacz9`, промпт требует `claude/stage-0-skeleton`; работа велась в ветке из промпта. Пуш в main не делался.

## 5. Вопросы владельцу
См. `docs/OPEN_QUESTIONS.md`. Главные: U6 (друг как отражатель или раздатчик адресов; выбор A или B), U7 (TCP-запасной путь), U13/U16 (открыть доступ к GitHub для проверки аналогов), U17 (лицензия), U18 (подпись кода), U19 (netns в облаке).
