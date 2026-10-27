# PLAN_DRAFT (этап 3, combine-architect)

Черновик для переноса в `docs/TASK.md` главной сессией. Опора: `docs/BRIEF.md`, `docs/DECISION.md` (2.4, 5), `docs/OPEN_QUESTIONS.md`. Ничего из этого не запускалось; это план, а не проверенный результат.

---

## ЧАСТЬ 1. Этапы после скелета

Общие правила для всех строк (не повторяются в каждой):
- Перед подключением любой библиотеки `scout` (haiku/low) снимает версию с crates.io и читает исходник/документацию этой версии (CORE п.3); версия и дата пишутся в коммит.
- «ведёт architect, не builder» = код пишет architect; builder допускается только на явно названные некритичные куски.
- Критерий «тесты на злые входы» значит: отдельный файл тестов с враждебными входами, все проходят, вывод приведён в отчёте этапа.
- Сеть в экспериментах только в netns. Если в среде нет netns (нужен CAP_NET_ADMIN), этап не подменять loopback-тестом: остановиться и записать в OPEN_QUESTIONS (стенд можно поднять на раннере GitHub Actions с sudo).

- [ ] 6. Модель угроз | architect (opus/high) | `docs/THREAT_MODEL.md` покрывает все 8 угроз из BRIEF раздел 7 (оператор и DPI, злой друг, подмена токена в мессенджере, кража ноутбука, replay токена, MITM при добавлении, скомпрометированный мини-сервер, утечка IP через токен) + DoS на открытый порт; для каждой: актив, атака, мера, этап плана, где мера реализуется, что остаётся непокрытым
- [ ] 7. Спайк транспорта: ворота G1-G3 (+G9 при переходе на B) | architect (opus/high), ведёт architect, не builder; сеть в netns | одноразовый код в `spike-transport-final:spikes/transport/` (не член workspace); `docs/SPIKE_TRANSPORT.md` с фактическими логами nftables/DNS и выводом тестов по G1, G2, G3; решение A или B записано; провал любого из G1-G3 переключает на B без обсуждения (DECISION 2.4), тогда пройдены G9. Дополнительно (не ворота): даёт ли выбранная база экспортёр ключевого материала TLS для SAS (нужно этапу 11)
- [ ] 8. Спайк транспорта: замеры G4-G8 | architect (opus/high), ведёт architect, не builder; долгие прогоны по готовому скрипту может запускать scout (haiku/low), выводы делает architect | в `docs/SPIKE_TRANSPORT.md` таблицы: G4 одновременное открытие по типам NAT (удалось/время), G5 порт-маппинг против miniupnpd (открыт/закрыт, куда ходили пакеты), G6 наблюдаемый адрес = внешний адрес NAT, G7 смена IP посреди передачи, G8 скорость и CPU A против B на одинаковых окнах; всё помечено «эмуляция, не реальные операторы»; U3, U14, U15 обновлены по фактам
- [ ] 9. Адаптер транспорта | architect (opus/high), ведёт architect, не builder | крейт `chervo-transport-iroh` или `chervo-transport-quinn` реализует трейт `chervo_transport::Transport`; ядро не меняется (тест layout из скелета зелёный); пиннинг ключей, `PeerFilter` до чтения прикладных данных, лимит попыток с одного IP до рукопожатия, 0-RTT и тикеты выключены (U11); статический страж CI зелёный; повторён тест G1 на адаптере; тесты на злые входы (неверный id, незнакомый клиент, поток рукопожатий)
- [ ] 10. Идентичность | architect (opus/high), ведёт architect, не builder | генерация Ed25519 только библиотекой; приватный ключ в хранилище ОС (Windows, macOS, Linux), в памяти обнуляется при выходе, на диск в открытом виде не пишется (тест сканирует каталог данных); ответ на U10 (бэкапы, iCloud Keychain) по исходнику `keyring` выбранной версии; CI-матрица 3 ОС зелёная; где поведение ОС не проверено, так и записано
- [ ] 11. Токены приглашения, SAS, друзья | architect (opus/high), ведёт architect, не builder; builder (sonnet/medium) только CRUD списка друзей и прав поверх готового зашифрованного хранилища | формат токена и QR (ключ, адреса, время, nonce, подпись), TTL, одноразовость, лимит попыток; SAS на обоих экранах из ключевого материала соединения, без совпадения SAS дружба не создаётся; список друзей зашифрован на диске библиотечным AEAD; отзыв и блокировка; тесты: подделка подписи, истёкший, повтор (replay), изменённый байт, слишком длинный, несовпадение SAS; fuzz-цель `decode` токена существует и проходит прогон
- [ ] 12. Адреса и смена IP | architect (opus/high), ведёт architect, не builder | книга адресов (источник, время, короткоживущие IPv6, U12); классификация IPv4 (частный, 100.64.0.0/10); токен обновления адреса с возрастающим номером, подписан постоянным ключом, старый номер отвергается; при смене IP рассылка новых адресов друзьям только после аутентификации; наблюдаемый адрес от друга только как подсказка (U6 вариант 5); сообщение пользователю, когда без ручного токена найтись нельзя (BRIEF раздел 4); тесты на злые входы токена обновления
- [ ] 13. Соединение | architect (opus/high), ведёт architect, не builder | параллельные попытки, побеждает первая: LAN mDNS без публичного ключа и имени в анонсе (U9), IPv6, IPv4 + UPnP/NAT-PMP/PCP с закрытием маппинга по окончании, одновременное открытие по известным адресам с периодическими попытками (DECISION 3.2); без relay, без угадывания портов (U8); диагноз «прямое соединение невозможно» с причиной (CGNAT, UDP закрыт, нет IPv6, неизвестно) и подсказкой; в netns: каждый путь соединяется, трафик только по списку G1
- [ ] 14. Передача | architect (opus/high), ведёт architect, не builder | ограниченный по длине кодек сообщений протокола; предложение и подтверждение получателем (отправитель, размер); параллельные QUIC-потоки и настраиваемое окно; хэш-дерево библиотекой, блок пишется на диск только после проверки; докачка после обрыва и смены IP с проверкой уже принятого; сжатие только при выигрыше, защита от «бомб» распаковки; тесты: подменённый блок отвергнут, обрыв на середине докачивается, файл побайтно совпадает; fuzz-цель кодека
- [ ] 15. Безопасный приём файлов | architect (opus/high), ведёт architect, не builder | `chervo-receive`: результат всегда внутри выбранной папки; отвергаются `..`, абсолютные пути, `C:\`, UNC, зарезервированные имена Windows (CON, NUL, COM1...), `:` (ADS), хвостовые точки и пробелы, симлинки и жёсткие ссылки, коллизии регистра и Unicode-нормализации; лимиты числа файлов, глубины, длины, суммарного размера; ничего не исполняется и не помечается исполняемым; автоприём только явно и с лимитами; таблица злых путей в тестах на CI 3 ОС; fuzz-цель санитайзера со свойством «результат внутри корня»
- [ ] 16. Тесты сети | builder (sonnet/medium) пишет стенд по спецификации из этапов 7-8; разбор и выводы architect (opus/high) | скрипты netns/tc netem для сценария BRIEF раздел 10: LAN, IPv6, белый IP, full cone, restricted, port-restricted, symmetric, CGNAT, двойной NAT, блок UDP, смена IP посреди передачи; таблица скоростей LAN, IPv6, UPnP, hole punch с CPU; отчёт «какие пары не соединились и почему»; отдельной строкой «не проверено: реальные операторы, ТСПУ»
- [ ] 17. Безопасность в целом | security (opus/high) + независимая повторная проверка критичного вторым запуском opus/high в свежем контексте (не автор кода) | `docs/SECURITY_REVIEW.md`: проверено и НЕ проверено по каждому пункту BRIEF раздел 7; `cargo audit` и `cargo deny` чистые или каждое исключение обосновано; SBOM генерируется в CI; fuzz-цели (токены, кодек протокола, санитайзер путей) прогнаны заданное время, корпус сохранён (если cargo-fuzz недоступен без nightly, так и записано, запасной вариант на stable назван); проверка, что логи не содержат имён файлов, IP и ключей; DoS до аутентификации; ноль открытых находок high/critical. Блокирует релиз
- [ ] 18. GUI | architect (opus/high) выбирает фреймворк (короткая запись в DECISION: версия, лицензия, без телеметрии и внешних CDN), реализует builder (sonnet/medium) | крейт GUI зависит только от `chervo-core` (тест по манифесту, как layout); экраны: друзья, добавление через QR/токен + SAS, отправка, подтверждение входящего, прогресс, диагноз соединения; сборка на 3 ОС в CI; ручной чек-лист сценария пройден и приложен
- [ ] 19. Релизы и подпись | architect (opus/high) для проверки подписи обновлений, ведёт architect, не builder; builder (sonnet/medium) для упаковки в CI | сборка в GitHub Actions с закреплённым toolchain и actions по SHA; артефакты подписаны ключом владельца, проверка подписи в приложении офлайн по вшитому публичному ключу; обновление только вручную или из GitHub Releases с проверкой подписи, без автообновления; SBOM приложен к релизу; релиз невозможен без зелёного этапа 17

Вычеркнуто (не делать без решения владельца):
- ~~Мини-сервер обмена адресами~~: опционален (BRIEF п.2.3), всё обязано работать без него; отдельный этап после ответа владельца.
- ~~TCP-запасной путь~~ (U7), ~~угадывание портов~~ (U8), ~~друг как раздатчик адресов общих друзей~~ (U6 вариант 6).
- ~~Мобильные оболочки~~: BRIEF раздел 1, этап 1 только компьютеры; ядро к ним готово по структуре скелета.

Новые вопросы для `docs/OPEN_QUESTIONS.md` (вносит главная сессия):
- U17. Лицензия проекта не задана. Решение: в скелете `publish = false`, поле `license` не ставить. Почему: выбор лицензии за владельцем.
- U18. Подпись кода Windows (Authenticode) и нотаризация macOS требуют платных сертификатов. Решение: в этапе 19 только своя подпись артефактов; без сертификатов ОС будет предупреждать. Почему: внешнее и платное действие только по «да».
- U19. Есть ли netns в облачной среде. Решение: этапы 7, 8, 13, 16 без netns не подменять; запускать стенд на раннере GitHub Actions. Почему: G1 без изоляции сети не доказателен.

---

## ЧАСТЬ 2. Спецификация скелета (этап 4, combine-skeleton, haiku/medium)

### 2.0. Жёсткие правила для исполнителя
1. Не писать криптографию, сеть, сериализацию, работу с файловой системой. Только типы, трейты и заглушки ниже.
2. Внешних зависимостей НЕТ: ни iroh, ни quinn, ни rustls, ни tokio, ни thiserror. Только std и path-зависимости между нашими крейтами. В `Cargo.lock` должны быть только пакеты `chervo-*`.
3. Заглушки закрыты по умолчанию (fail-closed): вместо `todo!()`/`unimplemented!()` возвращают `Err(...::NotImplemented)`. `todo!`/`unimplemented!` запрещены линтом (паника на враждебном входе = DoS).
4. `Debug` не выводит байты ключей; на типы с IP-адресами и путями `Debug` не выводить через derive, кроме перечисленных ниже.
5. Править только файлы из списка 2.1. Не трогать `docs/`, `.claude/`, `CLAUDE.md`, `README.md`, `.gitignore`.
6. Неиспользуемые параметры называть с `_`. В реализациях трейтов сигнатуры с `impl Future<...> + Send` писать ровно как в трейте, не подставлять `std::future::Ready<...>` (иначе предупреждение `refining_impl_trait`, а оно станет ошибкой под `-D warnings`).
7. Отчитаться фактическим выводом команд из 2.8 (хвосты), а не пересказом. Что не получилось, так и написать.

### 2.1. Дерево файлов (точно)
```
Cargo.toml
Cargo.lock                      (сгенерировать первой `cargo build`, закоммитить)
rust-toolchain.toml
deny.toml
.cargo/audit.toml
.github/workflows/ci.yml
scripts/check-forbidden.sh      (исполняемый, chmod +x)
crates/chervo-identity/   Cargo.toml  src/lib.rs  tests/identity.rs
crates/chervo-transport/  Cargo.toml  src/lib.rs  tests/transport.rs
crates/chervo-token/      Cargo.toml  src/lib.rs  tests/token.rs
crates/chervo-addr/       Cargo.toml  src/lib.rs
crates/chervo-friends/    Cargo.toml  src/lib.rs  tests/friends.rs
crates/chervo-connect/    Cargo.toml  src/lib.rs  tests/connect.rs
crates/chervo-transfer/   Cargo.toml  src/lib.rs  tests/transfer.rs
crates/chervo-receive/    Cargo.toml  src/lib.rs  tests/receive.rs
crates/chervo-core/       Cargo.toml  src/lib.rs  tests/layout.rs  tests/node.rs
crates/chervo-cli/        Cargo.toml  src/main.rs tests/cli.rs
```
Назначение: `chervo-core` это фасад без UI для будущих оболочек (CLI, GUI, мобильные); он обобщён по трейту транспорта и не зависит от конкретной реализации. Реализации транспорта (`chervo-transport-iroh` / `-quinn`) появятся в этапе 9, не в скелете.

Зависимости (только path, только эти):
| Крейт | Зависит от |
|---|---|
| chervo-identity | нет |
| chervo-addr | нет |
| chervo-transport | chervo-identity |
| chervo-token | chervo-identity |
| chervo-friends | chervo-identity, chervo-addr |
| chervo-connect | chervo-identity, chervo-transport |
| chervo-transfer | нет |
| chervo-receive | нет |
| chervo-core | все восемь выше |
| chervo-cli | chervo-core |

### 2.2. Корневой `Cargo.toml`
```toml
[workspace]
resolver = "3"
members = [
    "crates/chervo-identity",
    "crates/chervo-addr",
    "crates/chervo-transport",
    "crates/chervo-token",
    "crates/chervo-friends",
    "crates/chervo-connect",
    "crates/chervo-transfer",
    "crates/chervo-receive",
    "crates/chervo-core",
    "crates/chervo-cli",
]

[workspace.package]
version = "0.0.0"
edition = "2024"
rust-version = "<major.minor из `cargo --version`, ожидается 1.97>"
publish = false

[workspace.dependencies]
chervo-identity = { path = "crates/chervo-identity", version = "0.0.0" }
chervo-addr = { path = "crates/chervo-addr", version = "0.0.0" }
chervo-transport = { path = "crates/chervo-transport", version = "0.0.0" }
chervo-token = { path = "crates/chervo-token", version = "0.0.0" }
chervo-friends = { path = "crates/chervo-friends", version = "0.0.0" }
chervo-connect = { path = "crates/chervo-connect", version = "0.0.0" }
chervo-transfer = { path = "crates/chervo-transfer", version = "0.0.0" }
chervo-receive = { path = "crates/chervo-receive", version = "0.0.0" }
chervo-core = { path = "crates/chervo-core", version = "0.0.0" }

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"

[profile.release]
overflow-checks = true
```
Манифест каждого крейта:
```toml
[package]
name = "chervo-<имя>"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
publish.workspace = true

[dependencies]
# только из таблицы 2.1, в виде: chervo-identity.workspace = true

[lints]
workspace = true
```
`chervo-cli` дополнительно: `[[bin]] name = "chervo"`, `path = "src/main.rs"`. Поле `license` не ставить (U17).

### 2.3. `rust-toolchain.toml`
Сначала выполнить `rustup --version`, `rustup toolchain list`, `cargo --version`, `cargo clippy --version`, `cargo fmt --version` и привести вывод.
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "minimal"
```
Правило: если в `rustup toolchain list` нет `stable-*`, поставить `channel` равным точному имени установленного тулчейна (например `1.97.0`). После записи файла `cargo --version` в корне репозитория не должен ничего скачивать; если rustup пытается скачать и падает, убрать строку `components` и записать это в отчёт. Закрепление точной версии будет в этапе 19.

### 2.4. Конфиги цепочки поставок (локально не проверяются, см. 2.9)
`deny.toml`:
```toml
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.93

[licenses.private]
ignore = true

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```
`.cargo/audit.toml`:
```toml
[advisories]
ignore = []
```

### 2.5. Статический страж `scripts/check-forbidden.sh`
Строки (DECISION 2.4): `presets::N0`, `N0DisableRelay`, `RelayMode::Default`, `RelayMode::Staging`, `iroh.link`, `n0_dns`.
```bash
#!/usr/bin/env bash
# Guard: forbid third-party iroh presets/relays/DNS in our code (docs/DECISION.md 2.4).
set -euo pipefail
patterns=( 'presets::N0' 'N0DisableRelay' 'RelayMode::Default' 'RelayMode::Staging' 'iroh.link' 'n0_dns' )
args=()
for p in "${patterns[@]}"; do args+=( -e "$p" ); done

scan() {
  local rc=0
  grep -rnF "${args[@]}" \
    --exclude-dir=.git --exclude-dir=target --exclude-dir=docs --exclude-dir=.claude \
    --exclude=check-forbidden.sh -- "$1" || rc=$?
  return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  printf 'let x = %s;\n' "RelayMode::""Default" > "$tmp/bad.rs"
  rc=0; scan "$tmp" >/dev/null || rc=$?
  if [[ $rc -eq 0 ]]; then echo "self-test: ok"; exit 0; fi
  echo "self-test: FAILED (rc=$rc)" >&2; exit 1
fi

rc=0; scan "${1:-.}" || rc=$?
case $rc in
  0) echo "FORBIDDEN strings found (see above)" >&2; exit 1 ;;
  1) echo "forbidden-strings: ok"; exit 0 ;;
  *) echo "grep error rc=$rc" >&2; exit 2 ;;
esac
```
Нюанс: grep код 1 = «не найдено» (хорошо), 2 = ошибка (не считать успехом). `docs/` и `.claude/` исключены, потому что там эти строки описаны намеренно.

### 2.6. `.github/workflows/ci.yml`
```yaml
name: ci
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: rustup toolchain install stable --profile minimal --component rustfmt --component clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets --locked -- -D warnings
      - run: bash scripts/check-forbidden.sh
      - run: bash scripts/check-forbidden.sh --self-test
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: rustup toolchain install stable --profile minimal
      - run: cargo build --workspace --locked
      - run: cargo test --workspace --locked
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: cargo install cargo-audit --locked --version =<X>
      - run: cargo audit --deny warnings
      - run: cargo install cargo-deny --locked --version =<Y>
      - run: cargo deny check licenses sources
```
`<X>` и `<Y>`: взять из `cargo search cargo-audit --limit 1` и `cargo search cargo-deny --limit 1`, привести вывод в отчёте. Если `cargo search` недоступен, оставить без `--version` и комментарий `# TODO pin version`, сказать об этом в отчёте. Если в `rust-toolchain.toml` не `stable`, в шагах `rustup toolchain install` поставить то же имя.

### 2.7. Публичный API заглушек (std only)
Каждый крейт: свой enum ошибок с `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`, ручной `impl std::fmt::Display` (короткий английский текст) и `impl std::error::Error for X {}`.

**chervo-identity**
- `pub struct DeviceId([u8; 32]);` derive `Clone, Copy, PartialEq, Eq, Hash`; `pub const fn from_bytes(b: [u8; 32]) -> Self`; `pub const fn as_bytes(&self) -> &[u8; 32]`. Doc-комментарий: «ключ не валидируется, проверка точки кривой появится с библиотекой в этапе 10».
- ручной `impl Debug for DeviceId`: пишет ровно `DeviceId(..)`.
- `pub enum IdentityError { NotImplemented, StorageUnavailable }`.
- `pub trait SecretKeyStore { fn load_or_create(&self) -> Result<DeviceId, IdentityError>; fn delete(&self) -> Result<(), IdentityError>; }`
- `pub struct UnavailableKeyStore;` реализует трейт, оба метода `Err(IdentityError::NotImplemented)`.

**chervo-addr**
- `pub enum AddrSource { Interface, Lan, PortMapping, Invite, AddressUpdate, ObservedByFriend }` derive `Debug, Clone, Copy, PartialEq, Eq`.
- `pub struct KnownAddr { pub addr: std::net::SocketAddr, pub source: AddrSource, pub last_seen_unix: u64, pub short_lived: bool }` derive `Clone, PartialEq, Eq` (без Debug).

**chervo-transport**
- `pub struct PeerAddr { pub id: DeviceId, pub addrs: Vec<SocketAddr> }` (без Debug).
- `pub enum TransportError { NotImplemented, PeerNotAllowed, Closed }`.
- `pub trait PeerFilter: Send + Sync { fn is_allowed(&self, peer: &DeviceId) -> bool; }`; `pub struct DenyAll;` возвращает `false`. Doc трейта: «вызывается до чтения любых прикладных данных; соединение с запрещённым ключом не возвращается из accept/connect».
- Трейты (импорт `std::future::Future`):
```rust
pub trait SendStream: Send {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;
    fn finish(&mut self) -> Result<(), TransportError>;
}
pub trait RecvStream: Send {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<Option<usize>, TransportError>> + Send;
}
pub trait Connection: Send + Sync {
    type Tx: SendStream;
    type Rx: RecvStream;
    /// Key verified in the handshake (pinned), never self-reported.
    fn remote_id(&self) -> DeviceId;
    fn remote_addr(&self) -> SocketAddr;
    fn open_bi(&self) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send;
    fn accept_bi(&self) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send;
    fn close(&self);
}
pub trait Transport: Send + Sync {
    type Conn: Connection;
    fn local_addrs(&self) -> Vec<SocketAddr>;
    fn connect(&self, peer: &PeerAddr) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}
```
- Заглушки: `pub enum NullStream {}` и `pub enum NullConnection {}` (необитаемые: соединение из заглушки создать нельзя); `pub struct NullTransport;`.
  - async-методы всех трёх: тело `std::future::ready(Err(TransportError::NotImplemented))`.
  - синхронные методы `NullStream::finish`, `NullConnection::remote_id/remote_addr/close`: тело `match *self {}`.
  - `NullTransport::local_addrs` → `Vec::new()`; `type Conn = NullConnection`; у `NullConnection` `type Tx = NullStream; type Rx = NullStream;`.

**chervo-token**
- `pub const MAX_TOKEN_TEXT_LEN: usize = 2048;`
- `pub struct InviteToken { pub issuer: DeviceId, pub addrs: Vec<SocketAddr>, pub issued_at_unix: u64, pub expires_at_unix: u64, pub nonce: [u8; 16], pub signature: [u8; 64] }`
- `pub struct AddressUpdateToken { pub issuer: DeviceId, pub addrs: Vec<SocketAddr>, pub seq: u64, pub issued_at_unix: u64, pub signature: [u8; 64] }`
- `pub enum Token { Invite(InviteToken), AddressUpdate(AddressUpdateToken) }` (без Debug ни на чём из трёх).
- `pub enum TokenError { TooLong, NotImplemented }`.
- `pub fn decode(text: &str) -> Result<Token, TokenError>`: если `text.len() > MAX_TOKEN_TEXT_LEN` то `Err(TooLong)`, иначе `Err(NotImplemented)`. Никогда `Ok`.

**chervo-friends**
- `pub struct AutoAcceptLimits { pub max_total_bytes: u64, pub max_files: u32 }` derive `Debug, Clone, Copy, PartialEq, Eq`.
- `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub enum Permission { #[default] Ask, AutoAccept(AutoAcceptLimits) }`.
- `pub struct Friend { pub name: String, pub id: DeviceId, pub known_addrs: Vec<KnownAddr>, pub permission: Permission, pub last_addr_seq: u64, pub blocked: bool }` derive `Clone` (без Debug).
- `pub enum FriendsError { NotImplemented }`.
- `pub trait FriendStore { fn list(&self) -> Result<Vec<Friend>, FriendsError>; fn get(&self, id: &DeviceId) -> Result<Option<Friend>, FriendsError>; fn upsert(&mut self, friend: Friend) -> Result<(), FriendsError>; fn remove(&mut self, id: &DeviceId) -> Result<(), FriendsError>; }`
- `pub struct UnavailableFriendStore;` всё `Err(FriendsError::NotImplemented)`.

**chervo-connect**
- `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum PathKind { Lan, Ipv6, PortMapped, SimultaneousOpen }` (relay-варианта нет и не будет).
- `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum NoDirectPath { BothBehindCgnat, SymmetricNat, UdpBlocked, NoIpv6, NoKnownAddress, Unknown }`.
- `pub enum ConnectError { NoDirectPath(NoDirectPath), NotImplemented }`.
- `pub fn connect_direct<T: Transport>(_transport: &T, _peer: &PeerAddr) -> impl Future<Output = Result<(T::Conn, PathKind), ConnectError>> + Send` → `std::future::ready(Err(ConnectError::NotImplemented))`.

**chervo-transfer**
- `pub const MAX_MESSAGE_LEN: usize = 64 * 1024;`
- `pub struct TransferId(pub [u8; 16]);` и `pub struct BlockHash(pub [u8; 32]);` derive `Debug, Clone, Copy, PartialEq, Eq`.
- `pub struct FileEntry { pub rel_path: String, pub size: u64, pub root_hash: BlockHash }`; `pub struct Offer { pub id: TransferId, pub files: Vec<FileEntry> }` (без Debug).
- `pub enum Message { Offer(Offer), Accept(TransferId), Reject(TransferId), Resume { id: TransferId, file_index: u32, from_block: u64 } }` (без Debug).
- `pub enum ProtocolError { TooLong, NotImplemented }`.
- `pub fn decode_message(bytes: &[u8]) -> Result<Message, ProtocolError>`: длина больше `MAX_MESSAGE_LEN` → `TooLong`, иначе `NotImplemented`.

**chervo-receive**
- `pub struct ReceiveLimits { pub max_files: u32, pub max_depth: u16, pub max_name_bytes: u16, pub max_path_bytes: u16, pub max_total_bytes: u64 }` derive `Debug, Clone, Copy, PartialEq, Eq`; ручной `Default`: `10_000, 16, 255, 1024, 64 * 1024 * 1024 * 1024` с комментарием `// placeholder, revisit in stage 15`.
- `pub enum PathError { Empty, TooLong, NotImplemented }`.
- `pub fn sanitize_relative_path(_root: &std::path::Path, untrusted: &str, limits: &ReceiveLimits) -> Result<std::path::PathBuf, PathError>`: пусто → `Empty`; `untrusted.len() > limits.max_path_bytes as usize` → `TooLong`; иначе `NotImplemented`. Никогда `Ok`.

**chervo-core**
- `pub use` всех восьми крейтов (`pub use chervo_identity;` и т.д.).
- `pub const VERSION: &str = env!("CARGO_PKG_VERSION");`
- `pub struct NodeConfig { pub data_dir: std::path::PathBuf, pub receive_limits: chervo_receive::ReceiveLimits }`.
- `pub enum CoreError { NotImplemented }`.
- `pub struct Node<T: Transport> { transport: T, config: NodeConfig }`; `pub fn new(transport: T, config: NodeConfig) -> Self`; `pub fn transport(&self) -> &T`; `pub fn config(&self) -> &NodeConfig`; `pub fn start(&self) -> Result<(), CoreError>` → `Err(NotImplemented)`. Конструктор ничего не открывает и не пишет.

**chervo-cli** (`src/main.rs`)
- `fn main() -> std::process::ExitCode`: первый аргумент `--version` → `println!("chervo {}", chervo_core::VERSION)`, `ExitCode::SUCCESS`; иначе `eprintln!("chervo: not implemented")`, `ExitCode::from(2)`.

### 2.8. Базовые тесты (13, все в `tests/` как интеграционные)
Вспомогательная функция для async без рантайма (копия в `transport.rs` и `connect.rs`):
```rust
fn poll_once<F: std::future::Future>(f: F) -> std::task::Poll<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    f.as_mut().poll(&mut cx)
}
```
Проверять через `assert!(matches!(...))`, не через `unwrap_err` (у типов без Debug он не скомпилируется).
1. `identity.rs` `device_id_roundtrip`: `DeviceId::from_bytes([7; 32]).as_bytes() == &[7; 32]`.
2. `identity.rs` `debug_does_not_leak_key`: `format!("{:?}", DeviceId::from_bytes([0xAB; 32]))` равно `"DeviceId(..)"`; `UnavailableKeyStore.load_or_create()` = `Err(NotImplemented)`.
3. `transport.rs` `deny_all_denies`: `DenyAll.is_allowed(&DeviceId::from_bytes([1; 32]))` = `false`.
4. `transport.rs` `null_transport_fails_closed`: `poll_once(NullTransport.connect(&peer))` и `poll_once(NullTransport.accept())` дают `Poll::Ready(Err(TransportError::NotImplemented))`; `local_addrs()` пуст.
5. `token.rs` `oversize_rejected` (`"A"` повторить `MAX_TOKEN_TEXT_LEN + 1` раз → `TooLong`) и `never_ok`: для `""`, `"garbage"`, `"\0\0"`, `"чвч://x"`, строки ровно `MAX_TOKEN_TEXT_LEN` → результат `Err(_)`.
6. `receive.rs` `evil_paths_never_ok`: для `"../../etc/passwd"`, `"/etc/passwd"`, `"C:\\Windows\\x"`, `"\\\\server\\share"`, `"CON"`, `"a/../../b"`, `"ok.txt"` с `ReceiveLimits::default()` и корнем `Path::new("recv")` результат `Err(_)`; `""` → `Empty`; строка длиной `max_path_bytes + 1` → `TooLong`.
7. `receive.rs` `default_limits_nonzero`: все поля `ReceiveLimits::default()` больше нуля и `max_total_bytes < u64::MAX`.
8. `transfer.rs` `decode_message_bounds`: `vec![0u8; MAX_MESSAGE_LEN + 1]` → `TooLong`; `&[]` и `&[1, 2, 3]` → `NotImplemented`.
9. `friends.rs` `default_permission_is_ask`: `Permission::default() == Permission::Ask`; `UnavailableFriendStore.list()` = `Err(NotImplemented)`.
10. `connect.rs` `connect_direct_fails_closed`: `poll_once(connect_direct(&NullTransport, &peer))` = `Ready(Err(ConnectError::NotImplemented))`; плюс функция с исчерпывающим `match` по `PathKind` без `_` (новый вариант сломает компиляцию теста).
11. `core/tests/layout.rs` `workspace_layout`: читает `concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml")`, проверяет наличие всех 10 путей `crates/chervo-*`; читает `concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")` и проверяет, что в нём нет подстрок `chervo-cli`, `iroh`, `quinn`, `rustls`, `tokio` (ядро без UI и без конкретного транспорта).
12. `core/tests/node.rs` `node_start_not_implemented`: `Node::new(NullTransport, cfg).start()` = `Err(NotImplemented)`; `node.config().data_dir == PathBuf::from("data")`.
13. `cli/tests/cli.rs`: `std::process::Command::new(env!("CARGO_BIN_EXE_chervo"))` с `--version` → код 0 и stdout содержит `chervo 0.0.0`; без аргументов → код не 0.
Плюс shell: `bash scripts/check-forbidden.sh` (ok на репозитории) и `bash scripts/check-forbidden.sh --self-test` (ok).

### 2.9. Критерий приёмки (этап 5, главная сессия сама запускает и приводит вывод)
1. `cargo build --workspace --locked` без ошибок и предупреждений.
2. `cargo test --workspace --locked`: все тесты из 2.8 есть и проходят, 0 failed, 0 ignored.
3. `cargo clippy --workspace --all-targets --locked -- -D warnings` чисто.
4. `cargo fmt --all -- --check` чисто.
5. `bash scripts/check-forbidden.sh` → `forbidden-strings: ok`; `bash scripts/check-forbidden.sh --self-test` → `self-test: ok`.
6. В `Cargo.lock` только пакеты `chervo-*` (`grep '^name = ' Cargo.lock`); `grep -rn "unsafe\|todo!\|unimplemented!" crates` пусто.
7. Дерево совпадает с 2.1 (`find crates -name '*.rs' -o -name Cargo.toml | sort`); `git status` не показывает изменений вне списка 2.1.
8. В отчёте прямо: НЕ проверено локально: CI на GitHub, Windows и macOS, `cargo audit`, `cargo deny`, схема `deny.toml` и `audit.toml` (инструменты не ставились; база RustSec на GitHub за прокси), версия `actions/checkout@v4` (GitHub недоступен).
