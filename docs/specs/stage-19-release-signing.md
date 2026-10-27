# SPEC 19: Релизы, подпись, проверка обновлений, уведомление о новой версии, упаковка          критичность: КРИТИЧНЫЙ (19а, 19б, 19д), обычный (19в, 19г)

Редакция 3, 2026-10-27, architect (opus/high): Q1 отвечен (а); добавлен подэтап 19д (уведомление о новой версии, сеть); Р4 переписан; дымовые тесты релизного бинаря (19б, задания `smoke` и `release-smoke`); модель угроз T19; вопросы Q3, Q4. Редакция 1 от 2026-10-26, основа HEAD `1488f86`, ветка `claude/hopeful-hawking-2sacz9`.
Метки фактов: [П] проверено мной по файлу или исходнику; [В] вывод или память, перед кодом проверить по первоисточнику; [НП] не проверено.

Цель: релиз собирается в GitHub Actions из закреплённых входов, каждый артефакт и SBOM перечислены в манифесте, подписанном ключом владельца в формате minisign; программа офлайн проверяет подпись по вшитым публичным ключам и сверяет выбранный пользователем файл; обновление только вручную, без автообновления; единственный выход в сеть — уведомление «вышла новая версия» по подписанному манифесту с фиксированного адреса GitHub Releases, только с согласия пользователя.

## 0. Разбиение и порядок

| Подэтап | Что | Критичность | Исполнитель, effort | Ждёт |
|---|---|---|---|---|
| 19а | крейт `chervo-update` (разбор minisign, манифест, проверка артефакта, вшитые ключи), команды CLI `verify-release`, `release-keys`, инструмент сборки манифеста, fuzz | КРИТИЧНЫЙ | builder sonnet/high; приёмка verifier sonnet/low; ревью security opus/high | ничего |
| 19б | `release.yml` (черновик релиза), закрепление всех actions по SHA (C31), скрипт подписи владельца, запрет секретного ключа в репозитории, проверки состава и зависимостей бинарей, эксперимент воспроизводимости, дымовые тесты релизного бинаря (`smoke`, `release-smoke.yml`) | КРИТИЧНЫЙ (цепочка поставок, токен с правом записи) | builder sonnet/high; ревью security opus/high; дирижёр сам перепроверяет SHA | 19а (шаги «проверить своим бинарём» и `smoke`); 19в (только шаг `chervo doctor` в `smoke`; до слияния 19в шаг не добавляется) |
| 19в | `chervo doctor` (хранилище ключей ОС, только чтение), `docs/INSTALL.md` (Windows SmartScreen, macOS Gatekeeper, Linux Secret Service, первая загрузка), `docs/HEADLESS_LINUX.md` (мини-ПК) | обычный | builder sonnet/medium; ручная проверка владельцем | ничего |
| 19д | крейт `chervo-update-check` (HTTPS-запрос к вшитому адресу, манифест и подпись последнего релиза, проверка подписи и версии), команда CLI `chervo check-update`, fuzz разбора HTTP-ответа | КРИТИЧНЫЙ (сеть, недоверенный ввод) | builder sonnet/high; приёмка verifier sonnet/low; ревью security opus/high | 19а слит (API `verify_manifest`, `KeySet`, `Version`, `Target`); ответ Q4 (новая зависимость) |
| 19г | упаковка GUI на 3 ОС, экран «проверить файл обновления», экран согласия и периодическая проверка обновлений (на крейте 19д), реэкспорт `chervo_update` и `chervo_update_check` через `chervo-core` | обычный, итоговое ревью security перед первым публичным релизом | дополнение к спецификации пишет architect после слияния 18; builder sonnet/medium | этап 18 слит, 19д слит, ответы Q2, Q3 |

Параллельно с этапом 18 идут 19а, 19б, 19в, затем 19д. **Крейт GUI и `chervo-core` в 19а-19в и 19д не трогать** (этап 18 в ветке `claude/angry-ritchie-a296d8`; конфликт слияния исключаем). 19б до появления GUI собирает существующий бинарь `chervo` (`crates/chervo-cli`) и создаёт только **черновик** релиза: публикует владелец вручную; первый публичный релиз после 19г.

## 1. Решения architect (обоснование кратко)

Р1. **Формат подписи: minisign, алгоритм `ED` (Ed25519 над BLAKE2b-512 файла).** Подписывает владелец штатной программой minisign (или rsign2) [В: обе совместимы по формату; версии и лицензии проверить до 19б]; проверку пишем сами **только как разбор формата**, примитивы из библиотек, уже стоящих в workspace:
- `ed25519-dalek =3.0.0`, лицензия BSD-3-Clause, `VerifyingKey::from_bytes`, `is_weak`, `verify_strict` [П: `~/.cargo/registry/.../ed25519-dalek-3.0.0/Cargo.toml:49`, `src/verifying.rs:175,200,367`; уже используется в `chervo-identity/src/keys.rs:76`];
- `blake2 =0.10.6`, MIT OR Apache-2.0, `Blake2b512` [П: `blake2-0.10.6/Cargo.toml:30`, `src/lib.rs:137`];
- `ring =0.17.14` (`ring::digest::SHA256`) для хэшей артефактов [П: `Cargo.toml` workspace].
Новых внешних пакетов в 19а нет, `deny.toml` не меняется. Крейта base64 в `Cargo.lock` нет [П]; кодировка фиксированной длины (56, 100, 88 символов) разбирается своим строгим декодером (не криптография; каноничность проверяется повторным кодированием; тесты RFC 4648 разд. 10; fuzz).
Отвергнуто: `minisign-verify` [В: по памяти несёт собственную реализацию Ed25519 и BLAKE2b; второй, менее проверенный Ed25519 не берём; не проверено]; свой формат подписи (нечем проверить вручную); Sigstore/attestations GitHub (сторонний сервис, BRIEF разд. 2); подпись Authenticode/Apple (U18, Q2).
**Формат minisign до первой строки кода открыть по первоисточнику** (описание формата на jedisct1.github.io/minisign и исходник minisign) и сверить с разд. 2 [В]; расхождение = стоп.

Р2. **Подписывается манифест, а не только каждый файл.** Манифест перечисляет версию, коммит и для каждого артефакта цель (ОС-архитектура), SHA-256, размер, имя. Программа ищет артефакт по хэшу (браузер мог переименовать файл в `chervo (1).exe`), затем проверяет цель и версию. Так закрыты подмена файлом чужой ОС и откат на старую версию. Дополнительно владелец подписывает каждый файл (`.minisig` рядом) для ручной проверки штатным minisign без нашей программы (первая установка). Тот же подписанный манифест — единственный источник версии для уведомления 19д.

Р3. **Вшиты два ключа с первого релиза:** основной (Primary) и запасной (Backup, хранится офлайн, не используется до компрометации основного). Принимается подпись любым вшитым ключом. Ротация и отзыв в разд. 4. Постоянного состояния (списка отозванных) в 19а нет: отзыв = следующий бинарь не содержит ключа.

Р4. **Сеть только в уведомлении о новой версии (19д); проверка файлов обновления локальная.** Программа не скачивает бинари и не заменяет сама себя: пользователь скачивает файлы со страницы GitHub Releases, проверяет их `chervo verify-release` (или экраном 19г) без сети и заменяет файл вручную. Уведомление: программа обращается только к вшитому в код адресу GitHub Releases проекта (не из конфига и не из сети) по HTTPS, скачивает только `chervo-release.txt` и `chervo-release.txt.minisig` последнего релиза с жёсткими пределами размера и времени, проверяет подпись вшитыми ключами (19а) и сообщает версию, только если подпись верна и версия новее запущенной. Никакие URL, тексты и имена из ответа сети пользователю не показываются и не открываются; ссылка ведёт на вшитую страницу релизов. Проверка редкая (не чаще раза в сутки и по кнопке), без идентификаторов в запросе, сбой молчаливый (в фоне). Включается только с согласия пользователя (BRIEF разд. 2: чужой сервис; BRIEF разд. 7 стр. 62 прямо допускает GitHub Releases с проверкой подписи); умолчание — Q3. В CLI только явная однократная команда `chervo check-update` (сам вызов = согласие на один запрос, ничего не сохраняет); периодическая проверка и экран согласия — в GUI 19г.

Р5. **Откат запрещён по умолчанию:** версия манифеста меньше версии запущенной программы = `Downgrade`; разрешается только явным флагом `--allow-downgrade` с предупреждением. Атаку «заморозки» (скрыть новый релиз) не закрываем: обновление ручное, источник один; уведомление 19д заморозку тоже не закрывает (разд. 8).

Р6. **Уровень воспроизводимости, честно:** закреплены toolchain (`1.99.1`, `rust-toolchain.toml`) [П], `Cargo.lock` с `--locked`, версии cargo-инструментов, actions по SHA, образы раннеров по имени с версией; в манифест пишется SHA коммита. **Побитовая воспроизводимость не заявляется** [НП]. В 19б эксперимент: Linux-бинарь собирается двумя независимыми заданиями, SHA-256 сравниваются, результат записывается, релиз от него не зависит. Подпись владельца удостоверяет «эти байты собраны CI из тега X, и я сверил их хэши», а не независимую сборку: **закладку, внесённую во время сборки в CI, подпись не ловит**, она защищает от подмены файлов после сборки (OWNER_DECISIONS, этап 19).

Р7. **Linux «установщик» ничего не ставит.** Проверку Secret Service делает `chervo doctor`; при отсутствии печатает понятный текст и точную команду для пользователя (например `sudo apt install gnome-keyring`), но **сам пакетный менеджер не запускает никогда** (строже, чем «без да не ставит»). На файловое хранилище молча не переходит (локальные ключи U10c не реализованы и не предлагаются, SECURITY_REVIEW разд. 8).

Р8. **Чем делать HTTPS в 19д (решение за владельцем, Q4).** Без нового пакета нельзя [П: в `Cargo.lock` нет `webpki-roots`, `rustls-native-certs`, `ureq`, `hyper`, `httparse`; `rustls 0.23.46` в проекте проверяет только закреплённые ключи пар, корневых сертификатов нет]. Нужны как минимум корневые сертификаты. Варианты:
- (а) **рекомендую:** свой минимальный HTTP/1.1 `GET` поверх уже стоящих `rustls =0.23.46` (`ring`, `std`) и `std::net::TcpStream`, плюс один новый пакет `webpki-roots` (корни Mozilla, данные внутри бинаря) [В: версия 1.x, лицензия CDLA-Permissive-2.0, зависит только от `rustls-pki-types` — сверить по Cargo.toml пакета; лицензии нет в `deny.toml` allow, добавить исключением только для этого пакета]. Разбор ответа узкий (статус, `Location`, `Content-Length`), тело дальше проверяется подписью; ~300-400 строк, fuzz. Прецедент: свой клиент Secret Service (17а) вместо пакета.
- (б) `ureq` 3.x без default features, с rustls и `webpki-roots` [В: тянет ещё ~7 пакетов: `ureq-proto`, `http`, `httparse`, `base64`, `log`, `percent-encoding`, `utf-8`; по умолчанию читает переменные прокси; версии сверить]. Зрелый клиент, меньше своего кода, больше поверхности цепочки поставок.
- (в) как (а), но корни из ОС через `rustls-native-certs` [В: на Windows и macOS тянет платформенные пакеты]. Корни обновляет ОС, лицензии в пределах allow, но больше платформенного кода и разное поведение на 3 ОС.
Устаревание корней в (а) и (б): старый бинарь через годы может перестать доверять сертификату GitHub, тогда уведомление молча перестаёт работать (подлинность от этого не страдает, она на подписи).

## 2. Форматы (точно)

**Публичный ключ** (`crates/chervo-update/keys/primary.pub`, `backup.pub`, файлы minisign) [В: формат minisign, сверить]:
```
untrusted comment: <любой текст, игнорируется, до 1024 байт>\n
<base64 ровно 56 символов> = "Ed" (2 байта) || key_id (8) || ed25519_pk (32)
```
Необязательный завершающий `\n`; `\r\n` допускается вместо `\n` (файл мог пройти через Windows). Файл до 1024 байт. Отвергать: другой алгоритм, неканонический base64, ключ, который не принимает `VerifyingKey::from_bytes`, и слабый ключ (`is_weak()`).

**Подпись** (`chervo-release.txt.minisig`, до 4096 байт; `\r\n` допускается как в ключе):
```
untrusted comment: <игнорируется, до 1024 байт>\n
<base64 100 символов> = "ED" || key_id (8) || sig (64)
trusted comment: <текст до 1024 байт, без управляющих символов>\n
<base64 88 символов> = global_sig (64)
```
Проверка: `verify_strict(pk, BLAKE2b-512(manifest_bytes), sig)` и `verify_strict(pk, sig || trusted_comment_text, global_sig)` [В: так в minisign; сверить]. Алгоритм `Ed` (без предхэширования) отвергается кодом `UnsupportedAlgorithm`. Обе подписи обязательны. Доверенный комментарий только для показа, решений по нему нет (в уведомлении 19д не показывается).

**Манифест** `chervo-release.txt` (до 64 КиБ, ASCII, только `\n`, каждая строка заканчивается `\n`, без пробелов в конце, одиночные пробелы между полями):
```
chervo-release-manifest 1
version <MAJOR.MINOR.PATCH, десятичные u32 без ведущих нулей>
commit <40 hex строчными>
artifact <target> <sha256: 64 hex строчными> <size: десятичное u64 без ведущих нулей> <name>
... (1..=32 строк artifact)
```
`target` из закрытого списка: `linux-x86_64`, `macos-aarch64`, `macos-x86_64`, `windows-x86_64`, `any` (SBOM и прочие файлы для всех). `name`: `[A-Za-z0-9._-]`, 1..=128 байт, не начинается с `.`, уникально. Одинаковые хэши в двух строках запрещены. Неизвестное ключевое слово, другой порядок, `\r`, табуляция, пустая строка = ошибка с номером строки. Другая версия формата = `UnsupportedManifestVersion`. Генератор и разборщик один код: `Manifest::to_canonical_bytes()`; свойство «разобранное и снова записанное совпадает побайтно».

Имена файлов манифеста и подписи в каждом релизе фиксированы: `chervo-release.txt` и `chervo-release.txt.minisig` (на них опирается 19д).

**Цель запущенной программы:** `Target::current()` из `std::env::consts::{OS, ARCH}`: (`linux`,`x86_64`), (`macos`,`aarch64`), (`macos`,`x86_64`), (`windows`,`x86_64`); иначе `None` (подходят только строки `any`).

## 3. Подэтап 19а: крейт `chervo-update` и CLI          КРИТИЧНЫЙ

Прочитать: этот файл целиком; `Cargo.toml` (workspace: зависимости, линты); `crates/chervo-identity/src/keys.rs` (вызов `verify_strict`); `crates/chervo-receive/tests/fuzz_smoke.rs` (соглашения `CHERVO_FUZZ_ITERS`, `CHERVO_FUZZ_SEED`); `fuzz/Cargo.toml` и `fuzz/fuzz_targets/token_decode.rs`; `crates/chervo-cli/src/main.rs`, `crates/chervo-cli/tests/hardens_first.rs`; первоисточник формата minisign (Р1). Больше ничего не искать.

Сделать:
1. Новый крейт `crates/chervo-update` в `members` workspace; зависимости только `ed25519-dalek`, `blake2`, `ring` (workspace-версии, без новых features, если сборка не требует; потребовала = стоп); `[lints] workspace = true` (`unsafe_code = "forbid"`). Крейт не зависит от других крейтов `chervo-*`.
2. Модули: `b64` (строгий декодер фиксированной длины), `minisig` (публичный ключ, подпись), `manifest` (разбор, каноническая запись), `keys` (набор вшитых ключей), `verify` (проверка манифеста и артефакта), `lib.rs` (публичный API ниже). Порядок проверки: пределы длины -> разбор подписи -> поиск ключа по key_id -> обе подписи -> **только потом** разбор манифеста -> сверка артефакта.
3. Вшитые ключи: `include_bytes!("../keys/primary.pub")` и `backup.pub`. В 19а файлы **пустые** (владелец ещё не создал ключи): `KeySet::embedded()` возвращает `NoTrustedKeys`. Файл `tests/embedded_keys.rs` с тестом `embedded_keys_ready` под `#[ignore]`: оба файла разбираются, два разных key_id, роли Primary и Backup. Release-workflow (19б) запускает его с `--include-ignored`, поэтому релиз без ключей владельца невозможен. Ключи коммитит владелец или дирижёр по его файлам `.pub` (публичные ключи не секрет) отдельным коммитом.
4. Файл `tests/manifest_file.rs` с тестом `manifest_file_is_canonical` под `#[ignore]`: читает путь из `CHERVO_MANIFEST`, `Manifest::parse` проходит и `to_canonical_bytes()` равно файлу.
5. Бинарь-инструмент `crates/chervo-update/src/bin/chervo-make-manifest.rs` (в релиз не входит: релиз собирает только `--bin chervo`): `chervo-make-manifest --version V --commit SHA --out FILE (--artifact TARGET PATH)...` хэширует файлы потоково и пишет каноничный манифест; имя = последний компонент `PATH` (проверяется по правилам разд. 2).
6. CLI `crates/chervo-cli` (добавить зависимость `chervo-update`; `harden_process()` остаётся первой строкой, `hardens_first` зелёный; разбор аргументов вручную, без новых пакетов):
   - `chervo verify-release <manifest> <minisig> <file>... [--allow-downgrade]`: на каждый файл одна строка `OK <name> <version> newer|same|older-allowed` или `FAIL <код>`; код возврата 0 если все OK, 1 если хоть один FAIL или манифест не прошёл, 2 при ошибке использования. Сообщения по-русски, без эха содержимого файлов.
   - `chervo release-keys`: роль, key_id (16 hex, как в комментарии minisign [В]) и строка публичного ключа base64 для сверки с README; при пустых файлах: «ключи владельца не вшиты» и код 1.
7. Fuzz: цели libFuzzer `update_pubkey`, `update_minisig`, `update_manifest` в `fuzz/fuzz_targets/` (обновить `fuzz/Cargo.toml`, `fuzz/Cargo.lock`); stable fuzz-смоуки в крейте `fuzz_smoke_update_{pubkey,minisig,manifest}` по соглашениям проекта; свойства: нет паники; для `Ok` манифеста каноничная запись равна входу; случайные подписи не проходят `verify_manifest` с тестовым ключом.
8. Страж исходников `tests/src_guard.rs`: в `src/` (кроме `src/bin/`) нет `std::net`, `TcpStream`, `UdpSocket`, `std::process`, `Command`, `reqwest`, `ureq`, `hyper`, `fs::write`, `rename`, `set_permissions`, `remove_file`; `Cargo.toml` крейта перечисляет ровно разрешённые зависимости. (Сеть 19д живёт в отдельном крейте `chervo-update-check`; этот страж остаётся в силе.)

Интерфейс (точно; менять только по согласованию с дирижёром):
```rust
pub const MAX_MANIFEST_LEN: usize = 64 * 1024;
pub const MAX_MINISIG_LEN: usize = 4096;
pub const MAX_PUBKEY_LEN: usize = 1024;
pub const MAX_ARTIFACTS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub struct KeyId(pub [u8; 8]);
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum KeyRole { Primary, Backup }
pub struct KeySet { /* приватно: Vec<(KeyRole, KeyId, VerifyingKey)> */ }
impl KeySet {
    pub fn embedded() -> Result<KeySet, UpdateError>;
    pub fn from_pubkey_files(files: &[(KeyRole, &[u8])]) -> Result<KeySet, UpdateError>; // пусто -> NoTrustedKeys; повтор key_id -> KeysetInvalid
    pub fn list(&self) -> Vec<(KeyRole, KeyId, [u8; 32])>;
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version { pub major: u32, pub minor: u32, pub patch: u32 }   // FromStr строгий, Display
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target { LinuxX86_64, MacosAarch64, MacosX86_64, WindowsX86_64, Any } // FromStr/Display по разд. 2
impl Target { pub fn current() -> Option<Target>; }
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Artifact { pub target: Target, pub sha256: [u8; 32], pub size: u64, pub name: String }
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest { pub version: Version, pub commit: [u8; 20], pub artifacts: Vec<Artifact> }
impl Manifest { pub fn parse(b: &[u8]) -> Result<Manifest, UpdateError>; pub fn to_canonical_bytes(&self) -> Vec<u8>; }
/// Создаётся только `verify_manifest` (поля приватные, геттеры `manifest()`, `signer()`, `trusted_comment()`).
pub struct VerifiedManifest { /* manifest, signer: (KeyRole, KeyId), trusted_comment: String */ }
pub fn verify_manifest(keys: &KeySet, manifest: &[u8], minisig: &[u8]) -> Result<VerifiedManifest, UpdateError>;
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum Freshness { Newer, Same, OlderAllowed }
pub struct CheckedArtifact { pub artifact: Artifact, pub version: Version, pub freshness: Freshness }
pub fn check_artifact<R: std::io::Read>(vm: &VerifiedManifest, file: R, running: Version,
    target: Option<Target>, allow_downgrade: bool) -> Result<CheckedArtifact, UpdateError>;
pub fn check_artifact_path(vm: &VerifiedManifest, path: &std::path::Path, running: Version,
    target: Option<Target>, allow_downgrade: bool) -> Result<CheckedArtifact, UpdateError>;

#[non_exhaustive] #[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    TooLarge, MalformedPubkey, MalformedSignature, UnsupportedAlgorithm,
    NoTrustedKeys, KeysetInvalid, UnknownKey, BadSignature, BadGlobalSignature,
    UnsupportedManifestVersion, MalformedManifest { line: u32 },
    NotInManifest, WrongTarget { expected: Option<Target>, found: Target },
    SizeMismatch, Downgrade { running: Version, offered: Version },
    Io(std::io::ErrorKind),
}
```
`check_artifact`: читает потоком блоками по 1 МиБ, прекращает чтение и возвращает `NotInManifest`, как только прочитано больше наибольшего `size` манифеста; ищет строку с равным SHA-256; цель строки должна быть `Any` или равна `target`, иначе `WrongTarget`; `size` должен совпасть; версия: больше `running` -> `Newer`, равна -> `Same`, меньше -> `Downgrade` или `OlderAllowed` при `allow_downgrade`. `Display` ошибок не содержит байтов входа.

Не делать: не трогать `chervo-core`, крейт GUI, `chervo-identity`; не добавлять внешних пакетов (нужен пакет = стоп); никакой сети, записи файлов, запуска процессов, замены собственного бинаря; не генерировать ключи владельца, не класть в репозиторий секретных ключей (тестовые ключи только из фиксированного зерна прямо в коде тестов с пометкой «тестовый»).

Недоверенный ввод: все три файла и проверяемый артефакт. Длины проверяются до разбора; base64 только канонический; key_id сверяется до проверки подписи; при любой ошибке нет паники и нет частичного результата.

Критерии приёмки (каждый проверяется командой):
- [ ] `cargo build --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`; `bash scripts/check-forbidden.sh`
- [ ] `cargo test -p chervo-update --locked`: проходят `pubkey_ok`, `sig_ok_test_key` (подпись minisign-формата, собранная в тесте `ed25519-dalek` из фиксированного зерна), `rejects_legacy_ed_alg`, `rejects_unknown_key_id`, `rejects_flipped_bit_manifest`, `rejects_flipped_bit_sig`, `rejects_bad_global_sig`, `rejects_changed_trusted_comment`, `rejects_noncanonical_base64`, `rejects_wrong_lengths`, `rejects_oversize_inputs`, `rejects_weak_pubkey`, `rejects_sig_other_key_same_id`, `keyset_duplicate_ids_rejected`, `keyset_empty_is_no_trusted_keys`, `manifest_grammar_table` (не меньше 25 злых строк: `\r`, хвостовой пробел, нет `\n` в конце, повтор имени, повтор хэша, ведущие нули, верхний регистр hex, неизвестная цель, неизвестное слово, 33 артефакта, переполнение u32/u64, имя с `/`, `\`, `..`, пустое имя), `manifest_canonical_roundtrip`, `artifact_ok_newer`, `artifact_same_version`, `artifact_wrong_target`, `artifact_not_in_manifest`, `artifact_stops_reading_after_max_size`, `downgrade_rejected_unless_allowed`, `b64_rfc4648_vectors`, `src_guard`, три `fuzz_smoke_update_*`
- [ ] **Совместимость с настоящим minisign:** тест `real_minisign_fixture` на файлах, подписанных настоящей программой minisign (одноразовый тестовый ключ; `.pub`, файл и `.minisig` в `crates/chervo-update/tests/fixtures/`; создаёт владелец или берутся из тестов репозитория minisign с указанием источника и версии). Нет фикстуры = критерий записать «не проверено»; подписью из нашего же кода не подменять
- [ ] `cargo test -p chervo-cli --locked`: `hardens_first` и новые `verify_release_ok`, `verify_release_tampered_exit1`, `verify_release_usage_exit2`, `release_keys_placeholder_exit1`
- [ ] libFuzzer `update_pubkey`, `update_minisig`, `update_manifest` по 60 с без падений (Linux-машина владельца, `nightly-2026-10-01` как в этапе 17); нет прогона = записать «не проверено»
- [ ] `cargo deny check advisories bans licenses sources` и `cargo audit --deny warnings` зелёные; `git diff Cargo.lock` содержит только запись `chervo-update` и строки его зависимостей

## 4. Ключи владельца: создание, хранение, ротация, утечка

Решение владельца Q1 = (а), 2026-10-27: подписывает владелец локально, ключа в CI нет (OWNER_DECISIONS, этап 19).

Создание (владелец, на своём ПК): `minisign -G -p primary.pub -s primary.key`, так же `backup` [В: синтаксис сверить с `minisign -h` установленной версии]; секретный ключ зашифрован паролем [В: в minisign через scrypt; сверить]. Основной: на ПК владельца, вне облачной синхронизации и вне репозитория, длинный пароль. Запасной: сразу на офлайн-носитель (две копии в разных местах), с ПК удалить; пароль отдельный. Оба `.pub` в `crates/chervo-update/keys/`; key_id в `README` и во втором канале владельца (например его Telegram), чтобы первую загрузку можно было сверить не только через GitHub.

Запрет в репозитории (19б): `scripts/check-forbidden.sh` (с самопроверкой) падает на строках `minisign encrypted secret key` и `minisign secret key` и на файлах `*.key` в индексе; `.gitignore` получает `*.key`.

Плановая ротация: релиз N подписан старым основным ключом и вшивает новый набор (новый основной + запасной); с N+1 подпись новым ключом. Пропустивший N проверит N+1 только после установки N (в README: «обновляйтесь через N»). Уведомление 19д у пропустившего N покажет N+1 только если манифест N+1 подписан ключом, который у него вшит; иначе молчит: поэтому в README и заметках N+1 повторять «обновляйтесь через N».

**Утечка основного ключа.** Злоумышленник может подписать поддельный манифест и бинарь, которые примет любая установленная версия. Не может доставить их без участия пользователя (автообновления нет; нужно ещё убедить скачать). Если он ещё и подменяет ответ сети (19д), уведомление покажет поддельную «новую версию», но кнопка ведёт на вшитую страницу релизов настоящего репозитория, а не на его файл. Действия владельца: (1) выпустить релиз, подписанный **запасным** ключом, где основной удалён из вшитого набора, а новый запасной создан; (2) объявить в README, на странице релиза и во втором канале: «файлам, подписанным ключом `<key_id>`, не доверять»; (3) после установки нового релиза старый ключ у пользователя больше не принимается. **Остаток:** пока пользователь не поставил новый релиз, его версия принимает подписи утёкшего ключа; окно не ограничено и зависит от пользователя [В]. Постоянного списка отозванных ключей нет (Р3): он сократил бы окно только для тех, кто уже видел подлинный отзыв, и требует записи состояния; отложено.
**Утечка или потеря обоих ключей:** проверка обновлений бессильна; нужна переустановка с ручной сверкой нового ключа по внешнему каналу. Потеря без утечки (забыт пароль): то же, без угрозы.
**Отвергнутый вариант Q1 (б), ключ в секретах CI:** утечкой ключа стал бы захват аккаунта GitHub владельца, токена записи или workflow с доступом к секретам; подпись тогда не добавляла бы защиты сверх доверия GitHub [В].

## 5. Подэтап 19б: release workflow, actions по SHA, подпись владельцем, дымовые тесты          КРИТИЧНЫЙ

Прочитать: этот файл (разд. 1, 2, 4, 5); `.github/workflows/ci.yml`; `rust-toolchain.toml`; `deny.toml`; `scripts/check-forbidden.sh`; `scripts/ci-secret-service.sh`; `docs/SECURITY_REVIEW.md` разд. 5 и 8.

Сделать:
1. **C31, все actions по SHA** в `ci.yml` и новых `release.yml`, `release-smoke.yml`: `uses: owner/repo@<40 hex коммита> # vX.Y.Z`. SHA коммита получать с разыменованием аннотированного тега (`git ls-remote https://github.com/actions/checkout 'refs/tags/vX.Y.Z^{}'`; без `^{}` у аннотированного тега будет SHA объекта тега, а не коммита). Разрешены только `actions/checkout`, `actions/upload-artifact`, `actions/download-artifact`; сторонние actions запрещены. Новый скрипт `scripts/check-actions-pinned.sh` (+ `--self-test`) в задании `lint`: каждая строка `uses:` во всех workflow имеет 40 hex и комментарий с тегом; локальные `./.github/workflows/...` разрешены.
2. `ci.yml`: добавить `workflow_call` в `on:` (остальное без изменений, кроме п.1).
3. `.github/workflows/release.yml`:
   - запуск: `push` тегов `v[0-9]+.[0-9]+.[0-9]+` и `workflow_dispatch` (только пробный прогон, без задания `draft`); `pull_request*` нет; `permissions: {}` наверху, задания получают минимум (`contents: read`; `contents: write` только у задания `draft` и только при запуске от тега); `concurrency` на тег; кэшей (`actions/cache` и подобных) нет; везде `persist-credentials: false`.
   - `ci`: `uses: ./.github/workflows/ci.yml` (все задания: тесты 3 ОС, supply-chain, sbom, secret-service-live). Это автоматическая часть условия «релиз невозможен без зелёного этапа 17».
   - `gate` (ubuntu): `fetch-depth: 0`; коммит тега предок `origin/main`; версия тега равна `version` workspace (`cargo metadata --no-deps --locked --format-version 1`); `cargo test -p chervo-update --locked --test embedded_keys -- --include-ignored` (ключи владельца вшиты).
   - `build` (матрица; раннеры с явной версией образа вместо `*-latest` [В: доступные метки проверить на дату работы]; Linux — самый старый поддерживаемый образ Ubuntu, минимальная glibc записывается в заметки выпуска): `rustup toolchain install 1.99.1 --profile minimal`; `cargo build --release --locked -p chervo-cli --bin chervo` (никаких `--examples`, `--all-targets`, `--workspace`); окружение `CARGO_PROFILE_RELEASE_STRIP=symbols`, `CARGO_PROFILE_RELEASE_DEBUG=0`, `RUSTFLAGS` с `--remap-path-prefix` для каталога сборки и `CARGO_HOME`, для Windows ещё `-C target-feature=+crt-static` (без зависимости от VC++ redistributable); macOS: `aarch64-apple-darwin` обязательно, `x86_64-apple-darwin` кросс-сборкой на том же раннере, если собирается без новых инструментов, иначе записать «нет». Имя `chervo-<ver>-<target>[.exe]`. Проверка зависимостей бинаря: Linux `ldd` только `libc`, `libm`, `libgcc_s`, `ld-linux*`, `linux-vdso`; macOS `otool -L` только `/usr/lib/*` и `/System/Library/Frameworks/*`; Windows: в импорте нет `VCRUNTIME*`/`MSVCP*`/`api-ms-win-crt-*` (инструмент на раннере назвать в отчёте; нет инструмента = «не проверено»).
   - `repro` (ubuntu, как `build` для Linux, отдельное задание): сравнить SHA-256 с `build`, записать «совпало/не совпало» в `$GITHUB_STEP_SUMMARY`; релиз не валит.
   - `assemble` (ubuntu): скачать артефакты; SBOM `cargo cyclonedx` (`=0.5.9`, `--locked`) для `chervo-cli` как `chervo-<ver>-sbom.cdx.json` (если `cargo cyclonedx --help` версии 0.5.9 даёт выбор цели, по SBOM на цель; иначе один и пометка в заметках выпуска) [НП]; **белый список**: в каталоге выпуска ровно ожидаемые имена (бинари по целям + SBOM), любой лишний файл (в том числе `node13`, `node14`, `node15`, `node16`, `netcheck`, `upnp_probe`, `knockflood`) = провал; `cargo run --locked -p chervo-update --bin chervo-make-manifest -- ...` -> `chervo-release.txt`; проверка формата `CHERVO_MANIFEST=<путь> cargo test -p chervo-update --locked --test manifest_file -- --include-ignored`.
   - `smoke` (матрица тех же ОС, `needs: [assemble]`, `contents: read`): **запускается собранный релизный файл, а не тестовые обёртки и не пересборка.** Скачать артефакт своей цели из `assemble` и `chervo-release.txt`; SHA-256 файла равен строке манифеста (иначе провал); затем этим файлом:
     - `chervo --version` печатает версию тега (при `workflow_dispatch` версию workspace);
     - `chervo release-keys`: код 0 и два ключа (при `skip_keys_check` код 1 и «ключи владельца не вшиты»);
     - `chervo verify-release chervo-release.txt <minisig> <свой файл>`, где `<minisig>` — подпись из фикстуры 19а `crates/chervo-update/tests/fixtures/` (чужой одноразовый ключ): код 1, строка `FAIL` с кодом `UnknownKey` (при `skip_keys_check` — `NoTrustedKeys`). Манифест в CI ещё не подписан; положительная проверка в `release-smoke.yml` (п. 3а);
     - `chervo doctor` с **настоящим** хранилищем ОС (после слияния 19в): Linux — два прогона: с gnome-keyring, поднятым как в `scripts/ci-secret-service.sh` («доступно», код 0), и без демона Secret Service («недоступно», код 1); Windows и macOS — один прогон, вывод и код в `$GITHUB_STEP_SUMMARY`, критерий: код 0 или 1 с одной из трёх строк разд. 6, без падения и без зависания (таймаут шага 60 с) [НП: доступны ли Credential Manager и связка ключей macOS в сессии раннера]; положительная проверка этих хранилищ — ручной пункт чек-листа (п. 4);
     - `macos-x86_64`: запуск только если есть раннер Intel или Rosetta на раннере [В]; иначе в сводке «не проверено»;
     - `chervo check-update` в CI не запускается (релиз ещё черновик, сеть к GitHub из CI не нужна).
   - `draft` (только тег, `contents: write`, `needs` включает `smoke`): `gh release create "$TAG" --draft --verify-tag --notes-file ...` с файлами выпуска и манифестом; `GH_TOKEN: ${{ github.token }}` [В: `gh` предустановлен на раннерах; проверить]. Публикацию workflow не делает.
3а. `.github/workflows/release-smoke.yml` (запускает владелец после `sign.sh`, до публикации): `workflow_dispatch` с входом `tag`; вход передаётся через `env`, не подставляется `${{ }}` в `run`, и до использования проверяется по `^v[0-9]+\.[0-9]+\.[0-9]+$`; матрица 3 ОС; `persist-credentials: false`; кэшей нет. `gh release download "$TAG"` в новый пустой каталог [В: по документации GitHub черновик виден только с правом записи; если `contents: read` недостаточно — `contents: write` только этому заданию, и `scripts/check-actions-pinned.sh` (или отдельный страж с `--self-test`) проверяет, что в `release-smoke.yml` нет `gh release create|upload|edit|delete` и `gh api`]. Скачанным бинарём своей цели:
   - `chervo verify-release chervo-release.txt chervo-release.txt.minisig <бинарь своей цели> <файлы цели any>`: код 0, каждая строка `OK ... same`;
   - тот же вызов с бинарём другой цели: код 1, `WrongTarget`;
   - копия своего бинаря с изменённым байтом: код 1;
   - `chervo release-keys`: key_id печатаются в сводку для сверки с README.
4. `scripts/release/sign.sh` (запускает владелец на своей машине, bash: Linux-машина владельца или Git Bash): в новом пустом временном каталоге `gh release download "$TAG"`; `sha256sum` каждого файла против манифеста; `minisign -Sm chervo-release.txt -s <путь к основному ключу> -t "chervo-release <ver>"` и `minisign -Sm <файл>` для каждого артефакта (пароль вводит владелец) [В: флаги сверить]; проверка `minisign -Vm ... -p crates/chervo-update/keys/primary.pub` и своим бинарём из выпуска для текущей ОС `chervo verify-release`; показать список и спросить «загрузить подписи в черновик? (да/нет)», только при «да» `gh release upload` (имена `chervo-release.txt.minisig` и `<файл>.minisig`); публикацию скрипт **не делает**, её владелец выполняет вручную. Скрипт печатает чек-лист:
   - в `docs/SECURITY_REVIEW.md` нет открытых High/Critical на коде тега; ревью security этапов 18 и 19 есть; CI тега зелёный, задание `smoke` зелёное на всех ОС;
   - `release-smoke.yml` для этого тега зелёный на всех ОС;
   - вручную, релизным бинарём: Windows (ПК владельца, настоящий Credential Manager) `chervo doctor` -> «доступно»; Linux-машина владельца `chervo doctor` по `HEADLESS_LINUX.md`; macOS — машины нет, в заметках выпуска «на macOS не проверено»;
   - вручную, по аудиту тестов 2026-10-27 (п. 9; не блокирует, решает владелец): передача файла между двумя машинами релизными бинарями, SHA-256 совпали (как проверка 2026-10-27, но бинарём выпуска);
   - после публикации: `chervo check-update` бинарём предыдущей версии (или сборкой 0.0.0) показывает новую версию, бинарём выпуска — «установлена последняя версия».
5. `scripts/check-forbidden.sh`: запреты разд. 4 + самопроверка; `.gitignore`.
5а. **Тестовые крючки не попадают в релиз** (ограничение этапа 18а, коммит `2660c80` в ветке этапа 18). Там у `chervo-core` есть feature `test-store` (подставное хранилище ключей и крючок часов), которая включается только через dev-зависимость крейта на самого себя. С resolver 3 `--workspace`, `--all-targets` и `--all-features` объединяют dev-feature, и крючки компилируются в бинарь. Поэтому релизные бинари собираются только по пакету (`cargo build -p <крейт> --release --locked`), а в `release.yml` есть проверка-страж. Он валит сборку, если в команде сборки есть `--workspace`/`--all-targets`/`--all-features`, и, где это возможно без новых инструментов, если в итоговом наборе feature есть `test-store` (`cargo tree -e features -p <крейт> --release` или аналог). Самопроверка стража обязательна. Пока этап 18 не влит, страж проверяет хотя бы форму команды.
6. Настройки GitHub делает владелец (внешнее действие): правило защиты тегов `v*` (создаёт только владелец), защита `main`. Агенты настройки не меняют.

Не делать: не публиковать релиз, не создавать теги, не менять настройки репозитория, не добавлять секретов в Actions (Q1 = а: ключ только у владельца), не трогать крейт GUI и `chervo-core`, не использовать сторонние actions, кэши, `pull_request_target`, Sigstore/attestations; в `smoke` и `release-smoke` не пересобирать бинарь и не подменять его тестовым.

Недоверенный ввод: содержимое тега и коммита (кто может пушить теги, тот выпускает: правило защиты тегов); вход `tag` у `release-smoke` (строгий шаблон, только через `env`); артефакты между заданиями (белый список, хэши в манифесте); скачанное у владельца (новый пустой каталог, сверка SHA-256 до подписи).

Критерии приёмки:
- [ ] `bash scripts/check-actions-pinned.sh` и `--self-test` зелёные; для каждого SHA в отчёте команда разыменования тега и её вывод; дирижёр сам повторяет её хотя бы для `actions/checkout`
- [ ] `bash scripts/check-forbidden.sh --self-test` ловит подложенные строки секретного ключа minisign и файл `x.key`
- [ ] `ci.yml` зелёный на коммите правок (все задания, 3 ОС)
- [ ] Пробный прогон `release.yml` через `workflow_dispatch` до задания `gate`: `gate` **падает** на `embedded_keys` (ключи не вшиты) — проверенный отрицательный случай. Для проверки остальных заданий допустим вход `workflow_dispatch` `skip_keys_check: true`, действующий только без тега; с ним зелёные `build`, `repro`, `assemble`, `smoke`: в отчёте список файлов выпуска, вывод `ldd`/`otool -L`/проверки импорта Windows, `manifest_file` прошёл, результат `repro`; по каждой ОС из `smoke`: SHA-256 запущенного файла и строка манифеста, вывод `--version`, `release-keys`, `verify-release` (код 1, `NoTrustedKeys`), `doctor` (Linux оба случая; Windows и macOS фактический вывод, не толкование); `draft` не запускался
- [ ] Негатив белого списка: подложенный лишний файл валит проверку (`--self-test` скрипта белого списка)
- [ ] Страж прав `release-smoke.yml` (`--self-test`) ловит подложенную строку `gh release upload`
- [ ] `release-smoke.yml` прогнан на первом настоящем черновике до публикации (положительный `verify-release` на 3 ОС); до первого выпуска = «не проверено»
- [ ] `scripts/release/sign.sh` прогнан владельцем на пробном черновике с **одноразовым** тестовым ключом (не ключом релизов), черновик после удалён; не прогнан = «не проверено»
- [ ] Ручная проверка на чистых системах: Windows без VC++ redistributable (например Windows Sandbox) запускает `chervo --version`; macOS запускает после шагов `docs/INSTALL.md`; не сделано = «не проверено»

## 6. Подэтап 19в: `chervo doctor`, инструкции, мини-ПК          обычный

Сделать:
1. `chervo doctor` в `crates/chervo-cli` (зависимость `chervo-identity`, без правок самого `chervo-identity`): `OsKeyStore::open()`, затем только чтение `read_epoch()` [П: оба есть, `crates/chervo-identity/src/os_linux.rs:36,132`; на Windows/macOS проверить, что `read_epoch` у `OsKeyStore` тоже есть, иначе стоп]; итог одной из строк: «хранилище ключей доступно», «хранилище заблокировано: разблокируйте (инструкция)», «хранилище ключей недоступно: <что поставить, точная команда для вашей ОС>». Окно пароля не вызывает (`request_unlock` не использовать; решение владельца Q2 2026-10-18 «только по кнопке») [П: OWNER_DECISIONS:148]. Ничего не пишет, пакетный менеджер не запускает, на файлы не переходит. Коды: 0 доступно, 1 заблокировано или недоступно, 2 ошибка использования.
2. `docs/INSTALL.md` (для пользователя, по-русски): где скачать; как проверить первую загрузку (`minisign -Vm` с ключом из README, key_id из второго канала); Windows SmartScreen («Подробнее» -> «Выполнить в любом случае») [В]; macOS: программа не подписана Apple (U18), запуск через «Системные настройки -> Конфиденциальность и безопасность -> Всё равно открыть» или `xattr -d com.apple.quarantine` [В: поведение macOS 15 сверить]; Linux: `chmod +x`, `chervo doctor`, какие программы дают Secret Service (gnome-keyring, KWallet с Secret Service, KeePassXC) [В]; как обновиться вручную (`chervo verify-release`, затем заменить файл; почему программа не обновляется сама); уведомление о новой версии (`chervo check-update`: что уходит в сеть, что видит GitHub — после 19д).
3. `docs/HEADLESS_LINUX.md` (мини-ПК без рабочего стола, Ubuntu): пакеты, которые ставит владелец сам (`gnome-keyring`, `dbus-user-session`) [В]; `loginctl enable-linger`; запуск `gnome-keyring-daemon --components=secrets` пользовательской службой systemd [В]; после перезагрузки разблокировка по ssh: пароль через `read -rs` в stdin `gnome-keyring-daemon --unlock` (как `scripts/ci-secret-service.sh:10`) [П для CI, НП для мини-ПК]; проверка `chervo doctor`; что видно, если забыть разблокировать (ошибка «заблокировано», программа не зависает); пароль не передавать аргументом (история оболочки, список процессов).

Критерии приёмки:
- [ ] `cargo test -p chervo-cli --locked`: `doctor_usage_exit2`, `doctor_never_unlocks` (страж исходника: нет `request_unlock`, `std::process::Command`), `hardens_first`
- [ ] CI `secret-service-live`: `chervo doctor` при разблокированном gnome-keyring печатает «доступно», без демона — «недоступно» (вывод в отчёте)
- [ ] Ручная проверка на Linux-машине владельца по `HEADLESS_LINUX.md` после перезагрузки; не сделано = в документе «не проверено» с датой

## 7. Подэтап 19г (после этапа 18): упаковка GUI и экран обновления          обычный

Дополнение к спецификации пишет architect после слияния этапа 18 (фреймворк, его зависимости на Linux, формат пакета). Известно заранее:
- Windows: один `.exe` без установщика, `+crt-static`; macOS: `.app` в `.zip` или `.dmg` без подписи Apple, ad-hoc подпись компоновщика на arm64 [В]; Linux: один файл; AppImage только если не требует от пользователя libfuse2 [В: на Ubuntu 24.04 по умолчанию нет], иначе архив с бинарём. Системная зависимость GUI-фреймворка на Linux (например WebKitGTK) противоречит «ничего не доустанавливать» и решается в 18.
- Экран «Проверить файл обновления»: выбор манифеста, подписи и файла, вызов `chervo_core::update` (реэкспорт `chervo_update` добавляется в `chervo-core` в 19г; GUI зависит только от `chervo-core`), предупреждение при `OlderAllowed`; кнопки «скачать» нет, программа файлы не скачивает (Р4); показ key_id вшитых ключей; тот же результат, что `chervo doctor`, при первом запуске на Linux.
- Уведомление о новой версии (на `chervo_update_check` из 19д, через реэкспорт в `chervo-core`): экран согласия и умолчание по ответу Q3; переключатель в настройках; фоновая проверка не чаще раза в 24 ч (время последней проверки в настройках; часы ушли назад = считать «проверено сейчас», без запроса) и кнопка «Проверить сейчас»; фоновый сбой молчаливый, по кнопке — короткая фиксированная строка; в уведомлении только номер версии и кнопка, открывающая вшитую `RELEASES_PAGE` (способ открыть браузер и его зависимость решаются в дополнении 19г); при выключенном согласии сетевой код не вызывается вовсе (тест).
- Белый список выпуска расширяется пакетами GUI; оставлять ли CLI в выпуске, решает владелец при 19г.
- Перед первой публикацией: ревью security этапов 18 и 19 без открытых High/Critical.

## 7а. Подэтап 19д: уведомление «вышла новая версия»          КРИТИЧНЫЙ (сеть, недоверенный ввод)

Цель: по явному запросу программа без утечки идентификаторов узнаёт у вшитого адреса GitHub Releases, есть ли подписанный ключом владельца релиз новее запущенного, и сообщает только его номер.

Прочитать: этот файл (разд. 1 Р4, Р8; разд. 2; разд. 7а; разд. 8); публичный API `crates/chervo-update/src/lib.rs` (после 19а); `crates/chervo-transport-quinn/src/tls.rs:231` (как в проекте строится `rustls::ClientConfig` с провайдером ring); `crates/chervo-cli/src/main.rs`, `tests/hardens_first.rs`; документацию `rustls 0.23.46` (`ClientConfig`, `RootCertStore`, `StreamOwned`, `Resumption`, `ServerName`) и выбранного по Q4 пакета; документацию GitHub «Linking to releases» (адрес `releases/latest/download/<имя>`) [В]. Больше ничего не искать.

До первой строки кода (вручную, `curl -sSI` с машины builder или владельца; вывод в отчёт) [В, всё сверить]:
- `https://github.com/rekc2004/chervotochina/releases/latest/download/chervo-release.txt` отвечает перенаправлением 302 с абсолютным `Location` на `https://github.com/.../releases/download/<тег>/...`, затем на `https://release-assets.githubusercontent.com/...` или `https://objects.githubusercontent.com/...`; адрес репозитория взят из `.git/config` (`remote origin`) [П], владелец подтверждает, что он постоянный и публичный. Пока публичного релиза нет, ответ 404 — тогда записать форму перенаправлений как «не проверено» и сверить при первом выпуске;
- конечный ответ 200 с `Content-Length` и без `Transfer-Encoding`; TLS 1.3 на всех хостах цепочки.
Другая форма ответа (относительный `Location`, `chunked`, другой хост, только TLS 1.2) = стоп, вернуть architect.

Сделать:
1. Новый крейт `crates/chervo-update-check` в `members`; зависимости: `chervo-update`, `rustls` (workspace, без новых features), пакет по Q4 (при (а) `webpki-roots`, точная версия `=x.y.z` [В: сверить]); `[lints] workspace = true`. Синхронный код на `std::net::TcpStream` и потоке, без `tokio`. Сетевой код только в этом крейте; `chervo-update` остаётся без сети (его `src_guard`).
2. Константы (вшиты, не читаются из конфига, переменных окружения или сети):
   - `RELEASES_PAGE = "https://github.com/rekc2004/chervotochina/releases"`;
   - `LATEST_BASE = "https://github.com/rekc2004/chervotochina/releases/latest/download/"`, файлы `chervo-release.txt` и `chervo-release.txt.minisig`;
   - `ALLOWED_HOSTS = ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"]` (точное совпадение, строчные, без завершающей точки) [В: список сверить ручной проверкой выше], порт только 443;
   - `MAX_REDIRECTS = 3`, `MAX_HEADER_BYTES = 16 * 1024`, `MAX_LOCATION_LEN = 4096`; пределы тела = `MAX_MANIFEST_LEN` и `MAX_MINISIG_LEN` из 19а;
   - `CONNECT_TIMEOUT = 10 с` на адрес, `IO_TIMEOUT = 10 с` на чтение и запись, `TOTAL_DEADLINE = 30 с` на всю проверку.
3. Запрос — ровно эти байты (кроме пути и хоста): `GET <path> HTTP/1.1\r\nHost: <host>\r\nUser-Agent: chervo\r\nAccept: */*\r\nConnection: close\r\n\r\n`. Нет `Cookie`, `Referer`, `Accept-Encoding` (сжатия нет и распаковщика нет), `Accept-Language`, версии программы и ОС в `User-Agent`, никаких заголовков из ответа. `Set-Cookie` и остальные заголовки ответа игнорируются. Прокси и переменные окружения (`HTTPS_PROXY` и т.п.) не читаются.
4. TLS: `ClientConfig::builder_with_provider(ring)` с протоколом TLS 1.3, корни по Q4, без клиентского сертификата; ALPN `http/1.1`; `resumption = Resumption::disabled()` (нет сессионных билетов, связывающих проверки); SNI = хост из `ALLOWED_HOSTS`. Новый `ClientConfig` на каждую проверку. Проверка имени сервера и цепочки — штатная rustls, без своих верификаторов.
5. Разбор ответа (`http.rs`, функция над `impl Read`, тестируется без сети): статусная строка `HTTP/1.1 <3 цифры> <текст>\r\n`; заголовки до `\r\n\r\n` не длиннее `MAX_HEADER_BYTES`; имя заголовка `[!-~]` без `:`, сравнение без учёта регистра; значение без управляющих байтов (кроме HT), без продолжения строк; повтор `Location`, `Content-Length` или `Transfer-Encoding` = ошибка; любой `Transfer-Encoding` = ошибка; `Content-Length` десятичное без знака, больше предела тела = ошибка до чтения тела; без `Content-Length` тело читается до закрытия, но не больше предела + 1 байт (больше = ошибка); тело короче `Content-Length` = ошибка. Статусы: 200 — тело; 301, 302, 303, 307, 308 — нужен `Location`; прочие (включая 1xx, 204, 304, 404, 5xx) = ошибка. Тело перенаправлений не читается.
6. `Location`: только абсолютный `https://<хост><путь>`; хост из `ALLOWED_HOSTS` побайтно; нет порта, `userinfo` (`@`), фрагмента `#`, IP-литерала, процентного кодирования в хосте; путь начинается с `/`, байты `0x21..=0x7E`, длина до `MAX_LOCATION_LEN`. Счётчик перенаправлений общий для цепочки. Адрес перенаправления используется только как цель следующего запроса: не показывается, не пишется в журнал, не попадает в `Display`/`Debug` ошибок.
7. Порядок проверки: `KeySet::embedded()` (ошибка = `NoTrustedKeys`, **сети нет**) -> скачать подпись (предел `MAX_MINISIG_LEN`) -> скачать манифест (предел `MAX_MANIFEST_LEN`) -> `verify_manifest` -> версия манифеста строго больше `running` **и** в манифесте есть артефакт цели `Target::current()` (не `any`; `None` = нет) -> `Newer(version)`, иначе `UpToDate`. Подпись и манифест могут оказаться от разных релизов (релиз вышел между запросами) — это просто `BadSignature`, повтор при следующей проверке. Доверенный комментарий и имена артефактов не показываются.
8. Срок: работа идёт в отдельном потоке, вызывающий ждёт результат `recv_timeout(TOTAL_DEADLINE)`; по истечении `Timeout` (поток не убивается: DNS через `ToSocketAddrs` прервать нельзя, он завершится по своим таймаутам; CLI к этому моменту выходит). Адреса из DNS пробуются по порядку, каждый с `CONNECT_TIMEOUT`, в пределах общего срока.
9. CLI `chervo check-update` (без аргументов; лишний аргумент = код 2; `harden_process()` первой строкой): сначала строка «Проверка обновлений: запрос к github.com (GitHub увидит ваш IP-адрес).»; итог одной из фиксированных строк: «Вышла версия X.Y.Z (у вас A.B.C). Страница загрузки: <RELEASES_PAGE>. Скачанный файл проверьте: chervo verify-release ...» код 0; «Установлена последняя версия (A.B.C).» код 0; «Ключи владельца не вшиты: проверка невозможна.» код 1 (без сети); «Нет связи с GitHub.» код 1 (`Network`, `Timeout`); «Ответ не прошёл проверку.» код 1 (`BadResponse`, `BadSignature`). Ничего не сохраняет, браузер не открывает, процессов не запускает. Версия запущенной программы — `env!("CARGO_PKG_VERSION")`, разбор строгим `Version::from_str`.
10. Fuzz: цель libFuzzer `update_http_response` (разбор ответа и `Location`); stable-смоук `fuzz_smoke_update_http` по соглашениям проекта; свойства: нет паники, нет чтения сверх пределов.
11. Страж `tests/src_guard.rs`: в `src/` нет `std::process`, `Command`, `std::env::var`, `fs::` (запись и чтение файлов), `UdpSocket`, `reqwest`, `hyper`, `println!`/`eprintln!` (печать только в CLI); `TcpStream::connect*` вызывается в одном месте; `Cargo.toml` крейта перечисляет ровно разрешённые зависимости.

Интерфейс (точно; менять только по согласованию с дирижёром):
```rust
pub const RELEASES_PAGE: &str = "https://github.com/rekc2004/chervotochina/releases";
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateStatus { Newer(chervo_update::Version), UpToDate }
#[non_exhaustive] #[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckError { NoTrustedKeys, Network, Timeout, BadResponse, BadSignature } // без данных из сети; Display — фиксированные строки
pub fn check_latest(running: chervo_update::Version) -> Result<UpdateStatus, CheckError>;
```
Внутри (`pub(crate)`, не в публичном API, только для тестов): `check_latest_with(keys, fetcher: &dyn Fetch, running, target)`, трейт `Fetch`, построение клиента с подменой адреса хоста на `127.0.0.1:<порт>` и тестовым корнем. Публичных крючков и feature для тестов нет.

Не делать: не трогать `chervo-core`, крейт GUI, `chervo-update` (кроме чтения API); не показывать и не открывать ничего из ответа сети; не скачивать бинари; не сохранять состояние, cookies, время проверки (это GUI 19г); не читать конфиг и переменные окружения для адреса, прокси, корней; не добавлять пакетов сверх ответа Q4 (нужен ещё = стоп); не вызывать сеть в обычных тестах (`cargo test` без сети к внешним хостам).

Недоверенный ввод: весь ответ сети (статус, заголовки, `Location`, тело), DNS-ответ, сертификаты. Пределы до чтения; разбор манифеста только после проверки подписи (19а); никакие байты ответа не попадают в вывод, журнал и тексты ошибок; при любой ошибке нет паники и нет частичного результата.

Критерии приёмки (каждый проверяется командой):
- [ ] `cargo build --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`; `bash scripts/check-forbidden.sh`
- [ ] `cargo test -p chervo-update-check --locked`: `request_bytes_exact`, `http_parse_table` (не меньше 25 злых ответов: нет `\r\n`, заголовки больше предела, повтор `Content-Length`, `Content-Length` больше предела, нецифры и знак в `Content-Length`, `Transfer-Encoding: chunked`, 1xx, 204, 304, 404, 500, кривая статусная строка, заголовок без `:`, продолжение строки, NUL в значении, тело короче заявленного, тело без длины больше предела), `location_table` (относительный, `http://`, с портом, `https://github.com@evil.example/`, `github.com.`, IP-литерал, чужой хост, верхний регистр хоста, `#`, пробел, длиннее предела), `redirect_chain_ok`, `redirect_limit_exceeded`, `newer_signed_shown`, `same_version_up_to_date`, `older_signed_not_shown`, `newer_without_current_target_not_shown`, `bad_signature_rejected`, `sig_and_manifest_mismatch_rejected`, `oversize_bodies_rejected`, `no_trusted_keys_makes_no_request` (счётчик `Fetch` = 0), `slow_server_hits_deadline` (локальный сервер с уменьшенным сроком через `pub(crate)`), `tls_loopback_ok` (настоящий rustls-сервер на 127.0.0.1, тестовый корень), `tls_wrong_name_rejected`, `production_roots_reject_test_cert`, `error_display_fixed`, `src_guard`, `fuzz_smoke_update_http`. Тестовые сертификаты — файлы в `tests/fixtures/` с пометкой «тестовый» и командой их создания в README фикстур; генерация без нового пакета (нет инструмента = стоп)
- [ ] `cargo test -p chervo-cli --locked`: `hardens_first`, `check_update_usage_exit2`, `check_update_no_keys_exit1` (в 19а ключи пустые: сообщение «не вшиты», код 1, без сети)
- [ ] libFuzzer `update_http_response` 60 с без падений (Linux-машина владельца); нет прогона = «не проверено»
- [ ] `cargo deny check advisories bans licenses sources` и `cargo audit --deny warnings` зелёные; `git diff Cargo.lock` — только `chervo-update-check` и пакеты ответа Q4; изменение `deny.toml` — только исключение лицензии для этого пакета (если потребуется)
- [ ] Ручная проверка реальной цепочки GitHub (`curl -sSI`, см. выше) в отчёте; после первого публичного выпуска — пункт чек-листа `sign.sh` (`check-update` старым и новым бинарём); до этого «не проверено»

## 8. Модель угроз этапа (внести в THREAT_MODEL как T19 при закрытии; T17 занят этапом 13в, T18 этапом 18)

| Атака | Мера | Остаток |
|---|---|---|
| Подмена файла на странице релиза или по пути загрузки | подпись манифеста ключом владельца, хэш артефакта, проверка офлайн | первая установка проверяется только вручную (minisign, key_id из второго канала) |
| Файл другой ОС или старой версии с подлинной подписью | цель и версия в подписанном манифесте, `Downgrade` по умолчанию | «заморозка» (скрыть новый релиз) не закрыта |
| Захват CI, аккаунта GitHub, токена записи | ключ не в CI (Q1 = а), черновик без подписи, сверка хэшей у владельца перед подписью | подменённая в CI сборка будет подписана, если владелец не заметит: подпись не ловит закладку при сборке; побитовой воспроизводимости нет (Р6) |
| Подмена action, отравленный кэш | только `actions/*` по SHA коммита, без кэшей в релизе | доверие самим `actions/*` и образам раннеров |
| Подмена зависимости crates.io | `Cargo.lock`, `--locked`, `cargo audit`/`cargo deny` в `ci` до релиза, SBOM | уязвимость, ещё не попавшая в RustSec |
| Утечка основного ключа | запасной ключ вшит, релиз от запасного удаляет основной | окно до установки нового релиза не ограничено (разд. 4); при подмене сети — ложное уведомление о версии (ссылка всё равно вшитая) |
| Злой манифест или подпись | пределы длин, разбор манифеста только после проверки подписи, fuzz | ошибки в `ed25519-dalek`, `blake2`, `ring` |
| Linux без Secret Service | `chervo doctor` сообщает, ничего не ставит, на файлы не переходит | пользователь может не запустить `doctor`; GUI (19г) показывает то же |
| Тестовая сборка вместо релизной в дымовых тестах | `smoke` запускает файл из `assemble` после сверки SHA-256 с манифестом | Credential Manager и связка ключей macOS в CI проверены только «не падает»; положительно — вручную, macOS не проверяется |
| Подмена ответа уведомления (MITM, подставной сертификат, злой GitHub) | TLS 1.3 с проверкой цепочки; версия только из манифеста с верной подписью вшитым ключом; URL, тексты, имена из ответа не показываются; кнопка ведёт на вшитую `RELEASES_PAGE` | без ключа владельца ложное уведомление невозможно; с утёкшим ключом — возможно, но доставки файла нет |
| Откат версии в уведомлении (старый подписанный манифест) | показывается только версия строго новее запущенной и с артефактом для этой ОС | «заморозка»: сеть или GitHub могут скрыть новый релиз или блокировать запрос, сбой молчаливый |
| Злой ответ сети (огромный, медленный, бесконечные перенаправления, кривые заголовки) | пределы заголовков и тела до чтения, таймауты и общий срок 30 с, до 3 перенаправлений только `https` на хосты белого списка и порт 443, fuzz разбора | ошибки в rustls и своём разборе HTTP; повисший DNS-запрос держит поток до таймаута ОС |
| Слежка по запросам уведомления | только с согласия (Q3); не чаще раза в сутки и по кнопке; нет cookies, своих заголовков, версии в `User-Agent`; сессионные билеты TLS выключены; в CLI — только явная команда | GitHub и CDN видят IP, время и факт, что на этом адресе стоит Червоточина; провайдер и ТСПУ видят DNS-запрос и SNI `github.com` и хоста CDN; публичный счётчик скачиваний ассета манифеста выдаёт примерное число проверок [В] |
| Устаревшие корни TLS в старом бинаре (Q4 а, б) | — | уведомление молча перестаёт работать; подлинность не страдает |
| Подмена файла между проверкой и запуском | вне модели: вредонос под тем же пользователем (T9/T10) | — |

## 9. Общие правила

Стоп-условия: противоречие спецификации и кода; формат minisign по первоисточнику отличается от разд. 2; нужна новая зависимость или feature (сверх ответа Q4 для 19д); форма ответов GitHub отличается от разд. 7а; критерий непроверяем; метка раннера недоступна — остановиться и доложить, не обходить.
Лимит: не более 2 кругов «правка по ревью» на подэтап, затем доложить.
Отчёт builder (до 25 строк): изменённые файлы; команды приёмки и последние строки их вывода; что не сделано; отклонения от спецификации; для 19б таблица action -> тег -> SHA -> команда проверки; для 19д вывод ручной проверки цепочки GitHub и выбранная версия пакета Q4 с источником.

## 10. Вопросы владельцу

Q1 (отвечен 2026-10-27: **(а)**). Подписывает владелец локально: CI делает черновик без подписи, владелец сверяет хэши и подписывает minisign ключом под паролем; ключ только на его ПК, запасной офлайн; на ПК владельца нужны `minisign` и `gh`.
Q2 (нужен к 19г). Подпись Windows (Authenticode, U18): (а) пока без неё, SmartScreen предупреждает, в инструкции объяснено; (б) покупать сертификат. **Рекомендую (а)**, как решено для macOS.
Q3 (нужен к 19г). Проверка новой версии по умолчанию: (а) спросить при первом запуске, до ответа выключено; (б) включено, выключается в настройках; (в) выключено, включается в настройках. **Рекомендую (а):** BRIEF требует согласия на чужие сервисы, а при каждой проверке GitHub видит ваш IP и то, что на этом адресе стоит Червоточина; (б) делает запрос без согласия; (в) честно, но многие не узнают о функции и останутся на старых версиях. CLI не зависит от ответа: там только явная команда.
Q4 (нужен к 19д). Чем делать HTTPS-запрос; новый пакет нужен в любом варианте (Р8): (а) свой минимальный HTTP-клиент на имеющемся rustls + один пакет `webpki-roots` (корни сертификатов; лицензия CDLA-Permissive-2.0 [В], нужно исключение в `deny.toml`); (б) готовый клиент `ureq` + `webpki-roots`, около 8 новых пакетов; (в) как (а), но корни из ОС (`rustls-native-certs`, платформенные пакеты). **Рекомендую (а):** один пакет-данные вместо восьми, разбор ответа узкий, а подлинность всё равно держит подпись манифеста.

## 11. Резюме для владельца
- Подпись в формате minisign, проверка в программе на уже стоящих библиотеках (ed25519-dalek, blake2, ring), новых пакетов для проверки нет; своей криптографии нет, свой только разбор формата.
- Подписываете вы у себя (Q1 = а). Подпись защищает от подмены файлов после сборки, но не от закладки, внесённой во время сборки в CI.
- Подписывается список файлов релиза с хэшами, версией и целевой ОС; старую версию программа не примет без явного флага.
- Вшиты два ключа: основной и запасной офлайн. Утёк основной: выпускаем релиз запасным, основной удаляется; до обновления у пользователя остаётся окно.
- Программа не скачивает и не заменяет себя. Единственная сеть — уведомление о новой версии (19д): запрос только к вшитому адресу GitHub, только манифест и подпись, версия показывается лишь при верной подписи; включается только с вашего согласия (Q3). Для HTTPS нужен один новый пакет (Q4).
- В CI релизный бинарь `chervo` запускается на всех ОС (`--version`, `doctor`, `verify-release`); настоящие хранилища Windows и macOS проверяются вручную, macOS — нечем.
- Побитовую воспроизводимость не обещаем: закреплённые входы и замер.
- Без GUI сейчас делаются 19а, 19б, 19в, 19д; упаковка приложения и экран согласия (19г) после этапа 18.
