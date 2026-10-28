# SPEC 19г: упаковка GUI, экран обновлений, согласие на проверку новых версий          критичность: обычный (19г-1 с точечным ревью security, см. разд. 0)

Редакция 1, 2026-10-28, architect (opus/high). Дополнение к `docs/specs/stage-19-release-signing.md` (далее «SPEC 19»), разд. 7. Основа: main после PR #8 и #9 (`23e97a1`).
Метки: [П] проверено мной по файлу (путь:строка); [В] вывод или память, сверить до кода; [НП] не проверено. Я ничего не собирал и не запускал.

Цель: релиз содержит GUI `chervotochina` для 4 целей рядом с CLI; программа при первом запуске предлагает включить проверку новых версий (до ответа выключена), проверяет не чаще раза в сутки и по кнопке только с согласия; экран «Обновления» проверяет скачанные файлы выпуска офлайн, не читая файлы в потоке окна и не показывая непроверенных строк.

## 0. Разбиение, исполнители, порядок

| Часть | Что | Исполнитель | Ждёт |
|---|---|---|---|
| 19г-1 | `chervo-core`: модуль `update` (реэкспорт, `verify_release_files`, разрешение на запрос), ключи настроек `update_check`, `update_checked_at` | builder sonnet/**high** (трогает разбор настроек и единственный вход в сеть); ревью security opus/high по списку разд. 8 | ничего |
| 19г-2 | GUI: страница «Обновления», карточка согласия, поток обновлений, часы фоновой проверки, стражи, render-check | builder sonnet/medium | 19г-1 принят |
| 19г-3 | упаковка: `build-release.sh`, `package-macos.sh`, `release.yml`, `assemble.sh`, белый список, дымовые тесты GUI, `release-smoke`, правка `sign.sh`, `docs/INSTALL.md` | builder sonnet/medium; дирижёр сам перепроверяет пробный прогон | ответ Q5 (рекомендация (а) позволяет начать сразу); параллельно с 19г-1/2 (файлы не пересекаются) |
| 19г-4 | файл лицензий сторонних компонентов | builder sonnet/medium | ответ Q6 |

Перед первой публикацией: ревью security этапов 18 и 19 без открытых High/Critical (SPEC 19 разд. 7); ручные пункты владелец проходит одним заходом (OWNER_DECISIONS «Ручные проверки (2026-10-28)»), до того они «не проверено».

## 1. Решения architect (кратко, с причиной)

Р19г-1. **Форматы пакетов.**
- Windows: один файл `chervotochina-<ver>-windows-x86_64.exe`, без установщика, ресурсов и значка (в GUI запрещён `build.rs`, страж `manifest_only_core` [П: `crates/chervo-gui/tests/manifest_only_core.rs:102`]). Статический CRT: `.cargo/config.toml` задаёт его для обычной сборки, но в релизе `build-release.sh` выставляет `RUSTFLAGS`, а переменная окружения заменяет `target.<triple>.rustflags` из конфига, а не дополняет их [В: порядок источников rustflags в документации cargo]. Поэтому явный `-C target-feature=+crt-static` в `build-release.sh:38-40` [П] **остаётся**; `check-deps.sh windows` проверяет и GUI.
- macOS: `chervotochina-<ver>-macos-aarch64.zip` и `...-macos-x86_64.zip`, внутри `Chervotochina.app` (ASCII-имя каталога; отображаемое имя «Червоточина» в `Info.plist`). Подпись ad-hoc всего пакета `codesign --force --sign - --timestamp=none` [В: флаги сверить с `man codesign` на раннере]. Без нотаризации и Developer ID (U18). Архив `ditto -c -k --keepParent` [В]. Выбран `.zip`, а не `.dmg`: нет монтирования образа, `hdiutil` не нужен, хэш считается от одного файла, `verify-release` проверяет его до распаковки.
- Linux: один ELF `chervotochina-<ver>-linux-x86_64`, как CLI. AppImage не делаем: его среда запуска требует libfuse2, которой на Ubuntu 24.04 по умолчанию нет [В]; инструменты AppImage стали бы новым входом цепочки поставок. `.desktop` и значка нет. По 18p V3 в `NEEDED` только libc-семейство, X11/Wayland/Vulkan/GL грузятся во время работы [П: `docs/reports/GUI-PROBE-2026-10-25.md:54`].
- SBOM: второй файл `chervotochina-<ver>-sbom.cdx.json` (цель `any`) из `crates/chervo-gui/sbom.json`.

Р19г-2. **Сборка только по пакету, двумя отдельными вызовами cargo:** `-p chervo-cli --bin chervo` и `-p chervo-gui --bin chervotochina`. В одном вызове с двумя `-p` resolver 3 объединил бы возможности обоих пакетов. Для каждого пакета перед сборкой нужна проверка `cargo tree -e no-dev,features`: нет `test-store` (как `build-release.sh:46-50` [П]).

Р19г-3. **Запуск пакета в CI:** `--render-check` (рисует все состояния без узла, ключей и файлов [П: `crates/chervo-gui/src/main.rs:99-101`]). `--version` у GUI нет и не добавляется: в GUI запрещена печать, а на Windows у GUI-подсистемы нет консоли. Версию GUI подтверждают сверка SHA-256 с манифестом и то, что файл собран тем же заданием из тега.

Р19г-4. **Реэкспорт без нарушения стражей GUI.** В `chervo-core` новый модуль `pub mod update` с **поимённым** реэкспортом нужных типов. `pub use chervo_update;` и `pub use chervo_update_check;` не добавляются. Тогда GUI пишет `chervo_core::update::...`, что не задевает `uses_node_api_only` (запрещено `chervo_core::chervo_`) [П: `crates/chervo-gui/tests/uses_node_api_only.rs:13`], а `manifest_only_core` не меняется: новых зависимостей у GUI нет. Сырой `chervo_update_check::check_latest` наружу из ядра **не** реэкспортируется (см. Р19г-5).

Р19г-5. **Сеть без согласия невозможна по типу.** Ядро даёт `check_latest(permit: UpdateCheckPermit, running)`. `UpdateCheckPermit` создаёт только `Node::update_check_permit`, и только если в настройках записано согласие `Enabled` и подошло время (Р19г-6). Структура без публичного конструктора, не `Clone`, тратится на один запрос. GUI не может обратиться к сети иначе: прямой зависимости на `chervo-update-check` у него нет, путь `chervo_core::chervo_*` запрещён. Поведение проверяют тесты ядра (разд. 3), а стражи GUI (разд. 4) только ограничивают места вызова.

Р19г-6. **Хранение и расписание (в ядре, в файле настроек; GUI файлов не пишет).** Ключи `update_check=0|1` (нет строки = «не спрашивали», `NotAsked`) и `update_checked_at=<секунды UTC>` (0 = не проверяли). Время записывается **до** запроса, при выдаче разрешения, поэтому сбой не вызывает повтора. Правила `decide(consent, last, now, manual)`:
- согласие не `Enabled`: отказ, файл не меняется;
- фон: `last == 0` → разрешение; `last > now` (часы ушли назад) → записать `now`, без разрешения; `now - last >= 86400` → разрешение; иначе отказ;
- кнопка: `last > now` или `now - last >= 60` → разрешение (нижний предел 60 с против случайной серии нажатий); иначе отказ;
- при выдаче разрешения `update_checked_at = now`; ошибка записи = `Err`, разрешения нет.
Фоновые такты делает поток узла GUI: сразу после открытия узла и затем раз в 3600 с. Итог: проверка не чаще раза в сутки и не позже чем через час после срока.

Р19г-7. **Файлы читает ядро и не в потоке окна.** `chervo_core::update::verify_release_files` читает манифест и подпись с пределами (`MAX_*_LEN + 1`, как `read_capped` в `crates/chervo-cli/src/release.rs:29-40` [П]) и сверяет файлы через `check_artifact_path`. GUI вызывает её только в новом потоке обновлений (`update_worker.rs`). Этот поток не держит узел, поэтому долгая сверка не задерживает команды узла. Сетевая проверка (до 30 с) идёт в том же потоке. Оба типа работы выполняются по одной, по порядку.

Р19г-8. **Показ только проверенного и безопасного текста.** Доверенный комментарий подписи в GUI **не показывается вовсе**: в представлении ядра его нет. Так закрыта находка 19а Low 1 (bidi в доверенном комментарии; TASK 19а [П: `docs/TASK.md:114`]). Имена из манифеста и так ограничены `[A-Za-z0-9._-]`, но всё равно проходят ту же очистку. Имена файлов, выбранных пользователем, показываются только как `file_name()` после `safe_label` (разд. 4, п. 6). Тексты ошибок берутся из таблицы GUI по варианту ошибки, а не из `Display` (у `UpdateError::Downgrade` в `Display` есть «--allow-downgrade» для CLI [П: `crates/chervo-update/src/lib.rs:83-86`]).

Р19г-9. **Страница релизов.** По умолчанию (рекомендация Q7, вариант (а)) вшитая `RELEASES_PAGE` показывается выделяемым текстом с кнопкой «Копировать» (`ctx.copy_text`, уже используется [П: `crates/chervo-gui/src/screens/common.rs:23`]). Ни процессов, ни новых пакетов, ни `open_url`.

Р19г-10. **Linux без Secret Service** (SPEC 19 разд. 7, «тот же результат, что `chervo doctor`»): экран 1 из 18б уже показывает `KeyStoreLocked` с текстом для Linux [П: `crates/chervo-gui/src/texts.rs:28`]. В 19г ничего нового, только строка в `INSTALL.md`.

## 2. Интерфейс (точно; приватное builder добавляет сам)

```rust
// crates/chervo-core/src/update.rs; в lib.rs: `pub mod update;` (рядом с `pub use node::*`)
pub use chervo_update::{Freshness, KeyId, KeyRole, Target, UpdateError, Version, MAX_MANIFEST_LEN, MAX_MINISIG_LEN};
pub use chervo_update_check::{CheckError, UpdateStatus, RELEASES_PAGE};

pub const UPDATE_CHECK_INTERVAL_SECS: u64 = 86_400;
pub const MANUAL_CHECK_FLOOR_SECS: u64 = 60;

/// Версия запущенной программы (`crate::VERSION`); None, если это не MAJOR.MINOR.PATCH.
pub fn running_version() -> Option<Version>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EmbeddedKey { pub role: KeyRole, pub key_id: KeyId }
/// Без ввода-вывода: разбор вшитых файлов (`KeySet::embedded()`).
pub fn embedded_keys() -> Result<Vec<EmbeddedKey>, UpdateError>;

#[derive(PartialEq, Eq, Debug)]
pub struct FileVerdict { pub name: String /* из подписанного манифеста */, pub target: Target, pub freshness: Freshness }
#[derive(PartialEq, Eq, Debug)]
pub struct ReleaseCheck {
    pub version: Version,                 // версия подписанного манифеста
    pub signer: EmbeddedKey,              // каким вшитым ключом подписан
    pub files: Vec<Result<FileVerdict, UpdateError>>, // по одному на входной файл, в том же порядке
}   // доверенного комментария здесь нет намеренно (Р19г-8)
/// Ключи: `KeySet::embedded()`. Ошибка манифеста или подписи = Err целиком (файлы не читаются).
pub fn verify_release_files(manifest: &Path, minisig: &Path, files: &[PathBuf], allow_downgrade: bool)
    -> Result<ReleaseCheck, UpdateError>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateConsent { NotAsked, Enabled, Disabled }

/// Разрешение на ОДИН сетевой запрос. Публичного конструктора нет; не Clone, не Copy, не Default.
#[derive(Debug)] pub struct UpdateCheckPermit { _sealed: () }
/// Единственный путь в сеть для оболочек на ядре. Внутри `chervo_update_check::check_latest(running)`.
pub fn check_latest(permit: UpdateCheckPermit, running: Version) -> Result<UpdateStatus, CheckError>;

// crates/chervo-core/src/node/...
impl Node {
    pub fn set_update_consent(&self, enabled: bool) -> Result<(), NodeError>;
    /// Правила Р19г-6. Ok(None): нельзя сейчас (согласия нет, рано, часы ушли назад).
    pub fn update_check_permit(&self, now_unix_secs: u64, manual: bool) -> Result<Option<UpdateCheckPermit>, NodeError>;
}
// SettingsView: новое поле `pub update_consent: UpdateConsent` (время последней проверки наружу не отдаётся).
```
Внутренние (`pub(crate)`): `fn decide(consent, last, now, manual) -> Decision { Deny, RecordOnly, Permit }`; `fn verify_release_files_with(keys: Result<KeySet, UpdateError>, ...)` для тестов; поля `Settings.update_consent: Option<bool>`, `Settings.update_checked_at: u64`. Запись: строка `update_check` только при `Some`, `update_checked_at` всегда (как `clock_offset_at` [П: `crates/chervo-core/src/node/settings.rs:329`]). `Settings::new` и `reset_settings` дают `None` и 0.

Зависимости ядра: `chervo-update.workspace = true`, `chervo-update-check.workspace = true` без `features` (у `chervo-update-check` есть `fuzzing` [П: `crates/chervo-update-check/src/lib.rs:22`]); dev-зависимости `ed25519-dalek`, `blake2` (workspace, уже в `Cargo.lock`, как в тестах `chervo-cli` [П: `crates/chervo-cli/src/release.rs:155-156`]). Новых пакетов в `Cargo.lock` нет.

## 3. 19г-1: ядро          builder sonnet/high

Прочитать: этот файл разд. 1-3, 8; `crates/chervo-core/src/{lib.rs, node/settings.rs, node/transfers.rs:270-360, node/views.rs:330-360}`; `crates/chervo-core/tests/{layout.rs, features_guard.rs, node_basic.rs, fuzz_smoke.rs, support/harness.rs}`; `crates/chervo-update/src/lib.rs`, `src/verify.rs`; `crates/chervo-update-check/src/lib.rs`; `crates/chervo-cli/src/release.rs` (образец чтения с пределом и тестового ключа). Больше ничего не искать.

Сделать:
1. Модуль `src/update.rs` строго по разд. 2. `verify_release_files`: сначала `KeySet::embedded()` (ошибка = `NoTrustedKeys` без чтения файлов), затем чтение манифеста и подписи с пределом, `verify_manifest`, затем `check_artifact_path` на каждый файл с `running_version()` и `Target::current()`. `running_version() == None` → `Err(UpdateError::MalformedManifest { line: 0 })` недопустимо по смыслу: вместо этого вернуть `Err(UpdateError::Io(ErrorKind::InvalidData))` и описать это в doc-комментарии.
2. Ключи настроек по Р19г-6: строгий разбор (`update_check` только `0|1`, повтор = `SettingsCorrupt`; `update_checked_at` через `parse_u64`), запись, круговое свойство. Цель libFuzzer `settings` и `fuzz_smoke` покрывают новые ключи без правок кода фаззинга. Если правки нужны, сделать их и указать в отчёте.
3. `Node::set_update_consent`, `Node::update_check_permit` через `update_settings` [П: `transfers.rs:275`]; `SettingsView.update_consent`.
4. Страж в `tests/layout.rs` (или новый `tests/update_reexport.rs`): в `src/lib.rs` и `src/update.rs` нет `pub use chervo_update_check;`, `pub use chervo_update;`, `pub use chervo_update_check::check_latest`, `pub use chervo_update_check::*`, `pub use chervo_update::*`; строки зависимостей `chervo-update*` в `Cargo.toml` ядра без `features`. У стража есть самопроверка на подложенной строке.

Критерии приёмки:
- [ ] `cargo build --workspace --locked`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`; `bash scripts/check-forbidden.sh`
- [ ] `cargo test -p chervo-core --locked`: зелёные прежние (`layout`, `anchored_only`, `no_logger`, `redaction`, `features_guard`, `test_store_guard`, `settings_hostile_table`, `settings_roundtrip`, `fuzz_smoke`) и новые:
  - `settings_hostile_table` дополнена не меньше чем 8 строками: `update_check=2`, `update_check=`, `update_check=01`, повтор `update_check`, `update_checked_at=-1`, `update_checked_at=01`, 21 цифра, повтор `update_checked_at`;
  - `settings_update_keys_roundtrip`: нет строки → `NotAsked`, есть строка → `0|1`;
  - `update_decide_table`: не меньше 14 строк, все ветки Р19г-6, включая `now = 0`, `now = u64::MAX`, `last = u64::MAX`, ровно 86399/86400 и 59/60;
  - `update_permit_requires_consent`: `NotAsked` и `Disabled` при `manual` true/false и 5 разных `now` → `None`, байты файла настроек не изменились;
  - `update_permit_records_time_before_request`;
  - `update_permit_clock_back_records_only`;
  - `update_permit_sealed` (compile_fail doc-тест: `UpdateCheckPermit { _sealed: () }` и `UpdateCheckPermit::default()` вне ядра не собираются);
  - `verify_files_ok_newer_same_older` (тестовый ключ из фиксированного зерна, пометка «тестовый»);
  - `verify_files_no_keys_reads_nothing` (несуществующие пути → `NoTrustedKeys`, а не `Io`);
  - `verify_files_manifest_oversize` (64 КиБ + 1 → `TooLarge`);
  - `verify_files_sig_oversize`;
  - `verify_files_mixed_results` (подходит, `NotInManifest`, `WrongTarget`, `Downgrade` без флага, `OlderAllowed` с флагом);
  - `verify_files_bad_signature_whole_err`;
  - страж реэкспорта и его самопроверка.
- [ ] `cargo test -p chervo-cli -p chervo-update -p chervo-update-check --locked` зелёные (без правок этих крейтов)
- [ ] `cargo deny check advisories bans licenses sources`; `cargo audit` (с действующим исключением `.cargo/audit.toml`); `git diff main -- Cargo.lock` меняет только запись `chervo-core` (новые строки зависимостей), новых `[[package]]` нет

## 4. 19г-2: GUI          builder sonnet/medium

Прочитать: этот файл разд. 1, 2, 4, 6, 8; `crates/chervo-gui/src/{main.rs, app.rs, model.rs, main_model.rs:1-60, settings_model.rs:1-120, worker.rs, worker_ops.rs (поиск по `Command::`), picker.rs, texts.rs, fixtures.rs, redact.rs, screens/settings.rs, screens/common.rs}`; все `crates/chervo-gui/tests/*.rs`. Больше ничего не искать.

Сделать:
1. **Поток обновлений** `src/update_worker.rs`: `pub enum UpdateJob { Check { permit: UpdateCheckPermit, running: Version, manual: bool }, Verify { manifest: PathBuf, minisig: PathBuf, files: Vec<PathBuf>, allow_downgrade: bool } }`. Поток запускает `Worker::spawn` (имя `chervo-gui-updates`, канал без предела, задания по одной). Итоги идут в тот же канал `Outcome` с вызовом `wake`. Поток не держит узел и не упоминает `Node`. При закрытии его не ждут: канал заданий закрывается вместе с потоком узла, а незаконченная проверка (до 30 с) прерывается выходом процесса. `JOIN_BOUND` не меняется.
2. **Поток узла** (`worker.rs`, `worker_ops.rs`):
   - новые команды `SetUpdateConsent(bool)` (вызов `set_update_consent` в своей ветке `worker_ops`), `CheckUpdateNow`, `VerifyRelease { manifest, minisig, files, allow_downgrade }` (пересылается в поток обновлений; узел не нужен, но команда идёт через поток узла, чтобы окно не владело вторым каналом);
   - функция `worker_ops::update_tick(node, updates, manual) -> Option<Outcome>`: `now` из `SystemTime::now()` (ошибка → без запроса; при `manual` итог `UpdateSkipped`), затем `node.update_check_permit(now, manual)`; при `Some(permit)` и `running_version() == Some(v)` отправляет `UpdateJob::Check` и возвращает `Outcome::UpdateCheckStarted { manual }`, при `None` для `manual` возвращает `Outcome::UpdateSkipped`, для фона ничего;
   - такт фона: после `Opened` и затем раз в `UPDATE_TICK = 3600 с` (`Instant`) в цикле `run`; после успешного `SetUpdateConsent(true)` такт сбрасывается, и проверка начинается сразу.
3. **Модель** (`src/update_model.rs`, состояние `Model.update: UpdateUi`):
   - согласие берётся из снимка (`SettingsRow` получает `update_consent`); `checking`; `newer: Option<Version>` (только в памяти); `manual_status: Option<&'static str>`;
   - форма сверки: манифест, подпись и файлы, каждый как `(PathBuf, String)`, где строка = `safe_label` от имени; файлов не больше 16; `allow_downgrade` по умолчанию `false` и сбрасывается после каждой сверки; `busy`; `result`;
   - вшитые ключи: `embedded_keys()` при создании модели (без ввода-вывода).
   Намерения `UpdateIntent` (в коде `U::`): `SetConsent(bool)` (и карточка, и переключатель в настройках: одна ветка), `CheckNow`, `PickManifest(PathBuf)`, `PickSignature(PathBuf)`, `AddFiles(Vec<PathBuf>)`, `ClearFiles`, `AllowDowngrade(bool)`, `Verify`, `DismissNewer`.
   Правила:
   - `CheckNow` создаёт `Command::CheckUpdateNow` только при `consent == Enabled` и `!checking`;
   - `Verify` создаёт команду только когда выбраны все три части и `!busy`;
   - фоновый итог `UpdateChecked { manual: false, .. }` показывает только `Newer(v)`: уведомление и карточку; `UpToDate` и все ошибки молча;
   - ручной итог даёт ровно одну фиксированную строку из таблицы разд. 6.
4. **Экраны.**
   - Новая страница `Page::Updates`, пункт меню «Обновления».
   - Карточка согласия вверху главного окна (не модальная, не перекрывает SAS и вопросы доверия). Видна, пока `consent == NotAsked`; ответ сохраняется ядром. Без ответа при следующем запуске спросит снова; до ответа проверки нет.
   - Карточка «Вышла версия X.Y.Z» с кнопкой «Где скачать», которая открывает диалог со ссылкой и «Копировать» (Р19г-9).
   - Пункт «О программе» в настройках остаётся.
   - Выбор файлов: новый `picker::pick_file() -> Option<PathBuf>` и уже имеющийся `pick_files()` через `rfd`, без новых возможностей пакета.
5. **Тексты** только в `texts.rs`, разд. 6. Ошибки `UpdateError` и `CheckError` переводятся функцией модели `update_error_text(&UpdateError) -> &'static str` с ветвью `_` (перечисления `#[non_exhaustive]`).
6. **Очистка строк** `src/safe_text.rs`: `pub fn safe_label(s: &str, max_chars: usize) -> String` (в GUI `max_chars = 64`). Заменяет на U+FFFD каждый символ, для которого `char::is_control()`, а также U+061C, U+180E, U+200B..=U+200F, U+2028, U+2029, U+202A..=U+202E, U+2060..=U+206F, U+FEFF, U+FFF9..=U+FFFB. Длиннее предела: обрезать по символам и добавить «…». Пустая строка становится «(без имени)». Через неё проходят имена из манифеста и имена выбранных файлов (`Path::file_name()` → `to_string_lossy`).
7. **Стражи.**
   - Новый `tests/update_gates.rs` с самопроверкой каждого правила:
     - `check_latest(` встречается ровно один раз в `src/`, в `src/update_worker.rs`, внутри ветки `UpdateJob::Check`;
     - `verify_release_files(` ровно один раз, в `src/update_worker.rs`, внутри ветки `UpdateJob::Verify`;
     - `update_check_permit(` ровно один раз, в `src/worker_ops.rs`;
     - `UpdateCheckPermit` только в `src/update_worker.rs` и `src/worker_ops.rs`;
     - `UpdateJob::` нет в `src/screens/` и `src/app.rs`;
     - в `src/` нет `std::process`, `process::Command`, `open_url`, `OpenUrl`, `webbrowser`, `trusted_comment`;
     - в `src/screens/update.rs` нет `.display()` и `to_string_lossy` (имена только готовые, из модели).
   - `tests/gated_node_actions.rs`, массив `GATED` дополнить двумя записями:
     - `{ command: "Command::SetUpdateConsent", intent_arm: "U::SetConsent", node_call: "set_update_consent(" }`;
     - `{ command: "Command::CheckUpdateNow", intent_arm: "U::CheckNow", node_call: "update_tick(" }`. Если форма охраны не подходит для `update_tick` (вызов из такта и из ветки), оставить её только в `update_gates.rs` и указать в отчёте.
   - Прежние стражи `manifest_only_core`, `uses_node_api_only`, `ui_thread`, `no_fs_writes`, `hardens_first` не ослабляются.
8. **render-check:** `fixtures::all()` дополнить не меньше чем 20 состояниями:
   - карточка согласия;
   - страница «Обновления» при `NotAsked`, `Enabled` и `Disabled`;
   - «идёт проверка»;
   - карточка новой версии и диалог ссылки;
   - ручные итоги (последняя версия, нет связи, ответ не прошёл проверку, ключи не вшиты, проверка выключена или была меньше минуты назад);
   - форма сверки: пустая, занята, успех `Newer`, успех `Same`, успех с `OlderAllowed` и предупреждением, ошибка манифеста `BadSignature`, по строке на `NotInManifest`, `WrongTarget`, `SizeMismatch`, `Downgrade`, `TooLarge`, `Io`;
   - `NoTrustedKeys`;
   - список из 2 вшитых ключей и «ключи не вшиты»;
   - имя файла с U+202E, U+2066 и `\u{7}`.
   Рисование без узла, сети и файлов, как сейчас.

Критерии приёмки:
- [ ] сборка, clippy, fmt, `check-forbidden` (как в разд. 3)
- [ ] `cargo test -p chervo-gui --locked`: прежние стражи и модельные тесты зелёные; новые:
  - `consent_card_only_when_not_asked`;
  - `set_consent_builds_one_command`;
  - `check_now_needs_consent` (`NotAsked`, `Disabled` → нет команды);
  - `check_now_not_twice_while_checking`;
  - `background_failure_is_silent` (все варианты `CheckError` и `UpToDate`: ни уведомления, ни строки);
  - `background_newer_shows_version_only`;
  - `manual_results_fixed_texts`;
  - `verify_needs_three_parts`;
  - `verify_files_capped_16`;
  - `allow_downgrade_off_by_default_and_reset`;
  - `older_allowed_shows_warning`;
  - `safe_label_table` (не меньше 14 строк: каждый диапазон из п. 6, кириллица без изменений, 65 символов → 64 + «…», пустая);
  - `update_gates` и его самопроверки;
  - `gated_node_actions` с новыми записями
- [ ] CI `gui-render` зелёный на 3 ОС (`--render-check` рисует и новые состояния); вывод в отчёте
- [ ] `cargo deny check`; `git diff main -- Cargo.lock crates/chervo-gui/Cargo.toml Cargo.toml` пуст

## 5. 19г-3: упаковка и выпуск          builder sonnet/medium

Прочитать: этот файл разд. 1, 5, 8; SPEC 19 разд. 5; `.github/workflows/{release.yml, release-smoke.yml, ci.yml:40-80}`; `scripts/release/*.sh`; `scripts/check-release-guards.sh`; `scripts/check-gui-linux-tree.sh`; `docs/INSTALL.md`. Больше ничего не искать.

Сделать:
1. **`build-release.sh`**: после CLI собрать GUI отдельным вызовом `cargo build --release --locked -p chervo-gui --bin chervotochina --target "$triple"`, перед ним проверка `test-store` для `chervo-gui`. На Linux перед сборкой GUI выполнить `bash scripts/check-gui-linux-tree.sh` (в дереве GUI нет zvariant). Выход:
   - Linux: `chervotochina-$ver-linux-x86_64`;
   - Windows: `chervotochina-$ver-windows-x86_64.exe`;
   - macOS: вызов `scripts/release/package-macos.sh <бинарь> <ver> <label> <outdir>`.
   Если сборка GUI на `ubuntu-22.04` требует пакетов apt, это стоп.
2. **`scripts/release/package-macos.sh`** (с `--self-test`, который проверяет хотя бы шаблон и подстановку):
   - версия по `^[0-9]+\.[0-9]+\.[0-9]+$`, иначе отказ;
   - собрать `Chervotochina.app/Contents/{MacOS/chervotochina, Info.plist}` во **временном пустом каталоге**;
   - `Info.plist` из шаблона `packaging/macos/Info.plist` с единственной меткой `@VERSION@`. Ключи: `CFBundleExecutable=chervotochina`, `CFBundleIdentifier=io.github.rekc2004.chervotochina`, `CFBundleName`/`CFBundleDisplayName=Червоточина`, `CFBundlePackageType=APPL`, `CFBundleShortVersionString` и `CFBundleVersion=@VERSION@`, `LSMinimumSystemVersion=11.0` [В: минимум eframe/wgpu на macOS сверить], `NSHighResolutionCapable=true`. Проверить `plutil -lint`;
   - `codesign --force --sign - --timestamp=none Chervotochina.app` и `codesign --verify --strict --verbose=2 Chervotochina.app`;
   - `check-deps.sh macos` на `Contents/MacOS/chervotochina`;
   - `ditto -c -k --keepParent Chervotochina.app "$outdir/chervotochina-$ver-$label.zip"`.
   Нет `codesign`, `ditto` или `plutil` на `macos-15` = стоп.
3. **`release.yml`**:
   - `build`: шаг «Dependencies of the binary» проходит по всем файлам `dist/*`. Для `.zip` распаковать в новый каталог и проверить бинарь внутри пакета; для остальных файлов как сейчас. SHA-256 каждого файла в сводку;
   - `repro`: сравнить и CLI, и GUI для Linux (результат только записывается);
   - `smoke`: после шагов CLI новый шаг GUI на той же матрице:
     - Linux: `sudo apt-get install` того же набора, что `ci.yml:64` [П] (только CI), затем `scripts/release/smoke-gui.sh`;
     - macOS: `smoke-gui.sh`;
     - Windows: bash-шаг `smoke-gui.sh --check-only` (SHA-256 против манифеста), затем шаг pwsh `Start-Process -FilePath <файл> -ArgumentList '--render-check' -Wait -PassThru` с проверкой `ExitCode -eq 0`, как `ci.yml:72-73` [П].
   Новых actions нет; `persist-credentials: false` и права как сейчас.
4. **`scripts/release/smoke-gui.sh <rel> <label> <ext>`**:
   - SHA-256 файла GUI своей цели равен строке манифеста, иначе файл **не запускается** (как `smoke.sh:52-59` [П]);
   - Linux: `timeout 120 xvfb-run -a <файл> --render-check`;
   - macOS: распаковка `ditto -x -k` в новый пустой каталог, `codesign --verify --strict`, `timeout 120 .../Chervotochina.app/Contents/MacOS/chervotochina --render-check`;
   - итог и код в `$GITHUB_STEP_SUMMARY`.
   Для `macos-x86_64` запуск только на `macos-15-intel` (как сейчас).
5. **`assemble.sh`**:
   - SBOM GUI из `crates/chervo-gui/sbom.json`. Если `cargo cyclonedx` 0.5.9 его не создаёт, это стоп [НП];
   - белый список (`check-whitelist.sh`, `expected_names`): плюс `chervotochina-$v-linux-x86_64`, `-macos-aarch64.zip`, `-macos-x86_64.zip`, `-windows-x86_64.exe`, `chervotochina-$v-sbom.cdx.json`. Самопроверка: пропавший GUI-файл, лишний `Chervotochina.app` (каталог) и `.dmg` отвергаются;
   - манифест: ещё 5 строк `--artifact` (4 цели GUI и `any` для SBOM GUI). Всего 10 артефактов при пределе 32 [П: `MAX_ARTIFACTS`].
6. **`check-release-guards.sh`**: правило 1 требует обе строки сборки по пакету (CLI и GUI). Самопроверка: пропавшая строка GUI и строка с двумя `-p` в одном вызове ловятся.
7. **`release-smoke.sh` и `release-smoke.yml`**: положительный `verify-release` своим CLI покрывает CLI-файл своей цели, GUI-файл своей цели и все файлы `any`, все строки `OK ... same`. Отрицательные случаи как сейчас.
8. **`sign.sh`, найденная ошибка** [П: `scripts/release/sign.sh:155`]: `verify-release` вызывается со **всеми** артефактами. Файлы чужих целей дают `WrongTarget`, код 1, и `die` срабатывает уже после подписи. Так ломается любой выпуск больше чем с одной целью, в том числе текущий без GUI. Исправить: передавать только файлы своей цели и `any`, как `release-smoke.sh:39-45` [П]. Самопроверки у `sign.sh` нет, поэтому дирижёр проверяет правку чтением diff, а прогон остаётся пунктом владельца (SPEC 19 разд. 5, «не проверено»).
9. **`docs/INSTALL.md`**: какой файл скачивать (GUI основной, CLI для мини-ПК и проверок); Windows SmartScreen для `chervotochina-*.exe`; macOS: проверить `.zip` (`minisign -Vm` при первой установке, затем экран «Обновления» или `chervo verify-release`), распаковать, перенести в «Программы», первый запуск через «Системные настройки → Конфиденциальность и безопасность → Всё равно открыть» [В: macOS 15], запасной путь `xattr -dr com.apple.quarantine /Applications/Chervotochina.app`; Linux: `chmod +x`, нужен графический сеанс X11 или Wayland; если хранилища нет, `chervo doctor`; проверка новых версий: что уходит в сеть и как выключить; обновление: проверить файл на экране «Обновления», закрыть программу, заменить файл.

Критерии приёмки:
- [ ] `bash scripts/check-release-guards.sh` и `--self-test`; `bash scripts/release/check-whitelist.sh --self-test`; `bash scripts/release/check-deps.sh --self-test`; `bash scripts/release/package-macos.sh --self-test` (на macOS-раннере или «не проверено»); `bash scripts/check-actions-pinned.sh`
- [ ] CI `ci.yml` зелёный на коммите правок (3 ОС)
- [ ] Пробный `release.yml` (`workflow_dispatch`, `skip_keys_check: true`) зелёный: в отчёте список файлов выпуска (11 вместе с манифестом); вывод `ldd`/`otool -L`/проверки DLL для GUI каждой цели; `codesign --verify` обоих `.zip`; результат `repro` для CLI и GUI; по каждому из 4 раннеров `smoke` для CLI (как в 19б) и для GUI: SHA-256 = строка манифеста, код `--render-check` 0. Дирижёр сам открывает сводку прогона
- [ ] Негатив: подложенный лишний файл и пропавший GUI-файл валят белый список (самопроверка)
- [ ] Ручные (владелец, одним заходом; до этого «не проверено»): чистая Windows 11 запускает `chervotochina-*.exe` без VC++; Ubuntu 24.04 с рабочим столом запускает файл после `chmod +x`; macOS: машины нет, в заметках выпуска «на macOS не проверено»; `release-smoke.yml` и `sign.sh` на первом черновике

## 6. Тексты (добавить в `texts.rs`; дословно)

- Меню: `NAV_UPDATES` «Обновления».
- Согласие: `UPD_CONSENT_TITLE` «Проверять, не вышла ли новая версия?»; `UPD_CONSENT_TEXT` «Раз в сутки программа может спрашивать у GitHub, вышла ли новая версия. При каждой проверке GitHub видит ваш IP-адрес и то, что на этом адресе стоит Червоточина. Программа ничего не скачивает и сама не обновляется: она только сообщит номер новой версии. Решение можно изменить в разделе «Обновления».»; `BTN_UPD_ENABLE` «Включить проверку»; `BTN_UPD_DISABLE` «Не проверять».
- Страница: `UPD_RUNNING` «Установлена версия»; `UPD_TOGGLE` «Проверять новые версии раз в сутки (GitHub увидит ваш IP-адрес)»; `BTN_UPD_CHECK_NOW` «Проверить сейчас»; `UPD_CHECK_NEEDS_CONSENT` «Включите проверку, чтобы проверить сейчас.»; `UPD_CHECKING` «Проверяем…».
- Итоги проверки:
  - `UPD_NEWER` «Вышла версия {new} (у вас {cur}).» (подстановка только двух `Version`);
  - `BTN_UPD_WHERE` «Где скачать»;
  - `UPD_LINK_TEXT` «Скачайте файлы со страницы выпусков и проверьте их здесь, в разделе «Обновления», до запуска.»;
  - `UPD_UP_TO_DATE` «Установлена последняя версия ({cur}).»;
  - `UPD_NO_NETWORK` «Нет связи с GitHub.» (`Network`, `Timeout`);
  - `UPD_BAD_RESPONSE` «Ответ не прошёл проверку.» (`BadResponse`, `BadSignature`, прочие);
  - `UPD_NO_KEYS` «Ключи владельца не вшиты: проверка невозможна.»;
  - `UPD_SKIPPED` «Проверка выключена или была меньше минуты назад.».
- Сверка файлов:
  - заголовок и подсказки: `UPD_VERIFY_TITLE` «Проверить скачанные файлы»; `UPD_VERIFY_HINT` «Выберите список файлов выпуска (chervo-release.txt), его подпись (chervo-release.txt.minisig) и скачанные файлы. Проверка идёт без сети.»;
  - кнопки: `BTN_UPD_PICK_MANIFEST` «Список файлов…»; `BTN_UPD_PICK_SIG` «Подпись…»; `BTN_UPD_PICK_FILES` «Файлы…»; `BTN_UPD_VERIFY` «Проверить»;
  - откат: `UPD_ALLOW_DOWNGRADE` «Разрешить старую версию (откат)»;
  - итог манифеста: `UPD_SIGNED_BY` «Подписано ключом владельца: {role}, key_id {id}. Версия выпуска {ver}.» (`{role}`: «основной»/«запасной»);
  - строки по файлу: `UPD_FILE_NEWER` «подходит, новее установленной»; `UPD_FILE_SAME` «подходит, та же версия»; `UPD_FILE_OLDER` «подходит, но это СТАРАЯ версия: откат разрешён вами»;
  - после успеха: `UPD_REPLACE_HINT` «Файл подлинный. Закройте программу и замените её этим файлом вручную.».
- Ошибки сверки (по варианту):
  - `TooLarge`: «файл больше допустимого предела»;
  - `MalformedSignature`, `UnsupportedAlgorithm`: «файл подписи повреждён или не того формата»;
  - `NoTrustedKeys`: = `UPD_NO_KEYS`;
  - `UnknownKey`: «подписано не ключом владельца»;
  - `BadSignature`, `BadGlobalSignature`: «подпись не сходится: список файлов изменён или подпись чужая»;
  - `UnsupportedManifestVersion`, `MalformedManifest`: «список файлов повреждён или не того формата»;
  - `NotInManifest`: «этого файла нет в подписанном списке»;
  - `WrongTarget`: «файл для другой системы»;
  - `SizeMismatch`: «размер файла не совпал»;
  - `Downgrade`: «это старая версия; чтобы всё же принять её, отметьте «Разрешить старую версию»»;
  - `Io`: «файл не удалось прочитать»;
  - прочее: «проверка не прошла».
- Ключи: `UPD_KEYS_TITLE` «Вшитые ключи владельца (сверьте с README)»; `UPD_KEY_ROW` «{role}: {id}»; `UPD_KEYS_NONE` «Ключи владельца не вшиты.».

## 7. Не делать
Автообновление, скачивание, замену своего файла, запуск процессов, открытие ссылок (до ответа Q7 и иначе, чем по варианту ответа); показ доверенного комментария, адресов или текстов из сети; чтение файлов в GUI-коде или в потоке окна; запись файлов в GUI; хранение найденной версии на диске; новые пакеты и возможности (`eframe` `links`, `persistence`, возможности `rfd`); изменения `chervo-update`, `chervo-update-check`, форматов манифеста, подписи и настроек сверх разд. 2; изменения поведения CLI; Authenticode, нотаризацию, `.dmg`, AppImage, установщики, `.desktop`; новые actions и кэши; публикацию и теги. Нужен новый пакет, инструмент или возможность = стоп.

## 8. Модель угроз: T19-дополнение (внести в THREAT_MODEL вместе с T19)

| Атака или сбой | Мера | Остаток |
|---|---|---|
| Сетевой запрос без согласия (ошибка GUI, будущая оболочка) | `check_latest` ядра требует `UpdateCheckPermit`, который выдаёт только узел при записанном `Enabled`; тесты ядра и стражи GUI | процесс того же пользователя может вписать `update_check=1` в настройки (T18(a)) |
| Частые запросы как слежка или нагрузка | 24 ч в фоне, 60 с между ручными, время пишется до запроса, часы назад = без запроса | перевод часов вперёд даёт одну лишнюю проверку на каждый скачок; GitHub видит IP и время (SPEC 19 разд. 8) |
| Подмена отображения через bidi или управляющие символы (файл с U+202E в имени, доверенный комментарий) | доверенный комментарий не показывается; имена через `safe_label`; ошибки только фиксированными строками | гомоглифы в именах своих файлов не убираются; на решение это не влияет, сверка идёт по хэшу |
| Большой или медленный файл при сверке | пределы чтения манифеста и подписи; `check_artifact` прекращает чтение после наибольшего размера; отдельный поток, по одному заданию | окно показывает «Проверяем…», пока не дочитан файл с медленного носителя |
| Подмена между проверкой и запуском (TOCTOU) | подсказка «замените этим файлом» | вне модели (T9/T10) |
| Ложная «новая версия» (утёкший ключ, MITM) | только номер версии; ссылка вшитая, копируется, не открывается автоматически | пользователя можно уговорить скачать файл с другого места: экран сверки его отвергнет, если ключ не утёк |
| Неподписанные пакеты (ad-hoc macOS, Windows без Authenticode) | первая установка: `minisign` и key_id из второго канала; инструкция | обход Gatekeeper и SmartScreen приучает нажимать «всё равно открыть» (U18, Q2) |
| Тестовые крючки или чужая сборка в пакете | сборка по пакету, проверка `test-store` для обоих пакетов, белый список, SHA-256 перед запуском в `smoke` | как T19: закладка во время сборки в CI не ловится |
| Строки настроек от новой версии в старой | разбор строгий: старая версия выдаст `SettingsCorrupt`, «Сбросить настройки» сохранит копию | откат на сборки до 19г теряет настройки (публичных выпусков до 19г нет) |

Точечное ревью security 19г-1 по списку: Р19г-5 (запечатанность разрешения, нет обходного реэкспорта), Р19г-6 (таблица решений, порядок «записать, потом запрос»), разбор новых ключей настроек, пределы чтения в `verify_release_files`, отсутствие доверенного комментария в представлении.

## 9. Стоп-условия, лимит, отчёт
Стоп: противоречие спецификации и кода; нужен новый пакет, инструмент или возможность; GUI на `ubuntu-22.04` требует apt; нет SBOM GUI; нет `codesign`/`ditto`/`plutil`; `ldd` GUI показывает лишние библиотеки; критерий непроверяем. В этих случаях остановиться и доложить, не обходить.
Лимит: не более 2 кругов «правка по ревью» на часть.
Отчёт builder (до 25 строк): изменённые файлы; команды приёмки и последние строки вывода; что не сделано; отклонения.

## 10. Вопросы владельцу

**Q5. Оставлять ли консольную программу `chervo` в выпуске рядом с окном?** Вы уже решили (этап 18, Q8), что консольная версия входит в релиз 1; прошу подтвердить вид.
- (а) **Обе на всех 4 системах (рекомендую).** Консоль нужна на мини-ПК без рабочего стола, на ней держатся проверки выпуска в CI, `release-smoke` и `sign.sh`. Цена: лишний файл на странице выпуска, в инструкции сказано, какой скачивать.
- (б) Консоль только для Linux. Тогда проверку подписи на Windows и macOS в `sign.sh` и `release-smoke` придётся переделать.
- (в) Только окно. Мини-ПК остаётся без программы.
По умолчанию builder работает по (а).

**Q6. Лицензии сторонних компонентов.** Лицензии MIT, Apache и OFL (шрифты egui) требуют прикладывать их тексты к распространяемым файлам. Сейчас в программе на этом месте заглушка.
- (а) **Рекомендую:** в CI инструментом `cargo-about` (закреплённая версия, ставится только в CI, как `cargo-cyclonedx`) собирать файл `chervo-<ver>-third-party-licenses.txt` и прикладывать к выпуску; в «О программе» указать на него.
- (б) Свой скрипт по `cargo metadata`. Новых инструментов нет, но легко пропустить лицензию у пакета без файла лицензии.
- (в) Отложить. Не рекомендую: выпуск без текстов лицензий нарушает их условия.
Без ответа 19г-4 не делается, остальное не ждёт.

**Q7. Как открыть страницу выпусков из уведомления.**
- (а) **Показать ссылку и кнопку «Копировать» (рекомендую).** Ни новых пакетов, ни запуска программ; вы вставляете ссылку в браузер сами.
- (б) Кнопка «Открыть» через системную команду с фиксированным адресом (`explorer`, `open`, `xdg-open`). Новых пакетов нет, но программа начинает запускать другие программы; на Linux без `xdg-open` кнопка не сработает.
- (в) Встроенная возможность фреймворка (пакет `webbrowser` и его зависимости). Новые пакеты [В: наличие и состав сверить].
По умолчанию builder работает по (а).

## 11. Резюме для владельца
- В выпуске будет окно `chervotochina` для Windows (один `.exe`), macOS (`.zip` с приложением, подпись ad-hoc без Apple) и Linux (один файл). Рядом остаётся консольная `chervo`, если подтвердите Q5. AppImage и установщиков нет.
- Проверка новых версий выключена, пока вы не ответите на карточку при первом запуске. Включённая проверка идёт раз в сутки и по кнопке. Без вашего «да» сетевой код не вызывается: ядро не выдаст разрешения на запрос, и это проверяется тестами.
- Экран «Обновления» проверяет скачанные файлы без сети. Он показывает версию, каким ключом подписано и подходит ли каждый файл. Подписанный комментарий не показывается, имена файлов очищаются от символов, переворачивающих текст.
- В CI каждый пакет запускается на своей системе (`--render-check`) только после сверки хэша с манифестом.
- Найдена ошибка в `sign.sh`: проверка после подписи падала бы на любом выпуске с несколькими системами. Исправление входит в 19г-3.
- Нужны ваши ответы: Q5 (консоль в выпуске), Q6 (тексты лицензий), Q7 (как открыть ссылку). По Q5 и Q7 работа идёт по рекомендованным вариантам, пока вы не решите иначе.
