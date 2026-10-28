# SPEC 19г: упаковка GUI, экран обновлений, согласие на проверку новых версий          критичность: обычный (19г-1 и 19г-3 с точечным ревью security, см. разд. 0)

Редакция 2, 2026-10-28, architect (opus/high). Дополнение к `docs/specs/stage-19-release-signing.md` (далее «SPEC 19»), разд. 7. Основа: main после PR #8 и #9 (`23e97a1`).
Изменения ред. 2: ответы владельца Q5 (б), Q6 (а), Q7 (а) (`docs/OWNER_DECISIONS.md`, «Этап 19г (2026-10-28)»). Переписаны разд. 0, 5, 10, 11; новый разд. 5а (19г-4); дополнены Р19г-1, разд. 7, 8, 9; новые Р19г-11, Р19г-12. Разд. 2, 3, 4, 6 не менялись.
Метки: [П] проверено мной по файлу (путь:строка); [В] вывод или память, сверить до кода; [НП] не проверено. Я ничего не собирал и не запускал.

Цель: релиз содержит GUI `chervotochina` для 4 целей и CLI `chervo` только для Linux (Q5 б); программа при первом запуске предлагает включить проверку новых версий (до ответа выключена), проверяет не чаще раза в сутки и по кнопке только с согласия; экран «Обновления» проверяет скачанные файлы выпуска офлайн, не читая файлы в потоке окна и не показывая непроверенных строк; к выпуску приложен подписанный файл лицензий сторонних компонентов (Q6 а).

## 0. Разбиение, исполнители, порядок

| Часть | Что | Исполнитель | Ждёт |
|---|---|---|---|
| 19г-1 | `chervo-core`: модуль `update` (реэкспорт, `verify_release_files`, разрешение на запрос), ключи настроек `update_check`, `update_checked_at` | builder sonnet/**high** (трогает разбор настроек и единственный вход в сеть); ревью security opus/high по списку разд. 8 | ничего |
| 19г-2 | GUI: страница «Обновления», карточка согласия, поток обновлений, часы фоновой проверки, стражи, render-check | builder sonnet/medium | 19г-1 принят |
| 19г-3 | упаковка и выпуск по Q5 (б): `build-release.sh`, `package-macos.sh`, сборка-проверялка, `release.yml`, `assemble.sh`, белый список, `smoke`, `release-smoke`, `sign.sh`, стражи, `draft.sh`, `docs/INSTALL.md` | builder sonnet/**high** (права токенов, исполнение артефактов CI на машине владельца); ревью security opus/high по diff `release-smoke.yml`, `sign.sh`, `check-release-guards.sh`, `release.yml`; дирижёр сам открывает сводку пробного прогона | ничего; параллельно с 19г-1/2 (файлы не пересекаются) |
| 19г-4 | файл лицензий (`cargo-about` в CI) и текст «О программе» | builder sonnet/medium | 19г-3 принят (те же `assemble.sh`, белый список, `release.yml`, стражи); 19г-2 принят (`texts.rs`, `screens/settings.rs`); версия `cargo-about` сверена дирижёром (разд. 5а, п. 1) |

Перед первой публикацией: ревью security этапов 18 и 19 без открытых High/Critical (SPEC 19 разд. 7); ручные пункты владелец проходит одним заходом (OWNER_DECISIONS «Ручные проверки (2026-10-28)»), до того они «не проверено».

## 1. Решения architect (кратко, с причиной)

Р19г-1. **Форматы пакетов.**
- Windows: один файл `chervotochina-<ver>-windows-x86_64.exe`, без установщика, ресурсов и значка (в GUI запрещён `build.rs`, страж `manifest_only_core` [П: `crates/chervo-gui/tests/manifest_only_core.rs:102`]). Статический CRT: `.cargo/config.toml` задаёт его для обычной сборки, но в релизе `build-release.sh` выставляет `RUSTFLAGS`, а переменная окружения заменяет `target.<triple>.rustflags` из конфига, а не дополняет их [В: порядок источников rustflags в документации cargo]. Поэтому явный `-C target-feature=+crt-static` в `build-release.sh:38-40` [П] **остаётся**; `check-deps.sh windows` проверяет и GUI.
- macOS: `chervotochina-<ver>-macos-aarch64.zip` и `...-macos-x86_64.zip`, внутри `Chervotochina.app` (ASCII-имя каталога; отображаемое имя «Червоточина» в `Info.plist`). Подпись ad-hoc всего пакета `codesign --force --sign - --timestamp=none` [В: флаги сверить с `man codesign` на раннере]. Без нотаризации и Developer ID (U18). Архив `ditto -c -k --keepParent` [В]. Выбран `.zip`, а не `.dmg`: нет монтирования образа, `hdiutil` не нужен, хэш считается от одного файла, `verify-release` проверяет его до распаковки.
- Linux: один ELF `chervotochina-<ver>-linux-x86_64`, как CLI. AppImage не делаем: его среда запуска требует libfuse2, которой на Ubuntu 24.04 по умолчанию нет [В]; инструменты AppImage стали бы новым входом цепочки поставок. `.desktop` и значка нет. По 18p V3 в `NEEDED` только libc-семейство, X11/Wayland/Vulkan/GL грузятся во время работы [П: `docs/reports/GUI-PROBE-2026-10-25.md:54`].
- CLI `chervo` (Q5 б): в выпуске только `chervo-<ver>-linux-x86_64` (мини-ПК без рабочего стола, `chervo doctor`, `docs/HEADLESS_LINUX.md`). Файлов `chervo-<ver>-macos-*` и `chervo-<ver>-windows-x86_64.exe` в выпуске больше нет; белый список их отвергает.
- SBOM: `chervo-<ver>-sbom.cdx.json` (CLI) и `chervotochina-<ver>-sbom.cdx.json` (GUI), оба цели `any`.

Р19г-2. **Сборка только по пакету, двумя отдельными вызовами cargo:** `-p chervo-cli --bin chervo` и `-p chervo-gui --bin chervotochina`. В одном вызове с двумя `-p` resolver 3 объединил бы возможности обоих пакетов. Для каждого пакета перед сборкой нужна проверка `cargo tree -e no-dev,features`: нет `test-store` (как `build-release.sh:46-50` [П]). CLI по-прежнему собирается на всех 4 целях (Р19г-11), публикуется только Linux.

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

Р19г-9. **Страница релизов (Q7 = а, решено).** Вшитая `RELEASES_PAGE` показывается выделяемым текстом с кнопкой «Копировать» (`ctx.copy_text`, уже используется [П: `crates/chervo-gui/src/screens/common.rs:23`]). Ни процессов, ни новых пакетов, ни `open_url`.

Р19г-10. **Linux без Secret Service** (SPEC 19 разд. 7, «тот же результат, что `chervo doctor`»): экран 1 из 18б уже показывает `KeyStoreLocked` с текстом для Linux [П: `crates/chervo-gui/src/texts.rs:28`]. В 19г ничего нового, только строка в `INSTALL.md`. На Windows и macOS `chervo doctor` не нужен: тот же первый экран окна показывает состояние хранилища.

Р19г-11. **Проверка подписи на Windows и macOS без CLI в выпуске: «сборка-проверялка».** Задание `build` в `release.yml` по-прежнему собирает `chervo` на всех 4 целях той же командой. На Linux файл идёт в выпуск. На Windows и macOS он называется `chervo-verifier-<ver>-<label>[.exe]`, кладётся в отдельный артефакт `verifier-<label>` и **никогда** не попадает в `release-files`, манифест и черновик. Этим файлом `release-smoke` и `sign.sh` проверяют подписанный выпуск на своей ОС: GUI-файл своей цели и файлы `any`, строка `OK ... same` на каждый.
Почему так:
- Проверяется тот же код, что у пользователя. Экран «Обновления» вызывает `chervo_update` через `chervo_core::update`, со вшитыми ключами того же коммита. Проверялка собрана из того же коммита для той же цели, поэтому покрыты и `Target::current()`, и чтение файлов на этой ОС.
- Доверие не расширяется. `sign.sh` уже доверяет артефакту `release-files` того прогона (`sign.sh:106-131` [П]) и сейчас запускает CLI из черновика на машине владельца (`sign.sh:155` [П]). Проверялка берётся из **того же** прогона `$matched`, поэтому новой точки доверия нет (T19).
- Отвергнуто: «только `minisign`». Это ослабление: не проверяются наш разбор манифеста, формат подписи, вшитые ключи и цель на этой ОС. `minisign -Vm` по всем файлам в `sign.sh` остаётся дополнительно.
- Отвергнуто: «сборка из исходников в `release-smoke`». Нужен checkout тега с токеном и `with: ref:` из `inputs`, что запрещает страж правила 2. Ещё 10-20 минут на ОС [В]. Для `sign.sh` у владельца всё равно нет Rust.
- Отвергнуто: флаг `--target` у `verify-release`, чтобы проверять с Linux. Меняет поведение CLI (разд. 7) и даёт пользователю способ обойти проверку цели.
Цена: `release-smoke.yml` получает в `fetch` право `actions: read` и команды `gh run list|download`, страж правила 2 сужается до этих двух (разд. 5, п. 9). Проверялки живут 14 дней, как `release-files`: позже `sign.sh` и `release-smoke` откажут, и это правильно.

Р19г-12. **Лицензии (Q6 = а).** `cargo-about` с закреплённой версией ставится только в задании `assemble` и пишет `chervo-<ver>-third-party-licenses.txt` (цель `any`, в манифесте, подписывается вместе с остальным). Два прохода: по `chervo-gui` и по `chervo-cli`, без `--workspace`: запрет правила 1 [П: `scripts/check-release-guards.sh:32`]. Список принимаемых лицензий совпадает с `deny.toml` [П: `deny.toml:30-55`]. Исключения точечные, по пакету: BSL-1.0 только `clipboard-win` и `error-code`, OFL-1.1 и Ubuntu-font-1.0 только `epaint_default_fonts`, CDLA-Permissive-2.0 только `webpki-roots`. «О программе» называет файл и показывает адрес страницы выпусков с «Копировать».

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

## 5. 19г-3: упаковка и выпуск по Q5 (б)          builder sonnet/high

Прочитать: этот файл разд. 1, 5, 8; SPEC 19 разд. 5; `.github/workflows/{release.yml, release-smoke.yml, ci.yml:45-75}`; `scripts/release/*.sh`; `scripts/check-release-guards.sh`; `scripts/check-actions-pinned.sh`; `scripts/check-gui-linux-tree.sh`; `docs/INSTALL.md`; `docs/HEADLESS_LINUX.md`. Больше ничего не искать.

### 5.1. Состав выпуска (19г-3; 19г-4 добавит одну строку `any`, разд. 5а)

| # | Цель в манифесте | Файл | Что это |
|---|---|---|---|
| 1 | `linux-x86_64` | `chervo-<v>-linux-x86_64` | CLI |
| 2 | `linux-x86_64` | `chervotochina-<v>-linux-x86_64` | окно |
| 3 | `macos-aarch64` | `chervotochina-<v>-macos-aarch64.zip` | окно (`Chervotochina.app`) |
| 4 | `macos-x86_64` | `chervotochina-<v>-macos-x86_64.zip` | окно |
| 5 | `windows-x86_64` | `chervotochina-<v>-windows-x86_64.exe` | окно |
| 6 | `any` | `chervo-<v>-sbom.cdx.json` | SBOM CLI |
| 7 | `any` | `chervotochina-<v>-sbom.cdx.json` | SBOM GUI |

Итого 7 артефактов в манифесте (предел 32 [П: `crates/chervo-update/src/lib.rs:25`]) и 8 файлов в черновике вместе с `chervo-release.txt`. Две строки с одной целью допустимы: разбор отвергает только повтор имени или SHA-256 [П: `crates/chervo-update/src/manifest.rs:243-247`]. Сверка идёт по хэшу, не по имени [П: `crates/chervo-update/src/verify.rs:115-120`].
Не публикуются: `chervo-verifier-<v>-{macos-aarch64,macos-x86_64,windows-x86_64.exe}` (артефакты `verifier-<label>`, Р19г-11).

### 5.2. Сделать

1. **`build-release.sh <triple> <dist-dir> <verifier-dir>`** (третий аргумент новый):
   - CLI как сейчас: проверка `test-store` для `chervo-cli`, затем та же строка `cargo build --release --locked -p chervo-cli --bin chervo --target "$triple"`. Linux: в `<dist-dir>/chervo-$ver-linux-x86_64`. Остальные цели: в `<verifier-dir>/chervo-verifier-$ver-$label$ext`, в `<dist-dir>` CLI не кладётся;
   - GUI: проверка `test-store` для `chervo-gui` (`cargo tree --locked -e no-dev,features -p chervo-gui --target "$triple"`); на Linux перед сборкой `bash scripts/check-gui-linux-tree.sh`; затем отдельная строка `cargo build --release --locked -p chervo-gui --bin chervotochina --target "$triple"`. Выход:
     - Linux: `<dist-dir>/chervotochina-$ver-linux-x86_64`;
     - Windows: `<dist-dir>/chervotochina-$ver-windows-x86_64.exe`;
     - macOS: `scripts/release/package-macos.sh <бинарь> <ver> <label> <dist-dir>`.
   - печать SHA-256 каждого выходного файла с пометкой «published» или «verifier, not published».
   Если сборка GUI на `ubuntu-22.04` требует пакетов apt, это стоп.
2. **`scripts/release/package-macos.sh`** (с `--self-test`, который проверяет хотя бы шаблон и подстановку):
   - версия по `^[0-9]+\.[0-9]+\.[0-9]+$`, иначе отказ;
   - собрать `Chervotochina.app/Contents/{MacOS/chervotochina, Info.plist}` во **временном пустом каталоге**;
   - `Info.plist` из шаблона `packaging/macos/Info.plist` с единственной меткой `@VERSION@`. Ключи: `CFBundleExecutable=chervotochina`, `CFBundleIdentifier=io.github.rekc2004.chervotochina`, `CFBundleName`/`CFBundleDisplayName=Червоточина`, `CFBundlePackageType=APPL`, `CFBundleShortVersionString` и `CFBundleVersion=@VERSION@`, `LSMinimumSystemVersion=11.0` [В: минимум eframe/wgpu на macOS сверить], `NSHighResolutionCapable=true`. Проверить `plutil -lint`;
   - `codesign --force --sign - --timestamp=none Chervotochina.app` и `codesign --verify --strict --verbose=2 Chervotochina.app`;
   - `check-deps.sh macos` на `Contents/MacOS/chervotochina`;
   - `ditto -c -k --keepParent Chervotochina.app "$outdir/chervotochina-$ver-$label.zip"`.
   Нет `codesign`, `ditto` или `plutil` на `macos-15` = стоп.
3. **`release.yml`, задание `build`:**
   - шаг сборки: `build-release.sh "$TRIPLE" dist verifier`;
   - шаг «Dependencies of the binary» проходит по всем файлам `dist/*` и `verifier/*`. `.zip` распаковывается `ditto -x -k` в новый пустой каталог, и проверяется бинарь внутри пакета. Проверялка Windows тоже идёт через `check-deps.sh windows`: она запускается на ПК владельца без VC++. В сводку идёт SHA-256 каждого файла с пометкой «published» или «verifier (not published)»;
   - `upload-artifact` `bin-${{ matrix.target }}` с `dist/*` (как сейчас);
   - новый шаг `if: matrix.kind != 'linux'`: `upload-artifact` `verifier-${{ matrix.target }}` с `verifier/*`, `if-no-files-found: error`, `retention-days: 14`.
4. **`release.yml`, задания `repro`, `assemble`, `draft`:**
   - `repro`: `build-release.sh x86_64-unknown-linux-gnu repro-dist repro-verifier`; сравнить SHA-256 CLI и GUI Linux по отдельности (результат только записывается);
   - `assemble`: скачивание `pattern: bin-*` **без изменений**. Проверялки сюда не попадают: шаблон `bin-*` их не берёт, а п. 9 стережёт это правило;
   - `draft`: без изменений, кроме текста в `draft.sh` (п. 11).
5. **`release.yml`, задание `smoke`** (та же матрица 4 раннеров; в `include` добавить `gext`: `''` Linux, `'.zip'` macOS, `'.exe'` Windows):
   - шаг `download-artifact` `verifier-${{ matrix.target }}` в `verifier`, `if: matrix.target != 'linux-x86_64'`;
   - CLI: Linux `smoke.sh rel linux-x86_64 ''` (как сейчас); Windows/macOS `smoke.sh rel "$TARGET" "$EXT" verifier` (режим проверялки, п. 6);
   - GUI: Linux `sudo apt-get install` того же набора, что `ci.yml:64` [П] (только CI), затем `smoke-gui.sh rel "$TARGET" "$GEXT"`; macOS `smoke-gui.sh`; Windows bash-шаг `smoke-gui.sh --check-only`, затем шаг pwsh `Start-Process -FilePath <файл> -ArgumentList '--render-check' -Wait -PassThru` с проверкой `ExitCode -eq 0`, как `ci.yml:72-74` [П].
   Новых actions нет; `persist-credentials: false` и права как сейчас.
6. **`smoke.sh <rel> <label> <ext> [<verifier-dir>]`:**
   - Без 4-го аргумента (режим «выпуск»): допустим только `linux-x86_64`, иначе код 2 с текстом «CLI is released for Linux only (Q5 b); pass the verifier dir». Поведение прежнее, шаги 1-5.
   - С 4-м аргументом (режим «проверялка»): допустим только не-Linux, иначе код 2. Запускаемый файл `<verifier-dir>/chervo-verifier-$ver-$label$ext`, обычный файл, иначе код 1. Шаг 1 заменяется двумя проверками. Первая: в манифесте **нет** строки с этим именем; иначе FAIL, файл не запускается. Вторая: SHA-256 проверялки в сводку с пометкой «verifier, not published, not in the manifest». Шаги 2 (`--version`), 3 (`release-keys`) и 4 (чужая подпись) идут как сейчас; в шаге 4 вместо `$bin` передаётся GUI-файл своей цели из `rel`. Шаг 5 (`doctor`) не выполняется, в сводку пишется «doctor: not applicable, no CLI in the release for this OS (Q5 b)».
7. **`scripts/release/smoke-gui.sh <rel> <label> <gext> [--check-only]`:**
   - SHA-256 файла `chervotochina-$ver-$label$gext` равен строке манифеста **своей цели**, иначе файл **не запускается** (как `smoke.sh:48-59` [П]);
   - Linux: `timeout 120 xvfb-run -a <файл> --render-check`;
   - macOS: распаковка `ditto -x -k` в новый пустой каталог, `codesign --verify --strict`, `timeout 120 .../Chervotochina.app/Contents/MacOS/chervotochina --render-check`;
   - `--check-only`: только сверка SHA-256 (Windows; запуск делает шаг pwsh);
   - итог и код в `$GITHUB_STEP_SUMMARY`.
   `macos-x86_64` запускается только на `macos-15-intel` (как сейчас).
8. **`assemble.sh` и белый список:**
   - SBOM: после `cargo cyclonedx` (как сейчас) скопировать и `crates/chervo-gui/sbom.json` в `$dist/chervotochina-$ver-sbom.cdx.json`. Нет файла = стоп [НП: создаёт ли 0.5.9 SBOM для каждого члена workspace];
   - `check-whitelist.sh`, `expected_names`: ровно 7 имён таблицы 5.1. Самопроверка, сверх прежних случаев. Отвергаются лишние файлы: `chervo-$v-windows-x86_64.exe`, `chervo-$v-macos-aarch64`, `chervo-$v-macos-x86_64` (CLI не для Linux, Q5 б), `chervo-verifier-$v-windows-x86_64.exe`, `chervotochina-$v-macos-aarch64.dmg`. Отвергаются каталог `Chervotochina.app` и пропавший GUI-файл (каждый из 4). Принимается точный набор;
   - манифест: 7 строк `--artifact` по таблице 5.1 вместо прежних 5.
9. **`check-release-guards.sh`** (каждое новое правило с отрицательным случаем в `--self-test`):
   - правило 1, `guard_build_line`: в `build-release.sh` есть **обе** строки, `cargo build --release --locked -p chervo-cli --bin chervo --target` и `cargo build --release --locked -p chervo-gui --bin chervotochina --target`. Ни одна строка `cargo` в `release.yml` и `scripts/release/*.sh` не содержит двух `-p`. Самопроверка: пропавшая строка GUI; строка `cargo build ... -p chervo-cli -p chervo-gui`;
   - правило 2, `guard_smoke_yml`: `gh run` разрешён только как `gh run list` и `gh run download`. `rerun`, `cancel`, `delete`, `watch` и прочее запрещены, `gh api` и `gh release create|upload|edit|delete` как сейчас. Самопроверка: `gh run rerun 1`, `gh run cancel 1`, `gh run delete 1` ловятся, `list` и `download` в хорошем образце проходят;
   - правило 4, `guard_fetch_no_exec`: `dir_re` ловит и `verifier-files/`. Самопроверка: `chmod +x verifier-files/x`, `verifier-files/chervo-verifier-0.1.0-windows-x86_64.exe --version`, `./verifier-files/x` ловятся;
   - новое правило 6, `guard_no_verifier_in_release`: в блоках заданий `assemble` и `draft` файла `release.yml` (через `job_block`) нет подстроки `verifier`. Самопроверка: `name: verifier-linux-x86_64` в `assemble` ловится.
10. **`release-smoke.yml` и `release-smoke.sh`** (Р19г-11):
    - `fetch`:
      - `permissions: { contents: write, actions: read }`. Блочная форма как сейчас, плюс строка `actions: read`;
      - checkout с `fetch-depth: 0` (нужны теги), `persist-credentials: false`;
      - шаг «Download the draft» как сейчас;
      - новый шаг «Download the CI verifiers of the tag commit» (env `TAG`, `GH_TOKEN`, `REPO`; тот же строгий шаблон тега):
        - `commit="$(git rev-parse --verify --quiet "refs/tags/$TAG^{commit}")"`, проверка `^[0-9a-f]{40}$`;
        - `gh run list --repo "$REPO" --workflow release.yml --event push --status success --limit 200 --json databaseId,headSha,event,status,conclusion --jq` с тем же отбором, что `sign.sh:108-110` [П]; берётся первый id, проверка `^[0-9]+$`, нет такого id = отказ;
        - `mkdir verifier-files`, затем для `t` из `macos-aarch64 macos-x86_64 windows-x86_64`: `gh run download "$id" --repo "$REPO" -n "verifier-$t" -D verifier-files` [В: при одном `-n` файлы ложатся прямо в каталог, как `sign.sh:116` предполагает];
        - `printf 'commit %s\nrun %s\n' "$commit" "$id" > verifier-source.txt` (в корне, не в `verifier-files/`, иначе сработает правило 4);
        - `ls -l verifier-files`;
      - два `upload-artifact`: `verifier-files` (`path: verifier-files/*`) и `verifier-source` (`path: verifier-source.txt`), `retention-days: 1`.
    - `check`:
      - `permissions: {}` как сейчас;
      - матрица 4 ОС: добавить `{ os: macos-15-intel, target: macos-x86_64, ext: '' }`, сейчас её нет [П: `release-smoke.yml:66-69`]. В `include` поле `vdir`: `''` для Linux, `verifier-files` для остальных;
      - два `download-artifact` (`verifier-files` и `verifier-source`) в каталог `verifier-files`;
      - запуск: `args=(draft-files "$TARGET" "$EXT"); [[ -n "$VDIR" ]] && args+=("$VDIR"); bash tools/scripts/release/release-smoke.sh "${args[@]}"`.
    - `release-smoke.sh <dir> <label> <ext> [<verifier-dir>]`:
      - режимы как в `smoke.sh` (п. 6): без 4-го аргумента только Linux; с ним только не-Linux;
      - проверялка = `<verifier-dir>/chervo-verifier-$ver-$label$ext`. Файл `<verifier-dir>/verifier-source.txt` разбирается строго: ровно строки `^commit [0-9a-f]{40}$` и `^run [0-9]+$`. `commit` должен равняться строке `commit` подписанного манифеста, иначе FAIL и выход до запуска. В сводку идут SHA-256 проверялки, id прогона и коммит;
      - позитив: файлы манифеста с целью `$label` или `any`, имена из манифеста (как сейчас для `any`). Среди них обязан быть `chervotochina-$ver-$label$gext` (`gext` из `label`: `.exe` Windows, `.zip` macOS, пусто Linux). На Linux в набор входит и CLI. Требуются код 0 и ровно по строке `OK <name> <ver> same` на файл;
      - негатив «чужая цель»: как сейчас;
      - негатив «изменённый байт»: копия GUI-файла своей цели (на всех ОС) с изменённым байтом. Ожидается код 1 и ровно строка `FAIL NotInManifest`: сверка по хэшу [П: `verify.rs:115-120`]. Сейчас принимается любая `FAIL`; правило ужесточается;
      - `release-keys` проверялкой (или CLI на Linux): как сейчас;
      - `fetch` по-прежнему ничего скачанного не запускает. Проверялку запускает только `check`, у которого `permissions: {}`.
11. **`sign.sh`** (Р19г-11; исправление найденной ошибки и поведение без CLI). Порядок шагов после правки:
    - шаги 0, 1 и 1а без изменений;
    - **новый шаг 1б, до подписи.** Определить `label` по `uname`, как сейчас. Неизвестная ОС = `die "sign.sh runs on Linux x86_64, Windows x86_64 (Git Bash) or macOS; nothing was signed"`. Прежнее «WARNING ... was NOT run» с продолжением **удаляется**. Проверялка:
      - Linux: опубликованный `chervo-$ver-linux-x86_64` из черновика (размер и SHA-256 уже сверены с манифестом в шаге 1);
      - Windows и macOS: `vdir="$(mktemp -d)"` (добавить в `trap`), `gh run download "$matched" --repo "$repo" -n "verifier-$label" -D "$vdir"`. Нет артефакта = `die`: «artifact verifier-$label of run $matched is not available (14 days?); nothing was signed». В `$vdir` ровно один обычный файл `chervo-verifier-$ver-$label$ext`, иначе `die`. Печать SHA-256 с пометкой «verifier from run $matched, commit $commit, not published, not signed»;
      - список `own`: имена манифеста с целью `$label` или `any`. В нём обязан быть `chervotochina-$ver-$label$gext`, иначе `die`;
    - шаг 2 (подпись) без изменений;
    - **шаг 3.** `minisign -Vm` по манифесту и **всем** файлам, как сейчас. Затем `"$verifier" verify-release chervo-release.txt chervo-release.txt.minisig "${own[@]}"`: передаются только файлы своей цели и `any`. Это исправление ошибки `sign.sh:155` [П]: файлы чужих целей давали `WrongTarget` и код 1. Требуются код 0 и ровно `${#own[@]}` строк `^OK [A-Za-z0-9._-]+ $ver same$`, иначе `die` до загрузки подписей;
    - шаг 4 без изменений;
    - чек-лист в конце:
      - Windows: на ПК владельца из черновика запускается `chervotochina-*.exe`. Первый экран показывает «хранилище доступно» (настоящий Credential Manager). На экране «Обновления» скачанные манифест, подпись и `.exe` дают «подходит, та же версия». Ключи на экране сверяются с README;
      - Linux: `chervo doctor` по `docs/HEADLESS_LINUX.md`, `chervo release-keys` сверяется с README;
      - после публикации: на Linux `chervo check-update` как сейчас. На Windows в окне с включённой проверкой «Проверить сейчас» даёт «Установлена последняя версия»;
      - macOS: как сейчас («не проверено»);
      - `release-smoke.yml` зелёный на 4 ОС.
    Самопроверки у `sign.sh` нет: дирижёр проверяет правку чтением diff, прогон остаётся пунктом владельца (SPEC 19 разд. 5, «не проверено»).
12. **`draft.sh`**, текст заметки: «Состав: окно chervotochina для linux-x86_64, macos-aarch64 (.zip), macos-x86_64 (.zip), windows-x86_64 (.exe); консольная chervo только для linux-x86_64; SBOM для chervo и для chervotochina». Строку «SBOM один для chervo-cli» заменить. Строка про macOS: «macOS: не проверено на машине; приложение подписано ad-hoc, без Apple, запуск по docs/INSTALL.md».
13. **`docs/INSTALL.md`** (переписать разд. 1-8):
    - какой файл скачивать: окно для своей ОС; на Linux дополнительно `chervo` для мини-ПК и проверок. На Windows и macOS консольной программы нет;
    - первая проверка на всех ОС внешним `minisign` (как сейчас), затем SHA-256 файла: Linux `sha256sum`, macOS `shasum -a 256`, Windows `Get-FileHash -Algorithm SHA256` [В]. Следующие версии проверяются на экране «Обновления», на Linux ещё и `chervo verify-release`;
    - Windows: SmartScreen для `chervotochina-*.exe`;
    - macOS: проверить `.zip` до распаковки, распаковать, перенести в «Программы». Первый запуск через «Системные настройки → Конфиденциальность и безопасность → Всё равно открыть» [В: macOS 15]. Запасной путь `xattr -dr com.apple.quarantine /Applications/Chervotochina.app`;
    - Linux: `chmod +x`, нужен графический сеанс X11 или Wayland. Если хранилища нет, первый экран окна скажет об этом, а `chervo doctor` даст подробности (`docs/HEADLESS_LINUX.md`). Раздел `chervo doctor` пометить «только Linux»; на Windows и macOS состояние хранилища показывает первый экран окна;
    - проверка новых версий: карточка при первом запуске, что уходит в сеть (GitHub видит IP), как выключить. Прежний текст «пока не реализована» убрать;
    - обновление: проверить файл на экране «Обновления», закрыть программу, заменить файл.

### 5.3. Критерии приёмки
- [ ] `bash scripts/check-release-guards.sh` и `--self-test` (новые случаи п. 9 в выводе); `bash scripts/release/check-whitelist.sh --self-test`; `bash scripts/release/check-deps.sh --self-test`; `bash scripts/release/package-macos.sh --self-test` (на macOS-раннере, иначе «не проверено»); `bash scripts/check-actions-pinned.sh` и `--self-test`
- [ ] CI `ci.yml` зелёный на коммите правок (3 ОС)
- [ ] Пробный `release.yml` (`workflow_dispatch`, `skip_keys_check: true`) зелёный. В отчёте:
  - список `release-files`: ровно 8 файлов, 7 из таблицы 5.1 плюс манифест; манифест целиком;
  - артефакты `verifier-macos-aarch64`, `verifier-macos-x86_64`, `verifier-windows-x86_64` по одному файлу с SHA-256;
  - вывод `ldd`, `otool -L` и проверки DLL для каждого GUI-файла и проверялки Windows;
  - `codesign --verify` обоих `.zip`;
  - `repro` для CLI и GUI;
  - по каждому из 4 раннеров `smoke` для CLI: Linux в режиме «выпуск», остальные в режиме «проверялка» без `doctor`. Для GUI: SHA-256 равен строке манифеста, код `--render-check` 0.
  Дирижёр сам открывает сводку прогона.
- [ ] Негатив (самопроверки): лишний CLI не для Linux, проверялка в каталоге выпуска, `.dmg`, каталог `.app`, пропавший GUI-файл валят белый список; режим `smoke.sh` без проверялки на Windows даёт код 2
- [ ] Ревью security по diff `release-smoke.yml`, `sign.sh`, `check-release-guards.sh`, `release.yml`: без High/Critical
- [ ] Ручные (владелец, одним заходом; до этого «не проверено»):
  - чистая Windows 11 запускает `chervotochina-*.exe` без VC++;
  - Ubuntu 24.04 с рабочим столом запускает файл после `chmod +x`;
  - macOS: машины нет, в заметках выпуска «на macOS не проверено»;
  - `sign.sh` на Windows (Git Bash) и `release-smoke.yml` на первом черновике, сначала с одноразовым ключом.

## 5а. 19г-4: файл лицензий сторонних компонентов (Q6 = а)          builder sonnet/medium

Прочитать: этот файл разд. 1 (Р19г-12), 5, 5а; `deny.toml`; `scripts/release/assemble.sh`, `check-whitelist.sh`; `scripts/check-release-guards.sh`; `.github/workflows/release.yml`; `crates/chervo-gui/src/{texts.rs, screens/settings.rs}`; документация `cargo-about` закреплённой версии (ссылки в п. 1). Больше ничего не искать.

1. **Версия `cargo-about`** [В: актуальную версию я не сверял, доступа к crates.io у меня нет; по памяти ветка 0.6-0.8]. Дирижёр (через scout) сверяет до передачи builder:
   - `cargo info cargo-about` на toolchain 1.99.1 или `https://crates.io/api/v1/crates/cargo-about`: поле `max_stable_version`, флаг `yanked`, `rust_version` не выше 1.99.1;
   - `CHANGELOG.md` репозитория `EmbarkStudios/cargo-about` на этом теге: нет известных проблем с `--locked`;
   - справка по конфигу на том же теге (`docs/src/cli/generate/config.md` или аналог) и вывод `cargo about generate --help`.
   Номер вписывается сюда и в `release.yml` как `cargo install --locked --version =X.Y.Z cargo-about`. Ключи и флаги ниже помечены [В]; если в выбранной версии их нет, это стоп, а не подбор.
2. **`packaging/licenses/about.toml`** (ключи сверить с документацией версии из п. 1):
   ```toml
   # Stage 19g-4 (Q6 = a). Keep in sync with deny.toml [licenses]: same allow list, same crate-scoped exceptions.
   # Order matters for "A OR B": the first accepted licence is chosen [В], so MIT goes first.
   accepted = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
   targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"]
   ignore-dev-dependencies = true
   ignore-build-dependencies = false   # superset: harmless, nothing is missed
   no-clearly-defined = true           # no network lookups; the result depends on Cargo.lock only
   private = { ignore = true }         # our own crates (as deny.toml [licenses.private])

   [webpki-roots]
   accepted = ["CDLA-Permissive-2.0"]
   [epaint_default_fonts]
   accepted = ["OFL-1.1", "Ubuntu-font-1.0"]
   [clipboard-win]
   accepted = ["BSL-1.0"]
   [error-code]
   accepted = ["BSL-1.0"]
   ```
   Если в выбранной версии нет точечных `accepted` по пакету, точечные лицензии **не** переносятся в общий список: это стоп, нужно решение architect.
3. **`packaging/licenses/third-party-licenses.hbs`**: обычный текст, тексты лицензий только в тройных скобках `{{{text}}}` (двойные экранируют `<`, `&` как HTML). Набросок, имена полей [В]:
   ```
   {{#each licenses}}
   ================================================================
   {{{name}}} ({{{id}}})
   Used by:
   {{#each used_by}}  - {{{crate.name}}} {{{crate.version}}}
   {{/each}}
   ----------------------------------------------------------------
   {{{text}}}

   {{/each}}
   ```
4. **`assemble.sh`**, шаг 1б после SBOM:
   - файл `$dist/chervo-$ver-third-party-licenses.txt` собирается так:
     - заголовок ASCII: `Third-party licenses of Chervotochina $ver (commit $commit)`;
     - «Part 1: chervotochina (window, all 4 targets)» и вывод `cargo about generate -c packaging/licenses/about.toml -m crates/chervo-gui/Cargo.toml --fail <шаблон>`;
     - «Part 2: chervo (console, Linux)» и тот же вызов с `-m crates/chervo-cli/Cargo.toml`.
     Флаги [В: `-c`, `-m`, `--fail`, `--locked`/`--frozen`/`--offline`, если есть]. Без `--workspace` и `--all-features`: правило 1 их запрещает. В части 2 допустим перечень по всем 4 целям, это надмножество;
   - проверки сразу после сборки, любая неудача = выход 1:
     - размер больше 0 и меньше 8 МиБ;
     - есть подстроки `epaint_default_fonts`, `clipboard-win`, `error-code`, `webpki-roots`, `OFL-1.1`, `Ubuntu-font-1.0`, `BSL-1.0`, `CDLA-Permissive-2.0`, `MIT`, `Apache-2.0`;
     - нет HTML-сущностей `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#`;
     - нет строки, начинающейся с `{{`;
   - `check-whitelist.sh`: восьмое имя `chervo-$v-third-party-licenses.txt`, самопроверка «пропал файл лицензий»;
   - манифест: восьмая строка `--artifact any "$release/chervo-$ver-third-party-licenses.txt"`. Итого 8 артефактов и 9 файлов с манифестом;
   - строка в сводку: число разделов и число вхождений заглушек `<copyright holders>`, `<year>`, `<Copyright Holder>` (у пакетов без своего файла лицензии; только запись).
5. **`release.yml`, `assemble`:** после строки `cargo-cyclonedx` строка `- run: cargo install --locked --version =X.Y.Z cargo-about`. Больше нигде, ни в `ci.yml`, ни в `gui-probe.yml`.
6. **Страж закрепления, `check-release-guards.sh`, новое правило 5 `guard_cargo_install`** по всем `.github/workflows/*.yml`:
   - каждая логическая строка с `cargo install` имеет вид `cargo install --locked --version =<MAJOR>.<MINOR>.<PATCH> <имя>` и больше ничего: один пакет, без `--git`, `--path`, `--registry`, `--index`, `--force`. Нынешние строки `ci.yml:92,94,103`, `gui-probe.yml:31`, `release.yml:141` [П] этому виду уже соответствуют;
   - `cargo binstall` и `cargo-binstall` запрещены;
   - `cargo-about` ставится ровно одной строкой, в `release.yml`, в блоке задания `assemble` (`job_block`);
   - `cargo about` вызывается только в `scripts/release/assemble.sh`: в `.github/workflows/*.yml` и в остальных `scripts/**/*.sh` его нет.
   Самопроверка (каждое отвергается):
   - без `--locked`;
   - `--version 0.6.4` без `=`;
   - `--version =0.6`;
   - `--version '^0.6.4'`;
   - `--git https://...`;
   - два пакета в строке;
   - `cargo install cargo-about` без версии;
   - `cargo binstall cargo-about`;
   - установка `cargo-about` в `ci.yml`;
   - установка `cargo-about` в задании `build` файла `release.yml`;
   - `cargo about generate` в `release.yml`.
   Хороший образец проходит.
7. **«О программе»** (`texts.rs`, `screens/settings.rs::about`):
   - `ABOUT_LICENCES` = «В программе используются свободные библиотеки. Их лицензии и авторы перечислены в файле chervo-{ver}-third-party-licenses.txt на странице выпусков; файл подписан вместе с программой.» `{ver}` заменяется на `chervo_core::VERSION` при показе;
   - ниже `RELEASES_PAGE` выделяемым текстом и кнопка «Копировать». Используется тот же виджет, что в диалоге Р19г-9, без нового кода сети и процессов;
   - стражи 19г-2 (`update_gates`) не ослабляются; render-check: состояние «О программе» уже рисуется или добавляется.
8. **`draft.sh` и `docs/INSTALL.md`:** одна строка в заметке и в разд. 1 инструкции: «тексты лицензий сторонних библиотек: chervo-<версия>-third-party-licenses.txt».

Критерии приёмки:
- [ ] `bash scripts/check-release-guards.sh` и `--self-test` (правило 5, все случаи п. 6); `check-whitelist.sh --self-test`; `bash scripts/check-actions-pinned.sh`
- [ ] `cargo test -p chervo-gui --locked`, clippy, fmt; `gui-render` зелёный
- [ ] Пробный `release.yml` зелёный. В отчёте:
  - 9 файлов `release-files`;
  - первые 40 строк файла лицензий;
  - раздел OFL-1.1 и раздел Ubuntu-font-1.0 целиком;
  - строки проверки п. 4 и счётчик заглушек;
  - версия `cargo-about` из вывода `cargo about --version`.
  Дирижёр сам читает разделы OFL и Ubuntu-font. В тексте OFL должна стоять настоящая строка авторских прав шрифта, а не заглушка `<Copyright Holder>`. Если стоит заглушка, это стоп: в `about.toml` нужен `clarify` с файлом лицензии из пакета и его контрольной суммой [В], решение architect.
- [ ] Стоп и доклад, если у какого-то пакета выбрана лицензия Apache-2.0 и в его исходнике есть файл `NOTICE*`: Apache-2.0 требует переносить NOTICE [В: умеет ли это `cargo-about`]. Проверка: список пакетов с выбранной Apache-2.0 из вывода, затем `ls ~/.cargo/registry/src/*/<пакет>-<ver>/NOTICE*` в задании `assemble`, вывод в сводку.

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
- Автообновление, скачивание, замена своего файла, запуск процессов, открытие ссылок (Q7 = а: только «Копировать»).
- Показ доверенного комментария, адресов или текстов из сети.
- Чтение файлов в GUI-коде или в потоке окна; запись файлов в GUI; хранение найденной версии на диске.
- Новые пакеты и возможности (`eframe` `links`, `persistence`, возможности `rfd`).
- Изменения `chervo-update`, `chervo-update-check`, форматов манифеста, подписи и настроек сверх разд. 2; изменения поведения CLI, в том числе флаг цели у `verify-release`.
- Публикация проверялки: в `release-files`, черновике и манифесте её нет.
- `cargo-about` вне задания `assemble`, в зависимостях workspace, без закреплённой версии; перенос точечных лицензий в общий список `accepted`.
- Authenticode, нотаризация, `.dmg`, AppImage, установщики, `.desktop`; новые actions и кэши; публикация и теги.
Нужен новый пакет, инструмент или возможность сверх названных = стоп.

## 8. Модель угроз: T19-дополнение (внести в THREAT_MODEL вместе с T19)

| Атака или сбой | Мера | Остаток |
|---|---|---|
| Сетевой запрос без согласия (ошибка GUI, будущая оболочка) | `check_latest` ядра требует `UpdateCheckPermit`, который выдаёт только узел при записанном `Enabled`; тесты ядра и стражи GUI | процесс того же пользователя может вписать `update_check=1` в настройки (T18(a)) |
| Частые запросы как слежка или нагрузка | 24 ч в фоне, 60 с между ручными, время пишется до запроса, часы назад = без запроса | перевод часов вперёд даёт одну лишнюю проверку на каждый скачок; GitHub видит IP и время (SPEC 19 разд. 8) |
| Подмена отображения через bidi или управляющие символы (файл с U+202E в имени, доверенный комментарий) | доверенный комментарий не показывается; имена через `safe_label`; ошибки только фиксированными строками | гомоглифы в именах своих файлов не убираются; на решение это не влияет, сверка идёт по хэшу |
| Большой или медленный файл при сверке | пределы чтения манифеста и подписи; `check_artifact` прекращает чтение после наибольшего размера; отдельный поток, по одному заданию | окно показывает «Проверяем…», пока не дочитан файл с медленного носителя |
| Подмена между проверкой и запуском (TOCTOU) | подсказка «замените этим файлом» | вне модели (T9/T10) |
| Ложная «новая версия» (утёкший ключ, MITM) | только номер версии; ссылка вшитая, копируется, не открывается автоматически | пользователя можно уговорить скачать файл с другого места: экран сверки его отвергнет, если ключ не утёк |
| Неподписанные пакеты (ad-hoc macOS, Windows без Authenticode) | первая установка: `minisign`, SHA-256 и key_id из второго канала; инструкция | обход Gatekeeper и SmartScreen приучает нажимать «всё равно открыть» (U18, Q2) |
| Тестовые крючки или чужая сборка в пакете | сборка по пакету, проверка `test-store` для обоих пакетов, белый список, SHA-256 перед запуском в `smoke` | как T19: закладка во время сборки в CI не ловится |
| Строки настроек от новой версии в старой | разбор строгий: старая версия выдаст `SettingsCorrupt`, «Сбросить настройки» сохранит копию | откат на сборки до 19г теряет настройки (публичных выпусков до 19г нет) |
| Проверялка (неопубликованный CLI из CI) исполняется на машине владельца с ключом подписи и в `release-smoke` | берётся только из успешного push-прогона `release.yml` на коммите тега; в `sign.sh` из того же прогона, чей `release-files` совпал с черновиком; запуск только после сверки черновика; SHA-256 и id прогона в выводе; в `release-smoke` её запускает только `check` без прав; страж и белый список не пускают её в выпуск | не покрыта подписью владельца; компрометация CI даёт вредную проверялку на машине владельца. Это не новый риск: до 19г там запускался CLI из того же прогона (T19). Ключ minisign защищён паролем |
| Права `fetch` в `release-smoke` расширены (`actions: read`, `gh run list/download`) | только чтение; страж правила 2 пускает лишь `list` и `download`; `fetch` ничего скачанного не запускает (правило 4, в том числе `verifier-files/`) | регулярные стражи по тексту, не разбор оболочки (best effort, как сейчас) |
| На Windows и macOS нет CLI для проверки (Q5 б) | первая установка через `minisign` и SHA-256 средствами ОС; дальше экран «Обновления» | пользователь без `minisign` проверить первую загрузку не может; так же было и с CLI |
| Неполный или подменённый файл лицензий | собирается в CI из `Cargo.lock`, закреплённая версия, без сети (`no-clearly-defined`), подписан с остальными; проверки состава в `assemble.sh` | тексты берутся из файлов пакетов; у пакета без своего файла остаётся типовой текст с заглушкой; внутри `.exe` текстов нет, только рядом в выпуске |

Точечное ревью security 19г-1 по списку: Р19г-5 (запечатанность разрешения, нет обходного реэкспорта), Р19г-6 (таблица решений, порядок «записать, потом запрос»), разбор новых ключей настроек, пределы чтения в `verify_release_files`, отсутствие доверенного комментария в представлении.
Ревью security 19г-3 по diff:
- права и шаги `fetch`/`check`;
- отбор прогона и коммита;
- `verifier-source.txt` и его строгий разбор;
- порядок шагов `sign.sh` (проверялка до подписи, `die` до загрузки);
- новые правила стражей и их самопроверки.

## 9. Стоп-условия, лимит, отчёт
Стоп, если:
- спецификация противоречит коду;
- нужен новый пакет, инструмент или возможность;
- GUI на `ubuntu-22.04` требует apt;
- нет SBOM GUI;
- нет `codesign`/`ditto`/`plutil`;
- `ldd` GUI показывает лишние библиотеки;
- `gh run download -n ... -D` кладёт файлы не прямо в каталог;
- у `cargo-about` нет ключей или флагов из разд. 5а;
- в разделе OFL заглушка вместо строки авторских прав;
- есть Apache-2.0 с `NOTICE`;
- критерий непроверяем.
В этих случаях остановиться и доложить, не обходить.
Лимит: не более 2 кругов «правка по ревью» на часть.
Отчёт builder (до 25 строк): изменённые файлы; команды приёмки и последние строки вывода; что не сделано; отклонения.

## 10. Вопросы владельцу

**Q5. Консольная `chervo` в выпуске.** Ответ владельца 2026-10-28: **(б)**, консоль только для Linux, на Windows и macOS только окно. Рекомендация architect была (а). Исполнение: Р19г-11, разд. 5. Проверка подписи на Windows и macOS идёт неопубликованной сборкой-проверялкой из того же прогона CI; ослабления нет.

**Q6. Лицензии сторонних компонентов.** Ответ: **(а)**, `cargo-about` с закреплённой версией только в CI, файл `chervo-<ver>-third-party-licenses.txt` прикладывается к выпуску. Исполнение: Р19г-12, разд. 5а.

**Q7. Как открыть страницу выпусков.** Ответ: **(а)**, ссылка и кнопка «Копировать», браузер не запускается. Исполнение: Р19г-9 (без изменений).

Новых вопросов нет.

## 11. Резюме для владельца
- В выпуске:
  - окно `chervotochina` для Windows (один `.exe`), macOS (`.zip` с приложением, подпись ad-hoc без Apple) и Linux (один файл);
  - консольная `chervo` только для Linux (ваш ответ Q5 б);
  - два SBOM и файл лицензий.
  Всего 8 файлов плюс список файлов с подписью. AppImage и установщиков нет.
- Как теперь проверяется подпись на Windows и macOS без консольной программы:
  - CI по-прежнему собирает `chervo` для этих систем, но только как «проверялку». В выпуск она не попадает: это стерегут белый список и отдельное правило;
  - `release-smoke` и `sign.sh` на вашем ПК с Windows проверяют ею подписанные файлы своей системы, тем же кодом, что у экрана «Обновления»;
  - `sign.sh` берёт проверялку из того же прогона CI, с которым уже сверяет черновик. Новой точки доверия нет;
  - нет проверялки или ОС не поддерживается: `sign.sh` останавливается до подписи, а не пропускает шаг, как раньше.
- Исправлена ошибка `sign.sh`: проверка после подписи падала бы на любом выпуске с несколькими системами.
- Лицензии: файл собирает `cargo-about` в CI, версия закреплена, в CI его ставит только сборка выпуска. Файл подписан вместе с программой. «О программе» называет его и показывает адрес страницы выпусков. Исключения BSL-1.0 и OFL остаются точечными, как в `deny.toml`. Версию `cargo-about` дирижёр сверит до начала работы.
- Проверка новых версий выключена, пока вы не ответите на карточку при первом запуске; включённая идёт раз в сутки и по кнопке; без вашего «да» сетевой код не вызывается (проверяется тестами).
- На вашей стороне, ручные пункты, до них «не проверено»:
  - Windows: запуск окна без VC++;
  - Windows: экран «Обновления» на файлах черновика;
  - Windows: `sign.sh` в Git Bash с одноразовым ключом;
  - Ubuntu: запуск окна на рабочем столе.
