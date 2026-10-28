//! Выпуски и новые версии для оболочек (этап 19г-1, SPEC 19г): офлайн-сверка скачанных файлов
//! с подписанным списком и проверка новых версий, невозможная без согласия по самому типу.
//!
//! * Реэкспорт поимённый. Крейты `chervo_update` и `chervo_update_check` целиком наружу не
//!   выходят, как и сырой `chervo_update_check::check_latest` (охраняет `tests/update_reexport.rs`).
//! * В сеть ведёт одна функция: [`check_latest`], и ей нужен [`UpdateCheckPermit`]. Его выдаёт
//!   только `Node::update_check_permit`, когда в настройках записано согласие и подошло время.
//! * Доверенного комментария подписи в представлении нет намеренно: он не показывается.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub use chervo_update::{
    Freshness, KeyId, KeyRole, MAX_MANIFEST_LEN, MAX_MINISIG_LEN, Target, UpdateError, Version,
};
pub use chervo_update_check::{CheckError, RELEASES_PAGE, UpdateStatus};

use chervo_update::{KeySet, check_artifact_path, verify_manifest};

/// Фоновая проверка не чаще раза в сутки.
pub const UPDATE_CHECK_INTERVAL_SECS: u64 = 86_400;
/// Между нажатиями кнопки «Проверить сейчас» не меньше этого, секунд.
pub const MANUAL_CHECK_FLOOR_SECS: u64 = 60;

/// Версия запущенной программы (`crate::VERSION`); `None`, если это не `MAJOR.MINOR.PATCH`.
pub fn running_version() -> Option<Version> {
    Version::from_str(crate::VERSION).ok()
}

/// Вшитый ключ владельца: роль и `key_id`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EmbeddedKey {
    pub role: KeyRole,
    pub key_id: KeyId,
}

fn embedded_of(keys: &KeySet) -> Vec<EmbeddedKey> {
    keys.list()
        .into_iter()
        .map(|(role, key_id, _)| EmbeddedKey { role, key_id })
        .collect()
}

/// Без ввода-вывода: разбор вшитых файлов ключей (`KeySet::embedded()`). Ключи не вшиты:
/// `NoTrustedKeys`.
pub fn embedded_keys() -> Result<Vec<EmbeddedKey>, UpdateError> {
    KeySet::embedded().map(|k| embedded_of(&k))
}

/// Итог по одному файлу: имя берётся из подписанного списка, не из имени файла на диске.
#[derive(PartialEq, Eq, Debug)]
pub struct FileVerdict {
    pub name: String,
    pub target: Target,
    pub freshness: Freshness,
}

/// Итог сверки. Доверенного комментария подписи здесь нет намеренно.
#[derive(PartialEq, Eq, Debug)]
pub struct ReleaseCheck {
    /// Версия подписанного списка.
    pub version: Version,
    /// Каким вшитым ключом подписано.
    pub signer: EmbeddedKey,
    /// По одному итогу на входной файл, в том же порядке.
    pub files: Vec<Result<FileVerdict, UpdateError>>,
}

/// Открывает обычный файл. Путь проверяется до открытия (открытие FIFO на Unix блокируется до
/// появления писателя), а дескриптор после открытия: между проверкой и открытием путь могли
/// подменить. Unix: открытие с `O_NONBLOCK` (подставленный FIFO не повесит открытие), после
/// проверки открытого дескриптора флаг снимается. Как в `chervo_update::check_artifact_path`.
// тип `bits()` зависит от ОС (u32 или i32): приведение нужно не везде
#[allow(clippy::unnecessary_cast, clippy::cast_possible_wrap)]
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    let not_regular = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut opts,
        rustix::fs::OFlags::NONBLOCK.bits() as i32,
    );
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    #[cfg(unix)]
    {
        let flags = rustix::fs::fcntl_getfl(&file).map_err(std::io::Error::from)?;
        rustix::fs::fcntl_setfl(&file, flags - rustix::fs::OFlags::NONBLOCK)
            .map_err(std::io::Error::from)?;
    }
    Ok(file)
}

/// Читает файл не больше `max` байт; больше значит `TooLarge`. Только обычный файл.
fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, UpdateError> {
    let io = |e: std::io::Error| UpdateError::Io(e.kind());
    let file = open_regular(path).map_err(io)?;
    let mut buf = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(io)?;
    if buf.len() > max {
        return Err(UpdateError::TooLarge);
    }
    Ok(buf)
}

/// Сверка скачанных файлов выпуска с подписанным списком, офлайн. Ключи вшитые
/// (`KeySet::embedded()`); версия запущенной программы `running_version()`, цель `Target::current()`.
///
/// Порядок: ключи (ошибка = `NoTrustedKeys` без чтения файлов), версия программы, чтение
/// списка и подписи с пределами (`MAX_MANIFEST_LEN`, `MAX_MINISIG_LEN`), подпись, и только
/// потом каждый файл. Ошибка списка или подписи это `Err` целиком, файлы не читаются.
///
/// Если версия программы не `MAJOR.MINOR.PATCH` (`running_version() == None`), результат
/// `Err(UpdateError::Io(ErrorKind::InvalidData))`: это ошибка сборки, а не списка.
///
/// Читает файлы и может работать долго: вызывать не из потока окна.
pub fn verify_release_files(
    manifest: &Path,
    minisig: &Path,
    files: &[PathBuf],
    allow_downgrade: bool,
) -> Result<ReleaseCheck, UpdateError> {
    verify_release_files_with(
        KeySet::embedded(),
        running_version(),
        Target::current(),
        manifest,
        minisig,
        files,
        allow_downgrade,
    )
}

/// То же с подставными ключами, версией и целью (для тестов).
pub(crate) fn verify_release_files_with(
    keys: Result<KeySet, UpdateError>,
    running: Option<Version>,
    target: Option<Target>,
    manifest: &Path,
    minisig: &Path,
    files: &[PathBuf],
    allow_downgrade: bool,
) -> Result<ReleaseCheck, UpdateError> {
    let keys = keys?;
    let running = running.ok_or(UpdateError::Io(std::io::ErrorKind::InvalidData))?;
    let manifest_bytes = read_capped(manifest, MAX_MANIFEST_LEN)?;
    let sig_bytes = read_capped(minisig, MAX_MINISIG_LEN)?;
    let vm = verify_manifest(&keys, &manifest_bytes, &sig_bytes)?;
    let (role, key_id) = vm.signer();
    let verdicts = files
        .iter()
        .map(|path| {
            check_artifact_path(&vm, path, running, target, allow_downgrade).map(|c| FileVerdict {
                name: c.artifact.name,
                target: c.artifact.target,
                freshness: c.freshness,
            })
        })
        .collect();
    Ok(ReleaseCheck {
        version: vm.manifest().version,
        signer: EmbeddedKey { role, key_id },
        files: verdicts,
    })
}

/// Согласие на проверку новых версий. До ответа пользователя `NotAsked`: сети нет.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateConsent {
    NotAsked,
    Enabled,
    Disabled,
}

/// Разрешение на ОДИН сетевой запрос. Публичного конструктора нет; не `Clone`, не `Copy`,
/// не `Default`. Выдаёт только `Node::update_check_permit`; тратится в [`check_latest`].
///
/// Собрать значение снаружи ядра нельзя (поле закрыто):
///
/// ```compile_fail,E0451
/// let _ = chervo_core::update::UpdateCheckPermit { _sealed: () };
/// ```
///
/// Конструктора по умолчанию нет:
///
/// ```compile_fail,E0599
/// let _ = chervo_core::update::UpdateCheckPermit::default();
/// ```
///
/// Копировать разрешение нельзя:
///
/// ```compile_fail,E0277
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<chervo_core::update::UpdateCheckPermit>();
/// ```
#[derive(Debug)]
pub struct UpdateCheckPermit {
    _sealed: (),
}

impl UpdateCheckPermit {
    /// Только для ядра: вызывается из `Node::update_check_permit` после записи времени.
    pub(crate) fn issue() -> Self {
        Self { _sealed: () }
    }
}

/// Единственный путь в сеть для оболочек на ядре. Внутри `chervo_update_check::check_latest`;
/// блокируется до 30 с: вызывать не из потока окна. Разрешение тратится.
pub fn check_latest(
    permit: UpdateCheckPermit,
    running: Version,
) -> Result<UpdateStatus, CheckError> {
    let UpdateCheckPermit { _sealed } = permit;
    chervo_update_check::check_latest(running)
}

/// Решение по правилам Р19г-6.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Decision {
    /// Запроса нет, файл настроек не меняется.
    Deny,
    /// Часы ушли назад: записать `now`, запроса нет.
    RecordOnly,
    /// Записать `now` и выдать разрешение.
    Permit,
}

/// `consent`, время последней проверки `last` (0: не проверяли), текущее `now`, `manual`:
/// нажата кнопка. Без ввода-вывода.
pub(crate) fn decide(consent: UpdateConsent, last: u64, now: u64, manual: bool) -> Decision {
    if consent != UpdateConsent::Enabled {
        return Decision::Deny;
    }
    // время 0 (часы до 1970 или ошибка чтения часов): пределов не проверить, запроса и записи нет;
    // иначе `last == 0` («не проверяли») и `now == 0` обходили бы и сутки, и минуту
    if now == 0 {
        return Decision::Deny;
    }
    if manual {
        // кнопка: часы ушли назад или прошло не меньше нижнего предела
        return match now.checked_sub(last) {
            None => Decision::Permit,
            Some(d) if d >= MANUAL_CHECK_FLOOR_SECS => Decision::Permit,
            Some(_) => Decision::Deny,
        };
    }
    if last == 0 {
        return Decision::Permit;
    }
    match now.checked_sub(last) {
        // часы ушли назад: не проверяем, но запоминаем новое время, чтобы срок считался от него
        None => Decision::RecordOnly,
        Some(d) if d >= UPDATE_CHECK_INTERVAL_SECS => Decision::Permit,
        Some(_) => Decision::Deny,
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
