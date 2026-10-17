//! Папка приёма (спецификация 15, решения 7 и 9). Корень канонизируется один раз; рядом с
//! ним на том же томе лежит `.chervo-partial` (временные файлы этапа 14 и наши журналы).
//! В `Debug` и `Display` ошибок нет путей.

use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::path::{Path, PathBuf};

use crate::limits::ReceiveLimits;

/// Имя служебного каталога внутри папки приёма. Имя с точкой в начале нельзя прислать:
/// санитайзер заменяет ведущую точку (R3).
const PARTIAL_NAME: &str = ".chervo-partial";
/// Наши журналы внутри служебного каталога (имя не из 32 hex-цифр: уборка этапа 14 его
/// пропускает).
const JOURNAL_NAME: &str = "receive";
/// Пробный файл для определения нашего uid (Unix).
#[cfg(unix)]
const PROBE_NAME: &str = "uid.probe";

/// Настройки приёма. Хранятся в настройках приложения (этап 18), не в файле друзей.
#[derive(Clone)]
pub struct ReceiveConfig {
    pub root: PathBuf,
    pub limits: ReceiveLimits,
    /// Рев. 3: единственная защита автоприёма от переполнения диска. После приёма предложения
    /// на томе папки приёма должно остаться не меньше этого процента его объёма; иначе вопрос
    /// «принять?». Объёма предложения как предела нет. По умолчанию 10; 0 отключает запас
    /// (остаётся проверка, что предложение вообще помещается).
    pub min_free_percent: u8,
    /// Разрешить папку, доступную другим пользователям (Unix). По умолчанию нет.
    pub allow_shared_root: bool,
    /// Windows: поток `Zone.Identifier` (ZoneId=3) у каждого принятого файла.
    pub mark_of_the_web: bool,
    /// macOS: атрибут `com.apple.quarantine` у каждого принятого файла.
    pub quarantine: bool,
}

impl ReceiveConfig {
    /// Значения по умолчанию: свободного места после приёма не меньше 10 %, метки включены.
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            limits: ReceiveLimits::default(),
            min_free_percent: 10,
            allow_shared_root: false,
            mark_of_the_web: true,
            quarantine: true,
        }
    }
}

impl fmt::Debug for ReceiveConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiveConfig(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RootError {
    NotAbsolute,
    NotDir,
    /// Unix: папка принадлежит не нам или доступна на запись другим.
    Shared,
    /// Unix: `.chervo-partial` доступен другим или принадлежит не нам.
    PartialNotPrivate,
    Io(io::ErrorKind),
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAbsolute => "receive folder is not an absolute path",
            Self::NotDir => "receive folder is not a directory",
            Self::Shared => "receive folder is shared with other users",
            Self::PartialNotPrivate => "service folder of the receive folder is not private",
            Self::Io(_) => "receive folder i/o error",
        })
    }
}

impl std::error::Error for RootError {}

impl From<io::Error> for RootError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Проверенная папка приёма: канонический корень, служебный каталог и каталог журналов.
#[derive(Clone)]
pub struct ReceiveRoot {
    root: PathBuf,
    partial: PathBuf,
    journals: PathBuf,
}

impl fmt::Debug for ReceiveRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiveRoot(..)")
    }
}

/// Построитель каталогов без рекурсии; Unix: права 0o700.
pub(crate) fn private_dir_builder() -> DirBuilder {
    #[cfg(unix)]
    {
        let mut b = DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b
    }
    #[cfg(not(unix))]
    DirBuilder::new()
}

/// Создаёт каталог (Unix: права 0o700) или принимает уже существующий настоящий каталог.
/// Ссылка или файл под этим именем: ошибка.
fn ensure_private_dir(p: &Path) -> Result<(), RootError> {
    match private_dir_builder().create(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let m = fs::symlink_metadata(p)?;
            if m.file_type().is_dir() && !m.file_type().is_symlink() {
                Ok(())
            } else {
                Err(RootError::NotDir)
            }
        }
        Err(e) => Err(e.into()),
    }
}

impl ReceiveRoot {
    /// Проверяет и подготавливает папку приёма. Корень должен быть абсолютным и существовать;
    /// ссылки в нём самом разрешаются один раз (`canonicalize`).
    pub fn open(cfg: &ReceiveConfig) -> Result<Self, RootError> {
        if !cfg.root.is_absolute() {
            return Err(RootError::NotAbsolute);
        }
        let root = fs::canonicalize(&cfg.root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(RootError::NotDir);
        }
        let partial = root.join(PARTIAL_NAME);
        ensure_private_dir(&partial)?;
        let journals = partial.join(JOURNAL_NAME);
        ensure_private_dir(&journals)?;
        #[cfg(unix)]
        if !cfg.allow_shared_root {
            check_private_unix(&root, &partial, &journals)?;
        }
        Ok(Self {
            root,
            partial,
            journals,
        })
    }

    /// Канонический корень приёма.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `root/.chervo-partial`: сюда этап 14 кладёт временные файлы.
    pub fn partial_dir(&self) -> &Path {
        &self.partial
    }

    pub(crate) fn journal_dir(&self) -> &Path {
        &self.journals
    }
}

/// Unix: наш uid узнаётся (без `getuid` в std) по владельцу пробного файла, который мы создаём
/// в `.chervo-partial`. Корень принадлежит нам и не доступен на запись другим; служебный
/// каталог и каталог журналов принадлежат нам и закрыты для остальных.
#[cfg(unix)]
fn check_private_unix(root: &Path, partial: &Path, journals: &Path) -> Result<(), RootError> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let probe = partial.join(PROBE_NAME);
    match fs::remove_file(&probe) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let _ = f.flush();
    let uid = f.metadata()?.uid();
    drop(f);
    let _ = fs::remove_file(&probe);

    let rm = fs::metadata(root)?;
    if rm.uid() != uid || rm.mode() & 0o022 != 0 {
        return Err(RootError::Shared);
    }
    for d in [partial, journals] {
        let m = fs::symlink_metadata(d)?;
        if m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(RootError::PartialNotPrivate);
        }
    }
    Ok(())
}
