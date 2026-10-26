//! Каталог данных и единственный экземпляр (этап 18а, A1.1 и A1.2).
//!
//! Каталог считается собственным кодом из переменных окружения, без нового пакета. Единственный
//! экземпляр: `File::try_lock` на `<каталог>/instance.lock`. Замок на пользователя (каталог
//! данных свой у каждого пользователя), ОС снимает его при любом завершении процесса, поэтому
//! файла с номером процесса, который мог бы устареть, нет.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use super::error::NodeError;

const LOCK_NAME: &str = "instance.lock";

/// Операционные системы, для которых известен свой путь (отдельный тип ради проверки всех трёх
/// на любой машине).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Os {
    Windows,
    Mac,
    Linux,
}

impl Os {
    pub(crate) fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Mac
        } else {
            Self::Linux
        }
    }
}

fn absolute_var(get: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    let v = get(name)?;
    if v.is_empty() {
        return None;
    }
    Some(PathBuf::from(v))
}

/// Каталог данных по умолчанию. Значение переменной, которое не абсолютный путь, это
/// `DataDir`, а не молчаливая подмена.
pub(crate) fn default_data_dir(
    os: Os,
    get: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, NodeError> {
    let abs = |name: &str| -> Result<Option<PathBuf>, NodeError> {
        match absolute_var(get, name) {
            None => Ok(None),
            Some(p) if p.is_absolute() => Ok(Some(p)),
            Some(_) => Err(NodeError::DataDir),
        }
    };
    match os {
        Os::Windows => abs("LOCALAPPDATA")?
            .map(|p| p.join("Chervotochina"))
            .ok_or(NodeError::DataDir),
        Os::Mac => abs("HOME")?
            .map(|p| {
                p.join("Library")
                    .join("Application Support")
                    .join("Chervotochina")
            })
            .ok_or(NodeError::DataDir),
        Os::Linux => {
            if let Some(p) = abs("XDG_DATA_HOME")? {
                return Ok(p.join("chervotochina"));
            }
            abs("HOME")?
                .map(|p| p.join(".local").join("share").join("chervotochina"))
                .ok_or(NodeError::DataDir)
        }
    }
}

/// Каталог данных узла: заданный явно (абсолютный) или по умолчанию. Каталог создаётся
/// (Unix: режим 0700).
pub(crate) fn resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf, NodeError> {
    let dir = match explicit {
        Some(p) => {
            if !p.is_absolute() {
                return Err(NodeError::DataDir);
            }
            p.to_path_buf()
        }
        None => default_data_dir(Os::current(), &|n| std::env::var_os(n))?,
    };
    create_private_dir(&dir)?;
    Ok(dir)
}

fn create_private_dir(dir: &Path) -> Result<(), NodeError> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir).map_err(|_| NodeError::DataDir)?;
    if fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
        Ok(())
    } else {
        Err(NodeError::DataDir)
    }
}

/// Замок единственного экземпляра. Держится, пока жив `InstanceLock`; снимается при `Drop` и при
/// любом завершении процесса.
pub(crate) struct InstanceLock {
    _file: File,
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstanceLock(..)")
    }
}

impl InstanceLock {
    pub(crate) fn acquire(dir: &Path) -> Result<Self, NodeError> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let file = opts.open(dir.join(LOCK_NAME)).map_err(|_| NodeError::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(NodeError::AlreadyRunning),
            Err(TryLockError::Error(_)) => Err(NodeError::Io),
        }
    }
}

/// Секунды UTC (для имён копий и поправки часов).
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Имя файла списка друзей в каталоге данных.
pub(crate) fn friends_path(dir: &Path) -> PathBuf {
    dir.join("friends.chfl")
}
