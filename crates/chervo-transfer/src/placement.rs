//! Итоговое имя файла назначает внедряемый `Placement`. Этап 14 даёт только
//! `GeneratedNames` (для тестов и примера: имя без единого недоверенного байта) и
//! `place_no_clobber` (размещение без перезаписи).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::fsio::disk_root;
use crate::hash::FileRoot;
use crate::names::{TransferKey, UntrustedName};
use crate::paths::{remove_file_retry, rename_retry};
use crate::state::state_dir_name;

/// Файл, прошедший проверку корня на диске и ждущий итогового имени.
#[derive(Clone)]
pub struct CompletedFile {
    pub key: TransferKey,
    pub index: u32,
    pub name: UntrustedName,
    pub size: u64,
    pub root: FileRoot,
    temp: PathBuf,
}

impl CompletedFile {
    pub(crate) fn new(
        key: TransferKey,
        index: u32,
        name: UntrustedName,
        size: u64,
        root: FileRoot,
        temp: PathBuf,
    ) -> Self {
        Self {
            key,
            index,
            name,
            size,
            root,
            temp,
        }
    }

    /// Временный файл внутри `partial_dir`. Обязан быть перенесён или скопирован.
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }
}

impl fmt::Debug for CompletedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompletedFile(..)")
    }
}

/// Где оказался файл. `Debug` скрыт.
pub struct Placed {
    pub path: PathBuf,
}

impl fmt::Debug for Placed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Placed(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlaceError {
    /// Размещение отказало (имя занято чужим файлом, нет прав и тому подобное).
    Refused,
    Io(io::ErrorKind),
}

impl fmt::Display for PlaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => f.write_str("placement refused"),
            Self::Io(_) => f.write_str("placement i/o error"),
        }
    }
}

impl std::error::Error for PlaceError {}

pub trait Placement: Send + Sync + 'static {
    /// Вызывается в блокирующем потоке после совпадения корня на диске. Ничего не
    /// перезаписывает; идемпотентно для пары (key, index): если файл уже размещён, вернуть
    /// его место, а не размещать снова.
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError>;
}

/// Только для тестов и примера: итоговое имя `chervo-<hex(key)>-<index>` в `dest_dir`.
#[derive(Clone)]
pub struct GeneratedNames {
    pub dest_dir: PathBuf,
}

impl GeneratedNames {
    fn final_path(&self, f: &CompletedFile) -> PathBuf {
        let dir = state_dir_name(&f.key.pair, &f.key.id);
        self.dest_dir.join(format!("chervo-{dir}-{}", f.index))
    }
}

impl Placement for GeneratedNames {
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        let fin = self.final_path(f);
        // уже размещён раньше (сбой между размещением и записью состояния): тот же корень
        if fs::symlink_metadata(&fin).is_ok() {
            return if disk_root(&fin, f.size).is_ok_and(|r| r == f.root) {
                Ok(Placed { path: fin })
            } else {
                Err(PlaceError::Refused)
            };
        }
        match place_no_clobber(f.temp_path(), &fin) {
            Ok(_) => Ok(Placed { path: fin }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if disk_root(&fin, f.size).is_ok_and(|r| r == f.root) {
                    Ok(Placed { path: fin })
                } else {
                    Err(PlaceError::Refused)
                }
            }
            Err(e) => Err(PlaceError::Io(e.kind())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceMethod {
    HardLink,
    ReserveRename,
}

/// Размещение без перезаписи. Жёсткая ссылка атомарна и при существующем имени даёт
/// `AlreadyExists`; после успешной ссылки результат `Ok(HardLink)` даже если временное имя
/// удалить не удалось (удаление повторяется и остаётся уборкой). Если ссылки не
/// поддерживаются (FAT, часть сетевых дисков), имя
/// резервируется `create_new`, затем `rename` заменяет резерв; на время переименования (и
/// после сбоя в этот миг) под итоговым именем лежит пустой файл. При ошибке временный файл
/// остаётся на месте.
pub fn place_no_clobber(temp: &Path, final_path: &Path) -> io::Result<PlaceMethod> {
    place_no_clobber_with(temp, final_path, false)
}

pub(crate) fn place_no_clobber_with(
    temp: &Path,
    final_path: &Path,
    force_fallback: bool,
) -> io::Result<PlaceMethod> {
    place_impl(temp, final_path, force_fallback, &remove_file_retry)
}

/// То же с подменяемым удалением временного файла (проверка отказа удаления в тестах).
pub(crate) fn place_impl(
    temp: &Path,
    final_path: &Path,
    force_fallback: bool,
    remove: &dyn Fn(&Path) -> io::Result<()>,
) -> io::Result<PlaceMethod> {
    if !force_fallback {
        match fs::hard_link(temp, final_path) {
            Ok(()) => {
                // Файл уже размещён: итог успех. Временное имя теперь второе имя того же файла,
                // его удаление лишь уборка (с повторами на Windows). Если убрать не удалось,
                // получатель не пишет в такой файл (см. `paths::remove_part_strict`).
                let _ = remove(temp);
                sync_parent(final_path);
                return Ok(PlaceMethod::HardLink);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(e),
            Err(e) if e.kind() == io::ErrorKind::NotFound && !temp.exists() => return Err(e),
            Err(_) => {}
        }
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(final_path)?;
    if let Err(e) = rename_retry(temp, final_path) {
        let _ = remove_file_retry(final_path);
        return Err(e);
    }
    sync_parent(final_path);
    Ok(PlaceMethod::ReserveRename)
}

/// Unix: синхронизация каталога (по возможности). Windows: журнал NTFS, отдельного шага нет.
fn sync_parent(final_path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = final_path.parent()
        && let Ok(d) = fs::File::open(parent)
    {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = final_path;
}

impl fmt::Debug for GeneratedNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GeneratedNames(..)")
    }
}
