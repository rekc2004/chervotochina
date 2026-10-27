//! Выбор файлов и папок системным диалогом (`rfd`) и сведения о выбранном пути. Только выбор и
//! чтение сведений: GUI сам ничего не создаёт и не записывает. На Linux диалог идёт через
//! портал рабочего стола (без установки пакетов); если портала нет, диалог ничего не вернёт, а
//! файлы можно перетащить в окно.

use std::path::PathBuf;

use crate::rows::PickedPath;

/// Сведения о пути без обхода папки. Ссылки (symlink) не берём: узел их не разворачивает.
pub fn describe(path: PathBuf) -> Option<PickedPath> {
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    if meta.is_dir() {
        Some(PickedPath {
            path,
            is_dir: true,
            size: 0,
        })
    } else if meta.is_file() {
        Some(PickedPath {
            path,
            is_dir: false,
            size: meta.len(),
        })
    } else {
        None
    }
}

pub fn pick_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_folder()
}

pub fn pick_files() -> Vec<PickedPath> {
    rfd::FileDialog::new()
        .pick_files()
        .unwrap_or_default()
        .into_iter()
        .filter_map(describe)
        .collect()
}

pub fn pick_dir_to_send() -> Option<PickedPath> {
    pick_folder().and_then(describe)
}
