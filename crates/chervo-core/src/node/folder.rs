//! Раскрытие папок для отправки (этап 18а, A4.1). Собственный код: ссылки не разворачиваются
//! (`symlink_metadata`), имена относительные через `/`, глубина не больше предела приёма, файлов
//! не больше `MAX_FILES_PER_OFFER`. Имя не UTF-8 это `BadName(число таких имён)`.
//!
//! Имя в предложении: для файла его имя, для папки `имя папки/относительный путь`. Содержимое
//! папки идёт в порядке имён, чтобы предложение не зависело от порядка обхода ОС.

use std::fs;
use std::path::{Path, PathBuf};

use chervo_transfer::{MAX_FILES_PER_OFFER, MAX_NAME_BYTES, SourceFile, TransferError};

use super::error::NodeError;

/// Ссылки, сокеты, устройства и прочее, кроме обычных файлов и папок, пропускаются.
pub(crate) fn expand(paths: &[PathBuf], max_depth: u16) -> Result<Vec<SourceFile>, NodeError> {
    expand_with(paths, max_depth, MAX_FILES_PER_OFFER as usize)
}

/// `expand` с заданным пределом числа файлов (для проверки предела без десяти тысяч файлов).
pub(crate) fn expand_with(
    paths: &[PathBuf],
    max_depth: u16,
    max_files: usize,
) -> Result<Vec<SourceFile>, NodeError> {
    if paths.is_empty() {
        return Err(NodeError::Transfer(TransferError::BadName));
    }
    let mut out: Vec<SourceFile> = Vec::new();
    let mut bad_names = 0usize;
    for top in paths {
        let Ok(meta) = fs::symlink_metadata(top) else {
            return Err(NodeError::Transfer(TransferError::Io));
        };
        let ft = meta.file_type();
        let Some(top_name) = top.file_name().and_then(|n| n.to_str()) else {
            bad_names = bad_names.saturating_add(1);
            continue;
        };
        if ft.is_symlink() {
            // ссылку на верхнем уровне не отправляем: она может указывать на что угодно
            return Err(NodeError::Transfer(TransferError::BadName));
        }
        if ft.is_file() {
            push(&mut out, top.clone(), top_name.to_owned(), max_files)?;
        } else if ft.is_dir() {
            walk(
                top,
                &[top_name.to_owned()],
                max_depth,
                max_files,
                &mut out,
                &mut bad_names,
            )?;
        } else {
            return Err(NodeError::Transfer(TransferError::BadName));
        }
    }
    if bad_names > 0 {
        return Err(NodeError::BadName(bad_names));
    }
    if out.is_empty() {
        return Err(NodeError::Transfer(TransferError::BadName));
    }
    Ok(out)
}

fn push(
    out: &mut Vec<SourceFile>,
    path: PathBuf,
    name: String,
    max_files: usize,
) -> Result<(), NodeError> {
    if out.len() >= max_files {
        return Err(NodeError::Transfer(TransferError::TooManyFiles));
    }
    out.push(SourceFile { path, name });
    Ok(())
}

fn walk(
    dir: &Path,
    prefix: &[String],
    max_depth: u16,
    max_files: usize,
    out: &mut Vec<SourceFile>,
    bad_names: &mut usize,
) -> Result<(), NodeError> {
    // глубина пути в предложении: компоненты префикса плюс имя файла
    if prefix.len() >= usize::from(max_depth) {
        return Err(NodeError::Transfer(TransferError::BadName));
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return Err(NodeError::Transfer(TransferError::Io));
    };
    let mut entries: Vec<(String, PathBuf, fs::FileType)> = Vec::new();
    for e in rd {
        let Ok(e) = e else {
            return Err(NodeError::Transfer(TransferError::Io));
        };
        let Ok(ft) = e.file_type() else {
            return Err(NodeError::Transfer(TransferError::Io));
        };
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            *bad_names = bad_names.saturating_add(1);
            continue;
        };
        entries.push((name, e.path(), ft));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, path, ft) in entries {
        if ft.is_symlink() {
            continue;
        }
        if ft.is_file() {
            let full = format!("{}/{}", prefix.join("/"), name);
            if full.len() > MAX_NAME_BYTES {
                *bad_names = bad_names.saturating_add(1);
                continue;
            }
            push(out, path, full, max_files)?;
        } else if ft.is_dir() {
            let mut next = prefix.to_vec();
            next.push(name);
            walk(&path, &next, max_depth, max_files, out, bad_names)?;
        }
    }
    Ok(())
}
