//! План предложения (спецификация 15, решение 6): все имена предложения санитизируются,
//! затем расставляются по дереву так, чтобы внутри каждого каталога не было двух имён с
//! одинаковым `fold`. Чистая функция: файловой системы нет.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use chervo_transfer::OfferedFile;

use crate::classify::{FileClass, TypeInfo, classify};
use crate::limits::{PathError, ReceiveLimits};
use crate::name::{NameFlags, SafeRelPath, cut, fold, sanitize_path, split_ext};

/// Запас под ` (k)` с `k` до десяти цифр при усечении основы имени.
const SUFFIX_RESERVE: usize = 14;
/// Предел длины пути Win32 без завершающего NUL: больше этого нужны длинные пути.
const WIN_PATH_LIMIT: usize = 259;

pub struct PlannedFile {
    pub index: u32,
    pub path: SafeRelPath,
    pub flags: NameFlags,
    pub kind: TypeInfo,
    pub size: u64,
}

impl fmt::Debug for PlannedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedFile")
            .field("index", &self.index)
            .field("flags", &self.flags)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

pub struct OfferPlan {
    pub files: Vec<PlannedFile>,
    pub max_class: FileClass,
    pub any_deceptive: bool,
    pub total: u64,
}

impl fmt::Debug for OfferPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferPlan")
            .field("files", &self.files.len())
            .field("max_class", &self.max_class)
            .field("any_deceptive", &self.any_deceptive)
            .field("total", &self.total)
            .finish()
    }
}

impl OfferPlan {
    /// Все файлы обычные и ни один флаг имени не поднят.
    pub fn auto_ok(&self) -> bool {
        self.files.iter().all(|f| {
            f.kind.class == FileClass::Ordinary
                && !f.kind.deceptive
                && f.flags == NameFlags::default()
        })
    }
}

#[derive(Default)]
struct Entry {
    name: String,
    is_dir: bool,
    dir: Dir,
}

#[derive(Default)]
struct Dir {
    /// `fold(итоговое имя)` -> запись.
    entries: HashMap<String, Entry>,
    /// `fold(исходное имя каталога)` -> ключ в `entries` каталога, который его заменил.
    alias: HashMap<String, String>,
    /// Семейство (`fold(основа)`, `fold(расширение)`) -> следующее `k`.
    counters: HashMap<String, u32>,
}

impl Dir {
    /// Следующее свободное имя `основа (k)расширение`, `k` от 2. Счётчик общий для
    /// семейства, поэтому весь план линеен по числу имён.
    fn unique_name(
        &mut self,
        name: &str,
        is_file: bool,
        max_name: usize,
    ) -> Result<(String, String), PathError> {
        let (stem, ext) = if is_file { split_ext(name) } else { (name, "") };
        let budget = max_name
            .checked_sub(ext.len() + SUFFIX_RESERVE)
            .filter(|b| *b > 0)
            .ok_or(PathError::TooLong)?;
        let base = match cut(stem, budget) {
            "" => "_",
            b => b,
        };
        let family = format!("{}\0{}", fold(base), fold(ext));
        let mut k = self.counters.get(&family).copied().unwrap_or(2);
        loop {
            let cand = format!("{base} ({k}){ext}");
            let key = fold(&cand);
            k = k.checked_add(1).ok_or(PathError::TooManyFiles)?;
            if !self.entries.contains_key(&key) {
                self.counters.insert(family, k);
                return Ok((cand, key));
            }
        }
    }
}

/// Расставляет компоненты одного файла по дереву, возвращает итоговые имена.
fn place_in_tree(
    root: &mut Dir,
    comps: &[String],
    max_name: usize,
    flags: &mut NameFlags,
) -> Result<Vec<String>, PathError> {
    let n = comps.len();
    let mut out = Vec::with_capacity(n);
    let mut cur = root;
    for (i, c) in comps.iter().enumerate() {
        let key = fold(c);
        if i + 1 < n {
            let target = match (
                cur.alias.get(&key).cloned(),
                cur.entries.get(&key).map(|e| e.is_dir),
            ) {
                (Some(t), _) => t,
                (None, Some(false)) => {
                    // Каталог совпал по `fold` с файлом: берём свободное имя.
                    let (name, ck) = cur.unique_name(c, false, max_name)?;
                    cur.entries.insert(
                        ck.clone(),
                        Entry {
                            name,
                            is_dir: true,
                            dir: Dir::default(),
                        },
                    );
                    cur.alias.insert(key, ck.clone());
                    ck
                }
                (None, Some(true)) => key,
                (None, None) => {
                    cur.entries.insert(
                        key.clone(),
                        Entry {
                            name: c.clone(),
                            is_dir: true,
                            dir: Dir::default(),
                        },
                    );
                    key
                }
            };
            let e = cur.entries.entry(target).or_default();
            if e.name != *c {
                flags.changed = true;
                flags.renamed_in_offer = true;
            }
            out.push(e.name.clone());
            cur = &mut e.dir;
        } else {
            let (name, ck) = if cur.entries.contains_key(&key) {
                flags.changed = true;
                flags.renamed_in_offer = true;
                cur.unique_name(c, true, max_name)?
            } else {
                (c.clone(), key)
            };
            cur.entries.insert(
                ck,
                Entry {
                    name: name.clone(),
                    is_dir: false,
                    dir: Dir::default(),
                },
            );
            out.push(name);
        }
    }
    Ok(out)
}

/// Длина полного пути в единицах UTF-16 (без префикса `\\?\`).
fn win32_len(root: &Path, comps: &[String]) -> usize {
    let r = root.to_string_lossy();
    let mut n = r.trim_end_matches('\\').encode_utf16().count();
    if r.starts_with("\\\\?\\UNC\\") {
        n = n.saturating_sub(6);
    } else if r.starts_with("\\\\?\\") {
        n = n.saturating_sub(4);
    }
    comps
        .iter()
        .fold(n, |acc, c| acc + 1 + c.encode_utf16().count())
}

fn build_plan(
    files: &[OfferedFile],
    l: &ReceiveLimits,
    root: Option<&Path>,
) -> Result<OfferPlan, PathError> {
    l.validate()?;
    if files.len() > usize::try_from(l.max_files).map_err(|_| PathError::TooManyFiles)? {
        return Err(PathError::TooManyFiles);
    }
    let total = files
        .iter()
        .try_fold(0u64, |acc, f| acc.checked_add(f.size))
        .ok_or(PathError::TooLarge)?;
    if total > l.max_total_bytes {
        return Err(PathError::TooLarge);
    }
    let max_name = usize::from(l.max_name_bytes);
    let mut tree = Dir::default();
    let mut planned = Vec::with_capacity(files.len());
    let mut max_class = FileClass::Ordinary;
    let mut any_deceptive = false;
    for (i, f) in files.iter().enumerate() {
        let (path, mut flags) = sanitize_path(f.name.untrusted_str(), l)?;
        let comps = place_in_tree(&mut tree, path.components(), max_name, &mut flags)?;
        if let Some(root) = root
            && cfg!(windows)
            && win32_len(root, &comps) > WIN_PATH_LIMIT
        {
            flags.long_path = true;
        }
        let path = SafeRelPath::from_parts(comps);
        let kind = classify(&path);
        max_class = max_class.max(kind.class);
        any_deceptive |= kind.deceptive;
        planned.push(PlannedFile {
            index: u32::try_from(i).map_err(|_| PathError::TooManyFiles)?,
            path,
            flags,
            kind,
            size: f.size,
        });
    }
    Ok(OfferPlan {
        files: planned,
        max_class,
        any_deceptive,
        total,
    })
}

/// План без привязки к папке приёма (сторона отправителя и тесты).
pub fn plan_offer(files: &[OfferedFile], l: &ReceiveLimits) -> Result<OfferPlan, PathError> {
    build_plan(files, l, None)
}

/// План с проверкой длины пути под папку `root` (на Windows поднимает `long_path`).
/// `plan_offer_for_root` (этап R2) вызывает эту функцию с корнем приёма.
pub fn plan_offer_in(
    files: &[OfferedFile],
    l: &ReceiveLimits,
    root: &Path,
) -> Result<OfferPlan, PathError> {
    build_plan(files, l, Some(root))
}
