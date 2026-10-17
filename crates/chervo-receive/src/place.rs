//! Размещение принятых файлов (спецификация 15, решения 7, 8, 10, 13). Единственное место
//! (вместе с `root.rs` и `journal.rs`), где строятся пути внутри папки приёма.
//!
//! Правила: каталоги верхнего уровня предложения всегда новые (`create_dir`, при занятом
//! имени `имя (2)`, ...); внутри своего дерева существующий настоящий каталог переиспользуется,
//! любая ссылка или файл на его месте это отказ. Файл ставится `place_no_clobber`
//! (жёсткая ссылка либо `create_new` и переименование), занятое имя (в том числе висячая ссылка)
//! даёт `AlreadyExists` и следующее имя. До и после размещения проверяется вся цепочка
//! каталогов через `symlink_metadata`. Остаток, который не закрыт: локальный процесс с правом
//! записи в папку приёма может подменить каталог между проверкой и ссылкой (решение 8).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chervo_transfer::{
    CompletedFile, FileRoot, OfferedFile, PlaceError, Placed, Placement, TransferKey,
    UntrustedName, block_len, file_root, layout, leaf_hash, place_no_clobber, state_dir_name,
};

use crate::journal::{
    MAX_K, PlacedLog, plan_digest, read_dirs, remove_journals, sweep, write_dirs,
};
use crate::limits::ReceiveLimits;
use crate::mark::mark_origin;
use crate::name::{cut, split_ext};
use crate::plan::{OfferPlan, plan_offer_for_root};
use crate::root::{ReceiveConfig, ReceiveRoot, private_dir_builder};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Точки, в которых тест вмешивается в размещение (только для тестов крейта и его потребителей).
#[doc(hidden)]
pub enum TestPoint<'a> {
    /// Перед записью метки происхождения; `Err` считается ошибкой метки (она игнорируется).
    BeforeMark,
    /// После проверки цепочки каталогов, непосредственно перед жёсткой ссылкой.
    BeforeLink { dir: &'a Path },
}

type TestHook = dyn Fn(TestPoint<'_>) -> io::Result<()> + Send + Sync;

/// План одной принятой передачи в памяти.
struct SessionPlan {
    hex: String,
    plan: OfferPlan,
    names: Vec<UntrustedName>,
    /// Имя каталога верхнего уровня в плане -> выбранное `k` (1: имя как есть).
    tops: HashMap<String, u16>,
    log: Mutex<PlacedLog>,
    /// Создание каталогов этой передачи идёт по одному (писатели разных файлов параллельны).
    dir_lock: Mutex<()>,
}

pub struct ReceivePlacement {
    root: ReceiveRoot,
    limits: ReceiveLimits,
    motw: bool,
    quarantine: bool,
    sessions: Mutex<HashMap<TransferKey, Arc<SessionPlan>>>,
    hook: Mutex<Option<Arc<TestHook>>>,
    full_reads: AtomicU64,
}

impl std::fmt::Debug for ReceivePlacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceivePlacement(..)")
    }
}

/// Имя-кандидат номер `k`: 1 это само имя, иначе `основа (k)расширение` (файл) или
/// `имя (k)` (каталог); основа усекается, чтобы результат уложился в `max` байт.
fn candidate_name(name: &str, k: u16, is_file: bool, max: usize) -> String {
    if k <= 1 {
        return name.to_owned();
    }
    let (stem, ext) = if is_file { split_ext(name) } else { (name, "") };
    let suffix = format!(" ({k})");
    let budget = max.saturating_sub(ext.len() + suffix.len());
    format!("{}{suffix}{ext}", cut(stem, budget))
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| {
        let t = m.file_type();
        t.is_dir() && !t.is_symlink()
    })
}

/// Добавляет ровно один обычный компонент (не `..`, не диск, не абсолютный).
fn safe_push(p: &mut PathBuf, c: &str) -> Result<(), PlaceError> {
    let mut it = Path::new(c).components();
    match (it.next(), it.next()) {
        (Some(Component::Normal(_)), None) => {
            p.push(c);
            Ok(())
        }
        _ => Err(PlaceError::Refused),
    }
}

fn make_dir(p: &Path) -> io::Result<()> {
    private_dir_builder().create(p)
}

fn io_err(e: &io::Error) -> PlaceError {
    PlaceError::Io(e.kind())
}

/// Корень файла на диске (раскладка и хэши этапа 14).
fn disk_root(p: &Path, size: u64) -> io::Result<FileRoot> {
    let l = layout(size).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut f = File::open(p)?;
    let mut leaves = Vec::new();
    let mut buf = Vec::new();
    for i in 0..l.block_count {
        let len = block_len(size, l, i).ok_or(io::ErrorKind::InvalidData)?;
        buf.resize(
            usize::try_from(len).map_err(|_| io::ErrorKind::InvalidData)?,
            0,
        );
        f.read_exact(&mut buf)?;
        leaves.push(leaf_hash(i, &buf));
    }
    file_root(size, l, &leaves).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// Тот же файл, что мы поставили (Unix: устройство и номер; иначе длина).
fn same_file(before: &fs::Metadata, now: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == now.dev() && before.ino() == now.ino()
    }
    #[cfg(not(unix))]
    {
        before.len() == now.len()
    }
}

/// Имена каталогов верхнего уровня плана в порядке появления.
fn top_names(plan: &OfferPlan) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for f in &plan.files {
        let comps = f.path.components();
        if comps.len() >= 2
            && let Some(first) = comps.first()
            && seen.insert(first.as_str())
        {
            out.push(first.clone());
        }
    }
    out
}

impl ReceivePlacement {
    /// Убирает журналы без настоящего каталога сеанса (остатки отменённых передач).
    pub fn new(root: ReceiveRoot, cfg: &ReceiveConfig) -> Self {
        sweep(root.journal_dir(), root.partial_dir());
        let limits = if cfg.limits.validate().is_ok() {
            cfg.limits
        } else {
            ReceiveLimits::default()
        };
        Self {
            root,
            limits,
            motw: cfg.mark_of_the_web,
            quarantine: cfg.quarantine,
            sessions: Mutex::new(HashMap::new()),
            hook: Mutex::new(None),
            full_reads: AtomicU64::new(0),
        }
    }

    /// Подмена точек размещения для тестов.
    #[doc(hidden)]
    pub fn set_test_hook(&self, h: Arc<TestHook>) {
        *lock(&self.hook) = Some(h);
    }

    /// Сколько раз файл целиком перечитывался при повторе размещения.
    #[doc(hidden)]
    pub fn full_reads(&self) -> u64 {
        self.full_reads.load(Ordering::SeqCst)
    }

    fn at(&self, p: TestPoint<'_>) -> io::Result<()> {
        let h = lock(&self.hook).clone();
        match h {
            Some(h) => h(p),
            None => Ok(()),
        }
    }

    fn max_name(&self) -> usize {
        usize::from(self.limits.max_name_bytes)
    }

    /// Создаёт новые каталоги верхнего уровня; возвращает выбранные `k`. При ошибке созданные
    /// здесь пустые каталоги убираются.
    fn create_top_dirs(&self, names: &[String]) -> Result<Vec<u16>, PlaceError> {
        let root = self.root.root();
        if !is_real_dir(root) {
            return Err(PlaceError::Refused);
        }
        let mut made: Vec<PathBuf> = Vec::new();
        let mut ks = Vec::with_capacity(names.len());
        let res = (|| -> Result<(), PlaceError> {
            for name in names {
                let mut chosen = None;
                for k in 1..=MAX_K {
                    let mut p = root.to_path_buf();
                    safe_push(&mut p, &candidate_name(name, k, false, self.max_name()))?;
                    match make_dir(&p) {
                        Ok(()) => {
                            made.push(p);
                            chosen = Some(k);
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(io_err(&e)),
                    }
                }
                ks.push(chosen.ok_or(PlaceError::Refused)?);
            }
            Ok(())
        })();
        if let Err(e) = res {
            for p in made.iter().rev() {
                if is_real_dir(p) {
                    let _ = fs::remove_dir(p);
                }
            }
            return Err(e);
        }
        Ok(ks)
    }

    fn session(&self, key: &TransferKey) -> Option<Arc<SessionPlan>> {
        lock(&self.sessions).get(key).cloned()
    }

    /// Цепочка каталогов от корня вниз без создания: каждый обязан быть настоящим каталогом.
    fn walk_check(&self, dirs: &[String]) -> Result<PathBuf, PlaceError> {
        let mut p = self.root.root().to_path_buf();
        if !is_real_dir(&p) {
            return Err(PlaceError::Refused);
        }
        for d in dirs {
            safe_push(&mut p, d)?;
            if !is_real_dir(&p) {
                return Err(PlaceError::Refused);
            }
        }
        Ok(p)
    }

    /// То же с созданием недостающих каталогов (Unix: 0o700) и повторной проверкой каждого.
    /// Каталог верхнего уровня создаётся только нами (`create_dir`): если он появился
    /// между проверкой и созданием, это отказ. Ниже существующий настоящий каталог наш.
    fn walk_create(&self, dirs: &[String]) -> Result<PathBuf, PlaceError> {
        let mut p = self.root.root().to_path_buf();
        if !is_real_dir(&p) {
            return Err(PlaceError::Refused);
        }
        for (i, d) in dirs.iter().enumerate() {
            safe_push(&mut p, d)?;
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => return Err(PlaceError::Refused),
                Err(e) if e.kind() == io::ErrorKind::NotFound => match make_dir(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && i > 0 => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(PlaceError::Refused);
                    }
                    Err(e) => return Err(io_err(&e)),
                },
                Err(e) => return Err(io_err(&e)),
            }
            if !is_real_dir(&p) {
                return Err(PlaceError::Refused);
            }
        }
        Ok(p)
    }

    /// Проверка после размещения: цепочка, обычный файл, настоящий путь внутри корня.
    fn verify_placed(&self, dirs: &[String], cand: &Path) -> bool {
        let Ok(dir) = self.walk_check(dirs) else {
            return false;
        };
        if cand.parent() != Some(dir.as_path()) {
            return false;
        }
        if !fs::symlink_metadata(cand).is_ok_and(|m| m.file_type().is_file()) {
            return false;
        }
        fs::canonicalize(&dir).is_ok_and(|c| c.starts_with(self.root.root()))
    }

    /// Повтор после краха: файл из последней записи журнала уже стоит на месте.
    fn replay(
        &self,
        dirs: &[String],
        file_name: &str,
        k: u16,
        f: &CompletedFile,
    ) -> Option<PathBuf> {
        let dir = self.walk_check(dirs).ok()?;
        let mut cand = dir;
        safe_push(
            &mut cand,
            &candidate_name(file_name, k, true, self.max_name()),
        )
        .ok()?;
        let m = fs::symlink_metadata(&cand).ok()?;
        if !m.file_type().is_file() || m.len() != f.size {
            return None;
        }
        self.full_reads.fetch_add(1, Ordering::SeqCst);
        if disk_root(&cand, f.size).ok()? != f.root {
            return None;
        }
        self.verify_placed(dirs, &cand).then_some(cand)
    }
}

impl Placement for ReceivePlacement {
    fn prepare(&self, key: &TransferKey, files: &[OfferedFile]) -> Result<(), PlaceError> {
        if lock(&self.sessions).contains_key(key) {
            return Ok(());
        }
        let plan = plan_offer_for_root(files, &self.limits, &self.root)
            .map_err(|_| PlaceError::Refused)?;
        let tops = top_names(&plan);
        let hex = state_dir_name(&key.pair, &key.id);
        let refs: Vec<&str> = tops.iter().map(String::as_str).collect();
        let digest = plan_digest(&refs);
        let journals = self.root.journal_dir();
        // журнал размещения открывается первым: его отказ не оставляет созданных каталогов
        let log = PlacedLog::open(journals, &hex).map_err(|e| io_err(&e))?;
        let ks = match read_dirs(journals, &hex, key, &digest, tops.len()) {
            // каталоги созданы в прошлой жизни процесса; негодный журнал не доверяется
            Some(ks) => ks,
            None => {
                let ks = self.create_top_dirs(&tops)?;
                if !ks.is_empty()
                    && let Err(e) = write_dirs(journals, &hex, key, &digest, &ks)
                {
                    for (name, k) in tops.iter().zip(&ks).rev() {
                        let mut p = self.root.root().to_path_buf();
                        if safe_push(&mut p, &candidate_name(name, *k, false, self.max_name()))
                            .is_ok()
                            && is_real_dir(&p)
                        {
                            let _ = fs::remove_dir(&p);
                        }
                    }
                    return Err(io_err(&e));
                }
                ks
            }
        };
        let sess = Arc::new(SessionPlan {
            hex,
            plan,
            names: files.iter().map(|f| f.name.clone()).collect(),
            tops: tops.into_iter().zip(ks).collect(),
            log: Mutex::new(log),
            dir_lock: Mutex::new(()),
        });
        lock(&self.sessions).insert(*key, sess);
        Ok(())
    }

    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        let temp = f.temp_path();
        if !temp.starts_with(self.root.partial_dir())
            || temp.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err(PlaceError::Refused);
        }
        let sess = self.session(&f.key).ok_or(PlaceError::Refused)?;
        let idx = usize::try_from(f.index).map_err(|_| PlaceError::Refused)?;
        let planned = sess.plan.files.get(idx).ok_or(PlaceError::Refused)?;
        let offered = sess.names.get(idx).ok_or(PlaceError::Refused)?;
        if *offered != f.name || planned.size != f.size {
            return Err(PlaceError::Refused);
        }
        let comps = planned.path.components();
        let (file_name, dir_comps) = comps.split_last().ok_or(PlaceError::Refused)?;
        let mut dirs: Vec<String> = Vec::with_capacity(dir_comps.len());
        for (i, c) in dir_comps.iter().enumerate() {
            if i == 0 {
                let k = *sess.tops.get(c).ok_or(PlaceError::Refused)?;
                dirs.push(candidate_name(c, k, false, self.max_name()));
            } else {
                dirs.push(c.clone());
            }
        }

        // повтор после краха: файл уже поставлен прошлой жизнью процесса
        let prior = lock(&sess.log).last(f.index);
        if let Some(k) = prior
            && let Some(path) = self.replay(&dirs, file_name, k, f)
        {
            return Ok(Placed { path });
        }

        // временный файл: обычный файл нужной длины внутри служебного каталога
        let tmeta = fs::symlink_metadata(temp).map_err(|e| io_err(&e))?;
        if !tmeta.file_type().is_file() || tmeta.len() != f.size {
            return Err(PlaceError::Refused);
        }
        // метка происхождения до ссылки; ошибка метки не мешает размещению
        if self.at(TestPoint::BeforeMark).is_ok() {
            mark_origin(temp, self.motw, self.quarantine);
        }

        let dir = {
            let _g = lock(&sess.dir_lock);
            self.walk_create(&dirs)?
        };
        for k in 1..=MAX_K {
            lock(&sess.log).append(f.index, k).map_err(|e| io_err(&e))?;
            let mut cand = dir.clone();
            safe_push(
                &mut cand,
                &candidate_name(file_name, k, true, self.max_name()),
            )?;
            self.at(TestPoint::BeforeLink { dir: &dir })
                .map_err(|e| io_err(&e))?;
            match place_no_clobber(temp, &cand) {
                Ok(_) => {
                    if self.verify_placed(&dirs, &cand) {
                        return Ok(Placed { path: cand });
                    }
                    // подмена каталога: убираем только тот файл, который сами поставили
                    if let Ok(m) = fs::symlink_metadata(&cand)
                        && m.file_type().is_file()
                        && same_file(&tmeta, &m)
                    {
                        let _ = fs::remove_file(&cand);
                    }
                    return Err(PlaceError::Refused);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_err(&e)),
            }
        }
        Err(PlaceError::Refused)
    }

    fn forget(&self, key: &TransferKey) {
        let sess = lock(&self.sessions).remove(key);
        let hex = match &sess {
            Some(s) => s.hex.clone(),
            None => state_dir_name(&key.pair, &key.id),
        };
        if let Some(s) = sess {
            // пустые каталоги этой передачи (отмена до размещения): снизу вверх, только пустые
            let mut dirs: HashSet<Vec<String>> = HashSet::new();
            for pf in &s.plan.files {
                let comps = pf.path.components();
                let n = comps.len().saturating_sub(1);
                let mut resolved: Vec<String> = Vec::with_capacity(n);
                for (i, c) in comps.iter().take(n).enumerate() {
                    if i == 0 {
                        let Some(k) = s.tops.get(c) else { break };
                        resolved.push(candidate_name(c, *k, false, self.max_name()));
                    } else {
                        resolved.push(c.clone());
                    }
                    dirs.insert(resolved.clone());
                }
            }
            let mut dirs: Vec<Vec<String>> = dirs.into_iter().collect();
            dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
            drop(s);
            for d in dirs {
                let mut p = self.root.root().to_path_buf();
                if d.iter().all(|c| safe_push(&mut p, c).is_ok()) && is_real_dir(&p) {
                    let _ = fs::remove_dir(&p);
                }
            }
        }
        remove_journals(self.root.journal_dir(), &hex);
    }
}
