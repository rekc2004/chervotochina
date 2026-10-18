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
    CompletedFile, FileRoot, OfferView, OfferedFile, PlaceError, Placed, Placement, TransferKey,
    UntrustedName, block_len, file_root, layout, leaf_hash, place_no_clobber, state_dir_name,
};

use crate::journal::{
    MAX_K, PlacedLog, plan_digest, read_dirs, remove_journals, sweep, write_dirs,
};
use crate::limits::{PathError, ReceiveLimits};
use crate::mark::mark_origin;
use crate::name::{cut, split_ext};
use crate::plan::{OfferPlan, plan_offer_for_root, suffix_budget};
use crate::root::{ReceiveConfig, ReceiveRoot, private_dir_builder};
use crate::space::{SpaceCheck, SpaceProbe, SpaceShortfall, check_space, disk_space};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Точки, в которых тест вмешивается в размещение (только для тестов крейта и его потребителей).
#[doc(hidden)]
// без свойства `fuzzing` хук не устанавливается, поля читает только он (S1 L6)
#[cfg_attr(not(any(test, feature = "fuzzing")), allow(dead_code))]
pub enum TestPoint<'a> {
    /// Перед записью метки происхождения; `Err` считается ошибкой метки (она игнорируется).
    BeforeMark,
    /// После проверки цепочки каталогов, непосредственно перед жёсткой ссылкой.
    BeforeLink { dir: &'a Path },
    /// Сразу после успешной жёсткой ссылки, до итоговой проверки; результат не учитывается.
    AfterLink { dir: &'a Path },
}

type TestHook = dyn Fn(TestPoint<'_>) -> io::Result<()> + Send + Sync;

/// План одной принятой передачи в памяти.
struct SessionPlan {
    /// Папка приёма этой передачи (основная или выбранная для этого предложения, Рев. 5).
    root: ReceiveRoot,
    hex: String,
    plan: OfferPlan,
    names: Vec<UntrustedName>,
    /// Имя каталога верхнего уровня в плане -> выбранное `k` (1: имя как есть).
    /// Идентичность папки (inode / время создания) обновляется, если папку пришлось создать
    /// заново; меняется только под `dir_lock`.
    tops: HashMap<String, (u16, AtomicU64)>,
    log: Mutex<PlacedLog>,
    /// Создание каталогов этой передачи идёт по одному (писатели разных файлов параллельны).
    dir_lock: Mutex<()>,
}

pub struct ReceivePlacement {
    root: ReceiveRoot,
    /// Другие известные папки приёма: выбранные для отдельных предложений и заданные при
    /// запуске (чтобы найти недокачанные передачи после перезапуска).
    known: Mutex<Vec<ReceiveRoot>>,
    /// Папка, выбранная для ещё не принятого предложения.
    choices: Mutex<HashMap<TransferKey, ReceiveRoot>>,
    limits: ReceiveLimits,
    min_free_percent: u8,
    probe: Arc<SpaceProbe>,
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

/// Почему другая папка не подошла (`ReceivePlacement::choose_root`). `Debug` без путей.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChooseRootError {
    /// Имена предложения не годятся (не должно случаться: то же предложение уже прошло план).
    Plan(PathError),
    /// На томе новой папки не хватает места (за вычетом остальных приёмов и запаса).
    Insufficient(SpaceShortfall),
}

/// Имя-кандидат номер `k`: 1 это само имя, иначе `основа (k)расширение` (файл) или
/// `имя (k)` (каталог); основа усекается, чтобы результат уложился в `max` байт.
fn candidate_name(name: &str, k: u16, is_file: bool, max: usize) -> Result<String, PlaceError> {
    if k <= 1 {
        return Ok(name.to_owned());
    }
    let (stem, ext) = if is_file { split_ext(name) } else { (name, "") };
    let suffix = format!(" ({k})");
    // Рев. 3, F7: та же проверка запаса, что в плане: основе должен остаться хотя бы байт,
    // иначе имя вышло бы за предел.
    let budget = suffix_budget(max, ext.len(), suffix.len()).ok_or(PlaceError::Refused)?;
    let stem = match cut(stem, budget) {
        "" => "_",
        s => s,
    };
    Ok(format!("{stem}{suffix}{ext}"))
}

/// Идентичность папки, которую мы создали: Unix номер inode, Windows время создания (Рев. 3,
/// F5). На прочих ОС 0 (сверка тогда ничего не проверяет).
fn dir_ident(m: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.creation_time()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = m;
        0
    }
}

/// Идентичность настоящего каталога по пути (не ссылка); иначе `None`.
fn real_dir_ident(p: &Path) -> Option<u64> {
    let m = fs::symlink_metadata(p).ok()?;
    let t = m.file_type();
    (t.is_dir() && !t.is_symlink()).then(|| dir_ident(&m))
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

/// Тот же файл, что мы поставили (устройство и номер inode). Только Unix: на Windows надёжного
/// признака в std нет, поэтому там неудавшуюся проверку НЕ чистим удалением (Рев. 3, F1:
/// подставной исполнитель мог подменить папку ссылкой на чужой файл той же длины).
#[cfg(unix)]
fn same_file(before: &fs::Metadata, now: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == now.dev() && before.ino() == now.ino()
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
            known: Mutex::new(Vec::new()),
            choices: Mutex::new(HashMap::new()),
            limits,
            min_free_percent: cfg.min_free_percent,
            probe: Arc::new(disk_space),
            motw: cfg.mark_of_the_web,
            quarantine: cfg.quarantine,
            sessions: Mutex::new(HashMap::new()),
            hook: Mutex::new(None),
            full_reads: AtomicU64::new(0),
        }
    }

    /// Свой способ узнать свободное место при выборе другой папки (тесты).
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn with_space_probe(mut self, probe: Arc<SpaceProbe>) -> Self {
        self.probe = probe;
        self
    }

    /// Запоминает ещё одну папку приёма. Вызывать при запуске для всех папок, куда прежде
    /// принимались отдельные предложения (список хранит приложение): иначе недокачанные там
    /// передачи не найдутся после перезапуска (их данные остаются в `.chervo-partial` этой
    /// папки). Папка выбранная через `choose_root` запоминается сама, до перезапуска.
    pub fn add_known_root(&self, root: ReceiveRoot) {
        if root.root() == self.root.root() {
            return;
        }
        let mut known = lock(&self.known);
        if known.iter().any(|r| r.root() == root.root()) {
            return;
        }
        sweep(root.journal_dir(), root.partial_dir());
        known.push(root);
    }

    /// Принять это предложение в другую папку приёма (Рев. 5, решение владельца 2026-10-18).
    /// `offer` берётся из `Transfers::offer` (в нём резерв места остальных передач). Предложение
    /// заново планируется под новую папку (тот же санитайзер), место проверяется на её томе с
    /// тем же запасом `min_free_percent`; не хватает: `Insufficient` с обоими числами. Успех
    /// запоминает выбор: временные файлы передачи и итоговые файлы лягут в новую папку (одна
    /// `.chervo-partial` на одном томе), после чего вызывается `Transfers::respond(key, true)`.
    /// Если место узнать нельзя, выбор пользователя сохраняется.
    pub fn choose_root(&self, offer: &OfferView, root: ReceiveRoot) -> Result<(), ChooseRootError> {
        let plan = plan_offer_for_root(&offer.files, &self.limits, &root)
            .map_err(ChooseRootError::Plan)?;
        if let SpaceCheck::Short(s) = check_space(
            &*self.probe,
            root.root(),
            plan.total,
            self.min_free_percent,
            &offer.inbound,
        ) {
            return Err(ChooseRootError::Insufficient(s));
        }
        self.add_known_root(root.clone());
        lock(&self.choices).insert(offer.key, root);
        Ok(())
    }

    /// Снимает выбор папки для предложения (пользователь передумал или отказал).
    pub fn unchoose_root(&self, key: &TransferKey) {
        lock(&self.choices).remove(key);
    }

    /// Папка этой передачи: выбранная для предложения, иначе та, где лежит её каталог
    /// временных данных (после перезапуска), иначе основная.
    fn root_for(&self, key: &TransferKey) -> ReceiveRoot {
        if let Some(r) = lock(&self.choices).get(key) {
            return r.clone();
        }
        let hex = state_dir_name(&key.pair, &key.id);
        let known = lock(&self.known).clone();
        std::iter::once(&self.root)
            .chain(known.iter())
            .find(|r| is_real_dir(&r.partial_dir().join(&hex)))
            .unwrap_or(&self.root)
            .clone()
    }

    /// Подмена точек размещения для тестов.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn set_test_hook(&self, h: Arc<TestHook>) {
        *lock(&self.hook) = Some(h);
    }

    /// Сколько раз файл целиком перечитывался при повторе размещения.
    #[cfg(any(test, feature = "fuzzing"))]
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
    fn create_top_dirs(
        &self,
        rt: &ReceiveRoot,
        names: &[String],
    ) -> Result<Vec<(u16, u64)>, PlaceError> {
        let root = rt.root();
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
                    safe_push(&mut p, &candidate_name(name, k, false, self.max_name())?)?;
                    match make_dir(&p) {
                        Ok(()) => {
                            let ident = real_dir_ident(&p);
                            made.push(p);
                            chosen = Some((k, ident.ok_or(PlaceError::Refused)?));
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

    /// Папки верхнего уровня из журнала на месте и это те же папки (не ссылки; идентичность
    /// совпала). Любое расхождение: журнал негоден, каталоги создаются заново.
    fn top_dirs_match(&self, rt: &ReceiveRoot, names: &[String], ks: &[(u16, u64)]) -> bool {
        names.len() == ks.len()
            && names.iter().zip(ks).all(|(name, (k, ident))| {
                let mut p = rt.root().to_path_buf();
                candidate_name(name, *k, false, self.max_name())
                    .ok()
                    .is_some_and(|cn| safe_push(&mut p, &cn).is_ok())
                    && real_dir_ident(&p) == Some(*ident)
            })
    }

    fn top_path(&self, rt: &ReceiveRoot, dirs: &[String]) -> Option<PathBuf> {
        let mut p = rt.root().to_path_buf();
        safe_push(&mut p, dirs.first()?).ok()?;
        Some(p)
    }

    /// Рев. 3, F5: если каталог верхнего уровня уже есть, это обязана быть та самая папка,
    /// которую мы создали (идентичность совпадает). Отсутствующую (пользователь убрал её
    /// посреди передачи) `walk_create` создаст заново и запомнит. Только под `dir_lock`.
    fn check_top_ident(
        &self,
        sess: &SessionPlan,
        top_orig: Option<&String>,
        dirs: &[String],
    ) -> Result<(), PlaceError> {
        let (Some(orig), Some(path)) = (top_orig, self.top_path(&sess.root, dirs)) else {
            return Ok(());
        };
        let (_, cell) = sess.tops.get(orig).ok_or(PlaceError::Refused)?;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() && !m.file_type().is_symlink() => {
                if dir_ident(&m) == cell.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(PlaceError::Refused)
                }
            }
            Ok(_) => Err(PlaceError::Refused),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&e)),
        }
    }

    /// Запоминает идентичность каталога верхнего уровня после `walk_create` (он мог создать
    /// каталог заново). Только под `dir_lock`.
    fn store_top_ident(&self, sess: &SessionPlan, top_orig: Option<&String>, dirs: &[String]) {
        if let (Some(orig), Some(path)) = (top_orig, self.top_path(&sess.root, dirs))
            && let Some((_, cell)) = sess.tops.get(orig)
            && let Some(id) = real_dir_ident(&path)
        {
            cell.store(id, Ordering::SeqCst);
        }
    }

    fn session(&self, key: &TransferKey) -> Option<Arc<SessionPlan>> {
        lock(&self.sessions).get(key).cloned()
    }

    /// Цепочка каталогов от корня вниз без создания: каждый обязан быть настоящим каталогом.
    fn walk_check(&self, rt: &ReceiveRoot, dirs: &[String]) -> Result<PathBuf, PlaceError> {
        let mut p = rt.root().to_path_buf();
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
    fn walk_create(&self, rt: &ReceiveRoot, dirs: &[String]) -> Result<PathBuf, PlaceError> {
        let mut p = rt.root().to_path_buf();
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
    fn verify_placed(&self, rt: &ReceiveRoot, dirs: &[String], cand: &Path) -> bool {
        let Ok(dir) = self.walk_check(rt, dirs) else {
            return false;
        };
        if cand.parent() != Some(dir.as_path()) {
            return false;
        }
        if !fs::symlink_metadata(cand).is_ok_and(|m| m.file_type().is_file()) {
            return false;
        }
        fs::canonicalize(&dir).is_ok_and(|c| c.starts_with(rt.root()))
    }

    /// Повтор после краха: файл из последней записи журнала уже стоит на месте.
    fn replay(
        &self,
        rt: &ReceiveRoot,
        dirs: &[String],
        file_name: &str,
        k: u16,
        f: &CompletedFile,
    ) -> Option<PathBuf> {
        let dir = self.walk_check(rt, dirs).ok()?;
        let mut cand = dir;
        safe_push(
            &mut cand,
            &candidate_name(file_name, k, true, self.max_name()).ok()?,
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
        self.verify_placed(rt, dirs, &cand).then_some(cand)
    }
}

impl Placement for ReceivePlacement {
    fn prepare(&self, key: &TransferKey, files: &[OfferedFile]) -> Result<(), PlaceError> {
        if lock(&self.sessions).contains_key(key) {
            return Ok(());
        }
        let rt = self.root_for(key);
        let plan =
            plan_offer_for_root(files, &self.limits, &rt).map_err(|_| PlaceError::Refused)?;
        let tops = top_names(&plan);
        let hex = state_dir_name(&key.pair, &key.id);
        let refs: Vec<&str> = tops.iter().map(String::as_str).collect();
        let digest = plan_digest(&refs);
        let journals = rt.journal_dir();
        // журнал размещения открывается первым: его отказ не оставляет созданных каталогов
        let log = PlacedLog::open(journals, &hex).map_err(|e| io_err(&e))?;
        // каталоги созданы в прошлой жизни процесса; негодный журнал не доверяется, а каждая
        // папка из него должна быть той самой (inode / время создания, F5)
        let journaled = read_dirs(journals, &hex, key, &digest, tops.len())
            .filter(|ks| self.top_dirs_match(&rt, &tops, ks));
        let ks = match journaled {
            Some(ks) => ks,
            None => {
                let ks = self.create_top_dirs(&rt, &tops)?;
                if !ks.is_empty()
                    && let Err(e) = write_dirs(journals, &hex, key, &digest, &ks)
                {
                    for (name, (k, _)) in tops.iter().zip(&ks).rev() {
                        let mut p = rt.root().to_path_buf();
                        if let Ok(cn) = candidate_name(name, *k, false, self.max_name())
                            && safe_push(&mut p, &cn).is_ok()
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
            root: rt,
            hex,
            plan,
            names: files.iter().map(|f| f.name.clone()).collect(),
            tops: tops
                .into_iter()
                .zip(ks)
                .map(|(name, (k, ident))| (name, (k, AtomicU64::new(ident))))
                .collect(),
            log: Mutex::new(log),
            dir_lock: Mutex::new(()),
        });
        lock(&self.sessions).insert(*key, sess);
        Ok(())
    }

    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        let temp = f.temp_path();
        let sess = self.session(&f.key).ok_or(PlaceError::Refused)?;
        if !temp.starts_with(sess.root.partial_dir())
            || temp.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err(PlaceError::Refused);
        }
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
                let (k, _) = sess.tops.get(c).ok_or(PlaceError::Refused)?;
                dirs.push(candidate_name(c, *k, false, self.max_name())?);
            } else {
                dirs.push(c.clone());
            }
        }

        // повтор после краха: файл уже поставлен прошлой жизнью процесса
        let prior = lock(&sess.log).last(f.index);
        if let Some(k) = prior
            && let Some(path) = self.replay(&sess.root, &dirs, file_name, k, f)
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
            self.check_top_ident(&sess, dir_comps.first(), &dirs)?;
            let dir = self.walk_create(&sess.root, &dirs)?;
            self.store_top_ident(&sess, dir_comps.first(), &dirs);
            dir
        };
        for k in 1..=MAX_K {
            lock(&sess.log).append(f.index, k).map_err(|e| io_err(&e))?;
            let mut cand = dir.clone();
            safe_push(
                &mut cand,
                &candidate_name(file_name, k, true, self.max_name())?,
            )?;
            self.at(TestPoint::BeforeLink { dir: &dir })
                .map_err(|e| io_err(&e))?;
            match place_no_clobber(temp, &cand) {
                Ok(_) => {
                    let _ = self.at(TestPoint::AfterLink { dir: &dir });
                    if self.verify_placed(&sess.root, &dirs, &cand) {
                        return Ok(Placed { path: cand });
                    }
                    // подмена каталога: на Unix убираем только тот файл, который сами поставили
                    // (устройство и inode). На Windows не удаляем ничего (F1).
                    #[cfg(unix)]
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
        lock(&self.choices).remove(key);
        let hex = match &sess {
            Some(s) => s.hex.clone(),
            None => state_dir_name(&key.pair, &key.id),
        };
        // журналы лежат у папки этой передачи; без плана (сеанс снят до `prepare`) чистятся у всех
        let roots: Vec<ReceiveRoot> = match &sess {
            Some(s) => vec![s.root.clone()],
            None => std::iter::once(self.root.clone())
                .chain(lock(&self.known).iter().cloned())
                .collect(),
        };
        if let Some(s) = sess {
            let rt = s.root.clone();
            // пустые каталоги этой передачи (отмена до размещения): снизу вверх, только пустые
            let mut dirs: HashSet<Vec<String>> = HashSet::new();
            for pf in &s.plan.files {
                let comps = pf.path.components();
                let n = comps.len().saturating_sub(1);
                let mut resolved: Vec<String> = Vec::with_capacity(n);
                for (i, c) in comps.iter().take(n).enumerate() {
                    if i == 0 {
                        let Some((k, _)) = s.tops.get(c) else { break };
                        let Ok(cn) = candidate_name(c, *k, false, self.max_name()) else {
                            break;
                        };
                        resolved.push(cn);
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
                let mut p = rt.root().to_path_buf();
                if d.iter().all(|c| safe_push(&mut p, c).is_ok()) && is_real_dir(&p) {
                    let _ = fs::remove_dir(&p);
                }
            }
        }
        for r in &roots {
            remove_journals(r.journal_dir(), &hex);
        }
    }

    fn partial_base(&self, key: &TransferKey) -> Option<PathBuf> {
        lock(&self.choices)
            .get(key)
            .map(|r| r.partial_dir().to_path_buf())
    }

    fn extra_partial_dirs(&self) -> Vec<PathBuf> {
        lock(&self.known)
            .iter()
            .map(|r| r.partial_dir().to_path_buf())
            .collect()
    }
}
