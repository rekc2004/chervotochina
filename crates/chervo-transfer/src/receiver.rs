//! Сессия получателя: состояние, подготовка файлов, попытки на одном соединении и
//! возобновление. Потоки данных и поток управления в `rstream.rs`, запись и итоговая
//! проверка в `writer.rs`.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chervo_transport::{Connection, SendStream};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::codec::{CancelReason, FileErrCode, Message, encode};
use crate::events::{
    FailReason, FileFailure, PauseReason, Side, TransferEvent, TransferState, TransferStatus,
};
use crate::fsio::verify_blocks;
use crate::hash::{BlockHash, FileRoot, file_root};
use crate::layout::{Layout, layout};
use crate::limits::STREAM_TRANSFER_CTL;
use crate::links::Links;
use crate::liveness::{Liveness, idle_limit, stall_limit};
use crate::names::{TransferKey, UntrustedName};
use crate::paths::{
    create_part_new, ensure_part, placing_present, remove_hashes, remove_part_and_hashes,
    remove_part_strict, remove_placing_strict, remove_session, session_dir, write_hashes,
    write_state,
};
use crate::policy::OfferView;
use crate::sched::{Active, Prior, Run, Sched};
use crate::shared::{HookPoint, Shared, buffer_floor, lock, share_semaphore};
use crate::state::{
    FileStatus, Progress, RecvState, StateFile, encode_hashes, encode_state, state_dir_name,
};
use crate::util::{Bits, Stop, Tracker, now_unix};
use crate::wire_io::read_message;

pub(crate) use crate::inner::Inner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RPhase {
    Pending,
    Active,
    Paused(PauseReason),
    Ended,
}

/// Почему закончилась попытка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    Disconnected,
    Pause(PauseReason),
    PeerCancelled,
    Protocol,
}

/// Чем закончилась вся передача на стороне получателя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finish {
    Completed,
    Cancelled(Side),
    Failed(FailReason),
}

/// Одна попытка: одно соединение, поток управления, потоки данных и писатель. Сроки и
/// счётчики обрывов в попытке не живут (отправитель может начать её заново когда угодно):
/// они в `RecvSession::live`. Здесь только то, что относится к самой попытке.
pub(crate) struct Attempt {
    pub(crate) stop: Stop,
    pub(crate) tracker: Tracker,
    end: watch::Sender<Option<End>>,
    echo: watch::Sender<bool>,
    /// Начало попытки.
    start: tokio::time::Instant,
    /// Принят хотя бы один кадр HASH_PROGRESS.
    saw_frame: AtomicBool,
}

impl Attempt {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: Stop::new(),
            tracker: Tracker::new(),
            end: watch::channel(None).0,
            echo: watch::channel(false).0,
            start: tokio::time::Instant::now(),
            saw_frame: AtomicBool::new(false),
        })
    }

    /// Принят кадр HASH_PROGRESS.
    pub(crate) fn note_frame(&self) {
        self.saw_frame.store(true, Ordering::Release);
    }

    pub(crate) fn saw_frame(&self) -> bool {
        self.saw_frame.load(Ordering::Acquire)
    }

    /// До первого кадра попытке положен срок от её начала (связь могла пропадать надолго);
    /// после первого кадра сроки считаются от настоящего роста.
    pub(crate) fn grace(&self) -> Option<tokio::time::Instant> {
        (!self.saw_frame()).then_some(self.start)
    }

    /// Первая причина побеждает.
    pub(crate) fn finish(&self, e: End) {
        self.end.send_if_modified(|v| {
            if v.is_none() {
                *v = Some(e);
                true
            } else {
                false
            }
        });
    }

    pub(crate) async fn ended(&self) -> End {
        let mut rx = self.end.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(v) => (*v).unwrap_or(End::Disconnected),
            Err(_) => End::Disconnected,
        }
    }

    pub(crate) fn note_echo(&self) {
        self.echo.send_replace(true);
    }

    async fn wait_echo(&self) {
        let mut rx = self.echo.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }
}

pub(crate) struct RCore {
    pub(crate) phase: RPhase,
    pub(crate) sched: Sched,
    created_unix: u64,
    pub(crate) ctl: Option<mpsc::UnboundedSender<Message>>,
    pub(crate) att: Option<Arc<Attempt>>,
    pub(crate) last_progress: Option<Instant>,
    /// Когда в последний раз выдано событие `Preparing`.
    last_prep: Option<tokio::time::Instant>,
    /// Чем закончить передачу, когда сработает `end`.
    pub(crate) finish: Option<Finish>,
    /// Был файл с неудачным размещением: временные данные оставляются.
    pub(crate) place_failed: bool,
}

pub(crate) struct RecvSession {
    pub(crate) sh: Arc<Shared>,
    pub(crate) key: TransferKey,
    pub(crate) names: Vec<UntrustedName>,
    pub(crate) sizes: Vec<u64>,
    pub(crate) total: u64,
    pub(crate) sdir: PathBuf,
    pub(crate) core: Mutex<RCore>,
    /// Сроки ожидания отправителя и счётчики обрывов на всю сессию (не по попыткам).
    pub(crate) live: Mutex<Liveness>,
    /// Размещённые файлы, чьи остатки (`.placing`, хэши) убираются после записи `Placed`.
    cleanup: Mutex<Vec<u32>>,
    /// Когда в последний раз занято право на запись состояния по сроку: единый ограничитель,
    /// общий для контрольной точки писателя и записи после размещения (`reserve_state_write`).
    last_sync: Mutex<Option<Instant>>,
    io_lock: Mutex<()>,
    /// Трейлер файла имён (известен после принятия или загрузки с диска).
    names_sum: Mutex<[u8; 32]>,
    /// Состояние изменилось, а записи на диск ещё не было: запись объединяется по таймеру
    /// контрольной точки писателя (не по записи на каждое событие файла).
    dirty: AtomicBool,
    /// Доля этой передачи в бюджете памяти получения.
    pub(crate) share: Arc<Semaphore>,
    /// Изменилась работа планировщика (новый блок, файл закрыт и тому подобное).
    pub(crate) wake: Notify,
    pub(crate) retry: Notify,
    pub(crate) halt: Arc<AtomicBool>,
    pub(crate) end: Stop,
    answer: Mutex<Option<oneshot::Sender<bool>>>,
    /// Блокирующие задачи сессии (итоговая проверка, подготовка файлов).
    pub(crate) jobs: Tracker,
}

fn share_for(sh: &Shared, sizes: &[u64]) -> Arc<Semaphore> {
    share_semaphore(
        sh.cfg.recv_buffer_budget,
        sh.cfg.max_inbound_active,
        buffer_floor(sizes),
    )
}

fn sched_for(sh: &Shared, sizes: &[u64], runs: Vec<Run>) -> Sched {
    Sched::new(
        runs,
        sizes.to_vec(),
        usize::from(sh.cfg.streams),
        sh.cfg.max_block_refetch,
        sh.cfg.max_refetch_per_transfer,
    )
}

impl RecvSession {
    /// Предложение ждёт решения; на диск пока ничего не записано.
    pub(crate) fn pending(
        sh: Arc<Shared>,
        key: TransferKey,
        files: Vec<(UntrustedName, u64)>,
        total: u64,
        answer: oneshot::Sender<bool>,
    ) -> Arc<Self> {
        let sizes: Vec<u64> = files.iter().map(|f| f.1).collect();
        let names: Vec<UntrustedName> = files.into_iter().map(|f| f.0).collect();
        let runs = sizes.iter().map(|_| Run::Waiting(None)).collect();
        let sched = sched_for(&sh, &sizes, runs);
        let sdir = session_dir(&sh.cfg.partial_dir, &state_dir_name(&key.pair, &key.id));
        let share = share_for(&sh, &sizes);
        Arc::new(Self {
            sh,
            key,
            names,
            sizes,
            total,
            sdir,
            core: Mutex::new(RCore {
                phase: RPhase::Pending,
                sched,
                created_unix: now_unix(),
                ctl: None,
                att: None,
                last_progress: None,
                last_prep: None,
                finish: None,
                place_failed: false,
            }),
            live: Mutex::new(Liveness::new()),
            cleanup: Mutex::new(Vec::new()),
            last_sync: Mutex::new(None),
            io_lock: Mutex::new(()),
            names_sum: Mutex::new([0; 32]),
            dirty: AtomicBool::new(false),
            share,
            wake: Notify::new(),
            retry: Notify::new(),
            halt: Arc::new(AtomicBool::new(false)),
            end: Stop::new(),
            answer: Mutex::new(Some(answer)),
            jobs: Tracker::new(),
        })
    }

    /// Загружено с диска при запуске: на паузе до первого соединения.
    pub(crate) fn restored(
        sh: Arc<Shared>,
        key: TransferKey,
        files: Vec<(UntrustedName, u64)>,
        runs: Vec<Run>,
        created_unix: u64,
        sdir: PathBuf,
        names_sum: [u8; 32],
    ) -> Arc<Self> {
        let sizes: Vec<u64> = files.iter().map(|f| f.1).collect();
        let total = sizes.iter().fold(0u64, |a, b| a.saturating_add(*b));
        let names: Vec<UntrustedName> = files.into_iter().map(|f| f.0).collect();
        let sched = sched_for(&sh, &sizes, runs);
        let share = share_for(&sh, &sizes);
        Arc::new(Self {
            sh,
            key,
            names,
            sizes,
            total,
            sdir,
            core: Mutex::new(RCore {
                phase: RPhase::Paused(PauseReason::Disconnected),
                sched,
                created_unix,
                ctl: None,
                att: None,
                last_progress: None,
                last_prep: None,
                finish: None,
                place_failed: false,
            }),
            live: Mutex::new(Liveness::new()),
            cleanup: Mutex::new(Vec::new()),
            last_sync: Mutex::new(None),
            io_lock: Mutex::new(()),
            names_sum: Mutex::new(names_sum),
            dirty: AtomicBool::new(false),
            share,
            wake: Notify::new(),
            retry: Notify::new(),
            halt: Arc::new(AtomicBool::new(false)),
            end: Stop::new(),
            answer: Mutex::new(None),
            jobs: Tracker::new(),
        })
    }

    pub(crate) fn emit(&self, e: TransferEvent) {
        self.sh.emit(e);
    }

    /// Событие `Preparing` по принятому кадру HASH_PROGRESS; не чаще `progress_interval`,
    /// итоговое значение всегда.
    pub(crate) fn note_preparing(&self, hashed: u64) {
        let force = hashed >= self.total;
        {
            let mut c = lock(&self.core);
            let due = force
                || c.last_prep
                    .is_none_or(|t| t.elapsed() >= self.sh.cfg.progress_interval);
            if !due {
                return;
            }
            c.last_prep = Some(tokio::time::Instant::now());
        }
        self.emit(TransferEvent::Preparing {
            key: self.key,
            hashed,
            total: self.total,
        });
    }

    /// Настоящее продвижение: блок или манифест принят, блок записан. Обрывы не копятся.
    pub(crate) fn live_progress(&self) {
        lock(&self.live).progress(tokio::time::Instant::now());
    }

    /// Пределы живости сессии, общие для конца попытки и неудавшегося рукопожатия.
    /// Блокировка `core` берётся и отпускается до `live`.
    fn over_limits(&self, att: Option<&Attempt>, futile: u32, now: tokio::time::Instant) -> bool {
        let cfg = &self.sh.cfg;
        let (needs_hash, hashed) = {
            let c = lock(&self.core);
            (c.sched.needs_hash(), c.sched.hashed)
        };
        let mut lv = lock(&self.live);
        let mut over = futile >= stall_limit(cfg) || lv.idle_over(idle_limit(cfg));
        if needs_hash {
            lv.begin_wait(now, hashed);
            // предел по скорости считается от начала ожидания и пережил все прежние попытки
            over |= lv
                .rate_deadline(cfg.stall_timeout, cfg.min_hash_rate, self.total, None)
                .is_some_and(|d| now >= d);
            // кадр этой попытки показывает, что картина свежая: молчание считается от роста
            if att.is_some_and(Attempt::saw_frame) {
                over |= lv
                    .silence_deadline(cfg.stall_timeout, None)
                    .is_some_and(|d| now >= d);
            }
        }
        over
    }

    /// Попытка закончилась. `lost`: связь потеряна (закрыто соединение или поток управления),
    /// а не остановка или пауза по причине диска. `true`: отправитель слишком долго
    /// перезапускает попытки без продвижения, передачу надо ставить на паузу `Stalled`.
    /// `now`: момент, когда конец попытки замечен (а не когда закончилась уборка за ней), а
    /// `gone`: соединение закрыто, и с этого момента времени со связью нет.
    pub(crate) fn attempt_over(
        &self,
        att: &Attempt,
        seq0: u64,
        lost: bool,
        gone: bool,
        now: tokio::time::Instant,
    ) -> bool {
        let demand = lock(&self.core).sched.wants_data();
        let futile = {
            let mut lv = lock(&self.live);
            lv.end_attempt(now, demand);
            if gone {
                lv.link_lost(now);
            }
            if lost { lv.futile_attempt(seq0) } else { 0 }
        };
        lost && self.over_limits(Some(att), futile, now)
    }

    /// Рукопожатие возобновления не удалось (поток не открылся, ответа нет): тоже бесплодная
    /// попытка. `true`: пауза `Stalled`.
    pub(crate) fn handshake_over(&self) -> bool {
        let futile = lock(&self.live).stall();
        self.over_limits(None, futile, tokio::time::Instant::now())
    }

    pub(crate) fn take_answer(&self) -> Option<oneshot::Sender<bool>> {
        lock(&self.answer).take()
    }

    pub(crate) fn ctl_send(&self, m: Message) {
        if let Some(tx) = &lock(&self.core).ctl {
            let _ = tx.send(m);
        }
    }

    pub(crate) fn file_count(&self) -> u32 {
        u32::try_from(self.names.len()).unwrap_or(u32::MAX)
    }

    pub(crate) fn offer_view(&self) -> OfferView {
        OfferView {
            key: self.key,
            files: self
                .names
                .iter()
                .zip(&self.sizes)
                .map(|(n, s)| crate::names::OfferedFile {
                    name: n.clone(),
                    size: *s,
                })
                .collect(),
            total_size: self.total,
        }
    }

    pub(crate) fn status(&self) -> TransferStatus {
        let c = lock(&self.core);
        let state = match c.phase {
            RPhase::Pending => TransferState::AwaitingUser,
            RPhase::Active => TransferState::Active,
            RPhase::Paused(r) => TransferState::Paused(r),
            RPhase::Ended => TransferState::Finished,
        };
        TransferStatus {
            side: Side::Receiver,
            state,
            done: c.sched.done_bytes(),
            total: self.total,
        }
    }

    /// Файл состояния в том виде, в каком он будет записан. Битовые карты берутся из
    /// `durable` (подтверждено `sync_data`), а не из `have`.
    fn snapshot(&self, core: &RCore) -> RecvState {
        let mut files = Vec::with_capacity(self.sizes.len());
        for (i, size) in self.sizes.iter().enumerate() {
            let progress = |layout: Layout, root: FileRoot, bits: &Bits| -> FileStatus {
                if bits.count_ones() == layout.block_count {
                    FileStatus::Verified(root)
                } else {
                    FileStatus::InProgress(Progress {
                        layout,
                        root,
                        bitmap: bits.bytes().to_vec(),
                    })
                }
            };
            let status = match core.sched.runs.get(i) {
                Some(Run::Waiting(Some(p)) | Run::Requested(Some(p))) => {
                    progress(p.layout, p.root, &p.bits)
                }
                Some(Run::Active(a) | Run::Finalizing(a)) => progress(a.layout, a.root, &a.durable),
                Some(Run::Placed(root)) => FileStatus::Placed(*root),
                Some(Run::Failed) => FileStatus::Failed,
                _ => FileStatus::Waiting,
            };
            files.push(StateFile {
                size: *size,
                status,
            });
        }
        RecvState {
            pair: self.key.pair,
            id: self.key.id,
            created_unix: core.created_unix,
            last_progress_unix: now_unix(),
            total_size: self.total,
            names_sum: *lock(&self.names_sum),
            files,
        }
    }

    /// Файл имён предложения, один раз при принятии (блокирующая): имена в неизменяемый файл
    /// с контрольной суммой, трейлер запоминается для файла состояния.
    pub(crate) fn write_names_once(&self) -> io::Result<()> {
        let (bytes, sum) = crate::state::encode_names(&self.key.pair, &self.key.id, &self.names);
        self.sh.hook(HookPoint::NamesWrite { bytes: &bytes })?;
        crate::paths::write_names(&self.sdir, &bytes)?;
        *lock(&self.names_sum) = sum;
        Ok(())
    }

    /// Запись файла состояния (блокирующая). Замок ввода-вывода держится от снимка до
    /// переименования: более старый снимок не перекроет новый.
    pub(crate) fn persist(&self) -> io::Result<()> {
        let _io = lock(&self.io_lock);
        // флаг снимается до снимка: событие после снимка снова поднимет его
        self.dirty.store(false, Ordering::Release);
        // файлы, размещённые до этого снимка: после записи `Placed` их остатки не нужны. Список
        // берётся до снимка, а `set_placed` предшествует попаданию в список, поэтому снимок
        // содержит `Placed` для каждого из них.
        let placed: Vec<u32> = std::mem::take(&mut *lock(&self.cleanup));
        let bytes = {
            let core = lock(&self.core);
            encode_state(&self.snapshot(&core))
        };
        let res = self
            .sh
            .hook(HookPoint::StateWrite { bytes: &bytes })
            .and_then(|()| write_state(&self.sdir, &bytes));
        match &res {
            Ok(()) => {
                for f in placed {
                    remove_hashes(&self.sdir, f);
                    let _ =
                        crate::paths::remove_file_retry(&crate::paths::placing_path(&self.sdir, f));
                }
            }
            Err(_) => {
                self.dirty.store(true, Ordering::Release);
                lock(&self.cleanup).extend(placed);
            }
        }
        res
    }

    /// Занять право на запись состояния: не чаще раза за `checkpoint_interval` на все
    /// источники вместе (контрольная точка писателя и запись после размещения). Проверка и
    /// отметка времени атомарны, поэтому два источника не пишут друг за другом.
    pub(crate) fn reserve_state_write(&self) -> bool {
        let mut last = lock(&self.last_sync);
        let due = last.is_none_or(|t| t.elapsed() >= self.sh.cfg.checkpoint_interval);
        if due {
            *last = Some(Instant::now());
        }
        due
    }

    /// Сколько осталось до следующей разрешённой записи состояния.
    pub(crate) fn state_write_wait(&self) -> std::time::Duration {
        lock(&self.last_sync).map_or(std::time::Duration::ZERO, |t| {
            self.sh.cfg.checkpoint_interval.saturating_sub(t.elapsed())
        })
    }

    /// Файл размещён: его остатки (`.placing`, хэши) убираются после записи `Placed`. Запись
    /// делается сразу, а не контрольной точкой, чтобы окно между размещением и записью было
    /// минимальным; не чаще раза за `checkpoint_interval` вместе с контрольной точкой (тысячи
    /// мелких файлов не должны давать тысячи переписываний состояния; остальное сделает
    /// контрольная точка, она же уберёт остатки).
    pub(crate) fn placed_now(&self, file: u32) {
        lock(&self.cleanup).push(file);
        self.mark_dirty();
        if self.reserve_state_write() {
            let _ = self.persist();
        }
    }

    /// Состояние изменилось; запись выполнит контрольная точка писателя.
    pub(crate) fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Нет писателя, который сохранил бы изменение (попытки нет): записать сразу.
    pub(crate) fn flush_detached(&self) {
        if self.is_dirty() && lock(&self.core).att.is_none() {
            let _ = self.persist();
        }
    }

    /// Файл закрыт как проваленный. `tell`: код для FILE_ERROR отправителю.
    pub(crate) fn fail_file(
        self: &Arc<Self>,
        file: u32,
        why: FileFailure,
        tell: Option<FileErrCode>,
    ) {
        let changed = {
            let mut c = lock(&self.core);
            let ch = c.sched.fail(file);
            if ch {
                if why == FileFailure::PlaceFailed {
                    c.place_failed = true;
                }
                if let (Some(code), Some(tx)) = (tell, &c.ctl) {
                    let _ = tx.send(Message::FileError { index: file, code });
                }
            }
            ch
        };
        if !changed {
            return;
        }
        self.emit(TransferEvent::FileFailed {
            key: self.key,
            index: file,
            reason: why,
        });
        let s = self.clone();
        let g = self.jobs.guard();
        self.sh.spawn_blocking(move || {
            let _g = g;
            // временный файл с неудачным размещением остаётся (до отмены или срока)
            if why == FileFailure::PlaceFailed {
                remove_hashes(&s.sdir, file);
            } else {
                remove_part_and_hashes(&s.sdir, file);
            }
            s.mark_dirty();
            s.flush_detached();
        });
        self.wake.notify_waiters();
    }

    /// Переходит в паузу и сообщает об этом один раз.
    pub(crate) fn set_paused(&self, reason: PauseReason) {
        let changed = {
            let mut c = lock(&self.core);
            match c.phase {
                RPhase::Active => {
                    c.phase = RPhase::Paused(reason);
                    true
                }
                RPhase::Paused(old) if old != reason => {
                    c.phase = RPhase::Paused(reason);
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.emit(TransferEvent::Paused {
                key: self.key,
                reason,
            });
        }
    }

    /// Откат места, занятого `claim_slot`, без события (возобновление не состоялось).
    pub(crate) fn unclaim(&self, prev: PauseReason) {
        let mut c = lock(&self.core);
        if c.phase == RPhase::Active {
            c.phase = RPhase::Paused(prev);
        }
    }

    fn set_active(&self) {
        let was_paused = {
            let mut c = lock(&self.core);
            let p = matches!(c.phase, RPhase::Paused(_));
            if p || c.phase == RPhase::Pending {
                c.phase = RPhase::Active;
            }
            p
        };
        if was_paused {
            self.emit(TransferEvent::Resumed { key: self.key });
        }
    }

    /// Запускает итоговую проверку для файлов, у которых все блоки уже на месте.
    pub(crate) fn kick_finalizers(self: &Arc<Self>) {
        let ready: Vec<u32> = {
            let mut c = lock(&self.core);
            c.sched.take_complete()
        };
        for f in ready {
            self.spawn_finalize(f);
        }
    }

    pub(crate) fn spawn_finalize(self: &Arc<Self>, file: u32) {
        let s = self.clone();
        let g = self.jobs.guard();
        self.sh.spawn_blocking(move || {
            let _g = g;
            crate::writer::finalize_file(&s, file);
            s.flush_detached();
        });
    }

    /// Пустой файл: запросов нет.
    pub(crate) fn start_zero(self: &Arc<Self>, file: u32) {
        let l = layout(0).unwrap_or(Layout {
            block_size: crate::limits::MIN_BLOCK,
            block_count: 0,
        });
        let Ok(root) = file_root(0, l, &[]) else {
            self.fail_file(file, FileFailure::WriteError, Some(FileErrCode::WriteError));
            return;
        };
        let a = Active::new(l, root, Arc::new(Vec::new()), Bits::zeros(0), 0);
        lock(&self.core).sched.activate_zero(file, a);
        self.spawn_finalize(file);
    }

    /// Манифест файла пришёл и согласован: подготовить файлы на диске и пустить блоки в работу.
    /// `Err`: причина паузы (диск, ввод-вывод).
    pub(crate) async fn setup_file(
        self: &Arc<Self>,
        file: u32,
        l: Layout,
        root: FileRoot,
        leaves: Vec<BlockHash>,
    ) -> Result<(), PauseReason> {
        let Some(prior) = lock(&self.core).sched.begin_setup(file) else {
            return Ok(());
        };
        let s = self.clone();
        let leaves = Arc::new(leaves);
        let g = self.jobs.guard();
        let job = self.sh.rt.spawn_blocking(move || {
            let _g = g;
            prepare(&s, file, l, root, leaves, prior)
        });
        let res = job.await.map_err(|_| PauseReason::Io)?;
        match res {
            Ok(a) => {
                let need_final = lock(&self.core).sched.activate(file, a);
                if need_final {
                    self.spawn_finalize(file);
                }
                // запись состояния объединяется контрольной точкой писателя
                self.mark_dirty();
                self.wake.notify_waiters();
                Ok(())
            }
            Err((e, prior)) => {
                lock(&self.core).sched.restore_waiting(file, prior);
                self.wake.notify_waiters();
                Err(crate::writer::pause_reason(&e))
            }
        }
    }
}

type PrepareErr = (io::Error, Option<Prior>);

/// Блокирующая часть подготовки файла. Прежний прогресс с тем же корнем перепроверяется с
/// диска (каждый отмеченный блок перехэшируется); другой корень: файл начинается с нуля.
pub(crate) fn prepare(
    s: &Arc<RecvSession>,
    file: u32,
    l: Layout,
    root: FileRoot,
    leaves: Arc<Vec<BlockHash>>,
    prior: Option<Prior>,
) -> Result<Active, PrepareErr> {
    let size = s
        .sizes
        .get(usize::try_from(file).unwrap_or(usize::MAX))
        .copied()
        .unwrap_or(0);
    let mut prior = prior;
    // Крах после переименования `.part` -> `.placing` (возможно, и после жёсткой ссылки на
    // размещённый файл), но до записи `Placed`. `.placing` только читается: хэши свежего
    // манифеста (корень уже проверен) сверяются с диском. Всё совпало: файл готов, дальше
    // только размещение (идемпотентное). Не совпало: имя убирается (содержимое не трогается),
    // файл качается заново.
    if size > 0 && placing_present(&s.sdir, file) {
        s.emit(TransferEvent::Verifying { key: s.key });
        let placing = crate::paths::placing_path(&s.sdir, file);
        match verify_blocks(&placing, size, l, &leaves, None, &s.halt) {
            Ok(bad) if bad.is_empty() => {
                let gone =
                    s.sh.hook(HookPoint::RemovePart { file })
                        .and_then(|()| remove_part_strict(&s.sdir, file));
                if let Err(e) = gone {
                    return Err((e, prior));
                }
                s.sh.hook(HookPoint::Manifest { file })
                    .map_err(|e| (e, None))?;
                return Ok(Active::new(
                    l,
                    root,
                    leaves,
                    Bits::ones(l.block_count),
                    size,
                ));
            }
            Ok(_) => {
                if let Err(e) = remove_placing_strict(&s.sdir, file) {
                    return Err((e, prior));
                }
                // прежний прогресс описывал `.part`, которого больше нет
                prior = None;
            }
            Err(e) => {
                let kind = match e {
                    crate::fsio::ReadFail::Io(k) => k,
                    _ => io::ErrorKind::Interrupted,
                };
                return Err((io::Error::from(kind), prior));
            }
        }
    }
    let (reuse, stale) = match prior {
        Some(p) if p.root == root && p.layout == l => (Some(p), None),
        other => (None, other),
    };
    // Старый `<i>.part` другого файла (или без прогресса) удаляется строго: если убрать его не
    // удалось, дальше нельзя (он мог остаться жёсткой ссылкой на уже размещённый файл), и
    // передача встаёт на паузу.
    if reuse.is_none() {
        let removed =
            s.sh.hook(HookPoint::RemovePart { file })
                .and_then(|()| remove_part_strict(&s.sdir, file));
        if let Err(e) = removed {
            return Err((e, stale));
        }
    }
    let bits = if let Some(p) = reuse {
        s.emit(TransferEvent::Verifying { key: s.key });
        let part = crate::paths::part_path(&s.sdir, file);
        match verify_blocks(&part, size, l, &leaves, Some(&p.bits), &s.halt) {
            Ok(bad) => {
                let mut bits = p.bits.clone();
                for b in bad {
                    bits.clear(b);
                }
                // файла может не быть (все блоки тогда в `bad`): создаётся новый
                if let Err(e) = ensure_part(&s.sdir, file) {
                    return Err((e, Some(p)));
                }
                bits
            }
            Err(e) => {
                let kind = match e {
                    crate::fsio::ReadFail::Io(k) => k,
                    _ => io::ErrorKind::Interrupted,
                };
                return Err((io::Error::from(kind), Some(p)));
            }
        }
    } else {
        let step = || -> io::Result<()> {
            write_hashes(&s.sdir, file, &encode_hashes(&leaves))?;
            create_part_new(&s.sdir, file)?;
            Ok(())
        };
        if let Err(e) = step() {
            return Err((e, None));
        }
        Bits::zeros(l.block_count)
    };
    s.sh.hook(HookPoint::Manifest { file })
        .map_err(|e| (e, None))?;
    Ok(Active::new(l, root, leaves, bits, size))
}

// ------------------------------------------------------------------ попытки

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Соединение потеряно (закрыто). Годным считается любое живое соединение пары: номер
    /// погибшего не запоминается.
    Disconnected,
    /// Пауза, ждём `retry`.
    Paused,
    /// Попытка не удалась без вины соединения: повторить через время опроса.
    Retry,
    Over,
}

pub(crate) type Tx<C> = <C as Connection>::Tx;
pub(crate) type Rx<C> = <C as Connection>::Rx;
pub(crate) type CtlStreams<C> = (Tx<C>, Rx<C>);

pub(crate) struct FirstCtl<C: Connection> {
    pub(crate) conn: C,
    pub(crate) tx: Tx<C>,
    pub(crate) rx: Rx<C>,
}

async fn is_closed<C: Connection>(c: &C) -> bool {
    timeout(std::time::Duration::ZERO, c.closed()).await.is_ok()
}

/// Исход после потери связи в попытке: соединение закрыто, ждём другое; живое (сбой без вины
/// соединения): повтор через время опроса, без горячего цикла.
async fn lost<C: Connection>(c: &C) -> Outcome {
    if is_closed(c).await {
        Outcome::Disconnected
    } else {
        Outcome::Retry
    }
}

/// Ждёт живое соединение пары (событие или опрос раз в `poll`). `None`: передача закончена.
/// Соединение годно, если оно есть у движка и не закрыто; сравнения с номером погибшего нет.
async fn wait_conn<L: Links>(inner: &Arc<Inner<L>>, s: &Arc<RecvSession>) -> Option<L::Conn> {
    let mut gen_rx = inner.conn_gen.subscribe();
    let mut end = s.end.watcher();
    let mut down = s.sh.shutdown.watcher();
    loop {
        if s.end.is_stopped() || s.sh.shutdown.is_stopped() {
            return None;
        }
        if let Some(c) = inner.links.connection(&s.key.pair)
            && !is_closed(&c).await
        {
            // связь вернулась: время без неё в сроки хэширования не идёт
            lock(&s.live).link_back(tokio::time::Instant::now());
            return Some(c);
        }
        lock(&s.live).link_lost(tokio::time::Instant::now());
        tokio::select! {
            _ = gen_rx.changed() => {}
            () = tokio::time::sleep(inner.poll) => {}
            () = end.stopped() => return None,
            () = down.stopped() => return None,
        }
    }
}

/// Главная задача сессии получателя: попытки одна за другой, пока передача не закончится.
pub(crate) async fn recv_supervisor<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<RecvSession>,
    first: Option<FirstCtl<L::Conn>>,
) {
    let mut first = first;
    loop {
        let (conn, ctl) = match first.take() {
            Some(f) => (f.conn, Some((f.tx, f.rx))),
            None => {
                let Some(c) = wait_conn(&inner, &s).await else {
                    end_if_requested(&inner, &s).await;
                    return;
                };
                (c, None)
            }
        };
        match run_attempt(&inner, &s, conn, ctl).await {
            Outcome::Disconnected => {}
            Outcome::Paused => {
                // ждём `retry`, отмену или остановку
                let mut end = s.end.watcher();
                let mut down = s.sh.shutdown.watcher();
                tokio::select! {
                    // явное `retry`: сроки ожидания и счётчики обрывов начинаются заново
                    () = s.retry.notified() => lock(&s.live).reset(),
                    () = end.stopped() => {}
                    () = down.stopped() => {}
                }
            }
            Outcome::Retry => {
                let mut end = s.end.watcher();
                let mut down = s.sh.shutdown.watcher();
                tokio::select! {
                    () = tokio::time::sleep(inner.poll) => {}
                    () = end.stopped() => {}
                    () = down.stopped() => {}
                }
            }
            Outcome::Over => return,
        }
        if s.end.is_stopped() {
            end_if_requested(&inner, &s).await;
            return;
        }
        if s.sh.shutdown.is_stopped() {
            return;
        }
    }
}

/// Отмена пришла, пока попытки не было.
async fn end_if_requested<L: Links>(inner: &Arc<Inner<L>>, s: &Arc<RecvSession>) {
    let how = lock(&s.core).finish;
    if let Some(how) = how {
        finish_session(inner, s, how).await;
    }
}

/// Завершает передачу: событие, удаление временных данных, снятие с учёта.
pub(crate) async fn finish_session<L: Links>(
    inner: &Arc<Inner<L>>,
    s: &Arc<RecvSession>,
    how: Finish,
) {
    let keep = {
        let mut c = lock(&s.core);
        if c.phase == RPhase::Ended {
            return;
        }
        c.phase = RPhase::Ended;
        c.ctl = None;
        c.place_failed && how == Finish::Completed
    };
    s.end.stop();
    s.halt.store(true, Ordering::Relaxed);
    s.jobs.idle().await;
    if !keep {
        let dir = s.sdir.clone();
        let g = s.sh.tracker.guard();
        let _ =
            s.sh.rt
                .spawn_blocking(move || {
                    let _g = g;
                    remove_session(&dir);
                })
                .await;
    }
    inner.remove_inb(&s.key);
    s.emit(match how {
        Finish::Completed => TransferEvent::Completed { key: s.key },
        Finish::Cancelled(by) => TransferEvent::Cancelled { key: s.key, by },
        Finish::Failed(reason) => TransferEvent::Failed { key: s.key, reason },
    });
}

enum Hs {
    Ok,
    Forgot,
    PeerCancelled,
    Completed,
    Protocol,
    Retry,
}

/// Открывает новый поток управления с RESUME и читает ответ отправителя.
async fn resume_handshake<C: Connection>(
    conn: &C,
    s: &RecvSession,
) -> (Hs, Option<(Tx<C>, Rx<C>, Vec<u8>)>) {
    let cfg = &s.sh.cfg;
    let Ok(Ok((mut tx, mut rx))) = timeout(cfg.msg_timeout, conn.open_bi()).await else {
        return (Hs::Retry, None);
    };
    let mut out = vec![STREAM_TRANSFER_CTL];
    if encode(&Message::Resume { id: s.key.id }, &mut out).is_err() {
        return (Hs::Protocol, None);
    }
    if !matches!(
        timeout(cfg.msg_timeout, tx.write_all(&out)).await,
        Ok(Ok(()))
    ) {
        return (Hs::Retry, None);
    }
    let mut buf = Vec::new();
    let got = timeout(
        cfg.offer_read_timeout,
        read_message(&mut rx, &mut buf, cfg.msg_timeout),
    )
    .await;
    match got {
        Ok(Ok(Some(Message::ResumeOk {
            id,
            file_count,
            total_size,
        }))) => {
            if id == s.key.id && file_count == s.file_count() && total_size == s.total {
                (Hs::Ok, Some((tx, rx, buf)))
            } else {
                (Hs::Protocol, None)
            }
        }
        Ok(Ok(Some(Message::Cancel { id, reason }))) if id == s.key.id => {
            if reason == CancelReason::Unknown {
                (Hs::Forgot, None)
            } else {
                (Hs::PeerCancelled, None)
            }
        }
        Ok(Ok(Some(Message::Done { id }))) if id == s.key.id => (Hs::Completed, None),
        Ok(Err(crate::codec::ProtocolError::Closed | crate::codec::ProtocolError::TimedOut))
        | Ok(Ok(None))
        | Err(_) => (Hs::Retry, None),
        _ => (Hs::Protocol, None),
    }
}

async fn run_attempt<L: Links>(
    inner: &Arc<Inner<L>>,
    s: &Arc<RecvSession>,
    conn: L::Conn,
    first: Option<CtlStreams<L::Conn>>,
) -> Outcome {
    let sh = s.sh.clone();
    let cfg = &sh.cfg;
    if conn.remote_pair() != s.key.pair {
        return Outcome::Retry;
    }
    let is_first = first.is_some();
    // Возобновление занимает место среди активных входящих (приём принятых передач уже занял
    // его в `accept_flow`). Нет места: передача остаётся на паузе, повтор через время опроса.
    let claimed = if is_first {
        None
    } else {
        match inner.claim_slot(s) {
            Some(prev) => prev,
            None => return Outcome::Retry,
        }
    };
    // удержание: пока идёт передача, `max_live` соединение не закрывает
    let hold = inner.links.hold(&s.key.pair);
    let (ctl_tx, ctl_rx, buf) = match first {
        Some((t, r)) => (t, r, Vec::new()),
        None => {
            let (hs, streams) = resume_handshake(&conn, s).await;
            match (hs, streams) {
                (Hs::Ok, Some(x)) => x,
                (Hs::Retry, _) => {
                    if let Some(prev) = claimed {
                        s.unclaim(prev);
                    }
                    // отправитель, который не доводит рукопожатие, не ходит по кругу вечно
                    if s.handshake_over() {
                        s.set_paused(PauseReason::Stalled);
                        return Outcome::Paused;
                    }
                    s.set_paused(PauseReason::Disconnected);
                    return lost(&conn).await;
                }
                (Hs::Forgot, _) => {
                    finish_session(inner, s, Finish::Failed(FailReason::PeerForgot)).await;
                    return Outcome::Over;
                }
                (Hs::PeerCancelled, _) => {
                    finish_session(inner, s, Finish::Cancelled(Side::Sender)).await;
                    return Outcome::Over;
                }
                (Hs::Completed, _) => {
                    let all = lock(&s.core).sched.all_terminal();
                    let how = if all {
                        Finish::Completed
                    } else {
                        Finish::Failed(FailReason::Protocol)
                    };
                    finish_session(inner, s, how).await;
                    return Outcome::Over;
                }
                _ => {
                    // отправитель нарушил протокол при возобновлении
                    finish_session(inner, s, Finish::Failed(FailReason::Protocol)).await;
                    return Outcome::Over;
                }
            }
        }
    };
    let att = Attempt::new();
    let seq0 = lock(&s.live).begin_attempt(tokio::time::Instant::now());
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Message>();
    {
        let mut c = lock(&s.core);
        c.ctl = Some(out_tx.clone());
        c.att = Some(att.clone());
    }
    if is_first {
        let _ = out_tx.send(Message::Decision {
            id: s.key.id,
            verdict: crate::codec::Verdict::Accept,
        });
    } else {
        if claimed.is_some() {
            s.emit(TransferEvent::Resumed { key: s.key });
        }
        s.set_active();
        // файлы, размещённые до обрыва: отправитель мог не получить FILE_DONE
        let placed: Vec<u32> = {
            let c = lock(&s.core);
            c.sched
                .runs
                .iter()
                .enumerate()
                .filter(|(_, r)| matches!(r, Run::Placed(_)))
                .filter_map(|(i, _)| u32::try_from(i).ok())
                .collect()
        };
        for index in placed {
            let _ = out_tx.send(Message::FileDone { index });
        }
    }
    s.set_active();
    s.kick_finalizers();

    // писатель и задачи попытки
    let (wtx, wrx) = std::sync::mpsc::channel::<crate::writer::WCmd>();
    {
        let (s2, a2) = (s.clone(), att.clone());
        let g1 = att.tracker.guard();
        let g2 = sh.tracker.guard();
        drop(sh.rt.spawn_blocking(move || {
            let _g = (g1, g2);
            crate::writer::writer_main(&s2, &a2, &wrx);
        }));
    }
    spawn_att(
        &sh,
        &att,
        crate::rstream::ctl_writer(ctl_tx, out_rx, att.clone(), s.clone()),
    );
    spawn_att(
        &sh,
        &att,
        crate::rstream::ctl_reader(ctl_rx, buf, att.clone(), s.clone()),
    );
    for _ in 0..cfg.streams {
        spawn_att(
            &sh,
            &att,
            crate::rstream::data_stream_loop(s.clone(), att.clone(), conn.clone(), wtx.clone()),
        );
    }
    spawn_att(
        &sh,
        &att,
        crate::rstream::liveness_watchdog(s.clone(), att.clone()),
    );
    drop(wtx);

    // наблюдение
    let mut end_w = s.end.watcher();
    let mut down_w = sh.shutdown.watcher();
    enum Why {
        Closed,
        Attempt(End),
        Local,
        Shutdown,
        Complete,
    }
    let why = tokio::select! {
        () = conn.closed() => Why::Closed,
        e = att.ended() => Why::Attempt(e),
        () = end_w.stopped() => Why::Local,
        () = down_w.stopped() => Why::Shutdown,
        () = all_terminal(s) => Why::Complete,
    };
    // Конец попытки замечен сейчас: уборка за ней (писатель, диск) не должна сдвигать сроки.
    let ended_at = tokio::time::Instant::now();
    // Потеря связи: отправитель мог закрыть поток управления или соединение, чтобы начать
    // попытку заново и обнулить сроки. Сроки и счётчики сессии это учитывают. Время без
    // живого соединения в сроки хэширования не идёт (см. `Liveness::link_back`).
    let lost_link = matches!(
        why,
        Why::Closed | Why::Attempt(End::Disconnected | End::Pause(PauseReason::Disconnected))
    );
    let gone = matches!(why, Why::Closed) || (lost_link && is_closed(&conn).await);
    let mut echoed = true;
    if let Why::Complete = why {
        s.ctl_send(Message::Done { id: s.key.id });
        tokio::select! {
            () = att.wait_echo() => {}
            () = tokio::time::sleep(cfg.msg_timeout) => {}
            () = conn.closed() => echoed = false,
        }
    }
    // остановка и ожидание всех задач попытки (в том числе писателя)
    att.stop.stop();
    att.tracker.idle().await;
    drop(hold);
    {
        let mut c = lock(&s.core);
        c.sched.reset_requests();
        c.att = None;
        c.ctl = None;
    }
    // изменение, поднятое уже после последней контрольной точки писателя
    if s.is_dirty() {
        let (s2, g) = (s.clone(), s.jobs.guard());
        sh.spawn_blocking(move || {
            let _g = g;
            let _ = s2.persist();
        });
    }
    let stalled = s.attempt_over(&att, seq0, lost_link, gone, ended_at);
    match why {
        Why::Complete => {
            if echoed {
                finish_session(inner, s, Finish::Completed).await;
                Outcome::Over
            } else {
                s.set_paused(PauseReason::Disconnected);
                Outcome::Disconnected
            }
        }
        Why::Local => {
            end_if_requested(inner, s).await;
            Outcome::Over
        }
        Why::Shutdown => Outcome::Over,
        _ if stalled => {
            s.set_paused(PauseReason::Stalled);
            Outcome::Paused
        }
        Why::Closed => {
            s.set_paused(PauseReason::Disconnected);
            Outcome::Disconnected
        }
        Why::Attempt(End::Disconnected) => {
            s.set_paused(PauseReason::Disconnected);
            lost(&conn).await
        }
        Why::Attempt(End::Pause(reason)) => {
            s.set_paused(reason);
            if reason == PauseReason::Disconnected {
                lost(&conn).await
            } else {
                Outcome::Paused
            }
        }
        Why::Attempt(End::PeerCancelled) => {
            finish_session(inner, s, Finish::Cancelled(Side::Sender)).await;
            Outcome::Over
        }
        Why::Attempt(End::Protocol) => {
            // CANCEL{Protocol} уже в очереди потока управления, писатель допишет его
            finish_session(inner, s, Finish::Failed(FailReason::Protocol)).await;
            Outcome::Over
        }
    }
}

/// Завершается, когда каждый файл размещён или закрыт как проваленный.
async fn all_terminal(s: &RecvSession) {
    loop {
        let n = s.wake.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if lock(&s.core).sched.all_terminal() {
            return;
        }
        n.await;
    }
}

pub(crate) fn spawn_att<F>(sh: &Shared, att: &Attempt, f: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let g1 = att.tracker.guard();
    let g2 = sh.tracker.guard();
    drop(sh.rt.spawn(async move {
        let _g = (g1, g2);
        f.await;
    }));
}
