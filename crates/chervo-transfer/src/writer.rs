//! Писатель получателя и итоговая проверка файла. Блок попадает сюда только после проверки
//! хэша. Отметка в карте ставится после возврата `write_all`; `sync_data` предшествует записи
//! состояния, поэтому состояние не заявляет блок, который ещё мог не дойти до диска.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use tokio::sync::OwnedSemaphorePermit;

use crate::codec::FileErrCode;
use crate::events::{FileFailure, PauseReason, TransferEvent};
use crate::fsio::{ReadFail, verify_blocks};
use crate::hash::file_root;
use crate::paths::{
    open_part_existing, open_part_write, part_path, remove_file_retry, remove_hashes,
    temp_for_placement,
};
use crate::placement::CompletedFile;
use crate::receiver::{Attempt, End, RecvSession};
use crate::sched::{Mark, Run};
use crate::shared::{HookPoint, lock};

pub(crate) enum WCmd {
    Write {
        file: u32,
        block: u32,
        data: Vec<u8>,
        /// Бюджет памяти освобождается после записи.
        permit: OwnedSemaphorePermit,
    },
}

/// Нет места на диске: `StorageFull` или код ОС (ENOSPC, EDQUOT Linux и macOS, коды Windows).
pub(crate) fn pause_reason(e: &io::Error) -> PauseReason {
    if e.kind() == io::ErrorKind::StorageFull
        || matches!(e.raw_os_error(), Some(28 | 122 | 69 | 39 | 112))
    {
        PauseReason::DiskFull
    } else {
        PauseReason::Io
    }
}

fn note_progress(s: &RecvSession) {
    let done = {
        let mut c = lock(&s.core);
        let due = c
            .last_progress
            .is_none_or(|t| t.elapsed() >= s.sh.cfg.progress_interval);
        if !due {
            return;
        }
        c.last_progress = Some(Instant::now());
        c.sched.done_bytes()
    };
    s.emit(TransferEvent::Progress {
        key: s.key,
        done,
        total: s.total,
    });
}

/// Пишет один проверенный блок. Возвращает число записанных байт.
fn write_one(
    s: &Arc<RecvSession>,
    files: &mut HashMap<u32, File>,
    touched: &mut BTreeSet<u32>,
    file: u32,
    block: u32,
    data: &[u8],
) -> io::Result<u64> {
    // файл ещё нужен, а блок ещё не записан?
    let offset = {
        let c = lock(&s.core);
        match c.sched.run(file) {
            Some(Run::Active(a)) if !a.have.get(block) => {
                u64::from(block).checked_mul(u64::from(a.layout.block_size))
            }
            _ => None,
        }
    };
    let Some(offset) = offset else {
        files.remove(&file);
        return Ok(0);
    };
    s.sh.hook(HookPoint::Write { file, block, data })?;
    if let std::collections::hash_map::Entry::Vacant(e) = files.entry(file) {
        e.insert(open_part_write(&s.sdir, file)?);
    }
    let f = files
        .get_mut(&file)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)?;
    let marked = lock(&s.core).sched.mark_written(file, block);
    let _ = s.sh.hook(HookPoint::Written { file, block });
    match marked {
        Mark::Ignored => Ok(0),
        Mark::Written { len } => {
            touched.insert(file);
            note_progress(s);
            Ok(u64::from(len))
        }
        Mark::Last { len } => {
            // итоговая проверка сама сделает `sync_all`; наш дескриптор закрывается
            touched.remove(&file);
            files.remove(&file);
            note_progress(s);
            s.spawn_finalize(file);
            Ok(u64::from(len))
        }
    }
}

/// `sync_data` записанных файлов, затем файл состояния.
fn checkpoint(
    s: &Arc<RecvSession>,
    files: &HashMap<u32, File>,
    touched: &mut BTreeSet<u32>,
) -> io::Result<()> {
    for f in touched.iter() {
        if let Some(h) = files.get(f) {
            h.sync_data()?;
            s.sh.hook(HookPoint::Synced { file: *f })?;
        }
    }
    {
        let mut c = lock(&s.core);
        for f in touched.iter() {
            c.sched.mark_durable(*f);
        }
    }
    touched.clear();
    s.persist()
}

/// Поток писателя одной попытки. Выходит, когда все отправители блоков закрыты (после
/// обработки всего, что уже в очереди) или при ошибке записи. Перед выходом последняя
/// контрольная точка.
pub(crate) fn writer_main(s: &Arc<RecvSession>, att: &Arc<Attempt>, rx: &Receiver<WCmd>) {
    let cfg = &s.sh.cfg;
    let mut files: HashMap<u32, File> = HashMap::new();
    let mut touched: BTreeSet<u32> = BTreeSet::new();
    let mut since = 0u64;
    let mut last = Instant::now();
    loop {
        let wait = cfg
            .checkpoint_interval
            .saturating_sub(last.elapsed())
            .max(Duration::from_millis(1));
        match rx.recv_timeout(wait) {
            Ok(WCmd::Write {
                file,
                block,
                data,
                permit,
            }) => {
                let r = write_one(s, &mut files, &mut touched, file, block, &data);
                drop(data);
                drop(permit);
                match r {
                    Ok(n) => since = since.saturating_add(n),
                    Err(e) => {
                        att.finish(End::Pause(pause_reason(&e)));
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if !touched.is_empty()
            && (since >= cfg.checkpoint_bytes || last.elapsed() >= cfg.checkpoint_interval)
        {
            if let Err(e) = checkpoint(s, &files, &mut touched) {
                att.finish(End::Pause(pause_reason(&e)));
                break;
            }
            since = 0;
            last = Instant::now();
        }
    }
    // последняя контрольная точка: что записано, то и сохраняется (ошибки не маскируют причину)
    let _ = checkpoint(s, &files, &mut touched);
}

enum FinFail {
    Io(io::Error),
    Stopped,
}

fn read_fail(e: ReadFail) -> FinFail {
    match e {
        ReadFail::Io(k) => FinFail::Io(io::Error::from(k)),
        ReadFail::Stopped => FinFail::Stopped,
        ReadFail::Changed => FinFail::Io(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

/// Итоговая проверка и размещение файла, у которого записаны все блоки (блокирующая).
pub(crate) fn finalize_file(s: &Arc<RecvSession>, file: u32) {
    let size = s
        .sizes
        .get(usize::try_from(file).unwrap_or(usize::MAX))
        .copied()
        .unwrap_or(0);
    let (l, root, leaves) = {
        let c = lock(&s.core);
        match c.sched.run(file) {
            Some(Run::Finalizing(a)) => (a.layout, a.root, a.leaves.clone()),
            _ => return,
        }
    };
    // 1. файл на диске: точная длина и `sync_all`
    let synced = (|| -> io::Result<()> {
        let f = if size == 0 {
            open_part_write(&s.sdir, file)?
        } else {
            match open_part_existing(&s.sdir, file) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => open_part_write(&s.sdir, file)?,
                Err(e) => return Err(e),
            }
        };
        f.set_len(size)?;
        f.sync_all()?;
        s.sh.hook(HookPoint::Synced { file })?;
        Ok(())
    })();
    if let Err(e) = synced {
        abort_finalize(s, file, &e);
        return;
    }
    lock(&s.core).sched.mark_durable(file);
    // 2. перечитать файл с диска и сверить каждый блок
    let _ = s.sh.hook(HookPoint::FinalVerify { file });
    if s.halt.load(std::sync::atomic::Ordering::Relaxed) {
        lock(&s.core).sched.unfinalize(file);
        let _ = s.persist();
        return;
    }
    let part = part_path(&s.sdir, file);
    if s.sh.cfg.verify_after_write {
        s.emit(TransferEvent::Verifying { key: s.key });
        match verify_blocks(&part, size, l, &leaves, None, &s.halt) {
            Ok(bad) if bad.is_empty() => {}
            Ok(bad) => {
                let ok = lock(&s.core).sched.finalize_mismatch(file, &bad);
                if ok {
                    s.wake.notify_waiters();
                } else {
                    s.fail_file(file, FileFailure::Damaged, Some(FileErrCode::Damaged));
                }
                return;
            }
            Err(e) => {
                match read_fail(e) {
                    FinFail::Io(e) => abort_finalize(s, file, &e),
                    FinFail::Stopped => {
                        lock(&s.core).sched.unfinalize(file);
                        let _ = s.persist();
                    }
                }
                return;
            }
        }
    }
    // 3. корень всего файла
    let root_ok = file_root(size, l, &leaves).is_ok_and(|r| r == root);
    if !root_ok {
        s.fail_file(file, FileFailure::Damaged, Some(FileErrCode::Damaged));
        return;
    }
    // 4. состояние `Verified` на диск, затем размещение
    if let Err(e) = s.persist() {
        abort_finalize(s, file, &e);
        return;
    }
    let _ = s.sh.hook(HookPoint::BeforePlace { file });
    if s.halt.load(std::sync::atomic::Ordering::Relaxed) {
        lock(&s.core).sched.unfinalize(file);
        let _ = s.persist();
        return;
    }
    let name = s
        .names
        .get(usize::try_from(file).unwrap_or(usize::MAX))
        .cloned();
    let Some(name) = name else { return };
    let cf = CompletedFile::new(
        s.key,
        file,
        name,
        size,
        root,
        temp_for_placement(&s.sdir, file),
    );
    match s.sh.placement.place(&cf) {
        Ok(_) => {
            lock(&s.core).sched.set_placed(file);
            let _ = s.persist();
            remove_hashes(&s.sdir, file);
            let _ = remove_file_retry(&part);
            s.ctl_send(crate::codec::Message::FileDone { index: file });
            s.emit(TransferEvent::FileReceived {
                key: s.key,
                index: file,
            });
            s.wake.notify_waiters();
        }
        Err(_) => s.fail_file(
            file,
            FileFailure::PlaceFailed,
            Some(FileErrCode::PlaceFailed),
        ),
    }
}

/// Ошибка ввода-вывода при итоговой проверке: файл возвращается к `Active` (без блоков в
/// работе), передача встаёт на паузу; `retry` запустит проверку снова.
fn abort_finalize(s: &Arc<RecvSession>, file: u32, e: &io::Error) {
    let reason = pause_reason(e);
    let att = {
        let mut c = lock(&s.core);
        c.sched.unfinalize(file);
        c.att.clone()
    };
    match att {
        Some(a) => a.finish(End::Pause(reason)),
        None => s.set_paused(reason),
    }
}
