//! Писатель получателя и итоговая проверка файла. Блок попадает сюда только после проверки
//! хэша. Отметка в карте ставится после возврата `write_all`; `sync_data` предшествует записи
//! состояния, поэтому состояние не заявляет блок, который ещё мог не дойти до диска.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::codec::FileErrCode;
use crate::events::{FileFailure, PauseReason, TransferEvent};
use crate::fsio::{ReadFail, verify_blocks};
use crate::paths::{
    create_part_new, open_part_existing, part_path, part_to_placing, placing_path, placing_present,
    remove_file_retry, remove_part_strict, remove_placing_strict, temp_for_placement,
};
use crate::placement::CompletedFile;
use crate::receiver::{Attempt, End, RecvSession};
use crate::sched::{Mark, Run};
use crate::shared::{HookPoint, Permits, lock};

pub(crate) enum WCmd {
    Write {
        file: u32,
        block: u32,
        data: Vec<u8>,
        /// Бюджет памяти (доля передачи и общий) освобождается после записи.
        permit: Permits,
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
        // только существующий `.part`: новый создаёт `prepare` (create_new), писатель его не
        // воссоздаёт
        match open_part_existing(&s.sdir, file) {
            Ok(f) => {
                e.insert(f);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // файл успели закрыть как проваленный: блок не нужен
                let still = matches!(lock(&s.core).sched.run(file), Some(Run::Active(_)));
                if !still {
                    return Ok(0);
                }
                return Err(err);
            }
            Err(err) => return Err(err),
        }
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
            s.live_progress();
            touched.insert(file);
            note_progress(s);
            Ok(u64::from(len))
        }
        Mark::Last { len } => {
            s.live_progress();
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
            .max(s.state_write_wait())
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
        // Запись состояния объединяется: события файлов лишь поднимают флаг «грязно», а
        // запись делает эта контрольная точка (не чаще раза за `checkpoint_interval`, либо
        // раньше по объёму записанных данных).
        let pending = !touched.is_empty() || s.is_dirty();
        if !pending {
            // ждать нечего: срок отсчитывается от первого события
            last = Instant::now();
        } else if (!touched.is_empty() && since >= cfg.checkpoint_bytes)
            || (last.elapsed() >= cfg.checkpoint_interval && s.reserve_state_write())
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
    // Файл уже переименован в `.placing` (крах между переименованием и записью `Placed`;
    // `prepare` перепроверил его чтением): `.part` не открывается и не создаётся, длина и
    // содержимое `.placing` не меняются. Он мог уже быть жёсткой ссылкой на размещённый файл.
    let from_placing = size > 0 && placing_present(&s.sdir, file);
    // 1. файл на диске: точная длина и `sync_all`
    let synced = (|| -> io::Result<()> {
        if from_placing {
            return Ok(());
        }
        let f = if size == 0 {
            // пустой файл: старые `.part` и `.placing` (если остались) убираются строго (оба
            // могли остаться вторым именем размещённого файла), создаётся новый `.part`
            s.sh.hook(HookPoint::RemovePart { file })?;
            remove_part_strict(&s.sdir, file)?;
            remove_placing_strict(&s.sdir, file)?;
            create_part_new(&s.sdir, file)?
        } else {
            match open_part_existing(&s.sdir, file) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => create_part_new(&s.sdir, file)?,
                Err(e) => return Err(e),
            }
        };
        f.set_len(size)?;
        // у пустого файла нет данных, которые надо сделать долговечными: его существование
        // закрепляет размещение (на Unix с синхронизацией каталога); 10 000 пустых файлов не
        // должны давать 10 000 fsync
        if size > 0 {
            f.sync_all()?;
        }
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
        s.mark_dirty();
        return;
    }
    let part = part_path(&s.sdir, file);
    let checked = if from_placing {
        placing_path(&s.sdir, file)
    } else {
        part.clone()
    };
    if s.sh.cfg.verify_after_write {
        s.emit(TransferEvent::Verifying { key: s.key });
        match verify_blocks(&checked, size, l, &leaves, None, &s.halt) {
            Ok(bad) if bad.is_empty() => {}
            Ok(_) if from_placing => {
                // `.placing` изменился после проверки в `prepare`: в него не пишут, имя
                // убирается, файл закрывается как повреждённый
                let _ = remove_placing_strict(&s.sdir, file);
                s.fail_file(file, FileFailure::Damaged, Some(FileErrCode::Damaged));
                return;
            }
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
                        s.mark_dirty();
                    }
                }
                return;
            }
        }
    }
    // Корень по хэшам в памяти здесь уже не проверяется: список хэшей воспроизвёл корень при
    // получении манифеста (`handle_manifest`), а настоящая проверка это перечитывание файла
    // с диска выше (`verify_after_write`, вне тестов крейта обязательно).
    // Состояние `Verified` лишь помечается: запись объединяется контрольной точкой. После
    // сбоя файл перепроверится с диска, состояние ничему не доверяется.
    s.mark_dirty();
    let _ = s.sh.hook(HookPoint::BeforePlace { file });
    if s.halt.load(std::sync::atomic::Ordering::Relaxed) {
        lock(&s.core).sched.unfinalize(file);
        s.mark_dirty();
        return;
    }
    let name = s
        .names
        .get(usize::try_from(file).unwrap_or(usize::MAX))
        .cloned();
    let Some(name) = name else { return };
    // До размещения `.part` атомарно переименовывается в `.placing` (тот же каталог): жёсткая
    // ссылка на размещённый файл никогда не получает имя `.part`, в которое пишет получатель.
    if !from_placing && let Err(e) = part_to_placing(&s.sdir, file) {
        abort_finalize(s, file, &e);
        return;
    }
    let cf = CompletedFile::new(
        s.key,
        file,
        name,
        size,
        root,
        temp_for_placement(&s.sdir, file),
    );
    // восстановленная с диска передача: служебные данные размещения готовятся лениво, до
    // первого `place` в этом процессе; ошибка считается ошибкой размещения
    let placed = s.ensure_prepared().and_then(|()| s.sh.placement.place(&cf));
    match placed {
        Ok(_) => {
            lock(&s.core).sched.set_placed(file);
            // `Placed` записывается сразу, а не контрольной точкой; `.placing` и хэши убираются
            // только после этой записи (до неё они нужны для перепроверки чтением после краха)
            s.placed_now(file);
            // на случай `.part` рядом с `.placing` (не должно быть): только имя, не запись
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
