//! Задачи попытки получателя: запись и чтение потока управления и потоки данных. Получатель
//! сам просит блоки; ответы идут по порядку запросов потока. Блок уходит писателю только
//! после совпадения хэша.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use chervo_transport::{Connection, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, TryAcquireError, mpsc};
use tokio::time::timeout;

use crate::codec::{BlockErrCode, CancelReason, FileErrCode, Message, ProtocolError, encode};
use crate::events::{FileFailure, PauseReason};
use crate::hash::{BlockHash, FileRoot, file_root, leaf_hash};
use crate::layout::check_manifest_layout;
use crate::limits::STREAM_TRANSFER_DATA;
use crate::receiver::{Attempt, End, RecvSession};
use crate::sched::{BadBlock, Work};
use crate::shared::{kib, lock};
use crate::wire_io::{read_exact, read_message};
use crate::writer::WCmd;

/// Запись сообщения в поток с ограничением по времени.
pub(crate) async fn write_msg<T: SendStream>(tx: &mut T, m: &Message, limit: Duration) -> bool {
    let mut out = Vec::new();
    if encode(m, &mut out).is_err() {
        return false;
    }
    matches!(timeout(limit, tx.write_all(&out)).await, Ok(Ok(())))
}

/// Нарушение протокола отправителем: CANCEL{Protocol} и конец передачи.
fn protocol_fail(s: &RecvSession, att: &Attempt) {
    s.ctl_send(Message::Cancel {
        id: s.key.id,
        reason: CancelReason::Protocol,
    });
    att.finish(End::Protocol);
}

/// Пишет сообщения потока управления; на остановке дописывает очередь (CANCEL, DONE).
pub(crate) async fn ctl_writer<T: SendStream>(
    tx: T,
    rx: mpsc::UnboundedReceiver<Message>,
    att: Arc<Attempt>,
    s: Arc<RecvSession>,
) {
    let ok = write_loop(
        tx,
        rx,
        att.stop.watcher(),
        s.sh.cfg.stall_timeout,
        s.sh.cfg.msg_timeout,
    )
    .await;
    if !ok {
        att.finish(End::Disconnected);
    }
}

/// Общий цикл записи потока управления (обе роли). `false`: запись не удалась.
pub(crate) async fn write_loop<T: SendStream>(
    mut tx: T,
    mut rx: mpsc::UnboundedReceiver<Message>,
    mut stop: crate::util::StopWatch,
    stall: Duration,
    flush: Duration,
) -> bool {
    let mut ok = true;
    loop {
        tokio::select! {
            m = rx.recv() => match m {
                Some(m) => {
                    if !write_msg(&mut tx, &m, stall).await {
                        ok = false;
                        break;
                    }
                }
                None => break,
            },
            () = stop.stopped() => {
                while let Ok(m) = rx.try_recv() {
                    if !write_msg(&mut tx, &m, flush).await {
                        break;
                    }
                }
                break;
            }
        }
    }
    let _ = tx.finish();
    ok
}

fn file_failure(code: FileErrCode) -> Option<FileFailure> {
    match code {
        FileErrCode::SourceChanged => Some(FileFailure::SourceChanged),
        FileErrCode::ReadError => Some(FileFailure::SourceUnreadable),
        _ => None,
    }
}

/// Что ctl_reader помнит о кадрах HASH_PROGRESS этой попытки.
#[derive(Default)]
struct HashFrames {
    prev: Option<u64>,
    at_total: bool,
}

/// Правила кадра HASH_PROGRESS: первый кадр попытки не меньше значения сессии, дальше строго
/// больше предыдущего, не больше `total`, после `total` кадров нет. `false`: нарушение.
fn accept_hash_progress(s: &RecvSession, att: &Attempt, st: &mut HashFrames, hashed: u64) -> bool {
    if st.at_total || hashed > s.total {
        return false;
    }
    {
        let mut c = lock(&s.core);
        let ok = match st.prev {
            None => hashed >= c.sched.hashed,
            Some(p) => hashed > p,
        };
        if !ok {
            return false;
        }
        c.sched.hashed = hashed;
    }
    st.prev = Some(hashed);
    st.at_total = hashed == s.total;
    att.note_hash(hashed);
    s.wake.notify_waiters();
    s.note_preparing(hashed);
    true
}

/// Сторож ожидания хэширования у отправителя (одна задача на попытку). Работает, пока есть
/// незавершённый непустой файл, не покрытый отправителем. Пауза `Stalled`: нет кадров
/// HASH_PROGRESS `stall_timeout`, либо средняя скорость ниже `min_hash_rate`.
pub(crate) async fn hash_watchdog(s: Arc<RecvSession>, att: Arc<Attempt>) {
    let cfg = &s.sh.cfg;
    let mut stop = att.stop.watcher();
    loop {
        let news = s.wake.notified();
        tokio::pin!(news);
        news.as_mut().enable();
        if !lock(&s.core).sched.needs_hash() {
            return;
        }
        let deadline = att.hash_deadline(cfg.stall_timeout, cfg.min_hash_rate, s.total);
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                let due = lock(&s.core).sched.needs_hash()
                    && tokio::time::Instant::now()
                        >= att.hash_deadline(cfg.stall_timeout, cfg.min_hash_rate, s.total);
                if due {
                    att.finish(End::Pause(PauseReason::Stalled));
                    return;
                }
            }
            () = &mut news => {}
            () = stop.stopped() => return,
        }
    }
}

/// Читает сообщения отправителя на потоке управления. Допустимы CANCEL, FILE_ERROR с кодами
/// отправителя, HASH_PROGRESS и DONE; всё остальное это нарушение протокола.
pub(crate) async fn ctl_reader<R: RecvStream>(
    mut rx: R,
    mut buf: Vec<u8>,
    att: Arc<Attempt>,
    s: Arc<RecvSession>,
) {
    let mut stop = att.stop.watcher();
    let mut frames = HashFrames::default();
    loop {
        let r = tokio::select! {
            r = read_message(&mut rx, &mut buf, s.sh.cfg.msg_timeout) => r,
            () = stop.stopped() => return,
        };
        match r {
            Ok(Some(Message::Cancel { id, .. })) if id == s.key.id => {
                att.finish(End::PeerCancelled);
                return;
            }
            Ok(Some(Message::FileError { index, code })) if index < s.file_count() => {
                match file_failure(code) {
                    Some(why) => s.fail_file(index, why, None),
                    None => {
                        protocol_fail(&s, &att);
                        return;
                    }
                }
            }
            Ok(Some(Message::HashProgress { hashed })) => {
                if !accept_hash_progress(&s, &att, &mut frames, hashed) {
                    protocol_fail(&s, &att);
                    return;
                }
            }
            Ok(Some(Message::Done { id })) if id == s.key.id => att.note_echo(),
            // поток закрыт или оборван: соединение живо, но передача на паузе
            Ok(None) | Err(ProtocolError::Closed | ProtocolError::TimedOut) => {
                att.finish(End::Disconnected);
                return;
            }
            Ok(Some(_)) | Err(_) => {
                protocol_fail(&s, &att);
                return;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEnd {
    Stopped,
    Done,
    Failed,
    Stalled,
    Protocol,
}

enum Pend {
    Manifest {
        file: u32,
    },
    Block {
        file: u32,
        block: u32,
        len: u32,
        _permit: OwnedSemaphorePermit,
    },
}

enum Fill {
    Full,
    NoBudget,
    Idle { all_done: bool },
}

fn map_read(e: ProtocolError) -> StreamEnd {
    match e {
        ProtocolError::TimedOut => StreamEnd::Stalled,
        ProtocolError::Closed => StreamEnd::Failed,
        _ => StreamEnd::Protocol,
    }
}

/// Обёртка потока данных: оборванный или молчащий поток заменяется новым. Подряд идущие
/// обрывы без единого принятого блока (3 на поток) ставят передачу на паузу `Stalled`.
pub(crate) async fn data_stream_loop<C: Connection>(
    s: Arc<RecvSession>,
    att: Arc<Attempt>,
    conn: C,
    wtx: Sender<WCmd>,
) {
    let limit = 3 * u32::from(s.sh.cfg.streams);
    let mut stop = att.stop.watcher();
    loop {
        if att.stop.is_stopped() {
            return;
        }
        let end = data_stream(&s, &att, &conn, &wtx).await;
        match end {
            StreamEnd::Stopped | StreamEnd::Done => return,
            StreamEnd::Protocol => {
                protocol_fail(&s, &att);
                return;
            }
            StreamEnd::Failed | StreamEnd::Stalled => {
                let closed = timeout(Duration::ZERO, conn.closed()).await.is_ok();
                if closed {
                    att.finish(End::Disconnected);
                    return;
                }
                let n = att
                    .stalls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(1);
                if n >= limit {
                    att.finish(End::Pause(PauseReason::Stalled));
                    return;
                }
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(50)) => {}
                    () = stop.stopped() => return,
                }
            }
        }
    }
}

async fn send_request<T: SendStream>(
    tx: &mut T,
    m: &Message,
    limit: Duration,
) -> Result<(), StreamEnd> {
    if write_msg(tx, m, limit).await {
        Ok(())
    } else {
        Err(StreamEnd::Failed)
    }
}

async fn fill<T: SendStream>(
    s: &Arc<RecvSession>,
    tx: &mut T,
    pending: &mut VecDeque<Pend>,
    stop: &mut crate::util::StopWatch,
) -> Result<Fill, StreamEnd> {
    let cfg = &s.sh.cfg;
    let window = usize::from(cfg.per_stream_window);
    while pending.len() < window {
        let work = lock(&s.core).sched.take();
        match work {
            Work::Wait => return Ok(Fill::Idle { all_done: false }),
            Work::AllDone => return Ok(Fill::Idle { all_done: true }),
            Work::Zero { file } => s.start_zero(file),
            Work::Manifest { file } => {
                pending.push_back(Pend::Manifest { file });
                send_request(tx, &Message::GetManifest { index: file }, cfg.msg_timeout).await?;
            }
            Work::Block { file, block, len } => {
                let need = kib(len);
                let permit = match s.sh.recv_budget.clone().try_acquire_many_owned(need) {
                    Ok(p) => p,
                    Err(TryAcquireError::NoPermits) => {
                        if pending.is_empty() {
                            let got = tokio::select! {
                                p = s.sh.recv_budget.clone().acquire_many_owned(need) => p.ok(),
                                () = stop.stopped() => None,
                            };
                            match got {
                                Some(p) => p,
                                None => {
                                    lock(&s.core).sched.release_block(file, block);
                                    return Err(StreamEnd::Stopped);
                                }
                            }
                        } else {
                            // свои же невычитанные ответы держат бюджет: сначала читать
                            lock(&s.core).sched.release_block(file, block);
                            return Ok(Fill::NoBudget);
                        }
                    }
                    Err(TryAcquireError::Closed) => {
                        lock(&s.core).sched.release_block(file, block);
                        return Err(StreamEnd::Stopped);
                    }
                };
                pending.push_back(Pend::Block {
                    file,
                    block,
                    len,
                    _permit: permit,
                });
                send_request(
                    tx,
                    &Message::GetBlock { index: file, block },
                    cfg.msg_timeout,
                )
                .await?;
            }
        }
    }
    Ok(Fill::Full)
}

async fn data_stream<C: Connection>(
    s: &Arc<RecvSession>,
    att: &Arc<Attempt>,
    conn: &C,
    wtx: &Sender<WCmd>,
) -> StreamEnd {
    let cfg = &s.sh.cfg;
    let Ok(Ok((mut tx, mut rx))) = timeout(cfg.msg_timeout, conn.open_bi()).await else {
        return StreamEnd::Failed;
    };
    let mut head = vec![STREAM_TRANSFER_DATA];
    if encode(&Message::Bind { id: s.key.id }, &mut head).is_err() {
        return StreamEnd::Protocol;
    }
    if !matches!(
        timeout(cfg.msg_timeout, tx.write_all(&head)).await,
        Ok(Ok(()))
    ) {
        return StreamEnd::Failed;
    }
    let mut pending: VecDeque<Pend> = VecDeque::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut stop = att.stop.watcher();
    let end = loop {
        let news = s.wake.notified();
        tokio::pin!(news);
        news.as_mut().enable();
        match fill(s, &mut tx, &mut pending, &mut stop).await {
            Err(e) => break e,
            Ok(Fill::Idle { all_done: true }) if pending.is_empty() => break StreamEnd::Done,
            Ok(Fill::Full | Fill::NoBudget | Fill::Idle { .. }) => {}
        }
        if pending.is_empty() {
            tokio::select! {
                () = &mut news => continue,
                () = stop.stopped() => break StreamEnd::Stopped,
            }
        }
        let got = tokio::select! {
            r = timeout(cfg.stall_timeout, read_message(&mut rx, &mut buf, cfg.msg_timeout)) => r,
            () = stop.stopped() => break StreamEnd::Stopped,
        };
        let msg = match got {
            Err(_) => break StreamEnd::Stalled,
            Ok(Err(e)) => break map_read(e),
            Ok(Ok(None)) => break StreamEnd::Failed,
            Ok(Ok(Some(m))) => m,
        };
        let Some(front) = pending.pop_front() else {
            break StreamEnd::Protocol;
        };
        let step = match (front, msg) {
            (
                Pend::Manifest { file },
                Message::Manifest {
                    index,
                    block_size,
                    block_count,
                    root,
                },
            ) if index == file => {
                handle_manifest(s, att, &mut rx, file, block_size, block_count, root).await
            }
            (Pend::Manifest { file }, Message::BlockErr { index, code, .. }) if index == file => {
                s.fail_file(file, block_failure(code), None);
                Ok(())
            }
            (
                Pend::Block {
                    file,
                    block,
                    len,
                    _permit,
                },
                Message::Block {
                    index,
                    block: b,
                    len: l,
                },
            ) if index == file && b == block => {
                if l != len {
                    // длина не равна `block_len`: тело не читается
                    Err(StreamEnd::Protocol)
                } else {
                    handle_block(s, att, wtx, &mut rx, file, block, len, _permit).await
                }
            }
            (
                Pend::Block { file, block, .. },
                Message::BlockErr {
                    index,
                    block: b,
                    code,
                },
            ) if index == file && b == block => {
                s.fail_file(file, block_failure(code), None);
                Ok(())
            }
            _ => Err(StreamEnd::Protocol),
        };
        if let Err(e) = step {
            break e;
        }
    };
    // запросы без ответа снова свободны
    {
        let mut c = lock(&s.core);
        for p in pending.drain(..) {
            match p {
                Pend::Manifest { file } => c.sched.release_manifest(file),
                Pend::Block { file, block, .. } => c.sched.release_block(file, block),
            }
        }
    }
    s.wake.notify_waiters();
    let _ = tx.finish();
    end
}

fn block_failure(code: BlockErrCode) -> FileFailure {
    match code {
        BlockErrCode::SourceChanged => FileFailure::SourceChanged,
        BlockErrCode::ReadError => FileFailure::SourceUnreadable,
    }
}

async fn handle_manifest<R: RecvStream>(
    s: &Arc<RecvSession>,
    att: &Arc<Attempt>,
    rx: &mut R,
    file: u32,
    block_size: u32,
    block_count: u32,
    root: FileRoot,
) -> Result<(), StreamEnd> {
    let size = s
        .sizes
        .get(usize::try_from(file).unwrap_or(usize::MAX))
        .copied()
        .ok_or(StreamEnd::Protocol)?;
    // раскладку считаем сами; число хэшей решаем мы, до чтения
    let l =
        check_manifest_layout(size, block_size, block_count).map_err(|_| StreamEnd::Protocol)?;
    let n = usize::try_from(l.block_count)
        .ok()
        .and_then(|c| c.checked_mul(32))
        .ok_or(StreamEnd::Protocol)?;
    let mut raw = vec![0u8; n];
    read_exact(rx, &mut raw, s.sh.cfg.stall_timeout)
        .await
        .map_err(map_read)?;
    let (chunks, _) = raw.as_chunks::<32>();
    let leaves: Vec<BlockHash> = chunks.iter().map(|c| BlockHash(*c)).collect();
    // список хэшей обязан воспроизвести корень, который прислал отправитель
    match file_root(size, l, &leaves) {
        Ok(r) if r == root => {}
        _ => return Err(StreamEnd::Protocol),
    }
    att.stalls.store(0, std::sync::atomic::Ordering::Relaxed);
    match s.setup_file(file, l, root, leaves).await {
        Ok(()) => Ok(()),
        Err(reason) => {
            att.finish(End::Pause(reason));
            Err(StreamEnd::Stopped)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_block<R: RecvStream>(
    s: &Arc<RecvSession>,
    att: &Arc<Attempt>,
    wtx: &Sender<WCmd>,
    rx: &mut R,
    file: u32,
    block: u32,
    len: u32,
    permit: OwnedSemaphorePermit,
) -> Result<(), StreamEnd> {
    let n = usize::try_from(len).map_err(|_| StreamEnd::Protocol)?;
    let mut data = vec![0u8; n];
    read_exact(rx, &mut data, s.sh.cfg.stall_timeout)
        .await
        .map_err(map_read)?;
    let job = tokio::task::spawn_blocking(move || {
        let h = leaf_hash(block, &data);
        (data, h)
    });
    let (data, got) = job.await.map_err(|_| StreamEnd::Failed)?;
    att.stalls.store(0, std::sync::atomic::Ordering::Relaxed);
    let want = lock(&s.core).sched.leaf(file, block);
    match want {
        // файл уже закрыт или блок не нужен: данные отбрасываются
        None => Ok(()),
        Some(w) if w == got => wtx
            .send(WCmd::Write {
                file,
                block,
                data,
                permit,
            })
            .map_err(|_| StreamEnd::Stopped),
        Some(_) => {
            let r = lock(&s.core).sched.bad_block(file, block);
            match r {
                BadBlock::Requeue => s.wake.notify_waiters(),
                BadBlock::FileFailed => {
                    s.fail_file(file, FileFailure::Damaged, Some(FileErrCode::Damaged));
                }
            }
            Ok(())
        }
    }
}
