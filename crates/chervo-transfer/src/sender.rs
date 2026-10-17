//! Сессия отправителя: предложение, хэширование файлов заранее, ответы на запросы получателя
//! и возобновление. Сессии только в памяти (после перезапуска начинать заново).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chervo_connect::{ConnHold, IncomingStream};
use chervo_transport::{Connection, RecvStream, SendStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::codec::{
    BlockErrCode, CancelReason, FileErrCode, Message, ProtocolError, Verdict, encode,
};
use crate::events::{
    FailReason, FileFailure, PauseReason, Side, TransferEvent, TransferState, TransferStatus,
};
use crate::fsio::{ReadFail, hash_source, read_source_block};
use crate::hash::{BlockHash, FileRoot, leaf_hash};
use crate::layout::{Layout, block_len, layout};
use crate::limits::{MAX_MESSAGE_LEN, STREAM_TRANSFER_CTL};
use crate::links::Links;
use crate::names::{OfferedFile, TransferKey, UntrustedName};
use crate::receiver::Finish;
use crate::rstream::{write_loop, write_msg};
use crate::shared::{Shared, kib, lock};
use crate::util::{Stop, StopWatch, Tracker};
use crate::wire_io::read_message;

pub(crate) use crate::inner::Inner;

/// Наибольшее окно запросов на поток данных (верхняя граница настройки `per_stream_window`).
const MAX_STREAM_WINDOW: usize = 8;

/// Свой файл: путь известен только нам.
pub(crate) struct SrcFile {
    pub(crate) path: PathBuf,
    pub(crate) name: UntrustedName,
    pub(crate) size: u64,
}

pub(crate) struct Hashes {
    pub(crate) layout: Layout,
    pub(crate) leaves: Vec<BlockHash>,
    pub(crate) root: FileRoot,
}

#[derive(Clone)]
pub(crate) enum FileHash {
    Pending,
    Ready(Arc<Hashes>),
    Failed(FileFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SPhase {
    /// Предложение отправлено, ответа нет.
    Offering,
    Accepted,
    /// Соединение или поток управления потеряны, ждём RESUME.
    Paused,
    Finished,
}

pub(crate) struct SAttempt {
    pub(crate) stop: Stop,
    pub(crate) tracker: Tracker,
    conn_id: u64,
    pub(crate) ctl: mpsc::UnboundedSender<Message>,
    streams: AtomicUsize,
    _hold: Option<ConnHold>,
}

impl SAttempt {
    fn new(conn_id: u64, hold: Option<ConnHold>) -> (Arc<Self>, mpsc::UnboundedReceiver<Message>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                stop: Stop::new(),
                tracker: Tracker::new(),
                conn_id,
                ctl: tx,
                streams: AtomicUsize::new(0),
                _hold: hold,
            }),
            rx,
        )
    }
}

pub(crate) struct SCore {
    att: Option<Arc<SAttempt>>,
    serve: HashMap<(u32, u32), u8>,
    failed: HashMap<u32, FileFailure>,
    delivered: HashSet<u32>,
    served: u64,
    last_progress: Option<Instant>,
    paused_gen: u64,
    completed: bool,
}

pub(crate) struct SendSession {
    pub(crate) sh: Arc<Shared>,
    pub(crate) key: TransferKey,
    files: Vec<SrcFile>,
    pub(crate) total: u64,
    hashes: Vec<watch::Sender<FileHash>>,
    pub(crate) phase: watch::Sender<SPhase>,
    core: Mutex<SCore>,
    halt: Arc<AtomicBool>,
    stop: Stop,
}

impl SendSession {
    pub(crate) fn new(
        sh: Arc<Shared>,
        key: TransferKey,
        files: Vec<SrcFile>,
        total: u64,
    ) -> Arc<Self> {
        let hashes = files
            .iter()
            .map(|_| watch::channel(FileHash::Pending).0)
            .collect();
        Arc::new(Self {
            sh,
            key,
            files,
            total,
            hashes,
            phase: watch::channel(SPhase::Offering).0,
            core: Mutex::new(SCore {
                att: None,
                serve: HashMap::new(),
                failed: HashMap::new(),
                delivered: HashSet::new(),
                served: 0,
                last_progress: None,
                paused_gen: 0,
                completed: false,
            }),
            halt: Arc::new(AtomicBool::new(false)),
            stop: Stop::new(),
        })
    }

    pub(crate) fn phase(&self) -> SPhase {
        *self.phase.borrow()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.phase() == SPhase::Finished
    }

    fn file_count(&self) -> u32 {
        u32::try_from(self.files.len()).unwrap_or(u32::MAX)
    }

    fn emit(&self, e: TransferEvent) {
        self.sh.emit(e);
    }

    pub(crate) fn status(&self) -> TransferStatus {
        let state = match self.phase() {
            SPhase::Offering => TransferState::AwaitingAnswer,
            SPhase::Accepted => TransferState::Active,
            SPhase::Paused => TransferState::Paused(PauseReason::Disconnected),
            SPhase::Finished => TransferState::Finished,
        };
        let done = lock(&self.core).served.min(self.total);
        TransferStatus {
            side: Side::Sender,
            state,
            done,
            total: self.total,
        }
    }

    /// Остановка узла: попытка закрывается (получатель увидит конец потока и встанет на паузу).
    pub(crate) fn shutdown(&self) {
        self.halt.store(true, Ordering::Relaxed);
        self.stop.stop();
        if let Some(a) = &lock(&self.core).att {
            a.stop.stop();
        }
    }

    /// Перед отменой: получателю уходит CANCEL{User}.
    pub(crate) fn cancel_notice(&self) {
        self.ctl_send(Message::Cancel {
            id: self.key.id,
            reason: CancelReason::User,
        });
    }

    fn ctl_send(&self, m: Message) {
        if let Some(a) = &lock(&self.core).att {
            let _ = a.ctl.send(m);
        }
    }

    /// Сообщает об ошибке файла один раз: событие и FILE_ERROR получателю.
    fn report_failure(&self, index: u32, why: FileFailure) {
        let new = lock(&self.core).failed.insert(index, why).is_none();
        if !new {
            return;
        }
        self.emit(TransferEvent::FileFailed {
            key: self.key,
            index,
            reason: why,
        });
        let code = match why {
            FileFailure::SourceChanged => FileErrCode::SourceChanged,
            _ => FileErrCode::ReadError,
        };
        self.ctl_send(Message::FileError { index, code });
    }

    fn note_progress(&self, add: u64) {
        let done = {
            let mut c = lock(&self.core);
            c.served = c.served.saturating_add(add);
            let due = c
                .last_progress
                .is_none_or(|t| t.elapsed() >= self.sh.cfg.progress_interval);
            if !due {
                return;
            }
            c.last_progress = Some(Instant::now());
            c.served.min(self.total)
        };
        self.emit(TransferEvent::Progress {
            key: self.key,
            done,
            total: self.total,
        });
    }

    /// Нарушение протокола получателем: CANCEL{Protocol} и конец передачи.
    fn protocol_fail<L: Links>(self: &Arc<Self>, inner: &Arc<Inner<L>>, reason: CancelReason) {
        self.ctl_send(Message::Cancel {
            id: self.key.id,
            reason,
        });
        let how = if reason == CancelReason::Limits {
            FailReason::Limits
        } else {
            FailReason::Protocol
        };
        finish_send(inner, self, Finish::Failed(how));
    }
}

/// Завершает передачу на стороне отправителя. Завершённая успешно остаётся в памяти на
/// `resume_hold`: потерянный ответ DONE получатель повторит при RESUME.
pub(crate) fn finish_send<L: Links>(inner: &Arc<Inner<L>>, s: &Arc<SendSession>, how: Finish) {
    let att = {
        let mut c = lock(&s.core);
        if s.phase() == SPhase::Finished {
            return;
        }
        s.phase.send_replace(SPhase::Finished);
        c.completed = how == Finish::Completed;
        c.att.take()
    };
    s.halt.store(true, Ordering::Relaxed);
    s.stop.stop();
    if let Some(a) = att {
        // писатель дописывает очередь (CANCEL, DONE) и закрывает поток
        a.stop.stop();
    }
    s.emit(match how {
        Finish::Completed => TransferEvent::Completed { key: s.key },
        Finish::Cancelled(by) => TransferEvent::Cancelled { key: s.key, by },
        Finish::Failed(reason) => TransferEvent::Failed { key: s.key, reason },
    });
    if how == Finish::Completed {
        let (inner, s) = (inner.clone(), s.clone());
        let rt = s.sh.rt.clone();
        let hold = s.sh.cfg.resume_hold;
        let mut down = s.sh.shutdown.watcher();
        let g = s.sh.tracker.guard();
        drop(rt.spawn(async move {
            let _g = g;
            tokio::select! {
                () = tokio::time::sleep(hold) => inner.remove_out(&s.key),
                () = down.stopped() => {}
            }
        }));
    } else {
        inner.remove_out(&s.key);
    }
}

/// Поток управления или соединение потеряны: пауза до RESUME (или отказ, если ответа на
/// предложение не было).
fn attempt_lost<L: Links>(inner: &Arc<Inner<L>>, s: &Arc<SendSession>, att: &Arc<SAttempt>) {
    att.stop.stop();
    let (current, gen_now, phase) = {
        let mut c = lock(&s.core);
        let cur = c.att.as_ref().is_some_and(|a| Arc::ptr_eq(a, att));
        if cur {
            c.att = None;
            c.paused_gen = c.paused_gen.saturating_add(1);
        }
        (cur, c.paused_gen, s.phase())
    };
    if !current {
        return;
    }
    match phase {
        SPhase::Offering => finish_send(inner, s, Finish::Failed(FailReason::Protocol)),
        SPhase::Accepted => {
            s.phase.send_replace(SPhase::Paused);
            s.emit(TransferEvent::Paused {
                key: s.key,
                reason: PauseReason::Disconnected,
            });
            // сессия живёт `resume_hold`, потом забывается
            let (inner, s) = (inner.clone(), s.clone());
            let rt = s.sh.rt.clone();
            let hold = s.sh.cfg.resume_hold;
            let mut down = s.sh.shutdown.watcher();
            let mut ended = s.stop.watcher();
            let g = s.sh.tracker.guard();
            drop(rt.spawn(async move {
                let _g = g;
                tokio::select! {
                    () = tokio::time::sleep(hold) => {
                        let still = lock(&s.core).paused_gen == gen_now && s.phase() == SPhase::Paused;
                        if still {
                            finish_send(&inner, &s, Finish::Failed(FailReason::Expired));
                        }
                    }
                    () = down.stopped() => {}
                    () = ended.stopped() => {}
                }
            }));
        }
        SPhase::Paused | SPhase::Finished => {}
    }
}

// ----------------------------------------------------------------- хэширование

enum Waited {
    Ready(Arc<Hashes>),
    Failed(FileFailure),
    Stopped,
}

async fn wait_hash(s: &SendSession, index: u32, stop: &mut StopWatch) -> Waited {
    let Some(tx) = s.hashes.get(usize::try_from(index).unwrap_or(usize::MAX)) else {
        return Waited::Stopped;
    };
    let mut rx = tx.subscribe();
    loop {
        let cur = rx.borrow_and_update().clone();
        match cur {
            FileHash::Ready(h) => return Waited::Ready(h),
            FileHash::Failed(w) => return Waited::Failed(w),
            FileHash::Pending => {}
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return Waited::Stopped },
            () = stop.stopped() => return Waited::Stopped,
        }
    }
}

/// Хэши файлов по одному, в порядке предложения.
async fn hash_all(s: Arc<SendSession>) {
    for (i, f) in s.files.iter().enumerate() {
        if s.halt.load(Ordering::Relaxed) {
            return;
        }
        let Ok(index) = u32::try_from(i) else { return };
        let (path, size, halt) = (f.path.clone(), f.size, s.halt.clone());
        let job = tokio::task::spawn_blocking(move || hash_source(&path, size, &halt)).await;
        let state = match job {
            Ok(Ok((layout, leaves, root))) => FileHash::Ready(Arc::new(Hashes {
                layout,
                leaves,
                root,
            })),
            Ok(Err(ReadFail::Changed)) => FileHash::Failed(FileFailure::SourceChanged),
            Ok(Err(ReadFail::Io(_))) => FileHash::Failed(FileFailure::SourceUnreadable),
            Ok(Err(ReadFail::Stopped)) | Err(_) => return,
        };
        if let FileHash::Failed(why) = &state {
            s.report_failure(index, *why);
        }
        if let Some(tx) = s.hashes.get(i) {
            tx.send_replace(state);
        }
    }
}

// ------------------------------------------------------------------ предложение

/// Кадры предложения: OFFER_HEAD и записи пачками, которые влезают в кадр целиком.
fn offer_frames(s: &SendSession) -> Result<Vec<u8>, ProtocolError> {
    let mut out = vec![STREAM_TRANSFER_CTL];
    let offer_bytes: u64 = s
        .files
        .iter()
        .map(|f| 10u64.saturating_add(u64::try_from(f.name.len()).unwrap_or(u64::MAX)))
        .sum();
    encode(
        &Message::OfferHead {
            id: s.key.id,
            file_count: s.file_count(),
            total_size: s.total,
            offer_bytes: u32::try_from(offer_bytes).map_err(|_| ProtocolError::TooLarge)?,
        },
        &mut out,
    )?;
    let mut batch: Vec<OfferedFile> = Vec::new();
    let mut used = 3usize;
    for f in &s.files {
        let need = 10usize.saturating_add(f.name.len());
        if !batch.is_empty() && used.saturating_add(need) > MAX_MESSAGE_LEN {
            encode(&Message::OfferFiles(std::mem::take(&mut batch)), &mut out)?;
            used = 3;
        }
        batch.push(OfferedFile {
            name: f.name.clone(),
            size: f.size,
        });
        used = used.saturating_add(need);
    }
    if !batch.is_empty() {
        encode(&Message::OfferFiles(batch), &mut out)?;
    }
    Ok(out)
}

/// Открывает поток управления, отправляет предложение и ведёт сессию до первой паузы.
pub(crate) async fn sender_main<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<SendSession>,
    conn: L::Conn,
) {
    let cfg = &s.sh.cfg;
    let hold = inner.links.hold(&s.key.pair);
    let opened = timeout(cfg.msg_timeout, conn.open_bi()).await;
    let Ok(Ok((mut tx, rx))) = opened else {
        finish_send(&inner, &s, Finish::Failed(FailReason::Protocol));
        return;
    };
    let Ok(frames) = offer_frames(&s) else {
        finish_send(&inner, &s, Finish::Failed(FailReason::Limits));
        return;
    };
    let sent = timeout(cfg.offer_read_timeout, tx.write_all(&frames)).await;
    if !matches!(sent, Ok(Ok(()))) {
        finish_send(&inner, &s, Finish::Failed(FailReason::Protocol));
        return;
    }
    let (att, out_rx) = SAttempt::new(conn.conn_id(), hold);
    lock(&s.core).att = Some(att.clone());
    // хэширование не принадлежит попытке: обрыв соединения его не останавливает
    {
        let g = s.sh.tracker.guard();
        let s2 = s.clone();
        drop(s.sh.rt.spawn(async move {
            let _g = g;
            hash_all(s2).await;
        }));
    }
    start_attempt_tasks(&inner, &s, &att, conn.clone(), tx, rx, Vec::new(), out_rx);
    // ответа нет слишком долго: предложение снимается
    let ttl = cfg
        .offer_ttl
        .saturating_add(std::time::Duration::from_secs(30));
    let (inner2, s2) = (inner.clone(), s.clone());
    let mut stop = s.stop.watcher();
    spawn_att(&s.sh, &att, async move {
        tokio::select! {
            () = tokio::time::sleep(ttl) => {
                if s2.phase() == SPhase::Offering {
                    s2.ctl_send(Message::Cancel { id: s2.key.id, reason: CancelReason::User });
                    finish_send(&inner2, &s2, Finish::Failed(FailReason::Expired));
                }
            }
            () = stop.stopped() => {}
        }
    });
}

fn spawn_att<F>(sh: &Shared, att: &SAttempt, f: F)
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

/// Писатель и читатель потока управления и наблюдатель за соединением.
#[allow(clippy::too_many_arguments)]
fn start_attempt_tasks<L: Links>(
    inner: &Arc<Inner<L>>,
    s: &Arc<SendSession>,
    att: &Arc<SAttempt>,
    conn: L::Conn,
    tx: <L::Conn as Connection>::Tx,
    rx: <L::Conn as Connection>::Rx,
    buf: Vec<u8>,
    out_rx: mpsc::UnboundedReceiver<Message>,
) {
    let cfg = &s.sh.cfg;
    let (stall, flush) = (cfg.stall_timeout, cfg.msg_timeout);
    {
        let (inner, s, att2) = (inner.clone(), s.clone(), att.clone());
        let stop = att.stop.watcher();
        spawn_att(&s.sh.clone(), att, async move {
            if !write_loop(tx, out_rx, stop, stall, flush).await {
                attempt_lost(&inner, &s, &att2);
            }
        });
    }
    {
        let (inner, s, att2) = (inner.clone(), s.clone(), att.clone());
        spawn_att(&s.sh.clone(), att, ctl_reader(inner, s, att2, rx, buf));
    }
    {
        let (inner, s, att2) = (inner.clone(), s.clone(), att.clone());
        let mut stop = att.stop.watcher();
        spawn_att(&s.sh.clone(), att, async move {
            tokio::select! {
                () = conn.closed() => attempt_lost(&inner, &s, &att2),
                () = stop.stopped() => {}
            }
        });
    }
}

/// Читает сообщения получателя. До ответа допустимы DECISION и CANCEL; после него FILE_DONE,
/// FILE_ERROR с кодами получателя, CANCEL, DONE.
async fn ctl_reader<L: Links, R: RecvStream>(
    inner: Arc<Inner<L>>,
    s: Arc<SendSession>,
    att: Arc<SAttempt>,
    mut rx: R,
    mut buf: Vec<u8>,
) {
    let mut stop = att.stop.watcher();
    loop {
        let r = tokio::select! {
            r = read_message(&mut rx, &mut buf, s.sh.cfg.msg_timeout) => r,
            () = stop.stopped() => return,
        };
        let msg = match r {
            Ok(Some(m)) => m,
            Ok(None) | Err(ProtocolError::Closed | ProtocolError::TimedOut) => {
                attempt_lost(&inner, &s, &att);
                return;
            }
            Err(_) => {
                s.protocol_fail(&inner, CancelReason::Protocol);
                return;
            }
        };
        let phase = s.phase();
        match (phase, msg) {
            (SPhase::Offering, Message::Decision { id, verdict }) if id == s.key.id => {
                match verdict {
                    Verdict::Accept => {
                        s.phase.send_replace(SPhase::Accepted);
                        s.emit(TransferEvent::OfferAnswered {
                            key: s.key,
                            accepted: true,
                        });
                        s.emit(TransferEvent::Started { key: s.key });
                    }
                    other => {
                        s.emit(TransferEvent::OfferAnswered {
                            key: s.key,
                            accepted: false,
                        });
                        let why = match other {
                            Verdict::Decline | Verdict::Accept => FailReason::Declined,
                            Verdict::Busy => FailReason::Busy,
                            Verdict::Expired => FailReason::Expired,
                            Verdict::Limits => FailReason::Limits,
                        };
                        finish_send(&inner, &s, Finish::Failed(why));
                        return;
                    }
                }
            }
            (SPhase::Offering | SPhase::Accepted, Message::Cancel { id, .. }) if id == s.key.id => {
                finish_send(&inner, &s, Finish::Cancelled(Side::Receiver));
                return;
            }
            (SPhase::Accepted, Message::FileDone { index }) if index < s.file_count() => {
                let new = lock(&s.core).delivered.insert(index);
                if new {
                    s.emit(TransferEvent::FileDelivered { key: s.key, index });
                }
            }
            (SPhase::Accepted, Message::FileError { index, code }) if index < s.file_count() => {
                let why = match code {
                    FileErrCode::Damaged => FileFailure::Damaged,
                    FileErrCode::WriteError => FileFailure::WriteError,
                    FileErrCode::PlaceFailed => FileFailure::PlaceFailed,
                    _ => {
                        s.protocol_fail(&inner, CancelReason::Protocol);
                        return;
                    }
                };
                let new = lock(&s.core).failed.insert(index, why).is_none();
                if new {
                    s.emit(TransferEvent::FileFailed {
                        key: s.key,
                        index,
                        reason: why,
                    });
                }
            }
            (SPhase::Accepted, Message::Done { id }) if id == s.key.id => {
                s.ctl_send(Message::Done { id });
                finish_send(&inner, &s, Finish::Completed);
                return;
            }
            _ => {
                s.protocol_fail(&inner, CancelReason::Protocol);
                return;
            }
        }
    }
}

// ------------------------------------------------------------------- возобновление

/// Новый поток управления с RESUME: старая попытка останавливается, затем RESUME_OK.
pub(crate) async fn handle_resume<L: Links>(
    inner: Arc<Inner<L>>,
    conn: L::Conn,
    mut tx: <L::Conn as Connection>::Tx,
    rx: <L::Conn as Connection>::Rx,
    buf: Vec<u8>,
    key: TransferKey,
) {
    let cfg = &inner.sh.cfg;
    let reply = |m: Message| {
        let mut out = Vec::new();
        let _ = encode(&m, &mut out);
        out
    };
    let Some(s) = inner.find_out(&key) else {
        let out = reply(Message::Cancel {
            id: key.id,
            reason: CancelReason::Unknown,
        });
        let _ = timeout(cfg.msg_timeout, tx.write_all(&out)).await;
        let _ = tx.finish();
        return;
    };
    let (phase, completed) = (s.phase(), lock(&s.core).completed);
    if phase == SPhase::Finished {
        let m = if completed {
            Message::Done { id: key.id }
        } else {
            Message::Cancel {
                id: key.id,
                reason: CancelReason::Unknown,
            }
        };
        let _ = timeout(cfg.msg_timeout, tx.write_all(&reply(m))).await;
        let _ = tx.finish();
        return;
    }
    if phase == SPhase::Offering {
        let out = reply(Message::Cancel {
            id: key.id,
            reason: CancelReason::Unknown,
        });
        let _ = timeout(cfg.msg_timeout, tx.write_all(&out)).await;
        let _ = tx.finish();
        return;
    }
    // потоки старой попытки закрываются раньше, чем начнётся новая
    let old = lock(&s.core).att.take();
    if let Some(old) = old {
        old.stop.stop();
        let _ = timeout(cfg.msg_timeout, old.tracker.idle()).await;
    }
    let hold = inner.links.hold(&key.pair);
    let (att, out_rx) = SAttempt::new(conn.conn_id(), hold);
    {
        let mut c = lock(&s.core);
        if s.phase() == SPhase::Finished {
            return;
        }
        c.att = Some(att.clone());
    }
    let ok = reply(Message::ResumeOk {
        id: key.id,
        file_count: s.file_count(),
        total_size: s.total,
    });
    if !matches!(
        timeout(cfg.msg_timeout, tx.write_all(&ok)).await,
        Ok(Ok(()))
    ) {
        attempt_lost(&inner, &s, &att);
        return;
    }
    let was = s.phase.send_replace(SPhase::Accepted);
    if was == SPhase::Paused {
        s.emit(TransferEvent::Resumed { key: s.key });
    }
    start_attempt_tasks(&inner, &s, &att, conn, tx, rx, buf, out_rx);
}

// ----------------------------------------------------------------------- данные

/// Счётчик живых потоков данных попытки.
struct StreamSlot(Arc<SAttempt>);

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Поток данных: первое сообщение BIND. Чужая пара, неизвестный id, лишний поток: поток
/// сбрасывается молча.
pub(crate) async fn handle_data<L: Links>(inner: Arc<Inner<L>>, st: IncomingStream<L::Conn>) {
    let cfg = &inner.sh.cfg;
    let IncomingStream {
        pair,
        conn,
        mut tx,
        mut rx,
        ..
    } = st;
    let mut buf = Vec::new();
    let first = read_message(&mut rx, &mut buf, cfg.msg_timeout);
    let Ok(Ok(Some(Message::Bind { id }))) = timeout(cfg.msg_timeout, first).await else {
        return;
    };
    let key = TransferKey { pair, id };
    let Some(s) = inner.find_out(&key) else {
        return;
    };
    // BIND мог обогнать DECISION на потоке управления
    let mut ph = s.phase.subscribe();
    let accepted = matches!(
        timeout(
            cfg.msg_timeout,
            ph.wait_for(|p| matches!(p, SPhase::Accepted)),
        )
        .await,
        Ok(Ok(_))
    );
    if !accepted {
        return;
    }
    let att = {
        let c = lock(&s.core);
        match &c.att {
            Some(a) if a.conn_id == conn.conn_id() && !a.stop.is_stopped() => a.clone(),
            _ => return,
        }
    };
    let n = att.streams.fetch_add(1, Ordering::SeqCst);
    let slot = StreamSlot(att.clone());
    if n >= usize::from(cfg.max_data_streams) {
        return;
    }
    serve_stream(&inner, &s, &att, &mut tx, rx, buf).await;
    drop(slot);
    let _ = tx.finish();
}

/// Читатель запросов кладёт их в очередь не длиннее окна; переполнение это нарушение.
async fn serve_stream<L: Links, T: SendStream, R: RecvStream + 'static>(
    inner: &Arc<Inner<L>>,
    s: &Arc<SendSession>,
    att: &Arc<SAttempt>,
    tx: &mut T,
    mut rx: R,
    mut buf: Vec<u8>,
) {
    // Окно получателя его собственная настройка (1..=8); отправитель разрешает протокольный
    // максимум, а не свою настройку, иначе разные настройки друзей ломали бы передачу.
    let (qtx, mut qrx) = mpsc::channel::<Message>(MAX_STREAM_WINDOW);
    let (inner2, s2, att2) = (inner.clone(), s.clone(), att.clone());
    let mut stop = att.stop.watcher();
    let reader = async move {
        loop {
            let r = tokio::select! {
                r = read_message(&mut rx, &mut buf, s2.sh.cfg.msg_timeout) => r,
                () = stop.stopped() => return,
            };
            match r {
                Ok(Some(m)) => {
                    if qtx.try_send(m).is_err() {
                        // больше запросов, чем окно
                        s2.protocol_fail(&inner2, CancelReason::Protocol);
                        att2.stop.stop();
                        return;
                    }
                }
                Ok(None) | Err(ProtocolError::Closed | ProtocolError::TimedOut) => return,
                Err(_) => {
                    s2.protocol_fail(&inner2, CancelReason::Protocol);
                    return;
                }
            }
        }
    };
    let g = att.tracker.guard();
    let g2 = s.sh.tracker.guard();
    let handle = s.sh.rt.spawn(async move {
        let _g = (g, g2);
        reader.await;
    });
    let mut stop = att.stop.watcher();
    loop {
        let req = tokio::select! {
            r = qrx.recv() => r,
            () = stop.stopped() => None,
        };
        let Some(req) = req else { break };
        if !serve_one(inner, s, att, tx, req, &mut stop).await {
            break;
        }
    }
    handle.abort();
}

/// Один запрос. `false`: поток закончен.
async fn serve_one<L: Links, T: SendStream>(
    inner: &Arc<Inner<L>>,
    s: &Arc<SendSession>,
    att: &Arc<SAttempt>,
    tx: &mut T,
    req: Message,
    stop: &mut StopWatch,
) -> bool {
    let cfg = &s.sh.cfg;
    match req {
        Message::GetManifest { index } => {
            if index >= s.file_count() {
                s.protocol_fail(inner, CancelReason::Protocol);
                return false;
            }
            match wait_hash(s, index, stop).await {
                Waited::Ready(h) => {
                    let mut out = Vec::new();
                    let m = Message::Manifest {
                        index,
                        block_size: h.layout.block_size,
                        block_count: h.layout.block_count,
                        root: h.root,
                    };
                    if encode(&m, &mut out).is_err() {
                        return false;
                    }
                    for l in &h.leaves {
                        out.extend_from_slice(&l.0);
                    }
                    write_chunks(tx, &out, cfg.stall_timeout).await
                }
                Waited::Failed(why) => {
                    s.report_failure(index, why);
                    block_err(tx, index, 0, why, cfg.msg_timeout).await
                }
                Waited::Stopped => false,
            }
        }
        Message::GetBlock { index, block } => {
            let Some(file) = s.files.get(usize::try_from(index).unwrap_or(usize::MAX)) else {
                s.protocol_fail(inner, CancelReason::Protocol);
                return false;
            };
            let Ok(l) = layout(file.size) else {
                return false;
            };
            let Some(len) = block_len(file.size, l, block) else {
                s.protocol_fail(inner, CancelReason::Protocol);
                return false;
            };
            let over = {
                let mut c = lock(&s.core);
                let n = c.serve.entry((index, block)).or_insert(0);
                *n = n.saturating_add(1);
                *n > cfg.max_serve_per_block
            };
            if over {
                s.protocol_fail(inner, CancelReason::Limits);
                return false;
            }
            let hashes = match wait_hash(s, index, stop).await {
                Waited::Ready(h) => h,
                Waited::Failed(why) => {
                    s.report_failure(index, why);
                    return block_err(tx, index, block, why, cfg.msg_timeout).await;
                }
                Waited::Stopped => return false,
            };
            // уже известно, что файл изменился: ответ без чтения
            let known = lock(&s.core).failed.get(&index).copied();
            if let Some(why) = known {
                return block_err(tx, index, block, why, cfg.msg_timeout).await;
            }
            let permit = tokio::select! {
                p = s.sh.send_budget.clone().acquire_many_owned(kib(len)) => p.ok(),
                () = stop.stopped() => None,
            };
            let Some(permit) = permit else { return false };
            let (path, size) = (file.path.clone(), file.size);
            let h2 = hashes.clone();
            let job = tokio::task::spawn_blocking(move || {
                let data = read_source_block(&path, size, h2.layout, block)?;
                let want = h2.leaves.get(usize::try_from(block).unwrap_or(usize::MAX));
                if want.is_some_and(|w| leaf_hash(block, &data) == *w) {
                    Ok(data)
                } else {
                    Err(ReadFail::Changed)
                }
            });
            let data = match job.await {
                Ok(Ok(d)) => d,
                Ok(Err(ReadFail::Io(_))) => {
                    s.report_failure(index, FileFailure::SourceUnreadable);
                    return block_err(
                        tx,
                        index,
                        block,
                        FileFailure::SourceUnreadable,
                        cfg.msg_timeout,
                    )
                    .await;
                }
                Ok(Err(_)) => {
                    // файл на диске уже не тот, что хэшировали
                    s.report_failure(index, FileFailure::SourceChanged);
                    return block_err(
                        tx,
                        index,
                        block,
                        FileFailure::SourceChanged,
                        cfg.msg_timeout,
                    )
                    .await;
                }
                Err(_) => return false,
            };
            let mut out = Vec::new();
            if encode(&Message::Block { index, block, len }, &mut out).is_err() {
                return false;
            }
            if !write_msg_raw(tx, &out, cfg.msg_timeout).await {
                return false;
            }
            let ok = write_chunks(tx, &data, cfg.stall_timeout).await;
            drop(permit);
            if ok {
                s.note_progress(u64::from(len));
            }
            let _ = att;
            ok
        }
        _ => {
            s.protocol_fail(inner, CancelReason::Protocol);
            false
        }
    }
}

async fn write_msg_raw<T: SendStream>(
    tx: &mut T,
    bytes: &[u8],
    limit: std::time::Duration,
) -> bool {
    matches!(timeout(limit, tx.write_all(bytes)).await, Ok(Ok(())))
}

/// Запись частями: таймер сбрасывается при каждой части, медленный канал не режется.
async fn write_chunks<T: SendStream>(tx: &mut T, data: &[u8], stall: std::time::Duration) -> bool {
    for part in data.chunks(256 * 1024) {
        if !write_msg_raw(tx, part, stall).await {
            return false;
        }
    }
    true
}

async fn block_err<T: SendStream>(
    tx: &mut T,
    index: u32,
    block: u32,
    why: FileFailure,
    limit: std::time::Duration,
) -> bool {
    let code = match why {
        FileFailure::SourceChanged => BlockErrCode::SourceChanged,
        _ => BlockErrCode::ReadError,
    };
    write_msg(tx, &Message::BlockErr { index, block, code }, limit).await
}
