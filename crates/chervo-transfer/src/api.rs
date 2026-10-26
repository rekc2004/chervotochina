//! Публичный интерфейс передачи файлов: `Transfers`. Приём входящих потоков (предложения,
//! возобновление, потоки данных), запуск, отмена и остановка.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_connect::{EngineEvents, IncomingStream, StreamInbox};
use chervo_identity::PairId;
use chervo_transport::{Connection, RecvStream, SendStream};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::codec::{CancelReason, Message, OfferAssembler, ProtocolError, Verdict, encode};
use crate::config::TransferConfig;
use crate::events::{
    FailReason, PauseReason, Side, TransferError, TransferEvent, TransferEvents, TransferStatus,
};
use crate::inner::{Inner, Registry, Tomb};
use crate::limits::{
    MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_OFFER_BYTES, MAX_OFFER_TOTAL, STREAM_TRANSFER_CTL,
    STREAM_TRANSFER_DATA,
};
use crate::links::Links;
use crate::names::{OfferedFile, TransferId, TransferKey, UntrustedName};
use crate::paths::{create_session_dir, remove_session};
use crate::placement::Placement;
use crate::policy::{AcceptPolicy, OfferView, PolicyVerdict};
use crate::receiver::{
    Finish, FirstCtl, RPhase, RecvSession, Reoffer, Rx, is_closed, recv_supervisor,
};
use crate::sender::{SendSession, SrcFile, finish_send, handle_data, handle_resume, sender_main};
use crate::shared::{Hook, Shared, lock};
use crate::state::state_dir_name;
use crate::util::{Stop, Tracker};
use crate::wire_io::read_message;

/// Свой файл для отправки: путь наш, имя уйдёт в предложение как есть.
#[derive(Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    /// 1..=1024 байт, без NUL.
    pub name: String,
}

impl std::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceFile(..)")
    }
}

/// Все передачи узла. Не клонируется: уничтожение останавливает передачи (состояние
/// получателя на диске остаётся для возобновления).
pub struct Transfers<L: Links> {
    inner: Arc<Inner<L>>,
}

impl<L: Links> Transfers<L> {
    /// Внутри среды tokio. Просматривает `partial_dir` (недокачанные передачи загружаются на
    /// паузе), запускает приём потоков.
    pub fn start(
        links: Arc<L>,
        inbox: StreamInbox<L::Conn>,
        policy: Arc<dyn AcceptPolicy>,
        placement: Arc<dyn Placement>,
        cfg: TransferConfig,
    ) -> Result<(Self, TransferEvents), TransferError> {
        Self::start_with(
            links,
            inbox,
            policy,
            placement,
            cfg,
            None,
            Duration::from_secs(5),
        )
    }

    pub(crate) fn start_with(
        links: Arc<L>,
        inbox: StreamInbox<L::Conn>,
        policy: Arc<dyn AcceptPolicy>,
        placement: Arc<dyn Placement>,
        cfg: TransferConfig,
        hook: Option<Arc<dyn Hook>>,
        poll: Duration,
    ) -> Result<(Self, TransferEvents), TransferError> {
        cfg.validate()?;
        let rt = Handle::try_current().map_err(|_| TransferError::Io)?;
        let (etx, erx) = broadcast::channel(256);
        let sh = Arc::new(Shared {
            recv_budget: Arc::new(Semaphore::new(crate::shared::permits(
                cfg.recv_buffer_budget,
            ))),
            send_budget: Arc::new(Semaphore::new(crate::shared::permits(
                cfg.send_buffer_budget,
            ))),
            cfg,
            events: etx,
            placement,
            hook,
            rt,
            tracker: Tracker::new(),
            shutdown: Stop::new(),
        });
        let events = links.subscribe();
        let inner = Arc::new(Inner {
            sh: sh.clone(),
            links,
            policy,
            reg: std::sync::Mutex::new(Registry::default()),
            conn_gen: watch::channel(0u64).0,
            poll,
            decide_lock: std::sync::Mutex::new(()),
            relink: Mutex::new(std::collections::HashMap::new()),
            tombs: Mutex::new(std::collections::VecDeque::new()),
        });
        for s in crate::restore::load_all(&sh) {
            lock(&inner.reg).inb.insert(s.key, s.clone());
            s.emit(TransferEvent::Paused {
                key: s.key,
                reason: PauseReason::Disconnected,
            });
            spawn(&inner, recv_supervisor(inner.clone(), s, None));
        }
        spawn(&inner, inbox_loop(inner.clone(), inbox));
        spawn(&inner, friend_watch(inner.clone(), events));
        Ok((Self { inner }, TransferEvents::new(erx)))
    }

    /// Предлагает файлы другу. Пути проверяются сейчас (обычные файлы), имена по границам X1.
    pub fn send(
        &self,
        pair: &PairId,
        files: Vec<SourceFile>,
    ) -> Result<TransferKey, TransferError> {
        let inner = &self.inner;
        let cfg = &inner.sh.cfg;
        if inner.sh.shutdown.is_stopped() {
            return Err(TransferError::Shutdown);
        }
        if inner.links.permission(pair).is_none() {
            return Err(TransferError::NotFriend);
        }
        if files.is_empty() {
            return Err(TransferError::BadName);
        }
        if u32::try_from(files.len()).map_or(true, |n| n > MAX_FILES_PER_OFFER) {
            return Err(TransferError::TooManyFiles);
        }
        let mut src = Vec::with_capacity(files.len());
        let (mut total, mut offer_bytes) = (0u64, 0u64);
        for f in files {
            let name = UntrustedName::new(&f.name).map_err(|_| TransferError::BadName)?;
            let md = std::fs::metadata(&f.path).map_err(|_| TransferError::Io)?;
            if !md.is_file() {
                return Err(TransferError::Io);
            }
            let size = md.len();
            if size > MAX_FILE_SIZE {
                return Err(TransferError::TooLarge);
            }
            total = total.checked_add(size).ok_or(TransferError::TooLarge)?;
            offer_bytes = offer_bytes.saturating_add(10 + u64::try_from(name.len()).unwrap_or(0));
            if total > MAX_OFFER_TOTAL || offer_bytes > u64::from(MAX_OFFER_BYTES) {
                return Err(TransferError::TooLarge);
            }
            src.push(SrcFile {
                path: f.path,
                name,
                size,
            });
        }
        let conn = inner.links.connection(pair).ok_or(TransferError::Io)?;
        let id = TransferId::generate().ok_or(TransferError::Io)?;
        let key = TransferKey { pair: *pair, id };
        let s = SendSession::new(inner.sh.clone(), key, src, total);
        {
            let mut reg = lock(&inner.reg);
            let live = |x: &Arc<SendSession>| !x.is_finished();
            let busy = reg.out.values().any(|x| x.key.pair == *pair && live(x))
                || reg.out.values().filter(|x| live(x)).count() >= cfg.max_outbound_active;
            if busy || reg.out.contains_key(&key) {
                return Err(TransferError::Busy);
            }
            reg.out.insert(key, s.clone());
        }
        spawn(inner, sender_main(inner.clone(), s, conn));
        Ok(key)
    }

    /// Ожидающее решения предложение (для окна «принять или отклонить»).
    pub fn offer(&self, key: &TransferKey) -> Option<OfferView> {
        let s = self.inner.find_inb(key)?;
        let pending = lock(&s.core).phase == RPhase::Pending;
        pending.then(|| self.inner.offer_view_for(&s))
    }

    /// Ответ пользователя на предложение.
    pub fn respond(&self, key: &TransferKey, accept: bool) -> Result<(), TransferError> {
        let inner = &self.inner;
        if inner.sh.shutdown.is_stopped() {
            return Err(TransferError::Shutdown);
        }
        let s = inner.find_inb(key).ok_or(TransferError::NoSuchTransfer)?;
        if lock(&s.core).phase != RPhase::Pending {
            return Err(TransferError::WrongState);
        }
        if accept && inner.active_inbound() >= inner.sh.cfg.max_inbound_active {
            return Err(TransferError::Busy);
        }
        // Рев. 6, L1: ответ берётся под тем же замком, что и автоприём в `inbox_loop`, чтобы
        // решение политики по другому предложению видело это принятое предложение в резерве.
        // Замок не держится через `.await`.
        let answer = {
            let _g = lock(&inner.decide_lock);
            s.take_answer().ok_or(TransferError::WrongState)?
        };
        answer
            .send(accept)
            .map_err(|_| TransferError::NoSuchTransfer)
    }

    /// Отмена с любой стороны. Ожидающее предложение у получателя это отказ.
    pub fn cancel(&self, key: &TransferKey) -> Result<(), TransferError> {
        let inner = &self.inner;
        if let Some(s) = inner.find_out(key) {
            if s.is_finished() {
                return Err(TransferError::WrongState);
            }
            cancel_out(inner, &s);
            return Ok(());
        }
        let s = inner.find_inb(key).ok_or(TransferError::NoSuchTransfer)?;
        cancel_inb(&s).map_err(|()| TransferError::WrongState)
    }

    /// Продолжить после паузы (диск, ввод-вывод, молчание отправителя) или попробовать
    /// соединение сейчас.
    pub fn retry(&self, key: &TransferKey) -> Result<(), TransferError> {
        let s = self
            .inner
            .find_inb(key)
            .ok_or(TransferError::NoSuchTransfer)?;
        let phase = lock(&s.core).phase;
        match phase {
            RPhase::Paused(PauseReason::Disconnected) => {
                self.inner.bump();
                Ok(())
            }
            RPhase::Paused(_) => {
                s.retry.notify_one();
                Ok(())
            }
            _ => Err(TransferError::WrongState),
        }
    }

    pub fn status(&self, key: &TransferKey) -> Option<TransferStatus> {
        if let Some(s) = self.inner.find_out(key) {
            return Some(s.status());
        }
        self.inner.find_inb(key).map(|s| s.status())
    }

    /// Останавливает все передачи (получатель успевает записать последнюю контрольную точку).
    pub fn shutdown(&self) {
        self.inner.stop_all();
    }

    /// Ждёт, пока остановятся все задачи (после `shutdown`).
    pub async fn wait_stopped(&self) {
        self.inner.sh.tracker.idle().await;
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &Arc<Inner<L>> {
        &self.inner
    }
}

impl<L: Links> Drop for Transfers<L> {
    fn drop(&mut self) {
        self.inner.stop_all();
    }
}

fn spawn<L: Links, F>(inner: &Arc<Inner<L>>, f: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let g = inner.sh.tracker.guard();
    drop(inner.sh.rt.spawn(async move {
        let _g = g;
        f.await;
    }));
}

fn cancel_out<L: Links>(inner: &Arc<Inner<L>>, s: &Arc<SendSession>) {
    s.cancel_notice();
    finish_send(inner, s, Finish::Cancelled(Side::Sender));
}

/// Отмена получателем. `Err`: передача уже закончена.
fn cancel_inb(s: &Arc<RecvSession>) -> Result<(), ()> {
    let phase = lock(&s.core).phase;
    match phase {
        RPhase::Pending => {
            // ожидающее предложение: отказ
            match s.take_answer() {
                Some(a) => {
                    let _ = a.send(false);
                    Ok(())
                }
                None => Err(()),
            }
        }
        RPhase::Ended => Err(()),
        RPhase::Active | RPhase::Paused(_) => {
            {
                let mut c = lock(&s.core);
                if c.finish.is_none() {
                    c.finish = Some(Finish::Cancelled(Side::Receiver));
                }
            }
            s.ctl_send(Message::Cancel {
                id: s.key.id,
                reason: CancelReason::User,
            });
            s.end.stop();
            Ok(())
        }
    }
}

// ----------------------------------------------------------------- приём потоков

async fn inbox_loop<L: Links>(inner: Arc<Inner<L>>, mut inbox: StreamInbox<L::Conn>) {
    let mut down = inner.sh.shutdown.watcher();
    loop {
        let st = tokio::select! {
            s = inbox.recv() => s,
            () = down.stopped() => return,
        };
        let Some(st) = st else { return };
        match st.kind {
            STREAM_TRANSFER_CTL => spawn(&inner, handle_ctl_in(inner.clone(), st)),
            STREAM_TRANSFER_DATA => spawn(&inner, handle_data(inner.clone(), st)),
            _ => {}
        }
    }
}

async fn write_decision<T: SendStream>(
    tx: &mut T,
    id: TransferId,
    verdict: Verdict,
    limit: Duration,
) {
    let mut out = Vec::new();
    if encode(&Message::Decision { id, verdict }, &mut out).is_ok() {
        let _ = timeout(limit, tx.write_all(&out)).await;
    }
    let _ = tx.finish();
}

/// Поток управления: первое сообщение OFFER_HEAD (новое предложение) или RESUME.
async fn handle_ctl_in<L: Links>(inner: Arc<Inner<L>>, st: IncomingStream<L::Conn>) {
    let cfg = &inner.sh.cfg;
    let IncomingStream {
        pair,
        conn,
        tx,
        mut rx,
        ..
    } = st;
    if inner.links.permission(&pair).is_none() {
        return;
    }
    let Some(token) = inner.ctl_rate_ok(&pair) else {
        return;
    };
    let mut buf = Vec::new();
    let first = timeout(
        cfg.offer_read_timeout,
        read_message(&mut rx, &mut buf, cfg.msg_timeout),
    )
    .await;
    match first {
        Ok(Ok(Some(Message::OfferHead {
            id,
            file_count,
            total_size,
            offer_bytes,
        }))) => {
            let head = (file_count, total_size, offer_bytes);
            let key = TransferKey { pair, id };
            // повтор известного предложения не тратит общий предел потоков (см. `ctl_rate_ok`)
            inner.refund_reoffer(&key, token);
            receive_offer(&inner, conn, tx, rx, buf, key, head).await;
        }
        Ok(Ok(Some(Message::Resume { id }))) => {
            handle_resume(inner.clone(), conn, tx, rx, buf, TransferKey { pair, id }).await;
        }
        // первое сообщение не из допустимых для этого потока: поток закрывается
        _ => {}
    }
}

async fn write_cancel<T: SendStream>(
    tx: &mut T,
    id: TransferId,
    reason: CancelReason,
    limit: Duration,
) {
    let mut out = Vec::new();
    if encode(&Message::Cancel { id, reason }, &mut out).is_ok() {
        let _ = timeout(limit, tx.write_all(&out)).await;
    }
    let _ = tx.finish();
}

/// Ответ из надгробия: тот же, что получил (или мог не получить) отправитель в первый раз.
async fn write_tomb<T: SendStream>(tx: &mut T, id: TransferId, tomb: Tomb, limit: Duration) {
    match tomb {
        Tomb::Decline => write_decision(tx, id, Verdict::Decline, limit).await,
        Tomb::Expired => write_decision(tx, id, Verdict::Expired, limit).await,
        Tomb::Busy => write_decision(tx, id, Verdict::Busy, limit).await,
        Tomb::Limits => write_decision(tx, id, Verdict::Limits, limit).await,
        Tomb::Protocol => write_cancel(tx, id, CancelReason::Protocol, limit).await,
    }
}

/// Итог сборки предложения из потока.
enum Assembled {
    Files(Vec<OfferedFile>),
    /// Поток оборвался или молчит: нарушением это не считается.
    Lost,
    /// Нарушение границ или порядка кадров.
    Violation,
}

/// Собирает записи предложения: те же пределы и срок, что у первого предложения.
async fn assemble_offer<R: RecvStream>(
    cfg: &TransferConfig,
    rx: &mut R,
    buf: &mut Vec<u8>,
    head: (u32, u64, u32),
) -> Assembled {
    let Ok(mut asm) = OfferAssembler::new(head.0, head.1, head.2) else {
        return Assembled::Violation;
    };
    // записи собираются в пределах `offer_read_timeout` на всё предложение
    let deadline = tokio::time::Instant::now() + cfg.offer_read_timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let m = timeout(left, read_message(rx, buf, cfg.msg_timeout)).await;
        let done = match m {
            Ok(Ok(Some(Message::OfferFiles(v)))) => match asm.push(v) {
                Ok(done) => done,
                Err(_) => return Assembled::Violation,
            },
            Ok(Ok(None) | Err(ProtocolError::Closed | ProtocolError::TimedOut)) | Err(_) => {
                return Assembled::Lost;
            }
            _ => return Assembled::Violation,
        };
        if done {
            break;
        }
    }
    match asm.finish() {
        Ok(files) => Assembled::Files(files),
        Err(_) => Assembled::Violation,
    }
}

/// Что делать с пришедшим предложением (решается под замком `reg`).
enum Act<C: Connection> {
    /// Для ключа есть надгробие.
    Tomb(Tomb),
    /// Ожидающее предложение закрывается: повтор не совпал или повторов слишком много.
    EndPending(Arc<RecvSession>, Tomb),
    /// Принятая передача закрывается: повтор не совпал.
    EndActive(Arc<RecvSession>),
    /// Повтор совпал: поток уходит ожидающему предложению.
    Attach(Option<mpsc::Sender<Reoffer<C>>>),
    /// Повтор принятого предложения: `DECISION{Accept}`.
    Echo,
    /// Поток молча закрывается.
    Drop,
    Busy,
    Limits,
    /// Новое предложение.
    New(
        Arc<RecvSession>,
        oneshot::Receiver<bool>,
        mpsc::Receiver<Reoffer<C>>,
    ),
}

#[allow(clippy::too_many_arguments)]
async fn receive_offer<L: Links>(
    inner: &Arc<Inner<L>>,
    conn: L::Conn,
    mut tx: <L::Conn as Connection>::Tx,
    mut rx: <L::Conn as Connection>::Rx,
    mut buf: Vec<u8>,
    key: TransferKey,
    head: (u32, u64, u32),
) {
    let cfg = &inner.sh.cfg;
    // известный ключ: сессия или надгробие (повтор предложения после потери связи)
    let known = inner.is_known(&key);
    let files = match assemble_offer(cfg, &mut rx, &mut buf, head).await {
        Assembled::Files(f) => Some(f),
        // оборванный повтор нарушением не считается
        Assembled::Lost if known => return,
        Assembled::Violation if known => None,
        Assembled::Lost | Assembled::Violation => {
            write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await;
            return;
        }
    };
    let Some(perm) = inner.links.permission(&key.pair) else {
        return;
    };
    let (ans_tx, ans_rx) = oneshot::channel::<bool>();
    let (rtx, rrx) = mpsc::channel::<Reoffer<L::Conn>>(1);
    let act: Act<L::Conn> = {
        let mut reg = lock(&inner.reg);
        if let Some(t) = inner.tomb_get(&key) {
            Act::Tomb(t)
        } else if let Some(old) = reg.inb.get(&key).cloned() {
            let phase = lock(&old.core).phase;
            let same = files.as_deref().is_some_and(|f| old.same_offer(head, f));
            match phase {
                RPhase::Pending if !old.answered() => {
                    if !same {
                        Act::EndPending(old, Tomb::Protocol)
                    } else if !old.count_relink() {
                        Act::EndPending(old, Tomb::Limits)
                    } else {
                        Act::Attach(lock(&inner.relink).get(&key).cloned())
                    }
                }
                // ответ дан, передача ещё не началась: отправитель повторит или придёт RESUME
                RPhase::Pending | RPhase::Ended => Act::Drop,
                RPhase::Active | RPhase::Paused(_) => {
                    if same {
                        Act::Echo
                    } else {
                        Act::EndActive(old)
                    }
                }
            }
        } else if let Some(list) = files.as_deref() {
            let list: Vec<(UntrustedName, u64)> =
                list.iter().map(|f| (f.name.clone(), f.size)).collect();
            let s = RecvSession::pending(inner.sh.clone(), key, list, head.1, ans_tx);
            // один ожидающий ответа от друга и не больше `max_pending_offers` всего
            let pending = reg
                .inb
                .values()
                .filter(|x| lock(&x.core).phase == RPhase::Pending)
                .count();
            let busy = reg.inb.values().any(|x| x.key.pair == key.pair)
                || pending >= cfg.max_pending_offers;
            if busy {
                Act::Busy
            } else {
                reg.inb.insert(key, s.clone());
                lock(&inner.relink).insert(key, rtx);
                Act::New(s, ans_rx, rrx)
            }
        } else {
            Act::Limits
        }
    };
    match act {
        Act::Tomb(t) => write_tomb(&mut tx, key.id, t, cfg.msg_timeout).await,
        Act::Drop => {}
        Act::Busy => write_decision(&mut tx, key.id, Verdict::Busy, cfg.msg_timeout).await,
        Act::Limits => write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await,
        Act::Echo => {
            write_decision(&mut tx, key.id, Verdict::Accept, cfg.msg_timeout).await;
            // передача ждёт связь: пусть попробует сейчас
            inner.bump();
        }
        Act::Attach(Some(ch)) => {
            // занято или закрыто: поток отбрасывается, отправитель повторит
            let _ = ch.try_send(Reoffer { conn, tx, rx, buf });
        }
        Act::Attach(None) => {}
        Act::EndPending(old, tomb) => end_pending(inner, &old, tomb, &mut tx).await,
        Act::EndActive(old) => end_active(&old, &mut tx, cfg.msg_timeout).await,
        Act::New(s, ans_rx, rrx) => {
            // Решения по одному (Рев. 5): политика видит резерв места уже принятых передач, а
            // принятое предложение (ответ взят) сразу входит в этот резерв для следующего решения.
            let verdict = {
                let _g = lock(&inner.decide_lock);
                let view = inner.offer_view_for(&s);
                let verdict = inner.policy.decide(&key.pair, perm, &view);
                if verdict == PolicyVerdict::Accept
                    && let Some(a) = s.take_answer()
                {
                    let _ = a.send(true);
                }
                verdict
            };
            match verdict {
                PolicyVerdict::Decline => {
                    inner.remove_inb_tomb(&key, Tomb::Decline);
                    inner.unreg_relink(&key);
                    write_decision(&mut tx, key.id, Verdict::Decline, cfg.msg_timeout).await;
                    return;
                }
                PolicyVerdict::Ask => s.emit(TransferEvent::OfferReceived { key }),
                PolicyVerdict::Accept => {}
            }
            pending_task(inner.clone(), s, conn, tx, rx, buf, ans_rx, rrx).await;
        }
    }
}

/// Закрывает ожидающее предложение по повтору (не совпал или слишком много): надгробие,
/// событие и ответ на новый поток. Решение берётся тут же: если пользователь успел ответить,
/// повтор молча отбрасывается.
async fn end_pending<L: Links, T: SendStream>(
    inner: &Arc<Inner<L>>,
    s: &Arc<RecvSession>,
    tomb: Tomb,
    tx: &mut T,
) {
    let key = s.key;
    let Some(answer) = s.take_answer() else {
        return;
    };
    inner.remove_inb_tomb(&key, tomb);
    // `pending_task` выходит молча; ответ отброшен вместе с отправителем oneshot
    s.end.stop();
    drop(answer);
    write_tomb(tx, key.id, tomb, inner.sh.cfg.msg_timeout).await;
    let reason = if tomb == Tomb::Limits {
        FailReason::Limits
    } else {
        FailReason::Protocol
    };
    s.emit(TransferEvent::Failed { key, reason });
}

/// Повтор принятого предложения не совпал с ним: передача заканчивается нарушением, временные
/// данные убирает обычное завершение сессии.
async fn end_active<T: SendStream>(s: &Arc<RecvSession>, tx: &mut T, limit: Duration) {
    {
        let mut c = lock(&s.core);
        if c.finish.is_none() {
            c.finish = Some(Finish::Failed(FailReason::Protocol));
        }
    }
    s.ctl_send(Message::Cancel {
        id: s.key.id,
        reason: CancelReason::Protocol,
    });
    s.end.stop();
    write_cancel(tx, s.key.id, CancelReason::Protocol, limit).await;
}

/// Чтение кадра с потока управления, которое не прерывается посреди кадра: поток и буфер
/// принадлежат будущему, а при его уничтожении (в том числе на середине кадра) возвращаются в
/// `back`. Читать дальше можно только тем же будущим.
struct Reading<C: Connection + 'static> {
    fut: Option<ReadFut>,
    back: Slot<Rx<C>>,
}

type ReadFut = Pin<Box<dyn Future<Output = Result<Option<Message>, ProtocolError>> + Send>>;
type Slot<R> = Arc<Mutex<Option<(R, Vec<u8>)>>>;

struct ReadGuard<R> {
    parts: Option<(R, Vec<u8>)>,
    slot: Slot<R>,
}

impl<R> Drop for ReadGuard<R> {
    fn drop(&mut self) {
        if let Some(p) = self.parts.take() {
            *lock(&self.slot) = Some(p);
        }
    }
}

impl<C: Connection + 'static> Reading<C> {
    fn new(rx: Rx<C>, buf: Vec<u8>, limit: Duration) -> Self {
        let back = Arc::new(Mutex::new(None));
        let guard = ReadGuard {
            parts: Some((rx, buf)),
            slot: back.clone(),
        };
        let fut = Box::pin(async move {
            let mut g = guard;
            match g.parts.as_mut() {
                Some((rx, buf)) => read_message(rx, buf, limit).await,
                None => Err(ProtocolError::Closed),
            }
        });
        Self {
            fut: Some(fut),
            back,
        }
    }

    /// Следующий кадр. После готового результата вызывать нельзя: читатель заменяют или
    /// выбрасывают.
    async fn next(&mut self) -> Result<Option<Message>, ProtocolError> {
        match self.fut.as_mut() {
            Some(f) => f.await,
            None => std::future::pending().await,
        }
    }

    /// Возвращает поток (для принятия на этом же потоке управления).
    fn into_rx(mut self) -> Option<Rx<C>> {
        self.fut = None;
        lock(&self.back).take().map(|(rx, _)| rx)
    }
}

/// Запись в `Inner::relink` живёт, пока идёт `pending_task`.
struct Unreg<L: Links> {
    inner: Arc<Inner<L>>,
    key: TransferKey,
}

impl<L: Links> Drop for Unreg<L> {
    fn drop(&mut self) {
        self.inner.unreg_relink(&self.key);
    }
}

/// Конец ожидающего предложения достаётся тому, кто взял ответ (`take_answer`): ответ
/// пользователя, `end_pending` и концы в `pending_task` не выдадут два итоговых события и не
/// затрут чужое надгробие. Проигравший ничего не делает: победитель либо пришлёт ответ по
/// oneshot, либо остановит `s.end`, и цикл `pending_task` это увидит. Уступка планировщику не
/// даёт крутить цикл вхолостую в окне между `take_answer` и `send`.
async fn win_end(s: &Arc<RecvSession>) -> bool {
    if s.take_answer().is_some() {
        return true;
    }
    tokio::task::yield_now().await;
    false
}

enum Ev<C: Connection> {
    Answer(Result<bool, oneshot::error::RecvError>),
    /// Кто-то другой закрыл ожидающее предложение и всё сделал сам.
    Ended,
    Down,
    Deadline,
    Grace,
    Reattach(Option<Reoffer<C>>),
    Closed,
    Read(Result<Option<Message>, ProtocolError>),
}

/// Ждёт решения. Ничего на диск не пишется до принятия. Потеря потока управления или
/// соединения предложение не снимает: оно ждёт повтора от отправителя до `offer_relink_grace`
/// и в любом случае не дольше `offer_deadline`.
#[allow(clippy::too_many_arguments)]
async fn pending_task<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<RecvSession>,
    conn: L::Conn,
    tx: <L::Conn as Connection>::Tx,
    rx: <L::Conn as Connection>::Rx,
    buf: Vec<u8>,
    mut answer: oneshot::Receiver<bool>,
    mut rrx: mpsc::Receiver<Reoffer<L::Conn>>,
) {
    let cfg = &inner.sh.cfg;
    let key = s.key;
    let unreg = Unreg {
        inner: inner.clone(),
        key,
    };
    let mut down = inner.sh.shutdown.watcher();
    let mut ended = s.end.watcher();
    let mut conn_cur = Some(conn);
    let mut tx_cur = Some(tx);
    let mut rd = Some(Reading::<L::Conn>::new(rx, buf, cfg.msg_timeout));
    let mut detached_at: Option<tokio::time::Instant> = None;
    let mut rrx_open = true;
    loop {
        let grace_at = detached_at.map(|t| t + cfg.offer_relink_grace);
        let ev = tokio::select! {
            biased;
            () = ended.stopped() => Ev::Ended,
            () = down.stopped() => Ev::Down,
            a = &mut answer => Ev::Answer(a),
            () = tokio::time::sleep_until(s.offer_deadline) => Ev::Deadline,
            () = async {
                match grace_at {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            } => Ev::Grace,
            m = rrx.recv(), if rrx_open => Ev::Reattach(m),
            () = async {
                match conn_cur.as_ref() {
                    Some(c) => c.closed().await,
                    None => std::future::pending::<()>().await,
                }
            } => Ev::Closed,
            r = async {
                match rd.as_mut() {
                    Some(r) => r.next().await,
                    None => std::future::pending().await,
                }
            } => Ev::Read(r),
        };
        match ev {
            Ev::Ended | Ev::Down => return,
            Ev::Answer(Ok(true)) => {
                // принятие на живом потоке управления или без него (тогда RESUME)
                let first = match (
                    conn_cur.take(),
                    tx_cur.take(),
                    rd.take().and_then(Reading::into_rx),
                ) {
                    (Some(conn), Some(tx), Some(rx)) => Some(FirstCtl { conn, tx, rx }),
                    _ => None,
                };
                drop(rrx);
                drop(unreg);
                accept_flow(inner, s, first).await;
                return;
            }
            Ev::Answer(Ok(false)) => {
                inner.remove_inb_tomb(&key, Tomb::Decline);
                s.emit(TransferEvent::OfferAnswered {
                    key,
                    accepted: false,
                });
                if let Some(tx) = tx_cur.as_mut() {
                    write_decision(tx, key.id, Verdict::Decline, cfg.msg_timeout).await;
                }
                return;
            }
            Ev::Answer(Err(_)) => {
                inner.remove_inb(&key);
                s.take_answer();
                s.emit(TransferEvent::Cancelled {
                    key,
                    by: Side::Sender,
                });
                return;
            }
            Ev::Deadline => {
                if !win_end(&s).await {
                    continue;
                }
                inner.remove_inb_tomb(&key, Tomb::Expired);
                if let Some(tx) = tx_cur.as_mut() {
                    write_decision(tx, key.id, Verdict::Expired, cfg.msg_timeout).await;
                }
                s.emit(TransferEvent::Failed {
                    key,
                    reason: FailReason::Expired,
                });
                return;
            }
            Ev::Grace => {
                if !win_end(&s).await {
                    continue;
                }
                inner.remove_inb_tomb(&key, Tomb::Expired);
                s.emit(TransferEvent::Failed {
                    key,
                    reason: FailReason::Disconnected,
                });
                return;
            }
            Ev::Reattach(None) => rrx_open = false,
            Ev::Reattach(Some(new)) => {
                // закрытое соединение живого не заменяет; два живых: отправитель бросил прежнее
                if is_closed(&new.conn).await {
                    continue;
                }
                conn_cur = Some(new.conn);
                tx_cur = Some(new.tx);
                rd = Some(Reading::<L::Conn>::new(new.rx, new.buf, cfg.msg_timeout));
                detached_at = None;
            }
            Ev::Closed => {
                conn_cur = None;
                tx_cur = None;
                rd = None;
                detached_at = Some(tokio::time::Instant::now());
            }
            Ev::Read(r) => match r {
                Ok(Some(Message::Cancel { id, .. })) if id == key.id => {
                    // прочитанный кадр израсходован: читатель больше не опрашивается
                    rd = None;
                    if !win_end(&s).await {
                        continue;
                    }
                    inner.remove_inb(&key);
                    s.emit(TransferEvent::Cancelled {
                        key,
                        by: Side::Sender,
                    });
                    return;
                }
                // конец потока или обрыв: предложение ждёт повтора
                Ok(None) | Err(ProtocolError::Closed | ProtocolError::TimedOut) => {
                    conn_cur = None;
                    tx_cur = None;
                    rd = None;
                    detached_at = Some(tokio::time::Instant::now());
                }
                // HASH_PROGRESS до принятия и любое другое сообщение или ошибка разбора
                Ok(Some(_)) | Err(_) => {
                    rd = None;
                    if !win_end(&s).await {
                        continue;
                    }
                    inner.remove_inb_tomb(&key, Tomb::Protocol);
                    if let Some(tx) = tx_cur.as_mut() {
                        write_cancel(tx, key.id, CancelReason::Protocol, cfg.msg_timeout).await;
                    }
                    s.emit(TransferEvent::Failed {
                        key,
                        reason: FailReason::Protocol,
                    });
                    return;
                }
            },
        }
    }
}

/// Принято: каталог и первое состояние на диск, DECISION{Accept}, потоки данных. Без потока
/// управления (`first = None`) ответ получит отправитель по RESUME, когда вернётся связь.
async fn accept_flow<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<RecvSession>,
    first: Option<FirstCtl<L::Conn>>,
) {
    let cfg = &inner.sh.cfg;
    let key = s.key;
    let mut first = first;
    // занять место сразу и атомарно: два одновременных ответа не превысят предел
    if inner.claim_slot(&s).is_none() {
        inner.remove_inb_tomb(&key, Tomb::Busy);
        if let Some(f) = first.as_mut() {
            write_decision(&mut f.tx, key.id, Verdict::Busy, cfg.msg_timeout).await;
        }
        s.emit(TransferEvent::Failed {
            key,
            reason: FailReason::Busy,
        });
        return;
    }
    let dir = state_dir_name(&key.pair, &key.id);
    let s2 = s.clone();
    let g = inner.sh.tracker.guard();
    let made = inner
        .sh
        .rt
        .spawn_blocking(move || {
            let _g = g;
            // каталог передачи: база от размещения (папка, выбранная для этого предложения)
            // или `partial_dir` из настроек
            let base = s2.choose_sdir()?;
            create_session_dir(&base, &dir)?;
            // имена один раз в отдельный неизменяемый файл; состояние хранит только статусы
            s2.write_names_once()?;
            // служебные данные размещения (этап 15); ошибка отменяет передачу как `Limits`
            if s2.ensure_prepared().is_err() {
                remove_session(s2.sdir());
                s2.sh.placement.forget(&s2.key);
                return Err(std::io::Error::from(std::io::ErrorKind::Other));
            }
            let saved = s2.persist();
            if saved.is_err() {
                s2.sh.placement.forget(&s2.key);
            }
            saved
        })
        .await;
    if !matches!(made, Ok(Ok(()))) {
        lock(&s.core).phase = RPhase::Ended;
        inner.remove_inb_tomb(&key, Tomb::Limits);
        if let Some(f) = first.as_mut() {
            write_cancel(&mut f.tx, key.id, CancelReason::Limits, cfg.msg_timeout).await;
        }
        s.emit(TransferEvent::Failed {
            key,
            reason: FailReason::Limits,
        });
        return;
    }
    s.emit(TransferEvent::OfferAnswered {
        key,
        accepted: true,
    });
    s.emit(TransferEvent::Started { key });
    recv_supervisor(inner, s, first).await;
}

// ---------------------------------------------------------------- права друзей

/// Следит за событиями движка: будит ожидающих соединение, снимает передачи с пар, которые
/// больше не `Active`.
async fn friend_watch<L: Links>(inner: Arc<Inner<L>>, mut events: EngineEvents) {
    let mut down = inner.sh.shutdown.watcher();
    let mut events_open = true;
    loop {
        tokio::select! {
            e = events.recv(), if events_open => {
                if e.is_none() {
                    events_open = false;
                }
                inner.bump();
                check_friends(&inner);
            }
            () = tokio::time::sleep(inner.poll) => check_friends(&inner),
            () = down.stopped() => return,
        }
    }
}

fn check_friends<L: Links>(inner: &Arc<Inner<L>>) {
    let (outs, inbs) = {
        let reg = lock(&inner.reg);
        let outs: Vec<Arc<SendSession>> = reg
            .out
            .values()
            .filter(|s| !s.is_finished())
            .cloned()
            .collect();
        let inbs: Vec<Arc<RecvSession>> = reg.inb.values().cloned().collect();
        (outs, inbs)
    };
    for s in outs {
        if inner.links.permission(&s.key.pair).is_none() {
            cancel_out(inner, &s);
        }
    }
    for s in inbs {
        if inner.links.permission(&s.key.pair).is_none() {
            let _ = cancel_inb(&s);
        }
    }
}
