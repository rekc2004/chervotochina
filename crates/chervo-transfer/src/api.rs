//! Публичный интерфейс передачи файлов: `Transfers`. Приём входящих потоков (предложения,
//! возобновление, потоки данных), запуск, отмена и остановка.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chervo_connect::{EngineEvents, IncomingStream, StreamInbox};
use chervo_identity::PairId;
use chervo_transport::{Connection, SendStream};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, broadcast, oneshot, watch};
use tokio::time::timeout;

use crate::codec::{CancelReason, Message, OfferAssembler, Verdict, encode};
use crate::config::TransferConfig;
use crate::events::{
    FailReason, PauseReason, Side, TransferError, TransferEvent, TransferEvents, TransferStatus,
};
use crate::inner::{Inner, Registry};
use crate::limits::{
    MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_OFFER_BYTES, MAX_OFFER_TOTAL, STREAM_TRANSFER_CTL,
    STREAM_TRANSFER_DATA,
};
use crate::links::Links;
use crate::names::{TransferId, TransferKey, UntrustedName};
use crate::paths::create_session_dir;
use crate::placement::Placement;
use crate::policy::{AcceptPolicy, OfferView, PolicyVerdict};
use crate::receiver::{Finish, FirstCtl, RPhase, RecvSession, recv_supervisor};
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

fn permits(bytes: u64) -> usize {
    usize::try_from(bytes / 1024)
        .unwrap_or(usize::MAX)
        .min(Semaphore::MAX_PERMITS)
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
            recv_budget: Arc::new(Semaphore::new(permits(cfg.recv_buffer_budget))),
            send_budget: Arc::new(Semaphore::new(permits(cfg.send_buffer_budget))),
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
        pending.then(|| s.offer_view())
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
        if accept && active_inbound(inner) >= inner.sh.cfg.max_inbound_active {
            return Err(TransferError::Busy);
        }
        let answer = s.take_answer().ok_or(TransferError::WrongState)?;
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

/// Сколько принятых (не ожидающих решения) входящих передач сейчас идёт.
fn active_inbound<L: Links>(inner: &Arc<Inner<L>>) -> usize {
    lock(&inner.reg)
        .inb
        .values()
        .filter(|s| !matches!(lock(&s.core).phase, RPhase::Pending | RPhase::Ended))
        .count()
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
    if inner.links.permission(&pair).is_none() || !inner.ctl_rate_ok(&pair) {
        return;
    }
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
            receive_offer(&inner, conn, tx, rx, buf, TransferKey { pair, id }, head).await;
        }
        Ok(Ok(Some(Message::Resume { id }))) => {
            handle_resume(inner.clone(), conn, tx, rx, buf, TransferKey { pair, id }).await;
        }
        // первое сообщение не из допустимых для этого потока: поток закрывается
        _ => {}
    }
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
    let mut asm = match OfferAssembler::new(head.0, head.1, head.2) {
        Ok(a) => a,
        Err(_) => {
            write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await;
            return;
        }
    };
    // записи собираются в пределах `offer_read_timeout` на всё предложение
    let deadline = tokio::time::Instant::now() + cfg.offer_read_timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let m = timeout(left, read_message(&mut rx, &mut buf, cfg.msg_timeout)).await;
        let done = match m {
            Ok(Ok(Some(Message::OfferFiles(v)))) => match asm.push(v) {
                Ok(done) => done,
                Err(_) => {
                    write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await;
                    return;
                }
            },
            _ => {
                write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await;
                return;
            }
        };
        if done {
            break;
        }
    }
    let Ok(files) = asm.finish() else {
        write_decision(&mut tx, key.id, Verdict::Limits, cfg.msg_timeout).await;
        return;
    };
    let Some(perm) = inner.links.permission(&key.pair) else {
        return;
    };
    let list: Vec<(UntrustedName, u64)> = files.iter().map(|f| (f.name.clone(), f.size)).collect();
    let (ans_tx, ans_rx) = oneshot::channel::<bool>();
    let s = RecvSession::pending(inner.sh.clone(), key, list, head.1, ans_tx);
    // один ожидающий ответа от друга и не больше `max_pending_offers` всего
    let busy = {
        let mut reg = lock(&inner.reg);
        let pending = reg
            .inb
            .values()
            .filter(|x| lock(&x.core).phase == RPhase::Pending)
            .count();
        let busy = reg.inb.contains_key(&key)
            || reg.inb.values().any(|x| x.key.pair == key.pair)
            || pending >= cfg.max_pending_offers;
        if !busy {
            reg.inb.insert(key, s.clone());
        }
        busy
    };
    if busy {
        write_decision(&mut tx, key.id, Verdict::Busy, cfg.msg_timeout).await;
        return;
    }
    let view = s.offer_view();
    let verdict = inner.policy.decide(&key.pair, perm, &view);
    match verdict {
        PolicyVerdict::Decline => {
            inner.remove_inb(&key);
            write_decision(&mut tx, key.id, Verdict::Decline, cfg.msg_timeout).await;
            return;
        }
        PolicyVerdict::Ask => s.emit(TransferEvent::OfferReceived { key }),
        PolicyVerdict::Accept => {
            if let Some(a) = s.take_answer() {
                let _ = a.send(true);
            }
        }
    }
    pending_task(inner.clone(), s, conn, tx, rx, buf, ans_rx).await;
}

enum Pending {
    Answer(bool),
    Expired,
    SenderCancelled,
    Lost,
    Shutdown,
}

/// Ждёт решения. Ничего на диск не пишется до принятия.
async fn pending_task<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<RecvSession>,
    conn: L::Conn,
    mut tx: <L::Conn as Connection>::Tx,
    mut rx: <L::Conn as Connection>::Rx,
    mut buf: Vec<u8>,
    mut answer: oneshot::Receiver<bool>,
) {
    let cfg = &inner.sh.cfg;
    let mut down = inner.sh.shutdown.watcher();
    let p = tokio::select! {
        a = &mut answer => a.map_or(Pending::Lost, Pending::Answer),
        () = tokio::time::sleep(cfg.offer_ttl) => Pending::Expired,
        m = read_message(&mut rx, &mut buf, cfg.msg_timeout) => match m {
            Ok(Some(Message::Cancel { id, .. })) if id == s.key.id => Pending::SenderCancelled,
            _ => Pending::Lost,
        },
        () = conn.closed() => Pending::Lost,
        () = down.stopped() => Pending::Shutdown,
    };
    let key = s.key;
    match p {
        Pending::Shutdown => {}
        Pending::Answer(true) => accept_flow(inner, s, conn, tx, rx).await,
        Pending::Answer(false) => {
            inner.remove_inb(&key);
            s.emit(TransferEvent::OfferAnswered {
                key,
                accepted: false,
            });
            write_decision(&mut tx, key.id, Verdict::Decline, cfg.msg_timeout).await;
        }
        Pending::Expired => {
            inner.remove_inb(&key);
            s.take_answer();
            write_decision(&mut tx, key.id, Verdict::Expired, cfg.msg_timeout).await;
            s.emit(TransferEvent::Failed {
                key,
                reason: FailReason::Expired,
            });
        }
        Pending::SenderCancelled | Pending::Lost => {
            inner.remove_inb(&key);
            s.take_answer();
            s.emit(TransferEvent::Cancelled {
                key,
                by: Side::Sender,
            });
        }
    }
}

/// Принято: каталог и первое состояние на диск, DECISION{Accept}, потоки данных.
async fn accept_flow<L: Links>(
    inner: Arc<Inner<L>>,
    s: Arc<RecvSession>,
    conn: L::Conn,
    mut tx: <L::Conn as Connection>::Tx,
    rx: <L::Conn as Connection>::Rx,
) {
    let cfg = &inner.sh.cfg;
    let key = s.key;
    if active_inbound(&inner) >= cfg.max_inbound_active {
        inner.remove_inb(&key);
        write_decision(&mut tx, key.id, Verdict::Busy, cfg.msg_timeout).await;
        s.emit(TransferEvent::Failed {
            key,
            reason: FailReason::Busy,
        });
        return;
    }
    // занять место сразу: два одновременных ответа не превысят предел
    lock(&s.core).phase = RPhase::Active;
    let dir = state_dir_name(&key.pair, &key.id);
    let (base, s2) = (cfg.partial_dir.clone(), s.clone());
    let g = inner.sh.tracker.guard();
    let made = inner
        .sh
        .rt
        .spawn_blocking(move || {
            let _g = g;
            create_session_dir(&base, &dir)?;
            s2.persist()
        })
        .await;
    if !matches!(made, Ok(Ok(()))) {
        lock(&s.core).phase = RPhase::Ended;
        inner.remove_inb(&key);
        let mut out = Vec::new();
        if encode(
            &Message::Cancel {
                id: key.id,
                reason: CancelReason::Limits,
            },
            &mut out,
        )
        .is_ok()
        {
            let _ = timeout(cfg.msg_timeout, tx.write_all(&out)).await;
        }
        let _ = tx.finish();
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
    recv_supervisor(inner, s, Some(FirstCtl { conn, tx, rx })).await;
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
