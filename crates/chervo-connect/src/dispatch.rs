//! Диспетчер потоков соединения с другом: первый байт — вид потока, остальное решает вид.
//! Гостевые пары сюда не попадают (`on_connection` не запускает диспетчер для гостей).
//!
//! Цикл только принимает потоки: байт вида читается и обрабатывается в отдельной задаче, так
//! что один молчащий поток не задерживает остальные потоки друга. Число одновременных чтений
//! байта вида на соединение ограничено (`max_pending_kind_reads`); сверх него приём ждёт.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_token::STREAM_ADDR_INFO;
use chervo_token::addr_flow::answer_addr_info;
use chervo_transport::{Connection, ManagedTransport, RecvStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::engine::Inner;
use crate::inbox::IncomingStream;

const MINUTE: Duration = Duration::from_secs(60);

/// Недавние потоки соединения для пределов в минуту (общие для задач потоков).
#[derive(Default)]
struct Recent {
    addr_info: VecDeque<Instant>,
    extra: VecDeque<Instant>,
}

/// Поток укладывается в предел `cap` за минуту: тогда он засчитывается.
fn within_cap(recent: &mut VecDeque<Instant>, now: Instant, cap: usize) -> bool {
    while recent
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= MINUTE)
    {
        recent.pop_front();
    }
    if recent.len() >= cap {
        return false;
    }
    recent.push_back(now);
    true
}

type SharedRecent = Arc<Mutex<Recent>>;

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Принимает потоки, пока живо соединение. ADDR_INFO обслуживается здесь, виды из
    /// `Engine::stream_inbox` уходят в приёмник, всё остальное сбрасывается. Ошибка обмена
    /// сбрасывает поток, не соединение.
    pub(crate) async fn run_streams(self: Arc<Self>, pair: PairId, conn: T::Conn) {
        let recent: SharedRecent = Arc::new(Mutex::new(Recent::default()));
        let pending = Arc::new(Semaphore::new(self.cfg.max_pending_kind_reads.max(1)));
        loop {
            let Ok((tx, rx)) = conn.accept_bi().await else {
                return;
            };
            // ждать место для чтения байта вида: обратное давление, а не рост числа задач
            let Ok(permit) = pending.clone().acquire_owned().await else {
                return;
            };
            let inner = self.clone();
            let conn = conn.clone();
            let recent = recent.clone();
            self.spawn_task(async move {
                inner
                    .handle_stream(pair, conn, tx, rx, permit, recent)
                    .await;
            });
        }
    }

    async fn handle_stream(
        self: Arc<Self>,
        pair: PairId,
        conn: T::Conn,
        tx: <T::Conn as Connection>::Tx,
        mut rx: <T::Conn as Connection>::Rx,
        permit: OwnedSemaphorePermit,
        recent: SharedRecent,
    ) {
        let mut kind = [0u8; 1];
        let read = tokio::time::timeout(self.cfg.addr_info_timeout, rx.read(&mut kind)).await;
        // место освобождается сразу после байта вида: обмен ADDR_INFO идёт дальше без него
        drop(permit);
        if !matches!(read, Ok(Ok(Some(1)))) {
            return;
        }
        match kind.first() {
            Some(&STREAM_ADDR_INFO) => self.serve_addr_info(pair, conn, tx, rx, &recent).await,
            Some(&k) => self.route_to_inbox(pair, k, conn, tx, rx, &recent),
            None => {}
        }
    }

    /// ADDR_INFO: ответ на обмен друга, с пределом в минуту и проверкой `Active`.
    async fn serve_addr_info(
        &self,
        pair: PairId,
        conn: T::Conn,
        tx: <T::Conn as Connection>::Tx,
        rx: <T::Conn as Connection>::Rx,
        recent: &SharedRecent,
    ) {
        let in_per_min = usize::try_from(self.cfg.addr_info_in_per_min).unwrap_or(usize::MAX);
        let counted = {
            let mut r = recent.lock().unwrap_or_else(PoisonError::into_inner);
            within_cap(&mut r.addr_info, Instant::now(), in_per_min)
        };
        if !counted {
            return;
        }
        let unix = self.clock.now_unix();
        let ours = {
            let mut st = self.lock();
            if !st.book.is_active(&pair) {
                return;
            }
            self.ours(&mut st, &pair, conn.remote_addr(), unix)
        };
        let res = tokio::time::timeout(
            self.cfg.addr_info_timeout,
            answer_addr_info(&conn, &pair, tx, rx, ours.as_ref()),
        )
        .await;
        if let Ok(Ok(info)) = res {
            let now = Instant::now();
            let unix = self.clock.now_unix();
            let mut st = self.lock();
            self.apply_peer_info(&mut st, pair, info, now, unix);
        }
    }

    /// Зарегистрированный вид: предел в минуту на соединение, `Active`, затем `try_send`.
    /// Приёмник переполнен или закрыт: обе половины потока сбрасываются. Незарегистрированный
    /// вид сбрасывается без учёта в пределе.
    fn route_to_inbox(
        &self,
        pair: PairId,
        kind: u8,
        conn: T::Conn,
        tx: <T::Conn as Connection>::Tx,
        rx: <T::Conn as Connection>::Rx,
        recent: &SharedRecent,
    ) {
        let Some(sender) = self.kinds_lock().get(&kind).cloned() else {
            return;
        };
        let cap = usize::try_from(self.cfg.extra_streams_in_per_min).unwrap_or(usize::MAX);
        let counted = {
            let mut r = recent.lock().unwrap_or_else(PoisonError::into_inner);
            within_cap(&mut r.extra, Instant::now(), cap)
        };
        if !counted || !self.lock().book.is_active(&pair) {
            return;
        }
        let _ = sender.try_send(IncomingStream {
            pair,
            kind,
            conn,
            tx,
            rx,
        });
    }
}
