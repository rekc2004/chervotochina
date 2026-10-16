//! Диспетчер потоков соединения с другом: первый байт — вид потока, остальное решает вид.
//! Гостевые пары сюда не попадают (`on_connection` не запускает диспетчер для гостей).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_token::STREAM_ADDR_INFO;
use chervo_token::addr_flow::answer_addr_info;
use chervo_transport::{Connection, ManagedTransport, RecvStream};
use tokio::time::Instant;

use crate::engine::Inner;

const MINUTE: Duration = Duration::from_secs(60);

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Принимает потоки, пока живо соединение. Всё, что не ADDR_INFO, сбрасывается (виды
    /// потоков этапа 14 добавятся здесь). Ошибка обмена сбрасывает поток, не соединение.
    pub(crate) async fn run_streams(self: Arc<Self>, pair: PairId, conn: T::Conn) {
        let in_per_min = usize::try_from(self.cfg.addr_info_in_per_min).unwrap_or(usize::MAX);
        let mut recent: VecDeque<Instant> = VecDeque::new();
        loop {
            let Ok((tx, mut rx)) = conn.accept_bi().await else {
                return;
            };
            let mut kind = [0u8; 1];
            let read = tokio::time::timeout(self.cfg.addr_info_timeout, rx.read(&mut kind)).await;
            if !matches!(read, Ok(Ok(Some(1)))) {
                continue;
            }
            if kind.first() != Some(&STREAM_ADDR_INFO) {
                continue;
            }
            let now = Instant::now();
            while recent
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= MINUTE)
            {
                recent.pop_front();
            }
            if recent.len() >= in_per_min {
                continue;
            }
            recent.push_back(now);
            let unix = self.clock.now_unix();
            let ours = {
                let mut st = self.lock();
                if !st.book.is_active(&pair) {
                    continue;
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
    }
}
