//! Сигнал прерывания для оболочек без интерфейса (этап 18в): Ctrl+C и, на unix, SIGTERM
//! превращаются в сообщения по обычному каналу. Остановку (`Node::shutdown`, со снятием
//! проброса) вызывает сама оболочка тем же путём, что и команду «выход».

use std::sync::mpsc::{Receiver, Sender, channel};

use super::Node;

/// Пересылает каждое срабатывание `wait` в канал. `wait` возвращает `false`, когда сигналов
/// больше не будет. Заканчивается, когда получатель закрыт.
async fn forward(mut wait: impl AsyncFnMut() -> bool, tx: Sender<()>) {
    while wait().await {
        if tx.send(()).is_err() {
            break;
        }
    }
}

async fn watch(tx: Sender<()>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            drop(tokio::spawn(forward(
                async move || term.recv().await.is_some(),
                tx.clone(),
            )));
        }
    }
    forward(async || tokio::signal::ctrl_c().await.is_ok(), tx).await;
}

impl Node {
    /// Каждое нажатие Ctrl+C (на unix и SIGTERM) даёт одно сообщение в возвращённом канале.
    /// Подписка живёт на фоновой среде узла и заканчивается с узлом. Узел сам не останавливается:
    /// оболочка получает сообщение и вызывает `shutdown`; второе сообщение во время остановки
    /// она может считать просьбой выйти немедленно. Пока подписка не оформлена (первые
    /// миллисекунды), сигнал обрабатывается системой по умолчанию.
    pub fn interrupt_signals(&self) -> Receiver<()> {
        let (tx, rx) = channel();
        drop(self.core.rt.spawn(watch(tx)));
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn every_signal_is_forwarded_then_stops() {
        let n = AtomicUsize::new(0);
        let (tx, rx) = channel();
        forward(async || n.fetch_add(1, Ordering::SeqCst) < 3, tx).await;
        assert_eq!(rx.try_iter().count(), 3);
    }

    #[tokio::test]
    async fn closed_receiver_ends_the_task() {
        let (tx, rx) = channel();
        drop(rx);
        // без выхода по закрытому получателю этот вызов не вернулся бы
        forward(async || true, tx).await;
    }
}
