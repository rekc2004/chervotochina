//! Фоновый поток с однопоточной средой tokio (этап 18а, A2.3, решение D4). Узел 16 на
//! `current_thread` дал около 157-160 МиБ/с на стенде (TASK 16), многопоточная среда не нужна.
//! Публичные методы узла синхронные и могут блокироваться; вызывать их из потока интерфейса
//! нельзя по замыслу (оболочка обязана работать с узлом из своего рабочего потока).

use std::future::Future;
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot;

use super::error::NodeError;

pub(crate) struct RtThread {
    pub(crate) handle: Handle,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RtThread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RtThread(..)")
    }
}

impl RtThread {
    pub(crate) fn start() -> Result<Self, NodeError> {
        let (htx, hrx) = std::sync::mpsc::channel::<Option<Handle>>();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let join = std::thread::Builder::new()
            .name("chervo-node".to_owned())
            .spawn(move || {
                let rt = match Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(_) => {
                        let _ = htx.send(None);
                        return;
                    }
                };
                let _ = htx.send(Some(rt.handle().clone()));
                rt.block_on(async {
                    let _ = stop_rx.await;
                });
                // незавершённые блокирующие задачи не держат выход дольше двух секунд
                rt.shutdown_timeout(Duration::from_secs(2));
            })
            .map_err(|_| NodeError::Io)?;
        match hrx.recv() {
            Ok(Some(handle)) => Ok(Self {
                handle,
                stop: Some(stop_tx),
                join: Some(join),
            }),
            _ => {
                let _ = join.join();
                Err(NodeError::Io)
            }
        }
    }

    /// Останавливает среду и ждёт поток. Повторный вызов ничего не делает.
    pub(crate) fn stop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Выполнить будущее на фоновой среде и дождаться результата. `None`: среда остановлена.
pub(crate) fn run<F>(handle: &Handle, f: F) -> Option<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    drop(handle.spawn(async move {
        let _ = tx.send(f.await);
    }));
    rx.recv().ok()
}
