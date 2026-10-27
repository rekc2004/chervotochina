//! Мелкие помощники: сигнал остановки, счётчик задач и битовая карта.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

/// Сигнал остановки одной попытки или сессии. Остановка необратима.
#[derive(Clone)]
pub(crate) struct Stop(Arc<watch::Sender<bool>>);

impl Stop {
    pub(crate) fn new() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }

    pub(crate) fn stop(&self) {
        self.0.send_replace(true);
    }

    pub(crate) fn is_stopped(&self) -> bool {
        *self.0.borrow()
    }

    pub(crate) fn watcher(&self) -> StopWatch {
        StopWatch(self.0.subscribe())
    }
}

pub(crate) struct StopWatch(watch::Receiver<bool>);

impl StopWatch {
    /// Завершается, когда остановка объявлена (или сигнал уничтожен).
    pub(crate) async fn stopped(&mut self) {
        let _ = self.0.wait_for(|v| *v).await;
    }
}

/// Число работающих задач; `idle` ждёт нуля. Задача держит `Guard` до конца.
#[derive(Clone)]
pub(crate) struct Tracker(Arc<watch::Sender<usize>>);

impl Tracker {
    pub(crate) fn new() -> Self {
        Self(Arc::new(watch::channel(0usize).0))
    }

    pub(crate) fn guard(&self) -> Guard {
        self.0.send_modify(|n| *n = n.saturating_add(1));
        Guard(self.clone())
    }

    pub(crate) async fn idle(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|n| *n == 0).await;
    }
}

pub(crate) struct Guard(Tracker);

impl Drop for Guard {
    fn drop(&mut self) {
        (self.0).0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Битовая карта на `n` блоков (формат совпадает с битовой картой файла состояния:
/// младший бит байта это блок с меньшим номером).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Bits {
    v: Vec<u8>,
    n: u32,
}

impl Bits {
    pub(crate) fn zeros(n: u32) -> Self {
        let len = usize::try_from(n.div_ceil(8)).unwrap_or(0);
        Self { v: vec![0; len], n }
    }

    pub(crate) fn ones(n: u32) -> Self {
        let mut b = Self::zeros(n);
        for i in 0..n {
            b.set(i);
        }
        b
    }

    /// Длина `bytes` обязана быть `ceil(n/8)`, иначе все биты нулевые.
    pub(crate) fn from_bytes(n: u32, bytes: &[u8]) -> Self {
        let mut b = Self::zeros(n);
        if bytes.len() == b.v.len() {
            b.v.copy_from_slice(bytes);
        }
        b
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.v
    }

    pub(crate) fn get(&self, i: u32) -> bool {
        if i >= self.n {
            return false;
        }
        let byte = usize::try_from(i / 8).unwrap_or(usize::MAX);
        self.v.get(byte).is_some_and(|b| b & (1u8 << (i % 8)) != 0)
    }

    pub(crate) fn set(&mut self, i: u32) {
        if i >= self.n {
            return;
        }
        let byte = usize::try_from(i / 8).unwrap_or(usize::MAX);
        if let Some(b) = self.v.get_mut(byte) {
            *b |= 1u8 << (i % 8);
        }
    }

    pub(crate) fn clear(&mut self, i: u32) {
        if i >= self.n {
            return;
        }
        let byte = usize::try_from(i / 8).unwrap_or(usize::MAX);
        if let Some(b) = self.v.get_mut(byte) {
            *b &= !(1u8 << (i % 8));
        }
    }

    pub(crate) fn count_ones(&self) -> u32 {
        (0..self.n)
            .filter(|i| self.get(*i))
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }
}

/// Секунды Unix по системным часам (для файла состояния; не для таймеров).
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
