//! Общее для всех сессий (не зависит от типа `Links`): настройки, события, бюджеты памяти,
//! счётчик задач и точки подмены для тестов.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::runtime::Handle;
use tokio::sync::{Semaphore, broadcast};

use crate::config::TransferConfig;
use crate::events::TransferEvent;
use crate::placement::Placement;
use crate::util::{Stop, Tracker};

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Точки, в которых тест может вмешаться (подменить ошибку записи, испортить файл, остановить
/// передачу в нужный момент). В рабочем запуске подмены нет.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum HookPoint<'a> {
    /// Перед записью блока на диск.
    Write {
        file: u32,
        block: u32,
        data: &'a [u8],
    },
    /// Блок записан и отмечен в карте.
    Written { file: u32, block: u32 },
    /// `sync_data` файла выполнен.
    Synced { file: u32 },
    /// Перед записью файла состояния.
    StateWrite { bytes: &'a [u8] },
    /// Манифест файла получен и проверен.
    Manifest { file: u32 },
    /// Перед итоговым перечитыванием файла с диска.
    FinalVerify { file: u32 },
    /// Корень на диске совпал, до вызова `Placement`.
    BeforePlace { file: u32 },
    /// Отправитель: перед хэшированием очередного блока своего файла.
    HashBlock { file: u32, block: u32 },
}

pub(crate) trait Hook: Send + Sync {
    fn at(&self, p: HookPoint<'_>) -> io::Result<()>;
}

pub(crate) struct Shared {
    pub(crate) cfg: TransferConfig,
    pub(crate) events: broadcast::Sender<TransferEvent>,
    pub(crate) placement: Arc<dyn Placement>,
    pub(crate) hook: Option<Arc<dyn Hook>>,
    pub(crate) rt: Handle,
    /// Все задачи; `shutdown` ждёт нуля.
    pub(crate) tracker: Tracker,
    pub(crate) shutdown: Stop,
    pub(crate) recv_budget: Arc<Semaphore>,
    pub(crate) send_budget: Arc<Semaphore>,
}

impl Shared {
    pub(crate) fn emit(&self, e: TransferEvent) {
        let _ = self.events.send(e);
    }

    pub(crate) fn hook(&self, p: HookPoint<'_>) -> io::Result<()> {
        match &self.hook {
            Some(h) => h.at(p),
            None => Ok(()),
        }
    }

    /// Блокирующая работа под счётчиком задач.
    pub(crate) fn spawn_blocking<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let g = self.tracker.guard();
        drop(self.rt.spawn_blocking(move || {
            let _g = g;
            f();
        }));
    }
}

/// Килобайты бюджета для блока (округление вверх).
pub(crate) fn kib(len: u32) -> u32 {
    len.div_ceil(1024).max(1)
}
