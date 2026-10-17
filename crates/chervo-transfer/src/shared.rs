//! Общее для всех сессий (не зависит от типа `Links`): настройки, события, бюджеты памяти,
//! счётчик задач и точки подмены для тестов.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, broadcast};

use crate::config::TransferConfig;
use crate::events::TransferEvent;
use crate::placement::Placement;
use crate::util::{Stop, StopWatch, Tracker};

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
    /// Перед записью файла имён (один раз при принятии).
    NamesWrite { bytes: &'a [u8] },
    /// Перед строгим удалением старого `<i>.part` (ошибка = удалить не удалось).
    RemovePart { file: u32 },
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

/// Число разрешений семафора на `bytes` байт (по килобайту на разрешение).
pub(crate) fn permits(bytes: u64) -> usize {
    usize::try_from(bytes / 1024)
        .unwrap_or(usize::MAX)
        .min(Semaphore::MAX_PERMITS)
}

/// Самый крупный буфер, который понадобится передаче с такими файлами: блок или список хэшей
/// манифеста (с запасом на заголовок).
pub(crate) fn buffer_floor(sizes: &[u64]) -> u64 {
    let mut floor = 0u64;
    for s in sizes {
        if let Ok(l) = crate::layout::layout(*s) {
            let manifest = u64::from(l.block_count)
                .saturating_mul(32)
                .saturating_add(64);
            floor = floor.max(u64::from(l.block_size)).max(manifest);
        }
    }
    floor
}

/// Доля общего бюджета на одну передачу: `budget / max_active`, но не меньше самого крупного
/// буфера этой передачи (иначе она не могла бы двигаться) и не больше всего бюджета. Один злой
/// друг, тянущий свою долю, не отнимает память у остальных.
pub(crate) fn share_semaphore(budget: u64, max_active: usize, floor: u64) -> Arc<Semaphore> {
    let n = u64::try_from(max_active.max(1)).unwrap_or(u64::MAX);
    let bytes = (budget / n).max(floor).min(budget);
    Arc::new(Semaphore::new(permits(bytes)))
}

/// Разрешения на один буфер: из доли передачи и из общего бюджета. Освобождаются вместе.
pub(crate) struct Permits {
    _share: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

pub(crate) enum Acquired {
    Got(Permits),
    /// Памяти сейчас нет, а ждать нельзя.
    Busy,
    Stopped,
}

/// Берёт `need` килобайт сначала из доли передачи, затем из общего бюджета (порядок всегда
/// один, цикла ожидания нет). `may_wait == false`: нехватка даёт `Busy`.
pub(crate) async fn acquire_pair(
    share: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    need: u32,
    may_wait: bool,
    stop: &mut StopWatch,
) -> Acquired {
    let a = match take_one(share, need, may_wait, stop).await {
        Ok(p) => p,
        Err(e) => return e,
    };
    let b = match take_one(global, need, may_wait, stop).await {
        Ok(p) => p,
        Err(e) => return e,
    };
    Acquired::Got(Permits {
        _share: a,
        _global: b,
    })
}

async fn take_one(
    sem: &Arc<Semaphore>,
    need: u32,
    may_wait: bool,
    stop: &mut StopWatch,
) -> Result<OwnedSemaphorePermit, Acquired> {
    match sem.clone().try_acquire_many_owned(need) {
        Ok(p) => Ok(p),
        Err(TryAcquireError::Closed) => Err(Acquired::Stopped),
        Err(TryAcquireError::NoPermits) if !may_wait => Err(Acquired::Busy),
        Err(TryAcquireError::NoPermits) => {
            tokio::select! {
                p = sem.clone().acquire_many_owned(need) => p.map_err(|_| Acquired::Stopped),
                () = stop.stopped() => Err(Acquired::Stopped),
            }
        }
    }
}

/// Срок на чтение или запись `len` байт одного блока: `stall_timeout` плюс время при самой
/// медленной допустимой скорости `min_block_rate`. Таймер потока сбрасывается на каждом
/// куске, этот срок нет: капающий по байту узел не держит память дольше него.
pub(crate) fn io_deadline(cfg: &TransferConfig, len: usize) -> std::time::Duration {
    let rate = cfg.min_block_rate.max(1);
    let secs = u64::try_from(len).unwrap_or(u64::MAX).div_ceil(rate);
    cfg.stall_timeout
        .saturating_add(std::time::Duration::from_secs(secs))
}
