//! Планировщик получателя: какой файл в каком состоянии и какой блок запрашивать следующим.
//! Чистая логика без ввода-вывода; вызывается под замком сессии. Запросы выдаются по блокам,
//! а не по долям потоков (ARCH-08 Н9): любой свободный поток берёт следующее нужное.

use std::collections::HashMap;
use std::sync::Arc;

use crate::hash::{BlockHash, FileRoot};
use crate::layout::{Layout, block_len};
use crate::util::Bits;

/// Прогресс прошлого запуска: проверяется заново перед использованием.
pub(crate) struct Prior {
    pub(crate) layout: Layout,
    pub(crate) root: FileRoot,
    pub(crate) bits: Bits,
}

pub(crate) struct Active {
    pub(crate) layout: Layout,
    pub(crate) root: FileRoot,
    pub(crate) leaves: Arc<Vec<BlockHash>>,
    /// Записано на диск (в кэш ОС) и проверено при записи.
    pub(crate) have: Bits,
    /// Подтверждено `sync_data`: то, что можно записывать в файл состояния.
    pub(crate) durable: Bits,
    inflight: Bits,
    cursor: u32,
    pub(crate) remaining: u32,
    pub(crate) have_bytes: u64,
    refetch: HashMap<u32, u8>,
}

impl Active {
    pub(crate) fn new(
        layout: Layout,
        root: FileRoot,
        leaves: Arc<Vec<BlockHash>>,
        have: Bits,
        size: u64,
    ) -> Self {
        let remaining = layout.block_count.saturating_sub(have.count_ones());
        let mut have_bytes = 0u64;
        for i in 0..layout.block_count {
            if have.get(i) {
                have_bytes =
                    have_bytes.saturating_add(u64::from(block_len(size, layout, i).unwrap_or(0)));
            }
        }
        Self {
            layout,
            root,
            leaves,
            durable: have.clone(),
            have,
            inflight: Bits::zeros(layout.block_count),
            cursor: 0,
            remaining,
            have_bytes,
            refetch: HashMap::new(),
        }
    }

    fn next_block(&mut self) -> Option<u32> {
        let mut i = self.cursor;
        while i < self.layout.block_count {
            if !self.have.get(i) && !self.inflight.get(i) {
                self.cursor = i.saturating_add(1);
                self.inflight.set(i);
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        self.cursor = self.layout.block_count;
        None
    }

    fn release(&mut self, block: u32) {
        self.inflight.clear(block);
        self.cursor = self.cursor.min(block);
    }
}

pub(crate) enum Run {
    /// Манифест не запрашивался; `Some` у файла, восстановленного с диска.
    Waiting(Option<Prior>),
    /// Манифест запрошен одним из потоков.
    Requested(Option<Prior>),
    /// Манифест получен и проверяется, готовятся файлы на диске.
    Setup,
    Active(Box<Active>),
    /// Все блоки записаны: идёт итоговая проверка и размещение.
    Finalizing(Box<Active>),
    Placed(FileRoot),
    Failed,
}

impl Run {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Placed(_) | Self::Failed)
    }

    fn in_progress(&self) -> bool {
        matches!(
            self,
            Self::Requested(_)
                | Self::Setup
                | Self::Active(_)
                | Self::Finalizing(_)
                | Self::Waiting(Some(_))
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Work {
    Block {
        file: u32,
        block: u32,
        len: u32,
    },
    Manifest {
        file: u32,
    },
    /// Пустой файл: запросов нет, нужно только создать и оформить.
    Zero {
        file: u32,
    },
    Wait,
    AllDone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BadBlock {
    Requeue,
    FileFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// Блока уже нет в плане (файл закрыт) или он уже был записан.
    Ignored,
    Written {
        len: u32,
    },
    /// Записан последний блок: файл перешёл в `Finalizing`.
    Last {
        len: u32,
    },
}

pub(crate) struct Sched {
    pub(crate) runs: Vec<Run>,
    sizes: Vec<u64>,
    /// `prefix[i]` = размеры файлов `0..=i`: манифест файла `i` просят, когда `hashed >= prefix[i]`.
    prefix: Vec<u64>,
    /// Сколько байт предложения отправитель уже захэшировал (только в памяти; 0 после
    /// перезапуска).
    pub(crate) hashed: u64,
    cap: usize,
    pub(crate) refetch_total: u32,
    max_block: u8,
    max_total: u32,
}

impl Sched {
    pub(crate) fn new(
        runs: Vec<Run>,
        sizes: Vec<u64>,
        cap: usize,
        max_block: u8,
        max_total: u32,
    ) -> Self {
        let mut acc = 0u64;
        let prefix = sizes
            .iter()
            .map(|s| {
                acc = acc.saturating_add(*s);
                acc
            })
            .collect();
        Self {
            runs,
            sizes,
            prefix,
            hashed: 0,
            cap,
            refetch_total: 0,
            max_block,
            max_total,
        }
    }

    pub(crate) fn size(&self, file: u32) -> u64 {
        self.sizes
            .get(usize::try_from(file).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(0)
    }

    fn run_mut(&mut self, file: u32) -> Option<&mut Run> {
        self.runs
            .get_mut(usize::try_from(file).unwrap_or(usize::MAX))
    }

    pub(crate) fn run(&self, file: u32) -> Option<&Run> {
        self.runs.get(usize::try_from(file).unwrap_or(usize::MAX))
    }

    pub(crate) fn all_terminal(&self) -> bool {
        self.runs.iter().all(Run::is_terminal)
    }

    pub(crate) fn in_progress_count(&self) -> usize {
        self.runs.iter().filter(|r| r.in_progress()).count()
    }

    /// Хэши файла готовы у отправителя (пустой файл манифеста не просит).
    fn covered(&self, file: usize) -> bool {
        self.sizes.get(file).copied().unwrap_or(0) == 0
            || self.prefix.get(file).is_none_or(|p| *p <= self.hashed)
    }

    /// Есть незавершённый непустой файл, чьи хэши ещё не покрыты сообщением отправителя.
    pub(crate) fn needs_hash(&self) -> bool {
        self.runs
            .iter()
            .enumerate()
            .any(|(i, r)| !r.is_terminal() && !self.covered(i))
    }

    /// Следующая работа для потока. Блоки раньше манифестов, файлы по порядку; манифест файла
    /// просится, только когда отправитель сообщил, что файл (и всё перед ним) захэшированы.
    pub(crate) fn take(&mut self) -> Work {
        for (i, r) in self.runs.iter_mut().enumerate() {
            let Ok(file) = u32::try_from(i) else { break };
            if let Run::Active(a) = r
                && let Some(block) = a.next_block()
            {
                let size = self.sizes.get(i).copied().unwrap_or(0);
                let len = block_len(size, a.layout, block).unwrap_or(0);
                return Work::Block { file, block, len };
            }
        }
        // восстановленные файлы: их манифест нужен, чтобы подтвердить корень (покрытие
        // считается только для тех, кто ждёт: на предложении в 10 000 файлов проход по всем
        // был бы квадратичным)
        for i in 0..self.runs.len() {
            let Ok(file) = u32::try_from(i) else { break };
            if !matches!(self.runs.get(i), Some(Run::Waiting(Some(_)))) || !self.covered(i) {
                continue;
            }
            if let Some(r) = self.runs.get_mut(i)
                && let Run::Waiting(prior) = r
            {
                let p = prior.take();
                *r = Run::Requested(p);
                return Work::Manifest { file };
            }
        }
        let mut busy: Option<usize> = None;
        for i in 0..self.runs.len() {
            let Ok(file) = u32::try_from(i) else { break };
            if !matches!(self.runs.get(i), Some(Run::Waiting(None))) {
                continue;
            }
            if self.sizes.get(i).copied().unwrap_or(0) == 0 {
                if let Some(r) = self.runs.get_mut(i) {
                    *r = Run::Setup;
                }
                return Work::Zero { file };
            }
            if !self.covered(i) {
                continue;
            }
            let in_progress = *busy.get_or_insert_with(|| self.in_progress_count());
            if in_progress < self.cap {
                if let Some(r) = self.runs.get_mut(i) {
                    *r = Run::Requested(None);
                }
                return Work::Manifest { file };
            }
            break;
        }
        if self.all_terminal() {
            Work::AllDone
        } else {
            Work::Wait
        }
    }

    /// Запрос не ушёл или поток оборвался: блок снова свободен.
    pub(crate) fn release_block(&mut self, file: u32, block: u32) {
        if let Some(Run::Active(a)) = self.run_mut(file) {
            a.release(block);
        }
    }

    /// Запрос манифеста не получил ответа: файл снова ждёт.
    pub(crate) fn release_manifest(&mut self, file: u32) {
        if let Some(r) = self.run_mut(file)
            && let Run::Requested(p) = r
        {
            let p = p.take();
            *r = Run::Waiting(p);
        }
    }

    /// После остановки всех задач попытки: ничто не считается запрошенным.
    pub(crate) fn reset_requests(&mut self) {
        for r in &mut self.runs {
            match r {
                Run::Active(a) => {
                    a.inflight = Bits::zeros(a.layout.block_count);
                    a.cursor = 0;
                }
                Run::Requested(p) => {
                    let p = p.take();
                    *r = Run::Waiting(p);
                }
                _ => {}
            }
        }
    }

    /// Манифест пришёл: забрать прежний прогресс и перейти к подготовке.
    pub(crate) fn begin_setup(&mut self, file: u32) -> Option<Option<Prior>> {
        let r = self.run_mut(file)?;
        if let Run::Requested(p) = r {
            let p = p.take();
            *r = Run::Setup;
            Some(p)
        } else {
            None
        }
    }

    /// Подготовка готова. `true`: блоков не осталось, нужна итоговая проверка.
    pub(crate) fn activate(&mut self, file: u32, a: Active) -> bool {
        let Some(r) = self.run_mut(file) else {
            return false;
        };
        if !matches!(r, Run::Setup) {
            return false;
        }
        if a.remaining == 0 {
            *r = Run::Finalizing(Box::new(a));
            true
        } else {
            *r = Run::Active(Box::new(a));
            false
        }
    }

    /// Без манифеста: пустой файл переходит к итоговой проверке.
    pub(crate) fn activate_zero(&mut self, file: u32, a: Active) {
        if let Some(r) = self.run_mut(file)
            && matches!(r, Run::Setup)
        {
            *r = Run::Finalizing(Box::new(a));
        }
    }

    pub(crate) fn leaf(&self, file: u32, block: u32) -> Option<BlockHash> {
        match self.run(file)? {
            Run::Active(a) => a
                .leaves
                .get(usize::try_from(block).unwrap_or(usize::MAX))
                .copied(),
            _ => None,
        }
    }

    pub(crate) fn mark_written(&mut self, file: u32, block: u32) -> Mark {
        let size = self.size(file);
        let Some(Run::Active(a)) = self.run_mut(file) else {
            return Mark::Ignored;
        };
        if a.have.get(block) {
            a.inflight.clear(block);
            return Mark::Ignored;
        }
        let len = block_len(size, a.layout, block).unwrap_or(0);
        a.have.set(block);
        a.inflight.clear(block);
        a.remaining = a.remaining.saturating_sub(1);
        a.have_bytes = a.have_bytes.saturating_add(u64::from(len));
        if a.remaining == 0 {
            let Some(r) = self.run_mut(file) else {
                return Mark::Ignored;
            };
            if let Run::Active(boxed) = std::mem::replace(r, Run::Setup) {
                *r = Run::Finalizing(boxed);
            }
            Mark::Last { len }
        } else {
            Mark::Written { len }
        }
    }

    /// Блок не прошёл проверку хэша: повторный запрос в пределах лимитов.
    pub(crate) fn bad_block(&mut self, file: u32, block: u32) -> BadBlock {
        self.refetch_total = self.refetch_total.saturating_add(1);
        let over_total = self.refetch_total > self.max_total;
        let max_block = self.max_block;
        let Some(Run::Active(a)) = self.run_mut(file) else {
            return BadBlock::Requeue;
        };
        a.release(block);
        let n = a.refetch.entry(block).or_insert(0);
        *n = n.saturating_add(1);
        // лимит исчерпан: закрыть файл обязан вызывающий (`RecvSession::fail_file`)
        if *n > max_block || over_total {
            BadBlock::FileFailed
        } else {
            BadBlock::Requeue
        }
    }

    /// Итоговая проверка нашла несовпавшие блоки: вернуть их в работу (с учётом лимитов).
    /// `false`: лимит исчерпан, файл провален.
    pub(crate) fn finalize_mismatch(&mut self, file: u32, bad: &[u32]) -> bool {
        let max_block = self.max_block;
        let mut total = self.refetch_total;
        let max_total = self.max_total;
        let size = self.size(file);
        let Some(r) = self.run_mut(file) else {
            return false;
        };
        if !matches!(r, Run::Finalizing(_)) {
            return false;
        }
        let Run::Finalizing(mut a) = std::mem::replace(r, Run::Setup) else {
            return false;
        };
        let mut ok = true;
        for &b in bad {
            if a.have.get(b) {
                a.have.clear(b);
                a.durable.clear(b);
                a.remaining = a.remaining.saturating_add(1);
                let len = block_len(size, a.layout, b).unwrap_or(0);
                a.have_bytes = a.have_bytes.saturating_sub(u64::from(len));
            }
            a.release(b);
            total = total.saturating_add(1);
            let n = a.refetch.entry(b).or_insert(0);
            *n = n.saturating_add(1);
            if *n > max_block || total > max_total {
                ok = false;
            }
        }
        self.refetch_total = total;
        let Some(r) = self.run_mut(file) else {
            return false;
        };
        // лимит исчерпан: файл остаётся в `Finalizing`, закрыть его обязан вызывающий
        if ok {
            *r = Run::Active(a);
        } else {
            *r = Run::Finalizing(a);
        }
        ok
    }

    /// Файлы, у которых записаны все блоки, но итоговая проверка не идёт (после паузы).
    pub(crate) fn take_complete(&mut self) -> Vec<u32> {
        let mut out = Vec::new();
        for (i, r) in self.runs.iter_mut().enumerate() {
            let Ok(file) = u32::try_from(i) else { break };
            if matches!(r, Run::Active(a) if a.remaining == 0)
                && let Run::Active(a) = std::mem::replace(r, Run::Setup)
            {
                *r = Run::Finalizing(a);
                out.push(file);
            }
        }
        out
    }

    /// Итоговая проверка не удалась из-за ввода-вывода: вернуть файл к `Active` без блоков.
    pub(crate) fn unfinalize(&mut self, file: u32) {
        if let Some(r) = self.run_mut(file)
            && matches!(r, Run::Finalizing(_))
            && let Run::Finalizing(a) = std::mem::replace(r, Run::Setup)
        {
            *r = Run::Active(a);
        }
    }

    /// Подготовка не удалась: файл снова ждёт манифест (с прежним прогрессом, если был).
    pub(crate) fn restore_waiting(&mut self, file: u32, prior: Option<Prior>) {
        if let Some(r) = self.run_mut(file)
            && matches!(r, Run::Setup)
        {
            *r = Run::Waiting(prior);
        }
    }

    /// Блоки файла подтверждены `sync_data`: их можно записывать в файл состояния.
    pub(crate) fn mark_durable(&mut self, file: u32) {
        if let Some(Run::Active(a) | Run::Finalizing(a)) = self.run_mut(file) {
            a.durable = a.have.clone();
        }
    }

    /// Файл закрыт как проваленный. `false`: он уже закрыт.
    pub(crate) fn fail(&mut self, file: u32) -> bool {
        match self.run_mut(file) {
            Some(r) if !r.is_terminal() => {
                *r = Run::Failed;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn set_placed(&mut self, file: u32) {
        if let Some(r) = self.run_mut(file)
            && let Run::Finalizing(a) = r
        {
            let root = a.root;
            *r = Run::Placed(root);
        }
    }

    /// Сколько байт уже принято (размещённые файлы целиком и записанные блоки).
    pub(crate) fn done_bytes(&self) -> u64 {
        let mut sum = 0u64;
        for (i, r) in self.runs.iter().enumerate() {
            let add = match r {
                Run::Placed(_) => self.sizes.get(i).copied().unwrap_or(0),
                Run::Active(a) | Run::Finalizing(a) => a.have_bytes,
                _ => 0,
            };
            sum = sum.saturating_add(add);
        }
        sum
    }
}
