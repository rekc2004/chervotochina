//! Живость передачи на уровне сессии. Отправитель может закрыть поток управления (или всё
//! соединение) и начать попытку заново когда угодно, поэтому всё, что ограничивает ожидание
//! отправителя, хранится в сессии, а не в попытке: новая попытка не обнуляет ни срок
//! хэширования, ни счётчики обрывов. Сбрасывает их только настоящее продвижение (принятый
//! блок или манифест, рост `hashed`, запись блока) и явное `retry` пользователя.
//!
//! Чистая логика без ввода-вывода; вызывается под замком `RecvSession::live`.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::TransferConfig;

/// Ожидание хэширования у отправителя (с первой попытки, которой оно понадобилось).
struct Wait {
    /// Начало ожидания: от него считается предел по скорости.
    start: Instant,
    /// Значение `hashed` в начале ожидания.
    h0: u64,
    /// Последний настоящий рост `hashed` (или начало ожидания).
    grown_at: Instant,
}

pub(crate) struct Liveness {
    wait: Option<Wait>,
    /// Растёт при каждом настоящем продвижении: попытка без роста счётчика бесплодна.
    seq: u64,
    /// Подряд оборванных потоков данных и бесплодных попыток без продвижения между ними.
    futile: u32,
    /// Время связи со спросом на данные без принятого блока (без текущей попытки).
    idle: Duration,
    /// Начало текущего отрезка попытки, который ещё не учтён в `idle`.
    mark: Option<Instant>,
}

/// Сколько обрывов подряд без продвижения ставят передачу на паузу `Stalled`.
pub(crate) fn stall_limit(cfg: &TransferConfig) -> u32 {
    3 * u32::from(cfg.streams)
}

/// Сколько связи со спросом на данные допускается без единого принятого блока.
pub(crate) fn idle_limit(cfg: &TransferConfig) -> Duration {
    cfg.stall_timeout.saturating_mul(stall_limit(cfg))
}

fn plus(t: Instant, d: Duration) -> Instant {
    t.checked_add(d)
        .or_else(|| t.checked_add(Duration::from_secs(86_400 * 365)))
        .unwrap_or(t)
}

impl Liveness {
    pub(crate) fn new() -> Self {
        Self {
            wait: None,
            seq: 0,
            futile: 0,
            idle: Duration::ZERO,
            mark: None,
        }
    }

    /// Явное `retry` пользователя: всё начинается с начала.
    pub(crate) fn reset(&mut self) {
        self.wait = None;
        self.futile = 0;
        self.idle = Duration::ZERO;
        self.mark = None;
    }

    /// Начало попытки; возвращает счётчик продвижения для `futile_attempt`.
    pub(crate) fn begin_attempt(&mut self, now: Instant) -> u64 {
        self.mark = Some(now);
        self.seq
    }

    /// Конец попытки: время, прошедшее при спросе на данные, копится в `idle`.
    pub(crate) fn end_attempt(&mut self, now: Instant, demand: bool) {
        if demand && let Some(m) = self.mark {
            self.idle = self.idle.saturating_add(now.saturating_duration_since(m));
        }
        self.mark = None;
    }

    /// Принят блок или манифест, блок записан, `hashed` вырос: обрывы не копятся.
    pub(crate) fn progress(&mut self, now: Instant) {
        self.seq = self.seq.wrapping_add(1);
        self.futile = 0;
        self.idle = Duration::ZERO;
        if self.mark.is_some() {
            self.mark = Some(now);
        }
    }

    /// Отправитель сообщил большее значение `hashed`, чем раньше.
    pub(crate) fn hash_grew(&mut self, now: Instant) {
        if let Some(w) = &mut self.wait {
            w.grown_at = now;
        }
        self.progress(now);
    }

    /// Ожидание хэширования началось (первый раз; повторные вызовы ничего не меняют).
    pub(crate) fn begin_wait(&mut self, now: Instant, hashed: u64) {
        if self.wait.is_none() {
            self.wait = Some(Wait {
                start: now,
                h0: hashed,
                grown_at: now,
            });
        }
    }

    /// Оборван или замолчал поток данных. Возвращает число обрывов подряд.
    pub(crate) fn stall(&mut self) -> u32 {
        self.futile = self.futile.saturating_add(1);
        self.futile
    }

    /// Попытка закончилась потерей связи. Бесплодная (продвижения с её начала не было) растит
    /// счётчик. Возвращает число обрывов подряд.
    pub(crate) fn futile_attempt(&mut self, seq0: u64) -> u32 {
        if self.seq == seq0 {
            self.futile = self.futile.saturating_add(1);
        }
        self.futile
    }

    /// Срок молчания: `stall` после последнего настоящего роста. У попытки, ещё не принявшей
    /// ни одного кадра, не раньше `stall` после её начала (`grace`): связь могла быть
    /// потеряна надолго, а кадр о росте придёт сразу после возобновления.
    pub(crate) fn silence_deadline(
        &self,
        stall: Duration,
        grace: Option<Instant>,
    ) -> Option<Instant> {
        let w = self.wait.as_ref()?;
        let from = grace.map_or(w.grown_at, |g| g.max(w.grown_at));
        Some(plus(from, stall))
    }

    /// Предел по скорости: `stall + (total - h0) / rate` от начала ожидания. Не сбрасывается
    /// ни новой попыткой, ни мелким ростом `hashed`: капающий по байту отправитель упирается в
    /// него. Для попытки без кадров (`grace`) не раньше `stall` после её начала.
    pub(crate) fn rate_deadline(
        &self,
        stall: Duration,
        rate: u64,
        total: u64,
        grace: Option<Instant>,
    ) -> Option<Instant> {
        let w = self.wait.as_ref()?;
        let left = u128::from(total.saturating_sub(w.h0));
        let secs = left.saturating_mul(1_000_000_000) / u128::from(rate.max(1));
        let extra = Duration::from_nanos(u64::try_from(secs).unwrap_or(u64::MAX));
        let d = plus(plus(w.start, stall), extra);
        Some(grace.map_or(d, |g| d.max(plus(g, stall))))
    }

    /// Срок таймера «нет принятого блока» при спросе на данные.
    pub(crate) fn idle_deadline(&self, limit: Duration) -> Option<Instant> {
        let m = self.mark?;
        Some(plus(m, limit.saturating_sub(self.idle)))
    }

    /// Спроса на данные нет (идёт своя работа: проверка, размещение): это время не считается.
    pub(crate) fn skip_idle(&mut self, now: Instant) {
        if self.mark.is_some() {
            self.mark = Some(now);
        }
    }

    pub(crate) fn idle_over(&self, limit: Duration) -> bool {
        self.idle >= limit
    }
}
