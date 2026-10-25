//! Настройки передачи. Значения по умолчанию заданы спецификацией этапа 14 (X2).

use std::path::PathBuf;
use std::time::Duration;

use crate::events::TransferError;
use crate::limits::MAX_BLOCK;

/// Вопрос владельцу Q1 (этап 14б): сколько предложение ждёт возврата связи. Принято 2 минуты
/// (рекомендация спецификации); меняется одной этой константой.
const DEFAULT_OFFER_RELINK_GRACE: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct TransferConfig {
    /// Абсолютный существующий каталог. Внутри создаются только подкаталоги со служебными
    /// именами (32 hex-цифры) и файлы с фиксированными шаблонами имён.
    pub partial_dir: PathBuf,
    /// Потоков данных на передачу (1..=8).
    pub streams: u8,
    /// Одновременных запросов на поток (1..=8).
    pub per_stream_window: u8,
    pub recv_buffer_budget: u64,
    pub send_buffer_budget: u64,
    pub max_inbound_active: usize,
    pub max_outbound_active: usize,
    pub max_pending_offers: usize,
    /// Потоков управления от одного друга в минуту.
    pub ctl_in_per_min: u32,
    pub offer_read_timeout: Duration,
    /// Тело одного кадра.
    pub msg_timeout: Duration,
    /// Предложение без ответа получателя получает `DECISION{Expired}`.
    pub offer_ttl: Duration,
    /// Без единого байта на потоке с невыполненными запросами.
    pub stall_timeout: Duration,
    pub max_block_refetch: u8,
    pub max_refetch_per_transfer: u32,
    /// Отправитель: ответов на один блок за сессию.
    pub max_serve_per_block: u8,
    /// Отправитель: одновременных потоков данных (BIND) на сессию.
    pub max_data_streams: u8,
    pub resume_hold: Duration,
    pub partial_ttl: Duration,
    pub checkpoint_bytes: u64,
    pub checkpoint_interval: Duration,
    /// Перечитывать готовый файл с диска перед размещением. `false` допускается только в
    /// тестах этого крейта (`validate` отвергает его в рабочей сборке).
    pub verify_after_write: bool,
    pub progress_interval: Duration,
    /// Наименьшая допустимая скорость приёма или отдачи одного блока (байт/с). Срок на блок:
    /// `stall_timeout + длина / min_block_rate`; таймер потока (`stall_timeout`) сбрасывается
    /// каждым байтом, этот срок нет.
    pub min_block_rate: u64,
    /// Получатель: наименьшая средняя скорость хэширования у отправителя (байт/с), которую он
    /// терпит, ожидая HASH_PROGRESS. Ниже: пауза `Stalled`.
    pub min_hash_rate: u64,
    /// Сколько ожидающее ответа предложение терпит отсутствие рабочего соединения (у отправителя
    /// и у получателя). Допустимо от 1 с до `offer_ttl`.
    pub offer_relink_grace: Duration,
}

impl TransferConfig {
    pub fn new(partial_dir: PathBuf) -> Self {
        Self {
            partial_dir,
            streams: 4,
            per_stream_window: 2,
            recv_buffer_budget: 128 << 20,
            send_buffer_budget: 128 << 20,
            max_inbound_active: 4,
            max_outbound_active: 4,
            max_pending_offers: 8,
            ctl_in_per_min: 6,
            offer_read_timeout: Duration::from_secs(30),
            msg_timeout: Duration::from_secs(10),
            offer_ttl: Duration::from_secs(600),
            stall_timeout: Duration::from_secs(60),
            max_block_refetch: 3,
            max_refetch_per_transfer: 64,
            max_serve_per_block: 4,
            max_data_streams: 8,
            resume_hold: Duration::from_secs(24 * 3600),
            partial_ttl: Duration::from_secs(7 * 24 * 3600),
            checkpoint_bytes: 64 << 20,
            checkpoint_interval: Duration::from_secs(2),
            verify_after_write: true,
            progress_interval: Duration::from_millis(250),
            min_block_rate: 32 << 10,
            min_hash_rate: 8 << 20,
            offer_relink_grace: DEFAULT_OFFER_RELINK_GRACE,
        }
    }

    /// Проверка при запуске. Любая неверная настройка даёт `TransferError::Io`
    /// (отдельной ошибки настройки в интерфейсе нет).
    pub fn validate(&self) -> Result<(), TransferError> {
        let max_block = u64::from(MAX_BLOCK);
        let ok = self.partial_dir.is_absolute()
            && self.partial_dir.is_dir()
            && (1..=8).contains(&self.streams)
            && (1..=8).contains(&self.per_stream_window)
            && self.recv_buffer_budget >= max_block
            && self.send_buffer_budget >= max_block
            && self.max_inbound_active >= 1
            && self.max_outbound_active >= 1
            && self.max_pending_offers >= 1
            && self.ctl_in_per_min >= 1
            && self.max_serve_per_block >= 1
            && (1..=8).contains(&self.max_data_streams)
            && self.checkpoint_bytes >= 1
            && self.min_hash_rate >= 1 << 20
            && self.min_block_rate >= 1024
            // проверка файла с диска обязательна вне тестов крейта
            && (self.verify_after_write || cfg!(test))
            && !self.offer_read_timeout.is_zero()
            && !self.msg_timeout.is_zero()
            && !self.offer_ttl.is_zero()
            && self.offer_relink_grace >= Duration::from_secs(1)
            && self.offer_relink_grace <= self.offer_ttl
            && !self.stall_timeout.is_zero()
            && !self.resume_hold.is_zero()
            && !self.checkpoint_interval.is_zero();
        if ok { Ok(()) } else { Err(TransferError::Io) }
    }
}

impl std::fmt::Debug for TransferConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferConfig(..)")
    }
}
