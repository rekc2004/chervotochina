//! Константы протокола передачи (спецификация этапа 14, X1). Все границы здесь, в одном месте.

/// Вид потока управления (первый байт потока).
pub const STREAM_TRANSFER_CTL: u8 = 0x31;
/// Вид потока данных.
pub const STREAM_TRANSFER_DATA: u8 = 0x32;
pub const PROTO_VERSION: u8 = 1;
/// Тело кадра (тип и поля), без 4 байт длины.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
/// Равно `ReceiveLimits::default().max_files`.
pub const MAX_FILES_PER_OFFER: u32 = 10_000;
/// Равно `ReceiveLimits::default().max_path_bytes`.
pub const MAX_NAME_BYTES: usize = 1024;
/// Сумма байт записей OFFER_FILES (`8 + 2 + name_len` на запись).
pub const MAX_OFFER_BYTES: u32 = 2 * 1024 * 1024;
pub const MAX_FILE_SIZE: u64 = 1 << 40;
/// 16 ТиБ.
pub const MAX_OFFER_TOTAL: u64 = 1 << 44;
pub const MIN_BLOCK: u32 = 1 << 20;
pub const MAX_BLOCK: u32 = 1 << 24;
pub const MAX_BLOCKS: u32 = 1 << 16;
pub const MAX_STATE_LEN: u64 = 4 * 1024 * 1024;
/// Не больше стольких файлов в состоянии `InProgress` (потоков данных не больше 8).
pub const MAX_INPROGRESS: usize = 8;
/// Байт на запись OFFER_FILES сверх имени: размер u64 и длина имени u16.
pub(crate) const ENTRY_OVERHEAD: u64 = 8 + 2;
