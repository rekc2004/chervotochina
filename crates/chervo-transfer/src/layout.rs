//! Размер блока и число блоков выводятся из размера файла; отправитель их не выбирает.

use crate::codec::ProtocolError;
use crate::limits::{MAX_BLOCK, MAX_BLOCKS, MAX_FILE_SIZE, MIN_BLOCK};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub block_size: u32,
    pub block_count: u32,
}

/// `block_size = clamp(next_pow2(ceil(size / 65536)), 1 MiB, 16 MiB)`,
/// `block_count = ceil(size / block_size)`. Размер 0: 1 MiB и 0 блоков.
pub fn layout(size: u64) -> Result<Layout, ProtocolError> {
    if size > MAX_FILE_SIZE {
        return Err(ProtocolError::TooLarge);
    }
    let units = size.div_ceil(65_536);
    let bs = units
        .checked_next_power_of_two()
        .ok_or(ProtocolError::TooLarge)?
        .clamp(u64::from(MIN_BLOCK), u64::from(MAX_BLOCK));
    let count = size.div_ceil(bs);
    let block_size = u32::try_from(bs).map_err(|_| ProtocolError::TooLarge)?;
    let block_count = u32::try_from(count).map_err(|_| ProtocolError::TooLarge)?;
    if block_count > MAX_BLOCKS {
        return Err(ProtocolError::TooLarge);
    }
    Ok(Layout {
        block_size,
        block_count,
    })
}

/// Длина блока `index`; `None`: блока нет (индекс вне раскладки или за концом файла).
pub fn block_len(size: u64, l: Layout, index: u32) -> Option<u32> {
    if index >= l.block_count {
        return None;
    }
    let start = u64::from(index).checked_mul(u64::from(l.block_size))?;
    let rem = size.checked_sub(start)?;
    if rem == 0 {
        return None;
    }
    u32::try_from(rem.min(u64::from(l.block_size))).ok()
}

/// Байт в битовой карте на `count` блоков.
pub(crate) fn bitmap_len(count: u32) -> usize {
    usize::try_from(count.div_ceil(8)).unwrap_or(usize::MAX)
}

/// Поля MANIFEST должны совпасть с раскладкой, которую мы считаем сами по размеру файла.
/// Вызывать до чтения `block_count * 32` байт хэшей.
pub fn check_manifest_layout(
    size: u64,
    block_size: u32,
    block_count: u32,
) -> Result<Layout, ProtocolError> {
    let l = layout(size)?;
    if l.block_size != block_size || l.block_count != block_count {
        return Err(ProtocolError::Malformed);
    }
    Ok(l)
}

/// `len` из заголовка BLOCK должен совпасть с `block_len`. Вызывать до чтения тела блока.
pub fn check_block_len(size: u64, l: Layout, block: u32, len: u32) -> Result<(), ProtocolError> {
    match block_len(size, l, block) {
        Some(want) if want == len => Ok(()),
        _ => Err(ProtocolError::Malformed),
    }
}
