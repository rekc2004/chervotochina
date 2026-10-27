//! Чтение файлов блоками и проверка хэшей. Пути приходят готовыми; здесь они не строятся.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::hash::{BlockHash, FileRoot, file_root, leaf_hash};
use crate::layout::{Layout, block_len, layout};
use crate::util::Bits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFail {
    /// Файл стал короче, длиннее или блок не совпал с хэшем.
    Changed,
    Io(io::ErrorKind),
    Stopped,
}

fn io_fail(e: &io::Error) -> ReadFail {
    ReadFail::Io(e.kind())
}

fn len_usize(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Читает ровно `buf.len()` байт; конец файла раньше срока это `Changed`.
fn read_full(f: &mut File, buf: &mut [u8]) -> Result<(), ReadFail> {
    match f.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(ReadFail::Changed),
        Err(e) => Err(io_fail(&e)),
    }
}

/// Хэши всех блоков своего файла. Размер на диске обязан совпасть с предложенным до и после.
/// `before(block)` вызывается перед каждым блоком (точка подмены в тестах; ошибка прерывает
/// чтение); длина каждого захэшированного блока добавляется к `progress`.
pub(crate) fn hash_source(
    path: &Path,
    size: u64,
    stop: &AtomicBool,
    progress: &AtomicU64,
    before: &dyn Fn(u32) -> io::Result<()>,
) -> Result<(Layout, Vec<BlockHash>, FileRoot), ReadFail> {
    let l = layout(size).map_err(|_| ReadFail::Changed)?;
    let mut f = File::open(path).map_err(|e| io_fail(&e))?;
    if f.metadata().map_err(|e| io_fail(&e))?.len() != size {
        return Err(ReadFail::Changed);
    }
    let cap = len_usize(l.block_size).min(usize::try_from(size).unwrap_or(usize::MAX));
    let mut buf = vec![0u8; cap];
    let mut leaves = Vec::with_capacity(len_usize(l.block_count));
    for i in 0..l.block_count {
        if stop.load(Ordering::Relaxed) {
            return Err(ReadFail::Stopped);
        }
        before(i).map_err(|e| io_fail(&e))?;
        let len = len_usize(block_len(size, l, i).ok_or(ReadFail::Changed)?);
        let chunk = buf.get_mut(..len).ok_or(ReadFail::Changed)?;
        read_full(&mut f, chunk)?;
        leaves.push(leaf_hash(i, chunk));
        progress.fetch_add(u64::try_from(len).unwrap_or(0), Ordering::Release);
    }
    let mut extra = [0u8; 1];
    if f.read(&mut extra).map_err(|e| io_fail(&e))? != 0 {
        return Err(ReadFail::Changed);
    }
    if f.metadata().map_err(|e| io_fail(&e))?.len() != size {
        return Err(ReadFail::Changed);
    }
    let root = file_root(size, l, &leaves).map_err(|_| ReadFail::Changed)?;
    Ok((l, leaves, root))
}

/// Блок своего файла. Хэш сверяет вызывающий.
pub(crate) fn read_source_block(
    path: &Path,
    size: u64,
    l: Layout,
    block: u32,
) -> Result<Vec<u8>, ReadFail> {
    let len = len_usize(block_len(size, l, block).ok_or(ReadFail::Changed)?);
    let mut f = File::open(path).map_err(|e| io_fail(&e))?;
    let off = u64::from(block)
        .checked_mul(u64::from(l.block_size))
        .ok_or(ReadFail::Changed)?;
    f.seek(SeekFrom::Start(off)).map_err(|e| io_fail(&e))?;
    let mut buf = vec![0u8; len];
    read_full(&mut f, &mut buf)?;
    Ok(buf)
}

/// Блоки `only` (все, если `None`), чей хэш на диске не совпал с `leaves`. Слишком короткий
/// файл или его отсутствие даёт несовпадение, а не ошибку.
pub(crate) fn verify_blocks(
    path: &Path,
    size: u64,
    l: Layout,
    leaves: &[BlockHash],
    only: Option<&Bits>,
    stop: &AtomicBool,
) -> Result<Vec<u32>, ReadFail> {
    let mut bad = Vec::new();
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            for i in 0..l.block_count {
                if only.is_none_or(|o| o.get(i)) {
                    bad.push(i);
                }
            }
            return Ok(bad);
        }
        Err(e) => return Err(io_fail(&e)),
    };
    let cap = len_usize(l.block_size).min(usize::try_from(size).unwrap_or(usize::MAX));
    let mut buf = vec![0u8; cap];
    for i in 0..l.block_count {
        if stop.load(Ordering::Relaxed) {
            return Err(ReadFail::Stopped);
        }
        if !only.is_none_or(|o| o.get(i)) {
            continue;
        }
        let len = len_usize(block_len(size, l, i).ok_or(ReadFail::Changed)?);
        let off = u64::from(i)
            .checked_mul(u64::from(l.block_size))
            .ok_or(ReadFail::Changed)?;
        f.seek(SeekFrom::Start(off)).map_err(|e| io_fail(&e))?;
        let chunk = buf.get_mut(..len).ok_or(ReadFail::Changed)?;
        let ok = match read_full(&mut f, chunk) {
            Ok(()) => leaves
                .get(len_usize(i))
                .is_some_and(|want| leaf_hash(i, chunk) == *want),
            Err(ReadFail::Changed) => false,
            Err(e) => return Err(e),
        };
        if !ok {
            bad.push(i);
        }
    }
    Ok(bad)
}

/// Корень файла на диске: для проверки уже размещённого файла.
pub(crate) fn disk_root(path: &Path, size: u64) -> Result<FileRoot, ReadFail> {
    let stop = AtomicBool::new(false);
    hash_source(path, size, &stop, &AtomicU64::new(0), &|_| Ok(())).map(|(_, _, root)| root)
}
