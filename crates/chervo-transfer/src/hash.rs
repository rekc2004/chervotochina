//! SHA-256 из `ring`. Хэш блока покрывает индекс и длину; корень покрывает размер, раскладку
//! и все хэши блоков по порядку. Корень и есть хэш всего файла.

use ring::digest::{Context, SHA256};

use crate::codec::ProtocolError;
use crate::layout::Layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHash(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRoot(pub [u8; 32]);

const LEAF_DOMAIN: &[u8] = b"chervo-xfer-v1-block\0";
const ROOT_DOMAIN: &[u8] = b"chervo-xfer-v1-file\0";

fn finish(ctx: Context) -> [u8; 32] {
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    for (o, i) in out.iter_mut().zip(digest.as_ref()) {
        *o = *i;
    }
    out
}

/// SHA-256 от склейки частей.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    finish(ctx)
}

/// `SHA256("chervo-xfer-v1-block\0" || u32 index || u32 len || data)`, числа big-endian.
/// Блоки не длиннее 16 МиБ; длина свыше `u32::MAX` не встречается.
pub fn leaf_hash(index: u32, data: &[u8]) -> BlockHash {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    BlockHash(sha256(&[
        LEAF_DOMAIN,
        &index.to_be_bytes(),
        &len.to_be_bytes(),
        data,
    ]))
}

/// `SHA256("chervo-xfer-v1-file\0" || u64 size || u32 block_size || u32 block_count || leaves)`.
/// `leaves.len() != l.block_count` даёт `Malformed`.
pub fn file_root(size: u64, l: Layout, leaves: &[BlockHash]) -> Result<FileRoot, ProtocolError> {
    if u32::try_from(leaves.len()).ok() != Some(l.block_count) {
        return Err(ProtocolError::Malformed);
    }
    let mut ctx = Context::new(&SHA256);
    ctx.update(ROOT_DOMAIN);
    ctx.update(&size.to_be_bytes());
    ctx.update(&l.block_size.to_be_bytes());
    ctx.update(&l.block_count.to_be_bytes());
    for leaf in leaves {
        ctx.update(&leaf.0);
    }
    Ok(FileRoot(finish(ctx)))
}
