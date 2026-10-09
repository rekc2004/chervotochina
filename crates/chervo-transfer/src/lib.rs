//! Протокол передачи: типы сообщений и заглушка декодера с границей длины.

use std::fmt;

/// Верхняя граница длины сообщения протокола.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHash(pub [u8; 32]);

/// Без Debug: пути файлов не печатаются через derive.
#[derive(Clone)]
pub struct FileEntry {
    pub rel_path: String,
    pub size: u64,
    pub root_hash: BlockHash,
}

/// Без Debug.
#[derive(Clone)]
pub struct Offer {
    pub id: TransferId,
    pub files: Vec<FileEntry>,
}

/// Без Debug.
#[derive(Clone)]
pub enum Message {
    Offer(Offer),
    Accept(TransferId),
    Reject(TransferId),
    Resume {
        id: TransferId,
        file_index: u32,
        from_block: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    TooLong,
    NotImplemented,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooLong => "message too long",
            Self::NotImplemented => "not implemented",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ProtocolError {}

/// Заглушка: длина сверх границы даёт `TooLong`, иначе `NotImplemented`. Никогда не `Ok`.
pub fn decode_message(bytes: &[u8]) -> Result<Message, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        Err(ProtocolError::TooLong)
    } else {
        Err(ProtocolError::NotImplemented)
    }
}
