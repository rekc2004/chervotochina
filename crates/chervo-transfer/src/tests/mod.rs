#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Тесты частей X1 (кодек, хэши, состояние, fuzz-смоук) и X2/X3 (сессии, писатель, размещение).

mod codec;
mod dos;
mod fake;
mod flow;
mod fuzz;
mod hash;
mod hashprog;
mod hooks;
mod integrity;
mod kit;
mod liveness;
mod place;
mod redaction;
mod relink;
mod reserve;
mod resume;
mod round2;
mod src_guard;
mod state;

use chervo_transport::{RecvStream, TransportError};

use crate::{Message, encode};

/// Поток в памяти: отдаёт `data` кусками не больше `chunk`, считает выданные байты.
/// После данных либо чисто заканчивается, либо зависает (`hang`).
pub(crate) struct MemRx {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    hang: bool,
}

impl MemRx {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            chunk: usize::MAX,
            hang: false,
        }
    }

    pub(crate) fn chunked(data: Vec<u8>, chunk: usize) -> Self {
        Self {
            chunk: chunk.max(1),
            ..Self::new(data)
        }
    }

    pub(crate) fn hanging(data: Vec<u8>) -> Self {
        Self {
            hang: true,
            ..Self::new(data)
        }
    }

    /// Сколько байт уже выдано читателю.
    pub(crate) fn taken(&self) -> usize {
        self.pos
    }
}

impl RecvStream for MemRx {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        let left = self.data.len() - self.pos;
        if left == 0 {
            if self.hang {
                std::future::pending::<()>().await;
            }
            return Ok(None);
        }
        let n = left.min(buf.len()).min(self.chunk);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(Some(n))
    }
}

/// Кадр целиком: u32 длины и тело.
pub(crate) fn frame(msg: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    encode(msg, &mut out).unwrap();
    out
}

/// Только тело кадра.
pub(crate) fn body(msg: &Message) -> Vec<u8> {
    frame(msg)[4..].to_vec()
}
