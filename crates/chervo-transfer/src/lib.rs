//! Протокол передачи файлов (этап 14, часть X1): кодек кадров с точными границами длины,
//! раскладка блоков, хэши SHA-256 (ring) и файл состояния получателя.
//! Спецификация: `docs/specs/stage-14-transfer.md`.
//!
//! Имена из сети лежат в `UntrustedName` и нигде не превращаются в пути. Сокетов в крейте нет.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod codec;
mod hash;
mod layout;
mod limits;
mod names;
mod state;
mod wire_io;

#[cfg(test)]
mod tests;

pub use codec::{
    BlockErrCode, CancelReason, FileErrCode, Message, OfferAssembler, ProtocolError, Verdict,
    decode_message, encode,
};
pub use hash::{BlockHash, FileRoot, file_root, leaf_hash};
pub use layout::{Layout, block_len, check_block_len, check_manifest_layout, layout};
pub use limits::{
    MAX_BLOCK, MAX_BLOCKS, MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_INPROGRESS, MAX_MESSAGE_LEN,
    MAX_NAME_BYTES, MAX_OFFER_BYTES, MAX_OFFER_TOTAL, MAX_STATE_LEN, MIN_BLOCK, PROTO_VERSION,
    STREAM_TRANSFER_CTL, STREAM_TRANSFER_DATA,
};
pub use names::{OfferedFile, TransferId, TransferKey, UntrustedName};
#[doc(hidden)]
pub use state::{RecvState, decode_state, encode_state};
pub use state::{StateError, encode_hashes, parse_hashes, state_dir_name};
pub use wire_io::{read_exact, read_message};
