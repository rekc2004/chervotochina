//! Передача файлов между друзьями по живому соединению (этап 14, части X1-X3): кодек кадров
//! с точными границами длины, раскладка блоков, хэши SHA-256 (ring), файл состояния
//! получателя, сессии отправителя и получателя, писатель и размещение.
//! Спецификация: `docs/specs/stage-14-transfer.md`.
//!
//! Имена из сети лежат в `UntrustedName` и нигде не превращаются в пути. Итоговое имя
//! файла назначает внедряемый `Placement`. Сокетов в крейте нет.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod api;
mod codec;
mod config;
mod events;
mod fsio;
mod hash;
mod inner;
mod layout;
mod limits;
mod links;
mod names;
mod paths;
mod placement;
mod policy;
mod receiver;
mod restore;
mod rstream;
mod sched;
mod sender;
mod shared;
mod state;
mod texts;
mod util;
mod wire_io;
mod writer;

#[cfg(test)]
mod tests;

pub use api::{SourceFile, Transfers};
pub use codec::{
    BlockErrCode, CancelReason, FileErrCode, Message, OfferAssembler, ProtocolError, Verdict,
    decode_message, encode,
};
pub use config::TransferConfig;
pub use events::{
    FailReason, FileFailure, PauseReason, Side, TransferError, TransferEvent, TransferEvents,
    TransferState, TransferStatus,
};
pub use hash::{BlockHash, FileRoot, file_root, leaf_hash};
pub use layout::{Layout, block_len, check_block_len, check_manifest_layout, layout};
pub use limits::{
    MAX_BLOCK, MAX_BLOCKS, MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_INPROGRESS, MAX_MESSAGE_LEN,
    MAX_NAME_BYTES, MAX_OFFER_BYTES, MAX_OFFER_TOTAL, MAX_STATE_LEN, MIN_BLOCK, PROTO_VERSION,
    STREAM_TRANSFER_CTL, STREAM_TRANSFER_DATA,
};
pub use links::Links;
pub use names::{OfferedFile, TransferId, TransferKey, UntrustedName};
pub use placement::{
    CompletedFile, GeneratedNames, PlaceError, PlaceMethod, Placed, Placement, place_no_clobber,
};
pub use policy::{AcceptPolicy, AskAlways, OfferView, PolicyVerdict};
#[doc(hidden)]
pub use state::{RecvState, decode_state, encode_state};
pub use state::{StateError, encode_hashes, parse_hashes, state_dir_name};
pub use texts::{
    DAMAGED_TEXT, DECLINED_TEXT, DISK_FULL_TEXT, EXPIRED_TEXT, PEER_CANCELLED_TEXT,
    PEER_FORGOT_TEXT, PREPARING_TEXT, SOURCE_CHANGED_TEXT, STALLED_TEXT,
};
pub use wire_io::{read_exact, read_message};
