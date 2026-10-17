//! Безопасный приём файлов (этап 15). Часть R1: чистые функции без файловой системы:
//! переносимый санитайзер имён, план предложения (коллизии, лимиты), классификация типов
//! и тексты предупреждений. Часть R2: папка приёма, размещение без перезаписи и без
//! переходов по ссылкам, журналы, метки происхождения и политика автоприёма.
//! Спецификация: `docs/specs/stage-15-receive.md`.
//!
//! Результат санитайзера всегда остаётся внутри корня: компоненты не бывают `.`, `..`,
//! пустыми, абсолютными, с буквой диска, обратной косой чертой или управляющими символами.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod accept;
mod classify;
mod journal;
mod limits;
mod mark;
mod name;
mod place;
mod plan;
mod policy;
mod root;
mod space;
mod texts;
mod trust;

pub use accept::{AcceptIntoError, accept_into};
pub use classify::{FileClass, TypeInfo, classify, is_known_inert};
pub use limits::{PathError, ReceiveLimits};
pub use name::{
    NameFlags, SafeRelPath, fold, is_portable_component, portable_component, sanitize_path,
    sanitize_relative_path,
};
#[doc(hidden)]
pub use place::TestPoint;
pub use place::{ChooseRootError, ReceivePlacement};
pub use plan::{OfferPlan, PlannedFile, plan_offer, plan_offer_for_root, plan_offer_in};
pub use policy::{ReceiveDecision, ReceivePolicy};
pub use root::{ReceiveConfig, ReceiveRoot, RootError};
pub use space::{DiskSpace, SpaceCheck, SpaceShortfall, disk_space};
pub use texts::{
    ACTIVE_DOC_TEXT, ASK_FILE_TEXT, CHOOSE_OTHER_FOLDER_TEXT, DECEPTIVE_TEXT, DISK_IMAGE_TEXT,
    EXECUTABLE_TEXT, HOSTILE_DECLINED_TEXT, LONG_PATH_TEXT, NAME_CHANGED_TEXT, SHARED_ROOT_TEXT,
    SUSPICIOUS_NAME_TEXT, TRUST_QUESTION_TEXT, insufficient_space_text,
};
pub use trust::{
    TrustConfirmation, auto_accept_permission, disable_auto_accept, enable_auto_accept,
};
