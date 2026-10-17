//! Решение о приёме предложения подставляется снаружи. Этап 14 всегда спрашивает пользователя:
//! автоприём (лимиты, исполняемые типы) требует разбора имён и относится к этапу 15.

use std::fmt;

use chervo_friends::Permission;
use chervo_identity::PairId;

use crate::names::{OfferedFile, TransferKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Ask,
    Accept,
    Decline,
}

/// Предложение глазами получателя. `Debug` скрыт: внутри имена.
#[derive(Clone)]
pub struct OfferView {
    pub key: TransferKey,
    pub files: Vec<OfferedFile>,
    pub total_size: u64,
}

impl fmt::Debug for OfferView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfferView(..)")
    }
}

pub trait AcceptPolicy: Send + Sync {
    fn decide(&self, pair: &PairId, p: Permission, offer: &OfferView) -> PolicyVerdict;
}

/// Всегда `Ask`, даже для друга с `Permission::AutoAccept`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AskAlways;

impl AcceptPolicy for AskAlways {
    fn decide(&self, _pair: &PairId, _p: Permission, _offer: &OfferView) -> PolicyVerdict {
        PolicyVerdict::Ask
    }
}
