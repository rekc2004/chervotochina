//! Решение о приёме предложения подставляется снаружи. Этап 14 всегда спрашивает пользователя:
//! автоприём (лимиты, исполняемые типы) требует разбора имён и относится к этапу 15.

use std::fmt;
use std::path::PathBuf;

use chervo_friends::Permission;
use chervo_identity::PairId;

use crate::names::{OfferedFile, TransferKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Ask,
    Accept,
    Decline,
}

/// Ещё не полученные байты одной входящей передачи (идущей, приостановленной или уже принятой,
/// но ещё не начавшейся). Нужны политике, чтобы не обещать одно и то же свободное место
/// нескольким приёмам (Рев. 5 этапа 15). `Debug` скрыт: внутри путь.
#[derive(Clone, PartialEq, Eq)]
pub struct InboundReservation {
    /// Каталог временных данных (`partial_dir`), где лежит или будет лежать эта передача:
    /// по нему политика определяет том.
    pub partial_dir: PathBuf,
    /// Сколько байт передача ещё должна получить (не больше её размера).
    pub outstanding: u64,
}

impl fmt::Debug for InboundReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InboundReservation(..)")
    }
}

/// Предложение глазами получателя. `Debug` скрыт: внутри имена.
#[derive(Clone)]
pub struct OfferView {
    pub key: TransferKey,
    pub files: Vec<OfferedFile>,
    pub total_size: u64,
    /// Остальные входящие передачи, которым ещё нужно место на диске (Active, Paused и
    /// принятые, но не начавшиеся). Само это предложение сюда не входит. Заполняет `Transfers`
    /// в момент решения и в `Transfers::offer`; пусто, если других передач нет.
    pub inbound: Vec<InboundReservation>,
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
