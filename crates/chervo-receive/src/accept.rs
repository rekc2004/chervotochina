//! Принять предложение в другую папку приёма (Рев. 5, решение владельца 2026-10-18): когда в
//! основной папке не хватает места, пользователю предлагается выбрать другую. Всё, что делает
//! размещение (санитайзер, новые каталоги верхнего уровня, отказ от ссылок), работает в новой
//! папке так же, а временные файлы передачи лежат в её `.chervo-partial` на том же томе.

use chervo_transfer::{Links, TransferError, TransferKey, Transfers};

use crate::place::{ChooseRootError, ReceivePlacement};
use crate::root::ReceiveRoot;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptIntoError {
    /// Предложения нет или оно уже не ждёт ответа.
    NoSuchOffer,
    /// Новая папка не подошла (в том числе: не хватает места на её томе).
    Root(ChooseRootError),
    /// Ответ не принят (например, уже идёт столько приёмов, сколько разрешено).
    Transfer(TransferError),
}

/// Проверяет место на томе `root` с учётом остальных приёмов, запоминает выбор и принимает
/// предложение `key`. При ошибке выбор снимается, предложение остаётся ждать ответа.
pub fn accept_into<L: Links>(
    transfers: &Transfers<L>,
    placement: &ReceivePlacement,
    key: &TransferKey,
    root: ReceiveRoot,
) -> Result<(), AcceptIntoError> {
    let offer = transfers.offer(key).ok_or(AcceptIntoError::NoSuchOffer)?;
    placement
        .choose_root(&offer, root)
        .map_err(AcceptIntoError::Root)?;
    if let Err(e) = transfers.respond(key, true) {
        placement.unchoose_root(key);
        return Err(AcceptIntoError::Transfer(e));
    }
    Ok(())
}
