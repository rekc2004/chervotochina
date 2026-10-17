//! Подтверждение доверия перед включением автоприёма (Рев. 3, решение владельца 2026-10-18;
//! Рев. 4: проверка на уровне API списка друзей). Автоприём для друга включается только после
//! явного вопроса пользователю (`texts::TRUST_QUESTION_TEXT`). Окно или команда создаёт
//! `TrustConfirmation` только после ответа «да». `FriendBook::set_permission` отказывает для
//! `Permission::AutoAccept` (`FriendsError::TrustRequired`); единственный путь это
//! `FriendBook::enable_auto_accept` с этим значением. Тип определён в `chervo-friends`
//! (зависимость идёт от приёма к друзьям) и переэкспортируется отсюда.

pub use chervo_friends::TrustConfirmation;
use chervo_friends::{AutoAcceptLimits, FriendBook, FriendsError, Permission};
use chervo_identity::{ListKeyStore, PairId};

/// Значение разрешения «автоприём». Лимитов объёма нет (решение владельца); поля
/// `AutoAcceptLimits` остаются из-за формата файла друзей. Само значение ничего не включает:
/// `FriendBook::set_permission` его отклоняет, включает только `enable_auto_accept`.
pub fn auto_accept_permission(_confirmation: TrustConfirmation) -> Permission {
    Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: u64::MAX,
        max_files: u32::MAX,
    })
}

/// Включает автоприём для друга. Требует подтверждения.
pub fn enable_auto_accept<K: ListKeyStore + ?Sized>(
    book: &mut FriendBook,
    keys: &K,
    pair: &PairId,
    confirmation: TrustConfirmation,
) -> Result<(), FriendsError> {
    book.enable_auto_accept(keys, pair, confirmation)
}

/// Выключает автоприём (обратно к вопросу по умолчанию). Подтверждение не нужно.
pub fn disable_auto_accept<K: ListKeyStore + ?Sized>(
    book: &mut FriendBook,
    keys: &K,
    pair: &PairId,
) -> Result<(), FriendsError> {
    book.set_permission(keys, pair, Permission::Ask)
}
