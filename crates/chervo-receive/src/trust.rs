//! Подтверждение доверия перед включением автоприёма (Рев. 3, решение владельца 2026-10-18).
//! Автоприём для друга включается только после явного вопроса пользователю
//! (`texts::TRUST_QUESTION_TEXT`). Окно или команда создаёт `TrustConfirmation` только после
//! ответа «да»; без этого значения включающая функция не вызывается (тип нельзя получить
//! случайно: нет `Default`, `Clone`, `Copy`, значение расходуется при вызове).

use chervo_friends::{AutoAcceptLimits, FriendBook, FriendsError, Permission};
use chervo_identity::{ListKeyStore, PairId};

/// Ответ пользователя «да» на вопрос `TRUST_QUESTION_TEXT`. Одноразовое значение.
#[derive(Debug)]
#[must_use = "подтверждение нужно передать включающей функции"]
pub struct TrustConfirmation {
    _private: (),
}

impl TrustConfirmation {
    /// Вызывается интерфейсом строго после того, как пользователь увидел
    /// `TRUST_QUESTION_TEXT` и ответил «да». Код приёма не может проверить это сам.
    pub fn user_confirmed_trust() -> Self {
        Self { _private: () }
    }
}

/// Разрешение «автоприём» для файла друзей. Лимитов объёма нет (решение владельца); поля
/// `AutoAcceptLimits` остаются из-за формата файла друзей и ненулевых проверок, политика
/// приёма их не читает.
pub fn auto_accept_permission(_confirmation: TrustConfirmation) -> Permission {
    Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: u64::MAX,
        max_files: u32::MAX,
    })
}

/// Включает автоприём для друга. Единственный путь из этого крейта; требует подтверждения.
pub fn enable_auto_accept<K: ListKeyStore + ?Sized>(
    book: &mut FriendBook,
    keys: &K,
    pair: &PairId,
    confirmation: TrustConfirmation,
) -> Result<(), FriendsError> {
    book.set_permission(keys, pair, auto_accept_permission(confirmation))
}

/// Выключает автоприём (обратно к вопросу по умолчанию). Подтверждение не нужно.
pub fn disable_auto_accept<K: ListKeyStore + ?Sized>(
    book: &mut FriendBook,
    keys: &K,
    pair: &PairId,
) -> Result<(), FriendsError> {
    book.set_permission(keys, pair, Permission::Ask)
}
