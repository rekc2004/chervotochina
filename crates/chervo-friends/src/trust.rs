/// Ответ пользователя «да» на вопрос о доверии (`TRUST_QUESTION_TEXT` из `chervo-receive`).
/// Без этого значения автоприём включить нельзя: `FriendBook::set_permission` отказывает для
/// `Permission::AutoAccept`, единственный путь это `FriendBook::enable_auto_accept`
/// (Рев. 4, решение владельца 2026-10-18). Одноразовое значение: нет `Default`, `Clone`, `Copy`,
/// расходуется при вызове. Тип живёт здесь, чтобы зависимость шла от `chervo-receive` к
/// `chervo-friends`; `chervo-receive` его переэкспортирует.
#[derive(Debug)]
#[must_use = "подтверждение нужно передать включающей функции"]
pub struct TrustConfirmation {
    _private: (),
}

impl TrustConfirmation {
    /// Вызывается интерфейсом строго после того, как пользователь увидел вопрос о доверии и
    /// ответил «да». Код списка друзей не может проверить это сам.
    pub fn user_confirmed_trust() -> Self {
        Self { _private: () }
    }
}
