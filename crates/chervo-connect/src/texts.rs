//! Тексты для пользователя (русский). Адресов в тексты не подставляется ничего.

use chervo_friends::FriendsError;

use crate::diag::NoDirectPath;

pub const CGNAT_TEXT: &str = "Вы за CGNAT: к вам не достучаться напрямую. Соединение возможно, если у друга белый IP или проброс порта (звоните вы). Сервер-посредник для поиска появится в следующей версии; без вашего согласия программа к нему не обращается.";
pub const DOUBLE_NAT_TEXT: &str = "Ваш роутер сам стоит за другим роутером или за NAT провайдера: снаружи к вам не достучаться. Соединение возможно, если у друга белый IP или проброс порта (звоните вы).";
pub const SYMMETRIC_TEXT: &str = "У вас симметричный NAT: друзья не могут позвонить вам по известному адресу. Соединение возможно, если у друга белый IP или проброс порта (звоните вы).";
pub const UDP_BLOCKED_TEXT: &str = "Ни один друг с постоянным адресом не ответил. Возможно, ваша сеть или провайдер блокирует UDP: тогда прямое соединение невозможно. Или друзья сейчас выключены.";
pub const NO_IPV6_TEXT: &str = "Для друга известны только адреса IPv6, а у вас сейчас нет связи по IPv6: её не даёт провайдер или роутер, либо IPv6 выключен на компьютере. Попросите друга прислать токен обновления адреса с адресом IPv4 или подключитесь к сети с IPv6.";
pub const NO_KNOWN_ADDRESS_TEXT: &str =
    "Адрес друга неизвестен. Попросите у друга токен обновления адреса.";
pub const UNKNOWN_TEXT: &str = "Друг не отвечает: возможно, он выключен или сменил адрес. Если не выйдет, попросите токен обновления адреса.";
pub const REVOCATION_NOT_SENT_TEXT: &str = "Отзыв не отправлен, повторите.";
/// Любая другая ошибка при отзыве.
pub const REVOCATION_FAILED_TEXT: &str = "Не удалось выполнить отзыв. Повторите позже.";
pub const PEER_UNREACHABLE_INVITE_TEXT: &str = "Друг недоступен. Добавьте друга заново.";

/// Текст причины, по которой нет прямого пути.
pub fn user_text(reason: NoDirectPath) -> &'static str {
    match reason {
        NoDirectPath::NoKnownAddress => NO_KNOWN_ADDRESS_TEXT,
        NoDirectPath::NeedToken => chervo_addr::NEED_TOKEN_TEXT,
        NoDirectPath::BehindCgnat => CGNAT_TEXT,
        NoDirectPath::DoubleNat => DOUBLE_NAT_TEXT,
        NoDirectPath::SymmetricNat => SYMMETRIC_TEXT,
        NoDirectPath::UdpBlockedSuspected => UDP_BLOCKED_TEXT,
        NoDirectPath::NoIpv6 => NO_IPV6_TEXT,
        NoDirectPath::Unknown => UNKNOWN_TEXT,
    }
}

/// `Io` при отзыве: список не сохранён, отзыв можно повторить.
pub fn revocation_error_text(e: FriendsError) -> &'static str {
    match e {
        FriendsError::Io => REVOCATION_NOT_SENT_TEXT,
        _ => REVOCATION_FAILED_TEXT,
    }
}
