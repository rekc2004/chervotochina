//! Токены приглашения и отзыва, протокол приглашения со SAS (этап 11).
//! Спецификация: `docs/specs/stage-11-invite.md`.
//!
//! Токен приглашения секретен как пароль до использования: он несёт одноразовый гостевой
//! секрет. Часов в крейте нет: время передаёт вызывающий (`now_unix`, секунды UTC с поправкой).
//! Печатать токен, SAS, случайные значения и ключи нельзя: у типов нет `Debug` с содержимым.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

pub mod addr_flow;
mod addr_update;
mod base32;
mod error;
pub mod flow;
mod invite;
mod revocation;
mod sas;

pub use addr_update::{
    AddrUpdate, IssuedAddrUpdate, SignedAddrUpdate, decode_addr_update_bin, issue_addr_update,
};
pub use error::{AddrFlowError, FlowError, InviteError, TokenError};
pub use invite::{
    InviteDraft, InviteToken, InviteeKeys, InviteeSession, PendingInvite, issue_invite,
};
pub use revocation::{RevocationNotice, RevocationReason, issue_revocation};
pub use sas::{Sas, decode_decision, encode_decision};
use zeroize::Zeroizing;

/// Предел длины текста токена, байт; проверяется до всего остального.
pub const MAX_TOKEN_TEXT_LEN: usize = 2048;
pub const INVITE_PREFIX: &str = "CHV1";
pub const REVOCATION_PREFIX: &str = "CHR1";
pub const TOKEN_VERSION: u8 = 0x01;
pub const KIND_INVITE: u8 = 0x01;
pub const KIND_REVOCATION: u8 = 0x02;
pub const MAX_INVITE_ADDRS: usize = 8;
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 86_400;
pub const DEFAULT_TTL_SECS: u64 = 900;
pub const CLOCK_TOLERANCE_SECS: u64 = 600;
pub const MAX_INVITE_SESSIONS: u32 = 3;
pub const TOKEN_HASH_TAG: &[u8] = b"chervotochina/v1/invite-token-hash\0";
pub const COMMIT_TAG: &[u8] = b"chervotochina/v1/invite-commit\0";
pub const SAS_TAG: &[u8] = b"chervotochina/v1/invite-sas\0";
pub const PROTO_V1: u8 = 0x01;
pub const MSG_M1: u8 = 0x11;
pub const M1_LEN: usize = 194;
pub const MSG_M2: u8 = 0x12;
pub const M2_LEN: usize = 34;
pub const MSG_DECISION: u8 = 0x13;
pub const DECISION_LEN: usize = 3;
pub const SAS_DIGITS: usize = 8;
pub const ADDR_UPDATE_PREFIX: &str = "CHA1";
pub const KIND_ADDR_UPDATE: u8 = 0x03;
/// Один адрес IPv4: 11 + 8 + 64.
pub const ADDR_UPDATE_MIN_LEN: usize = 83;
/// Восемь адресов IPv6: 11 + 8 * 20 + 64.
pub const ADDR_UPDATE_MAX_LEN: usize = 235;
pub const FLAG_SHORT_LIVED: u8 = 0x01;
pub const FLAG_HINT: u8 = 0x02;
pub const STREAM_ADDR_INFO: u8 = 0x21;
/// Кадр ADDR_INFO: 2 + (1 + 16 + 2) + 2 + 235.
pub const ADDR_INFO_MAX_LEN: usize = 258;

/// Разобранный токен. Без `Debug`: адреса и ключи не печатаются через derive.
#[non_exhaustive]
pub enum Token {
    Invite(InviteToken),
    Revocation(RevocationNotice),
    /// Подпись ещё не проверена: `SignedAddrUpdate::verify` с ключами пары.
    AddrUpdate(SignedAddrUpdate),
}

/// Разбор текста токена (`CHV1…`, `CHR1…` или `CHA1…`). Подпись приглашения и отзыва
/// проверяется внутри; сопоставление отзыва с другом делает вызывающий. Подпись токена
/// обновления адреса проверяет `SignedAddrUpdate::verify` (ключи пары знает вызывающий).
///
/// Порядок: длина строки (до всего), ASCII, удаление пробельных символов и подъём регистра,
/// префикс, строгий base32, версия, вид, структура, ключи, подпись.
pub fn decode(text: &str) -> Result<Token, TokenError> {
    if text.len() > MAX_TOKEN_TEXT_LEN {
        return Err(TokenError::TooLong);
    }
    if !text.is_ascii() {
        return Err(TokenError::BadEncoding);
    }
    // текст приглашения несёт гостевой секрет: копии обнуляются при выходе
    // ёмкость задана заранее: collect() из фильтра перевыделял бы буфер и оставлял копии
    let mut norm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(text.len()));
    norm.extend(
        text.bytes()
            .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .map(|b| b.to_ascii_uppercase()),
    );
    let (prefix, rest) = norm.split_at_checked(4).ok_or(TokenError::BadPrefix)?;
    let want_kind = if prefix == INVITE_PREFIX.as_bytes() {
        KIND_INVITE
    } else if prefix == REVOCATION_PREFIX.as_bytes() {
        KIND_REVOCATION
    } else if prefix == ADDR_UPDATE_PREFIX.as_bytes() {
        KIND_ADDR_UPDATE
    } else {
        return Err(TokenError::BadPrefix);
    };
    let bytes = Zeroizing::new(base32::decode(rest).ok_or(TokenError::BadEncoding)?);
    if want_kind == KIND_ADDR_UPDATE {
        // порядок ошибок задаёт разбор токена обновления: длина, версия, вид, структура
        return addr_update::parse(&bytes).map(Token::AddrUpdate);
    }
    let (version, kind) = match (bytes.first(), bytes.get(1)) {
        (Some(v), Some(k)) => (*v, *k),
        _ => return Err(TokenError::Malformed),
    };
    if version != TOKEN_VERSION {
        return Err(TokenError::UnsupportedVersion);
    }
    if kind != want_kind {
        return Err(TokenError::BadKind);
    }
    match kind {
        KIND_INVITE => invite::parse(&bytes).map(Token::Invite),
        _ => revocation::parse(&bytes).map(Token::Revocation),
    }
}

/// Только для тестов: каноническая запись произвольных байт как приглашение.
#[doc(hidden)]
pub fn encode_invite_bytes(bytes: &[u8]) -> String {
    format!("{INVITE_PREFIX}{}", base32::encode(bytes))
}

/// Только для тестов: каноническая запись произвольных байт как отзыв.
#[doc(hidden)]
pub fn encode_revocation_bytes(bytes: &[u8]) -> String {
    format!("{REVOCATION_PREFIX}{}", base32::encode(bytes))
}

/// Только для тестов: каноническая запись произвольных байт как токен обновления адреса.
#[doc(hidden)]
pub fn encode_addr_update_bytes(bytes: &[u8]) -> String {
    format!("{ADDR_UPDATE_PREFIX}{}", base32::encode(bytes))
}
