//! Токены приглашения и обновления адреса: типы и заглушка разбора.
//! `decode` никогда не возвращает `Ok` до реализации (этап 11/12).

use std::fmt;
use std::net::SocketAddr;

use chervo_identity::DeviceId;

pub const MAX_TOKEN_TEXT_LEN: usize = 2048;

/// Без Debug: адреса и подписи не печатаются через derive.
#[derive(Clone)]
pub struct InviteToken {
    pub issuer: DeviceId,
    pub addrs: Vec<SocketAddr>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

/// Без Debug: адреса и подписи не печатаются через derive.
#[derive(Clone)]
pub struct AddressUpdateToken {
    pub issuer: DeviceId,
    pub addrs: Vec<SocketAddr>,
    pub seq: u64,
    pub issued_at_unix: u64,
    pub signature: [u8; 64],
}

/// Без Debug.
#[derive(Clone)]
pub enum Token {
    Invite(InviteToken),
    AddressUpdate(AddressUpdateToken),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    TooLong,
    NotImplemented,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooLong => "token text too long",
            Self::NotImplemented => "not implemented",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TokenError {}

/// Заглушка: никогда не `Ok`.
pub fn decode(text: &str) -> Result<Token, TokenError> {
    if text.len() > MAX_TOKEN_TEXT_LEN {
        Err(TokenError::TooLong)
    } else {
        Err(TokenError::NotImplemented)
    }
}
