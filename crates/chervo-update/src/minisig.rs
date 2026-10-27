//! Разбор файлов minisign: публичный ключ и подпись. Только формат; примитивы в `verify`.
//!
//! Формат сверен 2026-10-27 с описанием на jedisct1.github.io/minisign и исходником
//! `src/minisign.c` (ветка master): префиксы `untrusted comment: ` и `trusted comment: `,
//! алгоритм `Ed` (ключ, устаревшая подпись) и `ED` (подпись над BLAKE2b-512), key_id 8 байт.

use ed25519_dalek::VerifyingKey;

use crate::{KeyId, MAX_MINISIG_LEN, MAX_PUBKEY_LEN, UpdateError, b64};

const COMMENT_PREFIX: &[u8] = b"untrusted comment: ";
const TRUSTED_PREFIX: &[u8] = b"trusted comment: ";
/// Предел текста комментария (строка без перевода строки), байт.
const MAX_COMMENT_LEN: usize = 1024;

/// Разобранный публичный ключ.
pub(crate) struct ParsedPubkey {
    pub key_id: KeyId,
    pub key: VerifyingKey,
}

/// Разобранная подпись (обе подписи ещё не проверены).
pub(crate) struct ParsedSig {
    pub key_id: KeyId,
    pub sig: [u8; 64],
    pub trusted_comment: String,
    pub global_sig: [u8; 64],
}

/// Делит на строки по `\n`; перед `\n` допускается один `\r`. Последняя строка может быть без
/// `\n`. Пустой хвост после последнего `\n` строкой не считается.
fn split_lines(b: &[u8]) -> Option<Vec<&[u8]>> {
    let mut lines = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        match rest.iter().position(|&c| c == b'\n') {
            Some(i) => {
                let mut line = &rest[..i];
                if let Some(stripped) = line.strip_suffix(b"\r") {
                    line = stripped;
                }
                lines.push(line);
                rest = &rest[i + 1..];
            }
            None => {
                lines.push(rest);
                rest = &[];
            }
        }
        if lines.len() > 8 {
            return None;
        }
    }
    Some(lines)
}

/// Строка-комментарий: префикс обязателен, текст не проверяется (только длина).
fn comment_ok(line: &[u8]) -> bool {
    line.len() <= COMMENT_PREFIX.len() + MAX_COMMENT_LEN && line.starts_with(COMMENT_PREFIX)
}

/// Текст доверенного комментария: табуляция, печатные ASCII и неуправляющие символы UTF-8.
fn trusted_text_ok(t: &str) -> bool {
    t.len() <= MAX_COMMENT_LEN && t.chars().all(|c| c == '\t' || !c.is_control())
}

pub(crate) fn parse_pubkey(b: &[u8]) -> Result<ParsedPubkey, UpdateError> {
    if b.len() > MAX_PUBKEY_LEN {
        return Err(UpdateError::TooLarge);
    }
    let lines = split_lines(b).ok_or(UpdateError::MalformedPubkey)?;
    let [comment, key_line] = lines.as_slice() else {
        return Err(UpdateError::MalformedPubkey);
    };
    if !comment_ok(comment) {
        return Err(UpdateError::MalformedPubkey);
    }
    let raw = b64::decode_exact::<42>(key_line).ok_or(UpdateError::MalformedPubkey)?;
    if &raw[..2] != b"Ed" {
        return Err(UpdateError::UnsupportedAlgorithm);
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&raw[2..10]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[10..42]);
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| UpdateError::MalformedPubkey)?;
    if key.is_weak() {
        return Err(UpdateError::MalformedPubkey);
    }
    // `to_bytes()` возвращает исходный ввод, поэтому каноничность точки проверяем перекодированием.
    if VerifyingKey::from(key.to_edwards()).to_bytes() != pk {
        return Err(UpdateError::MalformedPubkey);
    }
    Ok(ParsedPubkey {
        key_id: KeyId(id),
        key,
    })
}

pub(crate) fn parse_minisig(b: &[u8]) -> Result<ParsedSig, UpdateError> {
    if b.len() > MAX_MINISIG_LEN {
        return Err(UpdateError::TooLarge);
    }
    let lines = split_lines(b).ok_or(UpdateError::MalformedSignature)?;
    let [comment, sig_line, trusted_line, global_line] = lines.as_slice() else {
        return Err(UpdateError::MalformedSignature);
    };
    if !comment_ok(comment) {
        return Err(UpdateError::MalformedSignature);
    }
    let raw = b64::decode_exact::<74>(sig_line).ok_or(UpdateError::MalformedSignature)?;
    let text = trusted_line
        .strip_prefix(TRUSTED_PREFIX)
        .ok_or(UpdateError::MalformedSignature)?;
    let text = std::str::from_utf8(text).map_err(|_| UpdateError::MalformedSignature)?;
    if !trusted_text_ok(text) {
        return Err(UpdateError::MalformedSignature);
    }
    let global_sig = b64::decode_exact::<64>(global_line).ok_or(UpdateError::MalformedSignature)?;
    // Алгоритм проверяем после формы: `Ed` (без предхэширования) и любой иной отвергаются.
    if &raw[..2] != b"ED" {
        return Err(UpdateError::UnsupportedAlgorithm);
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&raw[2..10]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw[10..74]);
    Ok(ParsedSig {
        key_id: KeyId(id),
        sig,
        trusted_comment: text.to_owned(),
        global_sig,
    })
}

/// Строка публичного ключа в формате minisign (`RWQ...`): `"Ed" || key_id || pk`, base64.
pub(crate) fn pubkey_line(id: KeyId, pk: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(42);
    raw.extend_from_slice(b"Ed");
    raw.extend_from_slice(&id.0);
    raw.extend_from_slice(pk);
    b64::encode(&raw)
}
