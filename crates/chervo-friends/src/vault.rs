//! Зашифрованный файл списка: `[FILE_MAGIC][FILE_VERSION][nonce 12][шифртекст || тег 16]`,
//! AAD = первые 5 байт (заголовок). Шифр: ChaCha20-Poly1305 из `ring`, на каждую запись
//! новый случайный nonce (96 бит). Своей криптографии нет: только вызовы `ring`.

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::plain;
use crate::{BookData, FILE_MAGIC, FILE_VERSION, FriendsError, MAX_FILE_BYTES};

const HEADER_LEN: usize = 5;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_FILE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

fn aead_key(key: &[u8; 32]) -> Result<LessSafeKey, FriendsError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key.as_slice()).map_err(|_| FriendsError::Corrupt)?;
    Ok(LessSafeKey::new(unbound))
}

/// Шифрует список под `key`. Nonce случайный на каждый вызов.
pub fn seal(key: &[u8; 32], data: &BookData) -> Result<Vec<u8>, FriendsError> {
    let plaintext = plain::encode(data)?;
    let mut header = [0u8; HEADER_LEN];
    for (d, s) in header.iter_mut().zip(FILE_MAGIC.iter()) {
        *d = *s;
    }
    if let Some(v) = header.get_mut(4) {
        *v = FILE_VERSION;
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| FriendsError::RandomUnavailable)?;

    // ёмкость с запасом под тег: буфер не перевыделяется, открытый текст не остаётся в старой памяти
    let mut buf: Vec<u8> = Vec::with_capacity(plaintext.len().saturating_add(TAG_LEN));
    buf.extend_from_slice(&plaintext);
    aead_key(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header.as_slice()),
            &mut buf,
        )
        .map_err(|_| FriendsError::Corrupt)?;

    let mut file = Vec::with_capacity(HEADER_LEN + NONCE_LEN + buf.len());
    file.extend_from_slice(&header);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&buf);
    Ok(file)
}

/// Расшифровывает и разбирает файл. Длина < 33 или > `MAX_FILE_BYTES`, неверная магия, ошибка
/// AEAD (неверный ключ или порча) и ошибка разбора дают `Corrupt`; версия не 1: `UnsupportedVersion`.
pub fn open(key: &[u8; 32], file: &[u8]) -> Result<BookData, FriendsError> {
    if file.len() < MIN_FILE_LEN || file.len() > MAX_FILE_BYTES {
        return Err(FriendsError::Corrupt);
    }
    let header = file.get(..HEADER_LEN).ok_or(FriendsError::Corrupt)?;
    if header.get(..4) != Some(FILE_MAGIC.as_slice()) {
        return Err(FriendsError::Corrupt);
    }
    if header.get(4) != Some(&FILE_VERSION) {
        return Err(FriendsError::UnsupportedVersion);
    }
    let nonce: [u8; NONCE_LEN] = file
        .get(HEADER_LEN..HEADER_LEN + NONCE_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(FriendsError::Corrupt)?;
    let body = file
        .get(HEADER_LEN + NONCE_LEN..)
        .ok_or(FriendsError::Corrupt)?;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(body.to_vec());
    let plaintext = aead_key(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            buf.as_mut_slice(),
        )
        .map_err(|_| FriendsError::Corrupt)?;
    plain::decode(plaintext)
}
