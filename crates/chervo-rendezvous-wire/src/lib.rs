//! Протокол «эхо-сервера» (этап 13д, Р1): клиент спрашивает у сервера, с какого адреса и порта
//! его видно из интернета, и просит проверить, доходит ли ответ с другого порта сервера.
//!
//! Только `std`, без зависимостей. Версия 1, без подписи (решение владельца В1): подделку вне
//! пути закрывает случайный `nonce` из 16 байт (угадать: 2^-128), а ответ всегда короче запроса,
//! поэтому сервер не усиливает чужой трафик. Типы `0x10..=0x7F` оставлены за этапом 13б.
//!
//! Раскладка (все числа big-endian):
//! - заголовок, байты 0..8: магия `CHRV`, версия, тип, флаги u16 (пока 0);
//! - `0x01` запрос эха, 64 байта: 8..24 nonce, 24..64 нули;
//! - `0x02` ответ эха, 48 байт: 8..24 nonce; 24 семейство (4 или 6); 25 ноль; 26..28 порт,
//!   XOR `nonce[0..2]`; 28..44 адрес (v4: XOR `nonce[2..6]` и 12 нулей, v6: XOR `nonce[0..16]`);
//!   44..46 порт проверки сервера (0: проверки нет); 46..48 нули;
//! - `0x03` запрос проверки доступа, 64 байта: 8..24 nonce, 24..26 проверяемый порт (не 0),
//!   26..64 нули;
//! - `0x04` ответ проверки, 48 байт: как `0x02`, байты 44..46 равны 0.
//!
//! XOR адреса и порта сделан по образцу RFC 8489 §14.2 [не проверено по тексту]: простые
//! «исправители» адресов в пути не узнают адрес по байтам.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC: [u8; 4] = *b"CHRV";
pub const VERSION: u8 = 1;
pub const T_ECHO_REQUEST: u8 = 0x01;
pub const T_ECHO_RESPONSE: u8 = 0x02;
pub const T_REACH_REQUEST: u8 = 0x03;
pub const T_REACH_RESPONSE: u8 = 0x04;
pub const NONCE_LEN: usize = 16;
pub const REQUEST_LEN: usize = 64;
pub const RESPONSE_LEN: usize = 48;

/// Ответ всегда короче запроса: сервер не усиливает трафик.
const _: () = assert!(RESPONSE_LEN < REQUEST_LEN);

const NONCE_AT: usize = 8;
const FAMILY_AT: usize = 24;
const PORT_AT: usize = 26;
const ADDR_AT: usize = 28;
const ADDR_LEN: usize = 16;
const REACH_PORT_AT: usize = 44;
const TARGET_PORT_AT: usize = 24;

/// Случайное число запроса. `Debug` без содержимого: по нему принимается ответ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(..)")
    }
}

/// Причина отказа разбора. Отдельного текста нет: пакет молча отбрасывается.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Length,
    Magic,
    Version,
    Type,
    Flags,
    Padding,
    Nonce,
    Family,
    Port,
    Address,
}

/// Разобранный запрос. `Debug` не показывает nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Echo(Nonce),
    Reach { nonce: Nonce, target_port: u16 },
}

/// Разобранный ответ. `reach`: это ответ проверки доступа (тип `0x04`), а не эха.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub observed: SocketAddr,
    pub reach_port: u16,
    pub reach: bool,
}

/// Записать `src` в `buf` с позиции `at` (вне границ ничего не делает: длины заданы константами).
fn put(buf: &mut [u8], at: usize, src: &[u8]) {
    if let Some(dst) = buf.get_mut(at..at.saturating_add(src.len())) {
        dst.copy_from_slice(src);
    }
}

/// Заголовок и nonce.
fn base<const N: usize>(ty: u8, nonce: &Nonce) -> [u8; N] {
    let mut b = [0u8; N];
    put(&mut b, 0, &MAGIC);
    put(&mut b, 4, &[VERSION, ty]);
    // флаги (6..8) остаются нулями
    put(&mut b, NONCE_AT, &nonce.0);
    b
}

/// Запрос эха: 64 байта.
pub fn encode_echo_request(nonce: &Nonce) -> [u8; REQUEST_LEN] {
    base(T_ECHO_REQUEST, nonce)
}

/// Запрос проверки доступа: 64 байта. `target_port` обязан быть не нулевым (иначе сервер
/// отбросит запрос).
pub fn encode_reach_request(nonce: &Nonce, target_port: u16) -> [u8; REQUEST_LEN] {
    let mut b = base::<REQUEST_LEN>(T_REACH_REQUEST, nonce);
    put(&mut b, TARGET_PORT_AT, &target_port.to_be_bytes());
    b
}

/// Все поля после заголовка, кроме nonce и содержимого, должны быть нулями.
fn zeros(buf: &[u8], from: usize, to: usize) -> bool {
    buf.get(from..to).is_some_and(|s| s.iter().all(|b| *b == 0))
}

/// Общий заголовок: длина уже проверена типом массива. Возвращает тип.
fn check_header(buf: &[u8], allowed: [u8; 2]) -> Result<u8, WireError> {
    if buf.get(0..4) != Some(&MAGIC[..]) {
        return Err(WireError::Magic);
    }
    if buf.get(4) != Some(&VERSION) {
        return Err(WireError::Version);
    }
    let ty = *buf.get(5).ok_or(WireError::Length)?;
    if !allowed.contains(&ty) {
        return Err(WireError::Type);
    }
    if !zeros(buf, 6, 8) {
        return Err(WireError::Flags);
    }
    Ok(ty)
}

fn nonce_at(buf: &[u8]) -> Result<Nonce, WireError> {
    let s = buf
        .get(NONCE_AT..NONCE_AT + NONCE_LEN)
        .ok_or(WireError::Length)?;
    let a: [u8; NONCE_LEN] = s.try_into().map_err(|_| WireError::Length)?;
    Ok(Nonce(a))
}

/// Разбор запроса. Длина обязана быть ровно 64; всё лишнее и неизвестное отвергается.
pub fn parse_request(buf: &[u8]) -> Result<Request, WireError> {
    if buf.len() != REQUEST_LEN {
        return Err(WireError::Length);
    }
    let ty = check_header(buf, [T_ECHO_REQUEST, T_REACH_REQUEST])?;
    let nonce = nonce_at(buf)?;
    if ty == T_ECHO_REQUEST {
        if !zeros(buf, TARGET_PORT_AT, REQUEST_LEN) {
            return Err(WireError::Padding);
        }
        return Ok(Request::Echo(nonce));
    }
    let port_bytes = buf
        .get(TARGET_PORT_AT..TARGET_PORT_AT + 2)
        .ok_or(WireError::Length)?;
    let target_port = u16::from_be_bytes(port_bytes.try_into().map_err(|_| WireError::Length)?);
    if !zeros(buf, TARGET_PORT_AT + 2, REQUEST_LEN) {
        return Err(WireError::Padding);
    }
    if target_port == 0 {
        return Err(WireError::Port);
    }
    Ok(Request::Reach { nonce, target_port })
}

fn encode_response(
    ty: u8,
    nonce: &Nonce,
    observed: SocketAddr,
    reach_port: u16,
) -> [u8; RESPONSE_LEN] {
    let mut b = base::<RESPONSE_LEN>(ty, nonce);
    let key = &nonce.0;
    // `::ffff:a.b.c.d` кодируется как IPv4: одна каноническая форма
    match observed.ip().to_canonical() {
        IpAddr::V4(a) => {
            put(&mut b, FAMILY_AT, &[4]);
            let mut o = a.octets();
            xor_in_place(&mut o, key.get(2..6).unwrap_or(&[]));
            put(&mut b, ADDR_AT, &o);
        }
        IpAddr::V6(a) => {
            put(&mut b, FAMILY_AT, &[6]);
            let mut o = a.octets();
            xor_in_place(&mut o, key);
            put(&mut b, ADDR_AT, &o);
        }
    }
    let mut port = observed.port().to_be_bytes();
    xor_in_place(&mut port, key.get(0..2).unwrap_or(&[]));
    put(&mut b, PORT_AT, &port);
    put(&mut b, REACH_PORT_AT, &reach_port.to_be_bytes());
    b
}

fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (d, k) in data.iter_mut().zip(key) {
        *d ^= *k;
    }
}

/// Ответ эха: наблюдаемый адрес клиента и порт проверки сервера (0: проверки нет).
pub fn encode_echo_response(
    nonce: &Nonce,
    observed: SocketAddr,
    reach_port: u16,
) -> [u8; RESPONSE_LEN] {
    encode_response(T_ECHO_RESPONSE, nonce, observed, reach_port)
}

/// Ответ проверки доступа: тот же вид, порт проверки 0.
pub fn encode_reach_response(nonce: &Nonce, observed: SocketAddr) -> [u8; RESPONSE_LEN] {
    encode_response(T_REACH_RESPONSE, nonce, observed, 0)
}

/// Сравнение без раннего выхода: nonce служит «паролем» принятия ответа.
fn same_nonce(a: &Nonce, b: &Nonce) -> bool {
    a.0.iter()
        .zip(b.0.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Разбор ответа. Длина ровно 48, nonce равен ожидаемому, наблюдаемый адрес: порт не 0, адрес
/// не неуказанный, не групповой и не широковещательный. Хвосты и паддинг обязаны быть нулями.
pub fn parse_response(buf: &[u8], expected: &Nonce) -> Result<Response, WireError> {
    if buf.len() != RESPONSE_LEN {
        return Err(WireError::Length);
    }
    let ty = check_header(buf, [T_ECHO_RESPONSE, T_REACH_RESPONSE])?;
    let nonce = nonce_at(buf)?;
    if !same_nonce(&nonce, expected) {
        return Err(WireError::Nonce);
    }
    let family = *buf.get(FAMILY_AT).ok_or(WireError::Length)?;
    if family != 4 && family != 6 {
        return Err(WireError::Family);
    }
    if !zeros(buf, FAMILY_AT + 1, PORT_AT) {
        return Err(WireError::Padding);
    }
    let key = &nonce.0;
    let port_bytes = buf.get(PORT_AT..PORT_AT + 2).ok_or(WireError::Length)?;
    let mut port = [0u8; 2];
    port.copy_from_slice(port_bytes);
    xor_in_place(&mut port, key.get(0..2).unwrap_or(&[]));
    let port = u16::from_be_bytes(port);
    let addr_bytes = buf
        .get(ADDR_AT..ADDR_AT + ADDR_LEN)
        .ok_or(WireError::Length)?;
    let ip = if family == 4 {
        let mut o = [0u8; 4];
        o.copy_from_slice(addr_bytes.get(0..4).ok_or(WireError::Length)?);
        xor_in_place(&mut o, key.get(2..6).unwrap_or(&[]));
        if !zeros(buf, ADDR_AT + 4, REACH_PORT_AT) {
            return Err(WireError::Padding);
        }
        IpAddr::V4(Ipv4Addr::from(o))
    } else {
        let mut o = [0u8; ADDR_LEN];
        o.copy_from_slice(addr_bytes);
        xor_in_place(&mut o, key);
        IpAddr::V6(Ipv6Addr::from(o))
    };
    let reach_bytes = buf
        .get(REACH_PORT_AT..REACH_PORT_AT + 2)
        .ok_or(WireError::Length)?;
    let reach_port = u16::from_be_bytes(reach_bytes.try_into().map_err(|_| WireError::Length)?);
    if !zeros(buf, REACH_PORT_AT + 2, RESPONSE_LEN) {
        return Err(WireError::Padding);
    }
    let reach = ty == T_REACH_RESPONSE;
    if reach && reach_port != 0 {
        return Err(WireError::Padding);
    }
    if port == 0 {
        return Err(WireError::Port);
    }
    let bad_ip = match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_multicast() || a.is_broadcast(),
        // `::ffff:a.b.c.d` в семействе 6 не каноническая форма: так адрес не кодируется
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast() || a.to_ipv4_mapped().is_some(),
    };
    if bad_ip {
        return Err(WireError::Address);
    }
    Ok(Response {
        observed: SocketAddr::new(ip, port),
        reach_port,
        reach,
    })
}
