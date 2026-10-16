//! Обмен ADDR_INFO по одному двунаправленному потоку соединения (после Noise KK):
//! каждая сторона присылает один кадр и закрывает свою половину. В кадре: адрес, под
//! которым отправитель видит получателя, и необязательное подписанное обновление адреса.
//! Generic по `chervo_transport::Connection`, без tokio и без таймеров (срок у вызывающего).
//! Память не выделяется по длине от собеседника: только фиксированный буфер.
//!
//! Кадр (числа big-endian), длина 11..=258:
//! `[0] 0x21 [1] 0x01 [2] семейство 0x04|0x06, IP 4|16, порт u16, затем update_len u16`
//! (0 или 83..=235) и столько же байт двоичного обновления адреса.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use chervo_addr::{AddrClass, classify, normalize};
use chervo_identity::PairId;
use chervo_transport::{Connection, RecvStream, SendStream};

use crate::{
    ADDR_INFO_MAX_LEN, ADDR_UPDATE_MAX_LEN, ADDR_UPDATE_MIN_LEN, AddrFlowError, IssuedAddrUpdate,
    PROTO_V1, STREAM_ADDR_INFO, SignedAddrUpdate, decode_addr_update_bin,
};

/// Наименьший кадр: заголовок 2, IPv4 с портом 7, длина обновления 2.
const MIN_FRAME_LEN: usize = 11;
/// Заголовок и семейство.
const HEAD_LEN: usize = 3;

/// Результат обмена: что друг видит у нас и что он прислал.
pub struct PeerAddrInfo {
    /// Наш адрес с точки зрения друга.
    pub observed_me: SocketAddr,
    /// Адрес друга на пути соединения (`normalize(conn.remote_addr())` в момент получения).
    pub via: SocketAddr,
    /// Обновление адреса от друга; подпись не проверена.
    pub update: Option<SignedAddrUpdate>,
}

impl std::fmt::Debug for PeerAddrInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerAddrInfo(..)")
    }
}

/// Порт не 0 и класс не неуказанный, не multicast, не широковещательный, не v4-mapped.
fn observed_ok(a: &SocketAddr) -> bool {
    a.port() != 0
        && !matches!(
            classify(a.ip()),
            AddrClass::Unspecified
                | AddrClass::Multicast
                | AddrClass::Broadcast
                | AddrClass::V4Mapped
        )
}

/// Кадр для отправки. `observed` должен пройти правила наблюдения, иначе `Malformed`.
pub fn encode_addr_info(
    observed: SocketAddr,
    ours: Option<&IssuedAddrUpdate>,
) -> Result<Vec<u8>, AddrFlowError> {
    if !observed_ok(&observed) {
        return Err(AddrFlowError::Malformed);
    }
    let update: &[u8] = ours.map_or(&[], IssuedAddrUpdate::bytes);
    if !update.is_empty() && !(ADDR_UPDATE_MIN_LEN..=ADDR_UPDATE_MAX_LEN).contains(&update.len()) {
        return Err(AddrFlowError::Malformed);
    }
    let update_len = u16::try_from(update.len()).map_err(|_| AddrFlowError::Malformed)?;
    let mut b: Vec<u8> = Vec::with_capacity(ADDR_INFO_MAX_LEN);
    b.push(STREAM_ADDR_INFO);
    b.push(PROTO_V1);
    match observed.ip() {
        IpAddr::V4(ip) => {
            b.push(4);
            b.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            b.push(6);
            b.extend_from_slice(&ip.octets());
        }
    }
    b.extend_from_slice(&observed.port().to_be_bytes());
    b.extend_from_slice(&update_len.to_be_bytes());
    b.extend_from_slice(update);
    Ok(b)
}

fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], AddrFlowError> {
    let end = pos.checked_add(n).ok_or(AddrFlowError::Malformed)?;
    let s = b.get(*pos..end).ok_or(AddrFlowError::Malformed)?;
    *pos = end;
    Ok(s)
}

/// Разбор целого кадра. Любое отклонение (длина, заголовок, семейство, порт, класс
/// адреса, длина обновления, хвост, разбор обновления) даёт `Malformed`.
pub fn decode_addr_info(
    frame: &[u8],
) -> Result<(SocketAddr, Option<SignedAddrUpdate>), AddrFlowError> {
    if !(MIN_FRAME_LEN..=ADDR_INFO_MAX_LEN).contains(&frame.len()) {
        return Err(AddrFlowError::Malformed);
    }
    let mut pos = 0usize;
    let head = take(frame, &mut pos, 2)?;
    if head != [STREAM_ADDR_INFO, PROTO_V1] {
        return Err(AddrFlowError::Malformed);
    }
    let family = *take(frame, &mut pos, 1)?
        .first()
        .ok_or(AddrFlowError::Malformed)?;
    let ip = match family {
        4 => {
            let o: [u8; 4] = take(frame, &mut pos, 4)?
                .try_into()
                .map_err(|_| AddrFlowError::Malformed)?;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        6 => {
            let o: [u8; 16] = take(frame, &mut pos, 16)?
                .try_into()
                .map_err(|_| AddrFlowError::Malformed)?;
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return Err(AddrFlowError::Malformed),
    };
    let port_bytes: [u8; 2] = take(frame, &mut pos, 2)?
        .try_into()
        .map_err(|_| AddrFlowError::Malformed)?;
    let observed = SocketAddr::new(ip, u16::from_be_bytes(port_bytes));
    if !observed_ok(&observed) {
        return Err(AddrFlowError::Malformed);
    }
    let len_bytes: [u8; 2] = take(frame, &mut pos, 2)?
        .try_into()
        .map_err(|_| AddrFlowError::Malformed)?;
    let update_len = usize::from(u16::from_be_bytes(len_bytes));
    let update = if update_len == 0 {
        None
    } else if (ADDR_UPDATE_MIN_LEN..=ADDR_UPDATE_MAX_LEN).contains(&update_len) {
        let bytes = take(frame, &mut pos, update_len)?;
        Some(decode_addr_update_bin(bytes).map_err(|_| AddrFlowError::Malformed)?)
    } else {
        return Err(AddrFlowError::Malformed);
    };
    if pos != frame.len() {
        return Err(AddrFlowError::Malformed);
    }
    Ok((observed, update))
}

/// Дочитывает `buf[*filled..to]`; конец потока раньше даёт `Truncated`.
async fn fill<R: RecvStream>(
    rx: &mut R,
    buf: &mut [u8; ADDR_INFO_MAX_LEN],
    filled: &mut usize,
    to: usize,
) -> Result<(), AddrFlowError> {
    let to = to.min(ADDR_INFO_MAX_LEN);
    while *filled < to {
        let dst = buf.get_mut(*filled..to).ok_or(AddrFlowError::Malformed)?;
        match rx.read(dst).await? {
            None | Some(0) => return Err(AddrFlowError::Truncated),
            Some(n) => *filled = filled.saturating_add(n).min(to),
        }
    }
    Ok(())
}

/// Читает один кадр в фиксированный буфер: заголовок и семейство, затем ровно 6 или 18
/// байт адреса с портом, `update_len` (граница проверяется до чтения), ровно `update_len`
/// байт, затем одно чтение обязано дать конец потока. `kind_consumed`: нулевой байт уже
/// прочитан диспетчером.
async fn read_frame<R: RecvStream>(
    rx: &mut R,
    kind_consumed: bool,
) -> Result<(SocketAddr, Option<SignedAddrUpdate>), AddrFlowError> {
    let mut buf = [0u8; ADDR_INFO_MAX_LEN];
    let mut filled = 0usize;
    if kind_consumed {
        if let Some(first) = buf.first_mut() {
            *first = STREAM_ADDR_INFO;
        }
        filled = 1;
    }
    fill(rx, &mut buf, &mut filled, HEAD_LEN).await?;
    if buf.first() != Some(&STREAM_ADDR_INFO) || buf.get(1) != Some(&PROTO_V1) {
        return Err(AddrFlowError::Malformed);
    }
    let addr_end = match buf.get(2) {
        Some(4) => HEAD_LEN + 6,
        Some(6) => HEAD_LEN + 18,
        _ => return Err(AddrFlowError::Malformed),
    };
    let len_end = addr_end + 2;
    fill(rx, &mut buf, &mut filled, len_end).await?;
    let len_bytes: [u8; 2] = buf
        .get(addr_end..len_end)
        .and_then(|s| s.try_into().ok())
        .ok_or(AddrFlowError::Malformed)?;
    let update_len = usize::from(u16::from_be_bytes(len_bytes));
    let total = if update_len == 0 {
        len_end
    } else if (ADDR_UPDATE_MIN_LEN..=ADDR_UPDATE_MAX_LEN).contains(&update_len) {
        len_end + update_len
    } else {
        return Err(AddrFlowError::Malformed);
    };
    if total > ADDR_INFO_MAX_LEN {
        return Err(AddrFlowError::Malformed);
    }
    fill(rx, &mut buf, &mut filled, total).await?;
    let mut one = [0u8; 1];
    if rx.read(&mut one).await?.is_some() {
        return Err(AddrFlowError::TrailingData);
    }
    let frame = buf.get(..total).ok_or(AddrFlowError::Malformed)?;
    decode_addr_info(frame)
}

async fn write_frame<T: SendStream>(tx: &mut T, frame: &[u8]) -> Result<(), AddrFlowError> {
    tx.write_all(frame).await?;
    tx.finish()?;
    Ok(())
}

/// Соединение принадлежит паре вызывающего, а привязанный к паре токен выпущен именно для
/// неё (токен для другого друга не уходит по этому соединению).
fn peer_matches<C: Connection>(conn: &C, pair: &PairId, ours: Option<&IssuedAddrUpdate>) -> bool {
    let remote = conn.remote_pair();
    remote == *pair
        && ours
            .and_then(IssuedAddrUpdate::pair)
            .is_none_or(|p| p == remote)
}

/// Сторона, открывшая соединение. `remote_pair != *pair` или токен выпущен для другой пары
/// -> `WrongPeer` (ничего не отправлено). Открывает поток, пишет кадр, закрывает запись,
/// читает один кадр целиком (с байтом вида) и требует конец потока.
pub async fn exchange_addr_info<C: Connection>(
    conn: &C,
    pair: &PairId,
    ours: Option<&IssuedAddrUpdate>,
) -> Result<PeerAddrInfo, AddrFlowError> {
    if !peer_matches(conn, pair, ours) {
        return Err(AddrFlowError::WrongPeer);
    }
    let frame = encode_addr_info(normalize(conn.remote_addr()), ours)?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_frame(&mut tx, &frame).await?;
    let (observed_me, update) = read_frame(&mut rx, false).await?;
    Ok(PeerAddrInfo {
        observed_me,
        via: normalize(conn.remote_addr()),
        update,
    })
}

/// Принимающая сторона; диспетчер (этап 13) уже прочитал нулевой байт `STREAM_ADDR_INFO`.
/// `remote_pair != *pair` или токен выпущен для другой пары -> `WrongPeer` (ничего не
/// записано). Читает остаток кадра, требует конец потока, пишет свой кадр и закрывает запись.
pub async fn answer_addr_info<C: Connection>(
    conn: &C,
    pair: &PairId,
    mut tx: C::Tx,
    mut rx: C::Rx,
    ours: Option<&IssuedAddrUpdate>,
) -> Result<PeerAddrInfo, AddrFlowError> {
    if !peer_matches(conn, pair, ours) {
        return Err(AddrFlowError::WrongPeer);
    }
    let (observed_me, update) = read_frame(&mut rx, true).await?;
    let via = normalize(conn.remote_addr());
    let frame = encode_addr_info(via, ours)?;
    write_frame(&mut tx, &frame).await?;
    Ok(PeerAddrInfo {
        observed_me,
        via,
        update,
    })
}
