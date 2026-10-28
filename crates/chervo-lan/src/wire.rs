//! Формат датаграммы маяка (430 байт, фиксированная длина) и её разбор. Чистый код без сокетов.
//!
//! `ver(1) = 0x01 || reserved(1) = 0x00 || nonce(12) || слот * 16`, слот = 26 байт
//! (`chervo_identity::LanKeys::seal`). Неиспользованные слоты: 26 случайных байт. Порядок слотов
//! перемешан в каждой датаграмме. Всё, что приходит из сети, считается враждебным: порядок
//! проверок `parse`: длина, заголовок, правила источника, слоты (поиск метки, AEAD только при
//! попадании).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use chervo_addr::{AddrClass, LanSighting, classify};
use chervo_identity::{LAN_HDR, LAN_NONCE_LEN, LAN_SLOT_LEN, LanKeys, PairId};

use crate::error::LanError;
use crate::limits::{DGRAM_LEN, MAX_DGRAMS_PER_ROUND, SLOTS};
use crate::table::IdTable;

/// Правило источника. В продукте принимаются только частные адреса; в тестах на петле можно
/// разрешить `127.0.0.0/8` (адрес самого получателя всё равно отбрасывается).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SrcPolicy {
    pub(crate) allow_loopback: bool,
}

impl SrcPolicy {
    pub(crate) const PRODUCT: Self = Self {
        allow_loopback: false,
    };
    #[cfg(any(test, feature = "test-net"))]
    pub(crate) const LOOPBACK_OK: Self = Self {
        allow_loopback: true,
    };
}

fn random(buf: &mut [u8]) -> Result<(), LanError> {
    getrandom::fill(buf).map_err(|_| LanError::Random)
}

/// Перемешивание Фишера-Йетса на случайных байтах ОС.
fn shuffle(slots: &mut [[u8; LAN_SLOT_LEN]]) -> Result<(), LanError> {
    let mut i = slots.len();
    while i > 1 {
        let mut r = [0u8; 8];
        random(&mut r)?;
        let j = usize::try_from(u64::from_le_bytes(r) % u64::try_from(i).unwrap_or(1)).unwrap_or(0);
        i = i.saturating_sub(1);
        slots.swap(i, j);
    }
    Ok(())
}

/// Раунд маяка: датаграммы для пар `peers` с адресом отправителя `src` и портом `port`.
/// Не больше `SLOTS * MAX_DGRAMS_PER_ROUND` пар за раунд; если пар больше, пары идут по кругу
/// со сдвигом по `round`. Сбой ГСЧ даёт ошибку: ничего не отправляется.
pub(crate) fn build(
    peers: &[(PairId, &LanKeys)],
    window: u64,
    src: Ipv4Addr,
    port: u16,
    round: u64,
) -> Result<Vec<[u8; DGRAM_LEN]>, LanError> {
    if port == 0 {
        return Err(LanError::Crypto);
    }
    // повтор пары в наборе не даёт второго слота
    let mut uniq: Vec<(PairId, &LanKeys)> = Vec::new();
    for (p, k) in peers {
        if !uniq.iter().any(|(q, _)| q == p) {
            uniq.push((*p, *k));
        }
    }
    let n = uniq.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let cap = SLOTS * MAX_DGRAMS_PER_ROUND;
    let chosen: Vec<(PairId, &LanKeys)> = if n <= cap {
        uniq
    } else {
        let n64 = u64::try_from(n).unwrap_or(1);
        let cap64 = u64::try_from(cap).unwrap_or(1);
        let start = usize::try_from((round % n64).saturating_mul(cap64) % n64).unwrap_or(0);
        uniq.iter().cycle().skip(start).take(cap).copied().collect()
    };

    let mut out = Vec::new();
    for chunk in chosen.chunks(SLOTS) {
        let mut nonce = [0u8; LAN_NONCE_LEN];
        random(&mut nonce)?;
        let mut slots: Vec<[u8; LAN_SLOT_LEN]> = Vec::with_capacity(SLOTS);
        for (_, k) in chunk {
            slots.push(
                k.seal(window, &nonce, src, port)
                    .map_err(|_| LanError::Crypto)?,
            );
        }
        while slots.len() < SLOTS {
            let mut pad = [0u8; LAN_SLOT_LEN];
            random(&mut pad)?;
            slots.push(pad);
        }
        shuffle(&mut slots)?;
        let mut d = [0u8; DGRAM_LEN];
        let mut w = d.iter_mut();
        for b in LAN_HDR
            .iter()
            .chain(nonce.iter())
            .chain(slots.iter().flatten())
        {
            if let Some(x) = w.next() {
                *x = *b;
            }
        }
        out.push(d);
    }
    Ok(out)
}

/// Правила источника: только IPv4 (IPv6 и v4-mapped отбрасываются), не наш адрес, класс
/// `Private` (в тестах ещё `Loopback`). Возвращает адрес для AAD.
fn src_ip(src: SocketAddr, own: Ipv4Addr, policy: SrcPolicy) -> Option<Ipv4Addr> {
    let SocketAddr::V4(v4) = src else {
        return None;
    };
    let ip = *v4.ip();
    if ip == own {
        return None;
    }
    match classify(IpAddr::V4(ip)) {
        AddrClass::Private => Some(ip),
        AddrClass::Loopback if policy.allow_loopback => Some(ip),
        _ => None,
    }
}

/// Разбор датаграммы. Находки: не больше одной на пару.
pub(crate) fn parse(
    dgram: &[u8],
    src: SocketAddr,
    own: Ipv4Addr,
    table: &IdTable,
    policy: SrcPolicy,
) -> Vec<LanSighting> {
    if dgram.len() != DGRAM_LEN {
        return Vec::new();
    }
    if dgram.get(..LAN_HDR.len()) != Some(LAN_HDR.as_slice()) {
        return Vec::new();
    }
    let Some(ip) = src_ip(src, own, policy) else {
        return Vec::new();
    };
    let Some(nonce) = dgram
        .get(LAN_HDR.len()..LAN_HDR.len() + LAN_NONCE_LEN)
        .and_then(|s| <&[u8; LAN_NONCE_LEN]>::try_from(s).ok())
    else {
        return Vec::new();
    };
    let Some(body) = dgram.get(LAN_HDR.len() + LAN_NONCE_LEN..) else {
        return Vec::new();
    };
    let mut found: Vec<LanSighting> = Vec::new();
    for slot in body.as_chunks::<LAN_SLOT_LEN>().0 {
        if let Some((pair, port)) = table.open_slot(nonce, ip, slot) {
            if found.iter().any(|s| s.pair == pair) {
                continue;
            }
            found.push(LanSighting {
                pair,
                addr: SocketAddrV4::new(ip, port),
            });
        }
    }
    found
}
