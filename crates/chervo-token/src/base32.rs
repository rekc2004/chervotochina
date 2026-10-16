//! Строгий base32 RFC 4648: алфавит `A-Z2-7`, без `=`, заглавные. Не криптография.
//! Каноничность: длина по модулю 8 из {0, 2, 4, 5, 7}, неиспользуемые хвостовые биты равны 0,
//! поэтому у каждых байт ровно одна запись.

const fn symbol(v: u32) -> char {
    if v < 26 {
        (b'A' + v as u8) as char
    } else {
        (b'2' + (v - 26) as u8) as char
    }
}

/// Кодирование без заполнения.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol((acc >> bits) & 31));
        }
        acc &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(symbol((acc << (5 - bits)) & 31));
    }
    out
}

/// Строгий разбор: любое отклонение от канонической записи даёт `None`.
pub(crate) fn decode(s: &[u8]) -> Option<Vec<u8>> {
    if !matches!(s.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len().saturating_mul(5) / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'2'..=b'7' => u32::from(c - b'2') + 26,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}
