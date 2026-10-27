//! Строгий base64 (RFC 4648, разд. 4, с набивкой `=`) для строк фиксированной длины.
//!
//! Это не криптография, а разбор формата minisign. Каноничность проверяется повторным
//! кодированием: лишние биты в хвосте, неверная набивка, пробелы, переводы строк, алфавит
//! URL-safe и всё прочее отвергаются, потому что дают другую строку при перекодировании.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Кодирует байты в канонический base64 с набивкой.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        let idx = |shift: u32| ALPHABET[((n >> shift) & 0x3F) as usize] as char;
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Декодирует только канонический base64. Любое отклонение даёт `None`.
pub(crate) fn decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &s[..s.len() - pad];
    let mut out = Vec::with_capacity(body.len() * 3 / 4 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in body {
        acc = (acc << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Каноничность: перекодирование обязано дать ту же строку (хвостовые биты равны нулю,
    // набивка ровно та, что нужна).
    if encode(&out).as_bytes() != s {
        return None;
    }
    Some(out)
}

/// Декодирует ровно `N` байт; иная длина или неканоническая запись дают `None`.
pub(crate) fn decode_exact<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    let v = decode(s)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Векторы RFC 4648, разд. 10.
    #[test]
    fn b64_rfc4648_vectors() {
        let v: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in v {
            assert_eq!(encode(raw), enc);
            assert_eq!(decode(enc.as_bytes()).as_deref(), Some(raw));
        }
    }

    #[test]
    fn b64_rejects_noncanonical() {
        for bad in [
            "Zh==",   // ненулевые хвостовые биты
            "Zm9=",   // ненулевые хвостовые биты
            "Zg=",    // длина не кратна 4
            "Zg",     // нет набивки
            "Zg=A",   // набивка не в конце
            "Z===",   // слишком много набивки
            "====",   // только набивка
            "Zm9v ",  // пробел
            "Zm9v\n", // перевод строки
            "Zm9_",   // алфавит URL-safe
            "Zm9-",   // алфавит URL-safe
            "Zm9vYg=\n",
        ] {
            assert_eq!(decode(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(decode_exact::<3>(b"Zm9v"), Some(*b"foo"));
        assert_eq!(decode_exact::<2>(b"Zm9v"), None);
    }

    #[test]
    fn b64_roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            let enc = encode(&data[..n]);
            assert_eq!(decode(enc.as_bytes()).as_deref(), Some(&data[..n]));
        }
    }
}
