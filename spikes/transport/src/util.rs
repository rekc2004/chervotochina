//! События, hex, разбор аргументов.
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

pub type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn err(s: impl Into<String>) -> BoxErr {
    s.into().into()
}

static START: OnceLock<Instant> = OnceLock::new();

pub fn init_clock() {
    let _ = START.get_or_init(Instant::now);
}

pub fn now_ms() -> u128 {
    START.get_or_init(Instant::now).elapsed().as_millis()
}

/// Печатает `EVENT <имя> t=<мс> <k=v ...>` одной строкой.
pub fn emit(name: &str, kv: &str) {
    println!("EVENT {name} t={} {kv}", now_ms());
}

#[macro_export]
macro_rules! ev {
    ($name:expr) => { $crate::util::emit($name, "") };
    ($name:expr, $($arg:tt)*) => { $crate::util::emit($name, &format!($($arg)*)) };
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[usize::from(x >> 4)] as char);
        s.push(D[usize::from(x & 15)] as char);
    }
    s
}

pub fn unhex(s: &str) -> Result<Vec<u8>, BoxErr> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(err("hex: нечётная длина"));
    }
    let v = |c: u8| -> Result<u8, BoxErr> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(err("hex: недопустимый символ")),
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for ch in b.chunks(2) {
        if let [h, l] = ch {
            out.push((v(*h)? << 4) | v(*l)?);
        }
    }
    Ok(out)
}

pub fn unhex32(s: &str) -> Result<[u8; 32], BoxErr> {
    let v = unhex(s)?;
    v.try_into().map_err(|_| err("ожидалось 32 байта hex"))
}

/// Ошибки в строку события: кавычки и переводы строк убираем.
pub fn q(s: &str) -> String {
    s.chars()
        .map(|c| if c == '"' || c == '\n' || c == '\r' { '\'' } else { c })
        .collect()
}

/// Простейший разбор `--ключ значение` и флагов.
pub struct Args {
    pub cmd: String,
    map: HashMap<String, String>,
}

impl Args {
    pub fn parse(argv: &[String], flags: &[&str]) -> Result<Self, BoxErr> {
        let mut it = argv.iter();
        let cmd = it.next().cloned().ok_or_else(|| err("нет подкоманды"))?;
        let mut map = HashMap::new();
        while let Some(a) = it.next() {
            let k = a.strip_prefix("--").ok_or_else(|| err(format!("лишний аргумент {a}")))?;
            if flags.contains(&k) {
                map.insert(k.to_string(), String::new());
            } else {
                let v = it.next().ok_or_else(|| err(format!("нет значения для --{k}")))?;
                map.insert(k.to_string(), v.clone());
            }
        }
        Ok(Self { cmd, map })
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(String::as_str)
    }

    pub fn flag(&self, k: &str) -> bool {
        self.map.contains_key(k)
    }

    pub fn req(&self, k: &str) -> Result<&str, BoxErr> {
        self.get(k).ok_or_else(|| err(format!("нужен --{k}")))
    }

    pub fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> Result<T, BoxErr> {
        match self.get(k) {
            None => Ok(default),
            Some(v) => v.parse::<T>().map_err(|_| err(format!("--{k}: не число"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&b)).ok(), Some(b.to_vec()));
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
