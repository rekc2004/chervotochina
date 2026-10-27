#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Общий набор для тестов редакции вывода (этап 17, B3, решение 1b/1c). Подключается из тестов
//! разных крейтов через `#[path = "../../chervo-core/tests/support/redact_kit.rs"] mod redact_kit;`
//! (общего тестового пакета нет, новые пакеты запрещены).
//!
//! * `Needles`: список запретного (формы байтов ключей, `PairId`, текст токена, метки).
//! * `Out`: собранный вывод (`Debug` обычный и «красивый», `Display`).
//! * `check`: ни один вывод не содержит ни одной записи запретного.
//! * `assert_fixed_text`: текст ошибки фиксированный (нет динамических данных).

use std::fmt::{Debug, Display};

pub fn hex(b: &[u8], upper: bool) -> String {
    b.iter()
        .map(|x| {
            if upper {
                format!("{x:02X}")
            } else {
                format!("{x:02x}")
            }
        })
        .collect()
}

pub fn b64(b: &[u8], url: bool, pad: bool) -> String {
    let alpha: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(alpha[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

pub fn b32(b: &[u8]) -> String {
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for x in b {
        acc = (acc << 8) | u32::from(*x);
        bits += 8;
        while bits >= 5 {
            out.push(alpha[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(alpha[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn dec_list(b: &[u8]) -> String {
    b.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
}

fn distinct(b: &[u8]) -> usize {
    let mut s: Vec<u8> = b.to_vec();
    s.sort_unstable();
    s.dedup();
    s.len()
}

#[derive(Default)]
pub struct Needles(pub Vec<(String, String)>);

impl Needles {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, label: &str, needle: impl Into<String>) {
        let n = needle.into();
        assert!(n.len() >= 5, "needle {label} too short to be meaningful");
        self.0.push((label.to_owned(), n));
    }

    /// Все формы байтов: полные hex (оба регистра), base64 (обычный и url, с отступом и без),
    /// base32, префиксы, десятичный список (так печатает `derive(Debug)` массива), окна.
    pub fn bytes(&mut self, label: &str, b: &[u8]) {
        self.add(&format!("{label}/hex"), hex(b, false));
        self.add(&format!("{label}/HEX"), hex(b, true));
        self.add(&format!("{label}/b64"), b64(b, false, true));
        self.add(&format!("{label}/b64-nopad"), b64(b, false, false));
        self.add(&format!("{label}/b64url"), b64(b, true, false));
        self.add(&format!("{label}/b32"), b32(b));
        if b.len() >= 8 {
            self.add(&format!("{label}/hex-prefix"), hex(&b[..8], false));
            self.add(&format!("{label}/HEX-prefix"), hex(&b[..8], true));
            self.add(
                &format!("{label}/b64-prefix"),
                b64(b, false, false)[..10].to_owned(),
            );
            self.add(&format!("{label}/b32-prefix"), b32(b)[..10].to_owned());
            for (i, w) in b.windows(8).enumerate() {
                if distinct(w) >= 4 {
                    self.add(&format!("{label}/dec-window{i}"), dec_list(w));
                }
            }
            for (i, w) in b.windows(6).enumerate() {
                if distinct(w) >= 4 {
                    self.add(&format!("{label}/hex-window{i}"), hex(w, false));
                }
            }
        }
    }

    /// Текст токена: целиком, в нижнем регистре, без пробелов и дефисов, куски по 20 знаков.
    pub fn token(&mut self, label: &str, text: &str) {
        self.add(&format!("{label}/text"), text.to_owned());
        self.add(&format!("{label}/lower"), text.to_lowercase());
        let squeezed: String = text.chars().filter(|c| c.is_alphanumeric()).collect();
        self.add(&format!("{label}/squeezed"), squeezed.clone());
        let chars: Vec<char> = squeezed.chars().collect();
        for (i, w) in chars.windows(20).step_by(10).enumerate() {
            self.add(&format!("{label}/slice{i}"), w.iter().collect::<String>());
        }
    }
}

/// Собранный вывод: пары (метка, текст).
#[derive(Default, Clone)]
pub struct Out(pub Vec<(String, String)>);

impl Out {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rec(&mut self, label: &str, text: String) {
        self.0.push((label.to_owned(), text));
    }

    /// `Debug` обычный и «красивый».
    pub fn dbg(&mut self, label: &str, v: &dyn Debug) {
        self.rec(label, format!("{v:?}"));
        self.rec(label, format!("{v:#?}"));
    }

    /// `Display`.
    pub fn disp(&mut self, label: &str, v: &dyn Display) {
        self.rec(label, format!("{v}"));
    }

    /// `Display` и `Debug` ошибки.
    pub fn err<E: Display + Debug>(&mut self, label: &str, e: &E) {
        self.disp(label, e);
        self.dbg(label, e);
    }

    pub fn text(&self, label: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(l, _)| l == label)
            .map(|(_, t)| t.as_str())
            .collect()
    }
}

/// Все попадания: (метка вывода, метка запретного).
pub fn scan(outputs: &[(String, String)], needles: &Needles) -> Vec<(String, String)> {
    let mut hits = Vec::new();
    for (slabel, text) in outputs {
        for (nlabel, n) in &needles.0 {
            if text.contains(n.as_str()) {
                hits.push((slabel.clone(), nlabel.clone()));
            }
        }
    }
    hits
}

/// Проверка: в выводе нет ни одной записи запретного. Содержимое при падении не печатается,
/// только метки.
pub fn check(out: &Out, needles: &Needles) {
    let hits = scan(&out.0, needles);
    let mut listed: Vec<String> = hits.iter().map(|(s, n)| format!("{s} <- {n}")).collect();
    listed.sort();
    listed.dedup();
    assert!(hits.is_empty(), "утечки в выводе: {listed:#?}");
    assert!(!out.0.is_empty(), "проверка пуста: ничего не собрано");
}

/// Текст ошибки фиксированный: ASCII, без пути, без адреса, без длинных hex-рядов и чисел.
pub fn assert_fixed_text(what: &str, s: &str) {
    assert!(!s.is_empty(), "{what}: пустой текст");
    assert!(
        s.is_ascii() || s.chars().all(|c| !c.is_control()),
        "{what}: {s:?}"
    );
    let no_io = s.replace("i/o", "io");
    assert!(
        !no_io.contains('/') && !no_io.contains('\\'),
        "{what}: путь в тексте: {s:?}"
    );
    let mut run = 0;
    for c in s.chars() {
        run = if c.is_ascii_hexdigit() && c.is_ascii_digit() {
            run + 1
        } else {
            0
        };
        assert!(run < 5, "{what}: длинное число в тексте: {s:?}");
    }
    let mut hexrun = 0;
    for c in s.chars() {
        hexrun = if c.is_ascii_hexdigit() { hexrun + 1 } else { 0 };
        assert!(hexrun < 12, "{what}: длинный hex-ряд в тексте: {s:?}");
    }
    assert!(
        !s.split(|c: char| !c.is_ascii_digit() && c != '.')
            .any(|t| t.matches('.').count() == 3),
        "{what}: похоже на адрес IPv4: {s:?}"
    );
}

/// У типа есть `Debug`? (`Probe::<T>::new().has_debug()` без привязки к реализации.)
pub struct Probe<T>(std::marker::PhantomData<T>);

impl<T> Probe<T> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

pub trait NoDebug {
    fn has_debug(&self) -> bool {
        false
    }
}

impl<T> NoDebug for Probe<T> {}

impl<T: Debug> Probe<T> {
    pub fn has_debug(&self) -> bool {
        true
    }
}
