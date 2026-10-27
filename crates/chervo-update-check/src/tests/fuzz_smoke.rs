//! Дымовой фаззинг разбора ответа и `Location`: xorshift64*, без внешних пакетов.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000); зерно: `CHERVO_FUZZ_SEED`.
//! Свойства (в `fuzz::exercise`): нет паники; тело не больше предела; хост `Location` из
//! списка; чтение не больше `MAX_HEADER_BYTES + 4 + предел + 1` байт.

use crate::fuzz::exercise;
use crate::http::{Response, read_response};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

fn iterations() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Без `CHERVO_FUZZ_SEED` ровно `default`; с ней у каждой цели своё зерно (splitmix64).
fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const SEEDS: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\n\r\nno length body",
    b"HTTP/1.1 302 Found\r\nLocation: https://github.com/a/b?c=d\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 301 Moved\r\nlocation: https://release-assets.githubusercontent.com/x%2Fy?z=1\r\n\r\n",
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    b"https://github.com/rekc2004/chervotochina/releases/latest/download/chervo-release.txt",
    b"https://objects.githubusercontent.com/path?q=1",
];

const TOKENS: &[&[u8]] = &[
    b"\r\n",
    b"\r\n\r\n",
    b"Content-Length: ",
    b"Location: ",
    b"Transfer-Encoding: chunked",
    b"HTTP/1.1 ",
    b"https://",
    b"github.com",
    b"@",
    b"#",
    b":",
    b"\0",
    b"99999999999999999999",
    b"-1",
];

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..=rng.below(5) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.byte();
            }
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.byte());
            }
            3 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            4 if !v.is_empty() => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            5 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                let i = rng.below(v.len() + 1);
                for (k, b) in t.iter().enumerate() {
                    v.insert(i + k, *b);
                }
            }
            _ => {
                // длинный участок: проверка пределов
                let n = rng.below(40_000);
                let b = rng.byte();
                v.extend(std::iter::repeat_n(b, n));
            }
        }
    }
    v
}

#[test]
fn fuzz_smoke_update_http() {
    let n = iterations();
    println!(
        "fuzz_smoke_update_http: os={} iterations={n}",
        std::env::consts::OS
    );
    let mut rng = Rng(fuzz_seed(0xA11C_E0F0_0D5E_ED19));
    let mut bodies = 0u64;
    let mut redirects = 0u64;
    for i in 0..n {
        let input = match i % 3 {
            0 => {
                let len = rng.below(300);
                (0..len).map(|_| rng.byte()).collect()
            }
            _ => {
                let base = SEEDS[rng.below(SEEDS.len())];
                mutate(&mut rng, base)
            }
        };
        exercise(&input);
        match read_response(input.as_slice(), 1000) {
            Ok(Response::Body(_)) => bodies += 1,
            Ok(Response::Redirect(_)) => redirects += 1,
            Err(_) => {}
        }
    }
    println!("fuzz_smoke_update_http: ok-bodies={bodies} ok-redirects={redirects}");
    // генератор не вырожден: хоть иногда разбор успешен
    assert!(bodies > 0 && redirects > 0, "образцы не разбираются");
}
