#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout
)]
//! Fuzz-смоук разбора протокола эха на stable, без зависимостей (этап 13д, раздел 5): по 1 000 000
//! итераций на запрос и на ответ. ГПСЧ xorshift64*; число итераций `CHERVO_FUZZ_ITERS`, зерно
//! `CHERVO_FUZZ_SEED`.
//!
//! Свойства: ни одной паники; `Ok` ровно тогда, когда пакет допустим по независимой записи правил
//! (длина, заголовок, паддинг, nonce, семейство, порт, класс адреса); каждый принятый пакет
//! кодируется обратно в те же байты (одна каноническая форма).

use chervo_rendezvous_wire::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_iters() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
}

/// Зерно: без `CHERVO_FUZZ_SEED` ровно `default`; иначе splitmix64 от `seed ^ default`.
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

fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(7) {
        0 | 1 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        2 => {
            let i = rng.below(v.len() + 1);
            v.insert(i, rng.next() as u8);
        }
        3 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        4 => {
            let target = [0usize, 1, 47, 48, 49, 63, 64, 65, 2048][rng.below(9)];
            v.resize(target, rng.next() as u8);
        }
        5 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}

fn all_zero(s: &[u8]) -> bool {
    s.iter().all(|b| *b == 0)
}

/// Независимая запись правил запроса.
fn request_ok(b: &[u8]) -> bool {
    if b.len() != 64 || &b[0..4] != b"CHRV" || b[4] != 1 || b[6] != 0 || b[7] != 0 {
        return false;
    }
    match b[5] {
        0x01 => all_zero(&b[24..64]),
        0x03 => all_zero(&b[26..64]) && (b[24] != 0 || b[25] != 0),
        _ => false,
    }
}

/// Независимая запись правил ответа при данном ожидаемом nonce.
fn response_ok(b: &[u8], nonce: &[u8; 16]) -> bool {
    if b.len() != 48 || &b[0..4] != b"CHRV" || b[4] != 1 || b[6] != 0 || b[7] != 0 {
        return false;
    }
    let ty = b[5];
    if ty != 0x02 && ty != 0x04 {
        return false;
    }
    if b[8..24] != nonce[..] || b[25] != 0 {
        return false;
    }
    let port = u16::from_be_bytes([b[26] ^ nonce[0], b[27] ^ nonce[1]]);
    if port == 0 || !all_zero(&b[46..48]) {
        return false;
    }
    if ty == 0x04 && (b[44] != 0 || b[45] != 0) {
        return false;
    }
    match b[24] {
        4 => {
            if !all_zero(&b[32..44]) {
                return false;
            }
            let ip = Ipv4Addr::new(
                b[28] ^ nonce[2],
                b[29] ^ nonce[3],
                b[30] ^ nonce[4],
                b[31] ^ nonce[5],
            );
            !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
        }
        6 => {
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = b[28 + i] ^ nonce[i];
            }
            let ip = Ipv6Addr::from(o);
            !(ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some())
        }
        _ => false,
    }
}

fn nonce_of(rng: &mut XorShift) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&rng.bytes(NONCE_LEN));
    Nonce(n)
}

fn random_addr(rng: &mut XorShift) -> SocketAddr {
    let port = rng.next() as u16;
    if rng.below(2) == 0 {
        let o = rng.bytes(4);
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])), port)
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&rng.bytes(16));
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)
    }
}

#[test]
fn fuzz_smoke_request() {
    let mut rng = XorShift(fuzz_seed(0x0123_4567_89AB_CDEF));
    let mut accepted = 0u64;
    for _ in 0..fuzz_iters() {
        let n = nonce_of(&mut rng);
        let input: Vec<u8> = match rng.below(5) {
            0 => {
                let len = rng.below(130);
                rng.bytes(len)
            }
            1 => encode_echo_request(&n).to_vec(),
            2 => encode_reach_request(&n, rng.next() as u16).to_vec(),
            3 => mutate(&mut rng, &encode_echo_request(&n)),
            _ => {
                let p = rng.next() as u16;
                mutate(&mut rng, &encode_reach_request(&n, p))
            }
        };
        let got = parse_request(&input);
        assert_eq!(got.is_ok(), request_ok(&input), "{input:02x?}");
        if let Ok(req) = got {
            accepted += 1;
            let again = match req {
                Request::Echo(n) => encode_echo_request(&n),
                Request::Reach { nonce, target_port } => encode_reach_request(&nonce, target_port),
            };
            assert_eq!(&again[..], &input[..], "принятый запрос не канонический");
        }
    }
    println!("fuzz_smoke_request: принято {accepted}");
    assert!(accepted > 0, "ни один пакет не принят: прогон пустой");
}

#[test]
fn fuzz_smoke_response() {
    let mut rng = XorShift(fuzz_seed(0xFEDC_BA98_7654_3210));
    let mut accepted = 0u64;
    for _ in 0..fuzz_iters() {
        let n = nonce_of(&mut rng);
        let addr = random_addr(&mut rng);
        let reach_port = if rng.below(2) == 0 {
            0
        } else {
            rng.next() as u16
        };
        let input: Vec<u8> = match rng.below(6) {
            0 => {
                let len = rng.below(100);
                rng.bytes(len)
            }
            1 => encode_echo_response(&n, addr, reach_port).to_vec(),
            2 => encode_reach_response(&n, addr).to_vec(),
            3 | 4 => mutate(&mut rng, &encode_echo_response(&n, addr, reach_port)),
            _ => mutate(&mut rng, &encode_reach_response(&n, addr)),
        };
        // ожидаемый nonce: чаще настоящий (иначе дальше проверки не дойти), иногда чужой
        let expected = if rng.below(8) == 0 {
            nonce_of(&mut rng)
        } else {
            n
        };
        let got = parse_response(&input, &expected);
        assert_eq!(
            got.is_ok(),
            response_ok(&input, &expected.0),
            "{input:02x?}"
        );
        if let Ok(r) = got {
            accepted += 1;
            assert_ne!(r.observed.port(), 0);
            let again = if r.reach {
                encode_reach_response(&expected, r.observed)
            } else {
                encode_echo_response(&expected, r.observed, r.reach_port)
            };
            assert_eq!(&again[..], &input[..], "принятый ответ не канонический");
        }
    }
    println!("fuzz_smoke_response: принято {accepted}");
    assert!(accepted > 0, "ни один пакет не принят: прогон пустой");
}
