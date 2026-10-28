//! Fuzz-смоук разбора датаграммы: ни одной паники; случайный ввод даёт 0 находок; изменённый
//! байт верной датаграммы никогда не даёт другой порт или другой адрес. Число итераций:
//! `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug); тест печатает его.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};

use chervo_identity::{LAN_HDR, PairId};

use super::{OWN, PORT, SRC, W, fixture, sock};
use crate::limits::DGRAM_LEN;
use crate::wire::{SrcPolicy, build, parse};

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
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn fuzz_iters() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) {
            2_000
        } else {
            20_000
        })
}

#[test]
fn fuzz_smoke_beacon() {
    let mut fx = fixture(3);
    let valid = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    let orig: HashSet<(PairId, SocketAddrV4)> =
        parse(&valid, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT)
            .iter()
            .map(|s| (s.pair, s.addr))
            .collect();
    assert_eq!(orig.len(), 3);

    let n = fuzz_iters();
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let (mut random_in, mut mutated, mut kept) = (0u64, 0u64, 0u64);
    for _ in 0..n {
        match rng.below(5) {
            // случайные байты любой длины
            0 => {
                let len = rng.below(700);
                let v = rng.bytes(len);
                assert!(parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT).is_empty());
                crate::fuzz_beacon(&v);
                random_in += 1;
            }
            // верная длина и заголовок, остальное случайно
            1 => {
                let mut v = rng.bytes(DGRAM_LEN);
                v[..2].copy_from_slice(&LAN_HDR);
                assert!(parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT).is_empty());
                crate::fuzz_beacon(&v);
                random_in += 1;
            }
            // верный маяк с чужого частного адреса: AAD не сходится
            2 => {
                let ip = Ipv4Addr::new(10, rng.byte(), rng.byte(), rng.byte());
                if ip != SRC && ip != OWN {
                    let f = parse(&valid, sock(ip), &[OWN], &t, SrcPolicy::PRODUCT);
                    assert!(f.is_empty(), "{ip}");
                }
            }
            // мутации верной датаграммы
            _ => {
                let mut v = valid.to_vec();
                for _ in 0..=rng.below(4) {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
                if rng.below(4) == 0 {
                    let len = rng.below(DGRAM_LEN + 40);
                    v.resize(len, rng.byte());
                }
                mutated += 1;
                let f = parse(&v, sock(SRC), &[OWN], &t, SrcPolicy::PRODUCT);
                for s in &f {
                    assert!(orig.contains(&(s.pair, s.addr)), "другой порт или адрес");
                }
                kept += u64::try_from(f.len()).unwrap();
                crate::fuzz_beacon(&v);
            }
        }
    }
    println!(
        "fuzz_smoke_beacon: iterations {n}, random {random_in}, mutated {mutated}, sightings kept {kept}"
    );
}
