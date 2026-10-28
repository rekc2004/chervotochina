//! Fuzz-смоук разбора слота маяка (этап 13в, L1). Лежит здесь, а не в `src/tests/`: охрана
//! `src_has_no_io_or_default_store` не пускает в `src/` ни `env::var`, ни печать.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug); тест
//! печатает его (приёмка читает вывод с `--nocapture`).
#![allow(clippy::print_stdout)]

mod common;

use std::net::Ipv4Addr;

use chervo_identity::{KxPeer, LAN_NONCE_LEN, LAN_SLOT_LEN, LanKeys, PairId, create};
use common::MemStore;

const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 7);
const NONCE: [u8; LAN_NONCE_LEN] = [7; LAN_NONCE_LEN];
const W: u64 = 56_789_012;

fn pair_keys() -> (LanKeys, LanKeys) {
    let pid = PairId::generate().unwrap();
    let (sa, sb) = (MemStore::new(), MemStore::new());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    let a = KxPeer::new(pid, ka.into_kx(), pb).lan_keys().unwrap();
    let b = KxPeer::new(pid, kb.into_kx(), pa).lan_keys().unwrap();
    (a, b)
}

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

/// Случайные байты любой длины и мутации верного слота: паники нет; ни случайный слот, ни
/// изменённый верный слот не открывается (то есть изменённый бит никогда не даёт другой порт).
#[test]
fn fuzz_smoke_lan_open() {
    let (a, b) = pair_keys();
    let valid = a.seal(W, &NONCE, SRC, 41_000).unwrap();
    assert_eq!(b.open(W, &NONCE, SRC, &valid), Some(41_000));
    let n = fuzz_iters();
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut unchanged = 0u64;
    for _ in 0..n {
        match rng.below(3) {
            0 => {
                let len = rng.below(60);
                let v: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                assert_eq!(b.open(W, &NONCE, SRC, &v), None);
            }
            1 => {
                let v: Vec<u8> = (0..LAN_SLOT_LEN).map(|_| rng.byte()).collect();
                assert_eq!(b.open(W, &NONCE, SRC, &v), None);
            }
            _ => {
                let mut s = valid.to_vec();
                for _ in 0..=rng.below(3) {
                    let i = rng.below(s.len());
                    s[i] ^= 1 << rng.below(8);
                }
                if s == valid {
                    unchanged += 1;
                } else {
                    assert_eq!(b.open(W, &NONCE, SRC, &s), None);
                }
            }
        }
    }
    println!("fuzz_smoke_lan_open: iterations {n}, unchanged mutations {unchanged}");
}
