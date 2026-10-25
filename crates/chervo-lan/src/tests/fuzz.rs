//! Fuzz smoke on stable, no extra dependencies: xorshift64* with a fixed seed.
//! Iterations: `CHERVO_FUZZ_ITERS` (default 20 000 in release, 2 000 in debug). The seed:
//! `CHERVO_FUZZ_SEED` (a u64) gives every target its own derived seed; unset means the
//! built-in one. An unparsable seed panics, so a run never silently uses the old one.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use chervo_addr::LanPeer;
use chervo_identity::{LAN_ID_LEN, LAN_SLOT_LEN, PairId};

use super::{nonce_of, opened, pair, slots};
use crate::core::{CoreConfig, LanCore, lan_epoch};
use crate::fuzz_entry::{FIX_UNIX, SEND_LOCAL, fuzz_beacon, fuzz_lan_ready, send_src};
use crate::limits::{BEACON_LEN, LAN_SLOTS};

struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

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
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

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

/// A random source address of every class (and some IPv6).
fn random_src(rng: &mut XorShift) -> SocketAddr {
    let r = rng.next();
    let b = r.to_le_bytes();
    let port = u16::from_le_bytes([b[4], b[5]]);
    match rng.below(9) {
        0 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, b[0], b[1], b[2]), port)),
        1 => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(172, 16 + (b[0] & 15), b[1], b[2]),
            port,
        )),
        2 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, b[0], b[1]), port)),
        3 => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(b[0], b[1], b[2], b[3]),
            port,
        )),
        4 => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(100, 64 + (b[0] & 63), b[1], b[2]),
            port,
        )),
        5 => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(224 + (b[0] & 15), b[1], b[2], b[3]),
            port,
        )),
        6 => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, u16::from_le_bytes([b[0], b[1]]), 1),
            port,
            0,
            0,
        )),
        7 => SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 168, b[0], b[1]).to_ipv6_mapped(),
            port,
            0,
            0,
        )),
        _ => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, b[0]), port)),
    }
}

/// A mutation of the real beacon (or random bytes).
fn variant(rng: &mut XorShift, real: &[u8; BEACON_LEN]) -> Vec<u8> {
    match rng.below(10) {
        0 => {
            let n = rng.below(1501);
            rng.bytes(n)
        }
        1 => {
            let mut v = rng.bytes(BEACON_LEN);
            v[0] = 1;
            v
        }
        2 => {
            let mut v = real.to_vec();
            for _ in 0..=rng.below(3) {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            v
        }
        3 => {
            // swap two slots
            let mut v = real.to_vec();
            let (i, j) = (rng.below(LAN_SLOTS), rng.below(LAN_SLOTS));
            for k in 0..LAN_SLOT_LEN {
                v.swap(13 + i * LAN_SLOT_LEN + k, 13 + j * LAN_SLOT_LEN + k);
            }
            v
        }
        4 => {
            // duplicate one slot over another
            let mut v = real.to_vec();
            let (i, j) = (rng.below(LAN_SLOTS), rng.below(LAN_SLOTS));
            for k in 0..LAN_SLOT_LEN {
                v[13 + j * LAN_SLOT_LEN + k] = v[13 + i * LAN_SLOT_LEN + k];
            }
            v
        }
        5 => {
            // truncated or extended
            let mut v = real.to_vec();
            if rng.below(2) == 0 {
                v.truncate(rng.below(BEACON_LEN));
            } else {
                let n = 1 + rng.below(40);
                let extra = rng.bytes(n);
                v.extend(extra);
            }
            v
        }
        6 => {
            let mut v = real.to_vec();
            v[0] = rng.next() as u8;
            v
        }
        7 => real.to_vec(),
        8 => {
            // nonce mutated
            let mut v = real.to_vec();
            let i = 1 + rng.below(12);
            v[i] ^= 1 << rng.below(8);
            v
        }
        _ => {
            // real slot spread over every slot position (open cap)
            let mut v = real.to_vec();
            let src = 13 + rng.below(LAN_SLOTS) * LAN_SLOT_LEN;
            let slot: Vec<u8> = v[src..src + LAN_SLOT_LEN].to_vec();
            for j in 0..LAN_SLOTS {
                if rng.below(2) == 0 {
                    v[13 + j * LAN_SLOT_LEN..13 + (j + 1) * LAN_SLOT_LEN].copy_from_slice(&slot);
                }
            }
            v
        }
    }
}

#[test]
fn fuzz_smoke_beacon() {
    let iters = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0xBEAC_0123_4567_89AB));
    let fx = pair();
    let real = fx.real_beacon().unwrap();
    let keys = fx.peer_a().unwrap().keys;
    // the one real slot of the fixture friend
    let real_nonce = nonce_of(&real);
    let real_slot: Vec<u8> = slots(&real)
        .into_iter()
        .find(|s| {
            keys.open_slot(
                lan_epoch(FIX_UNIX),
                &real_nonce,
                SEND_LOCAL.ip().to_owned().into(),
                s,
            )
            .is_some()
        })
        .unwrap()
        .to_vec();
    assert_eq!(opened(&keys, &real, FIX_UNIX, *SEND_LOCAL.ip()).len(), 1);

    let mut r = fx.receiver().unwrap();
    let mut now = Duration::from_secs(1);
    let (mut found_total, mut no_found) = (0u64, 0u64);
    for i in 0..iters {
        now += Duration::from_secs(11);
        let data = variant(&mut rng, &real);
        let from = if rng.below(10) < 7 {
            send_src()
        } else {
            random_src(&mut rng)
        };
        let unix = if rng.below(10) < 8 {
            FIX_UNIX
        } else {
            FIX_UNIX.wrapping_add_signed(rng.below(601) as i64 - 300)
        };
        let opens_before = r.stats().aead_opens;
        r.on_datagram(from, &data, now, unix);
        let opens = r.stats().aead_opens - opens_before;
        assert!(opens <= 2, "iter {i}: {opens} opens for one datagram");
        assert!(r.source_map_len() <= 256);
        assert!(r.found_len() <= 64);
        let found = r.take_found();
        for f in &found {
            // found only from a real beacon of the fixture friend, never from forged bytes
            assert_eq!(data.len(), BEACON_LEN, "iter {i}");
            assert_eq!(data[0], 1, "iter {i}");
            assert_eq!(&data[1..13], &real_nonce, "iter {i}: nonce");
            assert!(
                slots(&data).contains(&real_slot.as_slice()),
                "iter {i}: the real slot is absent"
            );
            let SocketAddr::V4(sv4) = from else {
                panic!("iter {i}: found from a non-IPv4 source");
            };
            assert_eq!(*f.addr.ip(), *sv4.ip(), "iter {i}: address is the source");
            assert_eq!(
                *sv4.ip(),
                *SEND_LOCAL.ip(),
                "iter {i}: bound to the sender's IP"
            );
            assert_eq!(f.addr.port(), SEND_LOCAL.port());
            assert_ne!(f.addr.port(), 0);
            assert_eq!(f.pair, fx.pair);
            let de = lan_epoch(unix).abs_diff(lan_epoch(FIX_UNIX));
            assert!(de <= 1, "iter {i}: epoch difference {de}");
        }
        if found.is_empty() {
            no_found += 1;
        }
        found_total += found.len() as u64;
    }
    println!("fuzz_smoke_beacon: iterations={iters} found={found_total} not_found={no_found}");
    if iters >= 1000 {
        assert!(found_total > 0, "vacuous: the real beacon was never found");
        assert!(no_found > 0, "vacuous: nothing was ever rejected");
    }
}

#[test]
fn fuzz_smoke_core_sequence() {
    let iters = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0xC0DE_5EED_0000_0001));
    let pool: Vec<_> = (0..4).map(|_| pair()).collect();
    let unknown = PairId::generate().unwrap();
    let mut c = LanCore::new(CoreConfig::default());
    let real = pool[0].real_beacon().unwrap();
    let mut now = Duration::ZERO;
    let mut unix = FIX_UNIX;
    let mut sends: Vec<Duration> = Vec::new();
    let mut total_sends = 0u64;
    for i in 0..iters {
        match rng.below(40) {
            0 => {
                let local = match rng.below(6) {
                    0 => None,
                    1 => Some(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 4000)),
                    2 => Some(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 7), 0)),
                    3 => Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4000)),
                    _ => Some(SEND_LOCAL),
                };
                c.set_local(local, now);
            }
            1 => {
                let n = rng.below(4);
                let peers: Vec<LanPeer> =
                    pool.iter().take(n).map(|f| f.peer_a().unwrap()).collect();
                c.set_peers(peers);
            }
            2 => {
                let mut w: Vec<PairId> = pool
                    .iter()
                    .filter(|_| rng.below(2) == 0)
                    .map(|f| f.pair)
                    .collect();
                if rng.below(3) == 0 {
                    w.push(unknown);
                }
                c.set_wanted(w);
            }
            3..=6 => c.trigger(now),
            7..=16 => {
                if let Some(b) = c.poll_send(now, unix) {
                    assert_eq!(b.len(), 557);
                    assert_eq!(b[0], 1);
                    assert!(
                        c.wants_sockets().is_some(),
                        "iter {i}: beacon without sockets"
                    );
                    sends.push(now);
                    total_sends += 1;
                    let in_window = sends
                        .iter()
                        .rev()
                        .take_while(|t| now.saturating_sub(**t) < Duration::from_secs(60))
                        .count();
                    assert!(in_window <= 8, "iter {i}: {in_window} beacons in 60 s");
                }
            }
            17..=28 => {
                let data = variant(&mut rng, &real);
                let from = if rng.below(2) == 0 {
                    send_src()
                } else {
                    random_src(&mut rng)
                };
                c.on_datagram(from, &data, now, unix);
                assert!(c.found_len() <= 64);
            }
            29..=31 => {
                let f = c.take_found();
                assert!(f.len() <= 64);
            }
            32..=35 => {
                assert!(c.next_wakeup(now) <= Duration::from_millis(200));
                let _ = c.may_read(now);
                let _ = c.stats();
            }
            _ => {}
        }
        // time only moves forward; sometimes by a lot (several epochs)
        let step = match rng.below(200) {
            0 => rng.below(300) as u64 * 1000,
            1..=20 => rng.below(5000) as u64,
            _ => rng.below(300) as u64,
        };
        now += Duration::from_millis(step);
        unix += step / 1000;
        assert!(c.source_map_len() <= 256);
    }
    let _ = LAN_ID_LEN;
    println!("fuzz_smoke_core_sequence: iterations={iters} beacons={total_sends}");
    if iters >= 10_000 {
        assert!(total_sends > 0, "vacuous: no beacon was ever sent");
    }
}

#[test]
fn fuzz_entry_ready() {
    assert!(fuzz_lan_ready(), "fixture or positive control failed");
    // garbage never produces a found item
    assert!(!fuzz_beacon(&[]));
    assert!(!fuzz_beacon(&[1u8; BEACON_LEN]));
    let mut rng = XorShift::new(7);
    for _ in 0..200 {
        let n = rng.below(700);
        assert!(!fuzz_beacon(&rng.bytes(n)));
    }
    // the fixture really can find: a beacon built with the same keys is accepted by a fresh
    // receiver, so the property above is not vacuous (the entry itself holds a secret pair)
    let fx = pair();
    let real = fx.real_beacon().unwrap();
    let mut r = fx.receiver().unwrap();
    r.on_datagram(send_src(), &real, Duration::from_secs(1), FIX_UNIX);
    assert_eq!(r.take_found().len(), 1);
    // and the entry's own pair does not know this beacon
    assert!(!fuzz_beacon(&real));
}
