//! Тесты формата и разбора датаграммы (`wire.rs`).

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use chervo_identity::{LAN_HDR, LAN_ID_LEN, LAN_NONCE_LEN, LAN_SLOT_LEN, PairId};

use super::{OWN, PORT, SRC, W, fixture, sock};
use crate::error::LanError;
use crate::limits::{DGRAM_LEN, LAN_GROUP, MAX_DGRAMS_PER_ROUND, RECV_BUF, SLOTS};
use crate::wire::{SrcPolicy, build, parse};

const HDR_LEN: usize = 2;
const SLOTS_AT: usize = HDR_LEN + LAN_NONCE_LEN;

fn pairs_of(found: &[chervo_addr::LanSighting]) -> HashSet<PairId> {
    found.iter().map(|s| s.pair).collect()
}

#[test]
fn wire_exact_len_any_n() {
    for n in [1usize, 5, 16] {
        let mut fx = fixture(n);
        let ds = build(&fx.refs(), W, SRC, PORT, 0).unwrap();
        assert_eq!(ds.len(), 1, "n={n}");
        let d = ds[0];
        assert_eq!(d.len(), DGRAM_LEN);
        assert_eq!(d[..2], LAN_HDR);
        let t = fx.table(W);
        let found = parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT);
        assert_eq!(found.len(), n);
        assert_eq!(pairs_of(&found).len(), n);
        for s in &found {
            assert_eq!(s.addr.ip(), &SRC);
            assert_eq!(s.addr.port(), PORT);
        }
    }
}

#[test]
fn wire_n17_two_datagrams() {
    let mut fx = fixture(17);
    let ds = build(&fx.refs(), W, SRC, PORT, 0).unwrap();
    assert_eq!(ds.len(), 2);
    let t = fx.table(W);
    let mut all = HashSet::new();
    for d in &ds {
        for s in parse(d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT) {
            all.insert(s.pair);
        }
    }
    assert_eq!(all.len(), 17);
    // пустой набор: ничего не строится
    assert!(build(&[], W, SRC, PORT, 0).unwrap().is_empty());
}

#[test]
fn wire_n65_rotates() {
    let mut fx = fixture(65);
    let ids = fx.pair_ids();
    let r0 = build(&fx.refs(), W, SRC, PORT, 0).unwrap();
    let r1 = build(&fx.refs(), W, SRC, PORT, 1).unwrap();
    assert_eq!(r0.len(), MAX_DGRAMS_PER_ROUND);
    assert_eq!(r1.len(), MAX_DGRAMS_PER_ROUND);
    let t = fx.table(W);
    let seen = |ds: &[[u8; DGRAM_LEN]]| -> HashSet<PairId> {
        ds.iter()
            .flat_map(|d| parse(d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT))
            .map(|s| s.pair)
            .collect()
    };
    let (s0, s1) = (seen(&r0), seen(&r1));
    assert_eq!(s0.len(), SLOTS * MAX_DGRAMS_PER_ROUND);
    assert_eq!(s1.len(), SLOTS * MAX_DGRAMS_PER_ROUND);
    let union: HashSet<PairId> = s0.union(&s1).copied().collect();
    assert_eq!(union.len(), 65, "за два раунда видны все пары");
    for id in ids {
        assert!(union.contains(&id));
    }
}

#[test]
fn wire_slots_shuffled() {
    let fx = fixture(16);
    let ids: Vec<[u8; LAN_ID_LEN]> = fx.sender.iter().map(|(_, k)| k.send_id(W)).collect();
    let target = ids[0];
    let mut positions = HashSet::new();
    for _ in 0..60 {
        let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
        let pos = (0..SLOTS)
            .find(|i| {
                let at = SLOTS_AT + i * LAN_SLOT_LEN;
                d[at..at + LAN_ID_LEN] == target
            })
            .unwrap();
        positions.insert(pos);
    }
    assert!(
        positions.len() > 4,
        "положение слота пары меняется: {positions:?}"
    );
}

#[test]
fn wire_bad_len_table() {
    let mut fx = fixture(3);
    let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    assert_eq!(parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).len(), 3);
    for len in [0usize, 1, 13, 14, 429, 431, RECV_BUF, 1472] {
        let mut v = d.to_vec();
        v.resize(len, 0);
        assert!(
            parse(&v, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).is_empty(),
            "длина {len}"
        );
    }
    assert_eq!(t.opens(), 3, "на неверной длине AEAD не вызывается");
}

#[test]
fn wire_bad_header() {
    let mut fx = fixture(2);
    let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    for v in 0..=255u8 {
        let mut x = d;
        x[0] = v;
        let ok = v == LAN_HDR[0];
        assert_eq!(
            !parse(&x, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).is_empty(),
            ok,
            "версия {v}"
        );
        let mut y = d;
        y[1] = v;
        let ok = v == LAN_HDR[1];
        assert_eq!(
            !parse(&y, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).is_empty(),
            ok,
            "резерв {v}"
        );
    }
}

#[test]
fn wire_src_class_table() {
    let ok_src = [
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(172, 16, 5, 9),
        Ipv4Addr::new(172, 31, 255, 254),
        Ipv4Addr::new(192, 168, 0, 77),
    ];
    let bad_src = [
        OWN,
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        LAN_GROUP,
        Ipv4Addr::new(239, 1, 2, 3),
        Ipv4Addr::new(169, 254, 3, 4),
        Ipv4Addr::new(100, 64, 0, 9),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(192, 0, 2, 5),
    ];
    let mut fx = fixture(1);
    let t_keys = std::mem::take(&mut fx.receiver);
    let t = crate::table::IdTable::from_peers(t_keys, W);
    for ip in ok_src {
        let d = build(&fx.refs(), W, ip, PORT, 0).unwrap()[0];
        let f = parse(&d, sock(ip), OWN, &t, SrcPolicy::PRODUCT);
        assert_eq!(f.len(), 1, "{ip}");
        assert_eq!(f[0].addr.ip(), &ip);
    }
    let before = t.opens();
    for ip in bad_src {
        let d = build(&fx.refs(), W, ip, PORT, 0).unwrap()[0];
        let f = parse(&d, sock(ip), OWN, &t, SrcPolicy::PRODUCT);
        assert!(f.is_empty(), "{ip}");
    }
    assert_eq!(t.opens(), before, "правила источника раньше AEAD");
    // тестовая политика: петля допускается, но адрес самого получателя нет
    let lo = Ipv4Addr::new(127, 0, 0, 2);
    let d = build(&fx.refs(), W, lo, PORT, 0).unwrap()[0];
    assert_eq!(
        parse(&d, sock(lo), OWN, &t, SrcPolicy::LOOPBACK_OK).len(),
        1
    );
    assert!(parse(&d, sock(lo), lo, &t, SrcPolicy::LOOPBACK_OK).is_empty());
    assert!(parse(&d, sock(lo), OWN, &t, SrcPolicy::PRODUCT).is_empty());
}

#[test]
fn wire_v6_src_dropped() {
    let mut fx = fixture(1);
    let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    let v6 = [
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        // v4-mapped того же адреса, что в AAD
        SRC.to_ipv6_mapped(),
        OWN.to_ipv6_mapped(),
    ];
    for a in v6 {
        let s = SocketAddr::V6(SocketAddrV6::new(a, 55_555, 0, 0));
        assert!(parse(&d, s, OWN, &t, SrcPolicy::PRODUCT).is_empty(), "{a}");
        assert!(
            parse(&d, s, OWN, &t, SrcPolicy::LOOPBACK_OK).is_empty(),
            "{a}"
        );
    }
    assert_eq!(t.opens(), 0);
}

#[test]
fn wire_random_no_sighting() {
    let mut fx = fixture(4);
    let t = fx.table(W);
    let mut seed = 0x1234_5678_9ABC_DEF1u64;
    for _ in 0..1000 {
        let mut d = [0u8; DGRAM_LEN];
        d[..2].copy_from_slice(&LAN_HDR);
        for b in d.iter_mut().skip(2) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed.to_le_bytes()[0];
        }
        assert!(parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).is_empty());
    }
    assert_eq!(t.opens(), 0, "случайные слоты: ни одного вызова AEAD");
}

#[test]
fn wire_replay_other_ip_rejected() {
    let mut fx = fixture(2);
    let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let t = fx.table(W);
    let other = Ipv4Addr::new(192, 168, 50, 99);
    assert!(parse(&d, sock(other), OWN, &t, SrcPolicy::PRODUCT).is_empty());
    assert_eq!(t.opens(), 2, "метки нашлись, AEAD отказал");
    assert_eq!(parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT).len(), 2);
}

#[test]
fn wire_replay_same_ip_same_info() {
    let mut fx = fixture(2);
    let d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let mut t = fx.table(W);
    let first = parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT);
    let again = parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT);
    assert_eq!(first.len(), 2);
    let key = |v: &[chervo_addr::LanSighting]| -> HashSet<(PairId, std::net::SocketAddrV4)> {
        v.iter().map(|s| (s.pair, s.addr)).collect()
    };
    assert_eq!(key(&first), key(&again));
    // окно позже (w+1): метки окна w ещё в таблице
    t.rebuild(W + 1);
    assert_eq!(
        key(&parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT)),
        key(&first)
    );
    t.rebuild(W - 1);
    assert_eq!(
        key(&parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT)),
        key(&first)
    );
}

#[test]
fn wire_window_pm2_rejected() {
    let mut fx = fixture(1);
    let t = fx.table(W);
    for (w, hit) in [
        (W - 2, false),
        (W - 1, true),
        (W, true),
        (W + 1, true),
        (W + 2, false),
    ] {
        let d = build(&fx.refs(), w, SRC, PORT, 0).unwrap()[0];
        let before = t.opens();
        let f = parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT);
        assert_eq!(!f.is_empty(), hit, "окно {w}");
        if !hit {
            assert_eq!(t.opens(), before, "метка вне окон не даёт вызова AEAD");
        }
    }
}

#[test]
fn wire_dup_pair_once() {
    let mut fx = fixture(1);
    let id = fx.sender[0].1.send_id(W);
    let mut d = build(&fx.refs(), W, SRC, PORT, 0).unwrap()[0];
    let real = (0..SLOTS)
        .find(|i| {
            let at = SLOTS_AT + i * LAN_SLOT_LEN;
            d[at..at + LAN_ID_LEN] == id
        })
        .unwrap();
    // тот же слот ещё в трёх местах
    let src_at = SLOTS_AT + real * LAN_SLOT_LEN;
    let slot: Vec<u8> = d[src_at..src_at + LAN_SLOT_LEN].to_vec();
    let mut copies = 0;
    for i in 0..SLOTS {
        if i != real && copies < 3 {
            let at = SLOTS_AT + i * LAN_SLOT_LEN;
            d[at..at + LAN_SLOT_LEN].copy_from_slice(&slot);
            copies += 1;
        }
    }
    let t = fx.table(W);
    let f = parse(&d, sock(SRC), OWN, &t, SrcPolicy::PRODUCT);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].addr.port(), PORT);
}

#[test]
fn wire_port_zero_rejected() {
    let fx = fixture(3);
    assert_eq!(build(&fx.refs(), W, SRC, 0, 0), Err(LanError::Crypto));
}

#[test]
fn beacon_contains_no_identifiers() {
    let fx = fixture(5);
    let ids = fx.pair_ids();
    let host: Vec<Vec<u8>> = ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(String::into_bytes)
        .filter(|b| b.len() >= 4)
        .collect();
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    // Короткая последовательность (адрес, короткое имя) может случайно оказаться среди
    // псевдослучайных байт датаграммы (около 1e-7 на датаграмму). Утечка воспроизводима: она
    // есть в каждой сборке. Поэтому находка засчитывается, только если повторяется в трёх
    // сборках подряд (случайность этого не даёт: порядка 1e-21).
    let leaks = |w: u64, round: u64, needle: &[u8]| -> bool {
        (0..3).all(|_| {
            build(&fx.refs(), w, SRC, PORT, round)
                .unwrap()
                .iter()
                .any(|d| contains(d, needle))
        })
    };
    // сам детектор находит подложенную последовательность
    assert!(contains(&[1, 2, 3, 4, 5], &[3, 4]) && !contains(&[1, 2, 3], &[3, 4]));
    for i in 0..1000u64 {
        for d in build(&fx.refs(), W + i, SRC, PORT, i).unwrap() {
            for k in &fx.pubs {
                assert!(!contains(&d, k), "открытый ключ в маяке");
            }
            for p in &ids {
                assert!(!contains(&d, p.as_bytes()), "идентификатор пары в маяке");
            }
            if contains(&d, &SRC.octets()) {
                assert!(
                    !leaks(W + i, i, &SRC.octets()),
                    "свой адрес в открытом виде"
                );
            }
            for h in &host {
                if contains(&d, h) {
                    assert!(!leaks(W + i, i, h), "имя компьютера в маяке");
                }
            }
        }
    }
}

#[test]
fn beacon_unlinkable_across_windows() {
    let fx = fixture(6);
    let collect = |w: u64| -> (HashSet<Vec<u8>>, HashSet<Vec<u8>>) {
        let mut slots = HashSet::new();
        let mut nonces = HashSet::new();
        for r in 0..20u64 {
            for d in build(&fx.refs(), w, SRC, PORT, r).unwrap() {
                nonces.insert(d[HDR_LEN..SLOTS_AT].to_vec());
                for c in d[SLOTS_AT..].as_chunks::<LAN_SLOT_LEN>().0 {
                    slots.insert(c.to_vec());
                }
            }
        }
        (slots, nonces)
    };
    let (s0, n0) = collect(W);
    let (s1, n1) = collect(W + 1);
    assert!(s0.is_disjoint(&s1), "слот повторился между окнами");
    assert!(n0.is_disjoint(&n1), "nonce повторился между окнами");
    // и 8-байтные метки (начало слота) тоже различны
    let ids = |s: &HashSet<Vec<u8>>| -> HashSet<Vec<u8>> {
        s.iter().map(|x| x[..LAN_ID_LEN].to_vec()).collect()
    };
    // метки настоящих слотов окна w+1 не встречаются среди меток окна w
    let real0: HashSet<Vec<u8>> = fx
        .sender
        .iter()
        .map(|(_, k)| k.send_id(W).to_vec())
        .collect();
    let real1: HashSet<Vec<u8>> = fx
        .sender
        .iter()
        .map(|(_, k)| k.send_id(W + 1).to_vec())
        .collect();
    assert!(real0.is_disjoint(&real1));
    assert!(ids(&s0).is_disjoint(&real1));
    assert!(ids(&s1).is_disjoint(&real0));
}
