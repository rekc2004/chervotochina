//! Pure core: beacon content, schedule, hostile input.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use chervo_addr::LanPeer;
use chervo_identity::{LAN_SLOT_LEN, PairId};

use super::{
    RECV, SEND, UNIX, beacon_from, force_beacon, ids, ms, multi_sender, nonce_of, opened, pair,
    recv_core, secs, sender, slots, src,
};
use crate::core::{CoreConfig, LanCore, lan_epoch};
use crate::limits::{BEACON_LEN, LAN_SLOTS};
use crate::wire;

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
}

// ---- beacon content ------------------------------------------------------------------

#[test]
fn beacon_len_and_layout() {
    let fx = pair();
    let b = beacon_from(&fx, SEND, UNIX);
    assert_eq!(b.len(), 557);
    assert_eq!(b[0], 1);
    let ids = ids(&b);
    assert_eq!(ids.len(), 16);
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "sorted and distinct");
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 16);
    assert_eq!(wire::parse(&b).map(|p| p.slots.len()).unwrap(), 16 * 34);
}

#[test]
fn beacon_fillers_only_when_none_wanted() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![]);
    let b = c.poll_send(Duration::ZERO, UNIX).unwrap();
    let keys = fx.peer_a().unwrap().keys;
    assert!(opened(&keys, &b, UNIX, *SEND.ip()).is_empty());
    // the same for a pair that is wanted but unknown to the core
    let other = PairId::generate().unwrap();
    let mut c = sender(&fx, SEND, vec![other]);
    let b = c.poll_send(Duration::ZERO, UNIX).unwrap();
    assert!(opened(&keys, &b, UNIX, *SEND.ip()).is_empty());
}

#[test]
fn beacon_real_slot_matches_friend() {
    let fx = pair();
    let b = beacon_from(&fx, SEND, UNIX);
    let keys = fx.peer_a().unwrap().keys;
    assert_eq!(opened(&keys, &b, UNIX, *SEND.ip()), vec![SEND.port()]);
    // the friend's id sits in the slot list
    assert!(ids(&b).contains(&keys.recv_id(lan_epoch(UNIX))));
    // and the whole path finds it
    let mut r = recv_core(&fx);
    r.on_datagram(src(SEND), &b, secs(1), UNIX);
    let found = r.take_found();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].pair, fx.pair);
    assert_eq!(found[0].addr, SEND);
    // a stranger with other keys finds nothing
    let other = pair();
    let mut r = recv_core(&other);
    r.on_datagram(src(SEND), &b, secs(1), UNIX);
    assert!(r.take_found().is_empty());
}

#[test]
fn beacon_size_independent_of_wanted() {
    let fxs: Vec<_> = (0..40).map(|_| pair()).collect();
    let all: Vec<PairId> = fxs.iter().map(|f| f.pair).collect();
    for n in [0usize, 1, 5, 16, 40] {
        let mut c = multi_sender(&fxs, all[..n].to_vec());
        let b = c.poll_send(Duration::ZERO, UNIX).unwrap();
        assert_eq!(b.len(), BEACON_LEN);
        assert_eq!(slots(&b).len(), LAN_SLOTS);
        let real = fxs
            .iter()
            .filter(|f| !opened(&f.peer_a().unwrap().keys, &b, UNIX, *SEND.ip()).is_empty())
            .count();
        assert_eq!(real, n.min(16), "wanted {n}");
    }
}

#[test]
fn beacon_ids_stable_within_epoch() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![fx.pair]);
    let b1 = force_beacon(&mut c, secs(0), UNIX);
    let b2 = force_beacon(&mut c, secs(10), UNIX + 10);
    assert_ne!(nonce_of(&b1), nonce_of(&b2), "fresh nonce");
    assert_eq!(ids(&b1), ids(&b2));
    // fresh ciphertext and tag everywhere (fillers too), so slots differ
    assert!(slots(&b1).iter().zip(slots(&b2)).all(|(x, y)| *x != y));
}

#[test]
fn beacon_ids_change_across_epoch() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![fx.pair]);
    let mut prev: HashSet<[u8; 16]> = HashSet::new();
    for k in 0..6u64 {
        let b = force_beacon(&mut c, secs(k * 61), UNIX + k * 60);
        let cur: HashSet<[u8; 16]> = ids(&b).into_iter().collect();
        assert_eq!(cur.len(), 16);
        assert!(prev.is_disjoint(&cur), "epoch {k}: an id repeated");
        prev = cur;
    }
}

#[test]
fn rotation_covers_all_wanted() {
    let fxs: Vec<_> = (0..40).map(|_| pair()).collect();
    let all: Vec<PairId> = fxs.iter().map(|f| f.pair).collect();
    for start in [0u64, 1, 7] {
        let mut c = multi_sender(&fxs, all.clone());
        let mut seen: HashSet<usize> = HashSet::new();
        for k in 0..3u64 {
            let unix = UNIX + (start + k) * 60;
            let b = force_beacon(&mut c, secs(k * 61), unix);
            let mut in_epoch = 0;
            for (i, f) in fxs.iter().enumerate() {
                if !opened(&f.peer_a().unwrap().keys, &b, unix, *SEND.ip()).is_empty() {
                    seen.insert(i);
                    in_epoch += 1;
                }
            }
            assert_eq!(in_epoch, 16);
        }
        assert_eq!(
            seen.len(),
            40,
            "start {start}: every friend within 3 epochs"
        );
    }
}

#[test]
fn wanted_frozen_per_epoch() {
    let fx1 = pair();
    let fx2 = pair();
    let fxs = [fx1.clone(), fx2.clone()];
    let mut c = multi_sender(&fxs, vec![fx1.pair]);
    let k1 = fx1.peer_a().unwrap().keys;
    let k2 = fx2.peer_a().unwrap().keys;
    let b1 = force_beacon(&mut c, secs(0), UNIX);
    assert_eq!(opened(&k1, &b1, UNIX, *SEND.ip()).len(), 1);
    // wanted changes inside the epoch: the announced set stays
    c.set_wanted(vec![fx2.pair]);
    let b2 = force_beacon(&mut c, secs(10), UNIX + 10);
    assert_eq!(opened(&k1, &b2, UNIX + 10, *SEND.ip()).len(), 1);
    assert!(opened(&k2, &b2, UNIX + 10, *SEND.ip()).is_empty());
    assert_eq!(ids(&b1), ids(&b2));
    // next epoch: the new wanted set is read
    let b3 = force_beacon(&mut c, secs(70), UNIX + 60);
    assert!(opened(&k1, &b3, UNIX + 60, *SEND.ip()).is_empty());
    assert_eq!(opened(&k2, &b3, UNIX + 60, *SEND.ip()).len(), 1);
}

#[test]
fn removed_peer_dropped_immediately() {
    let fx1 = pair();
    let fx2 = pair();
    let fxs = [fx1.clone(), fx2.clone()];
    let mut c = multi_sender(&fxs, vec![fx1.pair, fx2.pair]);
    let k1 = fx1.peer_a().unwrap().keys;
    let k2 = fx2.peer_a().unwrap().keys;
    let b1 = force_beacon(&mut c, secs(0), UNIX);
    assert_eq!(opened(&k1, &b1, UNIX, *SEND.ip()).len(), 1);
    assert_eq!(opened(&k2, &b1, UNIX, *SEND.ip()).len(), 1);
    // fx2 is blocked: the next beacon of the same epoch has no slot for it
    c.set_peers(vec![fx1.peer_b().unwrap()]);
    let b2 = force_beacon(&mut c, secs(5), UNIX + 5);
    assert_eq!(opened(&k1, &b2, UNIX + 5, *SEND.ip()).len(), 1);
    assert!(opened(&k2, &b2, UNIX + 5, *SEND.ip()).is_empty());
    assert!(!ids(&b2).contains(&k2.recv_id(lan_epoch(UNIX))));
    // exactly one id changed: the removed slot became a fresh filler
    let (i1, i2) = (ids(&b1), ids(&b2));
    let old: HashSet<_> = i1.iter().collect();
    assert_eq!(i2.iter().filter(|i| !old.contains(i)).count(), 1);

    // receiving side: a removed peer's beacons no longer match
    let mut r = LanCore::new(CoreConfig::default());
    r.set_local(Some(RECV), Duration::ZERO);
    r.set_peers(vec![fx1.peer_a().unwrap(), fx2.peer_a().unwrap()]);
    r.on_datagram(src(SEND), &b1, secs(1), UNIX);
    assert_eq!(r.take_found().len(), 1, "first matching slot only");
    r.set_peers(vec![fx1.peer_a().unwrap()]);
    let b3 = beacon_from(&fx2, SEND, UNIX);
    r.on_datagram(src(SEND), &b3, secs(20), UNIX);
    assert!(r.take_found().is_empty());
}

// ---- when sockets are wanted -------------------------------------------------------------

#[test]
fn no_peers_no_sockets() {
    let mut c = LanCore::new(CoreConfig::default());
    c.set_local(Some(SEND), Duration::ZERO);
    assert_eq!(c.wants_sockets(), None);
    for k in 0..100 {
        assert!(c.poll_send(secs(k), UNIX + k).is_none());
    }
    c.trigger(secs(5));
    assert!(c.poll_send(secs(5), UNIX).is_none());
    assert_eq!(c.stats().beacons_out, 0);
    // with a peer sockets are wanted; removing it closes them again
    let fx = pair();
    c.set_peers(vec![fx.peer_b().unwrap()]);
    assert_eq!(c.wants_sockets(), Some(*SEND.ip()));
    c.set_peers(vec![]);
    assert_eq!(c.wants_sockets(), None);
}

#[test]
fn non_private_local_no_sockets() {
    let fx = pair();
    for local in [
        Some(v4(8, 8, 8, 8, 4000)),     // Global
        Some(v4(100, 64, 0, 9, 4000)),  // Shared (CGNAT, Tailscale)
        Some(v4(169, 254, 3, 4, 4000)), // LinkLocal
        Some(v4(127, 0, 0, 1, 4000)),   // Loopback in production
        Some(v4(192, 168, 1, 5, 0)),    // port 0
        None,
    ] {
        let mut c = LanCore::new(CoreConfig::default());
        c.set_peers(vec![fx.peer_b().unwrap()]);
        c.set_local(local, Duration::ZERO);
        assert_eq!(c.wants_sockets(), None, "{local:?}");
        assert!(c.poll_send(Duration::ZERO, UNIX).is_none());
    }
    for ip in [
        v4(10, 1, 2, 3, 1),
        v4(172, 16, 0, 1, 1),
        v4(192, 168, 0, 1, 1),
    ] {
        let mut c = LanCore::new(CoreConfig::default());
        c.set_peers(vec![fx.peer_b().unwrap()]);
        c.set_local(Some(ip), Duration::ZERO);
        assert_eq!(c.wants_sockets(), Some(*ip.ip()));
    }
}

// ---- schedule -----------------------------------------------------------------------------

#[test]
fn schedule_interval_and_jitter() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![fx.pair]);
    let mut sends = Vec::new();
    let mut t = ms(0);
    while t < secs(3600) {
        if c.poll_send(t, UNIX + t.as_secs()).is_some() {
            sends.push(t);
        }
        t += ms(100);
    }
    // the first burst: 0, 1, 3 s
    assert_eq!(&sends[..3], &[ms(0), ms(1000), ms(3000)]);
    let periodic = &sends[3..];
    assert!(periodic.len() >= 50, "{} beacons in an hour", sends.len());
    let mut gaps: Vec<Duration> = periodic.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.push(periodic[0] - ms(3000));
    for g in &gaps[..gaps.len() - 1] {
        // the polling step is 100 ms
        assert!(
            *g >= ms(49_900) && *g <= ms(70_100),
            "gap {g:?} outside 50-70 s"
        );
    }
    // jitter is real: gaps are not all equal
    let distinct: HashSet<u128> = gaps.iter().map(|g| g.as_millis()).collect();
    assert!(distinct.len() > 5);
}

fn max_in_window(sends: &[Duration], window: Duration) -> usize {
    let mut best = 0;
    for (i, s) in sends.iter().enumerate() {
        let n = sends[i..].iter().take_while(|t| **t - *s < window).count();
        best = best.max(n);
    }
    best
}

#[test]
fn trigger_burst_and_cap() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![fx.pair]);
    let mut sends = Vec::new();
    // 100 triggers at once, then one per second for 100 s
    for _ in 0..100 {
        c.trigger(ms(0));
    }
    let mut t = ms(0);
    while t < secs(300) {
        if t < secs(100) && t.subsec_millis() == 0 {
            c.trigger(t);
        }
        if c.poll_send(t, UNIX + t.as_secs()).is_some() {
            sends.push(t);
        }
        t += ms(50);
    }
    assert!(sends.len() >= 8, "bursts did send: {}", sends.len());
    assert!(max_in_window(&sends, secs(60)) <= 8, "{sends:?}");
}

#[test]
fn set_local_change_bursts() {
    let fx = pair();
    let mut c = sender(&fx, SEND, vec![fx.pair]);
    let mut sends = Vec::new();
    let mut t = ms(0);
    while t < secs(10) {
        if c.poll_send(t, UNIX + t.as_secs()).is_some() {
            sends.push(t);
        }
        t += ms(100);
    }
    assert_eq!(sends, vec![ms(0), ms(1000), ms(3000)]);
    // the same endpoint again: nothing
    c.set_local(Some(SEND), secs(10));
    assert!(c.poll_send(secs(10), UNIX + 10).is_none());
    // a new endpoint: a new burst at once, and the epoch state restarts
    let before = c.poll_send(secs(10), UNIX + 10);
    assert!(before.is_none());
    c.set_local(Some(v4(192, 168, 77, 40, 5000)), secs(100));
    let mut sends = Vec::new();
    let mut t = secs(100);
    while t < secs(110) {
        if let Some(b) = c.poll_send(t, UNIX + t.as_secs()) {
            sends.push(t);
            // sealed for the new port
            let keys = fx.peer_a().unwrap().keys;
            assert_eq!(
                opened(
                    &keys,
                    &b,
                    UNIX + t.as_secs(),
                    Ipv4Addr::new(192, 168, 77, 40)
                ),
                vec![5000]
            );
        }
        t += ms(100);
    }
    assert_eq!(sends, vec![secs(100), secs(101), secs(103)]);
}

#[test]
fn no_send_on_receive() {
    let fx = pair();
    let mut c = recv_core(&fx);
    // the receiver is also a sender: drain its first burst
    let mut t = ms(0);
    while t < secs(5) {
        let _ = c.poll_send(t, UNIX + t.as_secs());
        t += ms(100);
    }
    let sent = c.stats().beacons_out;
    let now = secs(10);
    let w0 = c.next_wakeup(now);
    let good = beacon_from(&fx, SEND, UNIX);
    let mut other_ip = good;
    other_ip[5] ^= 1;
    for i in 0..1000u64 {
        let data: &[u8] = match i % 4 {
            0 => &good,
            1 => &other_ip,
            2 => &[1, 2, 3],
            _ => &[],
        };
        let from = v4(192, 168, 77, 20 + u8::try_from(i % 100).unwrap(), 1000);
        c.on_datagram(src(from), data, now + ms(i * 50), UNIX + 10);
        assert!(
            c.poll_send(now, UNIX + 10).is_none(),
            "datagram {i} caused a send"
        );
    }
    assert_eq!(c.stats().beacons_out, sent);
    assert_eq!(c.next_wakeup(now), w0, "send time unchanged by receiving");
}

// ---- hostile input -----------------------------------------------------------------------

#[test]
fn drop_wrong_len() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    let mut r = recv_core(&fx);
    let mut long = good.to_vec();
    long.extend_from_slice(&[0u8; 943]);
    for (i, data) in [
        &good[..0],
        &good[..1],
        &good[..556],
        &[good.to_vec(), vec![0]].concat()[..],
        &long[..1500],
    ]
    .into_iter()
    .enumerate()
    {
        r.on_datagram(src(SEND), data, ms(i as u64 * 50), UNIX);
    }
    let s = r.stats();
    assert_eq!(s.dropped_len, 5);
    assert_eq!(s.dgrams_in, 5);
    assert_eq!(s.lookups, 0);
    assert!(r.take_found().is_empty());
    // control: the good one is found
    r.on_datagram(src(SEND), &good, secs(1), UNIX);
    assert_eq!(r.take_found().len(), 1);
}

#[test]
fn drop_wrong_version() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    let mut r = recv_core(&fx);
    for (i, v) in [0u8, 2, 3, 255].into_iter().enumerate() {
        let mut b = good;
        b[0] = v;
        r.on_datagram(src(SEND), &b, ms(i as u64 * 50), UNIX);
    }
    assert_eq!(r.stats().dropped_ver, 4);
    assert!(r.take_found().is_empty());
    assert_eq!(r.stats().lookups, 0);
}

#[test]
fn drop_bad_source() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    let own = *RECV.ip();
    let sources: Vec<SocketAddr> = vec![
        src(v4(8, 8, 8, 8, 1000)),         // public
        src(v4(127, 0, 0, 1, 1000)),       // loopback, production
        src(v4(100, 64, 0, 7, 1000)),      // shared
        src(v4(169, 254, 1, 2, 1000)),     // link-local
        src(v4(224, 0, 0, 1, 1000)),       // multicast
        src(v4(255, 255, 255, 255, 1000)), // broadcast
        src(v4(0, 0, 0, 0, 1000)),         // unspecified
        src(SocketAddrV4::new(own, 1000)), // our own address
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1000, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new("fd00::12".parse().unwrap(), 1000, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 168, 77, 12).to_ipv6_mapped(),
            1000,
            0,
            0,
        )),
    ];
    let mut r = recv_core(&fx);
    for (i, s) in sources.iter().enumerate() {
        r.on_datagram(*s, &good, ms(i as u64 * 50), UNIX);
    }
    assert_eq!(r.stats().dropped_src, sources.len() as u64);
    assert!(r.take_found().is_empty());
    assert_eq!(r.stats().lookups, 0, "no table work for a bad source");
    // positive control from a private source
    r.on_datagram(src(SEND), &good, secs(2), UNIX);
    assert_eq!(r.take_found().len(), 1);
}

#[test]
fn drop_when_not_active() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    // no local address: not active, every datagram is dropped as a bad source
    let mut r = LanCore::new(CoreConfig::default());
    r.set_peers(vec![fx.peer_a().unwrap()]);
    r.on_datagram(src(SEND), &good, secs(1), UNIX);
    assert!(r.take_found().is_empty());
    assert_eq!(r.stats().dropped_src, 1);
}

#[test]
fn replay_other_ip_rejected() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    let mut r = recv_core(&fx);
    // the same bytes from another LAN host
    r.on_datagram(src(v4(192, 168, 77, 99, 42_000)), &good, secs(1), UNIX);
    assert!(r.take_found().is_empty());
    assert!(
        r.stats().aead_opens > 0,
        "the slot was found and failed to open"
    );
    // and from the true source it is found
    r.on_datagram(src(SEND), &good, secs(2), UNIX);
    assert_eq!(r.take_found().len(), 1);
}

#[test]
fn replay_same_ip_throttled() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    let mut r = recv_core(&fx);
    r.on_datagram(src(SEND), &good, secs(1), UNIX);
    r.on_datagram(src(SEND), &good, secs(2), UNIX);
    r.on_datagram(src(SEND), &good, secs(5), UNIX);
    assert_eq!(r.take_found().len(), 1);
    assert_eq!(r.stats().found_throttled, 2);
    // after 10 s the same address is reported again
    r.on_datagram(src(SEND), &good, secs(12), UNIX);
    assert_eq!(r.take_found().len(), 1);
    assert_eq!(r.stats().found, 2);
}

#[test]
fn duplicate_slot_open_cap() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let keys = fx.peer_a().unwrap().keys;
    let id = keys.recv_id(lan_epoch(UNIX));
    let mut slot = [0u8; LAN_SLOT_LEN];
    slot[..16].copy_from_slice(&id);
    slot[16..].fill(0x5a); // not a valid ciphertext and tag
    let nonce = [9u8; 12];
    let slots_in = vec![slot; LAN_SLOTS];
    let b = wire::build(&nonce, &slots_in).unwrap();
    r.on_datagram(src(SEND), &b, secs(1), UNIX);
    let s = r.stats();
    assert_eq!(s.aead_opens, 2, "at most two opens per datagram");
    assert!(r.take_found().is_empty());
    // the real beacon with a duplicated real slot at the front still works
    let good = beacon_from(&fx, SEND, UNIX);
    r.on_datagram(src(SEND), &good, secs(20), UNIX);
    assert_eq!(r.take_found().len(), 1);
    assert!(r.stats().aead_opens <= 4);
}

#[test]
fn per_source_budget() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let junk = {
        let mut b = beacon_from(&fx, SEND, UNIX);
        b[20] ^= 0xff;
        b
    };
    let a = v4(192, 168, 77, 50, 1000);
    for _ in 0..30 {
        r.on_datagram(src(a), &junk, secs(1), UNIX);
    }
    assert_eq!(r.stats().dropped_source_rate, 20, "10 per burst");
    // another source is unaffected
    let before = r.stats().dropped_source_rate;
    r.on_datagram(src(v4(192, 168, 77, 51, 1000)), &junk, secs(1), UNIX);
    assert_eq!(r.stats().dropped_source_rate, before);
    // 6 s later one more token
    r.on_datagram(src(a), &junk, secs(7), UNIX);
    assert_eq!(r.stats().dropped_source_rate, before);
    r.on_datagram(src(a), &junk, secs(7), UNIX);
    assert_eq!(r.stats().dropped_source_rate, before + 1);
}

#[test]
fn global_budget_pauses_reading() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let now = secs(100);
    assert!(r.may_read(now));
    // any length is charged, empty included
    for i in 0..100u32 {
        let from = v4(192, 168, 78, u8::try_from(i % 200).unwrap(), 1);
        r.on_datagram(src(from), &[], now, UNIX);
    }
    assert_eq!(r.stats().dropped_len, 100);
    assert!(!r.may_read(now), "budget empty: the driver pauses");
    r.on_datagram(src(SEND), &[], now, UNIX);
    assert_eq!(r.stats().dropped_budget, 1);
    // refill: 50 per second
    assert!(!r.may_read(now + ms(10)));
    assert!(r.may_read(now + ms(20)));
    assert!(r.may_read(now + secs(5)));
    // after a pause a real beacon gets through
    let good = beacon_from(&fx, SEND, UNIX);
    r.on_datagram(src(SEND), &good, now + secs(5), UNIX);
    assert_eq!(r.take_found().len(), 1);
}

#[test]
fn source_map_bounded() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let junk = beacon_from(&fx, SEND, UNIX);
    let mut x: u32 = 0x1234_5678;
    for i in 0..100_000u64 {
        // xorshift32
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let ip = Ipv4Addr::new(10, (x >> 16) as u8, (x >> 8) as u8, x as u8);
        r.on_datagram(src(SocketAddrV4::new(ip, 1)), &junk, ms(i * 20), UNIX);
        assert!(r.source_map_len() <= 256);
    }
    assert!(r.source_map_len() > 100, "the table does fill up");
}

#[test]
fn found_queue_bounded() {
    let fx = pair();
    let mut r = recv_core(&fx);
    for i in 0..100u8 {
        let from = v4(192, 168, 90, i, 42_000);
        let b = beacon_from(&fx, from, UNIX);
        r.on_datagram(src(from), &b, ms(u64::from(i) * 100), UNIX);
        assert!(r.found_len() <= 64);
    }
    let found = r.take_found();
    assert_eq!(found.len(), 64);
    // oldest dropped: the first kept item is number 36
    assert_eq!(found[0].addr, v4(192, 168, 90, 36, 42_000));
    assert_eq!(found[63].addr, v4(192, 168, 90, 99, 42_000));
    assert!(r.take_found().is_empty());
}

#[test]
fn found_new_addr_not_throttled() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let a = beacon_from(&fx, SEND, UNIX);
    r.on_datagram(src(SEND), &a, secs(1), UNIX);
    // the same host, a new port (restart of the program)
    let other = v4(192, 168, 77, 12, 42_001);
    let b = beacon_from(&fx, other, UNIX);
    r.on_datagram(src(other), &b, secs(2), UNIX);
    let found = r.take_found();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].addr.port(), 42_000);
    assert_eq!(found[1].addr.port(), 42_001);
    assert_eq!(r.stats().found_throttled, 0);
}

#[test]
fn epoch_tolerance() {
    let fx = pair();
    let good = beacon_from(&fx, SEND, UNIX);
    for (delta, ok) in [
        (-180i64, false),
        (-120, false),
        (-60, true),
        (0, true),
        (60, true),
        (120, false),
        (180, false),
    ] {
        let mut r = recv_core(&fx);
        let unix = UNIX.checked_add_signed(delta).unwrap();
        r.on_datagram(src(SEND), &good, secs(1), unix);
        assert_eq!(r.take_found().len(), usize::from(ok), "delta {delta}");
    }
}

#[test]
fn stats_debug_has_no_addresses() {
    let fx = pair();
    let mut r = recv_core(&fx);
    let good = beacon_from(&fx, SEND, UNIX);
    r.on_datagram(src(SEND), &good, secs(1), UNIX);
    let text = format!("{:?} {:#?}", r.stats(), r.stats());
    assert!(text.starts_with("LanStats {"));
    for needle in [
        "192", "168", "77", "42000", "42_000", "41000", "addr", "pair", "127.",
    ] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
    // the debug text of the shared types hides everything too
    let f = {
        let mut r = recv_core(&fx);
        r.on_datagram(src(SEND), &good, secs(1), UNIX);
        r.take_found().remove(0)
    };
    assert_eq!(format!("{f:?}"), "LanFound(..)");
    let p: LanPeer = fx.peer_a().unwrap();
    assert_eq!(format!("{p:?}"), "LanPeer(..)");
}

#[test]
fn wire_roundtrip_and_rejects() {
    let nonce = [3u8; 12];
    let mut slots_in = vec![[0u8; LAN_SLOT_LEN]; LAN_SLOTS];
    for (i, s) in slots_in.iter_mut().enumerate() {
        s[0] = u8::try_from(i).unwrap();
    }
    let b = wire::build(&nonce, &slots_in).unwrap();
    let p = wire::parse(&b).unwrap();
    assert_eq!(p.nonce, nonce);
    assert_eq!(p.slots.len(), LAN_SLOTS * LAN_SLOT_LEN);
    assert!(wire::build(&nonce, &slots_in[..15]).is_none());
    assert!(wire::build(&nonce, &[slots_in.clone(), slots_in.clone()].concat()).is_none());
    assert_eq!(wire::parse(&b[..556]).err(), Some(wire::ParseError::Len));
    let mut bad = b;
    bad[0] = 2;
    assert_eq!(wire::parse(&bad).err(), Some(wire::ParseError::Version));
}
