//! Real sockets, unicast on 127.0.0.1 (runs on Windows, Linux and macOS): the driver thread,
//! the mailbox and the shutdown. Multicast itself is checked by the stand and by hand.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_addr::{LanLink, LanPeer, LanStatus};
use chervo_identity::PairId;

use super::pair;
use crate::core::CoreConfig;
use crate::fuzz_entry::{FIX_UNIX, PairFixture};
use crate::limits::BEACON_LEN;
use crate::link::LanDiscovery;
use crate::net::Net;

fn lo(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn real_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn clock_real() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(real_unix)
}

fn clock_fixed() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| FIX_UNIX)
}

/// A loopback port for a link. Not taken from the OS ephemeral range (other tests bind port 0 and
/// would be handed a port released a moment ago): a private counter in 30000-39999, started at
/// a different place in every process, skipping ports that are busy right now.
fn free_port() -> u16 {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    let next = NEXT.get_or_init(|| {
        let seed = std::process::id()
            .wrapping_mul(2_654_435_761)
            .wrapping_add(real_unix() as u32);
        AtomicU32::new(seed % 10_000)
    });
    loop {
        let p = 30_000 + u16::try_from(next.fetch_add(1, Ordering::SeqCst) % 10_000).unwrap();
        if UdpSocket::bind(lo(p)).is_ok() {
            return p;
        }
    }
}

/// Two distinct free loopback ports.
fn free_ports() -> (u16, u16) {
    (free_port(), free_port())
}

fn unicast_link(
    bind: u16,
    targets: &[u16],
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Arc<LanDiscovery> {
    LanDiscovery::start_with(
        Net::unicast(lo(bind), targets.iter().map(|p| lo(*p)).collect()),
        CoreConfig {
            allow_loopback: true,
        },
        clock,
    )
}

fn engage(l: &LanDiscovery, quic: u16, peer: LanPeer, wanted: PairId) {
    // the order the engine uses: wanted first, so it is known when the sockets are first wanted
    l.set_wanted(vec![wanted]);
    l.set_peers(vec![peer]);
    l.set_local(Some(lo(quic)));
    l.trigger();
}

fn wait_for<F: FnMut() -> bool>(timeout: Duration, mut f: F) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

fn side(fx: &PairFixture, a: bool) -> LanPeer {
    if a {
        fx.peer_a().unwrap()
    } else {
        fx.peer_b().unwrap()
    }
}

#[test]
fn loopback_two_links_find_each_other() {
    let fx = pair();
    let (pa, pb) = free_ports();
    let la = unicast_link(pa, &[pb], clock_real());
    let lb = unicast_link(pb, &[pa], clock_real());
    engage(&la, 41_001, side(&fx, true), fx.pair);
    engage(&lb, 41_002, side(&fx, false), fx.pair);
    let mut found_a = Vec::new();
    let mut found_b = Vec::new();
    let ok = wait_for(Duration::from_secs(5), || {
        found_a.extend(la.take_found());
        found_b.extend(lb.take_found());
        !found_a.is_empty() && !found_b.is_empty()
    });
    assert!(
        ok,
        "a: {} b: {} status a {:?} b {:?} stats a {:?} b {:?}",
        found_a.len(),
        found_b.len(),
        la.status(),
        lb.status(),
        la.stats(),
        lb.stats()
    );
    assert_eq!(found_a[0].pair, fx.pair);
    assert_eq!(found_a[0].addr, lo(41_002));
    assert_eq!(found_b[0].addr, lo(41_001));
    assert_eq!(la.status(), LanStatus::Running);
    assert!(la.stats().beacons_out >= 1 && la.stats().found >= 1);
    la.shutdown();
    lb.shutdown();
}

#[test]
fn loopback_sends_only_to_target() {
    let fx = pair();
    let target = UdpSocket::bind(lo(0)).unwrap();
    let other = UdpSocket::bind(lo(0)).unwrap();
    target
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    other
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let tp = target.local_addr().unwrap().port();
    let (own_port, _) = free_ports();
    let l = unicast_link(own_port, &[tp], clock_real());
    engage(&l, 41_010, side(&fx, true), fx.pair);
    let mut got = Vec::new();
    let mut buf = [0u8; 2048];
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end && got.len() < 2 {
        if let Ok((n, from)) = target.recv_from(&mut buf) {
            got.push((n, buf[0], from));
        }
    }
    assert!(got.len() >= 2, "beacons seen: {}", got.len());
    for (n, ver, from) in &got {
        assert_eq!(*n, BEACON_LEN);
        assert_eq!(*ver, 1);
        assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
    }
    // nothing reached the second socket, and nothing came back to anyone else
    assert!(other.recv_from(&mut buf).is_err());
    l.shutdown();
}

#[test]
fn loopback_garbage_then_finds() {
    let fx = pair();
    let (own_port, _) = free_ports();
    let l = unicast_link(own_port, &[], clock_fixed());
    engage(&l, 41_020, side(&fx, true), fx.pair);
    assert!(wait_for(Duration::from_secs(5), || l.status() == LanStatus::Running));
    // 10 000 garbage datagrams of random length, as fast as the loop allows
    let flood = UdpSocket::bind(lo(0)).unwrap();
    let mut x: u32 = 0x9E37_79B9;
    let mut junk = [0u8; 1200];
    for i in 0..10_000u32 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let len = (x % 1000) as usize;
        for (k, b) in junk.iter_mut().take(len).enumerate() {
            *b = (x as u8).wrapping_add(k as u8);
        }
        let _ = flood.send_to(&junk[..len], lo(own_port));
        if i % 500 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // then a valid beacon of the friend (from 127.0.0.1) arrives within 5 s
    let beacon = super::sender_lo(&fx, lo(41_021), vec![fx.pair])
        .poll_send(Duration::ZERO, FIX_UNIX)
        .unwrap();
    let mut ok = false;
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end && !ok {
        let _ = flood.send_to(&beacon, lo(own_port));
        std::thread::sleep(Duration::from_millis(100));
        let found = l.take_found();
        ok = found
            .iter()
            .any(|f| f.pair == fx.pair && f.addr == lo(41_021));
    }
    assert!(
        ok,
        "valid beacon not found after the flood: {:?}",
        l.stats()
    );
    let s = l.stats();
    assert!(s.dgrams_in >= 100, "{s:?}");
    l.shutdown();
}

#[test]
fn loopback_shutdown_closes_socket() {
    let fx = pair();
    let (own_port, _) = free_ports();
    let l = unicast_link(own_port, &[], clock_real());
    engage(&l, 41_030, side(&fx, true), fx.pair);
    assert!(wait_for(Duration::from_secs(5), || l.status() == LanStatus::Running));
    assert!(
        UdpSocket::bind(lo(own_port)).is_err(),
        "the link holds the port while running"
    );
    let t = Instant::now();
    l.shutdown();
    // shutdown only signals: it never waits for the thread (the caller may be a runtime worker)
    assert!(t.elapsed() < Duration::from_millis(50), "{:?}", t.elapsed());
    assert_eq!(l.status(), LanStatus::Off);
    // the thread closes the sockets within one receive timeout
    assert!(
        wait_for(Duration::from_secs(1), || UdpSocket::bind(lo(own_port))
            .is_ok()),
        "port still held after shutdown"
    );
    // idempotent, and a later call never panics or blocks
    l.shutdown();
    l.set_local(None);
    l.trigger();
    assert_eq!(l.status(), LanStatus::Off);
}

#[test]
fn drop_of_last_arc_shuts_down() {
    let fx = pair();
    let (own_port, _) = free_ports();
    {
        let l = unicast_link(own_port, &[], clock_real());
        engage(&l, 41_040, side(&fx, true), fx.pair);
        assert!(wait_for(Duration::from_secs(5), || l.status() == LanStatus::Running));
    }
    assert!(wait_for(Duration::from_secs(1), || UdpSocket::bind(lo(
        own_port
    ))
    .is_ok()));
}

#[test]
fn loopback_status_transitions() {
    let fx = pair();
    let (own_port, _) = free_ports();
    let l = unicast_link(own_port, &[], clock_real());
    assert_eq!(l.status(), LanStatus::Off);
    l.set_local(Some(lo(41_050)));
    assert!(wait_for(Duration::from_secs(2), || l.status() == LanStatus::NoPeers));
    l.set_peers(vec![side(&fx, true)]);
    assert!(wait_for(Duration::from_secs(2), || l.status() == LanStatus::Running));
    // a public address: no LAN, sockets closed
    l.set_local(Some(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 41_050)));
    assert!(wait_for(Duration::from_secs(2), || l.status() == LanStatus::NoLan));
    assert!(UdpSocket::bind(lo(own_port)).is_ok());
    l.shutdown();
}

#[test]
fn start_never_blocks() {
    let fx = pair();
    let t = Instant::now();
    // production constructor: no command, no socket, nothing sent
    let prod = LanDiscovery::start(clock_real());
    let (own_port, _) = free_ports();
    let l = unicast_link(own_port, &[], clock_real());
    l.set_local(Some(lo(41_060)));
    l.set_peers(vec![side(&fx, true)]);
    l.set_wanted(vec![fx.pair]);
    l.trigger();
    let _ = l.take_found();
    let _ = l.status();
    let _ = l.stats();
    l.set_peers(Vec::new());
    l.set_local(None);
    assert!(
        t.elapsed() < Duration::from_millis(50),
        "calls took {:?}",
        t.elapsed()
    );
    assert_eq!(prod.status(), LanStatus::Off);
    let t = Instant::now();
    prod.shutdown();
    l.shutdown();
    assert!(t.elapsed() < Duration::from_millis(50));
}

/// Manual check on a real machine: the real group on the default-route interface; both links
/// accept the own host (the test switch of the multicast mode). Run with `--ignored`.
#[test]
#[ignore = "manual: real multicast on the owner's machines"]
fn multicast_live() {
    let route = chervo_addr::probe_route_sources().v4;
    let Some(ip) = route.filter(|ip| {
        chervo_addr::classify(std::net::IpAddr::V4(*ip)) == chervo_addr::AddrClass::Private
    }) else {
        return;
    };
    let fx = pair();
    let cfg = CoreConfig {
        allow_loopback: true,
    };
    let la = LanDiscovery::start_with(Net::multicast_live(), cfg, clock_real());
    let lb = LanDiscovery::start_with(Net::multicast_live(), cfg, clock_real());
    for (l, quic, peer) in
        [(&la, 41_071u16, true), (&lb, 41_072u16, false)].map(|(l, q, a)| (l, q, side(&fx, a)))
    {
        l.set_wanted(vec![fx.pair]);
        l.set_peers(vec![peer]);
        l.set_local(Some(SocketAddrV4::new(ip, quic)));
        l.trigger();
    }
    let mut got = (false, false);
    let ok = wait_for(Duration::from_secs(10), || {
        got.0 |= la.take_found().iter().any(|f| f.addr.port() == 41_072);
        got.1 |= lb.take_found().iter().any(|f| f.addr.port() == 41_071);
        got.0 && got.1
    });
    la.shutdown();
    lb.shutdown();
    assert!(ok, "multicast beacons not found: {got:?}");
}
