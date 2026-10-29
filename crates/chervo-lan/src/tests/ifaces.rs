//! Тесты выбора интерфейсов (`ifaces.rs`): опрос маршрутов подставной, сети нет.

use std::cell::Cell;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use chervo_addr::{AddrClass, classify};

use crate::ifaces::{select, sweep_targets};
use crate::limits::{MAX_IFACES, SWEEP_PORT};
use crate::wire::SrcPolicy;

const HOME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

fn in_home_subnet(t: SocketAddrV4) -> bool {
    let o = t.ip().octets();
    o[0] == 192 && o[1] == 168 && o[2] == 1
}

fn run(
    default: Ipv4Addr,
    policy: SrcPolicy,
    mut f: impl FnMut(SocketAddrV4) -> Option<IpAddr>,
) -> Vec<Ipv4Addr> {
    select(default, &mut f, policy, &|| false)
}

#[test]
fn ifaces_targets_order_and_count() {
    let v: Vec<SocketAddrV4> = sweep_targets().collect();
    assert_eq!(v.len(), 533);
    assert_eq!(v[0], "192.168.0.1:9".parse().unwrap());
    assert_eq!(v[255], "192.168.255.1:9".parse().unwrap());
    assert_eq!(v[256], "10.0.0.1:9".parse().unwrap());
    assert_eq!(v[511], "10.255.0.1:9".parse().unwrap());
    assert_eq!(v[512], "10.0.1.1:9".parse().unwrap());
    assert_eq!(v[516], "10.90.90.1:9".parse().unwrap());
    assert_eq!(v[517], "172.16.0.1:9".parse().unwrap());
    assert_eq!(v[532], "172.31.0.1:9".parse().unwrap());
    assert!(
        v.iter()
            .all(|t| classify(IpAddr::V4(*t.ip())) == AddrClass::Private && t.port() == SWEEP_PORT)
    );
    let uniq: HashSet<SocketAddrV4> = v.iter().copied().collect();
    assert_eq!(uniq.len(), 533, "цели различны");
}

#[test]
fn ifaces_vpn_default_finds_home() {
    let tunnel = Ipv4Addr::new(172, 18, 0, 1);
    let r = run(tunnel, SrcPolicy::PRODUCT, |t| {
        Some(IpAddr::V4(if in_home_subnet(t) { HOME } else { tunnel }))
    });
    assert_eq!(r, vec![tunnel, HOME]);
}

#[test]
fn ifaces_benchmark_default_excluded() {
    let tunnel = Ipv4Addr::new(198, 18, 0, 1);
    let r = run(tunnel, SrcPolicy::PRODUCT, |t| {
        Some(IpAddr::V4(if in_home_subnet(t) { HOME } else { tunnel }))
    });
    assert_eq!(r, vec![HOME]);
}

#[test]
fn ifaces_public_default_finds_home() {
    let public = Ipv4Addr::new(8, 8, 8, 8);
    let r = run(public, SrcPolicy::PRODUCT, |t| {
        Some(IpAddr::V4(if in_home_subnet(t) { HOME } else { public }))
    });
    assert_eq!(r, vec![HOME]);
}

#[test]
fn ifaces_non_private_dropped() {
    let answers: [IpAddr; 8] = [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
    ];
    let i = Cell::new(0usize);
    let r = run(Ipv4Addr::new(100, 64, 0, 1), SrcPolicy::PRODUCT, |_| {
        let a = answers[i.get() % answers.len()];
        i.set(i.get() + 1);
        Some(a)
    });
    assert!(r.is_empty(), "{r:?}");
    // петля: в продукте нет, в тестовой политике есть
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(run(Ipv4Addr::UNSPECIFIED, SrcPolicy::PRODUCT, |_| Some(lo)).is_empty());
    assert_eq!(
        run(Ipv4Addr::UNSPECIFIED, SrcPolicy::LOOPBACK_OK, |_| Some(lo)),
        vec![Ipv4Addr::LOCALHOST]
    );
}

#[test]
fn ifaces_cap() {
    let calls = Cell::new(0usize);
    let r = run(Ipv4Addr::new(192, 168, 9, 9), SrcPolicy::PRODUCT, |_| {
        let n = calls.get();
        calls.set(n + 1);
        Some(IpAddr::V4(Ipv4Addr::new(
            10,
            99,
            0,
            u8::try_from(n % 200).unwrap(),
        )))
    });
    assert_eq!(r.len(), MAX_IFACES);
    assert_eq!(
        r[0],
        Ipv4Addr::new(192, 168, 9, 9),
        "адрес по умолчанию первый"
    );
    assert_eq!(
        calls.get(),
        MAX_IFACES - 1,
        "после набора предела опрос прекращён"
    );
}

#[test]
fn ifaces_dedup() {
    let calls = Cell::new(0usize);
    let r = run(HOME, SrcPolicy::PRODUCT, |_| {
        calls.set(calls.get() + 1);
        Some(IpAddr::V4(HOME))
    });
    assert_eq!(r, vec![HOME]);
    assert_eq!(calls.get(), 533);
}

#[test]
fn ifaces_stop() {
    // остановка проверяется на каждом 64-м обращении: перед первым и далее
    let calls = Cell::new(0usize);
    let r = select(
        HOME,
        &mut |_| {
            calls.set(calls.get() + 1);
            None
        },
        SrcPolicy::PRODUCT,
        &|| calls.get() >= 100,
    );
    assert_eq!(calls.get(), 128);
    assert_eq!(r, vec![HOME], "найденное до остановки остаётся");
    // остановка сразу: ни одного обращения
    let calls = Cell::new(0usize);
    let r = select(
        HOME,
        &mut |_| {
            calls.set(calls.get() + 1);
            None
        },
        SrcPolicy::PRODUCT,
        &|| true,
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(r, vec![HOME]);
}

#[test]
fn ifaces_none() {
    let calls = Cell::new(0usize);
    let r = run(Ipv4Addr::new(8, 8, 8, 8), SrcPolicy::PRODUCT, |_| {
        calls.set(calls.get() + 1);
        None
    });
    assert!(r.is_empty());
    assert_eq!(calls.get(), 533);
}
