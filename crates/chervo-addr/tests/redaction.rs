#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода типов с адресами (этап 17, B3, решение 1c; BRIEF 7, T8, SEC-8 #4): ни в
//! `Debug`, ни в иной печати нет IP-адресов, портов, WAN-адреса, адреса проброса, наблюдений
//! друзей и `PairId`. У `KnownAddr` нет `Debug` вовсе (и это зафиксировано).

#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use chervo_addr::{
    GatewayInfo, KnownAddr, LocalSnapshot, MapReport, MapRequest, MapStatus, OwnAddrs, PublishCtx,
    RouteSources,
};
use chervo_identity::PairId;
use redact_kit::{Needles, NoDebug, Out, Probe, check};

#[test]
fn addr_types_hide_addresses_and_pairs() {
    let route_v4: Ipv4Addr = "198.51.100.23".parse().unwrap();
    let route_v6: std::net::Ipv6Addr = "2001:db8::77".parse().unwrap();
    let wan: Ipv4Addr = "203.0.113.77".parse().unwrap();
    let mapped = SocketAddrV4::new(wan, 41_234);
    let internal = SocketAddrV4::new("192.168.77.5".parse().unwrap(), 40_001);
    let reporter = PairId::from_bytes([0x91; 16]);
    let observed: SocketAddr = "192.0.2.99:55555".parse().unwrap();
    let via: SocketAddr = "198.51.100.200:6000".parse().unwrap();

    let snap = LocalSnapshot {
        route: RouteSources {
            v4: Some(route_v4),
            v6: Some(route_v6),
        },
        listen: vec![
            "0.0.0.0:40001".parse().unwrap(),
            "[::]:40002".parse().unwrap(),
        ],
    };
    let gw = GatewayInfo {
        wan_ip: Some(wan),
        mapping: Some(mapped),
    };
    let mut own = OwnAddrs::new();
    own.set_local(snap.clone());
    own.set_gateway(Some(gw));
    let outcome = own.observe(reporter, via, observed, 1_000_000);
    let set = own.publishable(
        PublishCtx {
            include_lan: true,
            path_source: Some("192.168.77.5".parse().unwrap()),
        },
        1_000_000,
    );
    let req = MapRequest { internal };
    let report = MapReport {
        status: MapStatus::Mapped,
        gateway: Some(gw),
        retry_after: Duration::from_secs(60),
    };
    let known = KnownAddr {
        addr: observed,
        source: chervo_addr::AddrSource::Invite,
        last_seen_unix: 1,
        short_lived: false,
        hint: false,
    };

    let mut out = Out::new();
    out.dbg("LocalSnapshot", &snap);
    out.dbg("RouteSources", &snap.route);
    out.dbg("GatewayInfo", &gw);
    out.dbg("OwnAddrs", &own);
    out.dbg("ObserveOutcome", &outcome);
    out.dbg("PublishSet", &set);
    for u in set.as_slice() {
        out.dbg("UpdateAddr", u);
    }
    out.dbg(
        "PublishCtx",
        &PublishCtx {
            include_lan: true,
            path_source: Some("192.168.77.5".parse().unwrap()),
        },
    );
    out.dbg(
        "PublishCtx::for_connection",
        &PublishCtx::for_connection(via, Some("192.168.77.5".parse().unwrap())),
    );
    out.dbg("MapRequest", &req);
    out.dbg("MapReport", &report);
    out.dbg("MapStatus", &report.status);
    out.dbg("NatView", &own.nat_view(1_000_000));
    out.dbg(
        "findability",
        &chervo_addr::findability(false, std::slice::from_ref(&known), 1),
    );
    out.dbg("socket_addrs.len", &set.socket_addrs().len());

    let mut n = Needles::new();
    for (l, a) in [
        ("route v4", "198.51.100.23"),
        ("route v6", "2001:db8::77"),
        ("wan", "203.0.113.77"),
        ("mapped port", "41234"),
        ("internal ip", "192.168.77.5"),
        ("internal port", "40001"),
        ("observed ip", "192.0.2.99"),
        ("observed port", "55555"),
        ("via ip", "198.51.100.200"),
    ] {
        n.add(l, a);
    }
    n.bytes("reporter", reporter.as_bytes());
    check(&out, &n);
}

#[test]
fn addr_known_addr_has_no_debug() {
    assert!(!Probe::<KnownAddr>::new().has_debug());
    assert!(Probe::<LocalSnapshot>::new().has_debug());
    assert!(Probe::<GatewayInfo>::new().has_debug());
    assert!(Probe::<OwnAddrs>::new().has_debug());
}
