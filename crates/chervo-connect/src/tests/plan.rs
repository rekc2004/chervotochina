//! Этап 13г: правила набора IPv6 (`family_ok`, `dialable`, семейства по маршрутному источнику).

use std::net::{SocketAddr, SocketAddrV6};

use chervo_addr::AddrSource;

use super::kit::*;
use crate::plan::{Families, dialable, families, family_ok, friend_plan, guest_plan};

const GLOBAL_SRC: &str = "2a00:1450::5";

fn local_dual() -> Vec<SocketAddr> {
    vec![addr("0.0.0.0:4000"), addr("[::]:4000")]
}

fn dual_with_route(route_v6: Option<&str>) -> Families<'static> {
    families(
        &local_dual(),
        route_v6.map(|s| s.parse().unwrap()),
        &ROUTE_GLOBAL,
    )
}

fn got(plan: &crate::plan::Plan) -> Vec<SocketAddr> {
    plan.cands.iter().map(|c| c.addr).collect()
}

#[test]
fn plan_dual_accepts_v4_and_v6() {
    let fam = dual_with_route(Some(GLOBAL_SRC));
    assert!(fam.v4 && fam.v6 && fam.v6_egress);
    let book = vec![
        known("5.6.7.8:1000", AddrSource::Invite, false),
        known("[2606:4700::1]:1000", AddrSource::Invite, false),
    ];
    let plan = friend_plan(&book, &fam);
    assert_eq!(
        got(&plan),
        vec![addr("5.6.7.8:1000"), addr("[2606:4700::1]:1000")]
    );
    // только IPv4: IPv6 пропущен; только IPv6: IPv4 пропущен
    let v4 = families(&[addr("0.0.0.0:4000")], None, &ROUTE_GLOBAL);
    assert_eq!(got(&friend_plan(&book, &v4)), vec![addr("5.6.7.8:1000")]);
    let v6 = families(
        &[addr("[::]:4000")],
        Some(GLOBAL_SRC.parse().unwrap()),
        &ROUTE_GLOBAL,
    );
    assert_eq!(
        got(&friend_plan(&book, &v6)),
        vec![addr("[2606:4700::1]:1000")]
    );
}

#[test]
fn plan_v6_global_needs_egress() {
    let book = vec![
        known("[2606:4700::1]:1000", AddrSource::Invite, false),
        known("[fd12:3456:789a::7]:1000", AddrSource::Invite, false),
        known("[::1]:1000", AddrSource::Invite, false),
        known("5.6.7.8:1000", AddrSource::Invite, false),
    ];
    let keep = vec![
        addr("[::1]:1000"),
        addr("[fd12:3456:789a::7]:1000"),
        addr("5.6.7.8:1000"),
    ];
    let sorted = |plan: &crate::plan::Plan| {
        let mut v = got(plan);
        v.sort();
        v
    };
    let mut want = keep.clone();
    want.sort();
    // нет маршрута IPv6, link-local, Teredo, 6to4, документация: глобальный IPv6 не набирается
    for route in [
        None,
        Some("fe80::1"),
        Some("2001:0:4136:e378::1"),
        Some("2002:c000:204::1"),
        Some("2001:db8::5"),
    ] {
        let fam = dual_with_route(route);
        assert!(!fam.v6_egress, "{route:?}");
        assert_eq!(sorted(&friend_plan(&book, &fam)), want, "{route:?}");
    }
    // ULA за NAT66 это выход: глобальный набирается
    let fam = dual_with_route(Some("fd00::5"));
    assert!(fam.v6_egress);
    assert_eq!(friend_plan(&book, &fam).cands.len(), 4);
    // глобальный источник: то же
    assert_eq!(
        friend_plan(&book, &dual_with_route(Some(GLOBAL_SRC)))
            .cands
            .len(),
        4
    );
    // ULA и ::1 не требуют выхода, но требуют IPv6 в `local_addrs`
    let v4 = families(
        &[addr("0.0.0.0:4000")],
        Some(GLOBAL_SRC.parse().unwrap()),
        &ROUTE_GLOBAL,
    );
    assert_eq!(got(&friend_plan(&book, &v4)), vec![addr("5.6.7.8:1000")]);
}

#[test]
fn plan_v6_hostile_targets_skipped() {
    let fam = dual_with_route(Some(GLOBAL_SRC));
    let hostile = [
        "[::1.2.3.4]:1000",
        "[::]:1000",
        "[fe80::1]:1000",
        "[fe80::1%3]:1000",
        "[fec0::1]:1000",
        "[100::1]:1000",
        "[ff02::1]:1000",
        "[ff0e::1]:1000",
        "[64:ff9b::1.2.3.4]:1000",
        "[64:ff9b:1::1]:1000",
        "[2002::1]:1000",
        "[2001::1]:1000",
        "[2001:0:4136:e378::1]:1000",
        "[2001:db8::1]:1000",
        "[3fff::1]:1000",
        "[4000::1]:1000",
        "[2606:4700::1]:0",
    ];
    // link-local с идентификатором интерфейса (в строку `SocketAddr` он не разбирается)
    let mut all: Vec<SocketAddr> = hostile.iter().map(|h| addr(h)).collect();
    all.push(SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        1000,
        0,
        3,
    )));
    all.push(SocketAddr::V6(SocketAddrV6::new(
        "2002::1".parse().unwrap(),
        1000,
        7,
        0,
    )));
    for a in &all {
        assert!(!family_ok(a, &fam) || a.port() == 0, "{a:?}");
        assert!(!dialable(a), "{a:?}");
        assert!(
            friend_plan(&[known_addr(*a)], &fam).cands.is_empty(),
            "{a:?}"
        );
        assert!(guest_plan(&[*a], &fam).cands.is_empty(), "{a:?}");
    }
    // допустимый в том же списке остаётся
    let mut book: Vec<_> = all.iter().copied().map(known_addr).collect();
    book.push(known("[2606:4700::9]:1000", AddrSource::Invite, false));
    assert_eq!(
        got(&friend_plan(&book, &fam)),
        vec![addr("[2606:4700::9]:1000")]
    );
}

fn known_addr(a: SocketAddr) -> chervo_addr::KnownAddr {
    chervo_addr::KnownAddr {
        addr: a,
        ..known("203.0.113.1:1", AddrSource::Invite, false)
    }
}

#[test]
fn plan_v4_mapped_target_normalized_and_deduped() {
    let fam = dual_with_route(Some(GLOBAL_SRC));
    let book = vec![
        known("[::ffff:5.6.7.8]:1000", AddrSource::Invite, false),
        known("5.6.7.8:1000", AddrSource::Contact, false),
    ];
    let plan = friend_plan(&book, &fam);
    assert_eq!(got(&plan), vec![addr("5.6.7.8:1000")]);
    assert!(plan.cands[0].addr.is_ipv4());
    // v4-mapped на транспорте без IPv4 не уходит в IPv6
    let v6 = families(
        &[addr("[::]:4000")],
        Some(GLOBAL_SRC.parse().unwrap()),
        &ROUTE_GLOBAL,
    );
    assert!(friend_plan(&book, &v6).cands.is_empty());
}

#[test]
fn guest_plan_same_v6_rules() {
    let token = [
        addr("[2606:4700::1]:1000"),
        addr("[fe80::1]:1000"),
        addr("[2002::1]:1000"),
        addr("[::1]:1000"),
        addr("5.5.5.5:1111"),
    ];
    let with = dual_with_route(Some(GLOBAL_SRC));
    // локальная сеть (::1) идёт первой, дальше порядок токена
    assert_eq!(
        got(&guest_plan(&token, &with)),
        vec![
            addr("[::1]:1000"),
            addr("[2606:4700::1]:1000"),
            addr("5.5.5.5:1111")
        ]
    );
    let without = dual_with_route(None);
    assert_eq!(
        got(&guest_plan(&token, &without)),
        vec![addr("[::1]:1000"), addr("5.5.5.5:1111")]
    );
    assert!(guest_plan(&token, &with).cands.iter().all(|c| !c.strict));
}

// ------------------------------------------------ круг 1 ревью: источник маршрута к цели

fn ula_book() -> Vec<chervo_addr::KnownAddr> {
    vec![
        known("[fd12:3456:789a::7]:1000", AddrSource::Invite, false),
        known("[2606:4700::1]:1000", AddrSource::Invite, false),
        known("5.6.7.8:1000", AddrSource::Invite, false),
    ]
}

#[test]
fn plan_ula_via_teredo_source_dropped() {
    // ULA-цель, но ОС повела бы пакет через Teredo, 6to4, link-local или документацию: не набирать
    // (глобальная цель тоже: источник маршрута не глобальный и не ULA)
    for src in [
        "2001:0:4136:e378::1",
        "2002:c000:204::1",
        "fe80::1",
        "2001:db8::5",
    ] {
        let probe = FixedRoute(Some(std::net::IpAddr::V6(src.parse().unwrap())));
        let fam = families(&local_dual(), Some(GLOBAL_SRC.parse().unwrap()), &probe);
        assert!(fam.v6_egress);
        assert_eq!(
            got(&friend_plan(&ula_book(), &fam)),
            vec![addr("5.6.7.8:1000")],
            "{src}"
        );
        assert!(
            guest_plan(&[addr("[fd12:3456:789a::7]:1000")], &fam)
                .cands
                .is_empty(),
            "{src}"
        );
    }
}

#[test]
fn plan_ula_via_ula_source_kept() {
    let probe = FixedRoute(Some(std::net::IpAddr::V6("fd00::5".parse().unwrap())));
    // выхода (route_v6) нет: ULA-цель идёт, глобальная нет
    let fam = families(&local_dual(), None, &probe);
    assert_eq!(
        got(&friend_plan(&ula_book(), &fam)),
        vec![addr("[fd12:3456:789a::7]:1000"), addr("5.6.7.8:1000")]
    );
    // выход есть (ULA за NAT66): глобальная тоже
    let fam = families(&local_dual(), Some("fd00::5".parse().unwrap()), &probe);
    assert_eq!(friend_plan(&ula_book(), &fam).cands.len(), 3);
}

#[test]
fn plan_ula_no_route_dropped() {
    let fam = families(
        &local_dual(),
        Some(GLOBAL_SRC.parse().unwrap()),
        &ROUTE_NONE,
    );
    assert_eq!(
        got(&friend_plan(&ula_book(), &fam)),
        vec![addr("5.6.7.8:1000")]
    );
}

#[test]
fn plan_loopback_v6_no_route_check() {
    // `::1` маршрута не требует (проба к петле даёт `None`), но требует IPv6 в `local_addrs`
    let book = vec![known("[::1]:1000", AddrSource::Invite, false)];
    let fam = families(&local_dual(), None, &ROUTE_NONE);
    assert_eq!(got(&friend_plan(&book, &fam)), vec![addr("[::1]:1000")]);
    let v4 = families(&[addr("0.0.0.0:4000")], None, &ROUTE_NONE);
    assert!(friend_plan(&book, &v4).cands.is_empty());
}
