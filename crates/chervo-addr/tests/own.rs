//! Собственные адреса: наблюдения, вид сети, набор для публикации.
//! Значения `PublishSet` строятся только через `OwnAddrs`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use chervo_addr::{
    GatewayInfo, LocalSnapshot, MAX_OBSERVATIONS, MAX_UPDATE_ADDRS, NatView, OBSERVED_TTL_SECS,
    ObserveOutcome, ObserveReject, OwnAddrs, PublishCtx, PublishSet, RouteSources, UpdateAddr,
};
use chervo_identity::PairId;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn v4sa(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

fn pid(n: u8) -> PairId {
    PairId::from_bytes([n; 16])
}

fn snap(route_v4: Option<&str>, route_v6: Option<&str>, listen: &[&str]) -> LocalSnapshot {
    LocalSnapshot {
        route: RouteSources {
            v4: route_v4.map(v4),
            v6: route_v6.map(|s| s.parse().unwrap()),
        },
        listen: listen.iter().map(|s| sa(s)).collect(),
    }
}

/// За NAT: частный маршрутный адрес, один IPv4 порт прослушивания 4000.
fn natted() -> OwnAddrs {
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("192.168.1.2"), None, &["0.0.0.0:4000"]));
    o
}

const NOW: u64 = 1_000_000;

fn report(o: &mut OwnAddrs, who: u8, observed: &str) -> ObserveOutcome {
    o.observe(pid(who), sa("8.8.8.8:5000"), sa(observed), NOW)
}

fn flags(set: &PublishSet) -> Vec<(SocketAddr, bool, bool)> {
    set.as_slice()
        .iter()
        .map(|u: &UpdateAddr| (u.addr, u.short_lived, u.hint))
        .collect()
}

fn publish(o: &OwnAddrs) -> Vec<(SocketAddr, bool, bool)> {
    flags(&o.publishable(PublishCtx::default(), NOW))
}

#[test]
fn set_local_change_clears_observations_and_gateway() {
    let mut o = natted();
    assert_eq!(report(&mut o, 1, "9.9.9.9:6000"), ObserveOutcome::Accepted);
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: None,
    }));
    // шлюз с глобальным WAN и наблюдение с другим IP: двойной NAT
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    // изменился маршрут
    let changed = o.set_local(snap(Some("192.168.1.3"), None, &["0.0.0.0:4000"]));
    assert!(changed);
    assert!(o.observed_v4(NOW).is_none());
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    // шлюз тоже сброшен: проброс больше не виден
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: Some(v4sa("1.2.3.4:4000")),
    }));
    assert_eq!(o.nat_view(NOW), NatView::PortMapped);
    assert!(o.set_local(snap(Some("192.168.1.3"), None, &["0.0.0.0:4001"])));
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    // первый вызов тоже изменение
    let mut fresh = OwnAddrs::new();
    assert!(fresh.local().is_none());
    assert!(fresh.set_local(snap(None, None, &[])));
    assert!(fresh.local().is_some());
}

#[test]
fn set_local_same_snapshot_no_change() {
    let mut o = natted();
    assert_eq!(report(&mut o, 1, "9.9.9.9:6000"), ObserveOutcome::Accepted);
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: None,
    }));
    // WAN шлюза и наблюдение расходятся: двойной NAT виден, пока живы оба
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    assert!(!o.set_local(snap(Some("192.168.1.2"), None, &["0.0.0.0:4000"])));
    // наблюдение и шлюз сохранены
    assert!(o.local().is_some());
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    // порядок адресов прослушивания не считается изменением
    let mut p = OwnAddrs::new();
    assert!(p.set_local(snap(None, None, &["0.0.0.0:4000", "[::]:4000"])));
    assert!(!p.set_local(snap(None, None, &["[::]:4000", "0.0.0.0:4000"])));
    assert!(p.set_local(snap(None, None, &["[::]:4000"])));
}

#[test]
fn observe_rules() {
    let mut o = natted();
    let via = sa("8.8.8.8:5000");
    // ZeroPort идёт первым
    assert_eq!(
        o.observe(pid(1), via, sa("9.9.9.9:0"), NOW),
        ObserveOutcome::Rejected(ObserveReject::ZeroPort)
    );
    assert_eq!(
        o.observe(pid(1), sa("192.168.1.9:5000"), sa("9.9.9.9:0"), NOW),
        ObserveOutcome::Rejected(ObserveReject::ZeroPort)
    );
    // семейство
    assert_eq!(
        o.observe(pid(1), via, sa("[2606:4700::1]:6000"), NOW),
        ObserveOutcome::Rejected(ObserveReject::FamilyMismatch)
    );
    assert_eq!(
        o.observe(pid(1), sa("[2606:4700::2]:5000"), sa("9.9.9.9:6000"), NOW),
        ObserveOutcome::Rejected(ObserveReject::FamilyMismatch)
    );
    // не глобальный наблюдаемый адрес
    for bad in [
        "10.0.0.1:6000",
        "192.168.1.1:6000",
        "100.64.0.1:6000",
        "127.0.0.1:6000",
        "169.254.1.1:6000",
        "192.0.2.1:6000",
        "224.0.0.1:6000",
        "0.0.0.0:6000",
    ] {
        assert_eq!(
            o.observe(pid(1), via, sa(bad), NOW),
            ObserveOutcome::Rejected(ObserveReject::NotGlobal),
            "{bad}"
        );
    }
    // тот же IP, что у друга
    assert_eq!(
        o.observe(pid(1), via, sa("8.8.8.8:7000"), NOW),
        ObserveOutcome::Rejected(ObserveReject::ReporterOwnIp)
    );
    // ничего не сохранено после отказов
    assert!(o.observed_v4(NOW).is_none());
    // путь не глобальный: частный, общий (CGNAT), петлевой
    for local_via in ["192.168.1.9:5000", "100.64.0.9:5000", "127.0.0.1:5000"] {
        assert_eq!(
            o.observe(pid(1), sa(local_via), sa("9.9.9.9:6000"), NOW),
            ObserveOutcome::IgnoredLocalPath,
            "{local_via}"
        );
    }
    assert!(o.observed_v4(NOW).is_none());
    // принято; mapped-via нормализуется
    assert_eq!(
        o.observe(pid(1), sa("[::ffff:8.8.8.8]:5000"), sa("9.9.9.9:6000"), NOW),
        ObserveOutcome::Accepted
    );
    assert_eq!(o.observed_v4(NOW), Some(v4sa("9.9.9.9:6000")));
    // mapped-observed нормализуется и сравнивается по IPv4
    assert_eq!(
        o.observe(pid(2), via, sa("[::ffff:8.8.8.8]:7000"), NOW),
        ObserveOutcome::Rejected(ObserveReject::ReporterOwnIp)
    );
    // глобальный IPv6 принимается, но в IPv4-виде не участвует
    let mut o6 = natted();
    assert_eq!(
        o6.observe(
            pid(3),
            sa("[2606:4700::2]:5000"),
            sa("[2606:4700::1]:6000"),
            NOW
        ),
        ObserveOutcome::Accepted
    );
    assert!(o6.observed_v4(NOW).is_none());
    assert_eq!(o6.nat_view(NOW), NatView::Unknown);
}

#[test]
fn observe_replace_per_reporter_and_cap() {
    let mut o = natted();
    // репортёр 0 (самый старый) называет другой порт
    o.observe(pid(0), sa("8.8.8.8:5000"), sa("9.9.9.9:7000"), 100);
    for i in 1..MAX_OBSERVATIONS {
        let n = u8::try_from(i).unwrap();
        o.observe(
            pid(n),
            sa("8.8.8.8:5000"),
            sa("9.9.9.9:6000"),
            100 + u64::from(n),
        );
    }
    // 16 записей, из них одна с другим портом
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Symmetric);
    // 17-й вытесняет самого старого (репортёр 0): остаётся общий ip:port
    o.observe(
        pid(16),
        sa("8.8.8.8:5000"),
        sa("9.9.9.9:6000"),
        100 + MAX_OBSERVATIONS as u64,
    );
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Eim);
    // повторный отчёт того же репортёра заменяет запись, а не добавляет
    o.observe(pid(5), sa("8.8.8.8:5000"), sa("9.9.9.9:6001"), 200);
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Symmetric);
    o.observe(pid(5), sa("8.8.8.8:5000"), sa("9.9.9.9:6000"), 201);
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Eim);
    // остаются репортёры 1 и 2 с общим ip:port, затем один: вид Unknown
    for i in 3..=16u8 {
        o.forget_reporter(&pid(i));
    }
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Eim);
    o.forget_reporter(&pid(1));
    assert_eq!(o.nat_view(NOW_SMALL), NatView::Unknown);
}

/// Момент проверки для теста выше: все записи живые.
const NOW_SMALL: u64 = 300;

#[test]
fn observe_expiry() {
    let mut o = natted();
    let at = 1_000u64;
    o.observe(pid(1), sa("8.8.8.8:5000"), sa("9.9.9.9:6000"), at);
    assert!(o.observed_v4(at).is_some());
    assert!(o.observed_v4(at + OBSERVED_TTL_SECS - 1).is_some());
    // граница TTL: ровно at + TTL уже не живое
    assert!(o.observed_v4(at + OBSERVED_TTL_SECS).is_none());
    assert!(o.observed_v4(at + OBSERVED_TTL_SECS + 1).is_none());
    // запись «из будущего»: допуск 60 секунд
    let mut f = natted();
    f.observe(pid(1), sa("8.8.8.8:5000"), sa("9.9.9.9:6000"), 1_060);
    assert!(f.observed_v4(1_000).is_some());
    let mut g = natted();
    g.observe(pid(1), sa("8.8.8.8:5000"), sa("9.9.9.9:6000"), 1_061);
    assert!(g.observed_v4(1_000).is_none());
    // истёкшая запись не влияет на вид сети
    assert_eq!(
        o.nat_view(at + OBSERVED_TTL_SECS),
        NatView::Unknown,
        "без живых наблюдений"
    );
}

#[test]
fn forget_reporter_drops_hint() {
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    assert!(publish(&o).iter().any(|(_, _, hint)| *hint));
    o.forget_reporter(&pid(2));
    assert!(publish(&o).iter().any(|(_, _, hint)| *hint));
    o.forget_reporter(&pid(1));
    assert!(publish(&o).is_empty());
}

#[test]
fn nat_view_rules() {
    // NoIpv4: нет снимка и нет маршрутного IPv4
    let mut o = OwnAddrs::new();
    assert_eq!(o.nat_view(NOW), NatView::NoIpv4);
    assert!(!o.stable_reachable(NOW));
    o.set_local(snap(None, Some("2606:4700::7"), &["[::]:4000"]));
    assert_eq!(o.nat_view(NOW), NatView::NoIpv4);
    // Public
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("8.8.4.4"), None, &["0.0.0.0:4000"]));
    assert_eq!(o.nat_view(NOW), NatView::Public);
    assert!(o.stable_reachable(NOW));
    // BehindCgnat: маршрутный адрес общий
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("100.64.0.5"), None, &["0.0.0.0:4000"]));
    assert_eq!(o.nat_view(NOW), NatView::BehindCgnat);
    // BehindCgnat: WAN шлюза общий
    let mut o = natted();
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("100.100.1.1")),
        mapping: Some(v4sa("100.100.1.1:4000")),
    }));
    assert_eq!(o.nat_view(NOW), NatView::BehindCgnat);
    // DoubleNat: WAN шлюза частный
    let mut o = natted();
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("10.1.1.1")),
        mapping: Some(v4sa("10.1.1.1:4000")),
    }));
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    // PortMapped: WAN глобальный и проброс на тот же адрес
    let mut o = natted();
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: Some(v4sa("1.2.3.4:4000")),
    }));
    assert_eq!(o.nat_view(NOW), NatView::PortMapped);
    assert!(o.stable_reachable(NOW));
    // Conflicting: два друга видят разные IP
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.10:6000");
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    // DoubleNat: WAN глобальный, но наблюдение с другим IP
    let mut o = natted();
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: None,
    }));
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    // Symmetric: тот же IP, разные порты
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.9:6001");
    assert_eq!(o.nat_view(NOW), NatView::Symmetric);
    // Eim: два друга видят один ip:port
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::Eim);
    // Unknown: нет наблюдений или одно
    let mut o = natted();
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert!(!o.stable_reachable(NOW));
}

#[test]
fn publish_white_ip() {
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("8.8.4.4"), None, &["0.0.0.0:4000"]));
    assert_eq!(publish(&o), vec![(sa("8.8.4.4:4000"), false, false)]);
    // наблюдения при белом IP не публикуются
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(publish(&o), vec![(sa("8.8.4.4:4000"), false, false)]);
    // без снимка и без порта прослушивания: пусто
    assert!(
        OwnAddrs::new()
            .publishable(PublishCtx::default(), NOW)
            .is_empty()
    );
    let mut np = OwnAddrs::new();
    np.set_local(snap(Some("8.8.4.4"), None, &[]));
    assert!(np.publishable(PublishCtx::default(), NOW).is_empty());
    // порт 0 не публикуется
    let mut z = OwnAddrs::new();
    z.set_local(snap(Some("8.8.4.4"), None, &["0.0.0.0:0"]));
    assert!(z.publishable(PublishCtx::default(), NOW).is_empty());
}

#[test]
fn publish_mapping_requires_global_wan_match() {
    let gw = |wan: Option<&str>, map: Option<&str>| GatewayInfo {
        wan_ip: wan.map(v4),
        mapping: map.map(v4sa),
    };
    // совпадение: проброс публикуется без флагов
    let mut o = natted();
    o.set_gateway(Some(gw(Some("1.2.3.4"), Some("1.2.3.4:5555"))));
    assert_eq!(publish(&o), vec![(sa("1.2.3.4:5555"), false, false)]);
    // IP проброса не равен WAN
    let mut o = natted();
    o.set_gateway(Some(gw(Some("1.2.3.4"), Some("1.2.3.5:5555"))));
    assert!(publish(&o).is_empty());
    // WAN частный, общий, не задан
    for (wan, map) in [
        (Some("10.1.1.1"), "10.1.1.1:5555"),
        (Some("100.100.1.1"), "100.100.1.1:5555"),
        (None, "1.2.3.4:5555"),
    ] {
        let mut o = natted();
        o.set_gateway(Some(gw(wan, Some(map))));
        assert!(publish(&o).is_empty(), "{wan:?}");
    }
}

#[test]
fn publish_observed_single_friend_hint() {
    // N6: одного друга достаточно
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:6000"), false, true)]);
    // два согласных друга: тот же адрес, один раз
    report(&mut o, 2, "9.9.9.9:6000");
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:6000"), false, true)]);
}

#[test]
fn publish_observed_withheld_on_conflict() {
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.10:6000");
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    assert!(publish(&o).is_empty());
    // после истечения одного из отчётов адрес снова виден
    let mut o = natted();
    o.observe(pid(1), sa("8.8.8.8:5000"), sa("9.9.9.9:6000"), NOW);
    o.observe(pid(2), sa("8.8.8.8:5000"), sa("9.9.9.10:6000"), NOW + 1_000);
    assert!(o.publishable(PublishCtx::default(), NOW + 1_000).is_empty());
    let later = NOW + OBSERVED_TTL_SECS;
    assert_eq!(
        flags(&o.publishable(PublishCtx::default(), later)),
        vec![(sa("9.9.9.10:6000"), false, true)]
    );
}

#[test]
fn publish_observed_withheld_on_symmetric() {
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.9:6001");
    assert_eq!(o.nat_view(NOW), NatView::Symmetric);
    assert!(publish(&o).is_empty());
}

#[test]
fn publish_observed_withheld_on_double_nat() {
    let mut o = natted();
    o.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: None,
    }));
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::DoubleNat);
    assert!(publish(&o).is_empty());
    // наблюдение совпадает с WAN шлюза: не двойной NAT, публикуется как подсказка
    let mut ok = natted();
    ok.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("9.9.9.9")),
        mapping: None,
    }));
    report(&mut ok, 1, "9.9.9.9:6000");
    assert_eq!(publish(&ok), vec![(sa("9.9.9.9:6000"), false, true)]);
}

#[test]
fn publish_v6_short_lived_never_eui64() {
    let mut o = OwnAddrs::new();
    o.set_local(snap(
        None,
        Some("2606:4700::7"),
        &["0.0.0.0:4000", "[::]:4001"],
    ));
    assert_eq!(publish(&o), vec![(sa("[2606:4700::7]:4001"), true, false)]);
    // EUI-64: не публикуется
    let mut e = OwnAddrs::new();
    e.set_local(snap(
        None,
        Some("2606:4700::211:22ff:fe33:4455"),
        &["[::]:4001"],
    ));
    assert!(publish(&e).is_empty());
    // EUI-64 ULA тоже не публикуется даже с LAN
    let mut u = OwnAddrs::new();
    u.set_local(snap(None, Some("fd00::211:22ff:fe33:4455"), &["[::]:4001"]));
    assert!(
        u.publishable(
            PublishCtx {
                include_lan: true,
                path_source: None,
            },
            NOW
        )
        .is_empty()
    );
    // не глобальный и не частный IPv6 не публикуется
    for bad in ["fe80::1", "2001:db8::1", "::1"] {
        let mut b = OwnAddrs::new();
        b.set_local(snap(None, Some(bad), &["[::]:4001"]));
        assert!(
            b.publishable(
                PublishCtx {
                    include_lan: true,
                    path_source: None,
                },
                NOW
            )
            .is_empty(),
            "{bad}"
        );
    }
}

#[test]
fn publish_lan_only_with_ctx() {
    let mut o = OwnAddrs::new();
    o.set_local(snap(
        Some("192.168.1.2"),
        Some("fd00::7"),
        &["0.0.0.0:4000", "[::]:4001"],
    ));
    assert!(o.publishable(PublishCtx::default(), NOW).is_empty());
    assert_eq!(
        flags(&o.publishable(
            PublishCtx {
                include_lan: true,
                path_source: None,
            },
            NOW
        )),
        vec![
            (sa("192.168.1.2:4000"), false, false),
            (sa("[fd00::7]:4001"), true, false)
        ]
    );
}

#[test]
fn publish_needs_listen_family() {
    // глобальный IPv4 есть, но слушаем только IPv6
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("8.8.4.4"), Some("2606:4700::7"), &["[::]:4001"]));
    assert_eq!(publish(&o), vec![(sa("[2606:4700::7]:4001"), true, false)]);
    // глобальный IPv6 есть, но слушаем только IPv4
    let mut p = OwnAddrs::new();
    p.set_local(snap(
        Some("8.8.4.4"),
        Some("2606:4700::7"),
        &["0.0.0.0:4000"],
    ));
    assert_eq!(publish(&p), vec![(sa("8.8.4.4:4000"), false, false)]);
}

#[test]
fn publish_dedup_and_cap() {
    // самый полный набор: подсказка, глобальный IPv6, LAN IPv4 и ULA
    let mut o = OwnAddrs::new();
    o.set_local(snap(
        Some("192.168.1.2"),
        Some("2606:4700::7"),
        &["0.0.0.0:4000", "[::]:4001"],
    ));
    report(&mut o, 1, "9.9.9.9:6000");
    let full = flags(&o.publishable(
        PublishCtx {
            include_lan: true,
            path_source: None,
        },
        NOW,
    ));
    assert_eq!(full.len(), 3);
    assert!(full.len() <= MAX_UPDATE_ADDRS);
    for (i, a) in full.iter().enumerate() {
        assert!(!full.iter().take(i).any(|b| b.0 == a.0), "повтор адреса");
    }
    // порядок: подсказка, IPv6, LAN IPv4
    assert_eq!(full.first().map(|a| a.2), Some(true));
    assert_eq!(full.get(1).map(|a| a.1), Some(true));
    assert_eq!(full.get(2).map(|a| a.0), Some(sa("192.168.1.2:4000")));
    assert_eq!(MAX_UPDATE_ADDRS, 8);
}

#[test]
fn for_connection_rules() {
    let src4: IpAddr = "10.99.0.1".parse().unwrap();
    let src6: IpAddr = "fd00::5".parse().unwrap();
    // частный удалённый адрес и частный источник того же семейства: путь принят
    for (s, src) in [
        ("192.168.1.9:5", src4),
        ("10.0.0.1:5", src4),
        ("172.16.0.1:5", src4),
        ("[fd00::1]:5", src6),
        ("[::ffff:192.168.1.9]:5", src4),
    ] {
        let c = PublishCtx::for_connection(sa(s), Some(src));
        assert!(!c.include_lan, "{s}");
        assert_eq!(c.path_source, Some(src), "{s}");
        // без источника пути нет, и LAN по умолчанию не включается
        let n = PublishCtx::for_connection(sa(s), None);
        assert_eq!(n, PublishCtx::default(), "{s}");
    }
    // не частный удалённый адрес: источника нет, что бы ни дали
    for s in [
        "8.8.8.8:5",
        "[2606:4700::1]:5",
        "127.0.0.1:5",
        "169.254.1.1:5",
        "100.64.0.1:5",
        "[fe80::1]:5",
        "[::ffff:8.8.8.8]:5",
    ] {
        for src in [src4, src6] {
            let c = PublishCtx::for_connection(sa(s), Some(src));
            assert!(!c.include_lan && c.path_source.is_none(), "{s}");
        }
    }
    // семейство источника другое: нет; источник не частный: нет
    assert!(
        PublishCtx::for_connection(sa("192.168.1.9:5"), Some(src6))
            .path_source
            .is_none()
    );
    assert!(
        PublishCtx::for_connection(sa("[fd00::1]:5"), Some(src4))
            .path_source
            .is_none()
    );
    for bad in [
        "8.8.8.8",
        "100.64.0.9",
        "169.254.1.1",
        "127.0.0.1",
        "2606:4700::7",
    ] {
        let ip: IpAddr = bad.parse().unwrap();
        let remote = if ip.is_ipv4() {
            "192.168.1.9:5"
        } else {
            "[fd00::1]:5"
        };
        assert!(
            PublishCtx::for_connection(sa(remote), Some(ip))
                .path_source
                .is_none(),
            "{bad}"
        );
    }
}

// ---------- ручной проброс порта (этап 13, C2) ----------

#[test]
fn manual_forward_view_and_publish() {
    let mut o = natted();
    o.set_manual_forward(Some(8000));
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::ManualForward);
    assert!(o.stable_reachable(NOW));
    // новейшее наблюдение даёт IP, порт задан пользователем; IP не проверен: hint
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:8000"), false, true)]);
    // `observed_v4` для ручного проброса пуст: порт наблюдения не публикуется
    assert!(o.observed_v4(NOW).is_none());
    // два согласных друга: тот же адрес, один раз
    report(&mut o, 2, "9.9.9.9:6000");
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:8000"), false, true)]);
    // сняли проброс: прежний вид
    o.set_manual_forward(None);
    assert_eq!(o.nat_view(NOW), NatView::Eim);
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:6000"), false, true)]);
}

#[test]
fn manual_forward_needs_observation() {
    let mut o = natted();
    o.set_manual_forward(Some(8000));
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert!(!o.stable_reachable(NOW));
    assert!(publish(&o).is_empty());
    // наблюдение появилось: вид и набор есть
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:8000"), false, true)]);
    // наблюдение истекло: снова без адреса
    let later = NOW + OBSERVED_TTL_SECS;
    assert_eq!(o.nat_view(later), NatView::Unknown);
    assert!(o.publishable(PublishCtx::default(), later).is_empty());
    // наблюдение с локального пути не считается
    let mut lan = natted();
    lan.set_manual_forward(Some(8000));
    lan.observe(pid(1), sa("192.168.1.9:5000"), sa("9.9.9.9:6000"), NOW);
    assert_eq!(lan.nat_view(NOW), NatView::Unknown);
}

#[test]
fn manual_forward_not_over_conflict_or_double_nat() {
    // разные IP у разных друзей: конфликт сильнее ручного проброса
    let mut o = natted();
    o.set_manual_forward(Some(8000));
    report(&mut o, 1, "9.9.9.9:6000");
    report(&mut o, 2, "9.9.9.10:6000");
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    assert!(!o.stable_reachable(NOW));
    assert!(publish(&o).is_empty());
    // WAN шлюза не равен наблюдению: двойной NAT сильнее
    let mut d = natted();
    d.set_manual_forward(Some(8000));
    d.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("1.2.3.4")),
        mapping: None,
    }));
    report(&mut d, 1, "9.9.9.9:6000");
    assert_eq!(d.nat_view(NOW), NatView::DoubleNat);
    assert!(publish(&d).is_empty());
    // WAN шлюза совпал с наблюдением: ручной проброс действует
    let mut ok = natted();
    ok.set_manual_forward(Some(8000));
    ok.set_gateway(Some(GatewayInfo {
        wan_ip: Some(v4("9.9.9.9")),
        mapping: None,
    }));
    report(&mut ok, 1, "9.9.9.9:6000");
    assert_eq!(ok.nat_view(NOW), NatView::ManualForward);
    // CGNAT по маршруту и белый IP по маршруту остаются прежними видами
    let mut cg = OwnAddrs::new();
    cg.set_local(snap(Some("100.64.1.2"), None, &["0.0.0.0:4000"]));
    cg.set_manual_forward(Some(8000));
    report(&mut cg, 1, "9.9.9.9:6000");
    assert_eq!(cg.nat_view(NOW), NatView::BehindCgnat);
    let mut white = OwnAddrs::new();
    white.set_local(snap(Some("8.8.4.4"), None, &["0.0.0.0:4000"]));
    white.set_manual_forward(Some(8000));
    assert_eq!(white.nat_view(NOW), NatView::Public);
    assert_eq!(publish(&white), vec![(sa("8.8.4.4:4000"), false, false)]);
}

#[test]
fn manual_forward_zero_is_none() {
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    o.set_manual_forward(Some(8000));
    assert_eq!(o.nat_view(NOW), NatView::ManualForward);
    o.set_manual_forward(Some(0));
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:6000"), false, true)]);
    // Some(0) с самого начала тоже ничего не включает
    let mut z = natted();
    z.set_manual_forward(Some(0));
    report(&mut z, 1, "9.9.9.9:6000");
    assert_eq!(z.nat_view(NOW), NatView::Unknown);
}

#[test]
fn manual_forward_survives_set_local() {
    let mut o = natted();
    o.set_manual_forward(Some(8000));
    // смена сети сбрасывает наблюдения, но не настройку пользователя
    assert!(o.set_local(snap(Some("192.168.7.2"), None, &["0.0.0.0:4000"])));
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    report(&mut o, 1, "9.9.9.9:6000");
    assert_eq!(o.nat_view(NOW), NatView::ManualForward);
    assert_eq!(publish(&o), vec![(sa("9.9.9.9:8000"), false, true)]);
}

#[test]
fn stable_reachable_includes_manual() {
    let mut o = natted();
    report(&mut o, 1, "9.9.9.9:6000");
    assert!(!o.stable_reachable(NOW));
    o.set_manual_forward(Some(8000));
    assert!(o.stable_reachable(NOW));
    // без наблюдения достижимости нет
    let mut n = natted();
    n.set_manual_forward(Some(8000));
    assert!(!n.stable_reachable(NOW));
}

#[test]
fn port_mapper_types_debug_redacted() {
    use chervo_addr::{MapReport, MapRequest, MapStatus};
    use std::time::Duration;
    let req = MapRequest {
        internal: v4sa("192.168.1.23:4000"),
    };
    let rep = MapReport {
        status: MapStatus::Mapped,
        gateway: Some(GatewayInfo {
            wan_ip: Some(v4("93.184.216.34")),
            mapping: Some(v4sa("93.184.216.34:4000")),
        }),
        retry_after: Duration::from_secs(1800),
    };
    assert_eq!(format!("{req:?}"), "MapRequest(..)");
    assert_eq!(format!("{rep:?}"), "MapReport(..)");
    assert_eq!(format!("{:?}", MapStatus::Refused(606)), "Refused(606)");
}
