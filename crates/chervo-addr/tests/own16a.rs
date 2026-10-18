//! Этап 16а: текущие наблюдения (F1) и адрес на пути частного соединения (П2a).
//! Продолжение `own.rs`: те же помощники, отдельный файл.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use chervo_addr::{
    LocalSnapshot, MAX_REPORTERS_UP, NatView, OBSERVED_TTL_SECS, ObserveOutcome, OwnAddrs,
    PublishCtx, PublishSet, RouteSources, UpdateAddr,
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

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pid(n: u8) -> PairId {
    PairId::from_bytes([n; 16])
}

fn pid32(n: u32) -> PairId {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&n.to_be_bytes());
    PairId::from_bytes(b)
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

fn natted() -> OwnAddrs {
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("192.168.1.2"), None, &["0.0.0.0:4000"]));
    o
}

const NOW: u64 = 1_000_000;
const X: &str = "9.9.9.9:6000";
const Y: &str = "7.7.7.7:6001";

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

// ---------- F1: текущие наблюдения ----------

#[test]
fn current_overrides_disconnected() {
    let mut o = natted();
    for who in [1, 2, 3] {
        o.reporter_up(pid(who));
        assert_eq!(report(&mut o, who, X), ObserveOutcome::Accepted);
    }
    assert_eq!(o.nat_view(NOW), NatView::Eim);
    o.reporter_down(&pid(2));
    o.reporter_down(&pid(3));
    // тот же друг вернулся и сообщает новое: старые мнения отключённых не спорят
    o.reporter_up(pid(1));
    assert_eq!(report(&mut o, 1, Y), ObserveOutcome::Accepted);
    assert_ne!(o.nat_view(NOW), NatView::Conflicting);
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(Y)));
    assert_eq!(publish(&o), vec![(sa(Y), false, true)]);
}

#[test]
fn current_disagree_conflicting_no_hint() {
    let mut o = natted();
    o.reporter_up(pid(1));
    o.reporter_up(pid(2));
    report(&mut o, 1, Y);
    report(&mut o, 2, X);
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    assert!(o.observed_v4(NOW).is_none());
    assert!(publish(&o).is_empty());
}

#[test]
fn no_current_falls_back_to_ttl() {
    // reporter_up не вызывался никогда: прежнее поведение на тех же входных данных
    let mut o = natted();
    report(&mut o, 1, X);
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(X)));
    report(&mut o, 2, Y);
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    assert!(publish(&o).is_empty());
    let mut e = natted();
    report(&mut e, 1, X);
    report(&mut e, 2, X);
    assert_eq!(e.nat_view(NOW), NatView::Eim);
    assert_eq!(publish(&e), vec![(sa(X), false, true)]);
    let mut s = natted();
    report(&mut s, 1, X);
    report(&mut s, 2, "9.9.9.9:6100");
    assert_eq!(s.nat_view(NOW), NatView::Symmetric);
    // TTL по-прежнему действует
    assert_eq!(e.nat_view(NOW + OBSERVED_TTL_SECS), NatView::Unknown);
}

#[test]
fn obs_before_up_not_current() {
    let mut o = natted();
    report(&mut o, 1, X);
    // друг помечен «на связи» уже после наблюдения: наблюдение не текущее, но других нет
    o.reporter_up(pid(1));
    assert_eq!(o.observed_v4(NOW), Some(v4sa(X)));
    // появилось текущее от другого друга: старое чужое мнение не спорит
    o.reporter_up(pid(2));
    report(&mut o, 2, Y);
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(Y)));
    // новое сообщение первого друга после его отметки: теперь два текущих, они спорят
    report(&mut o, 1, X);
    assert_eq!(o.nat_view(NOW), NatView::Conflicting);
    // повторная отметка первого делает его наблюдение снова нетекущим
    o.reporter_up(pid(1));
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(Y)));
}

#[test]
fn current_ttl_forget_symmetric() {
    let mut o = natted();
    // устаревшее мнение с другим портом: от друга без отметки
    o.observe(pid(9), sa("8.8.8.8:5000"), sa("9.9.9.9:7000"), NOW);
    for who in [1, 2] {
        o.reporter_up(pid(who));
        o.observe(pid(who), sa("8.8.8.8:5000"), sa(X), NOW);
    }
    // Symmetric судится только по текущим
    assert_eq!(o.nat_view(NOW), NatView::Eim);
    // единственное текущее истекло по TTL: запасной вариант, остаётся устаревшее
    let mut f = natted();
    f.reporter_up(pid(1));
    f.observe(pid(1), sa("8.8.8.8:5000"), sa(X), NOW);
    f.observe(pid(2), sa("8.8.8.8:5000"), sa(Y), NOW + 500);
    assert_eq!(f.observed_v4(NOW + 100), Some(v4sa(X)));
    assert_eq!(f.observed_v4(NOW + OBSERVED_TTL_SECS), Some(v4sa(Y)));
    // forget_reporter снимает отметку и наблюдения
    assert_eq!(f.reporters_up(), 1);
    f.forget_reporter(&pid(1));
    assert_eq!(f.reporters_up(), 0);
    f.forget_reporter(&pid(2));
    assert!(f.observed_v4(NOW + 600).is_none());
}

#[test]
fn reporter_down_keeps_obs() {
    let mut o = natted();
    o.reporter_up(pid(1));
    report(&mut o, 1, X);
    assert_eq!(o.reporters_up(), 1);
    o.reporter_down(&pid(1));
    assert_eq!(o.reporters_up(), 0);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(X)));
    // повторное снятие ничего не ломает
    o.reporter_down(&pid(1));
    assert_eq!(o.reporters_up(), 0);
}

#[test]
fn set_local_change_keeps_up_marks() {
    let mut o = natted();
    o.reporter_up(pid(1));
    report(&mut o, 1, X);
    assert!(o.set_local(snap(Some("192.168.7.2"), None, &["0.0.0.0:4000"])));
    assert_eq!(o.reporters_up(), 1);
    assert!(o.observed_v4(NOW).is_none());
    // отметка действует и в новой сети: текущее мнение перевешивает старое чужое
    report(&mut o, 2, X);
    report(&mut o, 1, Y);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(Y)));
}

#[test]
fn reporters_up_capped() {
    let mut o = natted();
    let total = MAX_REPORTERS_UP as u32 + 10;
    for n in 0..total {
        o.reporter_up(pid32(n));
    }
    assert_eq!(o.reporters_up(), MAX_REPORTERS_UP);
    // самая старая отметка ушла: её наблюдение нетекущее, у самой новой текущее
    o.observe(pid32(0), sa("8.8.8.8:5000"), sa(X), NOW);
    o.observe(pid32(total - 1), sa("8.8.8.8:5000"), sa(Y), NOW);
    assert_eq!(o.nat_view(NOW), NatView::Unknown);
    assert_eq!(o.observed_v4(NOW), Some(v4sa(Y)));
    // повторный вызов не плодит отметки
    o.reporter_up(pid32(total - 1));
    assert_eq!(o.reporters_up(), MAX_REPORTERS_UP);
}

#[test]
fn manual_forward_uses_current() {
    let mut o = natted();
    o.set_manual_forward(Some(8000));
    // более новое, но нетекущее мнение отключённого друга
    o.observe(pid(2), sa("8.8.8.8:5000"), sa(Y), NOW + 10);
    o.reporter_up(pid(1));
    o.observe(pid(1), sa("8.8.8.8:5000"), sa(X), NOW);
    assert_eq!(o.nat_view(NOW + 10), NatView::ManualForward);
    let got = o.publishable(PublishCtx::default(), NOW + 10);
    assert_eq!(flags(&got), vec![(sa("9.9.9.9:8000"), false, true)]);
}

// ---------- П2a: адрес на пути частного соединения ----------

fn lan_node(listen: &[&str]) -> OwnAddrs {
    let mut o = OwnAddrs::new();
    o.set_local(snap(Some("192.168.1.5"), Some("fd00::7"), listen));
    o
}

#[test]
fn publish_path_source_private_only() {
    let o = lan_node(&["0.0.0.0:4000", "[::]:4001"]);
    let ctx = PublishCtx::for_connection(sa("10.0.0.7:5"), Some(ip("10.99.0.1")));
    let got = flags(&o.publishable(ctx, NOW));
    assert_eq!(got, vec![(sa("10.99.0.1:4000"), false, false)]);
    assert!(got.iter().all(|a| a.0 != sa("192.168.1.5:4000")));
    // ULA: короткоживущий, порт IPv6
    let ctx6 = PublishCtx::for_connection(sa("[fd00::1]:5"), Some(ip("fd00::99")));
    assert_eq!(
        flags(&o.publishable(ctx6, NOW)),
        vec![(sa("[fd00::99]:4001"), true, false)]
    );
}

#[test]
fn publish_path_source_non_private_ignored() {
    let o = lan_node(&["0.0.0.0:4000", "[::]:4001"]);
    for bad in [
        "8.8.8.8",
        "100.64.0.9",
        "169.254.1.1",
        "127.0.0.1",
        "2606:4700::7",
        "fe80::1",
        "::1",
        // EUI-64 ULA
        "fd00::211:22ff:fe33:4455",
    ] {
        let ctx = PublishCtx {
            include_lan: false,
            path_source: Some(ip(bad)),
        };
        assert!(o.publishable(ctx, NOW).is_empty(), "{bad}");
        // и с include_lan путь остаётся единственным источником шага 5
        let both = PublishCtx {
            include_lan: true,
            path_source: Some(ip(bad)),
        };
        assert!(o.publishable(both, NOW).is_empty(), "{bad}");
    }
}

#[test]
fn publish_path_source_none_no_lan() {
    let o = lan_node(&["0.0.0.0:4000", "[::]:4001"]);
    let ctx = PublishCtx::for_connection(sa("192.168.1.9:5"), None);
    assert!(o.publishable(ctx, NOW).is_empty());
}

#[test]
fn publish_path_source_listen_mismatch() {
    // слушаем на конкретном адресе, не равном источнику пути
    let o = lan_node(&["10.0.0.5:4000"]);
    let ctx = PublishCtx::for_connection(sa("10.0.0.7:5"), Some(ip("10.99.0.1")));
    assert!(o.publishable(ctx, NOW).is_empty());
    // равный адрес прослушивания подходит
    let ctx = PublishCtx::for_connection(sa("10.0.0.7:5"), Some(ip("10.0.0.5")));
    assert_eq!(
        flags(&o.publishable(ctx, NOW)),
        vec![(sa("10.0.0.5:4000"), false, false)]
    );
    // нет адреса прослушивания того семейства
    let v4only = lan_node(&["0.0.0.0:4000"]);
    let ctx6 = PublishCtx::for_connection(sa("[fd00::1]:5"), Some(ip("fd00::99")));
    assert!(v4only.publishable(ctx6, NOW).is_empty());
}

#[test]
fn publish_include_lan_manual_unchanged() {
    let o = lan_node(&["0.0.0.0:4000", "[::]:4001"]);
    let ctx = PublishCtx {
        include_lan: true,
        path_source: None,
    };
    assert_eq!(
        flags(&o.publishable(ctx, NOW)),
        vec![
            (sa("192.168.1.5:4000"), false, false),
            (sa("[fd00::7]:4001"), true, false)
        ]
    );
}
