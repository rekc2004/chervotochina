//! Диагностика «нет прямого пути»: порядок проверок и однократность события.

use std::collections::HashSet;
use std::net::SocketAddr;

use chervo_addr::{NEED_TOKEN_TEXT, NatView};
use chervo_identity::PairId;
use chervo_transport::{Connection, TransportError};

use super::kit::*;
use crate::{
    CGNAT_TEXT, ConnectConfig, Diagnosis, EngineEvent, NoDirectPath, SYMMETRIC_TEXT,
    UDP_BLOCKED_TEXT, user_text,
};

fn diag(reason: NoDirectPath, help: bool) -> Diagnosis {
    Diagnosis {
        reason,
        rendezvous_could_help: help,
    }
}

fn unreachable_for(pair: PairId) -> impl Fn(&EngineEvent) -> bool {
    move |e| matches!(e, EngineEvent::Unreachable { pair: p, .. } if *p == pair)
}

#[tokio::test(start_paused = true)]
async fn diag_no_known_address() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let mut n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    // у нас постоянный адрес есть: токен не нужен, адреса друга просто неизвестны
    assert_eq!(
        n.engine.diagnose(&p).unwrap(),
        Some(diag(NoDirectPath::NoKnownAddress, false))
    );
    let e = wait_event(&mut n.events, secs(130), unreachable_for(p))
        .await
        .unwrap();
    assert_eq!(
        e,
        EngineEvent::Unreachable {
            pair: p,
            diagnosis: diag(NoDirectPath::NoKnownAddress, false)
        }
    );
    assert!(n.t.calls_for(&p).is_empty());
}

#[tokio::test(start_paused = true)]
async fn diag_need_token() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![]);
    let n = Node::start(pre, ConnectConfig::default());
    let d = n.engine.diagnose(&p).unwrap().unwrap();
    assert_eq!(d, diag(NoDirectPath::NeedToken, true));
    assert_eq!(user_text(d.reason), NEED_TOKEN_TEXT);

    // адрес друга есть, но подсказка (не постоянный) и своего постоянного нет
    let mut pre = Pre::new();
    let q = pre.solo_friend(vec![known(
        "5.6.7.8:4000",
        chervo_addr::AddrSource::AddressUpdate,
        true,
    )]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let e = wait_event(&mut n.events, secs(130), unreachable_for(q))
        .await
        .unwrap();
    assert_eq!(
        e,
        EngineEvent::Unreachable {
            pair: q,
            diagnosis: diag(NoDirectPath::NeedToken, true)
        }
    );
}

#[tokio::test(start_paused = true)]
async fn diag_cgnat_from_route() {
    let mut pre = Pre::new();
    let p1 = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let p2 = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let mut n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("100.64.0.9")),
    );
    // молчат все: эвристика «UDP заблокирован» сработала бы, но CGNAT проверяется раньше
    n.t.set_script(|_, _| Action::Fail(TransportError::NoResponse, secs(0)));
    assert_eq!(n.engine.nat_view(), NatView::BehindCgnat);
    let e = wait_event(&mut n.events, secs(130), unreachable_for(p1))
        .await
        .unwrap();
    let EngineEvent::Unreachable { diagnosis, .. } = e else {
        panic!("not unreachable");
    };
    assert_eq!(diagnosis, diag(NoDirectPath::BehindCgnat, true));
    assert!(diagnosis.rendezvous_could_help);
    assert_eq!(user_text(diagnosis.reason), CGNAT_TEXT);
    assert_eq!(
        n.engine.diagnose(&p2).unwrap().map(|d| d.reason),
        Some(NoDirectPath::BehindCgnat)
    );
    // ни одного пакета мимо адресов друзей
    let allowed: HashSet<SocketAddr> = [addr("5.6.7.1:4000"), addr("5.6.7.2:4000")].into();
    let calls = n.t.calls.lock().unwrap().clone();
    assert!(!calls.is_empty());
    for (_, addrs) in calls {
        assert!(addrs.iter().all(|a| allowed.contains(a)));
    }
}

#[tokio::test(start_paused = true)]
async fn diag_symmetric() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let y = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let z = pre.solo_friend(vec![inv("5.6.7.3:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    // два друга видят нас с одним IP, но разными портами
    apply_obs(&n, x, "5.6.7.1:4000", "9.9.9.9:1111");
    apply_obs(&n, y, "5.6.7.2:4000", "9.9.9.9:2222");
    assert_eq!(n.engine.nat_view(), NatView::Symmetric);
    let e = wait_event(&mut n.events, secs(130), unreachable_for(z))
        .await
        .unwrap();
    let EngineEvent::Unreachable { diagnosis, .. } = e else {
        panic!("not unreachable");
    };
    assert_eq!(diagnosis, diag(NoDirectPath::SymmetricNat, false));
    assert_eq!(user_text(diagnosis.reason), SYMMETRIC_TEXT);
}

#[tokio::test(start_paused = true)]
async fn diag_udp_blocked_suspected() {
    let mut pre = Pre::new();
    let p1 = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::NoResponse, secs(0)));
    let e = wait_event(&mut n.events, secs(130), |e| {
        matches!(
            e,
            EngineEvent::Unreachable { diagnosis, .. }
                if diagnosis.reason == NoDirectPath::UdpBlockedSuspected
        )
    })
    .await
    .unwrap();
    let EngineEvent::Unreachable { diagnosis, .. } = e else {
        panic!("not unreachable");
    };
    assert!(!diagnosis.rendezvous_could_help);
    assert_eq!(user_text(diagnosis.reason), UDP_BLOCKED_TEXT);
    assert_eq!(
        n.engine.diagnose(&p1).unwrap().map(|d| d.reason),
        Some(NoDirectPath::UdpBlockedSuspected)
    );
}

#[tokio::test(start_paused = true)]
async fn diag_not_udp_blocked_when_one_answers() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let y = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    pre.solo_friend(vec![inv("5.6.7.3:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let conn = FakeConn::lonely(x, addr("5.6.7.1:4000"), true);
    let cc = conn.clone();
    let mut answered = false;
    n.t.set_script(move |pair, _| {
        if *pair == x && !std::mem::replace(&mut answered, true) {
            Action::Ok(cc.clone(), secs(0))
        } else {
            Action::Fail(TransportError::NoResponse, secs(0))
        }
    });
    // один друг ответил и ушёл: живых соединений нет, но успех был в окне
    tokio::time::sleep(secs(3)).await;
    conn.close();
    tokio::time::sleep(secs(60)).await;
    assert!(n.engine.connection(&x).is_none());
    assert_eq!(
        n.engine.diagnose(&y).unwrap().map(|d| d.reason),
        Some(NoDirectPath::Unknown)
    );
    assert!(!drain(&mut n.events).await.iter().any(|e| matches!(
        e,
        EngineEvent::Unreachable { diagnosis, .. }
            if diagnosis.reason == NoDirectPath::UdpBlockedSuspected
    )));
}

#[tokio::test(start_paused = true)]
async fn diag_no_ipv6() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("[2001:4860::1]:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    assert_eq!(
        n.engine.diagnose(&p).unwrap(),
        Some(diag(NoDirectPath::NoIpv6, false))
    );
    tokio::time::sleep(secs(60)).await;
    assert!(n.t.calls_for(&p).is_empty(), "no IPv6 socket, no dial");
}

#[tokio::test(start_paused = true)]
async fn unreachable_emitted_once_per_reason() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.3:4000")]);
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let y = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    tokio::time::sleep(secs(400)).await;
    let count = |evs: &[EngineEvent]| -> Vec<NoDirectPath> {
        evs.iter()
            .filter_map(|e| match e {
                EngineEvent::Unreachable { pair, diagnosis } if *pair == p => {
                    Some(diagnosis.reason)
                }
                _ => None,
            })
            .collect()
    };
    let evs = drain(&mut n.events).await;
    assert_eq!(
        count(&evs),
        vec![NoDirectPath::Unknown],
        "one event, not one per failure"
    );
    // причина сменилась: ровно одно новое событие
    apply_obs(&n, x, "5.6.7.1:4000", "9.9.9.9:1111");
    apply_obs(&n, y, "5.6.7.2:4000", "9.9.9.9:2222");
    n.engine.connect_now(&p).unwrap();
    tokio::time::sleep(secs(60)).await;
    let evs = drain(&mut n.events).await;
    assert_eq!(count(&evs), vec![NoDirectPath::SymmetricNat]);
    tokio::time::sleep(secs(600)).await;
    assert!(count(&drain(&mut n.events).await).is_empty());
}

#[tokio::test(start_paused = true)]
async fn diag_double_nat() {
    use super::fake_mapper::{FakeMapper, wait_until};
    use crate::DOUBLE_NAT_TEXT;
    use chervo_addr::{GatewayInfo, MapReport, MapStatus};

    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    // внешний адрес роутера частный: роутер сам за другим роутером
    let m = FakeMapper::new(|_, _| MapReport {
        status: MapStatus::DoubleNat,
        gateway: Some(GatewayInfo {
            wan_ip: Some("10.9.9.1".parse().unwrap()),
            mapping: None,
        }),
        retry_after: secs(1800),
    });
    n.engine.attach_mapper(m).unwrap();
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::DoubleNat)).await;
    assert_eq!(n.engine.nat_view(), NatView::DoubleNat);
    n.t.set_script(|_, _| Action::Fail(TransportError::NoResponse, secs(0)));
    let e = wait_event(&mut n.events, secs(130), unreachable_for(p))
        .await
        .unwrap();
    let EngineEvent::Unreachable { diagnosis, .. } = e else {
        panic!("not unreachable");
    };
    assert_eq!(diagnosis, diag(NoDirectPath::DoubleNat, true));
    assert_eq!(user_text(diagnosis.reason), DOUBLE_NAT_TEXT);
    assert_eq!(
        n.engine.diagnose(&p).unwrap().map(|d| d.reason),
        Some(NoDirectPath::DoubleNat)
    );
}

// ------------------------------------------------------------------ этап 13г: NoIpv6

fn node_v6_friend(local: Vec<SocketAddr>, route_v6: Option<&str>, friend: &str) -> (Node, PairId) {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv(friend)]);
    let t = FakeTransport::new();
    t.set_local(local);
    let probe = FakeProbe::new(Some("192.168.1.5"));
    probe.set_v6(route_v6);
    let n = Node::start_with(pre, ConnectConfig::default(), t, probe);
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    (n, p)
}

#[tokio::test(start_paused = true)]
async fn diag_no_ipv6_v4_only_transport() {
    // транспорт слушает только IPv4: маршрут IPv6 у системы есть, но пользоваться им нечем
    let (n, p) = node_v6_friend(
        vec![addr("0.0.0.0:4000")],
        Some("2a00:1450::5"),
        "[2606:4700::1]:4000",
    );
    tokio::time::sleep(secs(60)).await;
    assert_eq!(
        n.engine.diagnose(&p).unwrap(),
        Some(diag(NoDirectPath::NoIpv6, false))
    );
    assert!(n.t.calls_for(&p).is_empty(), "no IPv6 socket, no dial");
}

#[tokio::test(start_paused = true)]
async fn diag_no_ipv6_no_v6_egress() {
    // двойное гнездо есть, а собственного выхода в IPv6 нет: глобальный друг не набирается
    for route in [None, Some("fe80::1"), Some("2001:0:4136:e378::1")] {
        let (n, p) = node_v6_friend(
            vec![addr("0.0.0.0:4000"), addr("[::]:4000")],
            route,
            "[2606:4700::1]:4000",
        );
        tokio::time::sleep(secs(60)).await;
        assert_eq!(
            n.engine.diagnose(&p).unwrap(),
            Some(diag(NoDirectPath::NoIpv6, false)),
            "{route:?}"
        );
        assert!(
            n.t.calls_for(&p).is_empty(),
            "{route:?}: no egress, no dial"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn diag_not_no_ipv6_dual_with_egress() {
    for route in [Some("2a00:1450::5"), Some("fd00::5")] {
        let (n, p) = node_v6_friend(
            vec![addr("0.0.0.0:4000"), addr("[::]:4000")],
            route,
            "[2606:4700::1]:4000",
        );
        tokio::time::sleep(secs(60)).await;
        assert!(!n.t.calls_for(&p).is_empty(), "{route:?}: must dial");
        assert_ne!(
            n.engine.diagnose(&p).unwrap().map(|d| d.reason),
            Some(NoDirectPath::NoIpv6),
            "{route:?}"
        );
    }
}
