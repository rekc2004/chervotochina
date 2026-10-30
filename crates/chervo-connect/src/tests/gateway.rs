//! Задача проброса порта: вызовы отображателя, применение итога, устаревшие итоги, таймаут.
//! Время приостановлено; отображатель поддельный (сети нет).

use std::net::SocketAddrV4;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};

use chervo_addr::{GatewayInfo, MapReport, MapStatus, NatView};

use super::fake_mapper::*;
use super::kit::*;
use crate::{ConnectConfig, ConnectError, EngineEvent};

fn mapping_events(evs: &[EngineEvent]) -> Vec<MapStatus> {
    evs.iter()
        .filter_map(|e| match e {
            EngineEvent::MappingChanged { status } => Some(*status),
            _ => None,
        })
        .collect()
}

fn private_node() -> Node {
    let mut pre = Pre::new();
    pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    Node::start(pre, ConnectConfig::default())
}

#[tokio::test(start_paused = true)]
async fn mapper_not_called_without_attach() {
    let mut n = private_node();
    tokio::time::sleep(secs(30)).await;
    n.probe.set_v4(Some("10.0.0.2"));
    tokio::time::sleep(secs(30)).await;
    n.engine.refresh_mapping();
    tokio::time::sleep(secs(30)).await;
    assert_eq!(n.engine.mapping_status(), None);
    assert!(mapping_events(&drain(&mut n.events).await).is_empty());
}

#[tokio::test(start_paused = true)]
async fn mapper_called_on_attach_private_route_only() {
    let n = private_node();
    let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 1800));
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| n.engine.mapping_status().is_some()).await;
    assert_eq!(m.call_count(), 1);
    assert_eq!(m.call(0).internal, "192.168.1.5:4000".parse().unwrap());
    assert_eq!(n.engine.mapping_status(), Some(MapStatus::Mapped));
    assert_eq!(n.engine.nat_view(), NatView::PortMapped);
}

#[tokio::test(start_paused = true)]
async fn mapper_skipped_on_public_or_cgnat_route() {
    for v4 in [Some("7.7.7.7"), Some("100.64.0.9"), Some("127.0.0.1"), None] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            FakeTransport::new(),
            FakeProbe::new(v4),
        );
        let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 60));
        n.engine.attach_mapper(m.clone()).unwrap();
        tokio::time::sleep(secs(300)).await;
        assert_eq!(m.call_count(), 0, "{v4:?}");
        assert_eq!(m.release_count(), 0, "{v4:?}");
        assert_eq!(n.engine.mapping_status(), None, "{v4:?}");
    }
    // частный маршрут, но порт прослушивания IPv4 не известен: тоже нет вызова
    for local in [vec![addr("0.0.0.0:0")], vec![addr("[::]:4000")], vec![]] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let t = FakeTransport::new();
        t.set_local(local.clone());
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            t,
            FakeProbe::new(Some("192.168.1.5")),
        );
        let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 60));
        n.engine.attach_mapper(m.clone()).unwrap();
        tokio::time::sleep(secs(300)).await;
        assert_eq!(m.call_count(), 0, "{local:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn mapper_result_sets_gateway_and_resends_addr_info() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let mut a = Node::start(pre_a, ConnectConfig::default());
    let b = Node::start(pre_b, ConnectConfig::default());
    let links = link_nodes(&a, pa, "5.6.7.8:4000", &b, pb, "7.7.7.7:4000");
    // первый вызов: проброса нет; второй и дальше: подтверждённый проброс
    let m = FakeMapper::new(|n, _| {
        if n == 0 {
            plain(MapStatus::Failed, 30)
        } else {
            mapped("9.9.9.9", 4000, 30)
        }
    });
    a.engine.attach_mapper(m.clone()).unwrap();
    tokio::time::sleep(secs(3)).await;
    wait_until(|| m.call_count() >= 1).await;
    let conn_a = links.lock().unwrap()[0].0.clone();
    assert_eq!(conn_a.opened(), 1, "first exchange right after connect");
    assert_eq!(a.engine.nat_view(), NatView::Unknown);
    let _ = drain(&mut a.events).await;

    // проброс подтверждён: публикуемый набор изменился, ADDR_INFO уходит снова
    wait_until(|| a.engine.mapping_status() == Some(MapStatus::Failed)).await;
    tokio::time::sleep(secs(31)).await;
    wait_until(|| a.engine.mapping_status() == Some(MapStatus::Mapped)).await;
    assert_eq!(a.engine.nat_view(), NatView::PortMapped);
    let evs = drain(&mut a.events).await;
    assert!(evs.contains(&EngineEvent::OwnAddrsChanged));
    assert_eq!(mapping_events(&evs), vec![MapStatus::Mapped]);
    tokio::time::sleep(secs(12)).await;
    assert_eq!(conn_a.opened(), 2, "re-send after the publish set changed");
    // повторный такой же итог: набор не меняется, нового обмена нет
    tokio::time::sleep(secs(100)).await;
    assert!(m.call_count() >= 3);
    assert_eq!(conn_a.opened(), 2);
    assert!(
        !drain(&mut a.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
    // подтверждённый проброс меняет объявляемый глобальный набор, поэтому F2 объявляет это
    // один раз (повторный стук + ADDR_INFO + `OwnAddrsChanged`); быстрого окна и сброса
    // ограничителя нет: проброс не новая сеть
    assert_eq!(a.t.reknock_count(), 1);
    let st = a.engine.inner.lock();
    assert!(
        st.fast_global_until
            .is_none_or(|t| t <= tokio::time::Instant::now()),
        "no fast window from the mapping announce"
    );
}

#[tokio::test(start_paused = true)]
async fn mapper_stale_result_ignored_after_network_change() {
    let mut n = private_node();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate_rx = Mutex::new(gate_rx);
    let m = FakeMapper::new(move |i, _| {
        if i == 0 {
            // первый вызов держится, пока тест не сменит сеть
            let _ = gate_rx.lock().unwrap().recv();
            mapped("9.9.9.9", 4000, 1800)
        } else {
            plain(MapStatus::Failed, 600)
        }
    });
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| m.call_count() == 1).await;
    n.probe.set_v4(Some("10.0.0.7"));
    advance(secs(3)).await;
    assert!(
        drain(&mut n.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
    // итог для старой сети приходит после смены сети и выбрасывается целиком
    gate_tx.send(()).unwrap();
    wait_until(|| m.call_count() == 2).await;
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::Failed)).await;
    assert_eq!(m.call(1).internal, "10.0.0.7:4000".parse().unwrap());
    assert_ne!(n.engine.nat_view(), NatView::PortMapped);
    // устаревший итог не оставил событий: только итог новой сети
    assert_eq!(
        mapping_events(&drain(&mut n.events).await),
        vec![MapStatus::Failed]
    );
}

#[tokio::test(start_paused = true)]
async fn mapper_renew_at_retry_after() {
    let n = private_node();
    let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 100));
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| n.engine.mapping_status().is_some()).await;
    assert_eq!(m.call_count(), 1);
    tokio::time::sleep(secs(99)).await;
    assert_eq!(m.call_count(), 1, "not before retry_after");
    tokio::time::sleep(secs(2)).await;
    wait_until(|| m.call_count() == 2).await;
    wait_until(|| m.max_concurrent.load(Ordering::SeqCst) >= 1).await;
    // следующий срок отсчитывается от конца второго вызова
    tokio::time::sleep(secs(99)).await;
    assert_eq!(m.call_count(), 2);
    tokio::time::sleep(secs(2)).await;
    wait_until(|| m.call_count() == 3).await;
}

#[tokio::test(start_paused = true)]
async fn mapper_rerun_on_own_change() {
    let n = private_node();
    let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 1800));
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| m.call_count() == 1).await;
    n.probe.set_v4(Some("10.1.1.1"));
    tokio::time::sleep(secs(3)).await;
    wait_until(|| m.call_count() == 2).await;
    assert_eq!(m.call(1).internal, "10.1.1.1:4000".parse().unwrap());
    // смена порта прослушивания тоже
    n.t.set_local(vec![addr("0.0.0.0:5000")]);
    tokio::time::sleep(secs(3)).await;
    wait_until(|| m.call_count() == 3).await;
    assert_eq!(m.call(2).internal, "10.1.1.1:5000".parse().unwrap());
    // действие пользователя
    n.engine.refresh_mapping();
    wait_until(|| m.call_count() == 4).await;
    assert_eq!(m.call(3).internal, "10.1.1.1:5000".parse().unwrap());
}

#[tokio::test(start_paused = true)]
async fn mapper_release_when_route_not_private() {
    let mut n = private_node();
    let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 1800));
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::Mapped)).await;
    assert_eq!(m.release_count(), 0);
    n.probe.set_v4(Some("7.7.7.7"));
    tokio::time::sleep(secs(3)).await;
    wait_until(|| m.release_count() == 1).await;
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::Off)).await;
    assert_eq!(n.engine.nat_view(), NatView::Public);
    // дальнейшие смены без частного маршрута освобождение не повторяют
    n.probe.set_v4(None);
    tokio::time::sleep(secs(30)).await;
    n.probe.set_v4(Some("100.64.1.1"));
    tokio::time::sleep(secs(30)).await;
    assert_eq!(m.release_count(), 1);
    assert_eq!(m.call_count(), 1);
    // частный маршрут вернулся: новый вызов
    n.probe.set_v4(Some("192.168.1.5"));
    tokio::time::sleep(secs(3)).await;
    wait_until(|| m.call_count() == 2).await;
    assert_eq!(
        mapping_events(&drain(&mut n.events).await),
        vec![MapStatus::Mapped, MapStatus::Off, MapStatus::Mapped]
    );
}

#[tokio::test(start_paused = true)]
async fn mapper_timeout_abandons_and_retries() {
    let n = private_node();
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate_rx = Mutex::new(gate_rx);
    let m = FakeMapper::new(move |i, _| {
        if i == 0 {
            // отображатель завис: брошенный поток выйдет, когда тест уронит отправителя
            let _ = gate_rx.lock().unwrap().recv();
            mapped("9.9.9.9", 4000, 1800)
        } else {
            mapped("9.9.9.9", 4000, 1800)
        }
    });
    n.engine.attach_mapper(m.clone()).unwrap();
    wait_until(|| m.call_count() == 1).await;
    advance(secs(29)).await;
    assert_eq!(n.engine.mapping_status(), None, "not before 25 s + 5 s");
    advance(secs(2)).await;
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::Failed)).await;
    assert_eq!(n.engine.nat_view(), NatView::Unknown);
    // повтор через 60 с
    advance(secs(59)).await;
    assert_eq!(m.call_count(), 1);
    advance(secs(2)).await;
    wait_until(|| n.engine.mapping_status() == Some(MapStatus::Mapped)).await;
    assert_eq!(m.call_count(), 2);
    drop(gate_tx);
}

#[tokio::test(start_paused = true)]
async fn mapper_never_concurrent() {
    let n = private_node();
    let m = FakeMapper::new(|_, _| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        mapped("9.9.9.9", 4000, 1)
    });
    n.engine.attach_mapper(m.clone()).unwrap();
    for i in 0..8 {
        n.engine.refresh_mapping();
        n.probe
            .set_v4(Some(if i % 2 == 0 { "10.0.0.3" } else { "10.0.0.4" }));
        tokio::time::sleep(secs(2)).await;
    }
    wait_until(|| m.call_count() >= 4).await;
    assert_eq!(m.max_concurrent.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn attach_twice_rejected() {
    let n = private_node();
    let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 1800));
    n.engine.attach_mapper(m.clone()).unwrap();
    let other = FakeMapper::new(|_, _| mapped("9.9.9.9", 4000, 1800));
    assert_eq!(
        n.engine.attach_mapper(other.clone()),
        Err(ConnectError::Internal)
    );
    wait_until(|| m.call_count() == 1).await;
    tokio::time::sleep(secs(60)).await;
    assert_eq!(other.call_count(), 0);
    assert_eq!(m.call_count(), 1);
    n.engine.shutdown();
    assert_eq!(
        n.engine.attach_mapper(other.clone()),
        Err(ConnectError::Shutdown)
    );
}

#[tokio::test(start_paused = true)]
async fn mapping_changed_event_once_per_status() {
    let mut n = private_node();
    let gw = Arc::new(Mutex::new(0usize));
    let seen = gw.clone();
    let m = FakeMapper::new(move |i, _| {
        *seen.lock().unwrap() = i;
        match i {
            0..=2 => mapped("9.9.9.9", 4000, 10),
            3 => plain(MapStatus::Failed, 10),
            4 => MapReport {
                status: MapStatus::DoubleNat,
                gateway: Some(GatewayInfo {
                    wan_ip: Some("10.9.9.1".parse().unwrap()),
                    mapping: None::<SocketAddrV4>,
                }),
                retry_after: secs(10),
            },
            _ => mapped("9.9.9.9", 4000, 10),
        }
    });
    n.engine.attach_mapper(m.clone()).unwrap();
    for want in 1..=6 {
        wait_until(|| m.call_count() >= want).await;
        wait_until(|| *gw.lock().unwrap() + 1 >= want).await;
        tokio::time::sleep(secs(11)).await;
    }
    assert_eq!(
        mapping_events(&drain(&mut n.events).await),
        vec![
            MapStatus::Mapped,
            MapStatus::Failed,
            MapStatus::DoubleNat,
            MapStatus::Mapped
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn gateway_request_dual_listen() {
    // двойное гнездо: запрос проброса берёт порт из записи IPv4, IPv6 в запросе не участвует
    for local in [
        vec![addr("0.0.0.0:4321"), addr("[::]:4321")],
        vec![addr("[::]:4321"), addr("0.0.0.0:4321")],
    ] {
        let mut pre = Pre::new();
        pre.solo_friend(vec![inv("5.6.7.8:4000")]);
        let t = FakeTransport::new();
        t.set_local(local.clone());
        let n = Node::start_with(
            pre,
            ConnectConfig::default(),
            t,
            FakeProbe::new(Some("192.168.1.5")),
        );
        let m = FakeMapper::new(|_, _| mapped("9.9.9.9", 4321, 1800));
        n.engine.attach_mapper(m.clone()).unwrap();
        wait_until(|| n.engine.mapping_status().is_some()).await;
        assert_eq!(m.call_count(), 1, "{local:?}");
        assert_eq!(m.call(0).internal, "192.168.1.5:4321".parse().unwrap());
    }
}
