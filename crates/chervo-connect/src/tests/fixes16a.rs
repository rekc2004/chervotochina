//! Этап 16а, вызов 2: текущие наблюдения (F1), объявление смены внешнего адреса (F2),
//! сдвиг адреса друга (F3), адрес пути частного соединения (П2a), продление частных записей
//! живым соединением (П2c). Поддельный транспорт, приостановленное время.

use std::net::SocketAddr;

use chervo_addr::{AddrSource, LocalSnapshot, NatView, OwnAddrs, PublishCtx, RouteSources};
use chervo_identity::PairId;
use chervo_token::addr_flow::{PeerAddrInfo, encode_addr_info};
use chervo_token::{SignedAddrUpdate, decode_addr_update_bin};
use chervo_transport::{Connection, RecvStream, SendStream, TransportError, TransportEvent};
use tokio::time::Instant;

use super::kit::*;
use crate::{Clock, ConnectConfig, ConnectError, EngineEvent};

const X: &str = "9.9.9.9:4000";
const Y: &str = "8.8.8.8:4000";
const Z: &str = "9.9.9.8:4000";

/// Входящее соединение друга (мы не звоним, ADDR_INFO сами не начинаем).
fn live_in(n: &Node, pair: PairId, remote: &str) -> FakeConn {
    let c = FakeConn::lonely(pair, addr(remote), false);
    n.t.push_incoming(c.clone());
    c
}

/// Собеседник отвечает на ADDR_INFO кадром «вы выглядите как `seen_as`». Если IP совпадает с
/// IP соединения, наблюдение отвергается (`ReporterOwnIp`), и обмен тестовые наблюдения не меняет.
fn blind_peer(peer: FakeConn, seen_as: &str) {
    let frame = encode_addr_info(addr(seen_as), None).unwrap();
    tokio::spawn(async move {
        while let Ok((mut tx, mut rx)) = peer.accept_bi().await {
            let mut buf = [0u8; 64];
            while let Ok(Some(_)) = rx.read(&mut buf).await {}
            let _ = tx.write_all(&frame).await;
            let _ = tx.finish();
        }
    });
}

/// Живое входящее соединение с глухим собеседником (отвечает, наблюдений не вносит).
fn up(n: &Node, pair: PairId, remote_ip: &str) -> FakeConn {
    let c = live_in(n, pair, &format!("{remote_ip}:4000"));
    blind_peer(c.peer(), &format!("{remote_ip}:1"));
    c
}

fn reporters_up(n: &Node) -> usize {
    n.engine.inner.lock().own.reporters_up()
}

fn live_count(n: &Node) -> usize {
    n.engine.inner.lock().live.len()
}

fn own_changed(events: &[EngineEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, EngineEvent::OwnAddrsChanged))
        .count()
}

fn update_entries(n: &Node, pair: &PairId) -> Vec<(SocketAddr, bool)> {
    let mut v: Vec<(SocketAddr, bool)> = n.engine.read_book(|b| {
        b.get(pair)
            .unwrap()
            .known_addrs
            .iter()
            .filter(|k| k.source == AddrSource::AddressUpdate)
            .map(|k| (k.addr, k.hint))
            .collect()
    });
    v.sort();
    v
}

/// Подписанное обновление настоящего друга `pair` из книги `pre`.
fn issue_from(pre: &mut Pre, pair: &PairId, route: &str, unix: u64) -> SignedAddrUpdate {
    let mut own = OwnAddrs::new();
    own.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some(route.parse().unwrap()),
            v6: None,
        },
        listen: vec![addr("0.0.0.0:4000")],
    });
    let set = own.publishable(PublishCtx::default(), unix);
    let t = pre
        .book
        .issue_addr_update(&*pre.store, pair, &set, unix)
        .unwrap();
    decode_addr_update_bin(t.bytes()).unwrap()
}

fn is_unknown_or_eim(v: NatView) -> bool {
    matches!(v, NatView::Unknown | NatView::Eim)
}

// -------------------------------------------------------------------------- F1

#[tokio::test(start_paused = true)]
async fn c20_model_token_new_hint_only() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    // P: настоящий друг (с ним есть узел B, чтобы прочитать выпущенный токен)
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.3:4000")], vec![]);
    let w1 = pre_a.solo_friend(vec![inv("5.6.7.1:4000")]);
    let w2 = pre_a.solo_friend(vec![inv("5.6.7.2:4000")]);
    let a = Node::start(pre_a, ConnectConfig::default());
    let b = Node::start(pre_b, ConnectConfig::default());
    let c1 = up(&a, w1, "5.6.7.1");
    let c2 = up(&a, w2, "5.6.7.2");
    let c3 = up(&a, pa, "5.6.7.3");
    tokio::time::sleep(secs(1)).await;
    assert_eq!(reporters_up(&a), 3);
    // все трое сообщают X по живым соединениям
    apply_obs_live(&a, w1, "5.6.7.1:4000", X);
    apply_obs_live(&a, w2, "5.6.7.2:4000", X);
    apply_obs_live(&a, pa, "5.6.7.3:4000", X);
    assert_eq!(a.engine.nat_view(), NatView::Eim);
    // все соединения закрыты: отметки сняты, наблюдения остаются запасом по TTL
    for c in [&c1, &c2, &c3] {
        c.close();
    }
    tokio::time::sleep(secs(1)).await;
    assert_eq!(reporters_up(&a), 0);
    assert_eq!(a.engine.nat_view(), NatView::Eim);
    // W1 вернулся, но ещё ничего не сообщил: подсказка не пропадает (нет текущих наблюдений)
    let _c1b = up(&a, w1, "5.6.7.1");
    tokio::time::sleep(secs(1)).await;
    assert_eq!(reporters_up(&a), 1);
    assert_eq!(a.engine.nat_view(), NatView::Eim);
    // W1 сообщил Y: считается только оно
    apply_obs_live(&a, w1, "5.6.7.1:4000", Y);
    assert_ne!(a.engine.nat_view(), NatView::Conflicting);
    assert!(is_unknown_or_eim(a.engine.nat_view()));
    let text = a.engine.issue_addr_update_text(&pa, false).unwrap();
    b.engine.apply_addr_update_text(&text).unwrap();
    assert_eq!(update_entries(&b, &pb), vec![(addr(Y), true)]);
}

#[tokio::test(start_paused = true)]
async fn connected_liar_conflicting_no_addresses() {
    let mut pre = Pre::new();
    let honest = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let liar = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let _c1 = up(&n, honest, "5.6.7.1");
    let _c2 = up(&n, liar, "5.6.7.2");
    tokio::time::sleep(secs(1)).await;
    apply_obs_live(&n, honest, "5.6.7.1:4000", Y);
    apply_obs_live(&n, liar, "5.6.7.2:4000", Z);
    assert_eq!(n.engine.nat_view(), NatView::Conflicting);
    // маршрут частный, подсказки нет: адресов для токена нет
    assert_eq!(
        n.engine.issue_addr_update_text(&honest, false),
        Err(ConnectError::NoAddresses)
    );
}

#[tokio::test(start_paused = true)]
async fn observation_only_from_live_conn() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let n = Node::start(
        pre_a,
        ConnectConfig {
            manual_forward: Some(4000),
            ..ConnectConfig::default()
        },
    );
    let c1 = up(&n, pa, "5.6.7.8");
    tokio::time::sleep(secs(1)).await;
    // соединение заменено новым: старый обмен уже не от живого соединения
    let c2 = up(&n, pa, "5.6.7.8");
    tokio::time::sleep(secs(1)).await;
    let live_id = n.engine.connection(&pa).map(|c| c.conn_id());
    assert_eq!(live_id, Some(c2.conn_id()));
    assert_eq!(reporters_up(&n), 1);
    let upd = issue_from(&mut pre_b, &pb, "8.8.8.8", BASE_UNIX);
    {
        let now = Instant::now();
        let unix = n.clock.now_unix();
        let mut st = n.engine.inner.lock();
        n.engine.inner.apply_peer_info(
            &mut st,
            pa,
            c1.conn_id(),
            PeerAddrInfo {
                observed_me: addr(X),
                via: addr("5.6.7.8:4000"),
                update: Some(upd),
            },
            now,
            unix,
        );
    }
    assert_ne!(
        n.engine.nat_view(),
        NatView::ManualForward,
        "no observation"
    );
    // подписанное обновление применено независимо от соединения
    assert!(
        update_entries(&n, &pa)
            .iter()
            .any(|(a, _)| *a == addr("8.8.8.8:4000"))
    );
    apply_obs_on(&n, pa, c2.conn_id(), "5.6.7.8:4000", X);
    assert_eq!(n.engine.nat_view(), NatView::ManualForward);
}

#[tokio::test(start_paused = true)]
async fn reporter_marks_follow_live() {
    let mut pre = Pre::new();
    let ps: Vec<PairId> = (1..=4)
        .map(|i| pre.solo_friend(vec![inv(&format!("5.6.7.{i}:4000"))]))
        .collect();
    let n = Node::start(
        pre,
        ConnectConfig {
            max_live: 2,
            ..ConnectConfig::default()
        },
    );
    let check = |n: &Node, want: usize| {
        assert_eq!(live_count(n), want);
        assert_eq!(reporters_up(n), want);
    };
    let ca = up(&n, ps[0], "5.6.7.1");
    tokio::time::sleep(secs(1)).await;
    let _cb = up(&n, ps[1], "5.6.7.2");
    tokio::time::sleep(secs(1)).await;
    check(&n, 2);
    // закрытие
    ca.close();
    tokio::time::sleep(secs(1)).await;
    check(&n, 1);
    // предел: третье соединение вытесняет самое давнее (ps[1])
    let _cc = up(&n, ps[2], "5.6.7.3");
    tokio::time::sleep(secs(1)).await;
    check(&n, 2);
    let _cd = up(&n, ps[3], "5.6.7.4");
    tokio::time::sleep(secs(1)).await;
    check(&n, 2);
    assert!(n.engine.connection(&ps[1]).is_none(), "oldest evicted");
    // блокировка (cleanup_inactive)
    n.engine.update_book(|b, s| b.block(s, &ps[2])).unwrap();
    check(&n, 1);
    // остановка
    n.engine.shutdown();
    check(&n, 0);
}

// -------------------------------------------------------------------------- F2

#[tokio::test(start_paused = true)]
async fn ext_first_observation_silent() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c = up(&n, p, "5.6.7.1");
    tokio::time::sleep(secs(1)).await;
    let _ = drain(&mut n.events).await;
    apply_obs_live(&n, p, "5.6.7.1:4000", X);
    tokio::time::sleep(secs(40)).await;
    assert_eq!(n.t.reknock_count(), 0);
    assert_eq!(c.opened(), 0, "no ADDR_INFO for the baseline");
    assert_eq!(own_changed(&drain(&mut n.events).await), 0);
    // то же значение ещё раз: тоже молчание
    apply_obs_live(&n, p, "5.6.7.1:4000", X);
    tokio::time::sleep(secs(40)).await;
    assert_eq!(n.t.reknock_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn ext_change_announces_once() {
    let mut pre = Pre::new();
    let f1 = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let f2 = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c1 = up(&n, f1, "5.6.7.1");
    let c2 = up(&n, f2, "5.6.7.2");
    tokio::time::sleep(secs(1)).await;
    let both = |n: &Node, o: &str| {
        apply_obs_live(n, f1, "5.6.7.1:4000", o);
        apply_obs_live(n, f2, "5.6.7.2:4000", o);
    };
    let _ = drain(&mut n.events).await;
    // исходное значение X: молча
    both(&n, X);
    tokio::time::sleep(secs(3)).await;
    assert_eq!(n.engine.nat_view(), NatView::Eim);
    assert_eq!(n.t.reknock_count(), 0);
    assert_eq!(own_changed(&drain(&mut n.events).await), 0);
    // Y: ровно одно объявление
    both(&n, Y);
    tokio::time::sleep(secs(2)).await;
    assert_eq!(n.t.reknock_count(), 1);
    assert_eq!(c1.opened(), 1);
    assert_eq!(c2.opened(), 1);
    assert_eq!(own_changed(&drain(&mut n.events).await), 1);
    assert_eq!(reporters_up(&n), 2);
    assert_eq!(n.engine.nat_view(), NatView::Eim, "observations kept");
    // Z через 10 с после Y: до +30 с ничего
    tokio::time::sleep(secs(8)).await;
    both(&n, Z);
    tokio::time::sleep(secs(15)).await;
    assert_eq!(n.t.reknock_count(), 1, "inside the 30 s gap");
    assert_eq!(own_changed(&drain(&mut n.events).await), 0);
    // конец промежутка: ровно ещё одно объявление
    tokio::time::sleep(secs(10)).await;
    assert_eq!(n.t.reknock_count(), 2);
    assert_eq!(own_changed(&drain(&mut n.events).await), 1);
    assert_eq!(c1.opened(), 2);
    tokio::time::sleep(secs(60)).await;
    assert_eq!(n.t.reknock_count(), 2, "nothing more without a new change");
}

#[tokio::test(start_paused = true)]
async fn own_change_then_observation_announced() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let _c = up(&n, p, "5.6.7.1");
    tokio::time::sleep(secs(1)).await;
    apply_obs_live(&n, p, "5.6.7.1:4000", X);
    tokio::time::sleep(secs(3)).await;
    assert_eq!(n.t.reknock_count(), 0, "baseline is silent");
    let _ = drain(&mut n.events).await;
    // смена маршрута: собственное событие, одно объявление
    n.probe.set_v4(Some("10.0.0.7"));
    tokio::time::sleep(secs(3)).await;
    assert_eq!(n.t.reknock_count(), 1);
    assert_eq!(own_changed(&drain(&mut n.events).await), 1);
    // дальше такты смену маршрута второй раз не объявляют
    tokio::time::sleep(secs(5)).await;
    assert_eq!(n.t.reknock_count(), 1);
    assert_eq!(own_changed(&drain(&mut n.events).await), 0);
    // новое наблюдение в новой сети объявляется
    apply_obs_live(&n, p, "5.6.7.1:4000", Y);
    tokio::time::sleep(secs(3)).await;
    assert_eq!(n.t.reknock_count(), 2);
    assert_eq!(own_changed(&drain(&mut n.events).await), 1);
}

#[tokio::test(start_paused = true)]
async fn ext_route_change_not_announced_twice() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let mut n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    let _c = up(&n, p, "5.6.7.1");
    tokio::time::sleep(secs(5)).await;
    assert_eq!(n.t.reknock_count(), 0);
    let _ = drain(&mut n.events).await;
    // белый адрес сменился: набор публикации изменился вместе с маршрутом
    n.probe.set_v4(Some("7.7.7.9"));
    tokio::time::sleep(secs(10)).await;
    assert_eq!(n.t.reknock_count(), 1, "only the route-change announce");
    assert_eq!(own_changed(&drain(&mut n.events).await), 1);
}

#[tokio::test(start_paused = true)]
async fn ext_change_no_fast_window_no_limiter_reset() {
    // Лгущий друг переключает адрес каждые 15 с; контроль: то же без лжеца.
    async fn run(liar: bool) -> (usize, usize) {
        let mut pre = Pre::new();
        let l = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
        let v = pre.solo_friend(vec![inv("7.7.7.7:4000")]);
        let n = Node::start(pre, ConnectConfig::default());
        n.t.set_script(move |pair, _| {
            if *pair == v {
                Action::Fail(TransportError::TimedOut, secs(0))
            } else {
                Action::Hang
            }
        });
        let _c = up(&n, l, "5.6.7.1");
        // быстрое окно запуска прошло
        tokio::time::sleep(secs(130)).await;
        let before = n.t.calls_for(&v).len();
        for i in 0..40 {
            if liar {
                let o = if i % 2 == 0 { Y } else { Z };
                apply_obs_live(&n, l, "5.6.7.1:4000", o);
            }
            tokio::time::sleep(secs(15)).await;
            let st = n.engine.inner.lock();
            assert!(
                st.fast_global_until.is_none_or(|t| t <= Instant::now()),
                "no fast window from an external change"
            );
        }
        (n.t.reknock_count(), n.t.calls_for(&v).len() - before)
    }
    let (reknocks_ctl, dials_ctl) = run(false).await;
    let (reknocks, dials) = run(true).await;
    assert_eq!(reknocks_ctl, 0);
    assert!((1..=21).contains(&reknocks), "reknocks {reknocks}");
    assert!(dials_ctl > 0, "the control dials the victim address");
    assert_eq!(dials, dials_ctl, "backoff schedule unchanged by the liar");
}

// -------------------------------------------------------------------------- F3

#[tokio::test(start_paused = true)]
async fn remote_change_sends_addr_info() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("192.168.1.9:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let c = up(&n, p, "192.168.1.9");
    tokio::time::sleep(secs(1)).await;
    assert_eq!(c.opened(), 0);
    c.set_remote(addr("192.168.1.10:4000"));
    n.t.emit(TransportEvent::RemoteAddrChanged { pair: p });
    tokio::time::sleep(secs(2)).await;
    assert_eq!(c.opened(), 1, "one ADDR_INFO after the change");
    for i in 11..16 {
        c.set_remote(addr(&format!("192.168.1.{i}:4000")));
        n.t.emit(TransportEvent::RemoteAddrChanged { pair: p });
        tokio::time::sleep(secs(1)).await;
    }
    assert_eq!(c.opened(), 1, "at most one per 10 s");
    tokio::time::sleep(secs(6)).await;
    assert_eq!(c.opened(), 2, "the pending one goes out after the interval");
}

#[tokio::test(start_paused = true)]
async fn remote_change_not_own_event() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("192.168.1.9:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c = up(&n, p, "192.168.1.9");
    // быстрое окно запуска прошло
    tokio::time::sleep(secs(130)).await;
    let _ = drain(&mut n.events).await;
    c.set_remote(addr("192.168.1.10:4000"));
    n.t.emit(TransportEvent::RemoteAddrChanged { pair: p });
    tokio::time::sleep(secs(5)).await;
    assert_eq!(n.t.reknock_count(), 0);
    assert_eq!(own_changed(&drain(&mut n.events).await), 0);
    let st = n.engine.inner.lock();
    assert!(
        st.fast_global_until.is_none_or(|t| t <= Instant::now()),
        "no global fast window"
    );
    assert!(
        st.friends
            .get(&p)
            .is_none_or(|r| r.fast_until.is_none_or(|t| t <= Instant::now())),
        "no pair fast window"
    );
}

// ------------------------------------------------------------------------- П2a

/// A звонит B по частному пути; возвращает узлы, A-конец соединения и пары.
async fn private_path(
    probe: std::sync::Arc<FakeProbe>,
    a_sees_b: &str,
    b_sees_a: &str,
) -> (Node, Node, FakeConn, PairId) {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv(a_sees_b)], vec![]);
    let a = Node::start_with(pre_a, ConnectConfig::default(), FakeTransport::new(), probe);
    let b = Node::start(pre_b, ConnectConfig::default());
    let links = link_nodes(&a, pa, a_sees_b, &b, pb, b_sees_a);
    tokio::time::sleep(secs(4)).await;
    let conn_a = links.lock().unwrap()[0].0.clone();
    (a, b, conn_a, pb)
}

#[tokio::test(start_paused = true)]
async fn addrinfo_private_path_publishes_path_source() {
    let probe = FakeProbe::new(Some("192.168.1.5"));
    probe.set_source("10.99.0.2:4000", Some("10.99.0.1"));
    let (_a, b, conn_a, pb) = private_path(probe.clone(), "10.99.0.2:4000", "10.99.0.1:4000").await;
    assert_eq!(conn_a.opened(), 1);
    assert!(probe.source_calls() >= 1);
    // другу ушёл адрес именно этого пути, а не адрес маршрута по умолчанию
    assert_eq!(
        update_entries(&b, &pb),
        vec![(addr("10.99.0.1:4000"), false)]
    );
}

#[tokio::test(start_paused = true)]
async fn addrinfo_private_path_probe_none_no_private() {
    let probe = FakeProbe::new(Some("192.168.1.5"));
    let (a, b, conn_a, pb) = private_path(probe.clone(), "10.99.0.2:4000", "10.99.0.1:4000").await;
    assert_eq!(conn_a.opened(), 1, "the exchange happened");
    assert!(probe.source_calls() >= 1);
    assert!(update_entries(&b, &pb).is_empty(), "no private address");
    assert!(
        a.engine
            .read_book(|bk| bk.friends().iter().all(|f| f.addr_seq_out == 0)),
        "nothing to publish: no token issued"
    );
}

#[tokio::test(start_paused = true)]
async fn addrinfo_global_path_no_probe_call() {
    let probe = FakeProbe::new(Some("7.7.7.7"));
    probe.set_source("5.6.7.8:4000", Some("10.99.0.1"));
    let (_a, b, conn_a, pb) = private_path(probe.clone(), "5.6.7.8:4000", "7.7.7.7:4000").await;
    assert_eq!(conn_a.opened(), 1);
    assert_eq!(probe.source_calls(), 0, "no route probe for a global path");
    assert_eq!(update_entries(&b, &pb), vec![(addr("7.7.7.7:4000"), false)]);
}

#[tokio::test(start_paused = true)]
async fn manual_token_include_lan_unchanged() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![], vec![]);
    let probe = FakeProbe::new(Some("192.168.1.5"));
    probe.set_source("10.99.0.2:4000", Some("10.99.0.1"));
    let a = Node::start_with(
        pre_a,
        ConnectConfig::default(),
        FakeTransport::new(),
        probe.clone(),
    );
    let b = Node::start(pre_b, ConnectConfig::default());
    // выбор пользователя «в одной сети»: частный адрес маршрута по умолчанию, пробы нет
    let t = a.engine.issue_addr_update_text(&pa, true).unwrap();
    b.engine.apply_addr_update_text(&t).unwrap();
    assert_eq!(
        update_entries(&b, &pb),
        vec![(addr("192.168.1.5:4000"), false)]
    );
    assert_eq!(probe.source_calls(), 0);
}

// ------------------------------------------------------------------------- П2c

#[tokio::test(start_paused = true)]
async fn private_contact_refreshed_while_live() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("192.168.1.9:4000")]);
    let cfg = ConnectConfig {
        tick: secs(60),
        probe_interval: secs(3600),
        ..ConnectConfig::default()
    };
    let n = Node::start(pre, cfg);
    let c = live_in(&n, p, "192.168.1.9:4000");
    tokio::time::sleep(secs(25 * 3600)).await;
    let unix = n.clock.now_unix();
    let has = |source: AddrSource| {
        n.engine.read_book(|b| {
            b.usable_known(&p, unix)
                .iter()
                .any(|k| k.addr == addr("192.168.1.9:4000") && k.source == source)
        })
    };
    assert!(n.engine.connection(&p).is_some());
    assert!(has(AddrSource::Contact), "refreshed by the live connection");
    assert!(!has(AddrSource::Invite), "the invite entry expired");
    // соединение закрыто: без него запись живёт ещё 24 ч и пропадает
    c.close();
    tokio::time::sleep(secs(24 * 3600 + 120)).await;
    let unix = n.clock.now_unix();
    assert!(
        n.engine.read_book(|b| b.usable_known(&p, unix).is_empty()),
        "gone 24 h after the last refresh"
    );
}
