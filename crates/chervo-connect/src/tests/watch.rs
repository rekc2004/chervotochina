//! Слежение за собственными адресами.

use chervo_transport::TransportError;

use super::kit::*;
use crate::{ConnectConfig, EngineEvent};

#[tokio::test(start_paused = true)]
async fn watch_first_snapshot_no_reknock() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    tokio::time::sleep(secs(1)).await;
    assert_eq!(n.t.reknock_count(), 0);
    tokio::time::sleep(secs(10)).await;
    assert_eq!(n.t.reknock_count(), 0);
    assert!(
        !drain(&mut n.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
}

#[tokio::test(start_paused = true)]
async fn watch_no_change_no_reknock() {
    let mut pre = Pre::new();
    pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    for _ in 0..10 {
        tokio::time::sleep(secs(3)).await;
        // то же значение: изменением не считается
        n.probe.set_v4(Some("192.168.1.5"));
    }
    assert_eq!(n.t.reknock_count(), 0);
    assert!(
        !drain(&mut n.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
    // изменённый порядок адресов прослушивания не изменение
    n.t.set_local(vec![addr("0.0.0.0:4000")]);
    tokio::time::sleep(secs(5)).await;
    assert_eq!(n.t.reknock_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn watch_change_reknocks_once_and_fast_window() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    // быстрое окно запуска прошло, интервалы выросли
    tokio::time::sleep(secs(300)).await;
    {
        let st = n.engine.inner.lock();
        assert!(
            st.fast_global_until
                .is_none_or(|t| t <= tokio::time::Instant::now())
        );
    }
    let before = n.t.calls_for(&p).len();
    let (_, wait) = n
        .engine
        .inner
        .lock()
        .limiter
        .entry_state(addr("5.6.7.8:4000"), tokio::time::Instant::now())
        .unwrap();
    assert!(wait > secs(100), "backoff must have grown: {wait:?}");

    n.probe.set_v4(Some("7.7.7.7"));
    tokio::time::sleep(secs(3)).await;
    assert_eq!(n.t.reknock_count(), 1);
    assert!(
        drain(&mut n.events)
            .await
            .contains(&EngineEvent::OwnAddrsChanged)
    );
    // ограничитель сброшен, окно быстрое: набор сразу и затем каждые ~5 с
    assert!(n.t.calls_for(&p).len() > before);
    tokio::time::sleep(secs(40)).await;
    assert!(
        n.t.calls_for(&p).len() >= before + 6,
        "fast redials expected"
    );
    // без нового изменения повторного стука нет
    assert_eq!(n.t.reknock_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn watch_change_resends_addr_info_rate_limited() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let a = Node::start_with(
        pre_a,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    let b = Node::start(pre_b, ConnectConfig::default());
    let links = link_nodes(&a, pa, "5.6.7.8:4000", &b, pb, "7.7.7.7:4000");
    tokio::time::sleep(secs(3)).await;
    let conn_a = links.lock().unwrap()[0].0.clone();
    assert_eq!(conn_a.opened(), 1, "first exchange right after connect");
    // смена адреса меньше чем через 10 с после прошлой отправки: повтор откладывается
    a.probe.set_v4(Some("7.7.7.9"));
    tokio::time::sleep(secs(4)).await;
    assert_eq!(a.t.reknock_count(), 1);
    assert_eq!(
        conn_a.opened(),
        1,
        "re-send must wait for the 10 s interval"
    );
    tokio::time::sleep(secs(6)).await;
    assert_eq!(conn_a.opened(), 2, "re-send after the interval");
}
