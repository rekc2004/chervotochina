//! Движок: единый набор на пару, соединения, события транспорта, следит за пределами.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use chervo_identity::PairId;
use chervo_transport::{Connection, TransportError, TransportEvent};

use super::kit::*;
use crate::{ConnectConfig, EngineEvent};

fn fail_script() -> impl FnMut(&PairId, &[SocketAddr]) -> Action + Send + 'static {
    |_, _| Action::Fail(TransportError::TimedOut, secs(0))
}

#[tokio::test(start_paused = true)]
async fn single_flight_per_pair() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(30)));
    tokio::time::sleep(secs(300)).await;
    assert!(n.t.calls_for(&p).len() >= 2);
    assert_eq!(n.t.max_pair.load(std::sync::atomic::Ordering::SeqCst), 1);
    let evs = drain(&mut n.events).await;
    assert!(!evs.contains(&EngineEvent::Internal));
}

#[tokio::test(start_paused = true)]
async fn no_dial_when_live() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(move |_, _| {
        Action::Ok(FakeConn::lonely(p, addr("5.6.7.8:4000"), true), secs(0))
    });
    let e = wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await;
    assert!(e.is_some());
    tokio::time::sleep(secs(300)).await;
    assert_eq!(n.t.call_count(), 1);
    assert!(n.engine.connection(&p).is_some());
}

#[tokio::test(start_paused = true)]
async fn max_concurrent_dials_respected() {
    let mut pre = Pre::new();
    let pairs: Vec<PairId> = (1..=8)
        .map(|i| pre.solo_friend(vec![inv(&format!("5.6.7.{i}:4000"))]))
        .collect();
    let cfg = ConnectConfig {
        max_concurrent_dials: 3,
        ..ConnectConfig::default()
    };
    let n = Node::start(pre, cfg);
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(20)));
    tokio::time::sleep(secs(300)).await;
    assert!(n.t.max_total.load(std::sync::atomic::Ordering::SeqCst) <= 3);
    // никто не голодает: каждой паре хоть раз звонили
    for p in &pairs {
        assert!(!n.t.calls_for(p).is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn dial_targets_only_from_book_or_token() {
    let mut pre = Pre::new();
    let f1_addrs = [
        known("5.6.7.1:4000", chervo_addr::AddrSource::Invite, false),
        known("5.6.7.2:4000", chervo_addr::AddrSource::AddressUpdate, true),
    ];
    let f1 = pre.solo_friend(f1_addrs.to_vec());
    let f2 = pre.solo_friend(vec![inv("6.6.6.1:4000")]);
    let n = Node::start_with(
        pre,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    n.t.set_script(fail_script());
    let guest = PairId::from_bytes([0x66; 16]);
    let token = vec![addr("8.8.8.8:1")];
    n.engine
        .add_guest(guest, token.clone(), Box::new(|| None))
        .unwrap();
    tokio::time::sleep(secs(600)).await;
    let own: HashSet<SocketAddr> = [addr("7.7.7.7:4000"), addr("0.0.0.0:4000")].into();
    let sets: Vec<(PairId, HashSet<SocketAddr>)> = vec![
        (f1, f1_addrs.iter().map(|k| k.addr).collect()),
        (f2, [addr("6.6.6.1:4000")].into()),
        (guest, token.into_iter().collect()),
    ];
    for (pair, allowed) in &sets {
        let calls = n.t.calls_for(pair);
        assert!(!calls.is_empty());
        for c in calls {
            for a in c {
                assert!(allowed.contains(&a), "address outside the book/token");
                assert!(!own.contains(&a));
                for (other, other_set) in &sets {
                    if other != pair {
                        assert!(!other_set.contains(&a));
                    }
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn dedupe_by_conn_id() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let made: Arc<Mutex<Vec<FakeConn>>> = Arc::new(Mutex::new(Vec::new()));
    let m = made.clone();
    n.t.set_script(move |_, _| {
        let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), true);
        m.lock().unwrap().push(c.clone());
        Action::Ok(c, secs(2))
    });
    tokio::time::sleep(secs(1)).await;
    // то же соединение приходит и через accept (путь `Lost` / дубль)
    let dial_done = wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await;
    assert!(dial_done.is_some());
    let c = made.lock().unwrap()[0].clone();
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(5)).await;
    let rest = drain(&mut n.events).await;
    assert!(
        !rest
            .iter()
            .any(|e| matches!(e, EngineEvent::Connected { .. }))
    );
    assert_eq!(n.engine.connection(&p).unwrap().conn_id(), c.conn_id());
    assert!(!c.is_closed());
}

#[tokio::test(start_paused = true)]
async fn replaced_conn_switches_entry() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c1 = FakeConn::lonely(p, addr("5.6.7.8:4000"), true);
    let c1c = c1.clone();
    let mut first = true;
    n.t.set_script(move |_, _| {
        if std::mem::take(&mut first) {
            Action::Ok(c1c.clone(), secs(0))
        } else {
            Action::Hang
        }
    });
    wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await
    .unwrap();
    let c2 = FakeConn::lonely(p, addr("5.6.7.8:4001"), false);
    n.t.push_incoming(c2.clone());
    wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await
    .unwrap();
    assert_eq!(n.engine.connection(&p).unwrap().conn_id(), c2.conn_id());
    // закрытие вытесненного соединения запись не трогает
    c1.close();
    tokio::time::sleep(secs(2)).await;
    assert_eq!(n.engine.connection(&p).unwrap().conn_id(), c2.conn_id());
    assert!(
        !drain(&mut n.events)
            .await
            .iter()
            .any(|e| matches!(e, EngineEvent::Disconnected { .. }))
    );
    // закрытие текущего снимает запись
    c2.close();
    let gone = wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Disconnected { .. })
    })
    .await;
    assert!(gone.is_some());
    assert!(n.engine.connection(&p).is_none());
}

#[tokio::test(start_paused = true)]
async fn peer_removed_drops_conn() {
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(p, addr("5.6.7.8:4000"), true);
    let cc = c.clone();
    let mut first = true;
    n.t.set_script(move |_, _| {
        if std::mem::take(&mut first) {
            Action::Ok(cc.clone(), secs(0))
        } else {
            Action::Hang
        }
    });
    wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Connected { .. })
    })
    .await
    .unwrap();
    // как в настоящем транспорте: событие, затем закрытие соединения
    n.t.events_tx
        .send(TransportEvent::PeerRemoved { pair: p })
        .unwrap();
    c.close();
    let gone = wait_event(&mut n.events, secs(5), |e| {
        matches!(e, EngineEvent::Disconnected { .. })
    })
    .await;
    assert!(gone.is_some());
    assert!(n.engine.connection(&p).is_none());
}

#[tokio::test(start_paused = true)]
async fn max_live_closes_oldest() {
    let mut pre = Pre::new();
    let ps: Vec<PairId> = (1..=3)
        .map(|i| pre.solo_friend(vec![inv(&format!("5.6.7.{i}:4000"))]))
        .collect();
    let cfg = ConnectConfig {
        max_live: 2,
        ..ConnectConfig::default()
    };
    let mut n = Node::start(pre, cfg);
    let conns: Vec<FakeConn> = ps
        .iter()
        .enumerate()
        .map(|(i, p)| FakeConn::lonely(*p, addr(&format!("5.6.7.{}:4000", i + 1)), false))
        .collect();
    for c in &conns {
        n.t.push_incoming(c.clone());
        tokio::time::sleep(secs(1)).await;
    }
    tokio::time::sleep(secs(1)).await;
    assert!(conns[0].is_closed());
    assert!(!conns[1].is_closed());
    assert!(!conns[2].is_closed());
    assert!(n.engine.connection(&ps[0]).is_none());
    assert!(n.engine.connection(&ps[1]).is_some());
    assert!(n.engine.connection(&ps[2]).is_some());
    let evs = drain(&mut n.events).await;
    assert!(evs.contains(&EngineEvent::Disconnected { pair: ps[0] }));
}

#[tokio::test(start_paused = true)]
async fn connect_now_errors_and_redials_soon() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let y = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    pre.book.block(&*pre.store, &y).unwrap();
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(fail_script());
    assert_eq!(
        n.engine.connect_now(&PairId::from_bytes([9; 16])),
        Err(crate::ConnectError::UnknownPair)
    );
    assert_eq!(
        n.engine.connect_now(&y),
        Err(crate::ConnectError::NotActive)
    );
    // быстрое окно запуска прошло, интервал вырос до предела
    tokio::time::sleep(secs(400)).await;
    let before = n.t.calls_for(&x).len();
    tokio::time::sleep(secs(30)).await;
    assert_eq!(n.t.calls_for(&x).len(), before, "backoff holds");
    n.engine.connect_now(&x).unwrap();
    tokio::time::sleep(secs(3)).await;
    assert!(
        n.t.calls_for(&x).len() > before,
        "connect_now dials at once"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_everything() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    let c = FakeConn::lonely(x, addr("5.6.7.1:4000"), false);
    n.t.push_incoming(c.clone());
    tokio::time::sleep(secs(2)).await;
    assert!(n.engine.connection(&x).is_some());
    n.engine.shutdown();
    assert!(c.is_closed());
    assert!(n.engine.connection(&x).is_none());
    let calls = n.t.call_count();
    tokio::time::sleep(secs(300)).await;
    assert_eq!(n.t.call_count(), calls);
    assert_eq!(n.engine.connect_now(&x), Err(crate::ConnectError::Shutdown));
    assert_eq!(
        n.engine.update_book(|_, _| Ok(())).unwrap_err(),
        crate::ConnectError::Shutdown
    );
}

#[test]
fn start_requires_runtime() {
    let pre = Pre::new();
    let clock: Arc<dyn crate::Clock> = Arc::new(FixedClock);
    let probe: Arc<dyn crate::RouteProbe> = FakeProbe::new(Some("192.168.1.5"));
    let r = crate::Engine::start(
        FakeTransport::new(),
        crate::AllowSet::new(),
        pre.book,
        pre.store,
        clock,
        probe,
        ConnectConfig::default(),
    );
    assert_eq!(r.err(), Some(crate::ConnectError::Internal));
}

struct FixedClock;

impl crate::Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        BASE_UNIX
    }
}
