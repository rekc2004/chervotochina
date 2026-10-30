//! Этап 13г, круг 2 ревью: проба маршрута `RouteProbe::source_for` не вызывается под замком
//! состояния (решение 16а П2a), а адрес без ответа пробы не набирается.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chervo_addr::RouteSources;
use chervo_transport::TransportError;

use super::kit::*;
use crate::engine::{Engine, Inner};
use crate::{AllowSet, Clock, ConnectConfig, RouteProbe};

type Check = Box<dyn Fn() -> bool + Send + Sync>;

/// Проба-шпион: в `source_for` пытается взять замок состояния движка. Если замок занят (его
/// держит тот же или другой поток), вызов считается сделанным под замком.
struct LockSpy {
    inner: Arc<FakeProbe>,
    /// `true`, если замок свободен.
    check: Mutex<Option<Check>>,
    checked: AtomicUsize,
    under_lock: AtomicUsize,
}

impl RouteProbe for LockSpy {
    fn probe(&self) -> RouteSources {
        self.inner.probe()
    }

    fn source_for(&self, target: SocketAddr) -> Option<std::net::IpAddr> {
        if let Some(free) = self.check.lock().unwrap().as_ref() {
            self.checked.fetch_add(1, Ordering::SeqCst);
            if !free() {
                self.under_lock.fetch_add(1, Ordering::SeqCst);
            }
        }
        self.inner.source_for(target)
    }
}

#[tokio::test(start_paused = true)]
async fn route_probe_never_under_state_lock() {
    let mut pre = Pre::new();
    let target = "[2606:4700::1]:4000";
    let p = pre.solo_friend(vec![inv(target)]);
    let t = FakeTransport::new();
    t.set_local(vec![addr("0.0.0.0:4000"), addr("[::]:4000")]);
    let fake = FakeProbe::new(Some("192.168.1.5"));
    fake.set_v6(Some("2a00:1450::5"));
    fake.set_source(target, Some("2a00:1450::5"));
    let spy = Arc::new(LockSpy {
        inner: fake,
        check: Mutex::new(None),
        checked: AtomicUsize::new(0),
        under_lock: AtomicUsize::new(0),
    });
    let clock = TestClock::new();
    let c: Arc<dyn Clock> = clock.clone();
    let probe: Arc<dyn RouteProbe> = spy.clone();
    let (engine, _events) = Engine::start(
        t.clone(),
        AllowSet::new(),
        pre.book,
        pre.store.clone(),
        c,
        probe,
        ConnectConfig::default(),
    )
    .unwrap();
    let inner: Arc<Inner<FakeTransport, MemStore>> = engine.inner.clone();
    *spy.check.lock().unwrap() = Some(Box::new(move || inner.state.try_lock().is_ok()));
    t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    // такты планировщика, неудачные наборы (итог набора с диагнозом)
    tokio::time::sleep(secs(300)).await;
    assert!(!t.calls_for(&p).is_empty(), "IPv6 friend must be dialled");
    // публичный диагноз
    let _ = engine.diagnose(&p).unwrap();
    assert!(
        spy.checked.load(Ordering::SeqCst) > 0,
        "the probe was never called: the test checks nothing"
    );
    assert_eq!(
        spy.under_lock.load(Ordering::SeqCst),
        0,
        "source_for called under the state lock"
    );
}

#[tokio::test(start_paused = true)]
async fn route_no_answer_not_dialled() {
    // нет ответа пробы (маршрута к цели нет): IPv6-цель не набирается, IPv4 набирается
    let mut pre = Pre::new();
    let p = pre.solo_friend(vec![inv("[2606:4700::1]:4000"), inv("5.6.7.8:4000")]);
    let t = FakeTransport::new();
    t.set_local(vec![addr("0.0.0.0:4000"), addr("[::]:4000")]);
    let fake = FakeProbe::new(Some("192.168.1.5"));
    fake.set_v6(Some("2a00:1450::5"));
    let n = Node::start_with(pre, ConnectConfig::default(), t, fake);
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    tokio::time::sleep(secs(120)).await;
    let calls = n.t.calls_for(&p);
    assert!(!calls.is_empty());
    assert!(
        calls
            .iter()
            .all(|c| c.iter().all(|a| *a == addr("5.6.7.8:4000"))),
        "{calls:?}"
    );
}
