mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chervo_identity::{KxPeer, PairId};
use chervo_transport::{Connection, PeerAddr, Transport, TransportError};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use common::*;

/// N пар: (стороны звонящего, стороны вызываемого).
fn make_pairs(n: usize) -> (Vec<KxPeer>, Vec<KxPeer>) {
    let mut callers = Vec::new();
    let mut callees = Vec::new();
    for _ in 0..n {
        let (c, e) = make_pair();
        callers.push(c);
        callees.push(e);
    }
    (callers, callees)
}

fn flood_cfg(rate: u32, burst: u32, deadline: Duration) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: deadline,
        max_kk_trials: 1,
        kk_budget_per_sec: rate,
        kk_budget_burst: burst,
        max_preauth: 128,
        per_ip_max: 1_000_000,
        // предмет этих тестов: ворота KK как предохранитель для того, кто дошёл до KK
        // (стук проверяют тесты `knock`)
        knock_required: false,
        ..QuinnConfig::default()
    }
}

/// Одно соединение друга и время до готового соединения.
async fn timed_connect(
    t: &QuinnTransport,
    peer: &PeerAddr,
) -> (Result<(), TransportError>, Duration) {
    let start = Instant::now();
    let r = t.connect(peer).await;
    let d = start.elapsed();
    if let Ok(c) = &r {
        c.close();
    }
    (r.map(|_| ()), d)
}

/// Запускает `count` задач-незнакомцев, которые бесконечно звонят и получают отказ.
fn spawn_strangers(
    stranger: Arc<QuinnTransport>,
    target: PeerAddr,
    count: usize,
    stop: Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    (0..count)
        .map(|_| {
            let (t, target, stop) = (stranger.clone(), target.clone(), stop.clone());
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let _ = t.connect(&target).await;
                }
            })
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_admitted_under_strangers() {
    let n = 10;
    let (callers, callees) = make_pairs(n);
    let friend_pid = callers[6].pair();
    let cfg = QuinnConfig {
        max_preauth: 64,
        ..flood_cfg(1000, 200, Duration::from_secs(10))
    };
    let callee = bind(cfg, callees);
    let friend = bind(test_cfg(), callers);
    let friend_peer = peer_addr(friend_pid, &callee);

    // t0: медиана трёх соединений друга без нагрузки
    let mut t0s = Vec::new();
    for _ in 0..3 {
        let (r, d) = timed_connect(&friend, &friend_peer).await;
        r.unwrap();
        t0s.push(d);
    }
    let t0 = median(&mut t0s);

    // 20 незнакомцев параллельно, через 50 мс звонок друга
    let spid = PairId::generate().unwrap();
    let stranger = Arc::new(bind(test_cfg(), vec![stranger_peer(spid)]));
    let sp = peer_addr(spid, &callee);
    let mut strangers = Vec::new();
    for _ in 0..20 {
        let (t, p) = (stranger.clone(), sp.clone());
        strangers.push(tokio::spawn(async move { t.connect(&p).await.map(|_| ()) }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (r, actual) = timed_connect(&friend, &friend_peer).await;
    let x =
        Duration::from_secs_f64((20.0 * 10.0 - 200.0) / 1000.0) + 20 * t0 + Duration::from_secs(1);
    println!(
        "friend_admitted_under_strangers: X = {:.3} s, actual = {:.3} s, t0 = {:.3} s, result = {:?}",
        x.as_secs_f64(),
        actual.as_secs_f64(),
        t0.as_secs_f64(),
        r
    );
    r.unwrap();
    assert!(actual <= x, "друг ждал {actual:?} > X = {x:?}");
    for s in strangers {
        let r = s.await.unwrap();
        assert!(r.is_err(), "незнакомец не должен проходить");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_starved_documented() {
    // Остаток T9: под потоком незнакомцев, исчерпавших бюджет, друг отвергается.
    let n = 10;
    let (callers, callees) = make_pairs(n);
    let friend_pid = callers[3].pair();
    let cfg = flood_cfg(0, (10 * n) as u32, Duration::from_secs(3));
    let callee = bind(cfg, callees);
    let friend = bind(test_cfg(), callers);

    let spid = PairId::generate().unwrap();
    let stranger = Arc::new(bind(test_cfg(), vec![stranger_peer(spid)]));
    let sp = peer_addr(spid, &callee);
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (t, p) = (stranger.clone(), sp.clone());
        tasks.push(tokio::spawn(async move { t.connect(&p).await.map(|_| ()) }));
    }
    for t in tasks {
        assert!(t.await.unwrap().is_err());
    }
    // ведро пусто (10 незнакомцев по 10 кандидатов), пополнения нет
    let (r, _d) = timed_connect(&friend, &peer_addr(friend_pid, &callee)).await;
    println!(
        "friend_starved_documented: friend result = {r:?}, kk_denied = {}",
        callee.stats().kk_denied
    );
    assert!(
        matches!(
            r,
            Err(TransportError::AuthFailed) | Err(TransportError::TimedOut)
        ),
        "друг должен быть отвергнут: {r:?}"
    );
    assert!(callee.stats().kk_denied >= 1);
}

/// Замер времени соединения до готового, медиана из 20, на петле.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "замер; запускать в --release с --nocapture"]
async fn accept_cost_by_pairs() {
    println!(
        "accept_cost_by_pairs (мс, медиана из 20, петля, release): N пар у вызываемого -> время connect"
    );
    println!("N | median_ms | min_ms | max_ms");
    for n in [1usize, 10, 50, 200] {
        let (mut callers, callees) = make_pairs(n);
        let caller = callers.remove(n / 2);
        let pid = caller.pair();
        let cfg = QuinnConfig {
            per_ip_max: 1_000_000,
            ..QuinnConfig::default()
        };
        let callee = bind(cfg, callees);
        let a = bind(test_cfg(), vec![caller]);
        let peer = peer_addr(pid, &callee);
        // прогрев
        let (r, _) = timed_connect(&a, &peer).await;
        r.unwrap();
        let mut times = Vec::new();
        for _ in 0..20 {
            let (r, d) = timed_connect(&a, &peer).await;
            r.unwrap();
            times.push(d);
        }
        let med = median(&mut times);
        println!(
            "{n} | {:.2} | {:.2} | {:.2}",
            med.as_secs_f64() * 1e3,
            times[0].as_secs_f64() * 1e3,
            times[times.len() - 1].as_secs_f64() * 1e3
        );
    }
}

/// Задержка друга под потоком незнакомцев.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "замер; запускать в --release с --nocapture"]
async fn friend_latency_under_flood() {
    println!(
        "friend_latency_under_flood (release, петля; дедлайн 5 с; медиана из 5 соединений друга)"
    );
    println!(
        "N | strangers | rate=burst | friend_median_ms | friend_fail/5 | kk_denied/s | kk_candidates/s"
    );
    for n in [10usize, 50, 200] {
        for strangers in [0usize, 10, 50] {
            for rate in [500u32, 2000, 8000] {
                let (mut callers, callees) = make_pairs(n);
                let friend_peer_kx = callers.remove(n / 2);
                let friend_pid = friend_peer_kx.pair();
                let cfg = flood_cfg(rate, rate, Duration::from_secs(5));
                let callee = bind(cfg, callees);
                let friend = bind(test_cfg(), vec![friend_peer_kx]);
                let fpeer = peer_addr(friend_pid, &callee);

                let spid = PairId::generate().unwrap();
                let stranger = Arc::new(bind(test_cfg(), vec![stranger_peer(spid)]));
                let stop = Arc::new(AtomicBool::new(false));
                let tasks =
                    spawn_strangers(stranger, peer_addr(spid, &callee), strangers, stop.clone());
                tokio::time::sleep(Duration::from_millis(500)).await;

                let s0 = callee.stats();
                let t_start = Instant::now();
                let mut times = Vec::new();
                let mut fails = 0;
                for _ in 0..5 {
                    let (r, d) = timed_connect(&friend, &fpeer).await;
                    match r {
                        Ok(()) => times.push(d),
                        Err(_) => fails += 1,
                    }
                }
                let el = t_start.elapsed().as_secs_f64();
                let s1 = callee.stats();
                stop.store(true, Ordering::Relaxed);
                for t in &tasks {
                    t.abort();
                }
                let med = if times.is_empty() {
                    "-".to_string()
                } else {
                    format!("{:.1}", median(&mut times).as_secs_f64() * 1e3)
                };
                println!(
                    "{n} | {strangers} | {rate} | {med} | {fails} | {:.1} | {:.0}",
                    (s1.kk_denied - s0.kk_denied) as f64 / el,
                    (s1.kk_candidates - s0.kk_candidates) as f64 / el
                );
            }
        }
    }
}
