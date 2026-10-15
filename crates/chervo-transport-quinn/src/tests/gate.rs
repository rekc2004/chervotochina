//! Ворота перебора KK и лимитер по IP.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use tokio::time::Instant;

use crate::QuinnConfig;
use crate::limits::{Counters, GateError, IpLimiter, KkGate};

fn gate_cfg(trials: usize, rate: u32, burst: u32) -> QuinnConfig {
    QuinnConfig {
        max_kk_trials: trials,
        kk_budget_per_sec: rate,
        kk_budget_burst: burst,
        max_preauth: 32,
        ..QuinnConfig::default()
    }
}

fn gate(cfg: &QuinnConfig) -> (Arc<KkGate>, Arc<Counters>) {
    let counters = Arc::new(Counters::default());
    (Arc::new(KkGate::new(cfg, counters.clone())), counters)
}

async fn wait_until(mut f: impl FnMut() -> bool, ms: u64) -> bool {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kk_gate_serializes() {
    let (g, c) = gate(&gate_cfg(1, 1000, 1000));
    let deadline = Instant::now() + Duration::from_secs(20);
    let barrier = Arc::new(Barrier::new(2));
    let second_started = Arc::new(AtomicBool::new(false));

    let (g1, b1) = (g.clone(), barrier.clone());
    let t1 = tokio::spawn(async move {
        g1.run(deadline, 1, move || {
            b1.wait();
            1u8
        })
        .await
    });
    assert!(wait_until(|| c.kk_trials.load(Ordering::SeqCst) == 1, 2000).await);

    let (g2, s2) = (g.clone(), second_started.clone());
    let t2 = tokio::spawn(async move {
        g2.run(deadline, 1, move || {
            s2.store(true, Ordering::SeqCst);
            2u8
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !second_started.load(Ordering::SeqCst),
        "второе замыкание стартовало, пока первое держит ворота"
    );
    barrier.wait();
    assert_eq!(t1.await.unwrap(), Ok(1));
    assert_eq!(t2.await.unwrap(), Ok(2));
    assert!(second_started.load(Ordering::SeqCst));
    assert_eq!(c.kk_trials_peak.load(Ordering::SeqCst), 1);

    // положительный контроль: при двух разрешениях оба стартуют одновременно
    let (g, c) = gate(&gate_cfg(2, 1000, 1000));
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let (gi, bi) = (g.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            gi.run(deadline, 1, move || {
                bi.wait();
                0u8
            })
            .await
        }));
    }
    assert!(wait_until(|| c.kk_trials_peak.load(Ordering::SeqCst) == 2, 3000).await);
    barrier.wait();
    for t in tasks {
        assert_eq!(t.await.unwrap(), Ok(0));
    }
    assert_eq!(c.kk_trials_peak.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kk_gate_budget() {
    // rate = 0, burst = 10: стоимость 10 проходит, следующая стоимости 1 отклонена сразу
    let (g, c) = gate(&gate_cfg(1, 0, 10));
    let far = Instant::now() + Duration::from_secs(5);
    assert_eq!(g.run(far, 10, || 1u8).await, Ok(1));
    let called = Arc::new(AtomicBool::new(false));
    let cl = called.clone();
    let t0 = Instant::now();
    let r = g
        .run(far, 1, move || {
            cl.store(true, Ordering::SeqCst);
            2u8
        })
        .await;
    assert_eq!(r, Err(GateError::Denied));
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "ждали вместо отказа"
    );
    assert!(
        !called.load(Ordering::SeqCst),
        "замыкание вызвано после отказа"
    );
    assert_eq!(c.kk_denied.load(Ordering::SeqCst), 1);
    assert_eq!(c.kk_candidates.load(Ordering::SeqCst), 10);

    // rate = 100, burst = 10: после исчерпания стоимость 10 проходит через 50..1000 мс
    let (g, c) = gate(&gate_cfg(1, 100, 10));
    assert_eq!(g.run(far, 10, || 0u8).await, Ok(0));
    let t0 = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(g.run(deadline, 10, || 0u8).await, Ok(0));
    let waited = t0.elapsed();
    assert!(
        waited >= Duration::from_millis(50) && waited < Duration::from_millis(1000),
        "ожидание бюджета {waited:?}"
    );
    // и отклоняется сразу при дедлайне 50 мс
    let t0 = Instant::now();
    let short = Instant::now() + Duration::from_millis(50);
    assert_eq!(g.run(short, 10, || 0u8).await, Err(GateError::Denied));
    assert!(
        t0.elapsed() < Duration::from_millis(40),
        "не отказано сразу"
    );
    assert_eq!(c.kk_denied.load(Ordering::SeqCst), 1);

    // стоимость 50 при burst = 10 списывает 10; kk_candidates растёт до старта замыкания
    let (g, c) = gate(&gate_cfg(1, 0, 10));
    let c2 = c.clone();
    let seen_inside = g
        .run(far, 50, move || c2.kk_candidates.load(Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(seen_inside, 10, "бюджет списан не до старта замыкания");
    assert_eq!(c.kk_candidates.load(Ordering::SeqCst), 10);
    assert_eq!(g.run(far, 1, || 0u8).await, Err(GateError::Denied));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kk_permit_held_after_deadline() {
    let (g, c) = gate(&gate_cfg(1, 1000, 1000));
    let first_done = Arc::new(AtomicBool::new(false));
    let fd = first_done.clone();
    let t0 = Instant::now();
    let r = g
        .run(t0 + Duration::from_millis(200), 1, move || {
            std::thread::sleep(Duration::from_millis(900));
            fd.store(true, Ordering::SeqCst);
        })
        .await;
    // асинхронная сторона получила таймаут...
    assert_eq!(r, Err(GateError::TimedOut));
    assert!(t0.elapsed() < Duration::from_millis(700));
    assert!(!first_done.load(Ordering::SeqCst));
    // ...а новое замыкание не стартует, пока первое не кончилось
    let fd = first_done.clone();
    let started_after_first = g
        .run(Instant::now() + Duration::from_secs(5), 1, move || {
            fd.load(Ordering::SeqCst)
        })
        .await
        .unwrap();
    assert!(
        started_after_first,
        "второе замыкание стартовало до конца первого"
    );
    assert_eq!(c.kk_trials_peak.load(Ordering::SeqCst), 1);
    assert_eq!(c.kk_trials.load(Ordering::SeqCst), 2);
}

#[test]
fn limiter_bounded() {
    let cap = 256;
    let mut lim = IpLimiter::new(5, Duration::from_secs(10), cap);
    let now = Instant::now();
    // 10 000 разных IPv6 /64
    for i in 0..10_000u32 {
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            (i >> 16) as u16,
            i as u16,
            0,
            0,
            0,
            1,
        ));
        assert!(lim.allow(ip, now));
        assert!(lim.len() <= cap);
    }
    // и 10 000 разных IPv4
    for i in 0..10_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        assert!(lim.allow(ip, now));
        assert!(lim.len() <= cap);
    }
    assert!(lim.len() <= cap);

    // адреса одного /64 считаются одним ключом
    let mut lim = IpLimiter::new(2, Duration::from_secs(10), 16);
    let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
    let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 0, 0, 9));
    let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
    assert!(lim.allow(a, now));
    assert!(lim.allow(b, now));
    assert!(!lim.allow(a, now), "третье из одного /64");
    assert!(lim.allow(c, now), "другой /64");
    assert_eq!(lim.len(), 2);
    // v4-mapped считается как IPv4
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
    assert!(lim.allow(v4, now));
    assert!(lim.allow(mapped, now));
    assert!(!lim.allow(v4, now));
    // окно истекло: снова можно
    assert!(lim.allow(v4, now + Duration::from_secs(11)));
}
