//! Одинаковость отказов и ограничение переборов KK под потоком незнакомцев (сырые клиенты).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chervo_identity::KK_MSG2_LEN;

use super::kit::*;
use crate::QuinnConfig;

/// Незнакомец: TLS, первый поток, `msg1` вида 1 со случайными байтами; что получено в ответ.
async fn stranger_probe(ep: &quinn::Endpoint, addr: SocketAddr, kind: u8) -> (usize, Seen) {
    let conn = raw_tls(ep, addr).await.unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let mut m = random_msg1();
    m[0] = kind;
    tx.write_all(&m).await.unwrap();
    let (bytes, seen) = drain(&mut rx, Duration::from_secs(30)).await;
    (bytes.len(), seen)
}

fn many_keys(n: usize) -> Vec<Keys> {
    (0..n).map(|_| Keys::new()).collect()
}

fn base(n_preauth: usize) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        max_preauth: n_preauth,
        ..test_cfg()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_indistinguishable() {
    let ep = raw_endpoint();
    let mut outcomes: Vec<(&str, usize, Seen)> = Vec::new();

    // 1. незнакомец
    {
        let keys = many_keys(5);
        let b = bind(base(32), keys.iter().map(Keys::peer_b).collect());
        let (n, seen) = stranger_probe(&ep, addr_of(&b), 0x01).await;
        sleep_ms(100).await;
        assert_eq!(
            b.stats().auth_failed,
            1,
            "причина не воспроизведена: незнакомец"
        );
        outcomes.push(("незнакомец", n, seen));
    }
    // 2. неизвестный вид 0x02
    {
        let keys = many_keys(5);
        let b = bind(base(32), keys.iter().map(Keys::peer_b).collect());
        let (n, seen) = stranger_probe(&ep, addr_of(&b), 0x02).await;
        sleep_ms(100).await;
        assert_eq!(
            b.stats().auth_failed,
            1,
            "причина не воспроизведена: вид 0x02"
        );
        assert_eq!(b.stats().kk_trials, 0);
        outcomes.push(("вид 0x02", n, seen));
    }
    // 3. PeerFilter запрещает
    {
        let k = Keys::new();
        let filter = Arc::new(BlockSet::default());
        filter.0.lock().unwrap().insert(k.pid);
        let b = bind_with(base(32), vec![k.peer_b()], filter);
        let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
        let (bytes, seen) = drain(&mut raw.rx, Duration::from_secs(8)).await;
        sleep_ms(100).await;
        assert_eq!(
            b.stats().auth_failed,
            1,
            "причина не воспроизведена: PeerFilter"
        );
        assert_eq!(b.stats().kk_trials, 0);
        outcomes.push(("PeerFilter", bytes.len(), seen));
    }
    // 4. бюджет исчерпан: первый незнакомец съедает ведро
    {
        let keys = many_keys(10);
        let cfg = QuinnConfig {
            kk_budget_per_sec: 0,
            kk_budget_burst: 10,
            ..base(32)
        };
        let b = bind(cfg, keys.iter().map(Keys::peer_b).collect());
        let (n0, s0) = stranger_probe(&ep, addr_of(&b), 0x01).await;
        assert_eq!((n0, s0), (0, REFUSED));
        assert_eq!(b.stats().kk_denied, 0);
        let (n, seen) = stranger_probe(&ep, addr_of(&b), 0x01).await;
        sleep_ms(100).await;
        assert_eq!(b.stats().kk_denied, 1, "причина не воспроизведена: бюджет");
        outcomes.push(("бюджет", n, seen));
    }
    // 5. ворота заняты до дедлайна: 200 пар, один перебор, короткий дедлайн, параллельные незнакомцы
    {
        let keys = many_keys(200);
        let cfg = QuinnConfig {
            auth_deadline: Duration::from_millis(700),
            max_kk_trials: 1,
            kk_budget_per_sec: 10_000_000,
            kk_budget_burst: 10_000_000,
            ..base(64)
        };
        let b = bind(cfg, keys.iter().map(Keys::peer_b).collect());
        let addr = addr_of(&b);
        let mut tasks = Vec::new();
        for _ in 0..40 {
            let e = ep.clone();
            tasks.push(tokio::spawn(
                async move { stranger_probe(&e, addr, 0x01).await },
            ));
        }
        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap());
        }
        sleep_ms(200).await;
        assert!(
            b.stats().kk_denied >= 1,
            "причина не воспроизведена: ворота заняты"
        );
        for (n, seen) in results {
            outcomes.push(("ворота заняты", n, seen));
        }
    }
    // 6. неверный msg3: прочитаны ровно 48 байт msg2 и больше ничего
    {
        let k = Keys::new();
        let b = bind(base(32), vec![k.peer_b()]);
        let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
        let mut m2 = [0u8; KK_MSG2_LEN];
        raw.rx.read_exact(&mut m2).await.unwrap();
        let mut m3 = raw.init.finish(&m2).unwrap();
        m3[0] ^= 0x80;
        raw.tx.write_all(&m3).await.unwrap();
        raw.tx.finish().unwrap();
        expect_refused_after_msg2(&mut raw.rx, &raw.conn).await;
        sleep_ms(100).await;
        assert_eq!(b.stats().auth_failed, 1, "причина не воспроизведена: msg3");
    }

    // У всех причин, кроме msg3: 0 байт и отказ приложения с кодом 0 и пустой причиной.
    for (why, n, seen) in &outcomes {
        assert_eq!(*n, 0, "{why}: прочитаны байты");
        assert_eq!(*seen, REFUSED, "{why}: иной вид закрытия");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kk_trials_bounded_under_strangers() {
    let keys = many_keys(50);
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(10),
        max_kk_trials: 1,
        kk_budget_per_sec: 1000,
        kk_budget_burst: 200,
        ..base(64)
    };
    let b = bind(cfg, keys.iter().map(Keys::peer_b).collect());
    let addr = addr_of(&b);
    let ep = raw_endpoint();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..30 {
        let e = ep.clone();
        tasks.push(tokio::spawn(
            async move { stranger_probe(&e, addr, 0x01).await },
        ));
    }
    for t in tasks {
        let (n, seen) = t.await.unwrap();
        assert_eq!(n, 0, "у незнакомца прочитаны байты");
        assert_eq!(seen, REFUSED);
    }
    let t = started.elapsed().as_secs_f64();
    sleep_ms(100).await;
    let st = b.stats();
    assert_eq!(st.kk_trials_peak, 1, "переборы шли параллельно: {st:?}");
    let bound = 200.0 + 1000.0 * t + 50.0;
    assert!(
        (st.kk_candidates as f64) <= bound,
        "кандидатов {} > {bound} за {t} с",
        st.kk_candidates
    );
    assert_eq!(st.kk_candidates, 50 * st.kk_trials);
    // каждый незнакомец либо прошёл ровно один перебор, либо отвергнут воротами до старта
    // (в debug-сборке перебор ~70 раз медленнее release, часть не успевает в дедлайн)
    assert_eq!(st.kk_trials + st.kk_denied, 30, "{st:?}");
    assert!(st.kk_trials >= 1);
}
