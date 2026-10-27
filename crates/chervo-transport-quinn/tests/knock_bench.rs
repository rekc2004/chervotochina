//! Замер: накладные расходы стука на пропускной способности (эхо 64 МиБ, стук вкл/выкл).
//! `#[ignore]`: запускать в `--release` с `--nocapture`; порога нет.

mod common;

use std::sync::Arc;
use std::time::Instant;

use chervo_transport::Transport;
use chervo_transport_quinn::QuinnConfig;
use common::*;

async fn echo_run(required: bool) -> f64 {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let cfg = QuinnConfig {
        knock_required: required,
        ..test_cfg()
    };
    let a = bind(cfg.clone(), vec![pa]);
    let b = Arc::new(bind(cfg, vec![pb]));
    spawn_echo(b.clone());
    let conn = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let chunk = vec![0x5Au8; 1024 * 1024];
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = conn.clone();
        let data = chunk.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..8 {
                let back = roundtrip(&c, &data).await.unwrap();
                assert_eq!(back.len(), data.len());
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let secs = start.elapsed().as_secs_f64();
    drop(conn);
    // 64 МиБ в одну сторону и столько же обратно
    128.0 / secs
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "замер; запускать в --release с --nocapture"]
async fn knock_throughput_overhead() {
    let mut on = Vec::new();
    let mut off = Vec::new();
    for _ in 0..3 {
        off.push(echo_run(false).await);
        on.push(echo_run(true).await);
    }
    on.sort_by(f64::total_cmp);
    off.sort_by(f64::total_cmp);
    let (m_on, m_off) = (on[1], off[1]);
    println!(
        "knock_throughput_overhead: стук выкл {m_off:.1} МиБ/с, вкл {m_on:.1} МиБ/с, отношение вкл/выкл {:.3}",
        m_on / m_off
    );
}
