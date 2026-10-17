mod common;

use std::sync::Arc;
use std::time::Duration;

use chervo_identity::PairId;
use chervo_transport::{Connection, Transport};
use chervo_transport_quinn::QuinnConfig;
use common::*;

#[test]
fn config_defaults_match_spec() {
    let c = QuinnConfig::default();
    assert_eq!(c.auth_deadline, Duration::from_secs(10));
    assert_eq!(c.per_ip_max, 5);
    assert_eq!(c.per_ip_window, Duration::from_secs(10));
    assert_eq!(c.limiter_capacity, 4096);
    assert_eq!(c.max_preauth, 32);
    assert_eq!(c.max_kk_trials, 1);
    assert_eq!(c.kk_budget_per_sec, 2000);
    assert_eq!(c.kk_budget_burst, 2000);
    assert_eq!(c.max_incoming, 128);
    assert_eq!(c.incoming_buffer, 16 * 1024);
    assert_eq!(c.incoming_buffer_total, 1024 * 1024);
    assert_eq!(c.preauth_receive_window, 64 * 1024);
    assert_eq!(c.stream_receive_window, 4 * 1024 * 1024);
    assert_eq!(c.post_auth_receive_window, 16 * 1024 * 1024);
    assert_eq!(c.send_window, 16 * 1024 * 1024);
    assert_eq!(c.post_auth_bidi, 16);
    assert_eq!(c.idle_timeout, Duration::from_secs(30));
    assert_eq!(c.keep_alive, Duration::from_secs(10));
    assert_eq!(c.accept_queue, 16);
    assert_eq!(c.addr_poll, Duration::from_secs(1));
    assert_eq!(chervo_transport_quinn::ALPN, b"chervo/1");
    assert_eq!(chervo_transport_quinn::SERVER_NAME, "chervo.invalid");
    assert_eq!(
        chervo_transport_quinn::EKM_LABEL,
        b"EXPERIMENTAL-chervotochina-conn-kk-v1"
    );
    assert_eq!(chervo_transport_quinn::EKM_CONTEXT, b"");
    assert_eq!(chervo_transport_quinn::CLOSE_REFUSED, 0);
    assert_eq!(chervo_transport_quinn::CLOSE_DUPLICATE, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_accept_echo() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let a = bind(test_cfg(), vec![pa]);
    let b = Arc::new(bind(test_cfg(), vec![pb]));

    let b2 = b.clone();
    let accepted = tokio::spawn(async move { b2.accept().await });
    let conn_a = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let conn_b = accepted.await.unwrap().unwrap();
    assert_eq!(conn_a.remote_pair(), pid);
    assert_eq!(conn_b.remote_pair(), pid);
    assert!(conn_a.is_initiator());
    assert!(!conn_b.is_initiator());
    tokio::spawn(echo_conn(conn_b));

    let data = pattern(1 << 20);
    let back = roundtrip(&conn_a, &data).await.unwrap();
    assert_eq!(back.len(), data.len());
    assert!(back == data, "эхо не совпало побайтно");
    let st = a.stats();
    assert_eq!(st.auth_ok, 1);
    assert_eq!(b.stats().auth_ok, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_pairs_right_one() {
    let mut callee_side = Vec::new();
    let mut callers = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..20 {
        let (c, e) = make_pair();
        ids.push(c.pair());
        callers.push(c);
        callee_side.push(e);
    }
    let b = Arc::new(bind(test_cfg(), callee_side));
    // звонящий из 13-й пары
    let caller = callers.remove(12);
    let pid = caller.pair();
    assert_eq!(pid, ids[12]);
    let a = bind(test_cfg(), vec![caller]);
    let b2 = b.clone();
    let accepted = tokio::spawn(async move { b2.accept().await });
    let conn_a = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let conn_b = accepted.await.unwrap().unwrap();
    assert_eq!(conn_a.remote_pair(), pid);
    assert_eq!(conn_b.remote_pair(), pid);
    for (i, other) in ids.iter().enumerate() {
        if i != 12 {
            assert_ne!(*other, conn_b.remote_pair());
        }
    }
    let _: PairId = conn_b.remote_pair();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_socket_both_roles() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let a = Arc::new(bind(test_cfg(), vec![pa]));
    let b = Arc::new(bind(test_cfg(), vec![pb]));
    let port_a = a.local_addrs()[0].port();
    let port_b = b.local_addrs()[0].port();

    let b2 = b.clone();
    let acc_b = tokio::spawn(async move { b2.accept().await });
    let ab = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let ab_b = acc_b.await.unwrap().unwrap();
    assert_eq!(ab.remote_pair(), pid);
    assert_eq!(ab_b.remote_pair(), pid);
    // первое соединение закрыто явно: иначе встречное по правилу одного соединения может проиграть
    ab.close();
    drop(ab_b);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B звонит A (с того же гнезда, на котором слушает)
    let a2 = a.clone();
    let acc_a = tokio::spawn(async move { a2.accept().await });
    let ba = b.connect(&peer_addr(pid, &a)).await.unwrap();
    let ba_a = acc_a.await.unwrap().unwrap();
    assert_eq!(ba.remote_pair(), pid);
    assert_eq!(ba_a.remote_pair(), pid);

    assert_eq!(a.local_addrs().len(), 1);
    assert_eq!(b.local_addrs().len(), 1);
    assert_eq!(a.local_addrs()[0].port(), port_a);
    assert_eq!(b.local_addrs()[0].port(), port_b);
    // адрес, с которого звонил B, это его же гнездо приёма
    assert_eq!(ba_a.remote_addr().port(), port_b);
    assert_eq!(ba.remote_addr().port(), port_a);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_auth_streams_raised() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let a = bind(test_cfg(), vec![pa]);
    let b = Arc::new(bind(test_cfg(), vec![pb]));
    spawn_echo(b.clone());
    let conn = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            let data = vec![i; 50_000];
            let back = roundtrip(&c, &data).await.unwrap();
            assert_eq!(back, data);
        }));
    }
    for t in tasks {
        tokio::time::timeout(Duration::from_secs(10), t)
            .await
            .unwrap()
            .unwrap();
    }
}
