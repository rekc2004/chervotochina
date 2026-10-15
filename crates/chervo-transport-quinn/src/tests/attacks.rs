//! Матрица атак на аутентификацию соединения (повтор G10 спайка, без подписей).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use chervo_identity::{KK_MSG2_LEN, KK_MSG3_LEN};
use chervo_transport::{Connection, Transport, TransportError};

use super::kit::*;
use crate::conn::binding;
use crate::limits::{Counters, KkGate};
use crate::{QuinnConfig, QuinnTransport};

fn rt_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(3),
        ..test_cfg()
    }
}

/// Принять не должно ничего.
async fn nothing_accepted(t: &QuinnTransport) {
    let r = tokio::time::timeout(Duration::from_millis(300), t.accept()).await;
    assert!(r.is_err(), "соединение не должно быть принято");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stranger_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    // свои секреты, правильный публичный ключ друга, чужие ключи вместо пары
    let a = bind(rt_cfg(), vec![stranger_peer(k.pid, k.b.kx_public)]);
    let r = a.connect(&peer_addr(k.pid, &b)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    sleep_ms(200).await;
    assert_eq!(b.stats().auth_failed, 1);
    assert_eq!(b.stats().auth_ok, 0);
    nothing_accepted(&b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_keys_only_attacker_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    let a = bind(rt_cfg(), vec![k.peer_a()]);
    // Атакующий знает оба публичных ключа пары (из токена), своего секрета пары нет.
    let attacker = bind(
        rt_cfg(),
        vec![stranger_peer(k.pid, k.b.kx_public)], // ours чужой, theirs = публичный ключ B
    );
    // 1) атакующий звонит B
    let r = attacker.connect(&peer_addr(k.pid, &b)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    sleep_ms(200).await;
    assert_eq!(b.stats().auth_ok, 0);
    nothing_accepted(&b).await;
    // 2) атакующий вместо B принимает звонок A (публичный ключ A известен, секрета B нет)
    let fake_b = bind(rt_cfg(), vec![stranger_peer(k.pid, k.a.kx_public)]);
    let r = a.connect(&peer_addr(k.pid, &fake_b)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    sleep_ms(200).await;
    assert_eq!(fake_b.stats().auth_ok, 0);
    nothing_accepted(&fake_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_own_key_rejected() {
    let k = Keys::new();
    let other = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    // ключ другой пары как «свой», публичный ключ друга верный
    let wrong = other.a.peer_as(k.pid, k.b.kx_public);
    let a = bind(rt_cfg(), vec![wrong]);
    let r = a.connect(&peer_addr(k.pid, &b)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    sleep_ms(200).await;
    assert_eq!(b.stats().auth_ok, 0);
    nothing_accepted(&b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_pair_treated_as_stranger() {
    let k = Keys::new();
    let filter = Arc::new(BlockSet::default());
    filter.0.lock().unwrap().insert(k.pid);
    let b = bind_with(rt_cfg(), vec![k.peer_b()], filter);
    let a = bind(rt_cfg(), vec![k.peer_a()]);
    let r = a.connect(&peer_addr(k.pid, &b)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    sleep_ms(200).await;
    assert_eq!(
        b.stats().kk_trials,
        0,
        "заблокированная пара не перебирается"
    );
    assert_eq!(b.stats().auth_failed, 1);

    // сырой звонящий: у вызываемого ни одного записанного байта
    let ep = raw_endpoint();
    let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
    let (bytes, seen) = drain(&mut raw.rx, Duration::from_secs(3)).await;
    assert!(bytes.is_empty());
    assert_eq!(seen, REFUSED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mitm_two_tls_sessions_rejected() {
    let k = Keys::new();
    let cfg = rt_cfg();
    let b = bind(cfg.clone(), vec![k.peer_b()]);
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let proxy = server_endpoint(&cfg);
    let proxy_addr = ep_addr(&proxy);
    let b_addr = addr_of(&b);
    let pcfg = cfg.clone();
    // Посредник: принимает звонящего своим TLS, звонит вызываемому, пересылает байты потока.
    let relay = tokio::spawn(async move {
        let conn_a = serve_one(&proxy, &pcfg).await;
        let (mut a_tx, mut a_rx) = conn_a.accept_bi().await.unwrap();
        let mut m1 = [0u8; 49];
        a_rx.read_exact(&mut m1).await.unwrap();
        let ep2 = raw_endpoint();
        let conn_b = raw_tls(&ep2, b_addr).await.unwrap();
        let (mut b_tx, mut b_rx) = conn_b.open_bi().await.unwrap();
        b_tx.write_all(&m1).await.unwrap();
        // что вернул вызываемый (должно быть ничего), пересылаем звонящему
        let (data, seen) = drain(&mut b_rx, Duration::from_secs(3)).await;
        if !data.is_empty() {
            a_tx.write_all(&data).await.unwrap();
        }
        // после пересылки посредник закрывает своё соединение со звонящим
        conn_a.close(7u32.into(), b"");
        (data.len(), seen)
    });
    let r = a.connect(&PeerAddrBuild::one(k.pid, proxy_addr)).await;
    assert!(
        matches!(
            r.err(),
            Some(TransportError::AuthFailed) | Some(TransportError::TimedOut)
        ),
        "звонящий не должен получить соединение"
    );
    let (relayed, seen) = relay.await.unwrap();
    assert_eq!(relayed, 0, "вызываемый не отдал ни байта");
    assert_eq!(seen, REFUSED);
    sleep_ms(200).await;
    assert_eq!(b.stats().auth_ok, 0);
    assert_eq!(b.stats().auth_failed, 1);
    nothing_accepted(&b).await;
}

struct PeerAddrBuild;

impl PeerAddrBuild {
    fn one(
        pair: chervo_identity::PairId,
        addr: std::net::SocketAddr,
    ) -> chervo_transport::PeerAddr {
        chervo_transport::PeerAddr {
            pair,
            addrs: vec![addr],
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_msg1_other_connection_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    // положительный контроль: настоящий друг проходит, msg1 снят с этого соединения
    let (conn1, msg1) = raw_full(&ep, addr_of(&b), &k.peer_a()).await;
    let accepted = tokio::time::timeout(Duration::from_secs(3), b.accept())
        .await
        .expect("исходное соединение должно пройти")
        .unwrap();
    assert_eq!(accepted.remote_pair(), k.pid);
    assert_eq!(b.stats().auth_ok, 1);
    // повтор в новом TLS-соединении
    let conn2 = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let (mut tx, mut rx) = conn2.open_bi().await.unwrap();
    tx.write_all(&msg1).await.unwrap();
    let (bytes, seen) = drain(&mut rx, Duration::from_secs(3)).await;
    assert!(bytes.is_empty());
    assert_eq!(seen, REFUSED);
    sleep_ms(100).await;
    assert_eq!(b.stats().auth_ok, 1);
    assert_eq!(b.stats().auth_failed, 1);
    drop(conn1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reflection_rejected() {
    let k = Keys::new();
    // Слушает A. Сырой клиент отражает ему msg1, составленное ключами самого A.
    let a = bind(rt_cfg(), vec![k.peer_a()]);
    let ep = raw_endpoint();
    let mut raw = raw_start(&ep, addr_of(&a), &k.peer_a()).await;
    let (bytes, seen) = drain(&mut raw.rx, Duration::from_secs(3)).await;
    assert!(bytes.is_empty());
    assert_eq!(seen, REFUSED);
    sleep_ms(100).await;
    assert_eq!(a.stats().auth_ok, 0);
    assert_eq!(a.stats().auth_failed, 1);
    nothing_accepted(&a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_msg2_rejected() {
    let k = Keys::new();
    let cfg = rt_cfg();
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let evil = server_endpoint(&cfg);
    let evil_addr = ep_addr(&evil);
    let peer_b = k.peer_b();
    let ecfg = cfg.clone();
    let task = tokio::spawn(async move {
        let conn = serve_one(&evil, &ecfg).await;
        let bind_ = binding(&conn).unwrap();
        let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
        let mut m1 = [0u8; 49];
        rx.read_exact(&mut m1).await.unwrap();
        let gate = KkGate::new(&ecfg, Arc::new(Counters::default()));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (_resp, mut m2) = gate
            .respond(deadline, Arc::new(vec![peer_b]), vec![0], bind_, m1)
            .await
            .unwrap();
        m2[10] ^= 0x01; // портим бит
        tx.write_all(&m2).await.unwrap();
        tx.finish().unwrap();
        // после порчи звонящий не должен прислать ни msg3, ни прикладных данных
        let (bytes, seen) = drain(&mut rx, Duration::from_secs(3)).await;
        (bytes.len(), seen)
    });
    let r = a.connect(&PeerAddrBuild::one(k.pid, evil_addr)).await;
    assert_eq!(r.err(), Some(TransportError::AuthFailed));
    let (n, seen) = task.await.unwrap();
    assert_eq!(n, 0, "после испорченного msg2 звонящий молчит");
    assert_eq!(seen, REFUSED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_msg3_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
    let mut m2 = [0u8; KK_MSG2_LEN];
    raw.rx.read_exact(&mut m2).await.unwrap();
    let mut m3 = raw.init.finish(&m2).unwrap();
    m3[3] ^= 0x01;
    raw.tx.write_all(&m3).await.unwrap();
    raw.tx.finish().unwrap();
    expect_refused_after_msg2(&mut raw.rx, &raw.conn).await;
    sleep_ms(100).await;
    assert_eq!(b.stats().auth_ok, 0);
    assert_eq!(b.stats().auth_failed, 1);
    nothing_accepted(&b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_kind_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    for kind in [0x00u8, 0x02, 0xFF] {
        let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        let mut m = random_msg1();
        m[0] = kind;
        tx.write_all(&m).await.unwrap();
        let (bytes, seen) = drain(&mut rx, Duration::from_secs(3)).await;
        assert!(bytes.is_empty());
        assert_eq!(seen, REFUSED);
    }
    sleep_ms(100).await;
    let st = b.stats();
    assert_eq!(st.kk_trials, 0);
    assert_eq!(st.kk_candidates, 0);
    assert_eq!(st.auth_failed, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_lengths_rejected() {
    let k = Keys::new();
    let b = bind(rt_cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    // msg1 неверной длины (содержимое случайное)
    for (len, finish) in [
        (0usize, true),
        (1, true),
        (48, true),
        (50, false),
        (4096, false),
    ] {
        let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        let mut data = vec![0u8; len];
        for (i, v) in data.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        if let Some(f) = data.first_mut() {
            *f = chervo_identity::KK_KIND_V1;
        }
        if len > 0 {
            tx.write_all(&data).await.unwrap();
        }
        if finish {
            tx.finish().unwrap();
        }
        let (bytes, seen) = drain(&mut rx, Duration::from_secs(3)).await;
        assert!(bytes.is_empty(), "msg1 длины {len}");
        assert_eq!(seen, REFUSED, "msg1 длины {len}");
    }
    // msg3 неверной длины после настоящих msg1/msg2
    for variant in ["short15", "long17", "extra_after"] {
        let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
        let mut m2 = [0u8; KK_MSG2_LEN];
        raw.rx.read_exact(&mut m2).await.unwrap();
        let m3 = raw.init.finish(&m2).unwrap();
        let mut payload = m3.to_vec();
        match variant {
            "short15" => payload.truncate(KK_MSG3_LEN - 1),
            _ => payload.push(0xAB),
        }
        raw.tx.write_all(&payload).await.unwrap();
        raw.tx.finish().unwrap();
        expect_refused_after_msg2(&mut raw.rx, &raw.conn).await;
    }
    sleep_ms(100).await;
    assert_eq!(b.stats().auth_ok, 0);
    nothing_accepted(&b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_caller_times_out() {
    let k = Keys::new();
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(1),
        ..test_cfg()
    };
    let b = bind(cfg, vec![k.peer_b()]);
    let ep = raw_endpoint();
    let started = Instant::now();
    let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
    // TLS есть, потока нет
    let seen = wait_closed(&conn, Duration::from_secs(4)).await;
    let elapsed = started.elapsed();
    assert_eq!(seen, REFUSED);
    assert!(
        elapsed >= Duration::from_millis(800),
        "закрыто рано: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2500),
        "закрыто поздно: {elapsed:?}"
    );
    assert_eq!(b.stats().auth_timeout, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_callee_times_out() {
    let k = Keys::new();
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(1),
        ..test_cfg()
    };
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let evil = server_endpoint(&cfg);
    let evil_addr = ep_addr(&evil);
    let ecfg = cfg.clone();
    let _task = tokio::spawn(async move {
        let conn = serve_one(&evil, &ecfg).await;
        // принимает поток и молчит
        let _s = conn.accept_bi().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let started = Instant::now();
    let r = a.connect(&PeerAddrBuild::one(k.pid, evil_addr)).await;
    let elapsed = started.elapsed();
    assert_eq!(r.err(), Some(TransportError::TimedOut));
    assert!(
        elapsed < Duration::from_millis(2000),
        "дольше дедлайна и секунды: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_stream_limit_callee_times_out() {
    let k = Keys::new();
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(1),
        ..test_cfg()
    };
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let evil = server_endpoint(&cfg);
    let evil_addr = ep_addr(&evil);
    let ecfg = cfg.clone();
    let _task = tokio::spawn(async move {
        loop {
            let incoming = evil.accept().await.unwrap();
            if !incoming.remote_address_validated() {
                incoming.retry().unwrap();
                continue;
            }
            // злой сервер: нулевой лимит двунаправленных потоков
            let sc = crate::tls::ephemeral_rustls().unwrap();
            let mut server = crate::tls::quic_server(
                {
                    let mut sc = sc;
                    crate::tls::harden(&mut sc);
                    sc
                },
                &ecfg,
                0,
            )
            .unwrap();
            let mut t = quinn::TransportConfig::default();
            t.max_concurrent_bidi_streams(0u32.into());
            t.max_concurrent_uni_streams(0u32.into());
            server.transport_config(Arc::new(t));
            let conn = incoming
                .accept_with(Arc::new(server))
                .unwrap()
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(conn);
            return;
        }
    });
    let started = Instant::now();
    let r = a.connect(&PeerAddrBuild::one(k.pid, evil_addr)).await;
    let elapsed = started.elapsed();
    assert_eq!(r.err(), Some(TransportError::TimedOut));
    assert!(elapsed < Duration::from_millis(2000), "{elapsed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_streams_blocked_before_auth() {
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        ..test_cfg()
    };
    let server = server_endpoint(&cfg);
    let addr = ep_addr(&server);
    let scfg = cfg.clone();
    let srv = tokio::spawn(async move { serve_one(&server, &scfg).await });
    let ep = raw_endpoint();
    let client = raw_tls(&ep, addr).await.unwrap();
    let srv_conn = srv.await.unwrap();

    // первый поток открывается, второй нет
    let (mut tx1, _rx1) = client.open_bi().await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(500), client.open_bi()).await;
    assert!(
        second.is_err(),
        "второй двунаправленный поток открылся до KK"
    );
    // однонаправленных нет
    let uni = tokio::time::timeout(Duration::from_millis(500), client.open_uni()).await;
    assert!(uni.is_err(), "однонаправленный поток открылся до KK");
    // датаграммы выключены
    assert!(client.send_datagram(vec![1u8].into()).is_err());
    // 4 МиБ в первый поток не проходят
    let big = vec![0xA5u8; 4 * 1024 * 1024];
    let w = tokio::time::timeout(Duration::from_secs(1), tx1.write_all(&big)).await;
    assert!(w.is_err(), "4 МиБ записаны до KK");
    sleep_ms(300).await;
    let rx_bytes = srv_conn.stats().udp_rx.bytes;
    assert!(
        rx_bytes < 512 * 1024,
        "вызываемый принял {rx_bytes} байт до KK"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_after_msg2_times_out() {
    // вызываемый отправил msg2, msg3 нет: закрытие у дедлайна, таймаут засчитан
    let k = Keys::new();
    let cfg = QuinnConfig {
        auth_deadline: Duration::from_secs(1),
        ..test_cfg()
    };
    let b = bind(cfg, vec![k.peer_b()]);
    let ep = raw_endpoint();
    let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
    let mut m2 = [0u8; KK_MSG2_LEN];
    raw.rx.read_exact(&mut m2).await.unwrap();
    expect_refused_after_msg2(&mut raw.rx, &raw.conn).await;
    assert_eq!(b.stats().auth_timeout, 1);
}
