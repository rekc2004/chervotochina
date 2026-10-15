//! Экспортёр, правило одного соединения, очередь приёма, семафор до аутентификации.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_transport::Transport;

use super::kit::*;
use crate::conn::ekm;
use crate::{QuinnConfig, QuinnConn, QuinnTransport, TransportEvent};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        ..test_cfg()
    }
}

fn alive(c: &QuinnConn) -> bool {
    c.conn.close_reason().is_none()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ekm_unique_per_connection() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = bind(cfg(), vec![k.peer_b()]);
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for _ in 0..5 {
        let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
        let cb = b.accept().await.unwrap();
        let ea = ekm(&ca.conn).unwrap();
        let eb = ekm(&cb.conn).unwrap();
        assert_eq!(*ea, *eb, "экспортёры сторон одного соединения совпадают");
        assert_ne!(*ea, [0u8; 32], "экспортёр из нулей");
        seen.push(*ea);
    }
    let uniq: HashSet<[u8; 32]> = seen.iter().copied().collect();
    assert_eq!(uniq.len(), 5, "экспортёры разных соединений различны");
}

/// Собирает всё, что отдаёт `accept`, пока не истечёт срок.
fn collect_accepts(t: Arc<QuinnTransport>, ms: u64) -> Arc<Mutex<Vec<QuinnConn>>> {
    let out = Arc::new(Mutex::new(Vec::new()));
    let o = out.clone();
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_millis(ms), async {
            while let Ok(c) = t.accept().await {
                o.lock().unwrap().push(c);
            }
        })
        .await;
    });
    out
}

/// Единственное живое соединение стороны (по `stable_id`), если оно ровно одно.
fn survivors(all: &[QuinnConn]) -> Vec<QuinnConn> {
    let mut ids = HashSet::new();
    all.iter()
        .filter(|c| alive(c) && ids.insert(c.conn.stable_id()))
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_connect_keeps_one() {
    for round in 0..20 {
        let k = Keys::new();
        let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
        let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
        let acc_a = collect_accepts(a.clone(), 1000);
        let acc_b = collect_accepts(b.clone(), 1000);
        let (to_b, to_a) = (peer_addr(k.pid, &b), peer_addr(k.pid, &a));
        let (ra, rb) = tokio::join!(a.connect(&to_b), b.connect(&to_a));
        let (ca, cb) = (ra.unwrap(), rb.unwrap());
        sleep_ms(1100).await;
        let mut all_a = vec![ca];
        all_a.extend(acc_a.lock().unwrap().iter().cloned());
        let mut all_b = vec![cb];
        all_b.extend(acc_b.lock().unwrap().iter().cloned());
        let (sa, sb) = (survivors(&all_a), survivors(&all_b));
        assert_eq!(sa.len(), 1, "раунд {round}: у A живых {}", sa.len());
        assert_eq!(sb.len(), 1, "раунд {round}: у B живых {}", sb.len());
        assert_ne!(
            sa[0].is_initiator(),
            sb[0].is_initiator(),
            "раунд {round}: роли совпали"
        );
        let a_is_caller = k.a.kx_public.to_bytes() < k.b.kx_public.to_bytes();
        assert_eq!(
            sa[0].is_initiator(),
            a_is_caller,
            "раунд {round}: остался не тот, у кого звонящий с меньшим ключом"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_direction_reconnect_replaces() {
    let k = Keys::new();
    let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
    let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
    let mut ev_a = a.events();
    let mut ev_b = b.events();
    let acc_b = collect_accepts(b.clone(), 2500);
    let first = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let second = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    sleep_ms(500).await;
    assert!(!alive(&first), "старое соединение должно быть закрыто");
    assert!(alive(&second));
    // локальное закрытие или закрытие кодом CLOSE_DUPLICATE от второй стороны
    match first.conn.close_reason() {
        Some(quinn::ConnectionError::LocallyClosed) => {}
        Some(quinn::ConnectionError::ApplicationClosed(ac)) => {
            assert_eq!(
                ac.error_code.into_inner(),
                u64::from(crate::CLOSE_DUPLICATE)
            );
        }
        _ => panic!("неожиданная причина закрытия"),
    }
    // Событие шлёт та сторона, которая закрыла старое соединение (если вторая успела раньше, у этой
    // стороны старое уже мертво): ждём его хотя бы у одной.
    let ev = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                Ok(TransportEvent::ConnectionReplaced { pair }) = ev_a.recv() => return pair,
                Ok(TransportEvent::ConnectionReplaced { pair }) = ev_b.recv() => return pair,
            }
        }
    })
    .await
    .expect("событие ConnectionReplaced хотя бы у одной стороны");
    assert_eq!(ev, k.pid);
    // у вызываемого тоже ровно одно живое
    let sb = survivors(&acc_b.lock().unwrap().clone());
    assert_eq!(sb.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_queue_full_closes() {
    let mut c = cfg();
    c.accept_queue = 1;
    let keys: Vec<Keys> = (0..3).map(|_| Keys::new()).collect();
    let b = bind(c.clone(), keys.iter().map(Keys::peer_b).collect());
    let mut conns = Vec::new();
    for k in &keys {
        let a = bind(c.clone(), vec![k.peer_a()]);
        let conn = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
        conns.push((a, conn));
        sleep_ms(150).await;
    }
    sleep_ms(300).await;
    assert!(b.stats().queue_full >= 1);
    // первое осталось в очереди и живо, остальные закрыты вызываемым
    assert!(alive(&conns[0].1));
    for (_, conn) in &conns[1..] {
        assert_eq!(
            wait_closed(&conn.conn, Duration::from_secs(2)).await,
            REFUSED
        );
    }
    assert_eq!(b.stats().queue_full, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preauth_semaphore() {
    let k = Keys::new();
    let c = QuinnConfig {
        max_preauth: 1,
        auth_deadline: Duration::from_secs(1),
        ..test_cfg()
    };
    let b = Arc::new(bind(c, vec![k.peer_b()]));
    let ep = raw_endpoint();
    // молчащий клиент проходит TLS и держит единственный слот
    let silent = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let a = Arc::new(bind(
        QuinnConfig {
            auth_deadline: Duration::from_secs(8),
            ..test_cfg()
        },
        vec![k.peer_a()],
    ));
    let (a2, target) = (a.clone(), peer_addr(k.pid, &b));
    let second = tokio::spawn(async move { a2.connect(&target).await });
    sleep_ms(400).await;
    assert!(
        b.stats().ignored_busy >= 1,
        "второй клиент не отвергнут по слоту"
    );
    assert!(
        !second.is_finished(),
        "второй клиент прошёл при занятом слоте"
    );
    // после дедлайна молчащего слот освобождается и второй проходит
    assert_eq!(wait_closed(&silent, Duration::from_secs(3)).await, REFUSED);
    let r = tokio::time::timeout(Duration::from_secs(8), second)
        .await
        .expect("второй клиент так и не прошёл")
        .unwrap();
    assert!(r.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_closed_with_code_for_authenticated_peer() {
    // сырой звонящий дважды проходит KK той же парой: старое закрывается кодом CLOSE_DUPLICATE
    let k = Keys::new();
    let b = bind(cfg(), vec![k.peer_b()]);
    let mut ev = b.events();
    let ep = raw_endpoint();
    let (conn1, _) = raw_full(&ep, addr_of(&b), &k.peer_a()).await;
    let (conn2, _) = raw_full(&ep, addr_of(&b), &k.peer_a()).await;
    let seen = wait_closed(&conn1, Duration::from_secs(3)).await;
    assert_eq!(
        seen,
        Seen::AppClosed {
            code: u64::from(crate::CLOSE_DUPLICATE),
            reason_empty: true
        }
    );
    assert!(conn2.close_reason().is_none());
    let pair = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(TransportEvent::ConnectionReplaced { pair }) = ev.recv().await {
                return pair;
            }
        }
    })
    .await
    .expect("событие ConnectionReplaced");
    assert_eq!(pair, k.pid);
    assert_eq!(b.stats().auth_ok, 2);
}
