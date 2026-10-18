//! Гонка адресов одного `connect`, один исходящий звонок на пару, объединение повторных стуков,
//! события и методы `Connection` (этап 13, часть C1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chervo_identity::PairId;
use chervo_transport::{
    Connection, EventSource, ManagedTransport, PeerAddr, RecvStream, SendStream, Transport,
    TransportError,
};

use super::kit::*;
use super::misc::{alive, collect_accepts, survivors};
use crate::{QuinnConfig, QuinnTransport, TransportEvent};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        knock_required: true,
        ..test_cfg()
    }
}

/// Молчащий адрес на петле: гнездо открыто и ничего не отвечает (ICMP не возвращается);
/// записывает, что на него что-то пришло.
struct Silent {
    sock: std::net::UdpSocket,
    addr: SocketAddr,
}

impl Silent {
    fn new() -> Self {
        let sock = std::net::UdpSocket::bind(lo()).unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        Self { sock, addr }
    }

    fn got_packet(&self) -> bool {
        let mut buf = [0u8; 2048];
        self.sock.recv_from(&mut buf).is_ok()
    }
}

fn target(pair: PairId, addrs: Vec<SocketAddr>) -> PeerAddr {
    PeerAddr { pair, addrs }
}

/// Ждёт, пока условие станет истинным (до 5 с).
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "не дождались: {what}"
        );
        sleep_ms(20).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_first_live_wins_over_dead() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = bind(cfg(), vec![k.peer_b()]);
    let (d1, d2) = (Silent::new(), Silent::new());
    let t0 = Instant::now();
    let c = a
        .connect(&target(k.pid, vec![d1.addr, d2.addr, addr_of(&b)]))
        .await
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert!(alive(&c));
    assert_eq!(a.stats().auth_ok, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_one_kk_per_call() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = bind(cfg(), vec![k.peer_b()]);
    let dead = Silent::new();
    let live = addr_of(&b);
    let before = b.stats();
    a.connect(&target(k.pid, vec![live, dead.addr, live]))
        .await
        .unwrap();
    until("auth_ok у вызываемого", || {
        b.stats().auth_ok > before.auth_ok
    })
    .await;
    sleep_ms(500).await;
    let after = b.stats();
    assert_eq!(after.auth_ok, before.auth_ok + 1);
    assert_eq!(after.duplicates_closed, 0);
}

#[cfg(not(target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_two_live_addresses_one_auth() {
    let k = Keys::new();
    let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let b = QuinnTransport::bind(any, cfg(), Arc::new(AllowAll)).unwrap();
    b.set_peers(vec![k.peer_b()]).unwrap();
    let port = b.inner.endpoint.local_addr().unwrap().port();
    // оба адреса стартуют одновременно: установиться могут оба, в KK идёт один
    let a = bind(
        QuinnConfig {
            connect_stagger: Duration::ZERO,
            ..cfg()
        },
        vec![k.peer_a()],
    );
    let two: Vec<SocketAddr> = vec![
        format!("127.0.0.1:{port}").parse().unwrap(),
        format!("127.0.0.2:{port}").parse().unwrap(),
    ];
    let c = a.connect(&target(k.pid, two)).await.unwrap();
    until("auth_ok у вызываемого", || {
        b.stats().auth_ok >= 1
    })
    .await;
    sleep_ms(500).await;
    assert_eq!(b.stats().auth_ok, 1);
    assert_eq!(b.stats().duplicates_closed, 0);
    assert_eq!(a.stats().auth_ok, 1);
    assert!(alive(&c));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_deadline_total_not_per_address() {
    let k = Keys::new();
    let deadline = Duration::from_secs(2);
    let a = bind(
        QuinnConfig {
            auth_deadline: deadline,
            ..cfg()
        },
        vec![k.peer_a()],
    );
    let dead: Vec<Silent> = (0..8).map(|_| Silent::new()).collect();
    let t0 = Instant::now();
    let r = a
        .connect(&target(k.pid, dead.iter().map(|d| d.addr).collect()))
        .await;
    let el = t0.elapsed();
    assert!(r.is_err());
    assert!(el <= deadline + Duration::from_secs(1), "{el:?}");
    assert!(el >= deadline - Duration::from_millis(100), "{el:?}");
}

/// Ревью 13, L1: ответчик на раннем адресе завершает QUIC, но молчит в KK. Его попытка KK
/// ограничена 3 с, и хороший адрес за ним успевает до общего срока (5 с).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_kk_silent_early_address_does_not_eat_deadline() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    // Хороший адрес стоит в очереди на KK за молчащим до его предела (3 с), а 3-секундный срок
    // до `msg1` у вызываемого идёт от его приёма QUIC: запас лишь `connect_stagger`. Предмет
    // теста клиентская гонка, поэтому срок вызываемого здесь расширен до общего.
    let b = bind(cfg(), vec![k.peer_b()]);
    let c = cfg();
    let ep = server_endpoint(&c);
    let mute = ep_addr(&ep);
    // принимает QUIC и держит соединение, ни разу не открыв поток
    let holder = tokio::spawn(async move {
        let conn = serve_one(&ep, &c).await;
        sleep_ms(20_000).await;
        drop(conn);
    });
    let t0 = Instant::now();
    let conn = a
        .connect(&target(k.pid, vec![mute, addr_of(&b)]))
        .await
        .unwrap();
    let el = t0.elapsed();
    holder.abort();
    assert!(alive(&conn));
    // KK на первом адресе шёл до своего предела, а не до общего срока
    assert!(el >= Duration::from_millis(2500), "{el:?}");
    assert!(el < Duration::from_millis(4500), "{el:?}");
    assert_eq!(a.stats().auth_ok, 1);
    assert!(a.stats().auth_timeout >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_all_dead_is_no_response() {
    let k = Keys::new();
    let a = bind(
        QuinnConfig {
            auth_deadline: Duration::from_millis(1500),
            ..cfg()
        },
        vec![k.peer_a()],
    );
    let (d1, d2) = (Silent::new(), Silent::new());
    let r = a.connect(&target(k.pid, vec![d1.addr, d2.addr])).await;
    assert_eq!(r.err(), Some(TransportError::NoResponse));
    assert_eq!(a.stats().connect_silent, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_dedup_normalize_and_cap() {
    let k = Keys::new();
    let a = bind(
        QuinnConfig {
            auth_deadline: Duration::from_millis(1500),
            connect_stagger: Duration::from_millis(10),
            // одно стучание на адрес: сверх первого пакета не шлём
            knock_resend_after: Duration::from_secs(60),
            ..cfg()
        },
        vec![k.peer_a()],
    );
    let socks: Vec<Silent> = (0..12).map(|_| Silent::new()).collect();
    let mapped = |s: &Silent| {
        let std::net::IpAddr::V4(v4) = s.addr.ip() else {
            panic!("ожидался IPv4")
        };
        SocketAddr::new(std::net::IpAddr::V6(v4.to_ipv6_mapped()), s.addr.port())
    };
    // v4-mapped и повторы первого адреса, затем остальные: после нормализации и дедупликации
    // 12 различных, берутся первые 8
    let mut addrs = vec![mapped(&socks[0]), socks[0].addr, socks[0].addr];
    addrs.extend(socks.iter().skip(1).map(|s| s.addr));
    let r = a.connect(&target(k.pid, addrs)).await;
    assert_eq!(r.err(), Some(TransportError::NoResponse));
    let got: Vec<bool> = socks.iter().map(Silent::got_packet).collect();
    assert_eq!(
        got,
        [
            true, true, true, true, true, true, true, true, false, false, false, false
        ],
        "опробованы ровно первые 8 различных адресов"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_v6_on_v4_endpoint_skipped() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = bind(cfg(), vec![k.peer_b()]);
    let v6: SocketAddr = "[::1]:9".parse().unwrap();
    // только IPv6: пустой список, ни одного пакета
    let t0 = Instant::now();
    let r = a.connect(&target(k.pid, vec![v6])).await;
    assert_eq!(r.err(), Some(TransportError::Io));
    assert!(t0.elapsed() < Duration::from_secs(1));
    // IPv6 пропущен, IPv4 работает
    a.connect(&target(k.pid, vec![v6, addr_of(&b)]))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_connect_same_pair_busy() {
    let k = Keys::new();
    let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
    let b = bind(cfg(), vec![k.peer_b()]);
    let dead = Silent::new();
    // живой адрес вторым: стартует через `connect_stagger`, первый звонок заведомо ещё идёт
    let t = target(k.pid, vec![dead.addr, addr_of(&b)]);
    let (a2, t2) = (a.clone(), t.clone());
    let first = tokio::spawn(async move { a2.connect(&t2).await });
    sleep_ms(50).await;
    assert!(!first.is_finished(), "первый звонок должен ещё идти");
    let t0 = Instant::now();
    let r = a.connect(&t).await;
    assert_eq!(r.err(), Some(TransportError::Busy));
    assert!(
        t0.elapsed() < Duration::from_millis(100),
        "{:?}",
        t0.elapsed()
    );
    assert!(first.await.unwrap().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_guard_released_on_cancel() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = bind(cfg(), vec![k.peer_b()]);
    let dead = Silent::new();
    // будущее первого звонка отбрасывается по таймеру
    let r = tokio::time::timeout(
        Duration::from_millis(150),
        a.connect(&target(k.pid, vec![dead.addr])),
    )
    .await;
    assert!(
        r.is_err(),
        "звонок на молчащий адрес не должен был закончиться"
    );
    let c = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    assert!(alive(&c));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_dial_keeps_one() {
    for round in 0..20 {
        let k = Keys::new();
        let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
        let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
        let acc_a = collect_accepts(a.clone(), 1500);
        let acc_b = collect_accepts(b.clone(), 1500);
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
        // оба конца одного соединения: поток от A доходит до B
        let (mut tx, _rx) = sa[0].open_bi().await.unwrap();
        tx.write_all(b"ping").await.unwrap();
        tx.finish().unwrap();
        let (_btx, mut brx) = tokio::time::timeout(Duration::from_secs(3), sb[0].accept_bi())
            .await
            .expect("accept_bi")
            .unwrap();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            let n = brx.read(&mut buf[got..]).await.unwrap().unwrap();
            got += n;
        }
        assert_eq!(&buf, b"ping", "раунд {round}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reknock_coalesced() {
    let k = Keys::new();
    let c = QuinnConfig {
        knock_resend_after: Duration::from_millis(200),
        ..cfg()
    };
    let a = bind(c.clone(), vec![k.peer_a()]);
    let b = bind(c, vec![k.peer_b()]);
    let _conn = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let base = a.stats().reknock_runs;
    for _ in 0..10 {
        a.reknock();
        sleep_ms(10).await;
    }
    until("конец серий стуков", || {
        !a.inner.reknock.lock().unwrap().0
    })
    .await;
    let runs = a.stats().reknock_runs - base;
    assert!((1..=2).contains(&runs), "серий: {runs}");
    // после окончания серии следующий вызов запускает новую
    a.reknock();
    until("новая серия", || {
        a.stats().reknock_runs > base + runs
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_lagged_reported() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let mut ev = a.subscribe();
    for _ in 0..100 {
        let _ = a
            .inner
            .events
            .send(TransportEvent::ClockSkewSuspected { pair: k.pid });
    }
    assert_eq!(ev.recv().await, Some(TransportEvent::Lagged));
    // после сигнала потери события снова приходят
    assert_eq!(
        ev.recv().await,
        Some(TransportEvent::ClockSkewSuspected { pair: k.pid })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conn_trait_methods() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    assert_eq!(Connection::conn_id(&ca), Connection::conn_id(&ca.clone()));
    assert_eq!(Connection::conn_id(&cb), Connection::conn_id(&cb.clone()));
    assert!(Connection::is_initiator(&ca));
    assert!(!Connection::is_initiator(&cb));
    // второе соединение той же стороны имеет другой идентификатор
    let k2 = Keys::new();
    let b_other = bind(cfg(), vec![k2.peer_b()]);
    a.set_peers(vec![k.peer_a(), k2.peer_a()]).unwrap();
    let ca2 = a.connect(&peer_addr(k2.pid, &b_other)).await.unwrap();
    assert_ne!(Connection::conn_id(&ca), Connection::conn_id(&ca2));
    // `closed` не завершён, пока соединение живо, и завершается после `close`
    let pending = tokio::time::timeout(Duration::from_millis(200), Connection::closed(&ca)).await;
    assert!(pending.is_err());
    Connection::close(&ca);
    tokio::time::timeout(Duration::from_secs(2), Connection::closed(&ca))
        .await
        .expect("closed() после close");
    tokio::time::timeout(Duration::from_secs(3), Connection::closed(&cb))
        .await
        .expect("closed() у собеседника");
}

/// Шаг 0 разбора R2-2: повторяются ли `stable_id` после сброса всех клонов соединения.
/// Диагностика (запускается вручную), не критерий.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "диагностика R2-2: запуск вручную"]
#[allow(clippy::print_stdout)]
async fn stable_id_reuse_probe() {
    let k = Keys::new();
    let a = Arc::new(bind(test_cfg(), vec![k.peer_a()]));
    let b = Arc::new(bind(test_cfg(), vec![k.peer_b()]));
    let mut seen_a = std::collections::HashSet::new();
    let mut seen_b = std::collections::HashSet::new();
    let (mut rep_a, mut rep_b) = (0usize, 0usize);
    for i in 0..64 {
        let b2 = b.clone();
        let acc = tokio::spawn(async move { b2.accept().await });
        let ca = match a.connect(&peer_addr(k.pid, &b)).await {
            Ok(c) => c,
            Err(e) => panic!("cycle {i}: {e:?}\nA {:?}\nB {:?}", a.stats(), b.stats()),
        };
        let cb = acc.await.unwrap().unwrap();
        if !seen_a.insert(ca.conn.stable_id()) {
            rep_a += 1;
        }
        if !seen_b.insert(cb.conn.stable_id()) {
            rep_b += 1;
        }
        Connection::close(&ca);
        Connection::close(&cb);
        Connection::closed(&ca).await;
        Connection::closed(&cb).await;
        drop(ca);
        drop(cb);
        a.inner.endpoint.wait_idle().await;
        b.inner.endpoint.wait_idle().await;
        sleep_ms(50).await;
    }
    println!("PROBE stable_id repeats: side A {rep_a}, side B {rep_b} of 64");
}

/// R2-2: номера соединений выдаёт счётчик; после сброса всех клонов и `wait_idle` (когда адрес
/// старого соединения в памяти свободен, `stable_id` повторяется) номер не повторяется.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conn_id_never_reused() {
    let k = Keys::new();
    let a = Arc::new(bind(test_cfg(), vec![k.peer_a()]));
    let b = Arc::new(bind(test_cfg(), vec![k.peer_b()]));
    let mut all = std::collections::HashSet::new();
    let (mut last_a, mut last_b) = (0u64, 0u64);
    for i in 0..64 {
        let b2 = b.clone();
        let acc = tokio::spawn(async move { b2.accept().await });
        let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
        let cb = acc.await.unwrap().unwrap();
        let (ia, ib) = (Connection::conn_id(&ca), Connection::conn_id(&cb));
        assert!(ia > last_a, "цикл {i}: сторона A {ia} <= {last_a}");
        assert!(ib > last_b, "цикл {i}: сторона B {ib} <= {last_b}");
        assert!(all.insert(ia) && all.insert(ib), "цикл {i}: номер повторён");
        assert_eq!(Connection::conn_id(&ca.clone()), ia);
        (last_a, last_b) = (ia, ib);
        Connection::close(&ca);
        Connection::close(&cb);
        Connection::closed(&ca).await;
        Connection::closed(&cb).await;
        drop(ca);
        drop(cb);
        a.inner.endpoint.wait_idle().await;
        b.inner.endpoint.wait_idle().await;
        sleep_ms(50).await;
    }
}

/// R2-2: при одновременном звонке проигравший дубликат возвращает номер победителя: у всех
/// живых `QuinnConn` стороны один и тот же номер, и он согласован с самим соединением quinn
/// (одинаковый номер тогда и только тогда, когда это одно соединение).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_duplicate_returns_winner_id() {
    for round in 0..20 {
        let k = Keys::new();
        let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
        let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
        let acc_a = collect_accepts(a.clone(), 1500);
        let acc_b = collect_accepts(b.clone(), 1500);
        let (to_b, to_a) = (peer_addr(k.pid, &b), peer_addr(k.pid, &a));
        let (ra, rb) = tokio::join!(a.connect(&to_b), b.connect(&to_a));
        let (ca, cb) = (ra.unwrap(), rb.unwrap());
        sleep_ms(1100).await;
        let mut all_a = vec![ca];
        all_a.extend(acc_a.lock().unwrap().iter().cloned());
        let mut all_b = vec![cb];
        all_b.extend(acc_b.lock().unwrap().iter().cloned());
        for (side, all) in [("A", &all_a), ("B", &all_b)] {
            let live: Vec<_> = all.iter().filter(|c| alive(c)).collect();
            assert!(!live.is_empty(), "раунд {round}: у {side} нет живых");
            for c in &live {
                assert_eq!(
                    Connection::conn_id(*c),
                    Connection::conn_id(live[0]),
                    "раунд {round}: у {side} живые QuinnConn с разными номерами"
                );
                assert_eq!(c.conn.stable_id(), live[0].conn.stable_id());
            }
            // разные соединения (в том числе закрытые проигравшие) не делят номер
            for x in all.iter() {
                for y in all.iter() {
                    assert_eq!(
                        Connection::conn_id(x) == Connection::conn_id(y),
                        x.conn.stable_id() == y.conn.stable_id(),
                        "раунд {round}: {side}: номер не согласован с соединением"
                    );
                }
            }
        }
    }
}
