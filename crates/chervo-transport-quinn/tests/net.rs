mod common;

use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

use chervo_identity::PairId;
use chervo_transport::{Connection, PeerAddr, Transport, TransportError};
use chervo_transport_quinn::{QuinnConfig, TransportEvent};
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_before_handshake() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let a = bind(test_cfg(), vec![pa]);
    let b = bind(test_cfg(), vec![pb]);
    for _ in 0..3 {
        a.connect(&peer_addr(pid, &b)).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let st = b.stats();
    assert!(st.retry_sent >= 3, "retry_sent = {}", st.retry_sent);
    assert_eq!(st.auth_ok, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_ip_limit() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let cb = QuinnConfig {
        per_ip_max: 2,
        ..test_cfg()
    };
    let b = bind(cb, vec![pb]);
    let ca = QuinnConfig {
        auth_deadline: Duration::from_millis(1500),
        ..test_cfg()
    };
    let a = bind(ca, vec![pa]);
    a.connect(&peer_addr(pid, &b)).await.unwrap();
    a.connect(&peer_addr(pid, &b)).await.unwrap();
    // третье за окно молча не обслуживается
    let r = a.connect(&peer_addr(pid, &b)).await;
    assert_eq!(r.err(), Some(TransportError::TimedOut));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(b.stats().ignored_rate >= 1);
    assert_eq!(b.stats().auth_ok, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn debug_redacted() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let a = bind(test_cfg(), vec![pa]);
    let b = bind(test_cfg(), vec![pb]);
    assert_eq!(format!("{a:?}"), "QuinnTransport(..)");
    let conn = a.connect(&peer_addr(pid, &b)).await.unwrap();
    assert_eq!(format!("{conn:?}"), "QuinnConn(..)");
}

/// Гнездо-приманка: пакетов на него не приходит.
fn decoy() -> (UdpSocket, std::net::SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let a = s.local_addr().unwrap();
    (s, a)
}

fn nothing_received(s: &UdpSocket) {
    let mut buf = [0u8; 2048];
    assert!(
        s.recv_from(&mut buf).is_err(),
        "на гнездо назначения пришёл пакет"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_pair_no_network() {
    let (pa, _pb) = make_pair();
    let a = bind(test_cfg(), vec![pa]);
    let (sock, addr) = decoy();
    let unknown = PairId::generate().unwrap();
    let r = a
        .connect(&PeerAddr {
            pair: unknown,
            addrs: vec![addr],
        })
        .await;
    assert_eq!(r.err(), Some(TransportError::UnknownPair));
    nothing_received(&sock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_not_allowed_no_network() {
    let (pa, _pb) = make_pair();
    let pid = pa.pair();
    let filter = Arc::new(BlockSet::default());
    filter.0.lock().unwrap().insert(pid);
    let a = chervo_transport_quinn::QuinnTransport::bind(lo(), test_cfg(), filter).unwrap();
    a.set_peers(vec![pa]).unwrap();
    let (sock, addr) = decoy();
    let r = a
        .connect(&PeerAddr {
            pair: pid,
            addrs: vec![addr],
        })
        .await;
    assert_eq!(r.err(), Some(TransportError::PeerNotAllowed));
    nothing_received(&sock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_addr_change_event() {
    let (pa, pb) = make_pair();
    let pid = pa.pair();
    let cfg = QuinnConfig {
        addr_poll: Duration::from_millis(100),
        ..test_cfg()
    };
    let a = bind(cfg.clone(), vec![pa]);
    let b = Arc::new(bind(cfg, vec![pb]));
    let mut events = b.events();
    let b2 = b.clone();
    let accepted = tokio::spawn(async move { b2.accept().await });
    let conn_a = a.connect(&peer_addr(pid, &b)).await.unwrap();
    let conn_b = accepted.await.unwrap().unwrap();
    tokio::spawn(echo_conn(conn_b.clone()));
    let old_port = conn_b.remote_addr().port();
    assert_eq!(
        roundtrip(&conn_a, &pattern(10_000)).await.unwrap(),
        pattern(10_000)
    );

    // звонящий переходит на новое гнездо
    let new_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_port = new_sock.local_addr().unwrap().port();
    assert_ne!(old_port, new_port);
    a.rebind(new_sock).unwrap();
    // трафик с нового адреса запускает миграцию; эхо продолжается
    for _ in 0..5 {
        let d = pattern(20_000);
        assert_eq!(roundtrip(&conn_a, &d).await.unwrap(), d);
    }
    let got = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(TransportEvent::RemoteAddrChanged { pair }) = events.recv().await {
                return pair;
            }
        }
    })
    .await
    .expect("RemoteAddrChanged за 3 с");
    assert_eq!(got, pid);
    assert_eq!(conn_b.remote_addr().port(), new_port);
    let d = pattern(30_000);
    assert_eq!(roundtrip(&conn_a, &d).await.unwrap(), d);
}
