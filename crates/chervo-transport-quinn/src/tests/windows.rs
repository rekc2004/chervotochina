//! Окна приёма (этап 14, X0): проверка настроек, предел памяти для непрочитанных данных
//! после KK и малое окно соединения до KK. Мерка: байты UDP, принятые вызываемой стороной
//! (`stats().udp_rx.bytes`); поток никто не читает, поэтому приём ограничен только окнами.

use std::sync::Arc;
use std::time::Duration;

use chervo_transport::{Connection, SendStream, Transport};

use super::kit::*;
use crate::{QuinnConfig, QuinnConn, QuinnTransport};

const KIB: u32 = 1024;
const MIB: u32 = 1024 * 1024;
/// Заголовки пакетов и рукопожатие поверх окна.
const SLACK: u64 = 96 * 1024;

fn rx_bytes(c: &quinn::Connection) -> u64 {
    c.stats().udp_rx.bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_rejects_bad_windows() {
    let ok = |c: QuinnConfig| QuinnTransport::bind(lo(), c, Arc::new(AllowAll)).is_ok();
    assert!(ok(test_cfg()), "по умолчанию окна верны");
    // границы включены
    assert!(ok(QuinnConfig {
        stream_receive_window: 64 * KIB,
        post_auth_receive_window: 64 * KIB,
        send_window: 64 * 1024,
        ..test_cfg()
    }));
    // окно потока меньше 64 КиБ
    assert!(!ok(QuinnConfig {
        stream_receive_window: 64 * KIB - 1,
        ..test_cfg()
    }));
    assert!(!ok(QuinnConfig {
        stream_receive_window: 0,
        ..test_cfg()
    }));
    // окно потока больше окна соединения после KK
    assert!(!ok(QuinnConfig {
        stream_receive_window: 2 * MIB,
        post_auth_receive_window: MIB,
        ..test_cfg()
    }));
    // окно отправки меньше 64 КиБ или непредставимо
    assert!(!ok(QuinnConfig {
        send_window: 64 * 1024 - 1,
        ..test_cfg()
    }));
    assert!(!ok(QuinnConfig {
        send_window: u64::MAX,
        ..test_cfg()
    }));
}

/// Соединение a -> b: (транспорт a, транспорт b, конец a, конец b).
async fn pair_with(cfg: QuinnConfig) -> (QuinnTransport, QuinnTransport, QuinnConn, QuinnConn) {
    let k = Keys::new();
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let b = bind(cfg, vec![k.peer_b()]);
    let target = peer_addr(k.pid, &b);
    let (dialed, accepted) = tokio::join!(a.connect(&target), b.accept());
    (a, b, dialed.unwrap(), accepted.unwrap())
}

type Tx = <QuinnConn as Connection>::Tx;
type Rx = <QuinnConn as Connection>::Rx;

/// Открывает поток и пишет один байт: так поток становится виден собеседнику (`accept_bi`),
/// пока окно соединения ещё не исчерпано.
async fn open_primed(conn: &QuinnConn) -> (Tx, Rx) {
    let (mut tx, rx) = conn.open_bi().await.unwrap();
    tx.write_all(&[0xA5]).await.unwrap();
    (tx, rx)
}

/// Дописывает в поток `total` байт и держит его открытым, пока задачу не снимут.
fn spawn_writer(mut tx: Tx, rx: Rx, total: usize) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let chunk = vec![0xA5u8; 64 * 1024];
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            if tx.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n;
        }
        let _keep = (tx, rx);
        std::future::pending::<()>().await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_auth_window_caps_unread_data() {
    // 8 потоков по 512 КиБ окна дали бы 4 МиБ; окно соединения после KK держит 1 МиБ
    let cfg = QuinnConfig {
        stream_receive_window: 512 * KIB,
        post_auth_receive_window: MIB,
        ..test_cfg()
    };
    let (_a, _b, conn_a, conn_b) = pair_with(cfg).await;
    let mut primed = Vec::new();
    for _ in 0..8 {
        primed.push(open_primed(&conn_a).await);
    }
    // 8 принятых и непрочитанных потоков
    let mut held = Vec::new();
    for _ in 0..8 {
        let s = tokio::time::timeout(Duration::from_secs(5), conn_b.accept_bi())
            .await
            .expect("поток не пришёл")
            .unwrap();
        held.push(s);
    }
    let writers: Vec<_> = primed
        .into_iter()
        .map(|(tx, rx)| spawn_writer(tx, rx, 4 * 1024 * 1024))
        .collect();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = rx_bytes(&conn_b.conn);
    let cap = u64::from(MIB) + SLACK;
    assert!(got <= cap, "принято {got} байт при окне {MIB} (+{SLACK})");
    assert!(got >= u64::from(MIB) / 2, "тест пуст: принято лишь {got}");
    for w in writers {
        w.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_window_caps_one_stream_postauth() {
    // окно соединения велико, окно потока мало: один непрочитанный поток держит своё окно
    let cfg = QuinnConfig {
        stream_receive_window: 256 * KIB,
        post_auth_receive_window: 4 * MIB,
        ..test_cfg()
    };
    let (_a, _b, conn_a, conn_b) = pair_with(cfg).await;
    let (tx, rx) = open_primed(&conn_a).await;
    let _held = tokio::time::timeout(Duration::from_secs(5), conn_b.accept_bi())
        .await
        .expect("поток не пришёл")
        .unwrap();
    let w = spawn_writer(tx, rx, 2 * 1024 * 1024);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = rx_bytes(&conn_b.conn);
    let cap = u64::from(256 * KIB) + SLACK;
    assert!(got <= cap, "принято {got} байт при окне потока 256 КиБ");
    assert!(got >= u64::from(128 * KIB), "тест пуст: принято лишь {got}");
    w.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_window_applied_preauth_still_capped() {
    // окно потока 4 МиБ (по умолчанию), но до KK окно соединения 64 КиБ держит предел
    let cfg = test_cfg();
    assert_eq!(cfg.stream_receive_window, 4 * MIB);
    let server = server_endpoint(&cfg);
    let addr = ep_addr(&server);
    let sc = cfg.clone();
    let srv = tokio::spawn(async move { serve_one(&server, &sc).await });
    let ep = raw_endpoint();
    let client = raw_tls(&ep, addr).await.unwrap();
    let sconn = srv.await.unwrap();
    let (mut tx, _rx) = client.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5Au8; 64 * 1024];
        for _ in 0..16 {
            if tx.write_all(&chunk).await.is_err() {
                return;
            }
        }
        std::future::pending::<()>().await;
    });
    let _held = tokio::time::timeout(Duration::from_secs(5), sconn.accept_bi())
        .await
        .expect("поток не пришёл")
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = rx_bytes(&sconn);
    let cap = u64::from(cfg.preauth_receive_window) + SLACK;
    assert!(got <= cap, "до KK принято {got} байт при окне 64 КиБ");
    assert!(got >= 32 * 1024, "тест пуст: принято лишь {got}");
    writer.abort();
}
