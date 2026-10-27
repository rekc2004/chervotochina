//! Этап 17, B2: срок до полного `msg1` и предел незавершённых соединений на ключ лимитера.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chervo_transport::Transport;

use super::kit::*;
use crate::limits::PreauthKeys;
use crate::{QuinnConfig, QuinnTransport};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        msg1_deadline: Duration::from_millis(700),
        knock_required: false,
        ..test_cfg()
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn msg1_deadline_defaults_and_clamp() {
    let d = QuinnConfig::default();
    assert_eq!(d.msg1_deadline, Duration::from_secs(5));
    assert_eq!(d.max_preauth_per_key, 2);
    assert_eq!(d.msg1_deadline_eff(), Duration::from_secs(5));
    let long = QuinnConfig {
        msg1_deadline: Duration::from_secs(60),
        auth_deadline: Duration::from_secs(8),
        ..QuinnConfig::default()
    };
    assert_eq!(long.msg1_deadline_eff(), Duration::from_secs(8));
}

/// TLS пройден, потом тишина: закрытие отказом (код 0, пустая причина) в `msg1_deadline`, а не
/// в `auth_deadline`; другой клиент с полным `msg1` в срок проходит.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_after_tls_closed_at_msg1_deadline() {
    let k = Keys::new();
    let b = bind(cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    let t0 = Instant::now();
    let idle = raw_tls(&ep, addr_of(&b)).await.unwrap();
    assert_eq!(wait_closed(&idle, Duration::from_secs(4)).await, REFUSED);
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(600),
        "закрыто раньше срока: {took:?}"
    );
    assert!(
        took < Duration::from_millis(2500),
        "закрыто по auth_deadline, а не по msg1_deadline: {took:?}"
    );
    assert_eq!(b.stats().auth_timeout, 1, "{:?}", b.stats());
    // полный `msg1` в срок: обычный путь не задет
    let (ok, _) = raw_full(&ep, addr_of(&b), &k.peer_a()).await;
    sleep_ms(1000).await;
    assert!(ok.close_reason().is_none(), "верный клиент закрыт по сроку");
}

/// Половина `msg1` и тишина: тот же срок и тот же отказ, без кадров потока от вызываемого.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_msg1_closed_at_msg1_deadline() {
    let b = bind(cfg(), vec![Keys::new().peer_b()]);
    let ep = raw_endpoint();
    let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    let half = random_msg1();
    tx.write_all(&half[..half.len() / 2]).await.unwrap();
    expect_refused_after_msg2(&mut rx, &conn).await;
    assert_eq!(b.stats().auth_timeout, 1, "{:?}", b.stats());
    assert_eq!(b.stats().auth_failed, 0, "{:?}", b.stats());
}

/// Новые пределы дают тот же вид отказа, что и прежние причины (неверный `msg1`): код 0, пустая
/// причина, ни STOP_SENDING, ни RESET_STREAM, ни байтов; предел на ключ молчит, как занятый
/// семафор (ни одного ответа после Retry).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_uniform_for_new_limits() {
    let ep = raw_endpoint();
    // эталон: прежняя причина, незнакомец с вызываемым без нужной пары
    let reference = {
        let b = bind(cfg(), vec![Keys::new().peer_b()]);
        let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        tx.write_all(&random_msg1()).await.unwrap();
        let (bytes, seen) = drain(&mut rx, Duration::from_secs(8)).await;
        (bytes.len(), seen, frames(&conn))
    };
    // новый предел 1: срок до msg1
    let by_deadline = {
        let b = bind(cfg(), vec![Keys::new().peer_b()]);
        let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
        let (_tx, mut rx) = conn.open_bi().await.unwrap();
        let (bytes, seen) = drain(&mut rx, Duration::from_secs(8)).await;
        (bytes.len(), seen, frames(&conn))
    };
    assert_eq!(reference, (0, REFUSED, Frames::default()));
    assert_eq!(
        by_deadline, reference,
        "срок до msg1 отличим от прежнего отказа"
    );
    // новый предел 2: третье соединение с ключа молчит (как при занятом семафоре)
    let c = QuinnConfig {
        msg1_deadline: Duration::from_secs(4),
        max_preauth_per_key: 2,
        ..cfg()
    };
    let b = bind(c, vec![Keys::new().peer_b()]);
    let _s1 = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let _s2 = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let third = tokio::time::timeout(Duration::from_millis(500), raw_tls(&ep, addr_of(&b))).await;
    assert!(third.is_err(), "третье соединение ключа получило ответ");
    assert!(b.stats().ignored_busy >= 1, "{:?}", b.stats());
    assert_eq!(b.stats().ignored_rate, 0, "{:?}", b.stats());
}

/// Третье незавершённое соединение с того же ключа отвергнуто; другой ключ проходит; после
/// освобождения мест (срок до msg1) тот же ключ снова принимается.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_key_cap_third_refused_other_key_ok() {
    let k = Keys::new();
    let c = QuinnConfig {
        msg1_deadline: Duration::from_millis(1500),
        max_preauth_per_key: 2,
        ..cfg()
    };
    let b = Arc::new(bind(c, vec![k.peer_b()]));
    let ep = raw_endpoint();
    let s1 = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let s2 = raw_tls(&ep, addr_of(&b)).await.unwrap();
    let third = tokio::time::timeout(Duration::from_millis(500), raw_tls(&ep, addr_of(&b))).await;
    assert!(third.is_err(), "третье соединение с ключа прошло");
    assert!(b.stats().ignored_busy >= 1, "{:?}", b.stats());
    assert_eq!(
        b.stats().ignored_rate,
        0,
        "лимитер IP списан зря: {:?}",
        b.stats()
    );

    // другой ключ лимитера (другой IPv4): проходит и аутентифицируется; там, где 127.0.0.2
    // не поднят (macOS), эта часть пропускается, ключи проверены на уровне `PreauthKeys`
    let other: std::net::SocketAddr = "127.0.0.2:0".parse().unwrap();
    if let Ok(a) = QuinnTransport::bind(other, cfg(), Arc::new(AllowAll)) {
        a.set_peers(vec![k.peer_a()]).unwrap();
        let r = a.connect(&peer_addr(k.pid, &b)).await;
        assert!(r.is_ok(), "друг с другого ключа не прошёл: {r:?}");
    }

    // места освобождаются по сроку до msg1 (оба молчуна закрыты отказом), тот же ключ проходит
    assert_eq!(wait_closed(&s1, Duration::from_secs(4)).await, REFUSED);
    assert_eq!(wait_closed(&s2, Duration::from_secs(4)).await, REFUSED);
    let a = bind(cfg(), vec![k.peer_a()]);
    let r = a.connect(&peer_addr(k.pid, &b)).await;
    assert!(r.is_ok(), "после освобождения мест друг не прошёл: {r:?}");
    drop(r);
    let _ = b.accept().await;
}

/// Ключи: IPv4 целиком, IPv6 по /64, v4-mapped как IPv4; место возвращается при сбросе,
/// карта не копит пустые записи.
#[test]
fn preauth_keys_grouping_and_release() {
    let keys = PreauthKeys::new(2);
    let p1 = keys.try_acquire(ip("192.0.2.1")).unwrap();
    let p2 = keys.try_acquire(ip("192.0.2.1")).unwrap();
    assert!(keys.try_acquire(ip("192.0.2.1")).is_none());
    // соседний IPv4 это другой ключ
    let p3 = keys.try_acquire(ip("192.0.2.2")).unwrap();
    // v4-mapped совпадает с IPv4
    assert!(keys.try_acquire(ip("::ffff:192.0.2.1")).is_none());
    // IPv6: один /64 общий, другой /64 отдельный
    let a = keys.try_acquire(ip("2001:db8:0:1::1")).unwrap();
    let b = keys.try_acquire(ip("2001:db8:0:1:ffff::2")).unwrap();
    assert!(keys.try_acquire(ip("2001:db8:0:1::3")).is_none());
    let c = keys.try_acquire(ip("2001:db8:0:2::1")).unwrap();
    drop(p1);
    let p4 = keys.try_acquire(ip("192.0.2.1")).unwrap();
    assert!(keys.try_acquire(ip("192.0.2.1")).is_none());
    drop((p2, p3, p4, a, b, c));
    assert_eq!(keys.tracked(), 0, "карта хранит пустые записи");
    // нулевой предел поднимается до 1
    let one = PreauthKeys::new(0);
    let _g = one.try_acquire(ip("192.0.2.9")).unwrap();
    assert!(one.try_acquire(ip("192.0.2.9")).is_none());
}

// ---------------------------------------------------------------------------------------------
// Этап 17, S2, L3: срок `msg3` после `msg2`
// ---------------------------------------------------------------------------------------------

#[test]
fn s2_defaults() {
    let d = QuinnConfig::default();
    assert_eq!(d.msg3_deadline, Duration::from_secs(5));
    assert_eq!(d.max_preauth_per_pair, 4);
}

/// Верный `msg1`, получен `msg2`, дальше тишина: место освобождается по `msg3_deadline`
/// (старый код держал его до `auth_deadline` 5 с); отказ тот же (код 0, пустая причина).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_after_msg2_closed_at_msg3_deadline() {
    let k = Keys::new();
    let c = QuinnConfig {
        msg3_deadline: Duration::from_millis(600),
        ..cfg()
    };
    let b = bind(c, vec![k.peer_b()]);
    let ep = raw_endpoint();
    let mut raw = raw_start(&ep, addr_of(&b), &k.peer_a()).await;
    let mut m2 = [0u8; chervo_identity::KK_MSG2_LEN];
    raw.rx.read_exact(&mut m2).await.unwrap();
    let t0 = Instant::now();
    assert_eq!(
        wait_closed(&raw.conn, Duration::from_secs(4)).await,
        REFUSED
    );
    let took = t0.elapsed();
    assert!(
        took < Duration::from_millis(2500),
        "закрыто по auth_deadline, а не по msg3_deadline: {took:?}"
    );
    assert_eq!(b.stats().auth_timeout, 1, "{:?}", b.stats());
    assert_eq!(b.stats().auth_ok, 0, "{:?}", b.stats());
    // честный звонящий с полным msg3 в срок проходит
    let (ok, _) = raw_full(&ep, addr_of(&b), &k.peer_a()).await;
    sleep_ms(1000).await;
    assert!(ok.close_reason().is_none(), "верный клиент закрыт по сроку");
}

/// Места пары: предел на пару, другая пара отдельно, возврат при сбросе, карта без пустых записей.
#[test]
fn preauth_pairs_cap_and_release() {
    let pairs = crate::limits::PreauthPairs::new(2);
    let (p, q) = (
        chervo_identity::PairId::from_bytes([1; 16]),
        chervo_identity::PairId::from_bytes([2; 16]),
    );
    let a = pairs.try_acquire(p).unwrap();
    let b = pairs.try_acquire(p).unwrap();
    assert!(pairs.try_acquire(p).is_none());
    let c = pairs.try_acquire(q).unwrap();
    drop(a);
    let d = pairs.try_acquire(p).unwrap();
    drop((b, c, d));
    assert_eq!(pairs.tracked(), 0);
}
