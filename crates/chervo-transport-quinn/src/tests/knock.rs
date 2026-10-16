//! Стук: порт молчит для чужих; друг соединяется. Сырой атакующий считает пакеты, дошедшие до его
//! гнезда: «0 пакетов» = счётчик равен нулю после ожидания. У каждого теста тишины есть
//! положительный контроль: те же действия при `knock_required: false` дают ответ.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use chervo_identity::KnockKeys;
use chervo_transport::Transport;

use super::kit::*;
use crate::{QuinnConfig, TransportEvent, TransportStats};

fn kc(required: bool) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        knock_required: required,
        ..QuinnConfig::default()
    }
}

struct Outcome {
    received: u64,
    stats: TransportStats,
    skew_event: bool,
}

/// Запускает сценарий при `knock_required: true` и (контроль) `false` одновременно.
async fn silent<F, Fut>(name: &str, f: F) -> Outcome
where
    F: Fn(bool) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let (on, off) = tokio::join!(f(true), f(false));
    assert!(off.received > 0, "{name}: нет контроля (при false тишина)");
    assert_eq!(on.received, 0, "{name}: атакующему пришли пакеты");
    on
}

fn friend_knock(k: &Keys, window: u64) -> [u8; 48] {
    let keys: KnockKeys = k.peer_a().knock_keys().unwrap();
    keys.make(window).unwrap()
}

/// Быстрый ГСЧ для заполнения шума (не криптография).
fn noise_fill(state: &mut u64, buf: &mut [u8]) {
    for b in buf {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *b = (*state >> 24) as u8;
    }
}

async fn settle() {
    sleep_ms(2000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_noise() {
    let on = silent("noise", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        let at = Attacker::new();
        let dest = addr_of(&b);
        let mut st = 0x9E37_79B9_7F4A_7C15u64;
        let mut buf = vec![0u8; 1500];
        for i in 0..2000usize {
            // 1700 датаграмм длин 1..=1500 и 300 по 48 байт
            let len = if i < 1700 { i % 1500 + 1 } else { 48 };
            noise_fill(&mut st, &mut buf[..len]);
            at.send(dest, &buf[..len]);
            if i % 100 == 0 {
                sleep_ms(5).await;
            }
        }
        settle().await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert!(on.stats.dropped_unadmitted >= 1);
    assert_eq!(on.stats.retry_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_initial_without_knock() {
    let on = silent("initial", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        let at = Attacker::new();
        let _ = at.initial(addr_of(&b), Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert!(on.stats.dropped_unadmitted >= 1);
    assert_eq!(on.stats.retry_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_stranger_knock() {
    let on = silent("stranger", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        // верный формат, но пара не в наборе вызываемого
        let other = Keys::new();
        let knock = friend_knock(&other, now_window());
        let at = Attacker::new();
        let dest = addr_of(&b);
        at.send(dest, &knock);
        sleep_ms(100).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert_eq!(on.stats.knock_ok, 0);
    assert_eq!(on.stats.retry_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_stale_window() {
    let on = silent("stale", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        let mut ev = b.events();
        let at = Attacker::new();
        let dest = addr_of(&b);
        let w = now_window();
        at.send(dest, &friend_knock(&k, w - 2));
        at.send(dest, &friend_knock(&k, w + 3));
        sleep_ms(100).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        let mut skew_event = false;
        while let Ok(e) = ev.try_recv() {
            if let TransportEvent::ClockSkewSuspected { pair } = e {
                assert_eq!(pair, k.pid);
                skew_event = true;
            }
        }
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event,
        }
    })
    .await;
    assert!(on.stats.knock_skewed >= 1, "knock_skewed = 0");
    assert!(on.skew_event, "нет события ClockSkewSuspected");
    assert_eq!(on.stats.knock_ok, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_replayed_knock() {
    let on = silent("replay", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        let dest = addr_of(&b);
        let knock = friend_knock(&k, now_window());
        // оригинал уходит с одного гнезда (друг), копия с другого (наблюдатель)
        let friend_sock = Attacker::new();
        friend_sock.send(dest, &knock);
        sleep_ms(200).await;
        let at = Attacker::new();
        at.send(dest, &knock);
        sleep_ms(100).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert!(on.stats.knock_replay >= 1, "knock_replay = 0");
    assert_eq!(on.stats.knock_ok, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_blocked_pair() {
    let on = silent("blocked", |req| async move {
        let k = Keys::new();
        let filter = Arc::new(BlockSet::default());
        filter.0.lock().unwrap().insert(k.pid);
        let b = bind_with(kc(req), vec![k.peer_b()], filter);
        let at = Attacker::new();
        let dest = addr_of(&b);
        at.send(dest, &friend_knock(&k, now_window()));
        sleep_ms(100).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert_eq!(on.stats.knock_ok, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_after_admit_expired() {
    let on = silent("expired", |req| async move {
        let k = Keys::new();
        let cfg = QuinnConfig {
            knock_admit_ttl: Duration::from_millis(300),
            ..kc(req)
        };
        let b = bind(cfg, vec![k.peer_b()]);
        let at = Attacker::new();
        let dest = addr_of(&b);
        at.send(dest, &friend_knock(&k, now_window()));
        // допуск истекает раньше, чем приходит Initial
        sleep_ms(600).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert_eq!(on.stats.knock_ok, 1);
    assert_eq!(on.stats.retry_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admit_attempts_bounded() {
    let k = Keys::new();
    let cfg = QuinnConfig {
        knock_admit_attempts: 1,
        auth_deadline: Duration::from_secs(2),
        ..kc(true)
    };
    let b = bind(cfg, vec![k.peer_b()]);
    let at = Attacker::new();
    let dest = addr_of(&b);
    at.send(dest, &friend_knock(&k, now_window()));
    sleep_ms(100).await;
    // первое подтверждённое рукопожатие использует единственную попытку (контроль: оно удалось)
    assert!(
        at.initial(dest, Duration::from_secs(3)).await,
        "нет контроля: первое рукопожатие должно удаться"
    );
    assert_eq!(b.stats().admit_exhausted, 0);
    // второе с того же адреса: Retry без состояния, но подтверждённый Initial не принят
    assert!(!at.initial(dest, Duration::from_secs(2)).await);
    assert!(b.stats().admit_exhausted >= 1, "admit_exhausted = 0");
    assert_eq!(b.stats().knock_ok, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_pin_no_incoming() {
    let k = Keys::new();
    let a = Arc::new(bind(kc(true), vec![k.peer_a()]));
    let a_addr = addr_of(&a);
    // X: сырой эндпоинт, который не принимает входящих, то есть звонок A к нему висит
    let x = server_endpoint(&kc(false));
    let x_addr = ep_addr(&x);
    let a2 = a.clone();
    let call = tokio::spawn(async move {
        a2.connect(&crate::tests::kit::peer_addr_raw(k.pid, x_addr))
            .await
    });
    sleep_ms(300).await;
    // пока A звонит X, X (с того же адреса) звонит A без стука: новое `Incoming` не принимается
    let ok = tokio::time::timeout(Duration::from_secs(2), raw_tls(&x, a_addr)).await;
    assert!(!matches!(ok, Ok(Ok(_))), "входящее от X принято");
    assert!(a.stats().admit_exhausted >= 1, "admit_exhausted = 0");
    assert_eq!(a.stats().auth_ok, 0);
    let got = tokio::time::timeout(Duration::from_millis(300), a.accept()).await;
    assert!(got.is_err(), "accept вернул соединение");
    call.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn friend_connects_with_knock() {
    let k = Keys::new();
    let a = bind(kc(true), vec![k.peer_a()]);
    let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    assert_eq!(chervo_transport::Connection::remote_pair(&ca), k.pid);
    assert_eq!(chervo_transport::Connection::remote_pair(&cb), k.pid);
    let st = b.stats();
    assert!(st.knock_ok >= 1);
    assert!(st.retry_sent >= 1);
    assert_eq!(st.auth_ok, 1);
    assert_eq!(a.stats().connect_silent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flood_knocks_friend_passes() {
    let k = Keys::new();
    let a = bind(kc(true), vec![k.peer_a()]);
    let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
    let dest = addr_of(&b);
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let mut floods = Vec::new();
    for n in 0..4u64 {
        let sock = std::net::UdpSocket::bind(lo()).unwrap();
        let sock = Arc::new(sock);
        let s2 = sock.clone();
        let h = tokio::task::spawn_blocking(move || {
            let mut st = 0x1234_5678_9ABC_DEF1u64.wrapping_add(n);
            let mut buf = [0u8; 48];
            for _ in 0..25_000 {
                noise_fill(&mut st, &mut buf);
                let _ = s2.send_to(&buf, dest);
            }
        });
        floods.push((sock, h));
    }
    sleep_ms(50).await;
    let ca = tokio::time::timeout(Duration::from_secs(5), a.connect(&peer_addr(k.pid, &b)))
        .await
        .expect("друг не уложился в auth_deadline")
        .unwrap();
    let _cb = acc.await.unwrap().unwrap();
    drop(ca);
    for (sock, h) in floods {
        h.await.unwrap();
        sock.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 2048];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "гнезду флуда пришёл пакет"
        );
    }
    assert!(b.stats().dropped_unadmitted >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clock_skew_within_tolerance() {
    for off in [25_000i64, -25_000] {
        let k = Keys::new();
        let a = bind(kc(true), vec![k.peer_a()]);
        a.set_clock_offset(off);
        assert_eq!(a.clock_offset_ms(), off);
        let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
        let b2 = b.clone();
        let acc = tokio::spawn(async move { b2.accept().await });
        a.connect(&peer_addr(k.pid, &b))
            .await
            .unwrap_or_else(|e| panic!("поправка {off} мс: {e:?}"));
        acc.await.unwrap().unwrap();
        assert_eq!(b.stats().knock_skewed, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clock_skew_outside_tolerance() {
    for skew in [120_000i64, -120_000] {
        let k = Keys::new();
        let cfg = QuinnConfig {
            auth_deadline: Duration::from_secs(3),
            ..kc(true)
        };
        let a = bind(cfg, vec![k.peer_a()]);
        // системные часы звонящего расходятся с часами вызываемого
        a.inner.knock.sys_skew_ms.store(skew, Ordering::Relaxed);
        let b = bind(kc(true), vec![k.peer_b()]);
        let mut ev = b.events();
        let r = a.connect(&peer_addr(k.pid, &b)).await;
        assert_eq!(
            r.err(),
            Some(chervo_transport::TransportError::TimedOut),
            "расхождение {skew} мс"
        );
        assert!(b.stats().knock_skewed >= 1, "knock_skewed = 0");
        assert!(matches!(
            ev.try_recv(),
            Ok(TransportEvent::ClockSkewSuspected { .. })
        ));
        assert_eq!(a.stats().connect_silent, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_offset_raw_fallback() {
    let k = Keys::new();
    let cfg = QuinnConfig {
        knock_resend_after: Duration::from_millis(300),
        ..kc(true)
    };
    let a = bind(cfg, vec![k.peer_a()]);
    // поправка устарела (+300 с), системные часы верны: третий стук по системному времени
    a.set_clock_offset(300_000);
    let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    acc.await.unwrap().unwrap();
    assert!(
        b.stats().knock_skewed >= 1,
        "первые стуки должны быть в подсказке"
    );
    assert_eq!(b.stats().knock_ok, 1, "допуск ровно по третьему стуку");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebind_reknock() {
    use chervo_transport::Connection;
    let k = Keys::new();
    let cfg = QuinnConfig {
        addr_poll: Duration::from_millis(100),
        ..kc(true)
    };
    let a = bind(cfg.clone(), vec![k.peer_a()]);
    let b = Arc::new(bind(cfg, vec![k.peer_b()]));
    let mut events = b.events();
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let conn_a = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let conn_b = acc.await.unwrap().unwrap();
    let ok_before = b.stats().knock_ok;
    let old_port = conn_b.remote_addr().port();
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_port = new_sock.local_addr().unwrap().port();
    assert_ne!(old_port, new_port);
    a.rebind(new_sock).unwrap();
    let (mut tx, mut rx) = conn_a.open_bi().await.unwrap();
    use chervo_transport::{RecvStream, SendStream};
    tx.write_all(b"ping").await.unwrap();
    tx.finish().unwrap();
    let (mut btx, mut brx) = conn_b.accept_bi().await.unwrap();
    let mut got = [0u8; 4];
    let mut n = 0;
    while n < 4 {
        match tokio::time::timeout(Duration::from_secs(5), brx.read(&mut got[n..]))
            .await
            .expect("данные после rebind")
            .unwrap()
        {
            Some(m) => n += m,
            None => break,
        }
    }
    assert_eq!(&got, b"ping");
    btx.write_all(b"pong").await.unwrap();
    btx.finish().unwrap();
    let mut back = [0u8; 4];
    let mut m = 0;
    while m < 4 {
        match tokio::time::timeout(Duration::from_secs(5), rx.read(&mut back[m..]))
            .await
            .expect("ответ после rebind")
            .unwrap()
        {
            Some(x) => m += x,
            None => break,
        }
    }
    assert_eq!(&back, b"pong");
    let pair = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(TransportEvent::RemoteAddrChanged { pair }) = events.recv().await {
                return pair;
            }
        }
    })
    .await
    .expect("RemoteAddrChanged за 3 с");
    assert_eq!(pair, k.pid);
    assert_eq!(conn_b.remote_addr().port(), new_port);
    assert!(
        b.stats().knock_ok > ok_before,
        "после rebind должен прийти новый стук"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_knock_connect() {
    use super::misc::{collect_accepts, survivors};
    for round in 0..10 {
        let k = Keys::new();
        let a = Arc::new(bind(kc(true), vec![k.peer_a()]));
        let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
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
    }
}

/// Повтор стука, ушедшего на адрес в состоянии `Open` (досланный при медленном рукопожатии или
/// после `rebind`), с другого адреса не даёт допуска: стук на `Open`-адресе тоже в кэше повторов.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_to_replay_of_knock_sent_to_open_address() {
    let on = silent("replay_open", |req| async move {
        let k = Keys::new();
        let b = bind(kc(req), vec![k.peer_b()]);
        let dest = addr_of(&b);
        let w = now_window();
        let first = friend_knock(&k, w);
        let resent = friend_knock(&k, w);
        assert_ne!(first, resent);
        let friend_sock = Attacker::new();
        friend_sock.send(dest, &first);
        sleep_ms(200).await;
        // допуск друга открыт; второй стук приходит на Open-адрес
        friend_sock.send(dest, &resent);
        sleep_ms(200).await;
        let at = Attacker::new();
        at.send(dest, &resent);
        sleep_ms(100).await;
        let _ = at.initial(dest, Duration::from_secs(2)).await;
        Outcome {
            received: at.received(),
            stats: b.stats(),
            skew_event: false,
        }
    })
    .await;
    assert!(on.stats.knock_replay >= 1, "knock_replay = 0");
    assert_eq!(
        on.stats.knock_ok, 2,
        "оба стука друга приняты на его адресе"
    );
    assert_eq!(on.stats.retry_sent, 0);
}

/// Состояние стука без сети: ключи вызываемого, допуск открывается прямым стуком.
fn bare_state(
    k: &Keys,
    filter: Arc<dyn chervo_transport::PeerFilter>,
) -> (Arc<crate::knock::KnockState>, Arc<crate::limits::Counters>) {
    use quinn::Runtime;
    let counters = Arc::new(crate::limits::Counters::default());
    let (events, _) = tokio::sync::broadcast::channel(8);
    let std_sock = std::net::UdpSocket::bind(lo()).unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
    let state = crate::knock::KnockState::new(&kc(true), counters.clone(), filter, events, raw);
    state.set_peers(&[k.peer_b()]);
    (state, counters)
}

fn one_batch(
    state: &crate::knock::KnockState,
    addr: std::net::SocketAddr,
    payload: &[u8],
    stride: usize,
) -> (usize, usize, Vec<u8>) {
    use quinn::udp::RecvMeta;
    use std::io::IoSliceMut;
    let mut storage = [0u8; 2048];
    storage[..payload.len()].copy_from_slice(payload);
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    meta[0].addr = addr;
    meta[0].len = payload.len();
    meta[0].stride = stride;
    let kept = state.filter_batch(&mut bufs, &mut meta, 1);
    let len = meta[0].len;
    let data = bufs[0][..len].to_vec();
    (kept, len, data)
}

/// Сегменты GRO на `Open`/`Pass`-адресе разбираются: стуки вырезаются и попадают в кэш повторов,
/// прочие сегменты проходят.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gro_segments_on_open_address() {
    let k = Keys::new();
    let (state, counters) = bare_state(&k, Arc::new(AllowAll));
    let w = now_window();
    let friend: std::net::SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let other: std::net::SocketAddr = "127.0.0.1:40002".parse().unwrap();
    let rd = |c: &std::sync::atomic::AtomicU64| c.load(Ordering::Relaxed);
    // допуск друга
    let (kept, ..) = one_batch(&state, friend, &friend_knock(&k, w), 48);
    assert_eq!(kept, 0);
    assert_eq!(rd(&counters.knock_ok), 1);
    // два склеенных стука на Open-адресе: оба потреблены, quinn ничего не получает
    let (k2, k3) = (friend_knock(&k, w), friend_knock(&k, w));
    let both: Vec<u8> = [k2, k3].concat();
    let (kept, ..) = one_batch(&state, friend, &both, 48);
    assert_eq!(kept, 0, "склеенные стуки отданы quinn");
    assert_eq!(rd(&counters.knock_ok), 3);
    // стук и обычный пакет: проходит только обычный, без искажений
    let (k4, junk) = (friend_knock(&k, w), [0x5Au8; 48]);
    let mixed: Vec<u8> = [&junk[..], &k4[..]].concat();
    let (kept, len, data) = one_batch(&state, friend, &mixed, 48);
    assert_eq!((kept, len), (1, 48));
    assert_eq!(data, junk);
    // стук раньше короткого последнего сегмента: короткий сдвигается на место стука
    let (k5, tail) = (friend_knock(&k, w), [0xA5u8; 20]);
    let mixed: Vec<u8> = [&k5[..], &tail[..]].concat();
    let (kept, len, data) = one_batch(&state, friend, &mixed, 48);
    assert_eq!((kept, len), (1, 20));
    assert_eq!(data, tail);
    // повтор любого из них с другого адреса: допуска нет
    let before = rd(&counters.knock_ok);
    for knock in [k2, k3, k4, k5] {
        let (kept, ..) = one_batch(&state, other, &knock, 48);
        assert_eq!(kept, 0);
    }
    assert_eq!(rd(&counters.knock_ok), before, "повтор дал допуск");
    assert_eq!(rd(&counters.knock_replay), 4);
    let (kept, ..) = one_batch(&state, other, &[7u8; 100], 100);
    assert_eq!(kept, 0, "чужой адрес допущен");
}

/// Жизнь записи кэша повторов покрывает оба окна приёма при поправке часов больше 30 с.
#[test]
fn replay_lifetime_covers_offset() {
    use crate::knock::{Replay, ReplayErr};
    use std::time::Instant;
    let t0 = Instant::now();
    let s = Duration::from_secs;
    let key = (chervo_identity::PairId::generate().unwrap(), [1u8; 16]);
    let seen = |r: &mut Replay, at: Duration, off: i64| {
        matches!(r.check_insert(key, t0 + at, off), Err(ReplayErr::Seen))
    };

    // без поправки 120 с хватает, дальше запись забывается
    let mut r = Replay::new(8);
    assert!(r.check_insert(key, t0, 0).is_ok());
    assert!(seen(&mut r, s(119), 0));
    assert!(!seen(&mut r, s(121), 0));

    // поправка +-300 с: повтор в позднем интервале (спустя 121 с и 419 с) отвергается
    for off in [300_000i64, -300_000] {
        let mut r = Replay::new(8);
        assert!(r.check_insert(key, t0, off).is_ok());
        assert!(seen(&mut r, s(121), off), "off={off}: забыт через 121 с");
        assert!(seen(&mut r, s(419), off), "off={off}: забыт через 419 с");
        assert!(
            !seen(&mut r, s(421), off),
            "off={off}: не забыт после срока"
        );
    }

    // поправка задана после внесения записи: срок продлевается
    let mut r = Replay::new(8);
    assert!(r.check_insert(key, t0, 0).is_ok());
    r.extend_for_offset(t0 + s(10), 300_000);
    assert!(seen(&mut r, s(300), 0), "забыт после смены поправки");
}

/// Подсказка о расхождении часов только после `PeerFilter`: заблокированная пара её не вызывает.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_pair_no_skew_hint() {
    let k = Keys::new();
    let filter = Arc::new(BlockSet::default());
    filter.0.lock().unwrap().insert(k.pid);
    let b = bind_with(kc(true), vec![k.peer_b()], filter);
    let mut ev = b.events();
    let at = Attacker::new();
    at.send(addr_of(&b), &friend_knock(&k, now_window() - 2));
    sleep_ms(300).await;
    assert_eq!(b.stats().knock_skewed, 0);
    assert!(ev.try_recv().is_err(), "событие для заблокированной пары");
    // контроль: у разрешённой пары тот же стук даёт подсказку
    let b2 = bind(kc(true), vec![k.peer_b()]);
    let mut ev2 = b2.events();
    at.send(addr_of(&b2), &friend_knock(&k, now_window() - 2));
    sleep_ms(300).await;
    assert_eq!(b2.stats().knock_skewed, 1);
    assert!(matches!(
        ev2.try_recv(),
        Ok(TransportEvent::ClockSkewSuspected { .. })
    ));
}

/// При `knock_required: true` слой KK по-прежнему работает: допущенный верным стуком сырой клиент
/// с чужими ключами KK отвергается, друг проходит. Стук выводится из тех же ключей, что и KK, поэтому
/// «верный стук, но неверная пара» достижим только как перехваченный стук друга у посторонних
/// ключей KK.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn knock_gate_then_kk_rejects_stranger() {
    let k = Keys::new();
    let b = Arc::new(bind(kc(true), vec![k.peer_b()]));
    let dest = addr_of(&b);
    // посторонний с копией стука друга (допуск открыт), но ключами KK не той пары
    let at = Attacker::new();
    at.send(dest, &friend_knock(&k, now_window()));
    sleep_ms(200).await;
    let mut raw = raw_start(&at.ep, dest, &stranger_peer(k.pid, k.b.kx_public)).await;
    let (bytes, seen) = drain(&mut raw.rx, Duration::from_secs(4)).await;
    assert!(bytes.is_empty(), "посторонний получил ответ KK");
    assert_eq!(seen, REFUSED);
    assert_eq!(b.stats().knock_ok, 1);
    assert_eq!(b.stats().auth_ok, 0);
    assert!(b.stats().auth_failed >= 1);
    // друг со стуком проходит
    let a = bind(kc(true), vec![k.peer_a()]);
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    acc.await.unwrap().unwrap();
    assert_eq!(b.stats().auth_ok, 1);
}

/// Модульный: фильтр уступает исполнителю под потоком мусора.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filter_yields_under_flood() {
    use quinn::Runtime;
    use quinn::udp::RecvMeta;
    use std::io::IoSliceMut;
    use std::task::{Context, Poll, Wake};

    struct Flag(std::sync::atomic::AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let k = Keys::new();
    let cfg = kc(true);
    let counters = Arc::new(crate::limits::Counters::default());
    let (events, _) = tokio::sync::broadcast::channel(8);
    let std_sock = std::net::UdpSocket::bind(lo()).unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let dest = ep_addr_of_pub(&std_sock);
    let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
    let state = crate::knock::KnockState::new(
        &cfg,
        counters.clone(),
        Arc::new(AllowAll),
        events,
        raw.clone(),
    );
    state.set_peers(&[k.peer_b()]);
    let sock = crate::knock::KnockSocket::new(raw, state);
    let sender = std::net::UdpSocket::bind(lo()).unwrap();
    for i in 0..10_000u32 {
        let _ = sender.send_to(&[(i % 251) as u8; 64], dest);
    }
    sleep_ms(200).await;
    let flag = Arc::new(Flag(std::sync::atomic::AtomicBool::new(false)));
    let waker = std::task::Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 2048];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    use quinn::AsyncUdpSocket;
    let r = sock.poll_recv(&mut cx, &mut bufs, &mut meta);
    assert!(
        matches!(r, Poll::Pending),
        "ожидали Pending, получили {r:?}"
    );
    assert!(
        flag.0.load(Ordering::SeqCst),
        "Pending без wake_by_ref: цикл вышел не по лимиту опросов"
    );
    // ровно 16 опросов по одной записи, ни одной не передано quinn
    assert_eq!(
        counters.dropped_unadmitted.load(Ordering::Relaxed),
        crate::knock::MAX_FILTER_POLLS as u64
    );
}

fn ep_addr_of_pub(s: &std::net::UdpSocket) -> std::net::SocketAddr {
    std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), s.local_addr().unwrap().port())
}

/// Замер: пересборка таблицы и проверка 48 случайных байт при N парах.
#[test]
#[ignore = "замер; запускать в --release с --nocapture"]
#[allow(clippy::print_stdout)]
fn knock_table_cost() {
    use quinn::Runtime;
    println!("knock_table_cost: N | set_peers мс | пересборка таблицы мс | проверка 48 Б, мкс");
    for n in [10usize, 200, 1000] {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _g = rt.enter();
        let peers: Vec<_> = (0..n).map(|_| Keys::new().peer_b()).collect();
        let std_sock = std::net::UdpSocket::bind(lo()).unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
        let (events, _) = tokio::sync::broadcast::channel(8);
        let state = crate::knock::KnockState::new(
            &kc(true),
            Arc::new(crate::limits::Counters::default()),
            Arc::new(AllowAll),
            events,
            raw,
        );
        let t = std::time::Instant::now();
        state.set_peers(&peers);
        let set_ms = t.elapsed().as_secs_f64() * 1e3;
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut buf = [0u8; 48];
        let mut st = 0xDEAD_BEEFu64;
        noise_fill(&mut st, &mut buf);
        let t = std::time::Instant::now();
        let _ = state.try_knock(addr, &buf);
        let rebuild_ms = t.elapsed().as_secs_f64() * 1e3;
        let reps = 20_000u32;
        let t = std::time::Instant::now();
        for _ in 0..reps {
            noise_fill(&mut st, &mut buf);
            let _ = state.try_knock(addr, &buf);
        }
        let check_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(reps);
        println!("knock_table_cost: {n} | {set_ms:.2} | {rebuild_ms:.2} | {check_us:.3}");
    }
}
