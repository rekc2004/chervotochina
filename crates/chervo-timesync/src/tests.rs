#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use super::*;

/// Миллисекунды -> NTP 32.32 (длительность, не момент).
fn d_ms(ms: i64) -> u64 {
    (((i128::from(ms)) << 32) / 1000) as u64
}

fn base_t() -> u64 {
    (3_900_000_000u64 << 32) | 0x1234_5678
}

/// Допустимый ответ: сервер впереди на `ahead_ms`, сетевая задержка 30 мс туда-обратно.
fn valid(origin: [u8; 8], t1: u64, ahead_ms: i64) -> ([u8; 48], u64) {
    let t2 = t1.wrapping_add(d_ms(ahead_ms + 10));
    let t3 = t1.wrapping_add(d_ms(ahead_ms + 20));
    let t4 = t1.wrapping_add(d_ms(30));
    let mut b = [0u8; 48];
    b[0] = 0x24; // LI 0, VN 4, mode 4
    b[1] = 2;
    b[24..32].copy_from_slice(&origin);
    b[32..40].copy_from_slice(&t2.to_be_bytes());
    b[40..48].copy_from_slice(&t3.to_be_bytes());
    (b, t4)
}

const ORIGIN: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[test]
fn parse_valid_vector() {
    let t1 = base_t();
    let (b, t4) = valid(ORIGIN, t1, 5000);
    let off = parse_response(&b, ORIGIN, t1, t4).unwrap();
    assert!((off - 5000).abs() <= 1, "поправка {off}");
    // сервер позади
    let (b, t4) = valid(ORIGIN, t1, -2500);
    let off = parse_response(&b, ORIGIN, t1, t4).unwrap();
    assert!((off + 2500).abs() <= 1, "поправка {off}");
    // длиннее 48 (расширения) допустимо до 1024
    let (b, t4) = valid(ORIGIN, t1, 0);
    let mut long = b.to_vec();
    long.resize(1024, 0xAA);
    assert!(parse_response(&long, ORIGIN, t1, t4).is_ok());
    long.resize(1025, 0xAA);
    assert!(parse_response(&long, ORIGIN, t1, t4).is_err());
}

#[test]
fn parse_rejects_each_field() {
    let t1 = base_t();
    let (good, t4) = valid(ORIGIN, t1, 100);
    let check = |name: &str, f: &dyn Fn(&mut [u8; 48])| {
        let mut b = good;
        f(&mut b);
        assert!(
            parse_response(&b, ORIGIN, t1, t4).is_err(),
            "принят ответ с неверным полем: {name}"
        );
    };
    check("LI 3", &|b| b[0] = (3 << 6) | (4 << 3) | 4);
    check("VN 2", &|b| b[0] = (2 << 3) | 4);
    check("VN 5", &|b| b[0] = (5 << 3) | 4);
    check("VN 0", &|b| b[0] = 4);
    for mode in [0u8, 1, 2, 3, 5, 6, 7] {
        let m = mode;
        check("mode", &move |b| b[0] = (4 << 3) | m);
    }
    check("stratum 0", &|b| b[1] = 0);
    check("stratum 16", &|b| b[1] = 16);
    check("stratum 255", &|b| b[1] = 255);
    check("чужой origin", &|b| b[24] ^= 1);
    check("чужой origin, последний байт", &|b| {
        b[31] ^= 0x80
    });
    check("transmit 0", &|b| b[40..48].fill(0));
    // root delay 2 с (16.16)
    check("root delay 2 с", &|b| {
        b[4..8].copy_from_slice(&0x2_0000u32.to_be_bytes())
    });
    check("root dispersion 2 с", &|b| {
        b[8..12].copy_from_slice(&0x2_0000u32.to_be_bytes())
    });
    // граница 1 с допустима
    let mut b = good;
    b[4..8].copy_from_slice(&0x1_0000u32.to_be_bytes());
    assert!(parse_response(&b, ORIGIN, t1, t4).is_ok());
    // длины 0..=47
    for n in 0..48 {
        assert!(
            parse_response(&good[..n], ORIGIN, t1, t4).is_err(),
            "длина {n}"
        );
    }
}

#[test]
fn parse_never_panics() {
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let origin = [0xAB; 8];
    for _ in 0..100_000 {
        let len = (next() % 1101) as usize;
        let mut buf = vec![0u8; len];
        for chunk in buf.chunks_mut(8) {
            let r = next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&r[..n]);
        }
        // половину буферов приводим к виду, близкому к допустимому, чтобы дойти до глубоких проверок
        if len >= 48 && next() % 2 == 0 {
            buf[0] = 0x24;
            buf[1] = 1 + (next() % 15) as u8;
            buf[4..12].fill(0);
        }
        let (t1, t4) = (next(), next());
        if parse_response(&buf, origin, t1, t4).is_ok() {
            assert_eq!(&buf[24..32], &origin, "принят ответ с неверным origin");
        }
    }
}

#[test]
fn offset_math_wraps() {
    // эра 2036: t1 перед переходом, сервер после перехода на 32 с
    let t1 = 0xFFFF_FFF0u64 << 32;
    let t2 = 0x0000_0010u64 << 32;
    let off = offset_ms(t1, t2, t2, t1);
    assert_eq!(off, 32_000);
    // и в обратную сторону
    assert_eq!(offset_ms(t2, t1, t1, t2), -32_000);
    // разность +-10 суток около границы
    let ten_days = 10u64 * 86_400;
    let t1 = (0xFFFF_FFFFu64 - 5) << 32;
    let t2 = t1.wrapping_add(ten_days << 32);
    assert_eq!(offset_ms(t1, t2, t2, t1), 864_000_000);
    let t2 = t1.wrapping_sub(ten_days << 32);
    assert_eq!(offset_ms(t1, t2, t2, t1), -864_000_000);
    // экстремум не вызывает паники
    let _ = offset_ms(0, u64::MAX, u64::MAX, 0);
    let _ = offset_ms(u64::MAX, 0, 0, u64::MAX);
}

fn cfg_n(n: usize) -> SyncConfig {
    SyncConfig {
        servers: (0..n).map(|i| format!("s{i}")).collect(),
        ..SyncConfig::default()
    }
}

#[test]
fn aggregate_median() {
    let cfg = cfg_n(3);
    let r = aggregate(vec![1000, 1100, 900], 3, 3, &cfg).unwrap();
    assert_eq!(r.offset_ms, 1000);
    assert_eq!((r.valid, r.queried), (3, 3));
    // чётное число: среднее двух средних
    let r = aggregate(vec![1000, 1200], 2, 2, &cfg_n(2)).unwrap();
    assert_eq!(r.offset_ms, 1100);
    // один выброс вне разброса: медиана по остальным, допустимых достаточно
    let r = aggregate(vec![1000, 1050, 90_000], 3, 3, &cfg).unwrap();
    assert_eq!(r.offset_ms, 1050);
}

#[test]
fn aggregate_disagree() {
    let cfg = cfg_n(2);
    assert_eq!(
        aggregate(vec![0, 5_000], 2, 2, &cfg).err(),
        Some(SyncError::Disagree)
    );
    let cfg = cfg_n(3);
    assert_eq!(
        aggregate(vec![0, 5_000, 20_000], 3, 3, &cfg).err(),
        Some(SyncError::Disagree)
    );
    assert_eq!(
        aggregate(vec![5_000], 3, 3, &cfg).err(),
        Some(SyncError::TooFewValid)
    );
}

#[test]
fn aggregate_too_large() {
    let cfg = cfg_n(2);
    let week = 7 * 24 * 3600 * 1000i64;
    assert!(aggregate(vec![week, week], 2, 2, &cfg).is_ok());
    assert_eq!(
        aggregate(vec![week + 1, week + 1], 2, 2, &cfg).err(),
        Some(SyncError::TooLarge)
    );
    assert_eq!(
        aggregate(vec![-week - 1, -week - 1], 2, 2, &cfg).err(),
        Some(SyncError::TooLarge)
    );
}

#[test]
fn aggregate_single_server() {
    // один сервер в списке: порог min(2, 1) = 1
    let cfg = cfg_n(1);
    let r = aggregate(vec![250], 1, 1, &cfg).unwrap();
    assert_eq!(r.offset_ms, 250);
    // пустой набор значений
    assert_eq!(
        aggregate(vec![], 1, 1, &cfg).err(),
        Some(SyncError::TooFewValid)
    );
}

#[test]
fn sync_no_servers() {
    let cfg = SyncConfig {
        servers: vec![],
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::NoServers));
    let cfg = SyncConfig {
        servers: vec![String::new(), "x".repeat(300)],
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::NoServers));
    assert_eq!(
        SyncError::NoServers.to_string(),
        "no time servers configured"
    );
}

/// Локальный фиктивный сервер: отвечает `requests` раз; режим `junk_first` сначала шлёт чужой
/// ответ с неверным origin.
fn fake_server(
    ahead_ms: i64,
    junk_first: bool,
    wrong_origin_only: bool,
) -> (String, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = sock.local_addr().unwrap();
    let h = thread::spawn(move || {
        let mut buf = [0u8; 64];
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return;
        };
        assert_eq!(n, 48);
        assert_eq!(buf[0], 0x23);
        let mut origin = [0u8; 8];
        origin.copy_from_slice(&buf[40..48]);
        let now = ntp_now();
        let make = |origin: [u8; 8]| {
            let mut b = [0u8; 48];
            b[0] = 0x24;
            b[1] = 2;
            b[24..32].copy_from_slice(&origin);
            let t = now.wrapping_add(d_ms(ahead_ms));
            b[32..40].copy_from_slice(&t.to_be_bytes());
            b[40..48].copy_from_slice(&t.to_be_bytes());
            b
        };
        if junk_first || wrong_origin_only {
            let mut bad = origin;
            bad[0] ^= 0xFF;
            let _ = sock.send_to(&make(bad), from);
        }
        if !wrong_origin_only {
            let _ = sock.send_to(&make(origin), from);
        }
    });
    (addr.to_string(), h)
}

/// Фиктивный сервер, отвечающий верно на `count` запросов подряд.
fn fake_server_multi(ahead_ms: i64, count: usize) -> (String, thread::JoinHandle<usize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let h = thread::spawn(move || {
        let mut answered = 0usize;
        let mut buf = [0u8; 64];
        while answered < count {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                break;
            };
            assert_eq!(n, 48);
            let mut b = [0u8; 48];
            b[0] = 0x24;
            b[1] = 2;
            b[24..32].copy_from_slice(&buf[40..48]);
            let t = ntp_now().wrapping_add(d_ms(ahead_ms));
            b[32..40].copy_from_slice(&t.to_be_bytes());
            b[40..48].copy_from_slice(&t.to_be_bytes());
            let _ = sock.send_to(&b, from);
            answered += 1;
        }
        answered
    });
    (addr.to_string(), h)
}

#[test]
fn duplicate_server_addresses_count_once() {
    // одно имя дважды: опрашивается и учитывается один раз
    let (a1, h1) = fake_server_multi(1000, 2);
    let cfg = SyncConfig {
        servers: vec![a1.clone(), a1.clone()],
        min_valid: 1,
        timeout: Duration::from_millis(800),
        ..SyncConfig::default()
    };
    let r = sync_clock(&cfg).unwrap();
    assert_eq!((r.valid, r.queried), (1, 1), "дубликат учтён дважды");
    assert_eq!(
        h1.join().unwrap(),
        1,
        "сервер получил больше одного запроса"
    );

    // порог «два сервера» не выполняется одним сервером под двумя именами
    let (a1, h1) = fake_server_multi(1000, 2);
    let cfg = SyncConfig {
        servers: vec![a1.clone(), a1],
        min_valid: 2,
        timeout: Duration::from_millis(800),
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::TooFewValid));
    assert_eq!(h1.join().unwrap(), 1);
}

#[test]
fn sync_clock_loopback() {
    // два сервера впереди на 3 с (один сначала шлёт чужой ответ), допустимых 2
    let (a1, h1) = fake_server(3000, false, false);
    let (a2, h2) = fake_server(3000, true, false);
    let cfg = SyncConfig {
        servers: vec![a1, a2],
        ..SyncConfig::default()
    };
    let r = sync_clock(&cfg).unwrap();
    assert!((r.offset_ms - 3000).abs() < 300, "поправка {}", r.offset_ms);
    assert_eq!((r.valid, r.queried), (2, 2));
    h1.join().unwrap();
    h2.join().unwrap();

    // сервер отвечает только с чужим origin: ответ не учитывается
    let (a1, h1) = fake_server(3000, false, true);
    let cfg = SyncConfig {
        servers: vec![a1],
        timeout: Duration::from_millis(600),
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::TooFewValid));
    h1.join().unwrap();

    // два сервера расходятся на 10 с
    let (a1, h1) = fake_server(0, false, false);
    let (a2, h2) = fake_server(10_000, false, false);
    let cfg = SyncConfig {
        servers: vec![a1, a2],
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::Disagree));
    h1.join().unwrap();
    h2.join().unwrap();

    // поправка свыше недели
    let (a1, h1) = fake_server(8 * 86_400 * 1000, false, false);
    let cfg = SyncConfig {
        servers: vec![a1],
        ..SyncConfig::default()
    };
    assert_eq!(sync_clock(&cfg).err(), Some(SyncError::TooLarge));
    h1.join().unwrap();
}

#[test]
#[ignore = "сеть: реальные серверы, запускать вручную на машине с интернетом"]
fn sync_real_servers() {
    let r = sync_clock(&SyncConfig::default());
    assert!(r.is_ok(), "{r:?}");
}
