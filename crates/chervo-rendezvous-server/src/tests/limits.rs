//! Лимиты и отбор источников без сети.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use chervo_rendezvous_wire::{Nonce, encode_echo_request, encode_reach_request};

use crate::limiter::{Key, Limiter, key_of};
use crate::{Action, Counters, ServerConfig, Shared, report_line, start_line};

fn shared(allow_private: bool, reach_port: Option<u16>, now: Instant) -> Shared {
    let cfg = ServerConfig {
        listen: vec![],
        reach_port,
        allow_private,
        report_every: Duration::from_secs(60),
    };
    Shared::new(&cfg, Limiter::new(now))
}

fn src(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn nonce(i: u8) -> Nonce {
    Nonce([i; 16])
}

#[test]
fn rate_limit_per_ip_shared_echo_and_reach() {
    let now = Instant::now();
    let s = shared(true, Some(45_901), now);
    let from = src(127, 0, 0, 1, 5000);
    let mut answered = 0;
    for i in 0..17u8 {
        // эхо и проверка делят один счёт
        let data = if i % 2 == 0 {
            encode_echo_request(&nonce(i)).to_vec()
        } else {
            encode_reach_request(&nonce(i), 6000).to_vec()
        };
        if s.handle(from, &data, now) != Action::Drop {
            answered += 1;
        }
    }
    assert_eq!(answered, 16);
    let c = s.snapshot();
    assert_eq!(c.requests, 17);
    assert_eq!(c.limited, 1);
    // другой IP не задет
    let other = src(127, 0, 0, 2, 5000);
    assert_ne!(
        s.handle(other, &encode_echo_request(&nonce(1)), now),
        Action::Drop
    );
    // через окно лимит обновляется
    let later = now + Duration::from_secs(11);
    assert_ne!(
        s.handle(from, &encode_echo_request(&nonce(2)), later),
        Action::Drop
    );
}

#[test]
fn global_limit() {
    let now = Instant::now();
    let mut l = Limiter::new(now);
    let mut ok = 0;
    for i in 0..1500u32 {
        if l.allow(Key::V4(i), now) {
            ok += 1;
        }
    }
    assert_eq!(ok, 1000, "не больше 1000 ответов в секунду");
    // в следующую секунду снова можно
    assert!(l.allow(Key::V4(5000), now + Duration::from_millis(1100)));
}

#[test]
fn tracked_cap_new_key_limited() {
    let now = Instant::now();
    let mut l = Limiter::with_limits(16, Duration::from_secs(10), 3, 1000, now);
    for i in 0..3u32 {
        assert!(l.allow(Key::V4(i), now));
    }
    assert!(
        !l.allow(Key::V4(99), now),
        "таблица полна: новый ключ отказан сразу"
    );
    assert!(
        l.allow(Key::V4(1), now),
        "известный ключ ещё в пределах лимита"
    );
    assert_eq!(l.tracked(), 3);
    // окно истекло: старые ключи выброшены, новый проходит
    let later = now + Duration::from_secs(12);
    assert!(l.allow(Key::V4(99), later));
    assert!(l.tracked() <= 3);
    assert_eq!(l.tracked(), 1, "устаревшие ключи не хранятся");
}

#[test]
fn ipv6_key_is_slash64() {
    let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:1:2:ffff:eeee:dddd:cccc".parse().unwrap();
    let c: Ipv6Addr = "2001:db8:1:3::1".parse().unwrap();
    assert_eq!(key_of(IpAddr::V6(a)), key_of(IpAddr::V6(b)));
    assert_ne!(key_of(IpAddr::V6(a)), key_of(IpAddr::V6(c)));
    // IPv4 в обёртке `::ffff:a.b.c.d` считается как IPv4
    let v4 = Ipv4Addr::new(203, 0, 113, 9);
    assert_eq!(
        key_of(IpAddr::V6(v4.to_ipv6_mapped())),
        key_of(IpAddr::V4(v4))
    );
    // 17 запросов из одной сети /64 с разных хостов: ответов 16
    let now = Instant::now();
    let mut l = Limiter::new(now);
    let mut ok = 0;
    for i in 0..17u16 {
        let host = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, i);
        if l.allow(key_of(IpAddr::V6(host)), now) {
            ok += 1;
        }
    }
    assert_eq!(ok, 16);
}

#[test]
fn bad_sources_refused_before_anything_else() {
    let now = Instant::now();
    let s = shared(true, None, now);
    let good = encode_echo_request(&nonce(1));
    for bad in [
        src(127, 0, 0, 1, 0),
        src(0, 0, 0, 0, 5),
        src(224, 0, 0, 1, 5),
        src(255, 255, 255, 255, 5),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5),
        SocketAddr::new(IpAddr::V6("ff02::1".parse().unwrap()), 5),
    ] {
        assert_eq!(s.handle(bad, &good, now), Action::Drop, "{bad}");
    }
    let c = s.snapshot();
    assert_eq!(c.refused_source, 6);
    assert_eq!(
        c.limited + c.malformed,
        0,
        "ни лимит, ни разбор не трогались"
    );
    // без `allow_private` отвечаем только публичным
    let s = shared(false, None, now);
    assert_eq!(s.handle(src(127, 0, 0, 1, 5), &good, now), Action::Drop);
    assert_eq!(s.handle(src(192, 168, 1, 5, 5), &good, now), Action::Drop);
    assert_eq!(
        s.handle(src(192, 0, 2, 1, 5), &good, now),
        Action::Drop,
        "документация не публичный"
    );
    assert_ne!(s.handle(src(8, 8, 8, 8, 5), &good, now), Action::Drop);
    assert_eq!(s.snapshot().refused_source, 3);
}

#[test]
fn report_line_has_no_addresses() {
    let c = Counters {
        requests: 12_345,
        replies: 10,
        reach_replies: 2,
        malformed: 3,
        limited: 4,
        refused_source: 5,
        recv_errors: 6,
    };
    let line = report_line(&c);
    assert!(
        line.contains("requests=12345") && line.contains("recv_errors=6"),
        "{line}"
    );
    assert!(
        !line.contains('.') && !line.contains(':') && !line.contains('['),
        "в строке счётчиков нет адресов: {line}"
    );
    // строка старта показывает только собственные адреса сервера
    let l = start_line("0.0.0", &[src(203, 0, 113, 5, 45_900)]);
    assert!(
        l.contains("203.0.113.5:45900") && l.contains("0.0.0"),
        "{l}"
    );
}
