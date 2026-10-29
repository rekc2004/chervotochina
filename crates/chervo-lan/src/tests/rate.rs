//! Тесты ограничения приёма (`rate.rs`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::limits::{IP_MAP, PER_IP, PER_IP_WINDOW, RX_BURST, RX_RATE};
use crate::rate::{RxLimiter, RxVerdict, TokenBucket};

fn at(ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, 1000))
}

fn ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(0xC0A8_0000u32 + n)
}

#[test]
fn rate_global_bucket() {
    let t0 = Instant::now();
    let mut b = TokenBucket::new(RX_RATE, RX_BURST, t0);
    let mut ok = 0;
    for _ in 0..200 {
        if b.take(t0) {
            ok += 1;
        }
    }
    assert_eq!(ok, RX_BURST, "всплеск ровно в размер корзины");
    // через секунду приходит RX_RATE токенов
    let t1 = t0 + Duration::from_secs(1);
    let mut ok = 0;
    for _ in 0..200 {
        if b.take(t1) {
            ok += 1;
        }
    }
    assert_eq!(ok, RX_RATE);
    // долгий простой не копит больше корзины
    let t2 = t1 + Duration::from_secs(3600);
    let mut ok = 0;
    for _ in 0..200 {
        if b.take(t2) {
            ok += 1;
        }
    }
    assert_eq!(ok, RX_BURST);
    // очень частые вызовы не теряют долю пополнения: за 10 с поток из вызовов раз в 100 мкс
    // даёт примерно RX_RATE * 10 токенов
    let mut b = TokenBucket::new(RX_RATE, 1, t0);
    assert!(b.take(t0));
    let mut ok = 0u32;
    for i in 1..=100_000u64 {
        if b.take(t0 + Duration::from_micros(i * 100)) {
            ok += 1;
        }
    }
    assert!((315..=325).contains(&ok), "принято {ok}");
}

#[test]
fn rate_per_ip() {
    let t0 = Instant::now();
    let mut l = RxLimiter::new(t0);
    let a = at(ip(1));
    let b = at(ip(2));
    for _ in 0..PER_IP {
        assert_eq!(l.check(t0, a), RxVerdict::Pass);
    }
    assert_eq!(l.check(t0, a), RxVerdict::DropIp);
    assert_eq!(l.dropped_ip(), 1);
    // другой адрес не затронут
    assert_eq!(l.check(t0, b), RxVerdict::Pass);
    // окно кончилось: адрес снова принимается
    let t1 = t0 + PER_IP_WINDOW + Duration::from_millis(1);
    assert_eq!(l.check(t1, a), RxVerdict::Pass);
}

#[test]
fn rate_global_before_ip() {
    // общий предел проверяется раньше предела по адресу и не зависит от адреса
    let t0 = Instant::now();
    let mut l = RxLimiter::with_params(1, 2, 100, PER_IP_WINDOW, IP_MAP, t0);
    assert_eq!(l.check(t0, at(ip(1))), RxVerdict::Pass);
    assert_eq!(l.check(t0, at(ip(2))), RxVerdict::Pass);
    assert_eq!(l.check(t0, at(ip(3))), RxVerdict::DropGlobal);
    assert_eq!(l.dropped_global(), 1);
    // IPv6 учитывается только в общей корзине
    let v6 = SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 5);
    let t1 = t0 + Duration::from_secs(1);
    assert_eq!(l.check(t1, v6), RxVerdict::Pass);
    assert_eq!(l.tracked_ips(), 2);
}

#[test]
fn rate_map_capacity() {
    let t0 = Instant::now();
    let mut l = RxLimiter::with_params(u32::MAX, u32::MAX, 1, PER_IP_WINDOW, 4, t0);
    // адрес 0 исчерпал свой предел
    assert_eq!(l.check(t0, at(ip(0))), RxVerdict::Pass);
    assert_eq!(l.check(t0, at(ip(0))), RxVerdict::DropIp);
    // ещё адреса, позже по времени: карта не растёт выше 4, самый старый (адрес 0) вытеснен
    for n in 1..=10u32 {
        let t = t0 + Duration::from_millis(u64::from(n));
        assert_eq!(l.check(t, at(ip(n))), RxVerdict::Pass);
        assert!(l.tracked_ips() <= 4, "карта {}", l.tracked_ips());
    }
    assert_eq!(
        l.check(t0 + Duration::from_millis(20), at(ip(0))),
        RxVerdict::Pass,
        "вытесненный адрес начал с нуля"
    );
    // и штатная карта ограничена IP_MAP
    let mut l = RxLimiter::new(t0);
    for n in 0..1000u32 {
        let t = t0 + Duration::from_secs(u64::from(n));
        let _ = l.check(t, at(ip(n)));
    }
    assert!(l.tracked_ips() <= IP_MAP);
}

#[test]
fn rate_saturating() {
    let base = Instant::now() + Duration::from_secs(1000);
    // время пошло назад: паники нет, токены не растут
    let mut b = TokenBucket::new(RX_RATE, 3, base);
    assert!(b.take(base));
    assert!(b.take(base - Duration::from_secs(500)));
    assert!(b.take(base - Duration::from_secs(900)));
    assert!(!b.take(base - Duration::from_secs(900)));
    // огромные скорость и интервал: насыщение, а не переполнение
    let mut b = TokenBucket::new(u32::MAX, u32::MAX, base);
    for _ in 0..10 {
        assert!(b.take(base + Duration::from_secs(100_000_000)));
    }
    let mut b = TokenBucket::new(u32::MAX, 0, base);
    assert!(!b.take(base + Duration::from_secs(1)));
    let mut l = RxLimiter::with_params(u32::MAX, u32::MAX, u32::MAX, Duration::MAX, 1, base);
    for _ in 0..5 {
        assert_eq!(l.check(base, at(ip(1))), RxVerdict::Pass);
    }
}
