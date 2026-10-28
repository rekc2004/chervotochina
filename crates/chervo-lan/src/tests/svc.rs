//! Тесты службы (L3) на петле: юникаст вместо группы (`TestNet`). Адреса 127.0.0.x разные у
//! разных участников; порты берутся из общего счётчика и проверяются привязкой.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chervo_addr::{LanDiscovery, LanLocal, LanMode, LanSighting, LanStatus};
use chervo_identity::{KxPeer, PairId};

use crate::service::{LanBeacon, TestNet, TestOracle};
use crate::table::IdTable;
use crate::testkit::peer_duo;
use crate::wire::{SrcPolicy, parse};

/// Последние октеты адресов 127.0.0.X, которые нужны этим тестам кроме 127.0.0.1 (разные участники
/// и источники). Linux и Windows принимают весь 127.0.0.0/8, а у macOS на lo0 по умолчанию только
/// 127.0.0.1: CI добавляет остальные шагом «Алиасы lo0 для тестов chervo-lan» в
/// `.github/workflows/ci.yml` (тест `loopback_aliases_listed_in_ci` сверяет список с этим шагом и
/// с адресами в тексте тестов). Локально на macOS: `sudo ifconfig lo0 alias 127.0.0.X up` для
/// каждого; без алиаса тест падает с понятным сообщением (`need_addr`).
pub const LOOPBACK_ALIASES: [u8; 14] = [2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
/// Источников потока в `svc_flood_bounded` (адреса 127.0.0.10 и далее).
const FLOOD_SOURCES: u8 = 10;

const A_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const B_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const REC_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 9);

/// Адрес должен быть на этой машине. Иначе понятная ошибка вместо перебора портов или молчаливого
/// отказа службы (macOS без алиаса lo0).
fn need_addr(ip: Ipv4Addr) {
    if let Err(e) = UdpSocket::bind((ip, 0)) {
        assert!(
            e.kind() != std::io::ErrorKind::AddrNotAvailable,
            "адреса {ip} нет на этой машине (macOS: на lo0 по умолчанию только 127.0.0.1). \
             Добавьте алиас: sudo ifconfig lo0 alias {ip} up (список: LOOPBACK_ALIASES, шаг CI \
             «Алиасы lo0 для тестов chervo-lan»)"
        );
        panic!("привязка к {ip}: {e}");
    }
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn port_for(ip: Ipv4Addr) -> u16 {
    if NEXT_PORT.load(Ordering::SeqCst) == 0 {
        let seed = 41_000 + u16::try_from(std::process::id() % 3000).unwrap();
        let _ = NEXT_PORT.compare_exchange(0, seed, Ordering::SeqCst, Ordering::SeqCst);
    }
    need_addr(ip);
    loop {
        let p = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        assert!(p < 48_000, "порты кончились");
        if UdpSocket::bind((ip, p)).is_ok() {
            return p;
        }
    }
}

fn clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| 1_700_000_000)
}

fn mk(
    mode: LanMode,
    bind: Ipv4Addr,
    port: u16,
    target: SocketAddrV4,
    interval: Duration,
) -> LanBeacon {
    mk_oracle(mode, bind, port, target, interval, TestNet::no_oracle())
}

fn mk_oracle(
    mode: LanMode,
    bind: Ipv4Addr,
    port: u16,
    target: SocketAddrV4,
    interval: Duration,
    oracle: TestOracle,
) -> LanBeacon {
    LanBeacon::new_on_loopback(
        mode,
        clock(),
        TestNet {
            target,
            bind,
            listen_port: port,
            allow_loopback: true,
            interval,
            oracle,
        },
    )
}

fn local(own: Ipv4Addr, port: u16) -> Option<LanLocal> {
    Some(LanLocal {
        own,
        listen_port: port,
    })
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f()
}

/// Приёмник вместо сети: сокет по адресу назначения, пишет время прихода каждой датаграммы.
fn recorder(port: u16) -> UdpSocket {
    let s = UdpSocket::bind((REC_IP, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    s
}

fn collect(s: &UdpSocket, dur: Duration) -> Vec<Instant> {
    let end = Instant::now() + dur;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            assert_eq!(n, 430);
            out.push(Instant::now());
        }
    }
    out
}

fn peers(n: usize) -> (Vec<KxPeer>, Vec<KxPeer>, Vec<PairId>) {
    let (mut a, mut b, mut ids) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..n {
        let (id, pa, pb) = peer_duo().unwrap();
        a.push(pa);
        b.push(pb);
        ids.push(id);
    }
    (a, b, ids)
}

fn rec_target(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(REC_IP, port)
}

#[test]
fn svc_off_opens_no_socket() {
    let port = port_for(A_IP);
    let (pa, _, _) = peers(1);
    let b = mk(
        LanMode::Off,
        A_IP,
        port,
        rec_target(port_for(REC_IP)),
        Duration::from_millis(200),
    );
    b.set_local(local(A_IP, 40_000));
    b.set_peers(pa);
    std::thread::sleep(Duration::from_millis(400));
    assert!(!b.thread_started(), "потока нет при режиме Off");
    assert_eq!(b.status(), LanStatus::Off);
    // порт свободен: привязка проходит и сразу отпускается
    drop(UdpSocket::bind((A_IP, port)).unwrap());
    // положительный контроль: в режиме «слушать» порт занят
    b.set_mode(LanMode::Listen);
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Listening));
    assert!(UdpSocket::bind((A_IP, port)).is_err());
    // и снова Off: сокет закрыт
    b.set_mode(LanMode::Off);
    assert!(wait_until(Duration::from_secs(2), || {
        b.status() == LanStatus::Off && UdpSocket::bind((A_IP, port)).is_ok()
    }));
}

#[test]
fn svc_listen_sends_nothing() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let (pa, _, _) = peers(2);
    let b = mk(
        LanMode::Listen,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(100),
    );
    b.set_local(local(A_IP, 40_000));
    b.set_peers(pa);
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Listening));
    assert_eq!(collect(&rec, Duration::from_secs(3)).len(), 0);
    assert_eq!(b.status(), LanStatus::Listening);
}

#[test]
fn svc_no_local_sends_nothing() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let (pa, _, _) = peers(2);
    let b = mk(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(100),
    );
    b.set_peers(pa);
    assert_eq!(collect(&rec, Duration::from_millis(1500)).len(), 0);
    assert_eq!(b.status(), LanStatus::NoPrivateRoute);
    assert!(!b.thread_started());
    // адрес по умолчанию не частный и опрос ничего не нашёл: частных интерфейсов нет, ничего
    // не открыто и не отправлено
    for default in [
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(100, 64, 0, 5),
        Ipv4Addr::new(198, 18, 0, 1),
    ] {
        let rp = port_for(REC_IP);
        let rec = recorder(rp);
        let (pa, _, _) = peers(1);
        let c = mk(
            LanMode::Announce,
            A_IP,
            port_for(A_IP),
            rec_target(rp),
            Duration::from_millis(100),
        );
        c.set_peers(pa);
        c.set_local(local(default, 40_000));
        assert!(wait_until(Duration::from_secs(2), || c.status()
            == LanStatus::NoPrivateRoute));
        assert_eq!(collect(&rec, Duration::from_millis(600)).len(), 0);
        assert!(c.addrs().is_empty());
    }
}

#[test]
fn svc_no_peers_sends_nothing() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let b = mk(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(100),
    );
    b.set_local(local(A_IP, 40_000));
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Announcing));
    assert_eq!(collect(&rec, Duration::from_millis(1500)).len(), 0);
    // порт 0 в адресе: тоже ничего
    let (pa, _, _) = peers(1);
    b.set_peers(pa);
    b.set_local(local(A_IP, 0));
    assert_eq!(collect(&rec, Duration::from_millis(1000)).len(), 0);
}

#[test]
fn svc_announce_burst_then_interval() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let (pa, _, _) = peers(1);
    let interval = Duration::from_millis(400);
    let b = mk(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        interval,
    );
    b.set_peers(pa);
    let start = Instant::now();
    b.set_local(local(A_IP, 40_000));
    let got = collect(&rec, Duration::from_millis(2600));
    let t: Vec<Duration> = got.iter().map(|i| i.duration_since(start)).collect();
    // серия: три датаграммы сразу после запуска (1, 3 и 7 с, сжатые в 400/30000 раза)
    let early = t
        .iter()
        .filter(|d| **d < Duration::from_millis(350))
        .count();
    assert!(
        early >= 3,
        "серия: {early} датаграмм в первые 350 мс, все: {t:?}"
    );
    // дальше раз в интервал с разбросом (5 с сжаты до ~67 мс)
    let later: Vec<Duration> = t
        .iter()
        .copied()
        .filter(|d| *d >= Duration::from_millis(150))
        .collect();
    assert!(later.len() >= 3, "после серии мало датаграмм: {t:?}");
    for pair in later.windows(2) {
        let gap = pair[1].saturating_sub(pair[0]);
        assert!(
            gap >= Duration::from_millis(250) && gap <= Duration::from_millis(700),
            "промежуток {gap:?}, все: {t:?}"
        );
    }
}

#[test]
fn svc_send_budget() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    // 64 пары: 4 датаграммы за раунд, раунды каждые 20 мс; бюджет 24 за 60 с
    let (pa, _, _) = peers(64);
    let b = mk(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(20),
    );
    b.set_peers(pa);
    b.set_local(local(A_IP, 40_000));
    let n = collect(&rec, Duration::from_millis(2000)).len();
    assert_eq!(n, 24, "бюджет отправки");
}

/// Собрать находки обоих участников, пока не наберётся нужное или не выйдет срок.
fn gather(
    b: &LanBeacon,
    got: &mut Vec<LanSighting>,
    limit: Duration,
    mut done: impl FnMut(&[LanSighting]) -> bool,
) -> bool {
    wait_until(limit, || {
        got.extend(b.take_sightings());
        done(got)
    })
}

#[test]
fn svc_two_beacons_find_each_other() {
    let (pa, pb, ids) = peers(1);
    let (port_a, port_b) = (port_for(A_IP), port_for(B_IP));
    let iv = Duration::from_millis(200);
    let a = mk(
        LanMode::Announce,
        A_IP,
        port_a,
        SocketAddrV4::new(B_IP, port_b),
        iv,
    );
    let b = mk(
        LanMode::Announce,
        B_IP,
        port_b,
        SocketAddrV4::new(A_IP, port_a),
        iv,
    );
    a.set_peers(pa);
    b.set_peers(pb);
    a.set_local(local(A_IP, 40_001));
    b.set_local(local(B_IP, 40_002));
    let (mut sa, mut sb) = (Vec::new(), Vec::new());
    let ok_a = gather(&a, &mut sa, Duration::from_secs(3), |g| !g.is_empty());
    let ok_b = gather(&b, &mut sb, Duration::from_secs(3), |g| !g.is_empty());
    assert!(ok_a && ok_b, "находки: A {} B {}", sa.len(), sb.len());
    // A слышит B по адресу и порту B, пара та же
    assert_eq!(sa[0].pair, ids[0]);
    assert_eq!(sa[0].addr, SocketAddrV4::new(B_IP, 40_002));
    assert_eq!(sb[0].pair, ids[0]);
    assert_eq!(sb[0].addr, SocketAddrV4::new(A_IP, 40_001));
    // своих маяков не принимает (адрес отправителя = свой адрес отбрасывается) и в режиме
    // «слушать» тоже находит
    a.shutdown();
    b.shutdown();
}

#[test]
fn svc_rebind_on_local_change() {
    need_addr(Ipv4Addr::new(127, 0, 0, 4));
    let (pa, pb, _) = peers(1);
    let (port_a, port_b) = (port_for(A_IP), port_for(B_IP));
    let iv = Duration::from_millis(200);
    let a = mk(
        LanMode::Announce,
        A_IP,
        port_a,
        SocketAddrV4::new(B_IP, port_b),
        iv,
    );
    let b = mk(
        LanMode::Listen,
        B_IP,
        port_b,
        SocketAddrV4::new(A_IP, port_a),
        iv,
    );
    a.set_peers(pa);
    b.set_peers(pb);
    b.set_local(local(B_IP, 40_002));
    a.set_local(local(A_IP, 40_001));
    let mut got = Vec::new();
    assert!(gather(&b, &mut got, Duration::from_secs(3), |g| !g.is_empty()));
    assert_eq!(got.last().unwrap().addr, SocketAddrV4::new(A_IP, 40_001));
    // новый адрес и порт: сокеты открываются заново, слоты запечатываются новым адресом
    let new_ip = Ipv4Addr::new(127, 0, 0, 4);
    a.set_local(local(new_ip, 40_009));
    got.clear();
    let want = SocketAddrV4::new(new_ip, 40_009);
    assert!(
        gather(&b, &mut got, Duration::from_secs(3), |g| g
            .iter()
            .any(|s| s.addr == want)),
        "после смены адреса: {} находок",
        got.len()
    );
    // порт приёма перекрыт заново: старый сокет закрыт, новый занят
    assert_eq!(a.status(), LanStatus::Announcing);
    assert!(UdpSocket::bind((A_IP, port_a)).is_err());
}

#[test]
fn svc_flood_bounded() {
    let (_, pb, _) = peers(2);
    let port_b = port_for(B_IP);
    let b = mk(
        LanMode::Listen,
        B_IP,
        port_b,
        rec_target(port_for(REC_IP)),
        Duration::from_millis(200),
    );
    b.set_peers(pb);
    b.set_local(local(B_IP, 40_002));
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Listening));
    let start = Instant::now();
    // FLOOD_SOURCES источников по 1000 датаграмм нужной длины с верным заголовком
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut d = [0u8; 430];
    d[0] = 1;
    for i in 0..FLOOD_SOURCES {
        let src = Ipv4Addr::new(127, 0, 0, 10 + i);
        need_addr(src);
        let s = UdpSocket::bind((src, 0)).unwrap();
        for _ in 0..1000 {
            for x in d.iter_mut().skip(2) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *x = seed.to_le_bytes()[0];
            }
            let _ = s.send_to(&d, (B_IP, port_b));
        }
    }
    // ждём, пока приём затихнет
    let mut last = 0;
    let mut stable = 0;
    while stable < 4 && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(75));
        let (rx, _) = b.rx_stats();
        stable = if rx == last { stable + 1 } else { 0 };
        last = rx;
    }
    let elapsed = start.elapsed();
    let (rx, passed) = b.rx_stats();
    assert!(
        elapsed < Duration::from_secs(2),
        "обработка заняла {elapsed:?}"
    );
    assert!(rx >= 100, "принято всего {rx}");
    let bound = 64 + 32 * (elapsed.as_secs() + 1);
    assert!(passed <= bound, "прошло ограничение {passed} > {bound}");
    assert!(passed < rx, "ограничение ничего не отбросило");
    assert!(b.take_sightings().is_empty());
    assert_eq!(b.status(), LanStatus::Listening);
}

#[test]
fn svc_port_busy_status() {
    let port = port_for(B_IP);
    let holder = UdpSocket::bind((B_IP, port)).unwrap();
    let b = mk(
        LanMode::Listen,
        B_IP,
        port,
        rec_target(port_for(REC_IP)),
        Duration::from_millis(200),
    );
    b.set_local(local(B_IP, 40_002));
    assert!(wait_until(Duration::from_secs(2), || b.status() == LanStatus::PortBusy));
    drop(holder);
    // повторный `set_local` снимает ожидание повтора
    b.set_local(local(B_IP, 40_002));
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Listening));
}

#[test]
fn svc_sightings_bounded_dedup() {
    let (pa, pb, _) = peers(70);
    let (port_a, port_b) = (port_for(A_IP), port_for(B_IP));
    let iv = Duration::from_millis(300);
    let a = mk(
        LanMode::Announce,
        A_IP,
        port_a,
        SocketAddrV4::new(B_IP, port_b),
        iv,
    );
    let b = mk(
        LanMode::Listen,
        B_IP,
        port_b,
        SocketAddrV4::new(A_IP, port_a),
        iv,
    );
    b.set_peers(pb);
    b.set_local(local(B_IP, 40_002));
    a.set_peers(pa);
    a.set_local(local(A_IP, 40_001));
    std::thread::sleep(Duration::from_millis(2500));
    let got = b.take_sightings();
    let uniq: HashSet<_> = got.iter().map(|s| s.pair).collect();
    assert_eq!(uniq.len(), got.len(), "одна находка на пару");
    assert!(got.len() <= 64, "очередь не больше 64: {}", got.len());
    assert!(got.len() >= 60, "находок мало: {}", got.len());
    assert!(b.take_sightings().is_empty(), "очередь забрана");
}

#[test]
fn svc_shutdown_fast() {
    let b = mk(
        LanMode::Listen,
        B_IP,
        port_for(B_IP),
        rec_target(port_for(REC_IP)),
        Duration::from_millis(200),
    );
    b.set_local(local(B_IP, 40_002));
    assert!(wait_until(Duration::from_secs(2), || b.status()
        == LanStatus::Listening));
    let t = Instant::now();
    b.shutdown();
    assert!(wait_until(Duration::from_secs(2), || b.thread_finished()));
    let took = t.elapsed();
    assert!(
        took <= Duration::from_millis(300),
        "остановка заняла {took:?}"
    );
}

// ---------------------------------------------------------------- несколько интерфейсов

/// Подставной опрос маршрутов: «цель -> какой свой адрес»; таблицу можно менять на ходу.
type Routes = Arc<Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>>;

fn routes_oracle(t: &Routes) -> TestOracle {
    let t = t.clone();
    Arc::new(move |a: SocketAddrV4| {
        t.lock()
            .unwrap()
            .iter()
            .find(|(target, _)| target == a.ip())
            .map(|(_, own)| IpAddr::V4(*own))
    })
}

const HOME_GW: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const OTHER_GW: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 1);
const IF_1: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const IF_4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

/// Источники всех датаграмм, пришедших на приёмник за `dur`.
fn collect_sources(s: &UdpSocket, dur: Duration) -> Vec<Ipv4Addr> {
    let end = Instant::now() + dur;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((_, std::net::SocketAddr::V4(src))) = s.recv_from(&mut buf) {
            out.push(*src.ip());
        }
    }
    out
}

fn sorted_ips(mut v: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    v.sort();
    v
}

#[test]
fn svc_multi_iface_both_send() {
    need_addr(IF_4);
    let (pa, pb, ids) = peers(1);
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let iv = Duration::from_millis(200);
    let routes: Routes = Arc::new(Mutex::new(vec![(HOME_GW, IF_1), (OTHER_GW, IF_4)]));
    let a = mk_oracle(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        iv,
        routes_oracle(&routes),
    );
    a.set_peers(pa);
    // адрес по умолчанию (туннель, класс не частный) не годится; интерфейсы находит опрос
    a.set_local(local(Ipv4Addr::new(198, 18, 0, 1), 40_001));
    // приёмник вместо сети записывает датаграммы с адресами отправителей
    let end = Instant::now() + Duration::from_millis(1500);
    let mut raw: Vec<(std::net::SocketAddr, Vec<u8>)> = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, src)) = rec.recv_from(&mut buf) {
            raw.push((src, buf[..n].to_vec()));
        }
    }
    assert_eq!(sorted_ips(a.addrs()), vec![IF_1, IF_4]);
    assert_eq!(a.status(), LanStatus::Announcing);
    // получатель с ключами второй стороны разбирает датаграммы обоих интерфейсов
    let keys = pb[0].lan_keys().unwrap();
    let table = IdTable::from_peers(vec![(ids[0], keys)], 1_700_000_000 / 30);
    let mut seen: HashSet<SocketAddrV4> = HashSet::new();
    for (src, d) in &raw {
        for s in parse(d, *src, &[B_IP], &table, SrcPolicy::LOOPBACK_OK) {
            assert_eq!(s.pair, ids[0]);
            seen.insert(s.addr);
        }
    }
    let want: HashSet<SocketAddrV4> = [
        SocketAddrV4::new(IF_1, 40_001),
        SocketAddrV4::new(IF_4, 40_001),
    ]
    .into_iter()
    .collect();
    assert_eq!(seen, want, "получено датаграмм {}", raw.len());
    // выключен: адресов нет
    a.set_mode(LanMode::Off);
    assert!(wait_until(Duration::from_secs(2), || a.addrs().is_empty()));
}

#[test]
fn svc_rebind_on_iface_change() {
    need_addr(IF_4);
    let (pa, pb, _) = peers(1);
    let (port_a, port_b) = (port_for(A_IP), port_for(B_IP));
    let iv = Duration::from_millis(200);
    let routes: Routes = Arc::new(Mutex::new(Vec::new()));
    let a = mk_oracle(
        LanMode::Announce,
        A_IP,
        port_a,
        SocketAddrV4::new(B_IP, port_b),
        iv,
        routes_oracle(&routes),
    );
    let b = mk(
        LanMode::Listen,
        B_IP,
        port_b,
        SocketAddrV4::new(A_IP, port_a),
        iv,
    );
    a.set_peers(pa);
    b.set_peers(pb);
    a.set_local(local(A_IP, 40_001));
    b.set_local(local(B_IP, 40_002));
    let mut got = Vec::new();
    assert!(gather(&b, &mut got, Duration::from_secs(3), |g| !g.is_empty()));
    assert_eq!(a.addrs(), vec![A_IP]);
    // второй интерфейс появился (сеть сменилась под VPN), `set_local` не вызывался
    routes.lock().unwrap().push((HOME_GW, IF_4));
    assert!(wait_until(Duration::from_secs(3), || a.addrs().len() == 2));
    assert_eq!(sorted_ips(a.addrs()), vec![A_IP, IF_4]);
    got.clear();
    let want = SocketAddrV4::new(IF_4, 40_001);
    assert!(
        gather(&b, &mut got, Duration::from_secs(3), |g| g
            .iter()
            .any(|s| s.addr == want)),
        "с нового интерфейса маяк не пришёл"
    );
    // интерфейс исчез: набор снова из одного адреса
    routes.lock().unwrap().clear();
    assert!(wait_until(Duration::from_secs(3), || a.addrs() == vec![A_IP]));
}

#[test]
fn svc_send_budget_per_iface() {
    need_addr(IF_4);
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    // 64 пары: 4 датаграммы за раунд на каждый интерфейс, бюджет 24 за 60 с на интерфейс
    let (pa, _, _) = peers(64);
    let routes: Routes = Arc::new(Mutex::new(vec![(HOME_GW, IF_4)]));
    let a = mk_oracle(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(20),
        routes_oracle(&routes),
    );
    a.set_peers(pa);
    a.set_local(local(A_IP, 40_001));
    let from = collect_sources(&rec, Duration::from_millis(2500));
    let count = |ip: Ipv4Addr| from.iter().filter(|s| **s == ip).count();
    assert_eq!(count(A_IP), 24, "бюджет первого интерфейса");
    assert_eq!(count(IF_4), 24, "бюджет второго интерфейса");
    assert_eq!(from.len(), 48);
}

#[test]
fn svc_sweep_respects_shutdown() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    // каждое обращение к опросу занимает около 1 мс (ожидание без сна: у сна на Windows грубый шаг)
    let slow: TestOracle = Arc::new(move |_| {
        c.fetch_add(1, Ordering::SeqCst);
        let end = Instant::now() + Duration::from_millis(1);
        while Instant::now() < end {
            std::hint::spin_loop();
        }
        None
    });
    let b = mk_oracle(
        LanMode::Listen,
        B_IP,
        port_for(B_IP),
        rec_target(port_for(REC_IP)),
        Duration::from_millis(200),
        slow,
    );
    b.set_local(local(B_IP, 40_002));
    assert!(wait_until(Duration::from_secs(2), || calls
        .load(Ordering::SeqCst)
        > 10));
    let t = Instant::now();
    b.shutdown();
    assert!(wait_until(Duration::from_secs(2), || b.thread_finished()));
    let took = t.elapsed();
    assert!(
        took <= Duration::from_millis(300),
        "остановка заняла {took:?}"
    );
    assert!(
        calls.load(Ordering::SeqCst) < 533,
        "опрос прерван остановкой, обращений {}",
        calls.load(Ordering::SeqCst)
    );
}

/// Нет адреса на машине (как 127.0.0.4 на macOS без алиаса): понятная ошибка, а не перебор портов.
#[test]
#[should_panic(expected = "нет на этой машине")]
fn need_addr_reports_missing_address() {
    need_addr(Ipv4Addr::new(203, 0, 113, 250));
}

/// Список адресов петли для macOS живёт в одном месте (`LOOPBACK_ALIASES`) и совпадает и с шагом
/// CI, и с адресами 127.0.0.X в тексте тестов службы: забытый адрес не дойдёт до macOS-раннера
/// молча.
#[test]
fn loopback_aliases_listed_in_ci() {
    use std::collections::BTreeSet;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let want: BTreeSet<u32> = LOOPBACK_ALIASES.iter().map(|n| u32::from(*n)).collect();
    // шаг CI
    let ci = std::fs::read_to_string(root.join("../../.github/workflows/ci.yml"))
        .unwrap()
        .replace("\r\n", "\n");
    let at = ci
        .find("Алиасы lo0 для тестов chervo-lan")
        .expect("в ci.yml нет шага с алиасами lo0");
    let block = &ci[at..];
    assert!(
        block.contains("runner.os == 'macOS'"),
        "шаг только для macOS"
    );
    let line = block
        .lines()
        .find(|l| l.contains("for n in "))
        .expect("в шаге нет списка");
    let list: BTreeSet<u32> = line
        .split("for n in ")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_whitespace()
        .map(|t| t.parse().unwrap())
        .collect();
    assert_eq!(list, want, "список шага CI и LOOPBACK_ALIASES разошлись");
    // адреса 127.0.0.X в тексте тестов службы и в проверках разбора
    let prefix = format!("127, 0, {}, ", 0);
    let flood = 10..10 + u32::from(FLOOD_SOURCES);
    for file in ["svc.rs", "wire.rs"] {
        let text = std::fs::read_to_string(root.join("src/tests").join(file)).unwrap();
        for part in text.split(&prefix).skip(1) {
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            let n: u32 = digits.parse().unwrap();
            assert!(
                n == 1 || want.contains(&n),
                "{file}: адрес 127.0.0.{n} не в LOOPBACK_ALIASES"
            );
        }
    }
    assert!(
        flood.clone().all(|n| want.contains(&n)),
        "источники потока вне списка"
    );
}

/// Все датаграммы приёмника за `dur`.
fn collect_raw(s: &UdpSocket, dur: Duration) -> Vec<Vec<u8>> {
    let end = Instant::now() + dur;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            out.push(buf[..n].to_vec());
        }
    }
    out
}

fn labels_of(d: &[u8]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = (0..16)
        .map(|i| d[14 + i * 26..14 + i * 26 + 8].to_vec())
        .collect();
    v.sort();
    v
}

/// Служба держит ключ `R` меток пустых слотов постоянным, пока сокеты открыты (метки всех слотов
/// в окне одни и те же), и берёт новый при смене набора интерфейсов (здесь: открытие заново).
#[test]
fn svc_pad_labels_stable_then_new_key_on_reopen() {
    let rp = port_for(REC_IP);
    let rec = recorder(rp);
    let (pa, _, _) = peers(3);
    let a = mk(
        LanMode::Announce,
        A_IP,
        port_for(A_IP),
        rec_target(rp),
        Duration::from_millis(150),
    );
    a.set_peers(pa);
    a.set_local(local(A_IP, 40_001));
    let first = collect_raw(&rec, Duration::from_millis(1000));
    assert!(first.len() >= 3, "датаграмм {}", first.len());
    let want = labels_of(&first[0]);
    assert!(
        first.iter().all(|d| labels_of(d) == want),
        "метки в окне меняются"
    );
    // порт в адресе изменился: сокеты открыты заново, ключ новый (окно то же: часы стоят)
    a.set_local(local(A_IP, 40_002));
    std::thread::sleep(Duration::from_millis(300));
    let _ = collect_raw(&rec, Duration::from_millis(100));
    let second = collect_raw(&rec, Duration::from_millis(1000));
    assert!(second.len() >= 3, "датаграмм {}", second.len());
    let want2 = labels_of(&second[0]);
    assert!(second.iter().all(|d| labels_of(d) == want2));
    let common = want.iter().filter(|l| want2.contains(l)).count();
    assert_eq!(
        common, 3,
        "общими остались только метки трёх настоящих слотов"
    );
}

/// Вручную на настоящей сети: открывает приём в группе на маршрутном адресе. Полная проверка
/// (две машины, приём чужого маяка) делается примером `lan_probe` и стендом, не здесь.
#[test]
#[ignore = "открывает порт на настоящем интерфейсе; запускать вручную"]
fn multicast_real_lan() {
    let own = chervo_addr::probe_route_sources()
        .v4
        .expect("нет маршрутного IPv4");
    let b = LanBeacon::new(LanMode::Listen, clock());
    b.set_local(local(own, 40_000));
    assert!(wait_until(Duration::from_secs(3), || b.status()
        == LanStatus::Listening));
    b.shutdown();
}
