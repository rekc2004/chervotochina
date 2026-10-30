//! Двойное гнездо (этап 13г, L2): `bind_listen`, режимы, канонический адрес, фильтр класса
//! источника IPv6, приём и звонки по IPv4 и IPv6 на петле.
//! Тесты на `::1` начинают с проверки, что IPv6 на петле есть; иначе печатают `SKIP ipv6 <имя>`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chervo_identity::PairId;
use chervo_transport::{Connection, PeerAddr, Transport, TransportError};
use quinn::Runtime;
use quinn::udp::RecvMeta;

use super::kit::*;
use super::knock::ping_pong;
use crate::bind::{self, DualFail};
use crate::knock::{KnockState, canon};
use crate::limits::Counters;
use crate::{BindError, ListenMode, QuinnConfig, QuinnTransport, bind_listen};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        knock_required: true,
        ..QuinnConfig::default()
    }
}

/// Есть ли IPv6 на петле; иначе печатает `SKIP ipv6 <имя>` (единственное место печати в тестах).
#[allow(clippy::print_stdout)]
fn v6_loopback(name: &str) -> bool {
    if UdpSocket::bind("[::1]:0").is_ok() {
        return true;
    }
    println!("SKIP ipv6 {name}");
    false
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// Источник IPv6 с заданными `flowinfo` и `scope_id`.
fn src6(ip: &str, port: u16, flow: u32, scope: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(v6(ip), port, flow, scope))
}

fn bind_dual(cfg: QuinnConfig, peers: Vec<chervo_identity::KxPeer>) -> QuinnTransport {
    let (sock, mode) = bind_listen(0).unwrap();
    assert_eq!(mode, ListenMode::DualStack);
    let t = QuinnTransport::from_socket(sock, cfg, Arc::new(AllowAll)).unwrap();
    t.set_peers(peers).unwrap();
    t
}

fn port_of(t: &QuinnTransport) -> u16 {
    t.local_addrs()[0].port()
}

fn to(pair: PairId, addrs: Vec<SocketAddr>) -> PeerAddr {
    PeerAddr { pair, addrs }
}

fn lo6(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)
}

fn lo4(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// Держатель порта `[::]:p` с `IPV6_V6ONLY = 1` (socket2 в `src/` только в `bind.rs`, а тесты
/// не входят в охрану исходников).
fn hold_v6only() -> (socket2::Socket, u16) {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    s.set_only_v6(true).unwrap();
    s.bind(&SockAddr::from(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))
    .unwrap();
    let port = s.local_addr().unwrap().as_socket().unwrap().port();
    (s, port)
}

// ---------------------------------------------------------------------------------------------
// bind_listen и choose
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_listen_dual_on_this_os() {
    let (sock, mode) = bind_listen(0).unwrap();
    assert_eq!(mode, ListenMode::DualStack, "ОС не дала двойного гнезда");
    let p = sock.local_addr().unwrap().port();
    let t = QuinnTransport::from_socket(sock, cfg(), Arc::new(AllowAll)).unwrap();
    assert_eq!(t.listen_mode(), ListenMode::DualStack);
    assert_eq!(
        t.local_addrs(),
        vec![
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p),
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p),
        ]
    );
}

#[test]
fn bind_listen_conflicts_with_v4_holder() {
    let holder = UdpSocket::bind("0.0.0.0:0").unwrap();
    let p = holder.local_addr().unwrap().port();
    assert_eq!(bind_listen(p).err(), Some(BindError::PortInUse));
    drop(holder);
}

#[test]
fn bind_listen_conflicts_with_v6_holder() {
    let (holder, p) = hold_v6only();
    assert_eq!(bind_listen(p).err(), Some(BindError::PortInUse));
    drop(holder);
}

#[test]
fn choose_unavailable_falls_back_to_v4() {
    let (s, mode) = bind::choose(Err(DualFail::Unavailable), || {
        UdpSocket::bind("127.0.0.1:0")
    })
    .unwrap();
    assert_eq!(mode, ListenMode::V4Only);
    assert!(s.local_addr().unwrap().is_ipv4());
    // двойное гнездо готово: запасной путь не вызывается
    let d = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (_, mode) = bind::choose(Ok(d), || panic!("запасной путь при готовом гнезде")).unwrap();
    assert_eq!(mode, ListenMode::DualStack);
}

#[test]
fn choose_port_in_use_no_fallback() {
    let mut called = false;
    let r = bind::choose(Err(DualFail::PortInUse), || {
        called = true;
        UdpSocket::bind("127.0.0.1:0")
    });
    assert_eq!(r.err(), Some(BindError::PortInUse));
    assert!(!called, "запасной путь вызван при занятом порте");
}

#[test]
fn choose_v4_error_mapping() {
    for (kind, want) in [
        (io::ErrorKind::AddrInUse, BindError::PortInUse),
        (io::ErrorKind::AddrNotAvailable, BindError::PortInUse),
        (io::ErrorKind::PermissionDenied, BindError::PortInUse),
        (io::ErrorKind::Other, BindError::Io),
        (io::ErrorKind::ConnectionRefused, BindError::Io),
    ] {
        let r = bind::choose(Err(DualFail::Unavailable), || Err(io::Error::from(kind)));
        assert_eq!(r.err(), Some(want), "{kind:?}");
    }
}

#[test]
fn listen_mode_detected_v4_v6only_dual() {
    let s4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(bind::mode_of(&s4), ListenMode::V4Only);
    if !v6_loopback("listen_mode_detected_v4_v6only_dual") {
        return;
    }
    let s6 = UdpSocket::bind("[::1]:0").unwrap();
    assert_eq!(bind::mode_of(&s6), ListenMode::V6Only);
    // `[::]` с IPV6_V6ONLY = 1 это не двойное гнездо
    let (h, _) = hold_v6only();
    let as_std: UdpSocket = h.into();
    assert_eq!(bind::mode_of(&as_std), ListenMode::V6Only);
    let (d, mode) = bind_listen(0).unwrap();
    assert_eq!(mode, ListenMode::DualStack);
    assert_eq!(bind::mode_of(&d), ListenMode::DualStack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebind_recomputes_mode() {
    let k = Keys::new();
    let t = bind(cfg(), vec![k.peer_a()]);
    assert_eq!(t.listen_mode(), ListenMode::V4Only);
    assert_eq!(t.local_addrs().len(), 1);
    let (d, _) = bind_listen(0).unwrap();
    let p = d.local_addr().unwrap().port();
    t.rebind(d).unwrap();
    assert_eq!(t.listen_mode(), ListenMode::DualStack);
    assert_eq!(t.local_addrs().len(), 2);
    assert_eq!(port_of(&t), p);
    t.rebind(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
    assert_eq!(t.listen_mode(), ListenMode::V4Only);
    assert_eq!(t.local_addrs().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Соединения на петле
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_v6_loopback_race_and_knock() {
    if !v6_loopback("dual_v6_loopback_race_and_knock") {
        return;
    }
    let k = Keys::new();
    let a = bind_dual(cfg(), vec![k.peer_a()]);
    let b = Arc::new(bind_dual(cfg(), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&to(k.pid, vec![lo6(port_of(&b))])).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    assert_eq!(b.stats().knock_ok, 1);
    ping_pong(&ca, &cb, Duration::from_secs(5)).await.unwrap();
    // канонический вид: IPv6 без flowinfo и scope id
    let SocketAddr::V6(r) = cb.remote_addr() else {
        panic!("ожидался IPv6");
    };
    assert_eq!((r.flowinfo(), r.scope_id()), (0, 0));
    assert_eq!(*r.ip(), Ipv6Addr::LOCALHOST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_v4_peer_admitted_as_v4() {
    let k = Keys::new();
    let a = bind(cfg(), vec![k.peer_a()]);
    let b = Arc::new(bind_dual(cfg(), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&to(k.pid, vec![lo4(port_of(&b))])).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    // допуск по V4: у вызываемого адрес собеседника V4, а не v4-mapped
    let remote = cb.remote_addr();
    assert!(remote.is_ipv4(), "{remote}");
    assert_eq!(remote.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(remote.port(), port_of(&a));
    assert_eq!(cb.established_addr(), remote);
    assert_eq!(b.stats().knock_ok, 1);
    ping_pong(&ca, &cb, Duration::from_secs(5)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_dials_v4_only_peer() {
    let k = Keys::new();
    let a = bind_dual(cfg(), vec![k.peer_a()]);
    let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&to(k.pid, vec![lo4(port_of(&b))])).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    // у звонящего двойного гнезда адрес собеседника тоже канонический V4
    assert_eq!(ca.remote_addr(), lo4(port_of(&b)));
    assert_eq!(ca.established_addr(), lo4(port_of(&b)));
    assert!(cb.remote_addr().is_ipv4());
    ping_pong(&ca, &cb, Duration::from_secs(5)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_mixed_race_one_auth() {
    if !v6_loopback("dual_mixed_race_one_auth") {
        return;
    }
    let k = Keys::new();
    let c = QuinnConfig {
        connect_stagger: Duration::ZERO,
        ..cfg()
    };
    let a = bind_dual(c, vec![k.peer_a()]);
    let b = Arc::new(bind_dual(cfg(), vec![k.peer_b()]));
    let pb = port_of(&b);
    let ca = a.connect(&to(k.pid, vec![lo6(pb), lo4(pb)])).await.unwrap();
    let t0 = Instant::now();
    while b.stats().auth_ok < 1 && t0.elapsed() < Duration::from_secs(5) {
        sleep_ms(20).await;
    }
    sleep_ms(500).await;
    assert_eq!(b.stats().auth_ok, 1);
    assert_eq!(b.stats().duplicates_closed, 0);
    assert_eq!(a.stats().auth_ok, 1);
    assert!(ca.conn.close_reason().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v6only_endpoint_skips_v4_candidates() {
    if !v6_loopback("v6only_endpoint_skips_v4_candidates") {
        return;
    }
    let k = Keys::new();
    let t = QuinnTransport::bind("[::1]:0".parse().unwrap(), cfg(), Arc::new(AllowAll)).unwrap();
    t.set_peers(vec![k.peer_a()]).unwrap();
    assert_eq!(t.listen_mode(), ListenMode::V6Only);
    // только IPv4: пустой список кандидатов, ни одного пакета
    let t0 = Instant::now();
    let r = t.connect(&to(k.pid, vec![lo4(9)])).await;
    assert_eq!(r.err(), Some(TransportError::Io));
    assert!(t0.elapsed() < Duration::from_secs(1));
}

// ---------------------------------------------------------------------------------------------
// Стук и фильтр класса источника без сети
// ---------------------------------------------------------------------------------------------

fn state_with(k: &Keys, required: bool) -> (Arc<KnockState>, Arc<Counters>) {
    let c = QuinnConfig {
        knock_required: required,
        ..cfg()
    };
    let counters = Arc::new(Counters::default());
    let (events, _) = tokio::sync::broadcast::channel(8);
    let std_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
    let state = KnockState::new(&c, counters.clone(), Arc::new(AllowAll), events, raw);
    state.set_peers(&[k.peer_b()]);
    (state, counters)
}

fn knock_of(k: &Keys) -> [u8; 48] {
    k.peer_a().knock_keys().unwrap().make(now_window()).unwrap()
}

/// Одна запись через `filter_batch`: (сколько осталось, адрес записи после фильтра).
fn feed(state: &KnockState, addr: SocketAddr, payload: &[u8]) -> (usize, SocketAddr) {
    let mut storage = vec![0u8; payload.len().max(1)];
    storage[..payload.len()].copy_from_slice(payload);
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    meta[0].addr = addr;
    meta[0].len = payload.len();
    let kept = state.filter_batch(&mut bufs, &mut meta, 1);
    (kept, meta[0].addr)
}

fn rd(c: &std::sync::atomic::AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admit_v4_mapped_equals_v4() {
    let k = Keys::new();
    let (state, counters) = state_with(&k, true);
    let mapped = src6("::ffff:127.0.0.1", 40_001, 0, 0);
    let plain = lo4(40_001);
    // допуск открыт с v4-mapped, найден по V4
    let (kept, _) = feed(&state, mapped, &knock_of(&k));
    assert_eq!(kept, 0);
    assert_eq!(rd(&counters.knock_ok), 1);
    assert_eq!(state.peek_admission(plain), Some(k.pid));
    assert_eq!(state.peek_admission(mapped), Some(k.pid));
    // и наоборот
    let other_mapped = src6("::ffff:127.0.0.1", 40_002, 0, 0);
    let (kept, _) = feed(&state, lo4(40_002), &knock_of(&k));
    assert_eq!(kept, 0);
    assert_eq!(rd(&counters.knock_ok), 2);
    assert_eq!(state.peek_admission(other_mapped), Some(k.pid));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn src_filter_drops_hostile_v6_sources() {
    let k = Keys::new();
    let (state, counters) = state_with(&k, true);
    let knock = knock_of(&k);
    let hostile = [
        src6("fe80::1", 4000, 0, 3),
        src6("2002::1", 4000, 0, 0),
        src6("2001:0::1", 4000, 0, 0),
        src6("64:ff9b::1", 4000, 0, 0),
        src6("::1.2.3.4", 4000, 0, 0),
        src6("ff02::1", 4000, 0, 0),
        src6("::", 4000, 0, 0),
        src6("2001:db8::1", 4000, 0, 0),
        src6("fec0::1", 4000, 0, 0),
    ];
    let mut kept = 0;
    for s in hostile {
        kept += feed(&state, s, &knock).0;
        // и не стук: в таблице допуска их тоже нет
        kept += feed(&state, s, &[0x40; 100]).0;
    }
    assert_eq!(kept, 0);
    assert_eq!(rd(&counters.dropped_src_class), 18);
    assert_eq!(rd(&counters.knock_ok), 0);
    // отброшены фильтром класса, а не таблицей допуска
    assert_eq!(rd(&counters.dropped_unadmitted), 0);
    // положительный контроль: тот же верный стук с `::1` допускает адрес
    let (kept, _) = feed(&state, lo6(4000), &knock);
    assert_eq!(kept, 0);
    assert_eq!(rd(&counters.knock_ok), 1);
    assert_eq!(rd(&counters.dropped_src_class), 18);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn src_filter_keeps_global_ula_loopback_and_all_v4() {
    let k = Keys::new();
    // без обязательного стука записи идут в quinn после фильтра класса
    let (state, counters) = state_with(&k, false);
    for s in [
        src6("2606:4700::1", 4000, 0, 0),
        src6("2606:4700::211:22ff:fe33:4455", 4000, 0, 0),
        src6("fd00::1", 4000, 0, 0),
        lo6(4000),
        lo4(4000),
        "10.0.0.1:4000".parse().unwrap(),
        "169.254.1.1:4000".parse().unwrap(),
        "224.0.0.1:4000".parse().unwrap(),
        "8.8.8.8:4000".parse().unwrap(),
        src6("::ffff:8.8.8.8", 4000, 0, 0),
    ] {
        assert_eq!(feed(&state, s, &[0x40; 100]).0, 1, "{s}");
    }
    assert_eq!(rd(&counters.dropped_src_class), 0);
    // а путь без стука тоже выбрасывает недопустимый класс
    assert_eq!(feed(&state, src6("2002::1", 4000, 0, 0), &[0x40; 100]).0, 0);
    assert_eq!(rd(&counters.dropped_src_class), 1);
    // со стуком те же источники без стука молчат по обычной причине (таблица допуска)
    let (state, counters) = state_with(&k, true);
    for s in [src6("2606:4700::1", 4000, 0, 0), lo4(4000), lo6(4000)] {
        assert_eq!(feed(&state, s, &[0x40; 100]).0, 0, "{s}");
    }
    assert_eq!(rd(&counters.dropped_src_class), 0);
    assert_eq!(rd(&counters.dropped_unadmitted), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recv_meta_canonicalized_for_quinn() {
    let k = Keys::new();
    let (state, counters) = state_with(&k, true);
    // глобальный IPv6 с ненулевыми flowinfo и scope id: стук допускает канонический адрес
    let dirty = src6("2606:4700::1", 5000, 7, 3);
    assert_eq!(feed(&state, dirty, &knock_of(&k)).0, 0);
    assert_eq!(rd(&counters.knock_ok), 1);
    let (kept, addr) = feed(&state, dirty, &[0x40; 100]);
    assert_eq!(kept, 1);
    let SocketAddr::V6(r) = addr else {
        panic!("ожидался IPv6");
    };
    assert_eq!((r.flowinfo(), r.scope_id(), r.port()), (0, 0, 5000));
    assert_eq!(*r.ip(), v6("2606:4700::1"));
    // v4-mapped: вид остаётся v4-mapped (так работает quinn на IPv6-гнезде), поля нули
    let mapped = src6("::ffff:127.0.0.1", 5001, 5, 2);
    assert_eq!(feed(&state, mapped, &knock_of(&k)).0, 0);
    let (kept, addr) = feed(&state, mapped, &[0x40; 100]);
    assert_eq!(kept, 1);
    let SocketAddr::V6(r) = addr else {
        panic!("v4-mapped должен остаться IPv6-видом для quinn");
    };
    assert_eq!((r.flowinfo(), r.scope_id(), r.port()), (0, 0, 5001));
    assert_eq!(r.ip().to_ipv4_mapped(), Some(Ipv4Addr::LOCALHOST));
    // IPv4 не меняется
    let (_, addr) = feed(&state, lo4(5002), &[0x40; 100]);
    assert_eq!(addr, lo4(5002));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_addr_canonical() {
    // двойные стороны по IPv4: на проводе v4-mapped, у обеих сторон адрес собеседника V4
    let k = Keys::new();
    let a = bind_dual(cfg(), vec![k.peer_a()]);
    let b = Arc::new(bind_dual(cfg(), vec![k.peer_b()]));
    let b2 = b.clone();
    let acc = tokio::spawn(async move { b2.accept().await });
    let ca = a.connect(&to(k.pid, vec![lo4(port_of(&b))])).await.unwrap();
    let cb = acc.await.unwrap().unwrap();
    assert_eq!(ca.remote_addr(), lo4(port_of(&b)));
    assert_eq!(ca.established_addr(), lo4(port_of(&b)));
    assert_eq!(cb.remote_addr(), lo4(port_of(&a)));
    assert_eq!(cb.established_addr(), lo4(port_of(&a)));
    assert!(
        b.inner
            .registry
            .live_remotes()
            .iter()
            .all(|(_, s)| s.is_ipv4())
    );
}

/// Монитор сравнивает канонические адреса: смена только `flowinfo` или `scope_id` не смена
/// адреса. Сам монитор на живом соединении `flowinfo` изменить не даёт, поэтому проверяется
/// правило сравнения и общий ключ закрепления.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitor_ignores_flowinfo_only_change() {
    let k = Keys::new();
    let (state, _) = state_with(&k, true);
    let clean = src6("2606:4700::1", 5000, 0, 0);
    for dirty in [
        src6("2606:4700::1", 5000, 9, 0),
        src6("2606:4700::1", 5000, 0, 4),
        src6("2606:4700::1", 5000, 1, 2),
    ] {
        assert_ne!(clean, dirty, "std сравнивает все поля");
        assert_eq!(canon(clean), canon(dirty));
    }
    // закрепление по «грязному» адресу и допуск по чистому делят одну запись
    assert_eq!(feed(&state, clean, &knock_of(&k)).0, 0);
    let pin = state.pin(src6("2606:4700::1", 5000, 9, 4));
    assert_eq!(state.peek_admission(clean), Some(k.pid));
    drop(pin);
}

// ---------------------------------------------------------------------------------------------
// Тишина и фаззинг
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stranger_v6_silence() {
    if !v6_loopback("stranger_v6_silence") {
        return;
    }
    let mut seen_control = false;
    for required in [true, false] {
        let k = Keys::new();
        let b = bind_dual(
            QuinnConfig {
                knock_required: required,
                ..cfg()
            },
            vec![k.peer_b()],
        );
        let dest = lo6(port_of(&b));
        let raw = UdpSocket::bind("[::1]:0").unwrap();
        raw.set_nonblocking(true).unwrap();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut buf = vec![0u8; 1200];
        for i in 0..1000usize {
            let len = if i % 3 == 0 { 48 } else { 20 + i % 1100 };
            for x in &mut buf[..len] {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *x = (seed >> 24) as u8;
            }
            let _ = raw.send_to(&buf[..len], dest);
            if i % 100 == 0 {
                sleep_ms(5).await;
            }
        }
        // QUIC-подобный Initial настоящим клиентом quinn с IPv6-гнезда
        let sock = UdpSocket::bind("[::1]:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let ep = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            sock,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let hs = tokio::time::timeout(Duration::from_secs(2), raw_tls(&ep, dest)).await;
        let answered = matches!(hs, Ok(Ok(_)));
        let mut reply = [0u8; 64];
        let got_raw = raw.recv_from(&mut reply).is_ok();
        if required {
            assert!(!answered, "ответ постороннему по IPv6");
            assert!(!got_raw, "ответ на случайные датаграммы по IPv6");
            assert!(b.stats().dropped_unadmitted >= 1);
        } else {
            // контроль: без обязательного стука тот же клиент получает ответ
            assert!(answered, "нет контроля: при false тишина");
            seen_control = true;
        }
    }
    assert!(seen_control);
}

fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[allow(clippy::print_stdout)]
fn report_iters(n: u64) {
    println!("fuzz_smoke_src_canon iterations={n}");
}

/// Случайные 16 байт, `flowinfo`, `scope_id` и порт: канон идемпотентен и без паники, а решение
/// фильтра класса совпадает с `v6_peer_ok` (без стука, записи идут в quinn).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fuzz_smoke_src_canon() {
    let k = Keys::new();
    let (state, counters) = state_with(&k, false);
    let n = fuzz_iters();
    let mut s = 0x1234_5678_9ABC_DEF1u64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut storage = [0x40u8; 8];
    let mut dropped = 0u64;
    for i in 0..n {
        let (a, b) = (next(), next());
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&a.to_le_bytes());
        o[8..].copy_from_slice(&b.to_le_bytes());
        // каждый четвёртый: близко к границам классов (v4-mapped, ::/96, 2001::, 2002::, fe80::)
        match i % 8 {
            0 => {
                o[..10].fill(0);
                o[10] = 0xff;
                o[11] = 0xff;
            }
            1 => o[..12].fill(0),
            2 => {
                o[0] = 0x20;
                o[1] = 0x01;
            }
            3 => {
                o[0] = 0x20;
                o[1] = 0x02;
            }
            4 => {
                o[0] = 0xfe;
                o[1] = 0x80 | (o[1] & 0x3f);
            }
            _ => {}
        }
        let r = next();
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(o),
            r as u16,
            (r >> 16) as u32,
            (r >> 40) as u32,
        ));
        let c = canon(addr);
        assert_eq!(canon(c), c);
        let want_keep = match c {
            SocketAddr::V4(_) => true,
            SocketAddr::V6(v) => chervo_addr::v6_peer_ok(v.ip()),
        };
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        meta[0].addr = addr;
        meta[0].len = 8;
        let kept = state.filter_batch(&mut bufs, &mut meta, 1);
        assert_eq!(kept == 1, want_keep, "{addr:?}");
        if kept == 1
            && let SocketAddr::V6(v) = meta[0].addr
        {
            assert_eq!((v.flowinfo(), v.scope_id()), (0, 0));
        }
        if !want_keep {
            dropped += 1;
        }
    }
    assert_eq!(rd(&counters.dropped_src_class), dropped);
    report_iters(n);
}
