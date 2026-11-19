//! Эхо-проба и проверка доступа (этап 13д): настоящее гнездо транспорта против поддельного
//! сервера на петле (потоки std). Поддельный сервер говорит по `chervo-rendezvous-wire`.
//! Тесты, где ответа быть не должно, идут весь срок пробы (3 с).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chervo_rendezvous_wire::{
    Nonce, REQUEST_LEN, RESPONSE_LEN, Request, encode_echo_response, encode_reach_response,
    parse_request,
};
use chervo_transport::{Connection, RecvStream, SendStream, Transport};

use super::kit::*;
use super::misc::alive;
use crate::{
    ECHO_DEADLINE, ECHO_MAX_PATHS, EchoError, EchoPathResult, QuinnConfig, QuinnTransport,
};

/// Порт проверки, который поддельный сервер называет в ответе эхо.
const REACH_PORT: u16 = 4242;

fn cfg(knock: bool) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        knock_required: knock,
        ..test_cfg()
    }
}

fn port_of(t: &QuinnTransport) -> u16 {
    t.local_addrs()[0].port()
}

type Log = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

/// Что поддельный сервер делает с принятым запросом.
struct Ctx {
    main: UdpSocket,
    second: UdpSocket,
    n: usize,
}

struct Fake {
    main_addr: SocketAddrV4,
    second_addr: SocketAddrV4,
    log: Log,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Fake {
    fn start(
        ip: Ipv4Addr,
        mut handler: impl FnMut(&Ctx, SocketAddr, &[u8]) + Send + 'static,
    ) -> Self {
        let main = UdpSocket::bind((ip, 0)).unwrap();
        let second = UdpSocket::bind((ip, 0)).unwrap();
        main.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let (SocketAddr::V4(main_addr), SocketAddr::V4(second_addr)) =
            (main.local_addr().unwrap(), second.local_addr().unwrap())
        else {
            panic!("IPv4");
        };
        let log: Log = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (l2, s2) = (log.clone(), stop.clone());
        let join = std::thread::spawn(move || {
            let mut ctx = Ctx { main, second, n: 0 };
            let mut buf = [0u8; 2048];
            while !s2.load(Ordering::Relaxed) {
                if let Ok((n, src)) = ctx.main.recv_from(&mut buf) {
                    l2.lock().unwrap().push((src, buf[..n].to_vec()));
                    ctx.n += 1;
                    handler(&ctx, src, &buf[..n]);
                }
            }
        });
        Self {
            main_addr,
            second_addr,
            log,
            stop,
            join: Some(join),
        }
    }

    fn requests(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn lo4() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

/// Верный сервер: на эхо отвечает наблюдаемым адресом с основного порта; на проверку доступа
/// отвечает со второго порта на порт из запроса.
fn honest(ctx: &Ctx, src: SocketAddr, data: &[u8]) {
    match parse_request(data) {
        Ok(Request::Echo(n)) => {
            let _ = ctx
                .main
                .send_to(&encode_echo_response(&n, src, REACH_PORT), src);
        }
        Ok(Request::Reach { nonce, target_port }) => {
            let to = SocketAddr::new(src.ip(), target_port);
            let _ = ctx.second.send_to(&encode_reach_response(&nonce, src), to);
        }
        Err(_) => {}
    }
}

fn nonce_of(data: &[u8]) -> Nonce {
    let mut b = [0u8; 16];
    b.copy_from_slice(&data[8..24]);
    Nonce(b)
}

fn observed(r: &EchoPathResult) -> (SocketAddrV4, u16) {
    match r {
        EchoPathResult::Observed { addr, reach_port } => (*addr, *reach_port),
        other => panic!("ожидался ответ, получено {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_loopback_default_path() {
    // и при обязательном стуке, и без него ответ забирается гнездом
    for knock in [false, true] {
        let t = bind(cfg(knock), vec![]);
        let server = Fake::start(lo4(), honest);
        let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
        assert_eq!(r.len(), 1);
        let (addr, reach) = observed(&r[0]);
        assert_eq!(*addr.ip(), lo4(), "knock = {knock}");
        assert_eq!(addr.port(), port_of(&t));
        assert_eq!(reach, REACH_PORT);
        // запрос ушёл ровно один раз, длиной 64
        let seen = server.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1.len(), REQUEST_LEN);
    }
}

/// Адрес источника на один пакет: сервер видит 127.0.0.2, а не 127.0.0.1. Гнездо на 0.0.0.0, как
/// в продукте. На Windows и Linux это IN_PKTINFO. На macOS источник не применяется (решение
/// владельца), там действует `echo_macos_source_ignored`.
#[cfg(not(target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_loopback_src_ip() {
    let t =
        QuinnTransport::bind("0.0.0.0:0".parse().unwrap(), cfg(false), Arc::new(AllowAll)).unwrap();
    let other = Ipv4Addr::new(127, 0, 0, 2);
    let server = Fake::start(lo4(), honest);
    let r = t
        .echo_probe(server.main_addr, &[None, Some(other)])
        .await
        .unwrap();
    assert_eq!(r.len(), 2);
    let seen: Vec<SocketAddr> = server.requests().iter().map(|(s, _)| *s).collect();
    assert!(
        r.iter()
            .all(|p| matches!(p, EchoPathResult::Observed { .. })),
        "пути: {r:?}; сервер видел запросы от: {seen:?}"
    );
    let (default_path, via_other) = (observed(&r[0]).0, observed(&r[1]).0);
    assert_eq!(*default_path.ip(), lo4());
    assert_eq!(*via_other.ip(), other, "адрес источника не применился");
    assert_eq!(via_other.port(), port_of(&t));
    // у сервера два запроса с двух адресов источника
    let mut ips: Vec<_> = server.requests().iter().map(|(s, _)| s.ip()).collect();
    ips.sort();
    assert_eq!(ips, [lo4(), other].map(std::net::IpAddr::V4));
}

/// macOS: quinn-udp передаёт источник через `IP_RECVDSTADDR`, а macOS при отправке это игнорирует
/// (CI: сервер видел 127.0.0.1). Решение владельца: принято, обход VPN на macOS не работает.
/// Тест фиксирует фактическое поведение: кандидат даёт тот же наблюдаемый IP, что путь по
/// умолчанию, или честное `SendFailed`; адрес источника не применяется. Вердикт ядра на таком
/// ответе `MaybeVpn` (`echo_verdict_table`: «не сильный хост, все кандидаты дали тот же IP»), а не
/// `Bypassed`. На других системах источник обязан примениться (`echo_loopback_src_ip`).
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_macos_source_ignored() {
    let t =
        QuinnTransport::bind("0.0.0.0:0".parse().unwrap(), cfg(false), Arc::new(AllowAll)).unwrap();
    let other = Ipv4Addr::new(127, 0, 0, 2);
    let server = Fake::start(lo4(), honest);
    let r = t
        .echo_probe(server.main_addr, &[None, Some(other)])
        .await
        .unwrap();
    let seen: Vec<SocketAddr> = server.requests().iter().map(|(s, _)| *s).collect();
    let default_path = observed(&r[0]).0;
    match &r[1] {
        EchoPathResult::Observed { addr, .. } => {
            assert_eq!(
                addr.ip(),
                default_path.ip(),
                "пути: {r:?}; сервер: {seen:?}"
            );
        }
        EchoPathResult::SendFailed => {}
        EchoPathResult::NoAnswer => panic!("отправка принята, ответа нет: {r:?}; сервер: {seen:?}"),
    }
}

/// Источник, которого нет на компьютере, ОС отвергает (Windows: `WSAEINVAL` 10022 для
/// 192.0.2.1, Linux: `EINVAL` при выборе маршрута). Раньше `AsyncUdpSocket::try_send` quinn
/// проглатывал ошибку и путь получал ложное «отправлено» (`NoAnswer`). Теперь `SendFailed`;
/// запрос ушёл только по пути по умолчанию. macOS источник игнорирует (см. выше), там проверяется
/// только путь по умолчанию.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_unusable_source_is_send_failed() {
    let t =
        QuinnTransport::bind("0.0.0.0:0".parse().unwrap(), cfg(false), Arc::new(AllowAll)).unwrap();
    let server = Fake::start(lo4(), honest);
    let r = t
        .echo_probe(server.main_addr, &[None, Some(Ipv4Addr::new(192, 0, 2, 1))])
        .await
        .unwrap();
    assert_eq!(r.len(), 2);
    observed(&r[0]);
    if !cfg!(target_os = "macos") {
        assert_eq!(r[1], EchoPathResult::SendFailed, "пути: {r:?}");
        // у сервера один запрос: с пути по умолчанию
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_wrong_nonce_ignored() {
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), |ctx, src, data| {
        let other = Nonce([0x5A; 16]);
        assert_ne!(other, nonce_of(data));
        let _ = ctx
            .main
            .send_to(&encode_echo_response(&other, src, REACH_PORT), src);
    });
    let started = Instant::now();
    let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
    assert_eq!(r, [EchoPathResult::NoAnswer]);
    assert!(started.elapsed() >= ECHO_DEADLINE - Duration::from_millis(100));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_wrong_source_port_ignored() {
    // верный ответ, но со второго порта: для эхо источник обязан быть точным ip:портом сервера
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), |ctx, src, data| {
        let n = nonce_of(data);
        let _ = ctx
            .second
            .send_to(&encode_echo_response(&n, src, REACH_PORT), src);
    });
    let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
    assert_eq!(r, [EchoPathResult::NoAnswer]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_malformed_replies_ignored() {
    // мусор, обрезки и порча каждого поля с верным nonce не принимаются; затем верный ответ да
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), |ctx, src, data| {
        let n = nonce_of(data);
        let good = encode_echo_response(&n, src, REACH_PORT);
        let mut bad: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xFF; RESPONSE_LEN],
            good[..RESPONSE_LEN - 1].to_vec(),
            [good.as_slice(), &[0]].concat(),
            data.to_vec(),
        ];
        for at in [0usize, 4, 5, 6, 24, 25, 46, 47] {
            let mut m = good;
            m[at] ^= 0x7F;
            bad.push(m.to_vec());
        }
        // порт 0 и адрес 0.0.0.0 после XOR: собираем ответ с нулями
        let zero_port = encode_echo_response(&n, SocketAddr::new(src.ip(), 1), 0);
        let mut zp = zero_port;
        zp[26] = n.0[0];
        zp[27] = n.0[1];
        bad.push(zp.to_vec());
        for m in &bad {
            let _ = ctx.main.send_to(m, src);
        }
        // верный ответ только на последний (третий) повтор запроса
        if ctx.n >= 3 {
            let _ = ctx.main.send_to(&good, src);
        }
    });
    let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
    let (addr, reach) = observed(&r[0]);
    assert_eq!(addr.port(), port_of(&t));
    assert_eq!(reach, REACH_PORT);
    // непринятые датаграммы пошли обычным путём и были отброшены как у любого недопущенного
    assert!(t.stats().dropped_unadmitted > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_retries_until_answer() {
    let t = bind(cfg(true), vec![]);
    // молчит на первые два запроса, отвечает на третий
    let server = Fake::start(lo4(), |ctx, src, data| {
        if ctx.n >= 3 {
            honest(ctx, src, data);
        }
    });
    let started = Instant::now();
    let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
    observed(&r[0]);
    let el = started.elapsed();
    assert!(el >= Duration::from_millis(1900), "{el:?}");
    assert!(el < ECHO_DEADLINE, "{el:?}");
    let seen = server.requests();
    assert_eq!(seen.len(), 3);
    // повторы одного пути несут один и тот же nonce
    assert_eq!(nonce_of(&seen[0].1), nonce_of(&seen[2].1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_no_answer_within_deadline() {
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), |_, _, _| {});
    let started = Instant::now();
    let r = t.echo_probe(server.main_addr, &[None, None]).await.unwrap();
    let el = started.elapsed();
    assert_eq!(r, [EchoPathResult::NoAnswer, EchoPathResult::NoAnswer]);
    assert!(el >= ECHO_DEADLINE - Duration::from_millis(100), "{el:?}");
    assert!(el <= Duration::from_millis(3100), "{el:?}");
    // не больше трёх запросов на путь, разные пути с разными nonce
    let seen = server.requests();
    assert_eq!(seen.len(), 6);
    let mut nonces: Vec<[u8; 16]> = seen.iter().map(|(_, d)| nonce_of(d).0).collect();
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(nonces.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_busy() {
    let t = Arc::new(bind(cfg(true), vec![]));
    let server = Fake::start(lo4(), |_, _, _| {});
    let (t2, addr) = (t.clone(), server.main_addr);
    let first = tokio::spawn(async move { t2.echo_probe(addr, &[None]).await });
    sleep_ms(300).await;
    assert_eq!(
        t.echo_probe(server.main_addr, &[None]).await,
        Err(EchoError::Busy)
    );
    assert_eq!(
        t.reach_probe(server.main_addr, None, 5000).await,
        Err(EchoError::Busy)
    );
    assert_eq!(first.await.unwrap().unwrap(), [EchoPathResult::NoAnswer]);
    // после окончания пробы гнездо свободно, фильтр выключен
    assert!(!t.inner.knock.echo_active.load(Ordering::Acquire));
    assert!(t.inner.knock.echo.lock().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_bad_server() {
    let t = bind(cfg(true), vec![]);
    let bad = [
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5000),
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 5000),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, 5000),
        SocketAddrV4::new(lo4(), 0),
    ];
    for s in bad {
        assert_eq!(t.echo_probe(s, &[None]).await, Err(EchoError::BadServer));
        assert_eq!(
            t.reach_probe(s, None, 5000).await,
            Err(EchoError::BadServer)
        );
    }
    let server = Fake::start(lo4(), honest);
    // порт проверки 0 бессмыслен
    assert_eq!(
        t.reach_probe(server.main_addr, None, 0).await,
        Err(EchoError::BadServer)
    );
    let many = vec![None; ECHO_MAX_PATHS + 1];
    assert_eq!(
        t.echo_probe(server.main_addr, &many).await,
        Err(EchoError::TooManyPaths)
    );
    // ни один пакет не отправлен
    sleep_ms(100).await;
    assert!(server.requests().is_empty());
}

/// Ответ эхо не открывает допуск адресу сервера: чужие пакеты оттуда по-прежнему молча
/// отбрасываются, и сам ответ не считается «отброшенным недопущенным».
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_does_not_admit() {
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), honest);
    let r = t.echo_probe(server.main_addr, &[None]).await.unwrap();
    observed(&r[0]);
    assert_eq!(t.stats().dropped_unadmitted, 0);
    assert_eq!(
        t.inner
            .knock
            .peek_admission(SocketAddr::V4(server.main_addr)),
        None
    );
    // после пробы тот же адрес шлёт обычный пакет: он отбрасывается как у любого чужого
    let dest = SocketAddr::new(lo4().into(), port_of(&t));
    let other = UdpSocket::bind((lo4(), 0)).unwrap();
    other.send_to(&[7u8; 100], dest).unwrap();
    sleep_ms(300).await;
    assert_eq!(t.stats().dropped_unadmitted, 1);
    assert_eq!(
        t.inner
            .knock
            .peek_admission(SocketAddr::V4(server.main_addr)),
        None
    );
}

/// Проба при живом соединении с другом: соединение не страдает, ответ находится.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_during_friend_connection() {
    let k = Keys::new();
    let a = bind(cfg(true), vec![k.peer_a()]);
    let b = bind(cfg(true), vec![k.peer_b()]);
    let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let cb = b.accept().await.unwrap();
    assert!(alive(&ca) && alive(&cb));
    let server = Fake::start(lo4(), honest);
    // друг шлёт данные, пока идёт проба
    let (mut tx, _rx) = ca.open_bi().await.unwrap();
    tx.write_all(b"before").await.unwrap();
    let probe = a.echo_probe(server.main_addr, &[None]).await.unwrap();
    observed(&probe[0]);
    tx.write_all(b"after").await.unwrap();
    tx.finish().unwrap();
    let (_btx, mut brx) = cb.accept_bi().await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while let Some(n) = brx.read(&mut buf).await.unwrap() {
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"beforeafter");
    assert!(alive(&ca) && alive(&cb));
}

// --- проверка доступа ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reach_probe_loopback_ok() {
    for knock in [false, true] {
        let t = bind(cfg(knock), vec![]);
        let server = Fake::start(lo4(), honest);
        let ok = t
            .reach_probe(server.main_addr, None, port_of(&t))
            .await
            .unwrap();
        assert!(ok, "knock = {knock}");
        assert_eq!(t.stats().dropped_unadmitted, 0);
        // запрос один, проверка достигла сервера на основном порту
        assert_eq!(server.requests().len(), 1);
        assert_ne!(server.second_addr.port(), server.main_addr.port());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reach_probe_reply_from_main_port_rejected() {
    // ответ проверки с основного порта не доказывает доступ: нужен другой порт того же IP
    let t = bind(cfg(true), vec![]);
    let server = Fake::start(lo4(), |ctx, src, data| {
        if let Ok(Request::Reach { nonce, target_port }) = parse_request(data) {
            let to = SocketAddr::new(src.ip(), target_port);
            let _ = ctx.main.send_to(&encode_reach_response(&nonce, src), to);
        }
    });
    let ok = t
        .reach_probe(server.main_addr, None, port_of(&t))
        .await
        .unwrap();
    assert!(!ok);
    // ответ эха (тип 2) со второго порта тоже не принимается за проверку
    let server = Fake::start(lo4(), |ctx, src, data| {
        if let Ok(Request::Reach { nonce, target_port }) = parse_request(data) {
            let to = SocketAddr::new(src.ip(), target_port);
            let _ = ctx
                .second
                .send_to(&encode_echo_response(&nonce, src, REACH_PORT), to);
        }
    });
    let ok = t
        .reach_probe(server.main_addr, None, port_of(&t))
        .await
        .unwrap();
    assert!(!ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reach_probe_other_ip_rejected() {
    // ответ проверки с другого IP (127.0.0.2), а не с IP сервера, не принимается
    let t = bind(cfg(true), vec![]);
    let impostor = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    let server = Fake::start(lo4(), move |_, src, data| {
        if let Ok(Request::Reach { nonce, target_port }) = parse_request(data) {
            let to = SocketAddr::new(src.ip(), target_port);
            let _ = impostor.send_to(&encode_reach_response(&nonce, src), to);
        }
    });
    let ok = t
        .reach_probe(server.main_addr, None, port_of(&t))
        .await
        .unwrap();
    assert!(!ok);
}
