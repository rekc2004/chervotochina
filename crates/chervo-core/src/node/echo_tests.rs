#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Эхо-проба, план приглашения, помощник доступа и поддержание адреса без узла (этап 13д).
//! Тесты с настоящим узлом и настоящим сервером лежат в `tests/echo_net.rs`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chervo_addr::{AddrClass, NatView};
use chervo_connect::AllowSet;
use chervo_rendezvous_server::{Counters, ServerConfig, serve};
use chervo_transport::Transport as _;
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use tokio::sync::Notify;

use super::echo::{
    EchoPath, EchoReport, EchoResult, EchoVerdict, EchoVia, ExternalPlan, ForwardHelp, HelpInputs,
    KeepaliveJob, SkipReason, echo_verdict, forward_help_from, keepalive_loop,
    plan_invite_external,
};
use super::events::{EventSink, NodeEvent};
use super::settings::{EchoHost, Settings, parse, parse_echo_server, serialize};
use super::texts::NO_ADDRESS_TEXT;
use super::views::InviteRef;

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn sa(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(v4(a, b, c, d), port)
}

fn path(via: EchoVia, result: EchoResult) -> EchoPath {
    EchoPath { via, result }
}

fn ok(a: SocketAddrV4) -> EchoResult {
    EchoResult::Observed(a)
}

fn iface(a: u8, b: u8, c: u8, d: u8) -> EchoVia {
    EchoVia::Interface(v4(a, b, c, d))
}

const DEF: EchoVia = EchoVia::DefaultRoute;
const NOANS: EchoResult = EchoResult::NoAnswer;

// ------------------------------------------------------------------------------ настройки

fn recv_root() -> std::path::PathBuf {
    if cfg!(windows) {
        "C:\\recv".into()
    } else {
        "/recv".into()
    }
}

#[test]
fn echo_server_default_none() {
    let s = Settings::new(49152, recv_root(), false);
    assert_eq!(s.echo_server, None);
    let text = serialize(&s).unwrap();
    assert!(!text.contains("echo="), "строки echo без сервера нет");
}

#[test]
fn settings_echo_roundtrip() {
    for value in [
        "203.0.113.5:45900",
        "server.example:45900",
        "a-b.c.example:1",
        "198.51.100.7:65535",
    ] {
        let mut s = Settings::new(49152, recv_root(), false);
        s.echo_server = Some(value.to_owned());
        let text = serialize(&s).unwrap();
        assert!(text.contains(&format!("echo={value}\n")));
        let back = parse(text.as_bytes()).unwrap();
        assert_eq!(back, s);
        assert_eq!(serialize(&back).unwrap(), text);
    }
    // повтор строки и неверные значения в файле это SettingsCorrupt
    let base = serialize(&Settings::new(49152, recv_root(), false)).unwrap();
    for bad in [
        "echo=203.0.113.5:45900\necho=198.51.100.7:1\n",
        "echo=\n",
        "echo=203.0.113.5\n",
        "echo=http://x.example:80\n",
        "echo=[::1]:5000\n",
        "echo=x y:5000\n",
        "echo=203.0.113.5:0\n",
        "echo=203.0.113.5:65536\n",
        "echo=203.0.113.5:045900\n",
    ] {
        assert!(
            parse(format!("{base}{bad}").as_bytes()).is_err(),
            "принято: {bad}"
        );
    }
}

#[test]
fn set_echo_server_validation() {
    let good = [
        ("203.0.113.5:45900", EchoHost::Ip(v4(203, 0, 113, 5)), 45900),
        (
            "server.example:80",
            EchoHost::Name("server.example".to_owned()),
            80,
        ),
        ("localhost:1", EchoHost::Name("localhost".to_owned()), 1),
    ];
    for (text, host, port) in good {
        assert_eq!(parse_echo_server(text), Some((host, port)), "{text}");
    }
    let long_name = format!("{}.example:80", "a".repeat(250));
    let too_long = format!("{}:80", "a".repeat(260));
    let bad: Vec<&str> = vec![
        "",
        "203.0.113.5",
        ":80",
        "203.0.113.5:",
        "203.0.113.5:0",
        "203.0.113.5:65536",
        "203.0.113.5:08",
        "203.0.113.5:+80",
        "[2001:db8::1]:80",
        "2001:db8::1:80",
        "http://server.example:80",
        "server.example/path:80",
        "user@server.example:80",
        "server example:80",
        " server.example:80",
        "server.example:80 ",
        "server.example:80\n",
        "-bad.example:80",
        "bad-.example:80",
        "bad..example:80",
        ".bad.example:80",
        "1.2.3:80",
        "999.1.1.1:80",
        "1.2.3.4.5:80",
        "сервер.example:80",
        &long_name,
        &too_long,
    ];
    for text in bad {
        assert_eq!(parse_echo_server(text), None, "принято: {text:?}");
    }
    // граница длины: 259 символов принимаются, 260 нет
    let edge = format!("{}.{}:80", "a".repeat(63), "b".repeat(63));
    assert!(edge.len() <= 259 && parse_echo_server(&edge).is_some());
}

// ------------------------------------------------------------------------------ вердикт

#[test]
#[allow(clippy::type_complexity)]
fn echo_verdict_table() {
    let g1 = sa(8, 8, 8, 8, 40000);
    let g2 = sa(9, 9, 9, 9, 40000);
    let g1b = sa(8, 8, 8, 8, 40001);
    let weak = false;
    let strong = true;
    let cand = iface(192, 168, 1, 5);
    let cand2 = iface(10, 0, 0, 5);
    let none: Option<AddrClass> = None;
    let private = Some(AddrClass::Private);
    // (название, пути, класс d, strong_host, ожидание)
    let rows: Vec<(&str, Vec<EchoPath>, Option<AddrClass>, bool, EchoVerdict)> = vec![
        ("нет путей", vec![], none, strong, EchoVerdict::NoAnswer),
        (
            "никто не ответил",
            vec![path(DEF, NOANS), path(cand, NOANS)],
            private,
            strong,
            EchoVerdict::NoAnswer,
        ),
        (
            "отправка не удалась",
            vec![path(DEF, EchoResult::SendFailed)],
            private,
            strong,
            EchoVerdict::NoAnswer,
        ),
        (
            "сервер видит частный (путь по умолчанию)",
            vec![path(DEF, ok(sa(192, 168, 1, 7, 5)))],
            private,
            strong,
            EchoVerdict::ServerSeesPrivate,
        ),
        (
            "сервер видит петлю",
            vec![path(DEF, ok(sa(127, 0, 0, 1, 5)))],
            none,
            strong,
            EchoVerdict::ServerSeesPrivate,
        ),
        (
            "частный у кандидата важнее обхода",
            vec![path(DEF, ok(g1)), path(cand, ok(sa(10, 1, 1, 1, 5)))],
            private,
            strong,
            EchoVerdict::ServerSeesPrivate,
        ),
        (
            "кандидат дал другой IP: обход",
            vec![path(DEF, ok(g1)), path(cand, ok(g2))],
            private,
            strong,
            EchoVerdict::Bypassed { real: g2 },
        ),
        (
            "путь по умолчанию молчит, кандидат ответил: обход",
            vec![path(DEF, NOANS), path(cand, ok(g2))],
            private,
            strong,
            EchoVerdict::Bypassed { real: g2 },
        ),
        (
            "обход: берётся первый ответивший кандидат с другим IP",
            vec![path(DEF, ok(g1)), path(cand, ok(g1)), path(cand2, ok(g2))],
            private,
            strong,
            EchoVerdict::Bypassed { real: g2 },
        ),
        (
            "класс d Benchmark: похоже на VPN",
            vec![path(DEF, ok(g1))],
            Some(AddrClass::Benchmark),
            strong,
            EchoVerdict::MaybeVpn,
        ),
        (
            "класс d Shared: похоже на VPN",
            vec![path(DEF, ok(g1))],
            Some(AddrClass::Shared),
            strong,
            EchoVerdict::MaybeVpn,
        ),
        (
            "кандидаты есть, ни один не ответил",
            vec![path(DEF, ok(g1)), path(cand, NOANS), path(cand2, NOANS)],
            private,
            strong,
            EchoVerdict::MaybeVpn,
        ),
        (
            "не сильный хост, все кандидаты дали тот же IP",
            vec![path(DEF, ok(g1)), path(cand, ok(g1b)), path(cand2, ok(g1))],
            private,
            weak,
            EchoVerdict::MaybeVpn,
        ),
        (
            "сильный хост, все кандидаты дали тот же IP: один путь",
            vec![path(DEF, ok(g1)), path(cand, ok(g1b))],
            private,
            strong,
            EchoVerdict::Single,
        ),
        (
            "не сильный хост, часть кандидатов молчит: один путь",
            vec![path(DEF, ok(g1)), path(cand, ok(g1)), path(cand2, NOANS)],
            private,
            weak,
            EchoVerdict::Single,
        ),
        (
            "только путь по умолчанию",
            vec![path(DEF, ok(g1))],
            private,
            weak,
            EchoVerdict::Single,
        ),
        (
            "только путь по умолчанию, класс неизвестен",
            vec![path(DEF, ok(g1))],
            none,
            strong,
            EchoVerdict::Single,
        ),
    ];
    for (name, paths, class, strong_host, want) in rows {
        assert_eq!(echo_verdict(&paths, class, strong_host), want, "{name}");
    }
}

// ------------------------------------------------------------------------------ план

fn report(verdict: EchoVerdict, paths: Vec<EchoPath>) -> EchoReport {
    EchoReport {
        local_port: 45817,
        paths,
        verdict,
        reach_port: 45901,
    }
}

#[test]
fn plan_invite_external_table() {
    let seen = sa(203, 0, 113, 9, 40000);
    let real = sa(198, 51, 100, 4, 41000);
    let single = report(EchoVerdict::Single, vec![path(DEF, ok(seen))]);
    let maybe = report(EchoVerdict::MaybeVpn, vec![path(DEF, ok(seen))]);
    let bypassed = report(
        EchoVerdict::Bypassed { real },
        vec![path(DEF, ok(seen)), path(iface(192, 168, 1, 5), ok(real))],
    );
    let no_answer = report(EchoVerdict::NoAnswer, vec![path(DEF, NOANS)]);
    let local = report(EchoVerdict::ServerSeesPrivate, vec![path(DEF, ok(seen))]);
    let a = |x: SocketAddrV4| SocketAddr::V4(x);

    // порядок проверок: NoAnswer, ServerLocal, Symmetric, MaybeVpn, остальное
    assert_eq!(
        plan_invite_external(&no_answer, NatView::Eim, None),
        ExternalPlan::Skip(SkipReason::NoAnswer)
    );
    assert_eq!(
        plan_invite_external(&no_answer, NatView::Symmetric, None),
        ExternalPlan::Skip(SkipReason::NoAnswer)
    );
    assert_eq!(
        plan_invite_external(&local, NatView::Eim, None),
        ExternalPlan::Skip(SkipReason::ServerLocal)
    );
    assert_eq!(
        plan_invite_external(&local, NatView::Symmetric, None),
        ExternalPlan::Skip(SkipReason::ServerLocal)
    );
    assert_eq!(
        plan_invite_external(&single, NatView::Symmetric, None),
        ExternalPlan::Skip(SkipReason::Symmetric)
    );
    assert_eq!(
        plan_invite_external(&maybe, NatView::Symmetric, None),
        ExternalPlan::Skip(SkipReason::Symmetric)
    );
    assert_eq!(
        plan_invite_external(&maybe, NatView::Eim, None),
        ExternalPlan::AskVpn {
            addrs: vec![a(seen)]
        }
    );
    assert_eq!(
        plan_invite_external(&single, NatView::Eim, None),
        ExternalPlan::Add {
            addrs: vec![a(seen)],
            vpn_on: false
        }
    );
    // при обходе VPN в приглашение идёт настоящий адрес, VPN помечен включённым
    assert_eq!(
        plan_invite_external(&bypassed, NatView::Eim, None),
        ExternalPlan::Add {
            addrs: vec![a(real)],
            vpn_on: true
        }
    );
    // ручной проброс: тот же IP с другим портом вторым адресом; тот же порт не удваивается
    assert_eq!(
        plan_invite_external(&single, NatView::ManualForward, Some(45817)),
        ExternalPlan::Add {
            addrs: vec![a(seen), a(sa(203, 0, 113, 9, 45817))],
            vpn_on: false
        }
    );
    assert_eq!(
        plan_invite_external(&single, NatView::Eim, Some(40000)),
        ExternalPlan::Add {
            addrs: vec![a(seen)],
            vpn_on: false
        }
    );
    assert_eq!(
        plan_invite_external(&maybe, NatView::Eim, Some(45817)),
        ExternalPlan::AskVpn {
            addrs: vec![a(seen), a(sa(203, 0, 113, 9, 45817))]
        }
    );
}

#[test]
fn debug_of_new_types_has_no_addresses() {
    let seen = sa(203, 0, 113, 9, 40000);
    let r = report(
        EchoVerdict::Bypassed { real: seen },
        vec![path(iface(192, 168, 1, 5), ok(seen))],
    );
    let plan = plan_invite_external(&r, NatView::Eim, Some(45817));
    let help = ForwardHelp {
        port: 45817,
        home: vec![v4(192, 168, 1, 5)],
        gw: Some(v4(192, 168, 1, 1)),
        gw_exact: true,
        vpn: false,
        cgnat: false,
    };
    let shown = [
        format!("{r:?}"),
        format!("{:?}", r.paths[0]),
        format!("{:?}", r.paths[0].via),
        format!("{:?}", r.paths[0].result),
        format!("{:?}", r.verdict),
        format!("{plan:?}"),
        format!("{help:?}"),
        format!("{help:#?}"),
    ];
    for text in &shown {
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "в Debug есть цифры: {text}"
        );
    }
}

// ------------------------------------------------------------------------------ помощник

fn inputs(report: Option<&EchoReport>) -> HelpInputs<'_> {
    HelpInputs {
        port: 45817,
        lan_ip: None,
        lan_route_source: None,
        report,
        default_src: Some(v4(192, 168, 1, 5)),
        private_srcs: vec![v4(192, 168, 1, 5)],
        nat: NatView::Eim,
    }
}

#[test]
fn forward_help_values() {
    // без роутера и пробы: домашний адрес по маршруту, адрес роутера a.b.c.1 (догадка)
    let h = forward_help_from(&inputs(None));
    assert_eq!(h.port, 45817);
    assert_eq!(h.home, [v4(192, 168, 1, 5)]);
    assert_eq!(h.gw, Some(v4(192, 168, 1, 1)));
    assert!(!h.gw_exact && !h.vpn && !h.cgnat);

    // роутер назвал себя: адрес точный, домашний адрес по маршруту к нему
    let mut i = inputs(None);
    i.lan_ip = Some(v4(10, 20, 30, 254));
    i.lan_route_source = Some(v4(10, 20, 30, 7));
    let h = forward_help_from(&i);
    assert_eq!(h.home, [v4(10, 20, 30, 7)]);
    assert_eq!(h.gw, Some(v4(10, 20, 30, 254)));
    assert!(h.gw_exact);

    // роутер назвал себя, но маршрут к нему не определился: домашний адрес по общим правилам,
    // адрес роутера всё равно точный
    let mut i = inputs(None);
    i.lan_ip = Some(v4(10, 20, 30, 254));
    let h = forward_help_from(&i);
    assert_eq!(h.home, [v4(192, 168, 1, 5)]);
    assert_eq!(h.gw, Some(v4(10, 20, 30, 254)));
    assert!(h.gw_exact);

    // VPN обойдён через кандидата c: домашний адрес c, пометка VPN
    let real = sa(198, 51, 100, 4, 41000);
    let r = report(
        EchoVerdict::Bypassed { real },
        vec![
            path(DEF, ok(sa(203, 0, 113, 9, 40000))),
            path(iface(172, 16, 4, 9), ok(real)),
        ],
    );
    let mut i = inputs(Some(&r));
    i.default_src = Some(v4(198, 18, 0, 1));
    i.private_srcs = vec![v4(172, 16, 4, 9), v4(192, 168, 1, 5)];
    let h = forward_help_from(&i);
    assert_eq!(h.home, [v4(172, 16, 4, 9)]);
    assert_eq!(h.gw, Some(v4(172, 16, 4, 1)));
    assert!(h.vpn && !h.gw_exact);

    // туннель по классу d (не частный): d в список не входит, остальные по порядку
    let mut i = inputs(None);
    i.default_src = Some(v4(198, 18, 0, 1));
    i.private_srcs = vec![v4(192, 168, 1, 5), v4(10, 0, 0, 8)];
    let h = forward_help_from(&i);
    assert_eq!(h.home, [v4(192, 168, 1, 5), v4(10, 0, 0, 8)]);
    assert_eq!(h.gw, Some(v4(192, 168, 1, 1)));

    // MaybeVpn при частном d: d тоже считается туннелем и убирается
    let maybe = report(
        EchoVerdict::MaybeVpn,
        vec![path(DEF, ok(sa(203, 0, 113, 9, 40000)))],
    );
    let mut i = inputs(Some(&maybe));
    i.default_src = Some(v4(10, 8, 0, 2));
    i.private_srcs = vec![v4(10, 8, 0, 2), v4(192, 168, 1, 5)];
    let h = forward_help_from(&i);
    assert_eq!(h.home, [v4(192, 168, 1, 5)]);
    assert!(h.vpn);

    // обычный случай: d первым, затем остальные; не больше четырёх
    let mut i = inputs(None);
    i.private_srcs = vec![
        v4(10, 0, 0, 1),
        v4(192, 168, 1, 5),
        v4(172, 16, 0, 2),
        v4(10, 0, 0, 3),
        v4(10, 0, 0, 4),
    ];
    let h = forward_help_from(&i);
    assert_eq!(h.home.len(), 4);
    assert_eq!(h.home[0], v4(192, 168, 1, 5));

    // домашних адресов нет: роутер не угадывается
    let mut i = inputs(None);
    i.default_src = None;
    i.private_srcs = vec![];
    let h = forward_help_from(&i);
    assert!(h.home.is_empty() && h.gw.is_none() && !h.gw_exact);

    // CGNAT и двойной NAT
    for nat in [NatView::BehindCgnat, NatView::DoubleNat] {
        let mut i = inputs(None);
        i.nat = nat;
        assert!(forward_help_from(&i).cgnat);
    }
}

#[test]
fn no_address_text_names_actions() {
    // В4: текст говорит, что делать
    assert!(NO_ADDRESS_TEXT.contains("Разрешить входящие подключения"));
    assert!(NO_ADDRESS_TEXT.contains("Связь через интернет"));
    assert!(NO_ADDRESS_TEXT.contains("Создать приглашение"));
    assert!(!NO_ADDRESS_TEXT.contains("пробросом порта"));
    // правило 18б п.8: слова «токен» нет
    assert!(!NO_ADDRESS_TEXT.to_lowercase().contains("токен"));
}

// ------------------------------------------------------------------------------ поддержание

struct Srv {
    addr: SocketAddrV4,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Srv {
    fn start() -> Self {
        let cfg = ServerConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            reach_port: None,
            allow_private: true,
            report_every: Duration::from_secs(3600),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let s2 = stop.clone();
        let join = std::thread::spawn(move || {
            let _ = serve(cfg, s2, move |a| tx.send(a).unwrap(), |_: &Counters| {});
        });
        let SocketAddr::V4(addr) = rx.recv_timeout(Duration::from_secs(5)).unwrap()[0] else {
            panic!("IPv4");
        };
        Self {
            addr,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for Srv {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn transport() -> Arc<QuinnTransport> {
    let filter: Arc<dyn chervo_transport::PeerFilter> = AllowSet::new();
    Arc::new(
        QuinnTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            QuinnConfig::default(),
            filter,
        )
        .unwrap(),
    )
}

fn invite_ref() -> InviteRef {
    InviteRef::new(chervo_identity::PairId::generate().unwrap())
}

fn job(
    t: &Arc<QuinnTransport>,
    sink: &Arc<EventSink>,
    server: SocketAddrV4,
    baseline: SocketAddrV4,
    every: Duration,
    lifetime: Duration,
) -> KeepaliveJob {
    KeepaliveJob {
        transport: t.clone(),
        sink: sink.clone(),
        invite: invite_ref(),
        server,
        via: None,
        baseline,
        every,
        lifetime,
    }
}

fn changed(e: &NodeEvent) -> bool {
    matches!(e, NodeEvent::InviteAddressChanged { .. })
}

#[tokio::test]
async fn keepalive_change_emits_event() {
    let srv = Srv::start();
    let t = transport();
    let port = t.local_addrs()[0].port();
    let (sink, events) = EventSink::channel();
    let same = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    // адрес не менялся: событий нет, поддержание продолжается
    let stop = Arc::new(Notify::new());
    let task = tokio::spawn(keepalive_loop(
        job(
            &t,
            &sink,
            srv.addr,
            same,
            Duration::from_millis(200),
            Duration::from_secs(60),
        ),
        stop.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(events.try_recv().is_err(), "событие без смены адреса");
    assert!(!task.is_finished());
    stop.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();

    // адрес в приглашении отличается от видимого серверу: событие один раз
    let other = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 5);
    let stop = Arc::new(Notify::new());
    let task = tokio::spawn(keepalive_loop(
        job(
            &t,
            &sink,
            srv.addr,
            other,
            Duration::from_millis(200),
            Duration::from_secs(60),
        ),
        stop.clone(),
    ));
    let got = tokio::task::spawn_blocking(move || {
        let e = events.recv_timeout(Duration::from_secs(5));
        (e.is_ok_and(|e| changed(&e)), events)
    })
    .await
    .unwrap();
    assert!(got.0, "события о смене адреса нет");
    // дальше адрес стабилен: второго события нет
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        got.1.try_recv().is_err(),
        "повторное событие без новой смены"
    );
    stop.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn keepalive_stops_on_sas_cancel_expiry() {
    // остановка по сигналу (SAS, отмена, конец приглашения) и по сроку; сервер не нужен:
    // проба в это время не успевает начаться
    let t = transport();
    let (sink, _events) = EventSink::channel();
    let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    let base = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    for lifetime_case in [false, true] {
        let stop = Arc::new(Notify::new());
        let (every, lifetime) = if lifetime_case {
            (Duration::from_millis(50), Duration::from_millis(10))
        } else {
            (Duration::from_secs(3600), Duration::from_secs(3600))
        };
        let task = tokio::spawn(keepalive_loop(
            job(&t, &sink, server, base, every, lifetime),
            stop.clone(),
        ));
        if !lifetime_case {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!task.is_finished());
            stop.notify_one();
        }
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("поддержание не остановилось")
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    // сигнал, поданный до первого ожидания, не теряется
    let stop = Arc::new(Notify::new());
    stop.notify_one();
    let task = tokio::spawn(keepalive_loop(
        job(
            &t,
            &sink,
            server,
            base,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        ),
        stop,
    ));
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn keepalive_three_misses_emit_event() {
    // «сервер» молчит: три пробы подряд без ответа дают одно событие, поддержание живёт дальше
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(addr) = silent.local_addr().unwrap() else {
        panic!("IPv4");
    };
    let t = transport();
    let (sink, events) = EventSink::channel();
    let stop = Arc::new(Notify::new());
    let started = Instant::now();
    let task = tokio::spawn(keepalive_loop(
        job(
            &t,
            &sink,
            addr,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
            Duration::from_millis(50),
            Duration::from_secs(120),
        ),
        stop.clone(),
    ));
    let got = tokio::task::spawn_blocking(move || {
        let e = events.recv_timeout(Duration::from_secs(20));
        (e.is_ok_and(|e| changed(&e)), events)
    })
    .await
    .unwrap();
    assert!(got.0, "события после трёх проб без ответа нет");
    // три пробы по 3 с: раньше восьми секунд события быть не может
    assert!(
        started.elapsed() >= Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    assert!(!task.is_finished(), "поддержание должно продолжаться");
    stop.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    drop(got.1);
}

// ------------------------------------------------------------------------ круг 1: DNS и роутер

#[test]
fn resolve_name_refused_while_previous_dns_hangs() {
    use super::echo::resolve;
    use super::error::{EchoFailure, NodeError};
    // зависший поток DNS держит флаг: новое разрешение имени получает «занято», сети не трогает
    let busy = Arc::new(AtomicBool::new(true));
    let r = resolve(EchoHost::Name("server.example".to_owned()), 45900, &busy);
    assert_eq!(r.err(), Some(NodeError::Echo(EchoFailure::Busy)));
    assert!(
        busy.load(Ordering::SeqCst),
        "флаг чужого потока не трогается"
    );
    // литерал адреса DNS не использует и флагом не задерживается
    let ip = resolve(EchoHost::Ip(v4(203, 0, 113, 5)), 45900, &busy).unwrap();
    assert_eq!(ip, sa(203, 0, 113, 5, 45900));
}

#[test]
fn resolve_name_releases_flag_when_done() {
    use super::echo::resolve;
    let busy = Arc::new(AtomicBool::new(false));
    // результат не важен (зависит от окружения), важно, что флаг снят после ответа
    let _ = resolve(EchoHost::Name("localhost".to_owned()), 45900, &busy);
    assert!(
        !busy.load(Ordering::SeqCst),
        "флаг остался после разрешения"
    );
}

#[test]
fn allowed_addr_only_in_same_network() {
    use super::echo::AllowedAddr;
    let id = chervo_upnp::RouterId::from_setting("uuid:unit-router").unwrap();
    let other = chervo_upnp::RouterId::from_setting("uuid:unit-other").unwrap();
    let a = AllowedAddr::with_source(id.clone(), v4(10, 0, 0, 1), Some(v4(10, 0, 0, 7)));
    assert!(a.same_network(Some(v4(10, 0, 0, 7))));
    assert!(!a.same_network(Some(v4(192, 168, 1, 7))), "другая сеть");
    assert!(!a.same_network(None), "маршрута к роутеру больше нет");
    assert!(a.is_router(&id) && !a.is_router(&other));
    // источник неизвестен уже при «Разрешить»: точным адрес не считается никогда
    let b = AllowedAddr::with_source(id, v4(10, 0, 0, 1), None);
    assert!(!b.same_network(None));
}
