#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Узел против настоящего эхо-сервера на петле (этап 13д): проба, приглашение с адресом от эхо,
//! поддержание адреса, проверка доступа, помощник. Сервер запущен с `allow_private`: на петле
//! настоящий вердикт «сервер видит частный адрес» (`ServerSeesPrivate`), поэтому часть тестов
//! подставляет вердикт `Single` в уже полученный отчёт и проверяет остальную цепочку.

#[path = "support/harness.rs"]
mod harness;

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chervo_core::chervo_token::{Token, decode};
use chervo_core::{
    EchoFailure, EchoReport, EchoResult, EchoVerdict, EchoVia, ExternalPlan, Node, NodeError,
    NodeEvent, ReachResult, SkipReason, plan_invite_external,
};
use chervo_rendezvous_server::{Counters, ServerConfig, serve};
use harness::{Rig, Watch};

const LONG: Duration = Duration::from_secs(40);

/// Настоящий сервер на петле. Счётчики обновляются каждые 20 мс.
struct Server {
    addr: SocketAddrV4,
    counters: Arc<Mutex<Counters>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Server {
    fn start(with_reach: bool) -> Self {
        let cfg = ServerConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            reach_port: with_reach.then(free_udp),
            allow_private: true,
            report_every: Duration::from_millis(20),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Mutex::new(Counters::default()));
        let (tx, rx) = mpsc::channel();
        let (s2, c2) = (stop.clone(), counters.clone());
        let join = std::thread::spawn(move || {
            serve(
                cfg,
                s2,
                move |a| tx.send(a).unwrap(),
                move |c| *c2.lock().unwrap() = *c,
            )
            .unwrap();
        });
        let SocketAddr::V4(addr) = rx.recv_timeout(Duration::from_secs(5)).unwrap()[0] else {
            panic!("IPv4");
        };
        Self {
            addr,
            counters,
            stop,
            join: Some(join),
        }
    }

    fn text(&self) -> String {
        self.addr.to_string()
    }

    /// Принятых сервером датаграмм (счётчик обновляется раз в 20 мс).
    fn requests(&self) -> u64 {
        std::thread::sleep(Duration::from_millis(80));
        self.counters.lock().unwrap().requests
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn start_node(tag: &str) -> (Rig, Node, Watch) {
    let rig = Rig::new(tag);
    let (node, ev) = rig.start_with_min_free(0);
    (rig, node, Watch::new(ev))
}

/// Отчёт, у которого сервер «глобальный»: настоящий вердикт на петле другой.
fn as_global(r: &EchoReport) -> EchoReport {
    let mut r = r.clone();
    r.verdict = EchoVerdict::Single;
    r
}

fn first_observed(r: &EchoReport) -> SocketAddrV4 {
    match r.paths[0].result {
        EchoResult::Observed(a) => a,
        other => panic!("ответа нет: {other:?}"),
    }
}

// ------------------------------------------------------------------------------ настройки

#[test]
fn echo_server_setting_is_saved_and_cleared() {
    let (rig, node, _w) = start_node("echo-set");
    assert_eq!(node.settings().echo_server, None);
    assert_eq!(
        node.set_echo_server(Some("http://x.example:80")),
        Err(NodeError::Echo(EchoFailure::BadAddress))
    );
    assert_eq!(
        node.set_echo_server(Some("203.0.113.5")),
        Err(NodeError::Echo(EchoFailure::BadAddress))
    );
    assert_eq!(node.settings().echo_server, None);
    node.set_echo_server(Some(" 203.0.113.5:45900 ")).unwrap();
    assert_eq!(
        node.settings().echo_server.as_deref(),
        Some("203.0.113.5:45900")
    );
    node.shutdown(Duration::from_secs(5));
    // строка переживает перезапуск
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(
        node.settings().echo_server.as_deref(),
        Some("203.0.113.5:45900")
    );
    node.set_echo_server(None).unwrap();
    assert_eq!(node.settings().echo_server, None);
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn listen_port_is_actual() {
    let (rig, node, _w) = start_node("echo-port");
    assert_eq!(node.listen_port(), Some(rig.port));
    node.shutdown(Duration::from_secs(5));
}

// ------------------------------------------------------------------------------ проба

#[test]
fn echo_not_configured_sends_nothing() {
    let server = Server::start(true);
    let (_rig, node, _w) = start_node("echo-none");
    // сервер существует, но в настройках не указан: ни одного пакета
    assert_eq!(
        node.echo_probe().err(),
        Some(NodeError::Echo(EchoFailure::NotConfigured))
    );
    assert_eq!(node.reach_check(), Ok(ReachResult::NoServer));
    assert_eq!(server.requests(), 0);
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn node_echo_probe_loopback() {
    let server = Server::start(true);
    let (rig, node, _w) = start_node("echo-probe");
    node.set_echo_server(Some(&server.text())).unwrap();
    let r = node.echo_probe().unwrap();
    assert_eq!(r.local_port, rig.port);
    assert_eq!(r.paths[0].via, EchoVia::DefaultRoute);
    // сервер видит петлю и порт узла
    let seen = first_observed(&r);
    assert_eq!(*seen.ip(), std::net::Ipv4Addr::LOCALHOST);
    assert_eq!(seen.port(), rig.port);
    // петля не глобальный адрес: настоящий вердикт «сервер рядом»
    assert_eq!(r.verdict, EchoVerdict::ServerSeesPrivate);
    assert!(
        r.reach_port != 0,
        "сервер с проверкой доступа не назвал порт"
    );
    assert_eq!(
        plan_invite_external(&r, node.nat_view(), None),
        ExternalPlan::Skip(SkipReason::ServerLocal)
    );
    // Debug отчёта без адресов
    assert_eq!(format!("{r:?}"), "EchoReport(..)");
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn echo_cooldown_returns_cached() {
    let server = Server::start(false);
    let (_rig, node, _w) = start_node("echo-cooldown");
    node.set_echo_server(Some(&server.text())).unwrap();
    let first = node.echo_probe().unwrap();
    let sent = server.requests();
    assert!(sent >= 1);
    // меньше 10 с: тот же отчёт, сеть не тронута
    let second = node.echo_probe().unwrap();
    assert_eq!(first, second);
    assert_eq!(server.requests(), sent, "повторная проба ушла в сеть");
    // смена сервера в настройках сбрасывает сохранённый отчёт
    node.set_echo_server(Some(&server.text())).unwrap();
    let third = node.echo_probe().unwrap();
    assert_eq!(first.paths[0].result, third.paths[0].result);
    assert!(
        server.requests() > sent,
        "после смены настройки проба не ушла"
    );
    node.shutdown(Duration::from_secs(5));
}

// ------------------------------------------------------------------------------ приглашение

fn token_addrs(text: &str) -> Vec<SocketAddr> {
    match decode(text).unwrap() {
        Token::Invite(t) => t.addrs().to_vec(),
        _ => panic!("не приглашение"),
    }
}

#[test]
fn node_invite_with_external_loopback() {
    let server = Server::start(false);
    let (rig, node, _w) = start_node("echo-invite");
    node.set_echo_server(Some(&server.text())).unwrap();
    let report = as_global(&node.echo_probe().unwrap());
    let ExternalPlan::Add { addrs, vpn_on } = plan_invite_external(&report, node.nat_view(), None)
    else {
        panic!("ожидалось вписать адрес");
    };
    assert!(!vpn_on);
    // собственных адресов у узла на петле нет: приглашение без `extra` не создалось бы
    assert_eq!(
        node.create_invite_ext(false, &[]).err(),
        Some(NodeError::Connect(
            chervo_core::chervo_connect::ConnectError::NoAddresses
        ))
    );
    let (_inv, token) = node.create_invite_ext(false, &addrs).unwrap();
    let got = token_addrs(token.as_str());
    assert_eq!(got[0], addrs[0], "адрес от эхо должен идти первым");
    assert_eq!(got[0].port(), rig.port);
    assert!(token.reveals_ip());
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn create_invite_ext_puts_extra_first() {
    let (_rig, node, _w) = start_node("echo-extra");
    let a: SocketAddr = "203.0.113.9:45817".parse().unwrap();
    let b: SocketAddr = "198.51.100.4:41000".parse().unwrap();
    let (_inv, token) = node.create_invite_ext(false, &[a, b, a]).unwrap();
    assert_eq!(token_addrs(token.as_str()), [a, b]);
    node.shutdown(Duration::from_secs(5));
}

/// Ждущее приглашение с адресом от эхо поддерживается и снимается при отмене и при SAS.
#[test]
fn keepalive_stops_on_sas_cancel_expiry() {
    let server = Server::start(false);
    let (rig_a, node_a, mut wa) = start_node("echo-ka-a");
    node_a.set_echo_server(Some(&server.text())).unwrap();
    node_a.set_keepalive_every_for_tests(Duration::from_millis(300));
    let report = as_global(&node_a.echo_probe().unwrap());
    let ExternalPlan::Add { addrs, .. } = plan_invite_external(&report, node_a.nat_view(), None)
    else {
        panic!("ожидалось вписать адрес");
    };

    // отмена
    let (inv, _t) = node_a.create_invite_ext(false, &addrs).unwrap();
    assert_eq!(node_a.keepalive_count_for_tests(), 1);
    node_a.cancel_invite(inv).unwrap();
    assert_eq!(node_a.keepalive_count_for_tests(), 0);

    // приглашение без адреса от эхо поддержания не заводит
    let other: SocketAddr = "203.0.113.9:45817".parse().unwrap();
    let (_inv2, _t2) = node_a.create_invite_ext(false, &[other]).unwrap();
    assert_eq!(node_a.keepalive_count_for_tests(), 0);

    // SAS: второй узел принимает приглашение по адресу от эхо (петля)
    let (inv3, token) = node_a.create_invite_ext(false, &addrs).unwrap();
    assert_eq!(node_a.keepalive_count_for_tests(), 1);
    wa.clear();
    let (_rig_b, node_b, _wb) = start_node("echo-ka-b");
    node_b.accept_invite(token.as_str()).unwrap();
    wa.wait(LONG, |e| match e {
        NodeEvent::InviteSas { invite, .. } if *invite == inv3 => Some(()),
        _ => None,
    })
    .expect("SAS у приглашающего");
    let end = Instant::now() + Duration::from_secs(5);
    while node_a.keepalive_count_for_tests() != 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        node_a.keepalive_count_for_tests(),
        0,
        "после SAS поддержание идёт"
    );
    node_b.shutdown(Duration::from_secs(5));
    node_a.shutdown(Duration::from_secs(5));
    drop(rig_a);
}

// ------------------------------------------------------------------------------ доступ

#[test]
fn node_reach_check_loopback() {
    let server = Server::start(true);
    let (rig, node, _w) = start_node("echo-reach");
    node.set_echo_server(Some(&server.text())).unwrap();
    // проверочный ответ приходит со второго порта сервера на порт программы
    assert_eq!(
        node.reach_check(),
        Ok(ReachResult::Reachable { port: rig.port })
    );
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn reach_check_sets_manual_forward_on_success() {
    let server = Server::start(true);
    let (rig, node, _w) = start_node("echo-reach-set");
    node.set_echo_server(Some(&server.text())).unwrap();
    assert_eq!(node.settings().manual_forward, None);
    assert_eq!(
        node.reach_check(),
        Ok(ReachResult::Reachable { port: rig.port })
    );
    assert_eq!(node.settings().manual_forward, Some(rig.port));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn reach_check_not_reachable_keeps_settings() {
    let server = Server::start(true);
    let (_rig, node, _w) = start_node("echo-reach-fail");
    node.set_echo_server(Some(&server.text())).unwrap();
    // правило в роутере с другим внешним номером, до программы он не доходит
    let closed = free_udp();
    node.set_manual_forward(Some(closed)).unwrap();
    assert_eq!(
        node.reach_check(),
        Ok(ReachResult::NotReachable { port: closed })
    );
    assert_eq!(node.settings().manual_forward, Some(closed));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn reach_check_no_server() {
    let (_rig, node, _w) = start_node("echo-reach-none");
    assert_eq!(node.reach_check(), Ok(ReachResult::NoServer));
    // сервер без проверки доступа
    let server = Server::start(false);
    node.set_echo_server(Some(&server.text())).unwrap();
    assert_eq!(node.reach_check(), Ok(ReachResult::ServerNoReach));
    // сервер, который не отвечает
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    node.set_echo_server(Some(&silent.local_addr().unwrap().to_string()))
        .unwrap();
    assert_eq!(node.reach_check(), Ok(ReachResult::NoServer));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn confirm_manual_forward_sets_listen_port() {
    let (rig, node, _w) = start_node("echo-confirm");
    assert_eq!(node.settings().manual_forward, None);
    node.confirm_manual_forward().unwrap();
    assert_eq!(node.settings().manual_forward, Some(rig.port));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn forward_help_uses_node_state() {
    let (rig, node, _w) = start_node("echo-help");
    let h = node.forward_help();
    assert_eq!(h.port, rig.port);
    assert!(!h.gw_exact, "роутер не искали");
    assert_eq!(format!("{h:?}"), "ForwardHelp(..)");
    node.shutdown(Duration::from_secs(5));
}
