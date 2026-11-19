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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// Сколько раз сервер сообщил счётчики (после записи в `counters`).
    reports: Arc<AtomicU64>,
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
        let reports = Arc::new(AtomicU64::new(0));
        let (s2, c2, r2) = (stop.clone(), counters.clone(), reports.clone());
        let join = std::thread::spawn(move || {
            serve(
                cfg,
                s2,
                move |a| tx.send(a).unwrap(),
                move |c| {
                    *c2.lock().unwrap() = *c;
                    r2.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();
        });
        let SocketAddr::V4(addr) = rx.recv_timeout(Duration::from_secs(5)).unwrap()[0] else {
            panic!("IPv4");
        };
        Self {
            addr,
            counters,
            reports,
            stop,
            join: Some(join),
        }
    }

    fn text(&self) -> String {
        self.addr.to_string()
    }

    /// Принятых сервером датаграмм. Сервер сообщает счётчики раз в 20 мс, но проверяет срок с
    /// шагом 50 мс, и на нагруженной машине (CI macOS) отчёт запаздывает дольше фиксированной
    /// паузы. Ждём два новых отчёта: второй целиком снят после вызова, значит, всё, что сервер
    /// принял до вызова, в нём есть (сервер считает запрос раньше, чем отвечает).
    fn requests(&self) -> u64 {
        let first = self.reports.load(Ordering::SeqCst);
        let end = Instant::now() + Duration::from_secs(10);
        while self.reports.load(Ordering::SeqCst) < first + 2 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.reports.load(Ordering::SeqCst) >= first + 2,
            "сервер не сообщил счётчики за 10 с"
        );
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

/// Ждущее приглашение с адресом от эхо, интервал поддержания 150 мс; сервер уже получает
/// запросы поддержания.
fn waiting_invite(node: &Node, server: &Server) {
    node.set_echo_server(Some(&server.text())).unwrap();
    node.set_keepalive_every_for_tests(Duration::from_millis(150));
    let report = as_global(&node.echo_probe().unwrap());
    let ExternalPlan::Add { addrs, .. } = plan_invite_external(&report, node.nat_view(), None)
    else {
        panic!("ожидалось вписать адрес");
    };
    node.create_invite_ext(false, &addrs).unwrap();
    assert_eq!(node.keepalive_count_for_tests(), 1);
    let before = server.requests();
    std::thread::sleep(Duration::from_millis(700));
    assert!(server.requests() > before, "поддержание не идёт");
}

/// Р9: убрали сервер из настроек: к нему не уходит ни одного пакета, поддержание снято.
#[test]
fn removing_server_stops_keepalive_packets() {
    let server = Server::start(false);
    let (_rig, node, _w) = start_node("echo-ka-revoke");
    waiting_invite(&node, &server);
    node.set_echo_server(None).unwrap();
    assert_eq!(node.keepalive_count_for_tests(), 0);
    std::thread::sleep(Duration::from_millis(150)); // запрос, уже ушедший в сеть
    let after = server.requests();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(server.requests(), after, "после отзыва пакеты идут");
    node.shutdown(Duration::from_secs(5));
}

/// Смена сервера: старый больше не получает запросов поддержания; тот же текст ничего не снимает.
#[test]
fn changing_server_stops_keepalive_to_old_one() {
    let old = Server::start(false);
    let new = Server::start(false);
    let (_rig, node, _w) = start_node("echo-ka-change");
    waiting_invite(&node, &old);
    // повторная запись того же сервера поддержание не трогает
    node.set_echo_server(Some(&old.text())).unwrap();
    assert_eq!(node.keepalive_count_for_tests(), 1);
    node.set_echo_server(Some(&new.text())).unwrap();
    assert_eq!(node.keepalive_count_for_tests(), 0);
    std::thread::sleep(Duration::from_millis(150));
    let after = old.requests();
    let new_before = new.requests();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(old.requests(), after, "старый сервер получает запросы");
    assert_eq!(new.requests(), new_before, "новый сервер получает запросы");
    node.shutdown(Duration::from_secs(5));
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

/// Адрес роутера в помощнике только от «Разрешить», и только пока сеть та же.
#[test]
fn router_address_exact_only_for_allowed_in_same_network() {
    let (_rig, node, _w) = start_node("echo-help-allowed");
    let ip = std::net::Ipv4Addr::new(10, 20, 30, 254);
    let mine = std::net::Ipv4Addr::new(10, 20, 30, 7);
    // роутер найден, но не разрешён: узел ничего не запомнил
    assert_eq!(node.allowed_router_for_tests(Some(mine)), (None, None));
    assert!(!node.forward_help().gw_exact);
    // найден заново, но в списке разрешённых его нет: адрес не запоминается
    assert!(!node.note_identified_for_tests("uuid:stranger-1", ip, false));
    assert_eq!(node.allowed_router_for_tests(Some(mine)), (None, None));
    assert!(!node.forward_help().gw_exact);
    // разрешён: адрес точный, пока источник маршрута к нему тот же
    node.set_allowed_router_for_tests(ip, Some(mine));
    assert_eq!(
        node.allowed_router_for_tests(Some(mine)),
        (Some(ip), Some(mine))
    );
    // сеть сменилась: адрес сброшен и обратно сам не возвращается
    assert_eq!(
        node.allowed_router_for_tests(Some(std::net::Ipv4Addr::new(192, 168, 5, 9))),
        (None, None)
    );
    assert_eq!(node.allowed_router_for_tests(Some(mine)), (None, None));
    // через настоящий `forward_help`: источник маршрута к чужому адресу не совпадёт с записью
    node.set_allowed_router_for_tests(std::net::Ipv4Addr::LOCALHOST, Some(mine));
    assert!(!node.forward_help().gw_exact, "запись другой сети");
    assert_eq!(node.allowed_router_for_tests(Some(mine)), (None, None));
    node.shutdown(Duration::from_secs(5));
}

/// Роутер, уже разрешённый раньше и найденный заново, запоминается (список разрешённых).
#[test]
fn router_found_again_is_remembered_only_if_in_list() {
    let (_rig, node, _w) = start_node("echo-help-again");
    let ip = std::net::Ipv4Addr::new(10, 20, 30, 254);
    assert!(node.note_identified_for_tests("uuid:known-1", ip, true));
    node.shutdown(Duration::from_secs(5));
}
