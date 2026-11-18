//! Ответы сервера по настоящим сокетам на петле.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chervo_rendezvous_wire::{
    Nonce, RESPONSE_LEN, encode_echo_request, encode_reach_request, parse_response,
};

use crate::{Counters, ServerConfig, serve};

struct Running {
    addr: SocketAddr,
    reach: Option<u16>,
    counters: Arc<Mutex<Counters>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(allow_private: bool, with_reach: bool) -> Running {
    let reach = with_reach.then(free_port);
    let cfg = ServerConfig {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        reach_port: reach,
        allow_private,
        report_every: Duration::from_millis(20),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Mutex::new(Counters::default()));
    let (tx, rx) = mpsc::channel();
    let (stop2, counters2) = (stop.clone(), counters.clone());
    let join = thread::spawn(move || {
        serve(
            cfg,
            stop2,
            move |a| tx.send(a).unwrap(),
            move |c| *counters2.lock().unwrap() = *c,
        )
    });
    let addr = rx.recv_timeout(Duration::from_secs(5)).unwrap()[0];
    Running {
        addr,
        reach,
        counters,
        stop,
        join: Some(join),
    }
}

impl Running {
    /// Ждать, пока отчёт покажет нужные счётчики (отчёт каждые 20 мс).
    fn wait(&self, f: impl Fn(&Counters) -> bool) -> Counters {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let c = *self.counters.lock().unwrap();
            if f(&c) || Instant::now() > end {
                return c;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn client() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    s
}

fn recv(s: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 2048];
    s.recv_from(&mut buf)
        .ok()
        .map(|(n, from)| (buf[..n].to_vec(), from))
}

fn nonce(i: u8) -> Nonce {
    Nonce([i; 16])
}

#[test]
fn answers_valid_request() {
    let srv = start(true, false);
    let c = client();
    c.send_to(&encode_echo_request(&nonce(7)), srv.addr)
        .unwrap();
    let (data, from) = recv(&c).expect("ответ эха");
    assert_eq!(from, srv.addr, "ответ с того же адреса, куда писали");
    assert_eq!(data.len(), RESPONSE_LEN);
    let r = parse_response(&data, &nonce(7)).unwrap();
    assert_eq!(r.observed, c.local_addr().unwrap());
    assert!(!r.reach);
    assert_eq!(r.reach_port, 0, "без --reach-port проверки нет");
    let counters = srv.wait(|c| c.replies == 1);
    assert_eq!((counters.requests, counters.replies), (1, 1));
}

#[test]
fn allow_private_answers_loopback() {
    // тот же сценарий с точки зрения запрета: с флагом петля отвечена, без флага нет
    let srv = start(true, false);
    let c = client();
    c.send_to(&encode_echo_request(&nonce(1)), srv.addr)
        .unwrap();
    assert!(recv(&c).is_some());
    let srv = start(false, false);
    c.send_to(&encode_echo_request(&nonce(1)), srv.addr)
        .unwrap();
    assert!(recv(&c).is_none());
}

#[test]
fn refuses_private_source_by_default() {
    let srv = start(false, true);
    let c = client();
    c.send_to(&encode_echo_request(&nonce(1)), srv.addr)
        .unwrap();
    c.send_to(
        &encode_reach_request(&nonce(2), c.local_addr().unwrap().port()),
        srv.addr,
    )
    .unwrap();
    assert!(recv(&c).is_none(), "частному адресу не отвечаем");
    let counters = srv.wait(|c| c.refused_source == 2);
    assert_eq!(counters.refused_source, 2);
    assert_eq!(counters.replies + counters.reach_replies, 0);
}

#[test]
fn echo_response_announces_reach_port() {
    let srv = start(true, true);
    let c = client();
    c.send_to(&encode_echo_request(&nonce(3)), srv.addr)
        .unwrap();
    let (data, _) = recv(&c).unwrap();
    let r = parse_response(&data, &nonce(3)).unwrap();
    assert_eq!(Some(r.reach_port), srv.reach);
    assert_ne!(r.reach_port, srv.addr.port());
}

#[test]
fn reach_reply_from_second_port_to_target_port() {
    let srv = start(true, true);
    let asker = client();
    let target = client();
    let tport = target.local_addr().unwrap().port();
    asker
        .send_to(&encode_reach_request(&nonce(9), tport), srv.addr)
        .unwrap();
    let (data, from) = recv(&target).expect("ответ проверки на проверяемый порт");
    assert_eq!(from.ip(), srv.addr.ip());
    assert_eq!(Some(from.port()), srv.reach, "со второго порта сервера");
    let r = parse_response(&data, &nonce(9)).unwrap();
    assert!(r.reach);
    assert_eq!(r.observed, asker.local_addr().unwrap());
    assert!(
        recv(&asker).is_none(),
        "на сам запрашивающий сокет ничего не приходит"
    );
    let counters = srv.wait(|c| c.reach_replies == 1);
    assert_eq!((counters.replies, counters.reach_replies), (0, 1));
}

#[test]
fn reach_without_flag_dropped() {
    let srv = start(true, false);
    let asker = client();
    let target = client();
    let tport = target.local_addr().unwrap().port();
    asker
        .send_to(&encode_reach_request(&nonce(9), tport), srv.addr)
        .unwrap();
    assert!(recv(&target).is_none());
    assert!(recv(&asker).is_none());
    let counters = srv.wait(|c| c.malformed == 1);
    assert_eq!((counters.malformed, counters.reach_replies), (1, 0));
}

#[test]
fn reach_target_port_zero_dropped() {
    let srv = start(true, true);
    let asker = client();
    asker
        .send_to(&encode_reach_request(&nonce(9), 0), srv.addr)
        .unwrap();
    assert!(recv(&asker).is_none());
    let counters = srv.wait(|c| c.malformed == 1);
    assert_eq!((counters.malformed, counters.reach_replies), (1, 0));
}

#[test]
fn drops_malformed() {
    let srv = start(true, true);
    let c = client();
    let good = encode_echo_request(&nonce(5));
    let mut bad_magic = good;
    bad_magic[0] = b'X';
    let mut bad_pad = good;
    bad_pad[63] = 1;
    for pkt in [
        &good[..63],
        &bad_magic[..],
        &bad_pad[..],
        &[0u8; 0][..],
        &[0xFFu8; 2048][..],
        &[0u8; 65][..],
    ] {
        c.send_to(pkt, srv.addr).unwrap();
    }
    assert!(recv(&c).is_none());
    let counters = srv.wait(|c| c.requests == 6 && c.malformed == 6);
    assert_eq!(counters.malformed, 6);
    assert_eq!(counters.replies, 0);
    // сервер жив
    c.send_to(&good, srv.addr).unwrap();
    assert!(recv(&c).is_some());
}
