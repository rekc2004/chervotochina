//! Настоящий rustls на loopback: клиент `net::Net` против сервера TLS 1.3 на 127.0.0.1 с тестовым
//! корнем. Имя хоста в запросе `github.com`, адрес подменён на loopback через `Resolver`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

use chervo_update::Target;

use super::helpers::*;
use crate::http::{Response, request_bytes};
use crate::net::{Net, Resolver, client_config, production_roots};
use crate::{
    CheckError, Fetch, MANIFEST_FILE, Redirecting, SIGNATURE_FILE, Transport, UpdateStatus,
    check_latest_with, run_with_deadline,
};

fn loopback(addr: SocketAddr) -> Resolver {
    Box::new(move |_host| Ok(vec![addr]))
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn test_net(addr: SocketAddr) -> Net {
    Net::new(
        client_config(test_roots()).expect("config"),
        loopback(addr),
        far(),
    )
}

#[test]
fn tls_loopback_ok() {
    let srv = tls_server(SERVER_GITHUB_DER, |_| ok_response(b"hello"));
    let net = test_net(srv.addr);
    let got = net.request("github.com", "/p/q?x=1", 100).expect("request");
    assert_eq!(got, Response::Body(b"hello".to_vec()));
    let seen = srv.seen.lock().expect("seen");
    assert_eq!(seen.requests.len(), 1);
    // сервер увидел ровно заранее известные байты запроса
    assert_eq!(seen.requests[0], request_bytes("github.com", "/p/q?x=1"));
    assert!(seen.tls13, "не TLS 1.3");
    assert!(seen.alpn_http11, "ALPN http/1.1 не согласован");
}

#[test]
fn tls_redirect_through_real_connection() {
    let srv = tls_server(SERVER_GITHUB_DER, |req| {
        if req.starts_with(b"GET /rekc2004/") {
            b"HTTP/1.1 302 Found\r\nLocation: https://github.com/next/file\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        } else {
            ok_response(b"final")
        }
    });
    let net = test_net(srv.addr);
    let got = Redirecting(&net).get(MANIFEST_FILE, 100).expect("get");
    assert_eq!(got, b"final");
    assert_eq!(srv.seen.lock().expect("seen").requests.len(), 2);
}

#[test]
fn tls_full_check_through_loopback() {
    let sk = test_key(7);
    let manifest = manifest_bytes(v(3, 0, 0), &[Target::LinuxX86_64]);
    let sig = sign(&sk, &manifest);
    let (m2, s2) = (manifest.clone(), sig.clone());
    let srv = tls_server(SERVER_GITHUB_DER, move |req| {
        let line = String::from_utf8_lossy(req);
        if line.contains(&format!("/{SIGNATURE_FILE} ")) {
            ok_response(&s2)
        } else {
            ok_response(&m2)
        }
    });
    let net = test_net(srv.addr);
    let status = check_latest_with(
        keyset(&sk),
        &Redirecting(&net),
        v(1, 0, 0),
        Some(Target::LinuxX86_64),
    );
    assert_eq!(status, Ok(UpdateStatus::Newer(v(3, 0, 0))));
    let seen = srv.seen.lock().expect("seen");
    // сначала подпись, потом манифест
    assert!(String::from_utf8_lossy(&seen.requests[0]).contains(SIGNATURE_FILE));
    assert!(!String::from_utf8_lossy(&seen.requests[1]).contains(".minisig"));
}

#[test]
fn tls_wrong_name_rejected() {
    // сертификат на evil.example, а запрос идёт к github.com
    let srv = tls_server(SERVER_WRONG_DER, |_| ok_response(b"secret"));
    let net = test_net(srv.addr);
    let got = net.request("github.com", "/x", 100);
    assert_eq!(got, Err(CheckError::BadResponse));
    assert!(srv.seen.lock().expect("seen").requests.is_empty());
}

#[test]
fn production_roots_reject_test_cert() {
    // тот же сервер и верное имя, но корни продукта (Mozilla) тестовый УЦ не знают
    let srv = tls_server(SERVER_GITHUB_DER, |_| ok_response(b"secret"));
    let net = Net::new(
        client_config(production_roots()).expect("config"),
        loopback(srv.addr),
        far(),
    );
    assert_eq!(
        net.request("github.com", "/x", 100),
        Err(CheckError::BadResponse)
    );
    assert!(srv.seen.lock().expect("seen").requests.is_empty());
    // и с тестовым корнем он принимается: проверка отказа не из-за другой причины
    let net = test_net(srv.addr);
    assert!(net.request("github.com", "/x", 100).is_ok());
}

#[test]
fn production_roots_are_not_empty() {
    assert!(production_roots().roots.len() > 50);
}

#[test]
fn no_listener_is_network_error() {
    // порт без слушателя: отказ в соединении, не паника
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    };
    let net = test_net(port);
    assert_eq!(
        net.request("github.com", "/x", 100),
        Err(CheckError::Network)
    );
}

#[test]
fn slow_server_hits_deadline() {
    // сервер принимает соединение и молчит
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _hold = std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().take(2).flatten() {
            held.push(s);
            std::thread::sleep(Duration::from_secs(8));
        }
    });
    let started = Instant::now();
    let r: Result<Response, CheckError> =
        run_with_deadline(Duration::from_millis(600), move |deadline| {
            let net = Net::new(
                client_config(test_roots()).expect("config"),
                loopback(addr),
                deadline,
            );
            net.request("github.com", "/x", 100)
        });
    let spent = started.elapsed();
    assert_eq!(r, Err(CheckError::Timeout));
    assert!(spent < Duration::from_secs(4), "ждали {spent:?}");
}

#[test]
fn slow_drip_server_hits_deadline() {
    // сервер отдаёт по байту: отдельный таймаут чтения не срабатывает, сроком управляет общий
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = srv_listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = srv_listener.accept() {
            for _ in 0..20 {
                if s.write_all(&[0x16]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            let mut sink = [0u8; 16];
            let _ = s.read(&mut sink);
        }
    });
    let started = Instant::now();
    let net = Net::new(
        client_config(test_roots()).expect("config"),
        loopback(addr),
        Instant::now() + Duration::from_millis(700),
    );
    let r = net.request("github.com", "/x", 100);
    assert!(r.is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
}
