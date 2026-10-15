//! Проверки TLS: одноразовый ключ, закрытый базовый конфиг, только Ed25519, нет тикетов и 0-RTT.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue,
};
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, NamedGroup};

use super::kit::*;
use crate::tls::{RpkVerifier, provider};
use crate::{ALPN, QuinnConfig};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(3),
        ..test_cfg()
    }
}

fn spki_of(conn: &quinn::Connection) -> Vec<u8> {
    let id = conn
        .peer_identity()
        .expect("у клиента есть удостоверение сервера");
    let certs = id
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("тип удостоверения");
    certs.first().expect("один ключ").as_ref().to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_key_fresh_per_connection() {
    let k = Keys::new();
    let b = bind(cfg(), vec![k.peer_b()]);
    let ep = raw_endpoint();
    let mut seen = HashSet::new();
    for _ in 0..3 {
        let conn = raw_tls(&ep, addr_of(&b)).await.unwrap();
        assert!(seen.insert(spki_of(&conn)), "ключ сервера повторился");
        conn.close(0u32.into(), b"");
    }
    assert_eq!(seen.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_identity_none() {
    let c = cfg();
    let server = server_endpoint(&c);
    let addr = ep_addr(&server);
    let sc = c.clone();
    let srv = tokio::spawn(async move { serve_one(&server, &sc).await });
    let ep = raw_endpoint();
    let _client = raw_tls(&ep, addr).await.unwrap();
    let conn = srv.await.unwrap();
    assert!(
        conn.peer_identity().is_none(),
        "сервер получил клиентский сертификат"
    );
}

#[test]
fn verifier_ed25519_only() {
    let v = RpkVerifier::new();
    assert_eq!(
        v.supported_verify_schemes(),
        vec![rustls::SignatureScheme::ED25519]
    );
    assert!(v.requires_raw_public_keys());
    let cert = CertificateDer::from(vec![0u8; 44]);
    // TLS 1.2 запрещён
    let dss12 = DigitallySignedStruct::read(&mut Reader::init(&[0x08, 0x07, 0, 2, 1, 2])).unwrap();
    assert!(v.verify_tls12_signature(b"m", &cert, &dss12).is_err());
    // схема ECDSA_NISTP256_SHA256 (0x0403) отвергнута нашей проверкой схемы
    let ecdsa =
        DigitallySignedStruct::read(&mut Reader::init(&[0x04, 0x03, 0, 4, 1, 2, 3, 4])).unwrap();
    let e = v.verify_tls13_signature(b"m", &cert, &ecdsa).unwrap_err();
    assert!(
        matches!(
            e,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoSignatureSchemesInCommon)
        ),
        "отказ не по схеме"
    );
    // контроль: схема Ed25519 с мусором отвергается уже по другой причине (проверка схемы пройдена)
    let ed =
        DigitallySignedStruct::read(&mut Reader::init(&[0x08, 0x07, 0, 4, 1, 2, 3, 4])).unwrap();
    let e = v.verify_tls13_signature(b"m", &cert, &ed).unwrap_err();
    assert!(!matches!(
        e,
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoSignatureSchemesInCommon)
    ));
    // непустая цепочка отвергается
    let name = ServerName::try_from(crate::SERVER_NAME).unwrap();
    let r = v.verify_server_cert(
        &cert,
        std::slice::from_ref(&cert),
        &name,
        &[],
        UnixTime::now(),
    );
    assert!(r.is_err());
    let r = v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now());
    assert!(r.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn base_config_refuses_handshake() {
    let c = cfg();
    let ep_srv = server_endpoint(&c);
    let addr = ep_addr(&ep_srv);
    let sc = c.clone();
    let srv = tokio::spawn(async move {
        // первое входящее: случайный вызов accept() берёт базовый конфиг
        let incoming = loop {
            let i = ep_srv.accept().await.unwrap();
            if i.remote_address_validated() {
                break i;
            }
            i.retry().unwrap();
        };
        let _ = incoming.accept().map(|c| tokio::spawn(c));
        // положительный контроль: с одноразовым конфигом на том же гнезде рукопожатие проходит
        serve_one(&ep_srv, &sc).await
    });
    let ep = raw_endpoint();
    let first = tokio::time::timeout(Duration::from_secs(3), raw_tls(&ep, addr)).await;
    assert!(
        matches!(first, Ok(Err(_))),
        "рукопожатие с базовым конфигом не должно проходить"
    );
    let second = raw_tls(&ep, addr).await;
    assert!(second.is_ok(), "контроль: одноразовый конфиг работает");
    drop(srv.await.unwrap());
}

// ---------------------------------------------------------------------------------------------
// Тикеты, 0-RTT, NEW_TOKEN
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
struct CountingStore {
    inner: ClientSessionMemoryCache,
    inserted: AtomicUsize,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(8),
            inserted: AtomicUsize::new(0),
        }
    }
}

impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group)
    }
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }
    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value)
    }
    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }
    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name)
    }
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.inserted.fetch_add(1, Ordering::SeqCst);
        self.inner.insert_tls13_ticket(server_name, value)
    }
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

/// Клиент с возобновлением и 0-RTT, но тем же верификатором.
fn resuming_client(store: Arc<CountingStore>) -> quinn::ClientConfig {
    let mut cc = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RpkVerifier::new()))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];
    cc.enable_sni = false;
    cc.enable_early_data = true;
    cc.resumption = Resumption::store(store);
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(cc)).unwrap();
    let mut qc = quinn::ClientConfig::new(Arc::new(quic));
    qc.token_store(Arc::new(quinn::NoneTokenStore));
    qc
}

/// Два соединения подряд тем же клиентом; сервер строится `make_server`.
/// Возвращает (вставлено тикетов, принято кадров NEW_TOKEN, `into_0rtt` второго соединения успешно).
async fn resume_experiment(
    make_server: impl Fn(&QuinnConfig) -> quinn::ServerConfig + Send + Sync + 'static,
) -> (usize, usize, bool) {
    let c = cfg();
    let sock = std::net::UdpSocket::bind(lo()).unwrap();
    sock.set_nonblocking(true).unwrap();
    let base = crate::tls::base_server_config(&c).unwrap();
    let ep_srv = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(base),
        sock,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let addr = ep_addr(&ep_srv);
    let sc = c.clone();
    let _srv = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Some(incoming) = ep_srv.accept().await else {
                return;
            };
            if !incoming.remote_address_validated() {
                incoming.retry().unwrap();
                continue;
            }
            let conn = incoming
                .accept_with(Arc::new(make_server(&sc)))
                .unwrap()
                .await;
            held.push(conn);
        }
    });
    let ep = raw_endpoint();
    let store = Arc::new(CountingStore::new());
    let mut new_tokens = 0u64;
    let mut zero_rtt_ok = false;
    for round in 0..2 {
        let cc = resuming_client(store.clone());
        let connecting = ep.connect_with(cc, addr, crate::SERVER_NAME).unwrap();
        if round == 1 {
            match connecting.into_0rtt() {
                Ok((conn, _accepted)) => {
                    zero_rtt_ok = true;
                    conn.close(0u32.into(), b"");
                }
                Err(connecting) => {
                    let conn = connecting.await.unwrap();
                    conn.close(0u32.into(), b"");
                }
            }
        } else {
            let conn = connecting.await.unwrap();
            sleep_ms(400).await; // тикеты и NEW_TOKEN приходят после рукопожатия
            new_tokens += conn.stats().frame_rx.new_token;
            conn.close(0u32.into(), b"");
        }
        sleep_ms(200).await;
    }
    (
        store.inserted.load(Ordering::SeqCst),
        new_tokens as usize,
        zero_rtt_ok,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_tickets_no_0rtt() {
    // Наш сервер: тикетов 0 и 0-RTT нет.
    let (tickets, _tokens, zero_rtt) = resume_experiment(|c| {
        let mut sc = crate::tls::ephemeral_rustls().unwrap();
        crate::tls::harden(&mut sc);
        crate::tls::quic_server(sc, c, 0).unwrap()
    })
    .await;
    assert_eq!(tickets, 0, "сервер выдал тикеты");
    assert!(!zero_rtt, "into_0rtt успешен");

    // Положительный контроль инструмента: без защитных настроек тикеты приходят.
    let (tickets, _tokens, zero_rtt) = resume_experiment(|c| {
        let mut sc = crate::tls::ephemeral_rustls().unwrap();
        sc.alpn_protocols = vec![ALPN.to_vec()];
        sc.max_early_data_size = u32::MAX;
        sc.send_tls13_tickets = 2;
        sc.session_storage = rustls::server::ServerSessionMemoryCache::new(16);
        crate::tls::quic_server(sc, c, 0).unwrap()
    })
    .await;
    assert!(tickets > 0, "контроль: тикеты должны были прийти");
    // 0-RTT на мягком сервере с RPK не воспроизведён (контроль `into_0rtt` недоступен): честно не проверяем.
    let _ = zero_rtt;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_new_token() {
    let (_t, tokens, _z) = resume_experiment(|c| {
        let mut sc = crate::tls::ephemeral_rustls().unwrap();
        crate::tls::harden(&mut sc);
        crate::tls::quic_server(sc, c, 0).unwrap()
    })
    .await;
    assert_eq!(tokens, 0, "сервер прислал NEW_TOKEN");

    // Положительный контроль: при sent > 0 токены приходят в хранилище клиента.
    let (_t, tokens, _z) = resume_experiment(|c| {
        let mut sc = crate::tls::ephemeral_rustls().unwrap();
        crate::tls::harden(&mut sc);
        crate::tls::quic_server(sc, c, 2).unwrap()
    })
    .await;
    assert!(tokens > 0, "контроль: NEW_TOKEN должны были прийти");
}
