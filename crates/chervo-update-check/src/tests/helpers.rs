//! Помощники тестов: тестовый ключ и подпись формата minisign, образцы манифеста, подставные
//! `Fetch` и `Transport`, сервер TLS на loopback.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blake2::{Blake2b512, Digest};
use chervo_update::{Artifact, KeyRole, KeySet, Manifest, Target, UpdateError, Version};
use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::http::Response;
use crate::{CheckError, Fetch, MANIFEST_FILE, SIGNATURE_FILE, Transport};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// ТЕСТОВЫЙ секретный ключ из зерна (не ключ релизов).
pub(crate) fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) const KEY_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

pub(crate) fn keyset(sk: &SigningKey) -> Result<KeySet, UpdateError> {
    let mut raw = b"Ed".to_vec();
    raw.extend_from_slice(&KEY_ID);
    raw.extend_from_slice(&sk.verifying_key().to_bytes());
    let file = format!("untrusted comment: test key\n{}\n", b64(&raw)).into_bytes();
    KeySet::from_pubkey_files(&[(KeyRole::Primary, file.as_slice())])
}

pub(crate) fn sign(sk: &SigningKey, manifest: &[u8]) -> Vec<u8> {
    let hash = Blake2b512::digest(manifest);
    let sig = sk.sign(hash.as_slice()).to_bytes();
    let mut raw = b"ED".to_vec();
    raw.extend_from_slice(&KEY_ID);
    raw.extend_from_slice(&sig);
    let trusted = "chervo-release test";
    let mut gm = sig.to_vec();
    gm.extend_from_slice(trusted.as_bytes());
    let global = sk.sign(&gm).to_bytes();
    format!(
        "untrusted comment: test\n{}\ntrusted comment: {trusted}\n{}\n",
        b64(&raw),
        b64(&global)
    )
    .into_bytes()
}

pub(crate) fn v(major: u32, minor: u32, patch: u32) -> Version {
    Version {
        major,
        minor,
        patch,
    }
}

/// Манифест версии `version` с артефактами для заданных целей.
pub(crate) fn manifest_bytes(version: Version, targets: &[Target]) -> Vec<u8> {
    let artifacts = targets
        .iter()
        .enumerate()
        .map(|(i, t)| Artifact {
            target: *t,
            sha256: [u8::try_from(i).unwrap_or(0) + 1; 32],
            size: 10,
            name: format!("file-{i}"),
        })
        .collect();
    Manifest {
        version,
        commit: [0xab; 20],
        artifacts,
    }
    .to_canonical_bytes()
}

/// Подставной `Fetch`: файлы из таблицы, счётчик вызовов.
pub(crate) struct MockFetch {
    pub(crate) files: HashMap<&'static str, Result<Vec<u8>, CheckError>>,
    pub(crate) calls: AtomicUsize,
}

impl MockFetch {
    pub(crate) fn new(manifest: Vec<u8>, sig: Vec<u8>) -> MockFetch {
        let mut files = HashMap::new();
        files.insert(MANIFEST_FILE, Ok(manifest));
        files.insert(SIGNATURE_FILE, Ok(sig));
        MockFetch {
            files,
            calls: AtomicUsize::new(0),
        }
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Fetch for MockFetch {
    fn get(&self, file: &str, max_body: usize) -> Result<Vec<u8>, CheckError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let r = self.files.get(file).cloned().ok_or(CheckError::Network)?;
        let body = r?;
        // как настоящая сеть: сверх предела тело не отдаётся
        if body.len() > max_body {
            return Err(CheckError::BadResponse);
        }
        Ok(body)
    }
}

/// Подставной `Transport`: очередь ответов и журнал запросов `(host, path)`.
pub(crate) struct MockTransport {
    pub(crate) replies: Mutex<Vec<Result<Response, CheckError>>>,
    pub(crate) log: Mutex<Vec<(String, String)>>,
}

impl MockTransport {
    pub(crate) fn new(replies: Vec<Result<Response, CheckError>>) -> MockTransport {
        MockTransport {
            replies: Mutex::new(replies),
            log: Mutex::new(Vec::new()),
        }
    }
}

impl Transport for MockTransport {
    fn request(
        &self,
        host: &'static str,
        path: &str,
        _max_body: usize,
    ) -> Result<Response, CheckError> {
        self.log
            .lock()
            .expect("log")
            .push((host.to_owned(), path.to_owned()));
        let mut q = self.replies.lock().expect("replies");
        if q.is_empty() {
            return Err(CheckError::Network);
        }
        q.remove(0)
    }
}

// ---------------------------------------------------------------------------------------------
// TLS-сервер на loopback
// ---------------------------------------------------------------------------------------------

pub(crate) const CA_DER: &[u8] = include_bytes!("../../tests/fixtures/ca.der");
pub(crate) const SERVER_GITHUB_DER: &[u8] =
    include_bytes!("../../tests/fixtures/server-github.der");
pub(crate) const SERVER_WRONG_DER: &[u8] = include_bytes!("../../tests/fixtures/server-wrong.der");
pub(crate) const SERVER_KEY_DER: &[u8] = include_bytes!("../../tests/fixtures/server-pkcs8.der");

pub(crate) fn test_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("test CA");
    roots
}

/// Что видел сервер: байты запроса и версия TLS.
#[derive(Default)]
pub(crate) struct Seen {
    pub(crate) requests: Vec<Vec<u8>>,
    pub(crate) tls13: bool,
    pub(crate) alpn_http11: bool,
}

pub(crate) struct TestServer {
    pub(crate) addr: SocketAddr,
    pub(crate) seen: Arc<Mutex<Seen>>,
}

fn server_config(cert: &[u8]) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(SERVER_KEY_DER.to_vec()));
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.to_vec())], key)
        .expect("cert");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Сервер TLS 1.3 на 127.0.0.1: на каждое соединение читает запрос до пустой строки и отвечает
/// `reply(запрос)`. Работает, пока жив процесс теста (поток-демон).
pub(crate) fn tls_server<F>(cert: &'static [u8], reply: F) -> TestServer
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    let cfg = server_config(cert);
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(sock) = sock else { continue };
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
            let Ok(conn) = ServerConnection::new(cfg.clone()) else {
                continue;
            };
            let mut tls = StreamOwned::new(conn, sock);
            let mut req = Vec::new();
            let mut byte = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") && req.len() < 8192 {
                match tls.read(&mut byte) {
                    Ok(1) => req.push(byte[0]),
                    _ => break,
                }
            }
            if !req.ends_with(b"\r\n\r\n") {
                continue;
            }
            {
                let mut s = seen2.lock().expect("seen");
                s.tls13 = tls.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
                s.alpn_http11 = tls.conn.alpn_protocol() == Some(b"http/1.1".as_slice());
                s.requests.push(req.clone());
            }
            let _ = tls.write_all(&reply(&req));
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    TestServer { addr, seen }
}

pub(crate) fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}
