//! Сетевой слой: TCP + TLS 1.3 (rustls, ring) + один обмен HTTP. Единственное место в крейте,
//! где открывается соединение. Прокси, переменные окружения и конфиг не читаются.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::http::{Response, map_io, read_response, request_bytes};
use crate::{CONNECT_TIMEOUT, CheckError, IO_TIMEOUT, Transport};

/// Разрешение имени в адреса. В продукте это `(host, 443)`; в тестах подменяется на loopback.
pub(crate) type Resolver = Box<dyn Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// Корни Mozilla из пакета `webpki-roots` (данные внутри бинаря).
pub(crate) fn production_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Только TLS 1.3, без клиентского сертификата, ALPN `http/1.1`, без сессионных билетов и
/// 0-RTT. Проверка имени и цепочки штатная, своих верификаторов нет.
pub(crate) fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, CheckError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cc = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| CheckError::Network)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"http/1.1".to_vec()];
    cc.resumption = rustls::client::Resumption::disabled();
    cc.enable_early_data = false;
    Ok(Arc::new(cc))
}

fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
}

/// Сокет, у которого перед каждой операцией таймаут равен меньшему из `IO_TIMEOUT` и остатка
/// общего срока: медленный сервер не удержит поток дольше срока.
struct DeadlineIo {
    sock: TcpStream,
    deadline: Instant,
}

impl DeadlineIo {
    fn left(&self) -> io::Result<Duration> {
        remaining(self.deadline)
            .map(|d| d.min(IO_TIMEOUT))
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl Read for DeadlineIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.set_read_timeout(Some(self.left()?))?;
        self.sock.read(buf)
    }
}

impl Write for DeadlineIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.set_write_timeout(Some(self.left()?))?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

pub(crate) struct Net {
    config: Arc<ClientConfig>,
    resolve: Resolver,
    deadline: Instant,
}

impl Net {
    pub(crate) fn new(config: Arc<ClientConfig>, resolve: Resolver, deadline: Instant) -> Net {
        Net {
            config,
            resolve,
            deadline,
        }
    }

    /// Продукт: корни Mozilla, адреса из системного DNS, порт только 443. Новый `ClientConfig`
    /// на каждую проверку.
    pub(crate) fn production(deadline: Instant) -> Result<Net, CheckError> {
        let resolve: Resolver = Box::new(|host| Ok((host, 443u16).to_socket_addrs()?.collect()));
        Ok(Net::new(
            client_config(production_roots())?,
            resolve,
            deadline,
        ))
    }

    /// Адреса пробуются по порядку, каждый с `CONNECT_TIMEOUT`, в пределах общего срока.
    fn connect(&self, addrs: &[SocketAddr]) -> Result<TcpStream, CheckError> {
        for addr in addrs {
            let left = remaining(self.deadline).ok_or(CheckError::Timeout)?;
            if let Ok(sock) = TcpStream::connect_timeout(addr, left.min(CONNECT_TIMEOUT)) {
                return Ok(sock);
            }
        }
        Err(CheckError::Network)
    }
}

impl Transport for Net {
    fn request(
        &self,
        host: &'static str,
        path: &str,
        max_body: usize,
    ) -> Result<Response, CheckError> {
        let addrs = (self.resolve)(host).map_err(|e| map_io(&e))?;
        let sock = self.connect(&addrs)?;
        let name = ServerName::try_from(host)
            .map_err(|_| CheckError::BadResponse)?
            .to_owned();
        let conn =
            ClientConnection::new(self.config.clone(), name).map_err(|_| CheckError::Network)?;
        let mut tls = StreamOwned::new(
            conn,
            DeadlineIo {
                sock,
                deadline: self.deadline,
            },
        );
        tls.write_all(&request_bytes(host, path))
            .and_then(|()| tls.flush())
            .map_err(|e| map_io(&e))?;
        read_response(&mut tls, max_body)
    }
}
