//! Абстракция транспорта: трейты и заглушки без реализации (реализация в этапе 9).
//! Заглушки закрыты по умолчанию: любая операция возвращает `NotImplemented`.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

use chervo_identity::PairId;

/// Без Debug: адреса не печатаются через derive.
#[derive(Clone)]
pub struct PeerAddr {
    pub pair: PairId,
    pub addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    NotImplemented,
    PeerNotAllowed,
    Closed,
    AuthFailed,
    TimedOut,
    UnknownPair,
    Io,
    Duplicate,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotImplemented => "not implemented",
            Self::PeerNotAllowed => "peer not allowed",
            Self::Closed => "connection closed",
            Self::AuthFailed => "authentication failed",
            Self::TimedOut => "timed out",
            Self::UnknownPair => "unknown pair",
            Self::Io => "i/o error",
            Self::Duplicate => "duplicate connection",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TransportError {}

/// Вызывается до чтения любых прикладных данных; соединение с запрещённым ключом не возвращается из accept/connect.
pub trait PeerFilter: Send + Sync {
    fn is_allowed(&self, pair: &PairId) -> bool;
}

/// Запрещает всех.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl PeerFilter for DenyAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        false
    }
}

pub trait SendStream: Send {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;
    fn finish(&mut self) -> Result<(), TransportError>;
}

pub trait RecvStream: Send {
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, TransportError>> + Send;
}

pub trait Connection: Send + Sync {
    type Tx: SendStream;
    type Rx: RecvStream;
    /// Пара, подтверждённая Noise KK внутри канала; никогда не со слов собеседника.
    fn remote_pair(&self) -> PairId;
    fn remote_addr(&self) -> SocketAddr;
    fn open_bi(&self) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send;
    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send;
    fn close(&self);
}

pub trait Transport: Send + Sync {
    type Conn: Connection;
    fn local_addrs(&self) -> Vec<SocketAddr>;
    fn connect(
        &self,
        peer: &PeerAddr,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}

/// Необитаемый: поток из заглушки создать нельзя.
pub enum NullStream {}

impl SendStream for NullStream {
    fn write_all(
        &mut self,
        _buf: &[u8],
    ) -> impl Future<Output = Result<(), TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        match *self {}
    }
}

impl RecvStream for NullStream {
    fn read(
        &mut self,
        _buf: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }
}

/// Необитаемый: соединение из заглушки создать нельзя.
pub enum NullConnection {}

impl Connection for NullConnection {
    type Tx = NullStream;
    type Rx = NullStream;

    fn remote_pair(&self) -> PairId {
        match *self {}
    }

    fn remote_addr(&self) -> SocketAddr {
        match *self {}
    }

    fn open_bi(&self) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::Tx, Self::Rx), TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }

    fn close(&self) {
        match *self {}
    }
}

/// Заглушка транспорта: ничего не открывает.
pub struct NullTransport;

impl Transport for NullTransport {
    type Conn = NullConnection;

    fn local_addrs(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    fn connect(
        &self,
        _peer: &PeerAddr,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }

    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send {
        std::future::ready(Err(TransportError::NotImplemented))
    }
}
