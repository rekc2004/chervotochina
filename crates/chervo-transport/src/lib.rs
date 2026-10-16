//! Абстракция транспорта: трейты и заглушки без реализации (реализация в этапе 9).
//! Заглушки закрыты по умолчанию: любая операция возвращает `NotImplemented`.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

use chervo_identity::{KxPeer, PairId};

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
    /// Исходящий звонок к этой паре уже идёт: второй не начинается, пакеты не уходят.
    Busy,
    /// Ни один из опробованных адресов не прислал ни одного пакета.
    NoResponse,
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
            Self::Busy => "dial already in progress",
            Self::NoResponse => "no response",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TransportError {}

/// В наборе пар две записи с одним `PairId`: набор отвергнут целиком, прежний остаётся.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicatePairError;

impl fmt::Display for DuplicatePairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("duplicate pair id in peer set")
    }
}

impl std::error::Error for DuplicatePairError {}

/// События транспорта: только `PairId` и вид; ничего из сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportEvent {
    RemoteAddrChanged {
        pair: PairId,
    },
    ConnectionReplaced {
        pair: PairId,
    },
    /// Стук пары пришёл с верным тегом, но в окне вне допуска: у кого-то сбиты часы.
    ClockSkewSuspected {
        pair: PairId,
    },
    /// Живое соединение закрыто: тройки `(пара, наш X25519, X25519 собеседника)` нет в наборе
    /// после `set_peers` (удаление, блокировка, смена ключа).
    PeerRemoved {
        pair: PairId,
    },
    /// Часть событий потеряна (получатель отстал).
    Lagged,
}

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
    /// Уникален среди соединений одного экземпляра транспорта; равен у клонов одного соединения.
    fn conn_id(&self) -> u64;
    /// Эта сторона звонила (а не принимала).
    fn is_initiator(&self) -> bool;
    /// Завершается, когда соединение закрыто по любой причине.
    fn closed(&self) -> impl Future<Output = ()> + Send;
}

pub trait Transport: Send + Sync {
    type Conn: Connection;
    fn local_addrs(&self) -> Vec<SocketAddr>;
    /// `peer.addrs` в порядке приоритета; реализация может пробовать их наперегонки;
    /// на один вызов не больше одной аутентификации; побеждает первый аутентифицированный.
    fn connect(
        &self,
        peer: &PeerAddr,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
    fn accept(&self) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}

/// Источник событий транспорта.
pub trait EventSource: Send + 'static {
    /// `None`: транспорта больше нет. Потерянные события приходят как `Some(TransportEvent::Lagged)`.
    fn recv(&mut self) -> impl Future<Output = Option<TransportEvent>> + Send;
}

/// Транспорт, которым управляет слой соединения.
pub trait ManagedTransport: Transport + 'static {
    type Events: EventSource;
    /// Атомарная замена набора пар; повтор `PairId` отвергается целиком.
    fn set_peers(&self, peers: Vec<KxPeer>) -> Result<(), DuplicatePairError>;
    /// С объединением: пока идёт серия повторных стуков, дальнейшие вызовы лишь помечают
    /// «ещё раз» (одна повторная серия).
    fn reknock(&self);
    fn subscribe(&self) -> Self::Events;
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

    fn conn_id(&self) -> u64 {
        match *self {}
    }

    fn is_initiator(&self) -> bool {
        match *self {}
    }

    async fn closed(&self) {
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
