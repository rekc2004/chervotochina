//! Соединение, потоки, экспортёр TLS и единый отказ.

use std::fmt;
use std::net::SocketAddr;

use chervo_identity::{BINDING_LEN, ChannelBinding, PairId};
use chervo_transport::{Connection, RecvStream, SendStream, TransportError};
use quinn::VarInt;
use zeroize::Zeroizing;

use crate::{CLOSE_DUPLICATE, EKM_CONTEXT, EKM_LABEL};

/// Значение экспортёра TLS этого соединения. Единственное место вызова экспортёра.
pub(crate) fn ekm(conn: &quinn::Connection) -> Result<Zeroizing<[u8; BINDING_LEN]>, ()> {
    let mut out = Zeroizing::new([0u8; BINDING_LEN]);
    conn.export_keying_material(out.as_mut_slice(), EKM_LABEL, EKM_CONTEXT)
        .map_err(|_| ())?;
    Ok(out)
}

/// Привязка к каналу: экспортёр этого соединения после завершения рукопожатия TLS.
/// Других источников `ChannelBinding` в `src/` нет.
pub(crate) fn binding(conn: &quinn::Connection) -> Result<ChannelBinding, ()> {
    let bytes = ekm(conn)?;
    Ok(ChannelBinding::from_bytes(*bytes))
}

/// Единый отказ на любую неудачу до подтверждения пары: код и пустая причина, ни одного байта.
pub(crate) fn refuse(conn: &quinn::Connection) {
    conn.close(VarInt::from_u32(crate::CLOSE_REFUSED), b"");
}

/// Закрытие всего гнезда (`shutdown`): тот же код и пустая причина, что у отказа.
pub(crate) fn close_endpoint(endpoint: &quinn::Endpoint) {
    endpoint.close(VarInt::from_u32(crate::CLOSE_REFUSED), b"");
}

/// Владеет потоками рукопожатия и закрывает соединение отказом при любом выходе до `disarm`
/// (в том числе при отмене future): `Drop::drop` защитника идёт раньше сброса его полей, то есть
/// раньше, чем освободятся потоки. Сброшенный без `finish` поток quinn завершает штатно (FIN), а
/// непрочитанный отправляет STOP_SENDING, и это опередило бы закрытие и стало бы видимым
/// отличием причин отказа; после `close` потоки при сбросе ничего не шлют.
pub(crate) struct RefuseGuard<'a> {
    conn: &'a quinn::Connection,
    armed: bool,
    pub(crate) tx: quinn::SendStream,
    pub(crate) rx: quinn::RecvStream,
}

impl<'a> RefuseGuard<'a> {
    pub(crate) fn new(
        conn: &'a quinn::Connection,
        tx: quinn::SendStream,
        rx: quinn::RecvStream,
    ) -> Self {
        Self {
            conn,
            armed: true,
            tx,
            rx,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RefuseGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            refuse(self.conn);
        }
    }
}

/// Проигравшее дубликат соединение (только аутентифицированному собеседнику).
pub(crate) fn close_duplicate(conn: &quinn::Connection) {
    conn.close(VarInt::from_u32(CLOSE_DUPLICATE), b"");
}

/// Аутентифицированное соединение. Пара подтверждена Noise KK внутри канала.
#[derive(Clone)]
pub struct QuinnConn {
    pub(crate) conn: quinn::Connection,
    pub(crate) pair: PairId,
    pub(crate) initiator: bool,
}

impl fmt::Debug for QuinnConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QuinnConn(..)")
    }
}

impl QuinnConn {
    /// Эта сторона звонила (а не принимала).
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
}

pub struct QuinnSend(quinn::SendStream);
pub struct QuinnRecv(quinn::RecvStream);

impl SendStream for QuinnSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.0
            .write_all(buf)
            .await
            .map_err(|_| TransportError::Closed)
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        self.0.finish().map_err(|_| TransportError::Closed)
    }
}

impl RecvStream for QuinnRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        self.0.read(buf).await.map_err(|_| TransportError::Closed)
    }
}

impl Connection for QuinnConn {
    type Tx = QuinnSend;
    type Rx = QuinnRecv;

    fn remote_pair(&self) -> PairId {
        self.pair
    }

    fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    async fn open_bi(&self) -> Result<(Self::Tx, Self::Rx), TransportError> {
        let (tx, rx) = self
            .conn
            .open_bi()
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok((QuinnSend(tx), QuinnRecv(rx)))
    }

    async fn accept_bi(&self) -> Result<(Self::Tx, Self::Rx), TransportError> {
        let (tx, rx) = self
            .conn
            .accept_bi()
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok((QuinnSend(tx), QuinnRecv(rx)))
    }

    fn close(&self) {
        refuse(&self.conn);
    }
}

/// Причина неудачи аутентификации. Наружу (в сеть) не различается; различия только для
/// локальных счётчиков и для ошибки, возвращаемой звонящему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
    Failed,
    Timeout,
    /// Отказ ворот (счётчик `kk_denied` уже увеличен).
    Denied,
}

impl From<crate::limits::GateError> for Fail {
    fn from(e: crate::limits::GateError) -> Self {
        match e {
            crate::limits::GateError::Denied => Self::Denied,
            crate::limits::GateError::TimedOut => Self::Timeout,
            crate::limits::GateError::Failed => Self::Failed,
        }
    }
}

/// Ровно `N` байт из потока; ранний конец или ошибка: `Err`.
pub(crate) async fn read_exact_n<const N: usize>(
    rx: &mut quinn::RecvStream,
) -> Result<[u8; N], Fail> {
    let mut buf = [0u8; N];
    rx.read_exact(&mut buf).await.map_err(|_| Fail::Failed)?;
    Ok(buf)
}

/// Дальше в потоке должен быть конец; любой лишний байт или ошибка: `Err`.
pub(crate) async fn expect_eof(rx: &mut quinn::RecvStream) -> Result<(), Fail> {
    let mut one = [0u8; 1];
    match rx.read(&mut one).await {
        Ok(None) => Ok(()),
        _ => Err(Fail::Failed),
    }
}
