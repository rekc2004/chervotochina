//! Чтение кадров и сырых данных из потока. Длина проверяется до чтения тела; сырые данные
//! читаются ровно в тот буфер, размер которого определили мы.

use std::time::Duration;

use chervo_transport::{RecvStream, TransportError};
use tokio::time::timeout;

use crate::codec::{Message, ProtocolError, decode_message};
use crate::limits::MAX_MESSAGE_LEN;

fn map_transport(e: TransportError) -> ProtocolError {
    match e {
        TransportError::TimedOut => ProtocolError::TimedOut,
        _ => ProtocolError::Closed,
    }
}

/// Один вызов `read`. `Some(0)` на непустом буфере нарушает контракт потока (иначе цикл
/// чтения мог бы крутиться без продвижения), поэтому считается обрывом.
async fn read_some<R: RecvStream>(
    rx: &mut R,
    buf: &mut [u8],
) -> Result<Option<usize>, ProtocolError> {
    let want = buf.len();
    match rx.read(buf).await.map_err(map_transport)? {
        Some(0) if want > 0 => Err(ProtocolError::Closed),
        Some(n) if n > want => Err(ProtocolError::Closed),
        other => Ok(other),
    }
}

/// Дочитывает `buf` до конца, начиная с `filled` уже лежащих в начале байт.
async fn fill<R: RecvStream>(
    rx: &mut R,
    buf: &mut [u8],
    mut filled: usize,
) -> Result<(), ProtocolError> {
    loop {
        let rest = buf.get_mut(filled..).ok_or(ProtocolError::Malformed)?;
        if rest.is_empty() {
            return Ok(());
        }
        match read_some(rx, rest).await? {
            None => return Err(ProtocolError::Closed),
            Some(n) => filled = filled.saturating_add(n),
        }
    }
}

/// Читает один кадр: 4 байта длины (1..=`MAX_MESSAGE_LEN`, проверяется до чтения тела), затем
/// тело; всё это за `deadline` от первого байта длины. Ожидание самого первого байта не
/// ограничено (его ограничивает вызывающий). `Ok(None)`: поток чисто закончился до первого
/// байта длины.
pub async fn read_message<R: RecvStream>(
    rx: &mut R,
    buf: &mut Vec<u8>,
    deadline: Duration,
) -> Result<Option<Message>, ProtocolError> {
    let mut head = [0u8; 4];
    let Some(first) = read_some(rx, &mut head).await? else {
        return Ok(None);
    };
    let frame = async {
        fill(rx, &mut head, first).await?;
        let len = usize::try_from(u32::from_be_bytes(head)).map_err(|_| ProtocolError::TooLong)?;
        if len == 0 {
            return Err(ProtocolError::Malformed);
        }
        if len > MAX_MESSAGE_LEN {
            return Err(ProtocolError::TooLong);
        }
        buf.clear();
        buf.resize(len, 0);
        fill(rx, buf.as_mut_slice(), 0).await?;
        decode_message(buf).map(Some)
    };
    timeout(deadline, frame)
        .await
        .map_err(|_| ProtocolError::TimedOut)?
}

/// Ровно `out.len()` сырых байт. Таймер сбрасывается при каждом прочитанном куске: срабатывает
/// только когда `stall` не пришло ни одного байта. Конец потока раньше срока это `Closed`.
pub async fn read_exact<R: RecvStream>(
    rx: &mut R,
    out: &mut [u8],
    stall: Duration,
) -> Result<(), ProtocolError> {
    let mut filled = 0usize;
    loop {
        let rest = out.get_mut(filled..).ok_or(ProtocolError::Malformed)?;
        if rest.is_empty() {
            return Ok(());
        }
        let got = timeout(stall, read_some(rx, rest))
            .await
            .map_err(|_| ProtocolError::TimedOut)??;
        match got {
            None => return Err(ProtocolError::Closed),
            Some(n) => filled = filled.saturating_add(n),
        }
    }
}
