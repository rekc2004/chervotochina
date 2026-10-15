//! Звонок: сторона-инициатор KK, один адрес за раз.

use std::net::SocketAddr;
use std::sync::Arc;

use chervo_identity::{KK_MSG2_LEN, PairId, kk_initiate};
use chervo_transport::{PeerAddr, TransportError};
use tokio::time::{Instant, timeout_at};

use crate::conn::{Fail, QuinnConn, RefuseGuard, binding, expect_eof, read_exact_n, refuse};
use crate::limits::Counters;
use crate::registry::{Promoted, promote};
use crate::tls::client_config;
use crate::{Inner, SERVER_NAME};

pub(crate) async fn connect(
    inner: &Arc<Inner>,
    peer: &PeerAddr,
) -> Result<QuinnConn, TransportError> {
    if !inner.filter.is_allowed(&peer.pair) {
        return Err(TransportError::PeerNotAllowed);
    }
    let snapshot = inner.peers_snapshot();
    if !snapshot.iter().any(|p| p.pair() == peer.pair) {
        return Err(TransportError::UnknownPair);
    }
    if peer.addrs.is_empty() {
        return Err(TransportError::Io);
    }
    let mut last = TransportError::Io;
    for addr in &peer.addrs {
        match attempt(inner, peer.pair, *addr).await {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn map_fail(f: Fail) -> TransportError {
    match f {
        Fail::Timeout => TransportError::TimedOut,
        Fail::Failed | Fail::Denied => TransportError::AuthFailed,
    }
}

async fn attempt(
    inner: &Arc<Inner>,
    pair: PairId,
    addr: SocketAddr,
) -> Result<QuinnConn, TransportError> {
    let deadline = Instant::now() + inner.cfg.auth_deadline;
    let cc = client_config(&inner.client_quic, &inner.client_transport);
    let connecting = inner
        .endpoint
        .connect_with(cc, addr, SERVER_NAME)
        .map_err(|_| TransportError::Io)?;
    let conn = match timeout_at(deadline, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => return Err(TransportError::Io),
        Err(_) => {
            Counters::bump(&inner.counters.auth_timeout);
            return Err(TransportError::TimedOut);
        }
    };
    match timeout_at(deadline, caller_handshake(inner, &conn, pair)).await {
        Ok(Ok(caller_pub)) => {
            Counters::bump(&inner.counters.auth_ok);
            match promote(inner, conn, pair, true, caller_pub) {
                Promoted::Winner(c) | Promoted::Lost(c) => Ok(c),
            }
        }
        Ok(Err(fail)) => {
            match fail {
                Fail::Failed => Counters::bump(&inner.counters.auth_failed),
                Fail::Timeout => Counters::bump(&inner.counters.auth_timeout),
                Fail::Denied => {}
            }
            refuse(&conn);
            Err(map_fail(fail))
        }
        Err(_) => {
            Counters::bump(&inner.counters.auth_timeout);
            refuse(&conn);
            Err(TransportError::TimedOut)
        }
    }
}

/// Возвращает публичный X25519 звонящего (наш) для правила одного соединения.
async fn caller_handshake(
    inner: &Arc<Inner>,
    conn: &quinn::Connection,
    pair: PairId,
) -> Result<[u8; 32], Fail> {
    let bind = binding(conn).map_err(|_| Fail::Failed)?;
    let snapshot = inner.peers_snapshot();
    let kx = snapshot
        .iter()
        .find(|p| p.pair() == pair)
        .ok_or(Fail::Failed)?;
    let (initiator, msg1) = kk_initiate(kx, &bind).map_err(|_| Fail::Failed)?;
    let ours_public = kx.ours_public().to_bytes();
    let (tx, rx) = conn.open_bi().await.map_err(|_| Fail::Failed)?;
    // защитник владеет потоками: при любом выходе или отмене отказ уходит раньше FIN/STOP_SENDING
    let mut guard = RefuseGuard::new(conn, tx, rx);
    guard.tx.write_all(&msg1).await.map_err(|_| Fail::Failed)?;
    let msg2: [u8; KK_MSG2_LEN] = read_exact_n(&mut guard.rx).await?;
    expect_eof(&mut guard.rx).await?;
    let msg3 = initiator.finish(&msg2).map_err(|_| Fail::Failed)?;
    guard.tx.write_all(&msg3).await.map_err(|_| Fail::Failed)?;
    guard.tx.finish().map_err(|_| Fail::Failed)?;
    guard.disarm();
    Ok(ours_public)
}
