//! Звонок: сторона-инициатор KK, один адрес за раз.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chervo_identity::{KK_MSG2_LEN, PairId, kk_initiate};
use chervo_transport::{PeerAddr, TransportError};
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

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
    let started = Instant::now();
    let deadline = started + inner.cfg.auth_deadline;
    let knock = &inner.knock;
    let required = knock.required;
    // закрепление: ответы адреса проходят, новый `Incoming` с него без своего стука нет
    let pin = knock.pin(addr);
    if required {
        let first = knock
            .make_knock(&pair, false)
            .ok_or(TransportError::AuthFailed)?;
        knock.send(addr, &first).await;
        sleep(inner.cfg.knock_lead).await;
    }
    let cc = client_config(&inner.client_quic, &inner.client_transport);
    let connecting = inner
        .endpoint
        .connect_with(cc, addr, SERVER_NAME)
        .map_err(|_| TransportError::Io)?;
    tokio::pin!(connecting);
    // досылка стука в моменты `resend` и `3*resend` (третий по системному времени при поправке)
    let resend = inner.cfg.knock_resend_after;
    let mut sent = 1u32;
    let outcome = loop {
        let next = match sent {
            1 => Some(started + resend),
            2 => Some(started + resend.saturating_mul(3)),
            _ => None,
        }
        .filter(|_| required);
        tokio::select! {
            r = &mut connecting => break Some(r),
            () = sleep_until(deadline) => break None,
            () = async {
                match next {
                    Some(t) => sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let raw = sent == 2 && knock.offset() != 0;
                if let Some(k) = knock.make_knock(&pair, raw) {
                    knock.send(addr, &k).await;
                }
                sent += 1;
            }
        }
    };
    let conn = match outcome {
        Some(Ok(c)) => c,
        Some(Err(_)) => {
            if !pin.heard() {
                Counters::bump(&inner.counters.connect_silent);
            }
            return Err(TransportError::Io);
        }
        None => {
            Counters::bump(&inner.counters.auth_timeout);
            if !pin.heard() {
                Counters::bump(&inner.counters.connect_silent);
            }
            return Err(TransportError::TimedOut);
        }
    };
    match timeout_at(deadline, caller_handshake(inner, &conn, pair)).await {
        Ok(Ok((ours, theirs))) => {
            Counters::bump(&inner.counters.auth_ok);
            #[cfg(test)]
            inner.test_pause_before_promote().await;
            match promote(inner, conn, pair, true, ours, theirs) {
                Promoted::Winner(c) | Promoted::Lost(c) => Ok(c),
                Promoted::NotAllowed => Err(TransportError::PeerNotAllowed),
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

/// Возвращает публичные X25519 (наш, собеседника) для правила одного соединения и членства в наборе.
async fn caller_handshake(
    inner: &Arc<Inner>,
    conn: &quinn::Connection,
    pair: PairId,
) -> Result<([u8; 32], [u8; 32]), Fail> {
    let bind = binding(conn).map_err(|_| Fail::Failed)?;
    let snapshot = inner.peers_snapshot();
    let kx = snapshot
        .iter()
        .find(|p| p.pair() == pair)
        .ok_or(Fail::Failed)?;
    let (initiator, msg1) = kk_initiate(kx, &bind).map_err(|_| Fail::Failed)?;
    let ours_public = kx.ours_public().to_bytes();
    let theirs_public = kx.theirs().to_bytes();
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
    Ok((ours_public, theirs_public))
}

/// После смены своего адреса или `rebind`: стук по каждому живому соединению (первый сразу,
/// остальные в моменты `resend`, `3*resend`), чтобы собеседник допустил новый адрес.
/// Все стуки уходят из одной задачи на `inner.rt`; первый тоже через `send`, который
/// при `WouldBlock` ждёт готовности гнезда, поэтому он не теряется на занятом гнезде.
pub(crate) fn reknock_live(inner: &Arc<Inner>) {
    if !inner.knock.required {
        return;
    }
    let targets = inner.registry.live_remotes();
    if targets.is_empty() {
        return;
    }
    let task_inner = inner.clone();
    inner.rt.spawn(async move {
        let inner = task_inner;
        let t0 = Instant::now();
        let resend = inner.cfg.knock_resend_after;
        for (n, at) in [Duration::ZERO, resend, resend.saturating_mul(3)]
            .into_iter()
            .enumerate()
        {
            sleep_until(t0 + at).await;
            let raw = n == 2 && inner.knock.offset() != 0;
            for (pair, addr) in &targets {
                if let Some(k) = inner.knock.make_knock(pair, raw) {
                    inner.knock.send(*addr, &k).await;
                }
            }
        }
    });
}
