//! Приём: единственная функция `admit` потребляет `Incoming`; вызываемая сторона KK.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chervo_identity::{KK_KIND_V1, KK_MSG1_LEN, KK_MSG3_LEN, PairId};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Instant, timeout_at};

use crate::Inner;
use crate::conn::{Fail, binding, expect_eof, read_exact_n, refuse};
use crate::limits::Counters;
use crate::registry::{Promoted, promote};
use crate::tls::ephemeral_server_config;

/// Фильтры до TLS. Любой отказ до TLS: молчание (`ignore`), одинаково для всех причин.
pub(crate) fn admit(inner: &Arc<Inner>, incoming: quinn::Incoming) {
    if !incoming.remote_address_validated() {
        match incoming.retry() {
            Ok(()) => Counters::bump(&inner.counters.retry_sent),
            Err(e) => e.into_incoming().ignore(),
        }
        return;
    }
    let allowed = {
        let mut lim = inner
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lim.allow(incoming.remote_address().ip(), Instant::now())
    };
    if !allowed {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_rate);
        return;
    }
    let Ok(permit) = inner.preauth.clone().try_acquire_owned() else {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_busy);
        return;
    };
    let Ok(server_cfg) = ephemeral_server_config(&inner.cfg) else {
        incoming.ignore();
        return;
    };
    let deadline = Instant::now() + inner.cfg.auth_deadline;
    if let Ok(connecting) = incoming.accept_with(server_cfg) {
        let inner = inner.clone();
        tokio::spawn(async move {
            serve(inner, connecting, deadline, permit).await;
        });
    }
}

/// Результат успешной проверки вызываемого.
struct Authed {
    pair: PairId,
    caller_pub: [u8; 32],
}

async fn serve(
    inner: Arc<Inner>,
    connecting: quinn::Connecting,
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
) {
    let conn = match timeout_at(deadline, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => return,
        Err(_) => {
            Counters::bump(&inner.counters.auth_timeout);
            return;
        }
    };
    let result = timeout_at(deadline, callee_handshake(&inner, &conn, deadline)).await;
    let authed = match result {
        Ok(Ok(a)) => a,
        Ok(Err(fail)) => {
            match fail {
                Fail::Failed => Counters::bump(&inner.counters.auth_failed),
                Fail::Timeout => Counters::bump(&inner.counters.auth_timeout),
                Fail::Denied => {}
            }
            refuse(&conn);
            return;
        }
        Err(_) => {
            Counters::bump(&inner.counters.auth_timeout);
            refuse(&conn);
            return;
        }
    };
    Counters::bump(&inner.counters.auth_ok);
    match promote(&inner, conn.clone(), authed.pair, false, authed.caller_pub) {
        Promoted::Lost(_) => {}
        Promoted::Winner(qc) => match inner.queue_tx.try_send(qc) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                inner.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                refuse(&conn);
            }
        },
    }
}

async fn callee_handshake(
    inner: &Arc<Inner>,
    conn: &quinn::Connection,
    deadline: Instant,
) -> Result<Authed, Fail> {
    let bind = binding(conn).map_err(|_| Fail::Failed)?;
    let (mut tx, mut rx) = conn.accept_bi().await.map_err(|_| Fail::Failed)?;
    let msg1: [u8; KK_MSG1_LEN] = read_exact_n(&mut rx).await?;
    if msg1.first() != Some(&KK_KIND_V1) {
        return Err(Fail::Failed);
    }
    let snapshot = inner.peers_snapshot();
    let allowed: Vec<usize> = snapshot
        .iter()
        .enumerate()
        .filter(|(_, p)| inner.filter.is_allowed(&p.pair()))
        .map(|(i, _)| i)
        .collect();
    if allowed.is_empty() {
        return Err(Fail::Failed);
    }
    let (responder, msg2) = inner
        .gate
        .respond(deadline, snapshot.clone(), allowed, bind, msg1)
        .await?;
    tx.write_all(&msg2).await.map_err(|_| Fail::Failed)?;
    tx.finish().map_err(|_| Fail::Failed)?;
    let msg3: [u8; KK_MSG3_LEN] = read_exact_n(&mut rx).await?;
    expect_eof(&mut rx).await?;
    let pair = responder.finish(&msg3).map_err(|_| Fail::Failed)?;
    if !inner.filter.is_allowed(&pair) {
        return Err(Fail::Failed);
    }
    let caller_pub = snapshot
        .iter()
        .find(|p| p.pair() == pair)
        .map(|p| p.theirs().to_bytes())
        .ok_or(Fail::Failed)?;
    Ok(Authed { pair, caller_pub })
}
