//! Приём: единственная функция `admit` потребляет `Incoming`; вызываемая сторона KK.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chervo_identity::{KK_KIND_V1, KK_MSG1_LEN, KK_MSG3_LEN, PairId};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout_at};

use crate::Inner;
use crate::conn::{Fail, RefuseGuard, binding, expect_eof, read_exact_n, refuse};
use crate::knock::Pin;
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
    if inner.knock.required && !inner.knock.consume_attempt(incoming.remote_address()) {
        // подтверждённый `Incoming` без допуска или сверх числа попыток: молчание
        incoming.ignore();
        return;
    }
    let ip = incoming.remote_address().ip();
    // Порядок: проверка лимита без списания, семафор, и только потом списание квоты. Иначе повторы
    // Initial под занятым семафором тратили бы квоту друга (за общим адресом она общая).
    let permitted = {
        let lim = inner
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lim.would_allow(ip, Instant::now())
    };
    if !permitted {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_rate);
        return;
    }
    let Ok(permit) = inner.preauth.clone().try_acquire_owned() else {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_busy);
        return;
    };
    let charged = {
        let mut lim = inner
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lim.allow(ip, Instant::now())
    };
    if !charged {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_rate);
        return;
    }
    let Ok(server_cfg) = ephemeral_server_config(&inner.cfg) else {
        incoming.ignore();
        return;
    };
    let deadline = Instant::now() + inner.cfg.auth_deadline;
    // закрепление адреса до конца KK: пакеты рукопожатия проходят и без действующего допуска
    let pin = inner.knock.pin(incoming.remote_address());
    if let Ok(connecting) = incoming.accept_with(server_cfg) {
        let inner = inner.clone();
        tokio::spawn(async move {
            serve(inner, connecting, deadline, permit, pin).await;
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
    _pin: Pin,
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
    // Место в очереди резервируется до `promote`: победитель, не помещающийся в очередь, не должен
    // вытеснить старое соединение пары и сам тут же закрыться.
    let Ok(slot) = inner.queue_tx.try_reserve() else {
        inner.counters.queue_full.fetch_add(1, Ordering::Relaxed);
        refuse(&conn);
        return;
    };
    match promote(&inner, conn.clone(), authed.pair, false, authed.caller_pub) {
        Promoted::Lost(_) => {}
        Promoted::Winner(qc) => slot.send(qc),
    }
}

async fn callee_handshake(
    inner: &Arc<Inner>,
    conn: &quinn::Connection,
    deadline: Instant,
) -> Result<Authed, Fail> {
    let bind = binding(conn).map_err(|_| Fail::Failed)?;
    let (tx, rx) = conn.accept_bi().await.map_err(|_| Fail::Failed)?;
    // защитник владеет потоками: при любом выходе или отмене отказ уходит раньше FIN/STOP_SENDING
    let mut guard = RefuseGuard::new(conn, tx, rx);
    let msg1: [u8; KK_MSG1_LEN] = read_exact_n(&mut guard.rx).await?;
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
    guard.tx.write_all(&msg2).await.map_err(|_| Fail::Failed)?;
    guard.tx.finish().map_err(|_| Fail::Failed)?;
    let msg3: [u8; KK_MSG3_LEN] = read_exact_n(&mut guard.rx).await?;
    expect_eof(&mut guard.rx).await?;
    let pair = responder.finish(&msg3).map_err(|_| Fail::Failed)?;
    if !inner.filter.is_allowed(&pair) {
        return Err(Fail::Failed);
    }
    let caller_pub = snapshot
        .iter()
        .find(|p| p.pair() == pair)
        .map(|p| p.theirs().to_bytes())
        .ok_or(Fail::Failed)?;
    guard.disarm();
    Ok(Authed { pair, caller_pub })
}
