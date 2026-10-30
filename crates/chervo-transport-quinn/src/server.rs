//! Приём: единственная функция `admit` потребляет `Incoming`; вызываемая сторона KK.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chervo_identity::{KK_KIND_V1, KK_MSG1_LEN, KK_MSG3_LEN, PairId};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout_at};

use crate::Inner;
use crate::conn::{Fail, RefuseGuard, binding, expect_eof, read_exact_n, refuse};
use crate::knock::Pin;
use crate::limits::{Counters, KeyPermit, PairPermit};
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
    // Допуск только проверяется; попытка списывается ниже, когда место до аутентификации уже
    // получено (S2, L2): отказанные по лимитам `Incoming` не сжигают попытки честного друга.
    let admitted_pair = if inner.knock.required {
        let Some(pair) = inner.knock.peek_admission(incoming.remote_address()) else {
            // подтверждённый `Incoming` без допуска или сверх числа попыток: молчание
            incoming.ignore();
            return;
        };
        Some(pair)
    } else {
        None
    };
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
    // Не больше `max_preauth_per_key` незавершённых с одного ключа лимитера: проверка без
    // списания квоты, молчание как при занятом семафоре. Место освобождается при сбросе.
    let Some(key_permit) = inner.preauth_keys.try_acquire(ip) else {
        incoming.ignore();
        Counters::bump(&inner.counters.ignored_busy);
        return;
    };
    // Не больше `max_preauth_per_pair` незавершённых на пару допуска (S2, L3): друг со многими
    // ключами лимитера не занимает все места. Молчание, как при занятом семафоре.
    let pair_permit = match admitted_pair {
        Some(pair) => {
            let Some(p) = inner.preauth_pairs.try_acquire(pair) else {
                incoming.ignore();
                Counters::bump(&inner.counters.ignored_busy);
                return;
            };
            Some(p)
        }
        None => None,
    };
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
    // место получено: теперь списывается попытка допуска (при гонке с другим `Incoming` того же
    // адреса попытки могло не остаться: молчание)
    if inner.knock.required && !inner.knock.consume_attempt(incoming.remote_address()) {
        incoming.ignore();
        return;
    }
    let Ok(server_cfg) = ephemeral_server_config(&inner.cfg) else {
        incoming.ignore();
        return;
    };
    let start = Instant::now();
    let deadline = start + inner.cfg.auth_deadline;
    // полный `msg1` обязан прийти раньше, чем кончится вся аутентификация
    let msg1_deadline = start + inner.cfg.msg1_deadline_eff();
    // закрепление адреса до конца KK: пакеты рукопожатия проходят и без действующего допуска
    let pin = inner.knock.pin(incoming.remote_address());
    if let Ok(connecting) = incoming.accept_with(server_cfg) {
        let inner = inner.clone();
        tokio::spawn(async move {
            serve(
                inner,
                connecting,
                Deadlines {
                    msg1_deadline,
                    deadline,
                },
                Held {
                    _permit: permit,
                    _key: key_permit,
                    _pair: pair_permit,
                    _pin: pin,
                },
            )
            .await;
        });
    }
}

/// Сроки приёма: до полного `msg1` и до конца всей аутентификации.
#[derive(Clone, Copy)]
struct Deadlines {
    msg1_deadline: Instant,
    deadline: Instant,
}

/// Всё, что держит место незавершённого соединения до конца `serve`.
struct Held {
    _permit: OwnedSemaphorePermit,
    _key: KeyPermit,
    _pair: Option<PairPermit>,
    _pin: Pin,
}

/// Результат успешной проверки вызываемого.
struct Authed {
    pair: PairId,
    ours_pub: [u8; 32],
    theirs_pub: [u8; 32],
}

async fn serve(
    inner: Arc<Inner>,
    connecting: quinn::Connecting,
    deadlines: Deadlines,
    _held: Held,
) {
    let Deadlines {
        msg1_deadline,
        deadline,
    } = deadlines;
    let conn = match timeout_at(msg1_deadline, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => return,
        Err(_) => {
            Counters::bump(&inner.counters.auth_timeout);
            return;
        }
    };
    // адрес, снятый сразу после QUIC-рукопожатия, до KK: ему доверяет `Contact`, а не позднему
    // `remote_address()`, который мог смениться миграцией пути
    let established = crate::knock::canon(conn.remote_address());
    let result = timeout_at(
        deadline,
        callee_handshake(&inner, &conn, msg1_deadline, deadline),
    )
    .await;
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
    // Место в очереди резервируется до `promote`: победитель, не помещающийся в очередь, не должен
    // вытеснить старое соединение пары и сам тут же закрыться.
    let Ok(slot) = inner.queue_tx.try_reserve() else {
        inner.counters.queue_full.fetch_add(1, Ordering::Relaxed);
        refuse(&conn);
        return;
    };
    #[cfg(test)]
    inner.test_pause_before_promote().await;
    match promote(
        &inner,
        conn.clone(),
        authed.pair,
        false,
        established,
        authed.ours_pub,
        authed.theirs_pub,
    ) {
        // тройки нет в текущем наборе: соединение уже закрыто отказом, вызываемый молчит
        Promoted::NotAllowed => Counters::bump(&inner.counters.auth_not_admitted),
        Promoted::Lost(_) => Counters::bump(&inner.counters.auth_ok),
        Promoted::Winner(qc) => {
            Counters::bump(&inner.counters.auth_ok);
            slot.send(qc);
        }
    }
}

async fn callee_handshake(
    inner: &Arc<Inner>,
    conn: &quinn::Connection,
    msg1_deadline: Instant,
    deadline: Instant,
) -> Result<Authed, Fail> {
    let bind = binding(conn).map_err(|_| Fail::Failed)?;
    // поток и полный `msg1` до `msg1_deadline`; при отмене по сроку защитник (создан внутри
    // будущего) закрывает соединение отказом, как при любом другом выходе
    let first = async {
        let (tx, rx) = conn.accept_bi().await.map_err(|_| Fail::Failed)?;
        // защитник владеет потоками: при любом выходе или отмене отказ уходит раньше FIN/STOP_SENDING
        let mut guard = RefuseGuard::new(conn, tx, rx);
        let msg1: [u8; KK_MSG1_LEN] = read_exact_n(&mut guard.rx).await?;
        Ok::<_, Fail>((guard, msg1))
    };
    let (mut guard, msg1) = match timeout_at(msg1_deadline, first).await {
        Ok(r) => r?,
        Err(_) => return Err(Fail::Timeout),
    };
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
    // `msg3` и EOF в короткий срок после `msg2` (S2, L3): молчащий после верного `msg1`
    // не держит место до `auth_deadline`
    let msg3_deadline = (Instant::now() + inner.cfg.msg3_deadline).min(deadline);
    let msg3: [u8; KK_MSG3_LEN] = match timeout_at(msg3_deadline, async {
        let m = read_exact_n(&mut guard.rx).await?;
        expect_eof(&mut guard.rx).await?;
        Ok::<_, Fail>(m)
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(Fail::Timeout),
    };
    let pair = responder.finish(&msg3).map_err(|_| Fail::Failed)?;
    if !inner.filter.is_allowed(&pair) {
        return Err(Fail::Failed);
    }
    // тройка берётся из снимка, с которым прошёл KK; `PairId` в снимке уникален (`set_peers`
    // отвергает повторы), поэтому `find` однозначно даёт запись, совпавшую в KK;
    // `promote` сверит её с текущим набором
    let (ours_pub, theirs_pub) = snapshot
        .iter()
        .find(|p| p.pair() == pair)
        .map(|p| (p.ours_public().to_bytes(), p.theirs().to_bytes()))
        .ok_or(Fail::Failed)?;
    guard.disarm();
    Ok(Authed {
        pair,
        ours_pub,
        theirs_pub,
    })
}
