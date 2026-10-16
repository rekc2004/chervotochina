//! Звонок: сторона-инициатор KK. Один `connect` гоняет адреса наперегонки (адрес `i` стартует
//! через `i * connect_stagger`), но аутентифицирует не больше одного соединения: первое,
//! закончившее QUIC-рукопожатие, идёт в KK; остальные закрываются отказом до KK.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use chervo_identity::{KK_MSG2_LEN, PairId, kk_initiate};
use chervo_transport::{PeerAddr, TransportError};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

use crate::conn::{Fail, QuinnConn, RefuseGuard, binding, expect_eof, read_exact_n, refuse};
use crate::knock::{Pin, canon};
use crate::limits::Counters;
use crate::registry::{Promoted, promote};
use crate::tls::client_config;
use crate::{Inner, SERVER_NAME};

/// Предел одной попытки KK на установленном соединении гонки (ревью 13, L1).
const KK_ATTEMPT_CAP: Duration = Duration::from_secs(3);

/// Не больше одного исходящего звонка на пару: запись убирается при любом выходе, в том числе
/// при отмене future.
struct DialGuard {
    inner: Arc<Inner>,
    pair: PairId,
}

impl DialGuard {
    /// `Busy`, если звонок к паре уже идёт; пакетов к этому моменту не отправлено.
    fn acquire(inner: &Arc<Inner>, pair: PairId) -> Result<Self, TransportError> {
        let mut set = inner.dialing.lock().unwrap_or_else(PoisonError::into_inner);
        if !set.insert(pair) {
            return Err(TransportError::Busy);
        }
        Ok(Self {
            inner: inner.clone(),
            pair,
        })
    }
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        self.inner
            .dialing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.pair);
    }
}

/// Кандидаты гонки: v4-mapped как IPv4, без семейства, чужого для гнезда, без повторов, не
/// больше `max_race`, порядок приоритета сохраняется.
fn candidates(inner: &Inner, addrs: &[SocketAddr]) -> Result<Vec<SocketAddr>, TransportError> {
    let v4_endpoint = inner
        .endpoint
        .local_addr()
        .map_err(|_| TransportError::Io)?
        .is_ipv4();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for a in addrs {
        let a = canon(*a);
        // IPv6 на IPv4-гнезде: `InvalidRemoteAddress`; IPv4 на IPv6-гнезде quinn отображает сам
        if v4_endpoint && a.is_ipv6() {
            continue;
        }
        if out.len() >= inner.cfg.max_race {
            break;
        }
        if seen.insert(a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(TransportError::Io);
    }
    Ok(out)
}

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
    let _guard = DialGuard::acquire(inner, peer.pair)?;
    let addrs = candidates(inner, &peer.addrs)?;
    let pair = peer.pair;
    let t0 = Instant::now();
    let deadline = t0.checked_add(inner.cfg.auth_deadline).unwrap_or(t0);
    let mut set: JoinSet<Result<Established, AttemptFail>> = JoinSet::new();
    for (i, addr) in addrs.iter().enumerate() {
        let delay = inner
            .cfg
            .connect_stagger
            .saturating_mul(u32::try_from(i).unwrap_or(u32::MAX));
        let start = t0.checked_add(delay).unwrap_or(deadline);
        set.spawn_on(
            dial_one(inner.clone(), pair, *addr, start, deadline),
            &inner.rt,
        );
    }

    // каждый адрес закончит сам не позже `deadline`, поэтому цикл ограничен им же
    let mut all_silent = true;
    let mut any_timeout = false;
    let mut kk_err: Option<TransportError> = None;
    let mut last = TransportError::Io;
    let mut outcome: Option<Result<QuinnConn, TransportError>> = None;
    while let Some(joined) = set.join_next().await {
        let est = match joined {
            Ok(Ok(est)) => est,
            Ok(Err(f)) => {
                all_silent &= f.silent;
                any_timeout |= f.err == TransportError::TimedOut;
                last = f.err;
                continue;
            }
            Err(_) => {
                all_silent = false;
                last = TransportError::Io;
                continue;
            }
        };
        // QUIC-рукопожатие закончено: собеседник отвечал
        all_silent = false;
        let conn = &est.conn;
        // ревью 13, L1: один KK не дольше `KK_ATTEMPT_CAP` (и не дольше общего срока):
        // ответчик, завершивший QUIC и молчащий в KK, не съедает весь вызов
        let kk_by = Instant::now()
            .checked_add(KK_ATTEMPT_CAP)
            .map_or(deadline, |t| t.min(deadline));
        match timeout_at(kk_by, caller_handshake(inner, conn, pair)).await {
            Ok(Ok((ours, theirs))) => {
                #[cfg(test)]
                inner.test_pause_before_promote().await;
                // `auth_ok` только после допуска реестром; иначе `auth_not_admitted`
                outcome = Some(
                    match promote(inner, conn.clone(), pair, true, ours, theirs) {
                        Promoted::Winner(c) | Promoted::Lost(c) => {
                            Counters::bump(&inner.counters.auth_ok);
                            Ok(c)
                        }
                        Promoted::NotAllowed => {
                            Counters::bump(&inner.counters.auth_not_admitted);
                            Err(TransportError::PeerNotAllowed)
                        }
                    },
                );
                break;
            }
            Ok(Err(fail)) => {
                match fail {
                    Fail::Failed => Counters::bump(&inner.counters.auth_failed),
                    Fail::Timeout => Counters::bump(&inner.counters.auth_timeout),
                    Fail::Denied => {}
                }
                refuse(conn);
                kk_err = Some(map_fail(fail));
            }
            Err(_) => {
                Counters::bump(&inner.counters.auth_timeout);
                refuse(conn);
                any_timeout = true;
            }
        }
    }

    // победитель найден (или конец): остальные попытки отменяются, установленные закрываются
    // отказом до KK, чтобы у собеседника было не больше одной аутентификации на звонок
    set.abort_all();
    while let Some(joined) = set.join_next().await {
        if let Ok(Ok(est)) = joined {
            refuse(&est.conn);
            Counters::bump(&inner.counters.race_losers);
        }
    }

    if let Some(r) = outcome {
        return r;
    }
    if all_silent {
        return Err(TransportError::NoResponse);
    }
    // отказ KK информативнее таймаута других адресов
    Err(kk_err.unwrap_or(if any_timeout {
        TransportError::TimedOut
    } else {
        last
    }))
}

fn map_fail(f: Fail) -> TransportError {
    match f {
        Fail::Timeout => TransportError::TimedOut,
        Fail::Failed | Fail::Denied => TransportError::AuthFailed,
    }
}

/// Законченное QUIC-рукопожатие одного адреса. Закрепление адреса живёт, пока идёт KK:
/// без него пакеты адреса не пройдут в гнездо.
struct Established {
    conn: quinn::Connection,
    _pin: Pin,
}

struct AttemptFail {
    err: TransportError,
    /// С адреса не пришло ни одного пакета (и ошибка сетевая, не локальная).
    silent: bool,
}

fn fail(err: TransportError, silent: bool) -> AttemptFail {
    AttemptFail { err, silent }
}

/// Один адрес гонки: до законченного QUIC-рукопожатия (стук, `knock_lead`, `connect_with`,
/// досылка стука в моменты `resend`, `3*resend` от старта этой попытки), общий срок `deadline`.
async fn dial_one(
    inner: Arc<Inner>,
    pair: PairId,
    addr: SocketAddr,
    start: Instant,
    deadline: Instant,
) -> Result<Established, AttemptFail> {
    if start >= deadline {
        return Err(fail(TransportError::TimedOut, true));
    }
    sleep_until(start).await;
    let started = Instant::now();
    let knock = &inner.knock;
    let required = knock.required;
    // закрепление: ответы адреса проходят, новый `Incoming` с него без своего стука нет
    let pin = knock.pin(addr);
    if required {
        let Some(first) = knock.make_knock(&pair, false) else {
            return Err(fail(TransportError::AuthFailed, false));
        };
        knock.send(addr, &first).await;
        sleep(inner.cfg.knock_lead).await;
    }
    let cc = client_config(&inner.client_quic, &inner.client_transport);
    let connecting = inner
        .endpoint
        .connect_with(cc, addr, SERVER_NAME)
        .map_err(|_| fail(TransportError::Io, false))?;
    tokio::pin!(connecting);
    // досылка стука в моменты `resend` и `3*resend` (третий по системному времени при поправке)
    let resend: Duration = inner.cfg.knock_resend_after;
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
    match outcome {
        Some(Ok(conn)) => Ok(Established { conn, _pin: pin }),
        Some(Err(_)) => {
            let silent = !pin.heard();
            if silent {
                Counters::bump(&inner.counters.connect_silent);
            }
            Err(fail(TransportError::Io, silent))
        }
        None => {
            Counters::bump(&inner.counters.auth_timeout);
            let silent = !pin.heard();
            if silent {
                Counters::bump(&inner.counters.connect_silent);
            }
            Err(fail(TransportError::TimedOut, silent))
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
///
/// С объединением: пока серия идёт, повторные вызовы лишь отмечают «ещё раз»; по окончании
/// серии, если отмечено, список живых пересчитывается и серия запускается ещё один раз.
pub(crate) fn reknock_live(inner: &Arc<Inner>) {
    if !inner.knock.required {
        return;
    }
    {
        let mut st = inner.reknock.lock().unwrap_or_else(PoisonError::into_inner);
        if st.0 {
            st.1 = true;
            return;
        }
        if inner.registry.live_remotes().is_empty() {
            return;
        }
        *st = (true, false);
    }
    let task_inner = inner.clone();
    inner.rt.spawn(async move {
        let inner = task_inner;
        loop {
            let targets = inner.registry.live_remotes();
            if !targets.is_empty() {
                knock_sequence(&inner, &targets).await;
                Counters::bump(&inner.counters.reknock_runs);
            }
            let mut st = inner.reknock.lock().unwrap_or_else(PoisonError::into_inner);
            if st.1 {
                st.1 = false;
            } else {
                st.0 = false;
                break;
            }
        }
    });
}

async fn knock_sequence(inner: &Arc<Inner>, targets: &[(PairId, SocketAddr)]) {
    let t0 = Instant::now();
    let resend = inner.cfg.knock_resend_after;
    for (n, at) in [Duration::ZERO, resend, resend.saturating_mul(3)]
        .into_iter()
        .enumerate()
    {
        sleep_until(t0 + at).await;
        let raw = n == 2 && inner.knock.offset() != 0;
        for (pair, addr) in targets {
            if let Some(k) = inner.knock.make_knock(pair, raw) {
                inner.knock.send(*addr, &k).await;
            }
        }
    }
}
