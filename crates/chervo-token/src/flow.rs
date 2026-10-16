//! Обмен M1, M2 и решениями по первому двунаправленному потоку соединения гостевой пары
//! (после Noise KK). Generic по `chervo_transport::Connection`, без tokio и без таймеров:
//! срок сессии у вызывающего. Читается ровно фиксированное число байт, буферы только
//! фиксированной длины (память не выделяется по длине от собеседника).

use chervo_transport::{Connection, RecvStream, SendStream};

use crate::{
    DECISION_LEN, FlowError, InviteError, InviteeKeys, InviteeSession, M1_LEN, M2_LEN,
    PendingInvite, Sas, decode_decision, encode_decision,
};

/// Поток приглашения: две половины первого двунаправленного потока.
pub struct InviteChannel<C: Connection> {
    tx: C::Tx,
    rx: C::Rx,
}

impl<C: Connection> std::fmt::Debug for InviteChannel<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteChannel(..)")
    }
}

/// Ровно `N` байт; конец потока раньше (`Ok(None)` или `Ok(Some(0))`) даёт `Truncated`.
async fn read_exact_n<R: RecvStream, const N: usize>(rx: &mut R) -> Result<[u8; N], FlowError> {
    let mut buf = [0u8; N];
    let mut filled = 0usize;
    while filled < N {
        let dst = buf.get_mut(filled..).ok_or(FlowError::Truncated)?;
        match rx.read(dst).await? {
            None | Some(0) => return Err(FlowError::Truncated),
            Some(n) => filled = filled.saturating_add(n).min(N),
        }
    }
    Ok(buf)
}

/// A: `accept_bi`, прочитать ровно `M1_LEN`, `pending.on_m1`, записать M2.
/// Перед вызовом на соединение гостевой пары нужен `pending.begin_session`.
pub async fn inviter_exchange<C: Connection>(
    conn: &C,
    pending: &mut PendingInvite,
) -> Result<(InviteChannel<C>, Sas, InviteeKeys), FlowError> {
    let (mut tx, mut rx) = conn.accept_bi().await?;
    let m1: [u8; M1_LEN] = read_exact_n(&mut rx).await?;
    let (m2, sas, keys) = pending.on_m1(&m1)?;
    tx.write_all(&m2).await?;
    Ok((InviteChannel { tx, rx }, sas, keys))
}

/// B: `open_bi`, записать `m1`, прочитать ровно `M2_LEN`, `session.on_m2`.
pub async fn invitee_exchange<C: Connection>(
    conn: &C,
    session: InviteeSession,
    m1: &[u8; M1_LEN],
) -> Result<(InviteChannel<C>, Sas), FlowError> {
    let (mut tx, mut rx) = conn.open_bi().await?;
    tx.write_all(m1).await?;
    let m2: [u8; M2_LEN] = read_exact_n(&mut rx).await?;
    let sas = session.on_m2(&m2)?;
    Ok((InviteChannel { tx, rx }, sas))
}

/// Записать своё решение, `finish()`, прочитать ровно `DECISION_LEN`, вернуть решение
/// собеседника. Дружбу создаёт сторона, только если подтвердила сама и подтвердил собеседник.
pub async fn exchange_decision<C: Connection>(
    ch: &mut InviteChannel<C>,
    confirm: bool,
) -> Result<bool, FlowError> {
    ch.tx.write_all(&encode_decision(confirm)).await?;
    ch.tx.finish()?;
    let theirs: [u8; DECISION_LEN] = read_exact_n(&mut ch.rx).await?;
    decode_decision(&theirs).map_err(|e: InviteError| FlowError::Invite(e))
}
