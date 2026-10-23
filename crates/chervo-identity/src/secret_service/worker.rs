//! Worker thread: one OS thread with its own current-thread Tokio runtime, one cached zbus
//! connection and session, jobs one at a time (spec 17a, D2, D8, D9).
//!
//! The zbus blocking helper is never used (it panics inside a Tokio task); only this thread
//! drives its own runtime. Callers talk to the worker over a bounded queue (`try_send`, never
//! blocks) and wait for the reply with a plain blocking timeout.

use std::sync::mpsc::SyncSender;
use std::time::Duration;

use tokio::sync::mpsc::{Receiver, Sender, channel};
use zbus::connection::Builder;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};
use zeroize::Zeroizing;

use super::Timeouts;
use super::errors::SsError;
use super::ops::{self, Conn, decode, mapped, rpc};
use super::proto::{
    ALGO_PLAIN, BUS_NAME, IFACE_SERVICE, M_OPEN_SESSION, QUEUE, SERVICE_PATH, SIG_OPEN_SESSION_OUT,
};
use super::unlock;
use crate::IdentityError;

/// Reply of a job.
pub(super) type Reply = Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;

/// What a job does. No `Debug` on purpose: it holds service, account and secret.
pub(super) enum JobKind {
    /// Connect and open a session, nothing else.
    Ping,
    Get {
        service: String,
        account: String,
    },
    Set {
        service: String,
        account: String,
        secret: Zeroizing<Vec<u8>>,
    },
    Delete {
        service: String,
        account: String,
    },
    /// Explicit unlock of the default collection; `wait` bounds the wait at the prompt.
    Unlock {
        wait: Duration,
    },
}

impl JobKind {
    /// Time limit of the whole job in the worker. An unlock may also wait for the user.
    fn limit(&self, timeouts: Timeouts) -> Duration {
        match self {
            Self::Unlock { wait } => wait.saturating_add(timeouts.op),
            _ => timeouts.op,
        }
    }
}

pub(super) struct Job {
    pub(super) kind: JobKind,
    pub(super) reply: SyncSender<Reply>,
}

/// Where connections come from.
pub(super) enum Connector {
    /// The session bus of the user.
    Session,
    /// Peer-to-peer streams of the fake service (tests only). `None`: no stream available.
    #[cfg(test)]
    P2p(Box<dyn FnMut() -> Option<std::os::unix::net::UnixStream> + Send>),
}

impl Connector {
    fn builder(&mut self) -> Option<Builder<'static>> {
        match self {
            Self::Session => Some(Builder::session()),
            #[cfg(test)]
            Self::P2p(next) => next().map(|s| Builder::unix_stream(s).p2p()),
        }
    }
}

/// Start the worker thread. The queue is returned; dropping it stops the worker.
pub(super) fn spawn(
    connector: Connector,
    timeouts: Timeouts,
) -> Result<Sender<Job>, IdentityError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| IdentityError::StorageUnavailable)?;
    let (tx, rx) = channel::<Job>(QUEUE);
    std::thread::Builder::new()
        .name("chervo-secret-service".into())
        .spawn(move || rt.block_on(run(rx, connector, timeouts)))
        .map_err(|_| IdentityError::StorageUnavailable)?;
    Ok(tx)
}

async fn run(mut rx: Receiver<Job>, mut connector: Connector, timeouts: Timeouts) {
    let mut conn: Option<Conn> = None;
    while let Some(job) = rx.recv().await {
        let Job { kind, reply } = job;
        let outcome = tokio::time::timeout(
            kind.limit(timeouts),
            execute(&kind, &mut connector, &mut conn, timeouts.call),
        )
        .await;
        let result = match outcome {
            Ok(r) => r,
            Err(_) => {
                // The whole job ran out of time: the connection state is unknown, drop it.
                conn = None;
                Err(IdentityError::StorageUnavailable)
            }
        };
        if matches!(result, Err(IdentityError::StorageUnavailable)) {
            conn = None;
        }
        // The caller may have given up already: nothing to do then.
        let _ = reply.send(result);
    }
}

/// One job, with one restart after a connection-level error (D9).
async fn execute(
    kind: &JobKind,
    connector: &mut Connector,
    slot: &mut Option<Conn>,
    call_timeout: Duration,
) -> Reply {
    for _attempt in 0..2 {
        if slot.is_none() {
            *slot = Some(connect(connector, call_timeout).await?);
        }
        let Some(conn) = slot.as_ref() else {
            return Err(IdentityError::StorageUnavailable);
        };
        match run_job(kind, conn).await {
            Ok(r) => return Ok(r),
            Err(SsError::Reconnect) => {
                *slot = None;
            }
            Err(e) => return Err(finish(e)),
        }
    }
    Err(IdentityError::StorageUnavailable)
}

fn finish(e: SsError) -> IdentityError {
    match e {
        SsError::Id(id) => id,
        SsError::Reconnect | SsError::NoSuchObject => IdentityError::StorageUnavailable,
    }
}

async fn run_job(kind: &JobKind, conn: &Conn) -> Result<Option<Zeroizing<Vec<u8>>>, SsError> {
    match kind {
        JobKind::Ping => Ok(None),
        JobKind::Get { service, account } => ops::get(conn, service, account).await,
        JobKind::Set {
            service,
            account,
            secret,
        } => ops::set(conn, service, account, secret.as_slice())
            .await
            .map(|()| None),
        JobKind::Delete { service, account } => {
            ops::delete(conn, service, account).await.map(|()| None)
        }
        JobKind::Unlock { wait } => unlock::request_unlock(conn, *wait).await.map(|()| None),
    }
}

/// Connect and open a `plain` session. Every failure is `StorageUnavailable`.
async fn connect(connector: &mut Connector, call_timeout: Duration) -> Result<Conn, IdentityError> {
    let unavailable = IdentityError::StorageUnavailable;
    let builder = connector.builder().ok_or(unavailable)?;
    let connection = builder
        .method_timeout(call_timeout)
        .build()
        .await
        .map_err(|_| unavailable)?;
    let input = (ALGO_PLAIN, Variant::from(""));
    let msg = rpc!(
        connection,
        SERVICE_PATH,
        IFACE_SERVICE,
        M_OPEN_SESSION,
        &input
    )
    .map_err(|_| unavailable)?;
    let (_output, session): (OwnedVariant, OwnedObjectPath) =
        decode(&msg, SIG_OPEN_SESSION_OUT).map_err(|_| unavailable)?;
    Ok(Conn {
        connection,
        session,
    })
}
