//! Own minimal Secret Service client on zbus 6 (spec 17a). Linux only.
//!
//! Read, write and delete never show a password prompt and never wait for one (D5). Every wait is
//! bounded: a D-Bus call by `Timeouts::call`, a whole job by `Timeouts::op`, the caller by
//! `Timeouts::caller`. Nothing is logged and nothing is written to disk.

mod errors;
mod ops;
mod proto;
mod worker;

#[cfg(test)]
mod tests;

use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use zeroize::Zeroizing;

use self::worker::{Connector, Job, JobKind, Reply};
use crate::IdentityError;

/// Time limits (spec D8).
#[derive(Clone, Copy)]
pub(crate) struct Timeouts {
    /// One D-Bus call (connection `method_timeout`).
    pub(crate) call: Duration,
    /// A whole job in the worker, connect and retry included.
    pub(crate) op: Duration,
    /// How long a caller waits for the worker.
    pub(crate) caller: Duration,
}

impl Timeouts {
    /// Product values: 5 s, 10 s, 12 s.
    pub(crate) const PRODUCT: Self = Self {
        call: Duration::from_secs(5),
        op: Duration::from_secs(10),
        caller: Duration::from_secs(12),
    };
}

/// Handle to the worker thread. Dropping it drops the queue; the thread ends on its own and is
/// never joined.
pub(crate) struct SsClient {
    queue: Sender<Job>,
    timeouts: Timeouts,
}

impl SsClient {
    /// Client for the session bus. Connects and opens a session before it returns.
    pub(crate) fn connect_session(timeouts: Timeouts) -> Result<Self, IdentityError> {
        Self::start(Connector::Session, timeouts)
    }

    /// Client over peer-to-peer streams, one per (re)connection (tests only).
    #[cfg(test)]
    pub(crate) fn connect_p2p(
        next: impl FnMut() -> Option<std::os::unix::net::UnixStream> + Send + 'static,
        timeouts: Timeouts,
    ) -> Result<Self, IdentityError> {
        Self::start(Connector::P2p(Box::new(next)), timeouts)
    }

    fn start(connector: Connector, timeouts: Timeouts) -> Result<Self, IdentityError> {
        let queue = worker::spawn(connector, timeouts)?;
        let client = Self { queue, timeouts };
        client.submit(JobKind::Ping, timeouts.caller)?;
        Ok(client)
    }

    /// Queue a job (never blocks) and wait for the answer with a plain blocking timeout, which
    /// is safe on any thread, Tokio workers included.
    fn submit(&self, kind: JobKind, wait: Duration) -> Reply {
        let unavailable = IdentityError::StorageUnavailable;
        let (reply, answer) = sync_channel::<Reply>(1);
        self.queue
            .try_send(Job { kind, reply })
            .map_err(|_| unavailable)?;
        match answer.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Err(unavailable),
        }
    }

    /// `Ok(None)` only if the entry certainly does not exist (D6).
    pub(crate) fn get(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.submit(
            JobKind::Get {
                service: service.to_owned(),
                account: account.to_owned(),
            },
            self.timeouts.caller,
        )
    }

    pub(crate) fn set(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), IdentityError> {
        self.submit(
            JobKind::Set {
                service: service.to_owned(),
                account: account.to_owned(),
                secret: Zeroizing::new(secret.to_vec()),
            },
            self.timeouts.caller,
        )
        .map(|_| ())
    }

    /// Missing entry: `Ok(())`.
    pub(crate) fn delete(&self, service: &str, account: &str) -> Result<(), IdentityError> {
        self.submit(
            JobKind::Delete {
                service: service.to_owned(),
                account: account.to_owned(),
            },
            self.timeouts.caller,
        )
        .map(|_| ())
    }
}
