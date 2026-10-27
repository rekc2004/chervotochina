//! The explicit unlock (spec 17a, section 4, `request_unlock`). The only file that calls `Unlock`
//! and `Prompt`: get, set and delete never do (D5). Unlocking is a user action in the GUI.
//!
//! Success is decided by the `Locked` property of the default collection, never by the `Completed`
//! signal alone: a same-user process can forge a signal, it cannot change the property.
//!
//! A `Completed` signal is also accepted only from the sender of the service's own reply (the
//! unique bus name in the header of the `Unlock` reply) and only with the path of our prompt.
//! zbus does not filter a well-known `sender=` of a match rule locally, and the bus delivers a
//! unicast signal addressed to our unique name whatever the rules say, so the check is ours. On a
//! peer-to-peer connection (no bus) the reply has no sender, and only signals without a sender are
//! accepted: there is no bus to name the peer, the single peer is the service.
//!
//! Signal floods: zbus 6.0.0 gives a `MessageStream` a bounded queue and no overflow mode; the
//! socket reader waits for room in it, and so also stops delivering method replies. Therefore the
//! stream is drained while the `Prompt` call is in flight and while we wait for `Completed`, and
//! it is dropped (which releases a waiting reader) before anything else is called: the `Locked`
//! check and `Dismiss` both run after `wait_completed` has returned and the stream is gone.

use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_core::Stream;
use zbus::message::Type as MsgType;
use zbus::{MatchRule, Message, MessageStream, OwnedObjectPath, OwnedVariant};

use super::errors::{SsError, map_call_error};
use super::ops::{
    Conn, OpResult, before, check_signature, collection_locked, decode, dismiss, is_none_path,
    mapped, read_alias, rpc,
};
use super::proto::{
    BUS_NAME, IFACE_PROMPT, IFACE_SERVICE, SERVICE_PATH, SIG_COMPLETED, SIG_EMPTY, SIG_UNLOCK_OUT,
};

const M_UNLOCK: &str = "Unlock";
const M_PROMPT: &str = "Prompt";
const M_COMPLETED: &str = "Completed";
/// Queue of the signal stream: one signal is expected.
const SIGNAL_QUEUE: usize = 4;

/// Unlock the default collection. `wait` bounds only the wait for the user at the prompt;
/// `deadline` is the moment the caller stops waiting: no `Unlock` and no `Prompt` is sent after
/// it, and the wait at the prompt ends before it.
pub(super) async fn request_unlock(c: &Conn, wait: Duration, deadline: Instant) -> OpResult<()> {
    let collection = read_alias(c).await?;
    if is_none_path(&collection) {
        // No default collection: we never create one (D7). No Unlock, no Prompt.
        return Err(SsError::UNAVAILABLE);
    }
    if !collection_locked(c, &collection).await? {
        return Ok(());
    }
    // `ao` with the object path from ReadAlias, never the string "default".
    // A Vec (a fixed-size array is sent as separate arguments, so its signature would be `o`).
    let targets: Vec<&OwnedObjectPath> = vec![&collection];
    before(deadline)?;
    let msg = rpc!(
        c.connection,
        SERVICE_PATH,
        IFACE_SERVICE,
        M_UNLOCK,
        &targets
    )?;
    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = decode(&msg, SIG_UNLOCK_OUT)?;
    let origin = sender_of(&msg);
    if unlocked.contains(&collection) {
        return Ok(());
    }
    if is_none_path(&prompt) {
        return still_locked(c, &collection).await;
    }
    prompt_and_wait(c, &collection, &prompt, origin.as_deref(), wait, deadline).await
}

/// The decision: `Locked` is `false` -> success.
async fn still_locked(c: &Conn, collection: &OwnedObjectPath) -> OpResult<()> {
    if collection_locked(c, collection).await? {
        Err(SsError::LOCKED)
    } else {
        Ok(())
    }
}

/// Run the prompt. On every outcome but success the prompt is dismissed, best effort (the dialog
/// must not stay open when we have stopped waiting for it, or after any error).
async fn prompt_and_wait(
    c: &Conn,
    collection: &OwnedObjectPath,
    prompt: &OwnedObjectPath,
    origin: Option<&str>,
    wait: Duration,
    deadline: Instant,
) -> OpResult<()> {
    // The signal stream lives inside `wait_completed` and is gone when `prompt_flow` returns.
    let result = prompt_flow(c, collection, prompt, origin, wait, deadline).await;
    if result.is_err() {
        dismiss(c, prompt).await;
    }
    result
}

/// The rule of the `Completed` signal of one prompt. The sender is the well-known name of the
/// service: the bus delivers only what its owner sent. zbus cannot check a well-known sender
/// itself (messages carry unique names), so on a peer-to-peer connection without a bus the rule
/// matches by path, interface and member only.
pub(super) fn completed_rule(prompt: &OwnedObjectPath) -> OpResult<MatchRule<'_>> {
    MatchRule::builder()
        .msg_type(MsgType::Signal)
        .sender(BUS_NAME)
        .path(prompt.as_str())
        .interface(IFACE_PROMPT)
        .member(M_COMPLETED)
        .build()
        .map_err(|_| SsError::UNAVAILABLE)
}

async fn prompt_flow(
    c: &Conn,
    collection: &OwnedObjectPath,
    prompt: &OwnedObjectPath,
    origin: Option<&str>,
    wait: Duration,
    deadline: Instant,
) -> OpResult<()> {
    // The signal stream is created and dropped inside: nothing below runs with it alive.
    let dismissed = wait_completed(c, prompt, origin, wait, deadline).await?;
    if dismissed {
        return Err(SsError::LOCKED);
    }
    // The signal says "not dismissed": believe only the property.
    still_locked(c, collection).await
}

/// Start the prompt and wait for its `Completed`: `Ok(dismissed)`. Owns the signal stream and
/// drops it on return, so that queued signals cannot block the socket reader of later calls.
async fn wait_completed(
    c: &Conn,
    prompt: &OwnedObjectPath,
    origin: Option<&str>,
    wait: Duration,
    deadline: Instant,
) -> OpResult<bool> {
    // Subscribe BEFORE the prompt starts, so that a fast `Completed` is not lost.
    let rule = completed_rule(prompt)?;
    let mut stream =
        MessageStream::for_match_rule(rule, &c.connection, NonZeroUsize::new(SIGNAL_QUEUE))
            .await
            .map_err(|e| map_call_error(&e))?;

    before(deadline)?;
    // While the call is in flight the stream is drained, so that a flood cannot block the reader.
    let mut first: Option<bool> = None;
    let mut open = true;
    let mut started =
        pin!(async { rpc!(c.connection, prompt.as_str(), IFACE_PROMPT, M_PROMPT, &"") });
    let reply = poll_fn(|cx| {
        if open {
            open = drain(&mut stream, cx, &mut first, origin, prompt);
        }
        started.as_mut().poll(cx)
    })
    .await?;
    check_signature(&reply, SIG_EMPTY)?;

    match first {
        Some(d) => Ok(d),
        None if !open => Err(SsError::UNAVAILABLE),
        None => {
            // The wait never reaches past the moment the caller gives up.
            let wait = wait.min(deadline.saturating_duration_since(Instant::now()));
            // The user did not answer in time: the collection stays locked.
            tokio::time::timeout(wait, completed(&mut stream, origin, prompt))
                .await
                .map_err(|_| SsError::LOCKED)?
        }
    }
}

/// Unique bus name of the sender of a message, if the message has one.
fn sender_of(msg: &Message) -> Option<String> {
    msg.header().sender().map(|s| s.as_str().to_owned())
}

/// A signal comes from the service if its sender is the one of the service's reply (both absent on
/// a peer-to-peer connection) and its path is the path of our prompt.
pub(super) fn from_service(
    sender: Option<&str>,
    path: Option<&str>,
    origin: Option<&str>,
    prompt: &str,
) -> bool {
    sender == origin && path == Some(prompt)
}

/// `Some(dismissed)` for a well-formed `Completed` body from the service for this prompt; a signal
/// of any other origin, path or body shape is ignored.
fn completed_flag(msg: &Message, origin: Option<&str>, prompt: &OwnedObjectPath) -> Option<bool> {
    let header = msg.header();
    let sender = header.sender().map(|s| s.as_str());
    let path = header.path().map(|p| p.as_str());
    if !from_service(sender, path, origin, prompt.as_str()) {
        return None;
    }
    check_signature(msg, SIG_COMPLETED).ok()?;
    let (dismissed, _result) = msg.body().deserialize::<(bool, OwnedVariant)>().ok()?;
    Some(dismissed)
}

/// Take what is queued on the stream without waiting; the first genuine, well-formed `Completed`
/// is kept, everything else is dropped. `false`: the stream has ended.
fn drain(
    stream: &mut MessageStream,
    cx: &mut Context<'_>,
    first: &mut Option<bool>,
    origin: Option<&str>,
    prompt: &OwnedObjectPath,
) -> bool {
    loop {
        match Pin::new(&mut *stream).poll_next(cx) {
            Poll::Pending => return true,
            Poll::Ready(Some(Ok(msg))) => {
                if first.is_none() {
                    *first = completed_flag(&msg, origin, prompt);
                }
            }
            Poll::Ready(None | Some(Err(_))) => return false,
        }
    }
}

/// Wait for the `Completed` signal of this prompt: `Ok(dismissed)`. The caller bounds the wait.
async fn completed(
    stream: &mut MessageStream,
    origin: Option<&str>,
    prompt: &OwnedObjectPath,
) -> OpResult<bool> {
    loop {
        let next = poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await;
        match next {
            // The connection ended while we waited.
            None | Some(Err(_)) => return Err(SsError::UNAVAILABLE),
            Some(Ok(msg)) => {
                if let Some(dismissed) = completed_flag(&msg, origin, prompt) {
                    return Ok(dismissed);
                }
            }
        }
    }
}
