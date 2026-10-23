//! The explicit unlock (spec 17a, section 4, `request_unlock`). The only file that calls `Unlock`
//! and `Prompt`: get, set and delete never do (D5). Unlocking is a user action in the GUI.
//!
//! Success is decided by the `Locked` property of the default collection, never by the `Completed`
//! signal alone: a same-user process can forge a signal, it cannot change the property.

use std::future::poll_fn;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use zbus::message::Type as MsgType;
use zbus::{AsyncDrop, MatchRule, MessageStream, OwnedObjectPath, OwnedVariant};

use super::errors::{SsError, map_call_error};
use super::ops::{
    Conn, OpResult, check_signature, collection_locked, decode, dismiss, is_none_path, mapped,
    read_alias, rpc,
};
use super::proto::{
    BUS_NAME, IFACE_PROMPT, IFACE_SERVICE, SERVICE_PATH, SIG_COMPLETED, SIG_EMPTY, SIG_UNLOCK_OUT,
};

const M_UNLOCK: &str = "Unlock";
const M_PROMPT: &str = "Prompt";
const M_COMPLETED: &str = "Completed";
/// Queue of the signal stream: one signal is expected.
const SIGNAL_QUEUE: usize = 4;

/// Unlock the default collection. `wait` bounds only the wait for the user at the prompt.
pub(super) async fn request_unlock(c: &Conn, wait: Duration) -> OpResult<()> {
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
    let msg = rpc!(
        c.connection,
        SERVICE_PATH,
        IFACE_SERVICE,
        M_UNLOCK,
        &targets
    )?;
    let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = decode(&msg, SIG_UNLOCK_OUT)?;
    if unlocked.contains(&collection) {
        return Ok(());
    }
    if is_none_path(&prompt) {
        return still_locked(c, &collection).await;
    }
    prompt_and_wait(c, &collection, &prompt, wait).await
}

/// The decision: `Locked` is `false` -> success.
async fn still_locked(c: &Conn, collection: &OwnedObjectPath) -> OpResult<()> {
    if collection_locked(c, collection).await? {
        Err(SsError::LOCKED)
    } else {
        Ok(())
    }
}

async fn prompt_and_wait(
    c: &Conn,
    collection: &OwnedObjectPath,
    prompt: &OwnedObjectPath,
    wait: Duration,
) -> OpResult<()> {
    // Subscribe BEFORE the prompt starts, so that a fast `Completed` is not lost.
    let rule = MatchRule::builder()
        .msg_type(MsgType::Signal)
        .path(prompt.as_str())
        .interface(IFACE_PROMPT)
        .member(M_COMPLETED)
        .build()
        .map_err(|_| SsError::UNAVAILABLE)?;
    let mut stream =
        MessageStream::for_match_rule(rule, &c.connection, NonZeroUsize::new(SIGNAL_QUEUE))
            .await
            .map_err(|e| map_call_error(&e))?;

    let started = rpc!(c.connection, prompt.as_str(), IFACE_PROMPT, M_PROMPT, &"");
    let outcome = match started {
        Ok(reply) => match check_signature(&reply, SIG_EMPTY) {
            Ok(()) => tokio::time::timeout(wait, completed(&mut stream))
                .await
                .map_err(|_| Elapsed),
            Err(e) => {
                stream.async_drop().await;
                return Err(e);
            }
        },
        Err(e) => {
            stream.async_drop().await;
            return Err(e);
        }
    };
    // Deregister the match rule at once.
    stream.async_drop().await;

    match outcome {
        // The user did not answer in time: close the prompt, the collection stays locked.
        Err(Elapsed) => {
            dismiss(c, prompt).await;
            Err(SsError::LOCKED)
        }
        Ok(Err(e)) => Err(e),
        Ok(Ok(true)) => Err(SsError::LOCKED),
        // The signal says "not dismissed": believe only the property.
        Ok(Ok(false)) => still_locked(c, collection).await,
    }
}

/// Marker of the prompt wait running out of time.
struct Elapsed;

/// Wait for the `Completed` signal of this prompt: `Ok(dismissed)`. A signal with a body of the
/// wrong shape is ignored. The caller bounds the wait.
async fn completed(stream: &mut MessageStream) -> OpResult<bool> {
    loop {
        let next = poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await;
        match next {
            // The connection ended while we waited.
            None | Some(Err(_)) => return Err(SsError::UNAVAILABLE),
            Some(Ok(msg)) => {
                if check_signature(&msg, SIG_COMPLETED).is_err() {
                    continue;
                }
                if let Ok((dismissed, _result)) = msg.body().deserialize::<(bool, OwnedVariant)>() {
                    return Ok(dismissed);
                }
            }
        }
    }
}
