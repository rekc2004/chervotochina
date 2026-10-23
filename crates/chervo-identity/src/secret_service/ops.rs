//! Calls of the Secret Service subset: get, set, delete (spec 17a, sections 3-4).
//!
//! No call here shows a prompt: a prompt object returned by the service is dismissed and the
//! operation reports `StorageLocked` (D5). Replies are decoded only into the exact expected types
//! after their body signature was compared with the one of section 3.

use std::collections::BTreeMap;
use std::time::Instant;

use zbus::wire::DynamicDeserialize;
use zbus::{Connection, Message, OwnedObjectPath, OwnedVariant, Signature, Variant};
use zeroize::Zeroizing;

use super::errors::{SsError, map_call_error};
use super::proto::{
    ALIAS_DEFAULT, ATTR_SERVICE, ATTR_USERNAME, BUS_NAME, CONTENT_TYPE, IFACE_COLLECTION,
    IFACE_ITEM, IFACE_PROMPT, IFACE_PROPERTIES, IFACE_SERVICE, LABEL_PREFIX, M_CREATE_ITEM,
    M_DELETE, M_DISMISS, M_GET_SECRET, M_PROP_GET, M_READ_ALIAS, M_SEARCH_ITEMS, M_SET_SECRET,
    MAX_SECRET_LEN, NO_OBJECT, PROP_ITEM_ATTRIBUTES, PROP_ITEM_LABEL, PROP_LOCKED, SERVICE_PATH,
    SIG_CREATE_ITEM_OUT, SIG_EMPTY, SIG_OBJECT, SIG_SEARCH_OUT, SIG_SECRET, SIG_VARIANT,
};

/// Connection with an open `plain` session.
pub(super) struct Conn {
    pub(super) connection: Connection,
    pub(super) session: OwnedObjectPath,
}

pub(super) type OpResult<T> = Result<T, SsError>;

/// Map the result of a call: errors are mapped, zbus error text is dropped here.
pub(super) fn mapped(r: zbus::Result<Message>) -> OpResult<Message> {
    r.map_err(|e| map_call_error(&e))
}

/// One method call to the Secret Service. A macro because the body bound would need `serde` by
/// name, and the crate has no direct dependency on it.
macro_rules! rpc {
    ($conn:expr, $path:expr, $iface:expr, $member:expr, $body:expr) => {
        mapped(
            $conn
                .call_method(Some(BUS_NAME), $path, Some($iface), $member, $body)
                .await,
        )
    };
}
pub(super) use rpc;

/// Compare the body signature with the expected one (parsed form of the wire string).
///
/// zbus 6.0.0 keeps the parsed form only, in which the body `oayays` and the single struct
/// `(oayays)` are the same value; the byte encodings of the two are identical. Nested forms such
/// as `((oayays))` are different values and are rejected here. The exact wire string of what we
/// send is checked in the unit tests on the fake service.
pub(super) fn check_signature(msg: &Message, expected: &str) -> OpResult<()> {
    let want = Signature::try_from(expected).map_err(|_| SsError::UNAVAILABLE)?;
    if *msg.body().signature() == want {
        Ok(())
    } else {
        Err(SsError::UNAVAILABLE)
    }
}

/// Decode the reply body into `T` after the signature check. Any failure: `StorageUnavailable`.
pub(super) fn decode<T>(msg: &Message, expected: &str) -> OpResult<T>
where
    T: for<'s> DynamicDeserialize<'s>,
{
    check_signature(msg, expected)?;
    msg.body()
        .deserialize::<T>()
        .map_err(|_| SsError::UNAVAILABLE)
}

/// A call that changes something (or shows a prompt) is sent only while the caller still waits:
/// a result that was reported as a failure must not be applied later.
pub(super) fn before(deadline: Instant) -> OpResult<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(SsError::UNAVAILABLE)
    }
}

pub(super) fn is_none_path(p: &OwnedObjectPath) -> bool {
    p.as_str() == NO_OBJECT
}

/// `Service.SearchItems` with the attributes of the compatibility contract (D4).
async fn search(
    c: &Conn,
    service: &str,
    account: &str,
) -> OpResult<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
    let mut attrs: BTreeMap<&str, &str> = BTreeMap::new();
    attrs.insert(ATTR_SERVICE, service);
    attrs.insert(ATTR_USERNAME, account);
    let msg = rpc!(
        c.connection,
        SERVICE_PATH,
        IFACE_SERVICE,
        M_SEARCH_ITEMS,
        &attrs
    )?;
    decode(&msg, SIG_SEARCH_OUT)
}

/// `Service.ReadAlias("default")`: path of the default collection, `/` if there is none.
pub(super) async fn read_alias(c: &Conn) -> OpResult<OwnedObjectPath> {
    let msg = rpc!(
        c.connection,
        SERVICE_PATH,
        IFACE_SERVICE,
        M_READ_ALIAS,
        &ALIAS_DEFAULT
    )?;
    decode(&msg, SIG_OBJECT)
}

/// `Locked` property of a collection.
pub(super) async fn collection_locked(c: &Conn, collection: &OwnedObjectPath) -> OpResult<bool> {
    let msg = rpc!(
        c.connection,
        collection.as_str(),
        IFACE_PROPERTIES,
        M_PROP_GET,
        &(IFACE_COLLECTION, PROP_LOCKED)
    )?;
    let v: OwnedVariant = decode(&msg, SIG_VARIANT)?;
    match &*v {
        Variant::Bool(b) => Ok(*b),
        _ => Err(SsError::UNAVAILABLE),
    }
}

/// `Prompt.Dismiss`, best effort: the result is ignored.
pub(super) async fn dismiss(c: &Conn, prompt: &OwnedObjectPath) {
    let _ = rpc!(c.connection, prompt.as_str(), IFACE_PROMPT, M_DISMISS, &());
}

/// The situation after a search.
enum Found<'a> {
    None,
    Unlocked(&'a OwnedObjectPath),
    Locked,
}

fn classify<'a>(
    unlocked: &'a [OwnedObjectPath],
    locked: &[OwnedObjectPath],
) -> OpResult<Found<'a>> {
    let n = unlocked.len().saturating_add(locked.len());
    if n > 1 {
        return Err(SsError::INCONSISTENT);
    }
    if n == 0 {
        return Ok(Found::None);
    }
    match unlocked.first() {
        Some(item) if locked.is_empty() => Ok(Found::Unlocked(item)),
        _ => Ok(Found::Locked),
    }
}

/// `NoSuchObject` on an item that the search just returned: it raced with a delete.
fn vanished(e: SsError) -> SsError {
    if e == SsError::NoSuchObject {
        SsError::INCONSISTENT
    } else {
        e
    }
}

/// The Secret struct `(session, parameters, value, content_type)`.
type SecretStruct<'a> = (&'a OwnedObjectPath, &'a [u8], &'a [u8], &'a str);

fn secret_struct<'a>(session: &'a OwnedObjectPath, value: &'a [u8]) -> SecretStruct<'a> {
    let no_parameters: &[u8] = &[];
    (session, no_parameters, value, CONTENT_TYPE)
}

pub(super) async fn get(
    c: &Conn,
    service: &str,
    account: &str,
) -> OpResult<Option<Zeroizing<Vec<u8>>>> {
    let (unlocked, locked) = search(c, service, account).await?;
    let item = match classify(&unlocked, &locked)? {
        Found::None => {
            // Absence is certain only if the default collection is known to be unlocked (D6).
            let alias = read_alias(c).await?;
            if is_none_path(&alias) {
                return Ok(None);
            }
            return if collection_locked(c, &alias).await? {
                Err(SsError::LOCKED)
            } else {
                Ok(None)
            };
        }
        Found::Locked => return Err(SsError::LOCKED),
        Found::Unlocked(item) => item,
    };
    let msg = vanished_on_err(rpc!(
        c.connection,
        item.as_str(),
        IFACE_ITEM,
        M_GET_SECRET,
        &c.session
    ))?;
    check_signature(&msg, SIG_SECRET)?;
    // `value` and `parameters` borrow from the message: the secret is copied exactly once, into
    // a buffer that is wiped on drop, and only after the length check.
    let body = msg.body();
    let (_session, parameters, value, _content_type): (OwnedObjectPath, &[u8], &[u8], &str) =
        body.deserialize().map_err(|_| SsError::UNAVAILABLE)?;
    if !parameters.is_empty() || value.len() > MAX_SECRET_LEN {
        return Err(SsError::INCONSISTENT);
    }
    Ok(Some(Zeroizing::new(value.to_vec())))
}

fn vanished_on_err(r: OpResult<Message>) -> OpResult<Message> {
    r.map_err(vanished)
}

pub(super) async fn set(
    c: &Conn,
    service: &str,
    account: &str,
    secret: &[u8],
    deadline: Instant,
) -> OpResult<()> {
    let (unlocked, locked) = search(c, service, account).await?;
    match classify(&unlocked, &locked)? {
        Found::Locked => Err(SsError::LOCKED),
        Found::Unlocked(item) => {
            // SetSecret takes ONE argument, the Secret struct: a one-element tuple around it.
            let body = (secret_struct(&c.session, secret),);
            before(deadline)?;
            let msg = vanished_on_err(rpc!(
                c.connection,
                item.as_str(),
                IFACE_ITEM,
                M_SET_SECRET,
                &body
            ))?;
            check_signature(&msg, SIG_EMPTY)
        }
        Found::None => create(c, service, account, secret, deadline).await,
    }
}

async fn create(
    c: &Conn,
    service: &str,
    account: &str,
    secret: &[u8],
    deadline: Instant,
) -> OpResult<()> {
    let collection = read_alias(c).await?;
    if is_none_path(&collection) {
        // No default collection: we never create one and never fall back (D7).
        return Err(SsError::UNAVAILABLE);
    }
    if collection_locked(c, &collection).await? {
        return Err(SsError::LOCKED);
    }
    let label = format!("{LABEL_PREFIX}{account}@{service}");
    let mut attrs: BTreeMap<&str, &str> = BTreeMap::new();
    attrs.insert(ATTR_SERVICE, service);
    attrs.insert(ATTR_USERNAME, account);
    let mut properties: BTreeMap<&str, Variant<'_>> = BTreeMap::new();
    properties.insert(PROP_ITEM_LABEL, Variant::from(label.as_str()));
    properties.insert(PROP_ITEM_ATTRIBUTES, Variant::from(attrs));
    // Three arguments: a{sv}, (oayays), b.
    let body = (properties, secret_struct(&c.session, secret), true);
    before(deadline)?;
    let msg = rpc!(
        c.connection,
        collection.as_str(),
        IFACE_COLLECTION,
        M_CREATE_ITEM,
        &body
    )?;
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = decode(&msg, SIG_CREATE_ITEM_OUT)?;
    if !is_none_path(&prompt) {
        dismiss(c, &prompt).await;
        return Err(SsError::LOCKED);
    }
    if is_none_path(&item) {
        return Err(SsError::UNAVAILABLE);
    }
    Ok(())
}

pub(super) async fn delete(
    c: &Conn,
    service: &str,
    account: &str,
    deadline: Instant,
) -> OpResult<()> {
    let (unlocked, locked) = search(c, service, account).await?;
    let item = match classify(&unlocked, &locked)? {
        Found::None => return Ok(()),
        Found::Locked => return Err(SsError::LOCKED),
        Found::Unlocked(item) => item,
    };
    before(deadline)?;
    let msg = match rpc!(c.connection, item.as_str(), IFACE_ITEM, M_DELETE, &()) {
        Ok(m) => m,
        Err(SsError::NoSuchObject) => return Ok(()),
        Err(e) => return Err(e),
    };
    let prompt: OwnedObjectPath = decode(&msg, SIG_OBJECT)?;
    if is_none_path(&prompt) {
        Ok(())
    } else {
        dismiss(c, &prompt).await;
        Err(SsError::LOCKED)
    }
}
