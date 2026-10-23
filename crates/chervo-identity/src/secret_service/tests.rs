//! Unit tests on a fake Secret Service (spec 17a, section 8): a raw message loop on the server end
//! of a `UnixStream::pair()` with in-memory items, fault knobs, call records and a check of the
//! exact body signature (wire string from the message header) of every incoming call.
//!
//! The zbus parsed `Signature` cannot tell `oayays` from `(oayays)`, so the fake reads the wire
//! string from the raw header bytes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::poll_fn;
use std::os::unix::net::UnixStream;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures_core::Stream;
use tokio::sync::{mpsc, watch};
use zbus::connection::Builder;
use zbus::message::Type as MsgType;
use zbus::{Guid, Message, MessageStream, ObjectPath, OwnedObjectPath, OwnedVariant, Variant};
use zeroize::Zeroizing;

use super::proto::{
    CONTENT_TYPE, MAX_SECRET_LEN, SIG_CREATE_ITEM_IN, SIG_EMPTY, SIG_OBJECT, SIG_OPEN_SESSION_IN,
    SIG_PROP_GET_IN, SIG_READ_ALIAS_IN, SIG_SEARCH_IN, SIG_SECRET,
};
use super::{SsClient, Timeouts};
use crate::{
    EPOCH_ACCOUNT, EpochStore, IdentityError, LIST_KEY_ACCOUNT, ListKeyStore, OsKeyStore, PairId,
    SecretStore,
};

const SVC: &str = "chervotochina-test";
const ACC: &str = "pair-v1-0123456789abcdef0123456789abcdef";
const SESSION: &str = "/org/freedesktop/secrets/session/s1";
/// Deliberately not `/org/freedesktop/secrets/aliases/default`.
const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/p1";
const NO_SUCH: &str = "org.freedesktop.Secret.Error.NoSuchObject";
const IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
const NO_SESSION: &str = "org.freedesktop.Secret.Error.NoSession";
const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const NOT_SUPPORTED: &str = "org.freedesktop.DBus.Error.NotSupported";

fn timeouts() -> Timeouts {
    Timeouts {
        call: Duration::from_millis(200),
        op: Duration::from_millis(500),
        caller: Duration::from_millis(800),
    }
}

// ---------- fake service ----------

#[derive(Clone)]
enum Action {
    /// Reply with this D-Bus error name.
    Error(&'static str),
    /// Never reply.
    Silent,
    /// Reply with a body of the wrong type.
    BadReply,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GetMode {
    Normal,
    /// Reply encoded as `((oayays))`.
    DoubleWrapped,
    Oversized,
    NonEmptyParameters,
}

#[derive(Clone)]
struct Item {
    path: String,
    attrs: BTreeMap<String, String>,
    secret: Vec<u8>,
    locked: bool,
}

struct Call {
    member: String,
    wire: Option<String>,
}

#[derive(Clone)]
struct CreateRecord {
    collection: String,
    property_keys: Vec<String>,
    attrs: BTreeMap<String, String>,
    label: String,
    content_type: String,
    parameters: Vec<u8>,
    replace: bool,
}

struct State {
    items: Vec<Item>,
    next_id: u32,
    has_default: bool,
    collection_locked: bool,
    once: HashMap<String, VecDeque<Action>>,
    always: HashMap<String, Action>,
    get_mode: GetMode,
    create_prompt: bool,
    delete_prompt: bool,
    calls: Vec<Call>,
    mismatches: Vec<String>,
    creates: Vec<CreateRecord>,
    searches: Vec<BTreeMap<String, String>>,
}

impl State {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            next_id: 1,
            has_default: true,
            collection_locked: false,
            once: HashMap::new(),
            always: HashMap::new(),
            get_mode: GetMode::Normal,
            create_prompt: false,
            delete_prompt: false,
            calls: Vec::new(),
            mismatches: Vec::new(),
            creates: Vec::new(),
            searches: Vec::new(),
        }
    }

    fn next_action(&mut self, member: &str) -> Option<Action> {
        if let Some(q) = self.once.get_mut(member)
            && let Some(a) = q.pop_front()
        {
            return Some(a);
        }
        self.always.get(member).cloned()
    }
}

struct Shared {
    state: Mutex<State>,
    killed: AtomicBool,
    connections: AtomicUsize,
}

struct Fake {
    shared: Arc<Shared>,
    streams: mpsc::UnboundedSender<UnixStream>,
    kill: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    fn start() -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new()),
            killed: AtomicBool::new(false),
            connections: AtomicUsize::new(0),
        });
        let (streams, mut incoming) = mpsc::unbounded_channel::<UnixStream>();
        let (kill, kill_rx) = watch::channel(false);
        let sh = shared.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            let mut stop = kill_rx.clone();
            rt.block_on(async move {
                loop {
                    tokio::select! {
                        s = incoming.recv() => match s {
                            Some(s) => {
                                tokio::spawn(serve(sh.clone(), s, kill_rx.clone()));
                            }
                            None => break,
                        },
                        _ = stop.changed() => break,
                    }
                }
            });
        });
        Self {
            shared,
            streams,
            kill,
            thread: Some(thread),
        }
    }

    /// Stream factory for `SsClient::connect_p2p`: one fresh pair per connection.
    fn connector(&self) -> impl FnMut() -> Option<UnixStream> + Send + 'static {
        let tx = self.streams.clone();
        let shared = self.shared.clone();
        move || {
            if shared.killed.load(Ordering::SeqCst) {
                return None;
            }
            let (client, server) = UnixStream::pair().ok()?;
            tx.send(server).ok()?;
            shared.connections.fetch_add(1, Ordering::SeqCst);
            Some(client)
        }
    }

    fn connect(&self) -> Result<SsClient, IdentityError> {
        SsClient::connect_p2p(self.connector(), timeouts())
    }

    /// Client connected to this fake; the fake must accept the connection.
    fn client(&self) -> SsClient {
        self.connect().expect("client connects")
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.shared.state.lock().unwrap())
    }

    fn add_item(&self, account: &str, secret: &[u8]) {
        self.add_item_locked(account, secret, false);
    }

    fn add_item_locked(&self, account: &str, secret: &[u8], locked: bool) {
        self.with(|s| {
            let id = s.next_id;
            s.next_id += 1;
            let mut attrs = BTreeMap::new();
            attrs.insert("service".to_owned(), SVC.to_owned());
            attrs.insert("username".to_owned(), account.to_owned());
            s.items.push(Item {
                path: format!("{COLLECTION}/{id}"),
                attrs,
                secret: secret.to_vec(),
                locked,
            });
        });
    }

    fn always(&self, member: &str, a: Action) {
        self.with(|s| {
            s.always.insert(member.to_owned(), a);
        });
    }

    fn once(&self, member: &str, actions: Vec<Action>) {
        self.with(|s| {
            s.once.insert(member.to_owned(), actions.into());
        });
    }

    fn count(&self, member: &str) -> usize {
        self.with(|s| s.calls.iter().filter(|c| c.member == member).count())
    }

    /// Every incoming call had exactly the body signature of section 3.
    fn assert_signatures(&self) {
        let bad = self.with(|s| s.mismatches.clone());
        assert!(bad.is_empty(), "body signature mismatches: {bad:?}");
    }

    fn wire_of(&self, member: &str) -> Vec<Option<String>> {
        self.with(|s| {
            s.calls
                .iter()
                .filter(|c| c.member == member)
                .map(|c| c.wire.clone())
                .collect()
        })
    }

    fn kill(&mut self) {
        self.shared.killed.store(true, Ordering::SeqCst);
        let _ = self.kill.send(true);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Read the body signature string from the raw header bytes of a message (little endian only).
fn wire_body_signature(b: &[u8]) -> Option<String> {
    if *b.first()? != b'l' {
        return None;
    }
    let fields_len = u32::from_le_bytes(b.get(12..16)?.try_into().ok()?) as usize;
    let end = 16usize.checked_add(fields_len)?;
    let mut pos = 16usize;
    while pos < end {
        pos = pos.next_multiple_of(8);
        if pos >= end {
            break;
        }
        let code = *b.get(pos)?;
        pos += 1;
        let siglen = *b.get(pos)? as usize;
        pos += 1;
        let sig = b.get(pos..pos + siglen)?.to_vec();
        pos += siglen + 1;
        match sig.as_slice() {
            b"g" => {
                let len = *b.get(pos)? as usize;
                pos += 1;
                let s = b.get(pos..pos + len)?;
                if code == 8 {
                    return String::from_utf8(s.to_vec()).ok();
                }
                pos += len + 1;
            }
            b"s" | b"o" => {
                pos = pos.next_multiple_of(4);
                let len = u32::from_le_bytes(b.get(pos..pos + 4)?.try_into().ok()?) as usize;
                pos += 4 + len + 1;
            }
            b"u" => {
                pos = pos.next_multiple_of(4) + 4;
            }
            _ => return None,
        }
    }
    Some(String::new())
}

fn expected_in(member: &str) -> Option<&'static str> {
    match member {
        "OpenSession" => Some(SIG_OPEN_SESSION_IN),
        "SearchItems" => Some(SIG_SEARCH_IN),
        "ReadAlias" => Some(SIG_READ_ALIAS_IN),
        "Get" => Some(SIG_PROP_GET_IN),
        "CreateItem" => Some(SIG_CREATE_ITEM_IN),
        "GetSecret" => Some(SIG_OBJECT),
        "SetSecret" => Some(SIG_SECRET),
        "Delete" | "Dismiss" => Some(SIG_EMPTY),
        _ => None,
    }
}

enum Disp {
    Send(Message),
    Silent,
}

fn obj(p: &str) -> ObjectPath<'_> {
    ObjectPath::try_from(p).expect("object path")
}

macro_rules! ok {
    ($hdr:expr, $body:expr) => {
        Disp::Send(
            Message::method_return(&$hdr)
                .build($body)
                .expect("build reply"),
        )
    };
}

macro_rules! fail {
    ($hdr:expr, $name:expr) => {
        Disp::Send(
            Message::error(&$hdr, $name)
                .build(&"fake error")
                .expect("build error"),
        )
    };
}

type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

fn find(st: &State, p: &str) -> Option<usize> {
    st.items.iter().position(|i| i.path == p)
}

fn handle(shared: &Shared, msg: &Message) -> Disp {
    let hdr = msg.header();
    let member = hdr
        .member()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let path = hdr
        .path()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    let wire = wire_body_signature(msg.data());
    let mut st = shared.state.lock().unwrap();
    st.calls.push(Call {
        member: member.clone(),
        wire: wire.clone(),
    });
    if let Some(exp) = expected_in(&member)
        && wire.as_deref() != Some(exp)
    {
        st.mismatches
            .push(format!("{member}: wire {wire:?}, expected {exp:?}"));
    }
    match st.next_action(&member) {
        Some(Action::Error(name)) => return fail!(hdr, name),
        Some(Action::Silent) => return Disp::Silent,
        Some(Action::BadReply) => return ok!(hdr, &42u32),
        None => {}
    }
    match member.as_str() {
        "OpenSession" => {
            let Ok((algo, input)) = msg.body().deserialize::<(String, OwnedVariant)>() else {
                return fail!(hdr, "org.freedesktop.DBus.Error.InvalidArgs");
            };
            let input_is_empty_string = matches!(&*input, Variant::Str(s) if s.as_str().is_empty());
            if algo != "plain" || !input_is_empty_string {
                st.mismatches.push("OpenSession arguments".to_owned());
            }
            ok!(hdr, &(Variant::from(""), obj(SESSION)))
        }
        "SearchItems" => {
            let Ok(query) = msg.body().deserialize::<BTreeMap<String, String>>() else {
                return fail!(hdr, "org.freedesktop.DBus.Error.InvalidArgs");
            };
            st.searches.push(query.clone());
            let all_locked = st.collection_locked;
            let mut unlocked = Vec::new();
            let mut locked = Vec::new();
            for i in st.items.iter().filter(|i| i.attrs == query) {
                if i.locked || all_locked {
                    locked.push(obj(&i.path));
                } else {
                    unlocked.push(obj(&i.path));
                }
            }
            ok!(hdr, &(unlocked, locked))
        }
        "ReadAlias" => {
            if msg.body().deserialize::<String>().ok().as_deref() != Some("default") {
                st.mismatches.push("ReadAlias argument".to_owned());
            }
            if st.has_default {
                ok!(hdr, &obj(COLLECTION))
            } else {
                ok!(hdr, &obj("/"))
            }
        }
        "Get" => {
            if path == COLLECTION {
                ok!(hdr, &Variant::from(st.collection_locked))
            } else {
                fail!(hdr, NO_SUCH)
            }
        }
        "CreateItem" => {
            type Body = (BTreeMap<String, OwnedVariant>, SecretStruct, bool);
            let Ok((props, secret, replace)) = msg.body().deserialize::<Body>() else {
                st.mismatches.push("CreateItem undecodable".to_owned());
                return fail!(hdr, "org.freedesktop.DBus.Error.InvalidArgs");
            };
            let property_keys: Vec<String> = props.keys().cloned().collect();
            let label = match props.get("org.freedesktop.Secret.Item.Label").map(|v| &**v) {
                Some(Variant::Str(s)) => s.as_str().to_owned(),
                _ => String::new(),
            };
            let attrs: BTreeMap<String, String> = props
                .get("org.freedesktop.Secret.Item.Attributes")
                .and_then(|v| v.try_clone().ok())
                .and_then(|v| BTreeMap::<String, String>::try_from(v).ok())
                .unwrap_or_default();
            let (_session, parameters, value, content_type) = secret;
            st.creates.push(CreateRecord {
                collection: path.clone(),
                property_keys,
                attrs: attrs.clone(),
                label,
                content_type,
                parameters,
                replace,
            });
            if st.create_prompt {
                return ok!(hdr, &(obj("/"), obj(PROMPT)));
            }
            if replace {
                st.items.retain(|i| i.attrs != attrs);
            }
            let id = st.next_id;
            st.next_id += 1;
            let item_path = format!("{path}/{id}");
            st.items.push(Item {
                path: item_path.clone(),
                attrs,
                secret: value,
                locked: false,
            });
            ok!(hdr, &(obj(&item_path), obj("/")))
        }
        "GetSecret" => {
            let Some(idx) = find(&st, &path) else {
                return fail!(hdr, NO_SUCH);
            };
            let mut value = st.items[idx].secret.clone();
            let mut parameters = Vec::<u8>::new();
            match st.get_mode {
                GetMode::Normal => {}
                GetMode::DoubleWrapped => {
                    return ok!(hdr, &(((obj(SESSION), parameters, value, CONTENT_TYPE),),));
                }
                GetMode::Oversized => value = vec![7u8; MAX_SECRET_LEN + 1],
                GetMode::NonEmptyParameters => parameters = vec![1u8],
            }
            ok!(hdr, &((obj(SESSION), parameters, value, CONTENT_TYPE),))
        }
        "SetSecret" => {
            let Some(idx) = find(&st, &path) else {
                return fail!(hdr, NO_SUCH);
            };
            let Ok((_session, _parameters, value, _ct)) = msg.body().deserialize::<SecretStruct>()
            else {
                st.mismatches.push("SetSecret undecodable".to_owned());
                return fail!(hdr, "org.freedesktop.DBus.Error.InvalidArgs");
            };
            st.items[idx].secret = value;
            ok!(hdr, &())
        }
        "Delete" => {
            let Some(idx) = find(&st, &path) else {
                return fail!(hdr, NO_SUCH);
            };
            if st.delete_prompt {
                return ok!(hdr, &obj(PROMPT));
            }
            st.items.remove(idx);
            ok!(hdr, &obj("/"))
        }
        "Dismiss" => ok!(hdr, &()),
        _ => fail!(hdr, "org.freedesktop.DBus.Error.UnknownMethod"),
    }
}

async fn serve(shared: Arc<Shared>, stream: UnixStream, mut kill: watch::Receiver<bool>) {
    let Ok(conn) = Builder::unix_stream(stream)
        .server(Guid::generate())
        .p2p()
        .build()
        .await
    else {
        return;
    };
    let mut messages = pin!(MessageStream::from(&conn));
    loop {
        let next = tokio::select! {
            m = poll_fn(|cx| messages.as_mut().poll_next(cx)) => m,
            _ = kill.changed() => break,
        };
        let Some(Ok(msg)) = next else { break };
        if *kill.borrow() {
            break;
        }
        if msg.message_type() != MsgType::MethodCall {
            continue;
        }
        match handle(&shared, &msg) {
            Disp::Send(reply) => {
                if conn.send(&reply).await.is_err() {
                    break;
                }
            }
            Disp::Silent => {}
        }
    }
}

// ---------- helpers ----------

fn value(
    r: Result<Option<Zeroizing<Vec<u8>>>, IdentityError>,
) -> Result<Option<Vec<u8>>, IdentityError> {
    r.map(|o| o.map(|z| z.to_vec()))
}

fn assert_fast(start: Instant) {
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "took {:?}",
        start.elapsed()
    );
}

const UNAVAILABLE: IdentityError = IdentityError::StorageUnavailable;
const LOCKED: IdentityError = IdentityError::StorageLocked;
const INCONSISTENT: IdentityError = IdentityError::StorageInconsistent;

// ---------- T1-T3: protocol and compatibility ----------

#[test]
fn ss_fake_roundtrip() {
    let fake = Fake::start();
    let c = fake.client();
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    c.set(SVC, ACC, b"one").unwrap();
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"one".to_vec())));
    c.set(SVC, ACC, b"two-two").unwrap();
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"two-two".to_vec())));
    c.delete(SVC, ACC).unwrap();
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    c.delete(SVC, ACC).unwrap();
    assert_eq!(fake.count("CreateItem"), 1);
    assert_eq!(fake.count("SetSecret"), 1);
    assert_eq!(
        fake.wire_of("CreateItem"),
        vec![Some("a{sv}(oayays)b".to_owned())]
    );
    assert_eq!(fake.wire_of("SetSecret"), vec![Some("(oayays)".to_owned())]);
    assert_eq!(fake.wire_of("GetSecret")[0].as_deref(), Some("o"));
    assert_eq!(fake.wire_of("OpenSession")[0].as_deref(), Some("sv"));
    fake.assert_signatures();
}

#[test]
fn ss_fake_create_exact_props() {
    let fake = Fake::start();
    let c = fake.client();
    c.set(SVC, ACC, b"secret-bytes").unwrap();
    let rec = fake.with(|s| s.creates.clone());
    assert_eq!(rec.len(), 1);
    let r = &rec[0];
    assert_eq!(
        r.property_keys,
        vec![
            "org.freedesktop.Secret.Item.Attributes".to_owned(),
            "org.freedesktop.Secret.Item.Label".to_owned()
        ]
    );
    let mut want = BTreeMap::new();
    want.insert("service".to_owned(), SVC.to_owned());
    want.insert("username".to_owned(), ACC.to_owned());
    assert_eq!(r.attrs, want);
    assert_eq!(r.label, format!("keyring:{ACC}@{SVC}"));
    assert_eq!(r.content_type, "application/octet-stream");
    assert!(r.replace);
    assert!(r.parameters.is_empty());
    assert_eq!(r.collection, COLLECTION);
    assert_eq!(fake.with(|s| s.searches[0].clone()), want);
    assert_eq!(fake.with(|s| s.items[0].secret.clone()), b"secret-bytes");
    fake.assert_signatures();
}

#[test]
fn ss_fake_existing_uses_setsecret() {
    let fake = Fake::start();
    fake.add_item(ACC, b"old");
    let c = fake.client();
    c.set(SVC, ACC, b"new").unwrap();
    assert_eq!(fake.count("CreateItem"), 0);
    assert_eq!(fake.count("SetSecret"), 1);
    assert_eq!(fake.wire_of("SetSecret"), vec![Some("(oayays)".to_owned())]);
    assert_eq!(fake.with(|s| s.items[0].secret.clone()), b"new");
    fake.assert_signatures();
}

// ---------- T4-T9: semantics ----------

#[test]
fn ss_fake_two_matches_inconsistent() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    fake.add_item(ACC, b"b");
    let c = fake.client();
    assert_eq!(value(c.get(SVC, ACC)), Err(INCONSISTENT));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(INCONSISTENT));
    assert_eq!(c.delete(SVC, ACC), Err(INCONSISTENT));
    assert_eq!(fake.count("CreateItem") + fake.count("SetSecret"), 0);
}

#[test]
fn ss_fake_locked_item_locked_no_prompt() {
    let fake = Fake::start();
    fake.add_item_locked(ACC, b"a", true);
    let c = fake.client();
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(LOCKED));
    assert_eq!(c.delete(SVC, ACC), Err(LOCKED));
    assert_eq!(fake.count("Unlock"), 0);
    assert_eq!(fake.count("Prompt"), 0);
    assert_eq!(fake.count("GetSecret"), 0);
    assert_eq!(fake.count("SetSecret"), 0);
    assert_eq!(fake.count("Delete"), 0);
}

#[test]
fn ss_fake_empty_default_locked_is_locked() {
    let fake = Fake::start();
    let c = fake.client();
    fake.with(|s| s.collection_locked = true);
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(LOCKED));
    assert_eq!(fake.count("CreateItem"), 0);
    fake.with(|s| s.collection_locked = false);
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    assert_eq!(fake.count("Unlock"), 0);
    assert_eq!(fake.count("Prompt"), 0);
}

#[test]
fn ss_fake_no_default_alias() {
    let fake = Fake::start();
    fake.with(|s| s.has_default = false);
    let c = fake.client();
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(UNAVAILABLE));
    assert_eq!(fake.count("CreateItem"), 0);
    fake.assert_signatures();
}

#[test]
fn ss_fake_create_prompt_dismissed() {
    let fake = Fake::start();
    fake.with(|s| s.create_prompt = true);
    let c = fake.client();
    assert_eq!(c.set(SVC, ACC, b"x"), Err(LOCKED));
    assert_eq!(fake.count("Dismiss"), 1);
    assert_eq!(fake.count("Prompt"), 0);
    assert_eq!(fake.count("Unlock"), 0);
    fake.assert_signatures();
}

#[test]
fn ss_fake_delete_prompt_locked() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    fake.with(|s| s.delete_prompt = true);
    let c = fake.client();
    assert_eq!(c.delete(SVC, ACC), Err(LOCKED));
    assert_eq!(fake.count("Dismiss"), 1);
    assert_eq!(fake.count("Prompt"), 0);
    assert_eq!(fake.count("Unlock"), 0);
}

// ---------- T10-T17: errors and hostile replies ----------

#[test]
fn ss_fake_is_locked_and_access_denied_map_locked() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    let c = fake.client();
    fake.once("GetSecret", vec![Action::Error(IS_LOCKED)]);
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    fake.once("GetSecret", vec![Action::Error(ACCESS_DENIED)]);
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    fake.once("SetSecret", vec![Action::Error(IS_LOCKED)]);
    assert_eq!(c.set(SVC, ACC, b"x"), Err(LOCKED));
    fake.once("SearchItems", vec![Action::Error(ACCESS_DENIED)]);
    assert_eq!(c.delete(SVC, ACC), Err(LOCKED));
    assert_eq!(fake.count("Unlock") + fake.count("Prompt"), 0);
}

#[test]
fn ss_fake_service_unknown_unavailable() {
    let fake = Fake::start();
    fake.always("OpenSession", Action::Error(SERVICE_UNKNOWN));
    let start = Instant::now();
    assert_eq!(fake.connect().err(), Some(UNAVAILABLE));
    assert_fast(start);
    fake.always(
        "OpenSession",
        Action::Error("org.freedesktop.DBus.Error.NameHasNoOwner"),
    );
    assert_eq!(fake.connect().err(), Some(UNAVAILABLE));
    fake.with(|s| s.always.clear());
    let c = fake.client();
    fake.always("SearchItems", Action::Error(SERVICE_UNKNOWN));
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(UNAVAILABLE));
    assert_eq!(c.delete(SVC, ACC), Err(UNAVAILABLE));
}

#[test]
fn ss_fake_plain_not_supported_unavailable() {
    let fake = Fake::start();
    fake.always("OpenSession", Action::Error(NOT_SUPPORTED));
    let start = Instant::now();
    assert_eq!(fake.connect().err(), Some(UNAVAILABLE));
    assert_fast(start);
    assert_eq!(fake.count("SearchItems"), 0);
}

#[test]
fn ss_fake_never_replies_bounded() {
    let fake = Fake::start();
    let c = fake.client();
    fake.always("SearchItems", Action::Silent);
    let start = Instant::now();
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    assert_fast(start);
    let start = Instant::now();
    assert_eq!(c.set(SVC, ACC, b"x"), Err(UNAVAILABLE));
    assert_fast(start);
    let start = Instant::now();
    assert_eq!(c.delete(SVC, ACC), Err(UNAVAILABLE));
    assert_fast(start);
    // The service answers again: the client recovers (new connection).
    fake.with(|s| s.always.clear());
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
}

#[test]
fn ss_fake_silent_peer_no_auth_bounded() {
    // The peer accepts the socket and never writes: no authentication reply, no message.
    let held: Arc<Mutex<Vec<UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
    let keep = held.clone();
    let next = move || {
        let (client, server) = UnixStream::pair().ok()?;
        keep.lock().unwrap().push(server);
        Some(client)
    };
    let start = Instant::now();
    let r = SsClient::connect_p2p(next, timeouts());
    assert_eq!(r.err(), Some(UNAVAILABLE));
    assert_fast(start);
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[test]
fn ss_fake_bad_signature_unavailable() {
    // Startup with a reply of the wrong type.
    let fake = Fake::start();
    fake.always("OpenSession", Action::BadReply);
    assert_eq!(fake.connect().err(), Some(UNAVAILABLE));
    fake.with(|s| s.always.clear());

    fake.add_item(ACC, b"a");
    let c = fake.client();
    fake.always("SearchItems", Action::BadReply);
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    assert_eq!(c.set(SVC, ACC, b"x"), Err(UNAVAILABLE));
    assert_eq!(c.delete(SVC, ACC), Err(UNAVAILABLE));
    fake.with(|s| s.always.clear());

    fake.always("GetSecret", Action::BadReply);
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    fake.with(|s| s.always.clear());

    // GetSecret reply encoded as ((oayays)) instead of (oayays).
    fake.with(|s| s.get_mode = GetMode::DoubleWrapped);
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    fake.with(|s| s.get_mode = GetMode::Normal);
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"a".to_vec())));
}

#[test]
fn ss_fake_oversized_secret_inconsistent() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    let c = fake.client();
    fake.with(|s| s.get_mode = GetMode::Oversized);
    assert_eq!(value(c.get(SVC, ACC)), Err(INCONSISTENT));
}

#[test]
fn ss_fake_nonempty_parameters_inconsistent() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    let c = fake.client();
    fake.with(|s| s.get_mode = GetMode::NonEmptyParameters);
    assert_eq!(value(c.get(SVC, ACC)), Err(INCONSISTENT));
}

// ---------- T18-T21: reconnect, queue, server gone ----------

#[test]
fn ss_fake_no_session_reconnects_once() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    let c = fake.client();
    assert_eq!(fake.count("OpenSession"), 1);
    fake.once("SearchItems", vec![Action::Error(NO_SESSION)]);
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"a".to_vec())));
    assert_eq!(fake.count("OpenSession"), 2);
    // Twice in a row: Unavailable, no third attempt.
    fake.once(
        "SearchItems",
        vec![Action::Error(NO_SESSION), Action::Error(NO_SESSION)],
    );
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    assert_eq!(fake.count("OpenSession"), 3);
    // And the client works again afterwards.
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"a".to_vec())));
}

#[test]
fn ss_fake_item_vanished() {
    let fake = Fake::start();
    fake.add_item(ACC, b"a");
    let c = fake.client();
    fake.once("GetSecret", vec![Action::Error(NO_SUCH)]);
    assert_eq!(value(c.get(SVC, ACC)), Err(INCONSISTENT));
    fake.once("SetSecret", vec![Action::Error(NO_SUCH)]);
    assert_eq!(c.set(SVC, ACC, b"x"), Err(INCONSISTENT));
    fake.once("Delete", vec![Action::Error(NO_SUCH)]);
    assert_eq!(c.delete(SVC, ACC), Ok(()));
}

#[test]
fn ss_fake_queue_full_unavailable() {
    let fake = Fake::start();
    let c = Arc::new(fake.client());
    fake.always("SearchItems", Action::Silent);
    let mut threads = Vec::new();
    for _ in 0..16 {
        let c = c.clone();
        threads.push(std::thread::spawn(move || {
            let start = Instant::now();
            let r = value(c.get(SVC, ACC));
            (r, start.elapsed())
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(results.iter().all(|(r, _)| *r == Err(UNAVAILABLE)));
    // One job runs and 8 wait in the queue: at least 7 of 16 are refused at once.
    let instant = results
        .iter()
        .filter(|(_, d)| *d < Duration::from_millis(100))
        .count();
    assert!(instant >= 7, "only {instant} immediate refusals");
}

#[test]
fn ss_fake_server_gone_unavailable_bounded() {
    let mut fake = Fake::start();
    let c = fake.client();
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    fake.kill();
    let start = Instant::now();
    assert_eq!(value(c.get(SVC, ACC)), Err(UNAVAILABLE));
    assert_fast(start);
    let start = Instant::now();
    assert_eq!(c.set(SVC, ACC, b"x"), Err(UNAVAILABLE));
    assert_fast(start);
    let start = Instant::now();
    assert_eq!(c.delete(SVC, ACC), Err(UNAVAILABLE));
    assert_fast(start);
}

// ---------- T22: through OsKeyStore ----------

#[test]
fn ss_fake_osstore_list_key_and_epoch() {
    let fake = Fake::start();
    let store = OsKeyStore::from_client(fake.client(), SVC).unwrap();
    assert_eq!(format!("{store:?}"), "OsKeyStore(..)");

    assert!(store.read_list_key().unwrap().is_none());
    store.write_list_key(&[0x5A; 32]).unwrap();
    assert_eq!(
        store.read_list_key().unwrap().unwrap().as_slice(),
        &[0x5A; 32]
    );
    store.write_list_key(&[0x33; 32]).unwrap();
    assert_eq!(
        store.read_list_key().unwrap().unwrap().as_slice(),
        &[0x33; 32]
    );
    store.delete_list_key().unwrap();
    assert!(store.read_list_key().unwrap().is_none());
    store.delete_list_key().unwrap();

    assert_eq!(store.read_epoch(), Ok(None));
    store.write_epoch(0x0102_0304_0506_0708).unwrap();
    assert_eq!(store.read_epoch(), Ok(Some(0x0102_0304_0506_0708)));
    assert_eq!(
        fake.with(|s| s
            .items
            .iter()
            .find(|i| i.attrs.get("username").map(String::as_str) == Some(EPOCH_ACCOUNT))
            .map(|i| i.secret.clone())),
        Some(0x0102_0304_0506_0708u64.to_be_bytes().to_vec())
    );
    // A stored value of another length is inconsistent, not a number.
    let client = fake.client();
    client.set(SVC, EPOCH_ACCOUNT, &[1u8; 7]).unwrap();
    assert_eq!(store.read_epoch(), Err(INCONSISTENT));
    client.set(SVC, EPOCH_ACCOUNT, &[1u8; 9]).unwrap();
    assert_eq!(store.read_epoch(), Err(INCONSISTENT));

    // Pair entries use the account name of the pair and nothing else.
    let pair = PairId::from_bytes([0x17; 16]);
    let blob = [0x44u8; 129];
    store.write(&pair, &blob).unwrap();
    assert_eq!(store.read(&pair).unwrap().unwrap().as_slice(), &blob);
    assert!(fake.with(|s| {
        s.items
            .iter()
            .any(|i| i.attrs.get("username") == Some(&pair.account_name()))
    }));
    store.delete(&pair).unwrap();
    assert!(store.read(&pair).unwrap().is_none());
    assert_ne!(LIST_KEY_ACCOUNT, EPOCH_ACCOUNT);
    fake.assert_signatures();

    // Service name checks of `open_with_service` (spec section 4).
    for bad in ["", "x".repeat(256).as_str(), "a\0b"] {
        assert_eq!(
            OsKeyStore::from_client(fake.client(), bad).err(),
            Some(UNAVAILABLE)
        );
    }
}
