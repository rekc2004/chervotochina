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
    SIG_PROMPT_IN, SIG_PROP_GET_IN, SIG_READ_ALIAS_IN, SIG_SEARCH_IN, SIG_SECRET, SIG_UNLOCK_IN,
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

/// What `Service.Unlock` does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockMode {
    /// Unlocks at once: the collection is in `unlocked`, prompt `/`.
    Direct,
    /// Returns a prompt object; the collection stays locked until the prompt completes.
    Prompt,
}

/// What `Prompt.Prompt` does after it was called.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PromptMode {
    /// The user enters the password: unlocks and signals `Completed(false, ..)`.
    Complete,
    /// The user cancels: `Completed(true, ..)`, still locked.
    Dismissed,
    /// A forged `Completed(false, ..)` while the collection stays locked.
    Forged,
    /// No signal at all (the user does not answer).
    Silent,
    /// 50 malformed `Completed` signals before the reply and 50 after it, then nothing.
    Flood,
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
    /// Pause before the call of this member is handled (the whole connection waits).
    delays: HashMap<String, Duration>,
    get_mode: GetMode,
    create_prompt: bool,
    delete_prompt: bool,
    unlock_mode: UnlockMode,
    prompt_mode: PromptMode,
    /// Object paths received by `Unlock`, one list per call.
    unlock_args: Vec<Vec<String>>,
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
            delays: HashMap::new(),
            get_mode: GetMode::Normal,
            create_prompt: false,
            delete_prompt: false,
            unlock_mode: UnlockMode::Direct,
            prompt_mode: PromptMode::Complete,
            unlock_args: Vec::new(),
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
        "Unlock" => Some(SIG_UNLOCK_IN),
        "Prompt" => Some(SIG_PROMPT_IN),
        _ => None,
    }
}

enum Disp {
    Send(Message),
    /// A reply and then signals.
    SendAll(Vec<Message>),
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
        "Unlock" => {
            let Ok(paths) = msg.body().deserialize::<Vec<OwnedObjectPath>>() else {
                st.mismatches.push("Unlock undecodable".to_owned());
                return fail!(hdr, "org.freedesktop.DBus.Error.InvalidArgs");
            };
            st.unlock_args
                .push(paths.iter().map(|p| p.as_str().to_owned()).collect());
            match st.unlock_mode {
                UnlockMode::Direct => {
                    st.collection_locked = false;
                    ok!(hdr, &(vec![obj(COLLECTION)], obj("/")))
                }
                UnlockMode::Prompt => ok!(hdr, &(Vec::<ObjectPath<'_>>::new(), obj(PROMPT))),
            }
        }
        "Prompt" => {
            let dismissed = match st.prompt_mode {
                PromptMode::Complete => {
                    st.collection_locked = false;
                    Some(false)
                }
                PromptMode::Dismissed => Some(true),
                PromptMode::Forged => Some(false),
                PromptMode::Silent | PromptMode::Flood => None,
            };
            let reply = Message::method_return(&hdr)
                .build(&())
                .expect("build reply");
            if st.prompt_mode == PromptMode::Flood {
                // Right path, interface and member, a body of the wrong shape.
                let junk = || {
                    Message::signal(path.as_str(), "org.freedesktop.Secret.Prompt", "Completed")
                        .build(&7u32)
                        .expect("build signal")
                };
                let mut out: Vec<Message> = (0..50).map(|_| junk()).collect();
                out.push(reply);
                out.extend((0..50).map(|_| junk()));
                return Disp::SendAll(out);
            }
            let mut out = vec![reply];
            if let Some(d) = dismissed {
                out.push(
                    Message::signal(path.as_str(), "org.freedesktop.Secret.Prompt", "Completed")
                        .build(&(d, Variant::from("")))
                        .expect("build signal"),
                );
            }
            Disp::SendAll(out)
        }
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
        let delay = msg
            .header()
            .member()
            .and_then(|m| shared.state.lock().unwrap().delays.get(m.as_str()).copied());
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        match handle(&shared, &msg) {
            Disp::Send(reply) => {
                if conn.send(&reply).await.is_err() {
                    break;
                }
            }
            Disp::SendAll(all) => {
                for m in &all {
                    if conn.send(m).await.is_err() {
                        return;
                    }
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

// ---------- T24-T28: explicit unlock ----------

const WAIT: Duration = Duration::from_millis(300);
/// What the old default alias path would look like: must never be sent to `Unlock`.
const ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";

#[test]
fn ss_fake_unlock_ok() {
    assert_ne!(COLLECTION, ALIAS_PATH);
    // Already unlocked: no Unlock, no Prompt.
    let fake = Fake::start();
    let c = fake.client();
    assert_eq!(c.request_unlock(WAIT), Ok(()));
    assert_eq!(fake.count("Unlock") + fake.count("Prompt"), 0);

    // Locked, the service unlocks at once (no prompt).
    fake.with(|s| s.collection_locked = true);
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Ok(()));
    assert_fast(start);
    assert_eq!(fake.count("Unlock"), 1);
    assert_eq!(fake.count("Prompt"), 0);
    // `ao` with exactly the path that ReadAlias returned; never "default", never "/".
    let args = fake.with(|s| s.unlock_args.clone());
    assert_eq!(args, vec![vec![COLLECTION.to_owned()]]);
    assert_eq!(fake.wire_of("Unlock"), vec![Some("ao".to_owned())]);
    assert!(!fake.with(|s| s.collection_locked));

    // Locked, the service asks for a prompt and the user enters the password.
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Complete;
    });
    assert_eq!(c.request_unlock(WAIT), Ok(()));
    assert_eq!(fake.count("Unlock"), 2);
    assert_eq!(fake.count("Prompt"), 1);
    assert_eq!(fake.count("Dismiss"), 0);
    assert_eq!(fake.wire_of("Prompt")[0].as_deref(), Some("s"));
    assert!(fake.with(|s| s.unlock_args.iter().all(|a| a == &[COLLECTION.to_owned()])));
    // The store works after the unlock.
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_dismissed_locked() {
    let fake = Fake::start();
    let c = fake.client();
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Dismissed;
    });
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(LOCKED));
    assert_fast(start);
    assert_eq!(fake.count("Prompt"), 1);
    // The prompt is closed on every outcome but success.
    assert_eq!(fake.count("Dismiss"), 1);
    assert!(fake.with(|s| s.collection_locked));
    // The store still reports "locked", no prompt on its own.
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    assert_eq!(fake.count("Unlock"), 1);
    assert_eq!(fake.count("Prompt"), 1);
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_timeout_dismisses_bounded() {
    let fake = Fake::start();
    let c = fake.client();
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Silent;
    });
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(LOCKED));
    let took = start.elapsed();
    assert!(took >= WAIT, "returned before the wait: {took:?}");
    assert_fast(start);
    assert_eq!(fake.count("Prompt"), 1);
    assert_eq!(fake.count("Dismiss"), 1);
    // The worker is free again afterwards.
    fake.with(|s| s.collection_locked = false);
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_forged_completed_rechecks() {
    let fake = Fake::start();
    let c = fake.client();
    // The signal says "not dismissed", the collection is still locked.
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Forged;
    });
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(LOCKED));
    assert_fast(start);
    assert_eq!(fake.count("Prompt"), 1);
    assert_eq!(fake.count("Dismiss"), 1);
    assert!(fake.with(|s| s.collection_locked));
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_no_default_alias() {
    let fake = Fake::start();
    fake.with(|s| s.has_default = false);
    let c = fake.client();
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(UNAVAILABLE));
    assert_fast(start);
    assert_eq!(fake.count("Unlock"), 0);
    assert_eq!(fake.count("Prompt"), 0);
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_hostile_replies_bounded() {
    let fake = Fake::start();
    let c = fake.client();
    fake.with(|s| s.collection_locked = true);
    // A reply of the wrong type.
    fake.always("Unlock", Action::BadReply);
    assert_eq!(c.request_unlock(WAIT), Err(UNAVAILABLE));
    // The service never answers `Unlock`.
    fake.always("Unlock", Action::Silent);
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(UNAVAILABLE));
    assert_fast(start);
    // The prompt call fails.
    fake.with(|s| {
        s.always.clear();
        s.unlock_mode = UnlockMode::Prompt;
    });
    fake.always("Prompt", Action::Error(SERVICE_UNKNOWN));
    assert_eq!(c.request_unlock(WAIT), Err(UNAVAILABLE));
    assert_eq!(fake.count("Prompt"), 1);
    assert_eq!(fake.count("Dismiss"), 1);
    // An access-denied answer to `Unlock` is "locked".
    fake.with(|s| s.always.clear());
    fake.always("Unlock", Action::Error(ACCESS_DENIED));
    assert_eq!(c.request_unlock(WAIT), Err(LOCKED));
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_signal_flood_bounded() {
    // 100 well-addressed signals with a body of the wrong shape, half of them before the reply to
    // `Prompt`. The queue of the signal stream holds 4: without draining, the socket reader would
    // wait for room and the reply to `Prompt` would never be dispatched.
    let fake = Fake::start();
    let c = fake.client();
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Flood;
    });
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(LOCKED));
    let took = start.elapsed();
    assert!(took >= WAIT, "returned before the wait: {took:?}");
    assert_fast(start);
    assert_eq!(fake.count("Prompt"), 1);
    assert_eq!(fake.count("Dismiss"), 1);
    assert!(fake.with(|s| s.collection_locked));
    // The connection is still usable (no stuck reader, no reconnect needed).
    fake.with(|s| s.collection_locked = false);
    assert_eq!(value(c.get(SVC, ACC)), Ok(None));
    assert_eq!(fake.shared.connections.load(Ordering::SeqCst), 1);
    fake.assert_signatures();
}

#[test]
fn ss_unlock_completed_rule_names_the_service() {
    let prompt: OwnedObjectPath = obj(PROMPT).into();
    let rule = super::unlock::completed_rule(&prompt)
        .ok()
        .expect("rule")
        .to_string();
    for part in [
        "type='signal'",
        "sender='org.freedesktop.secrets'",
        "interface='org.freedesktop.Secret.Prompt'",
        "member='Completed'",
        "path='/org/freedesktop/secrets/prompt/p1'",
    ] {
        assert!(rule.contains(part), "{part} missing in {rule}");
    }
}

// ---------- a job is never applied after its caller gave up ----------

/// Wide call and job limits, a short caller wait: only the deadline of the caller stops a job.
fn late_timeouts() -> Timeouts {
    Timeouts {
        call: Duration::from_secs(3),
        op: Duration::from_secs(5),
        caller: Duration::from_millis(600),
    }
}

fn late_client(fake: &Fake) -> SsClient {
    SsClient::connect_p2p(fake.connector(), late_timeouts()).expect("client connects")
}

const OTHER: &str = "pair-v1-ffffffffffffffffffffffffffffffff";

/// No write, create or delete reached the fake, and the stored data is untouched.
fn assert_untouched(fake: &Fake) {
    assert_eq!(fake.count("SetSecret"), 0);
    assert_eq!(fake.count("CreateItem"), 0);
    assert_eq!(fake.count("Delete"), 0);
    let items = fake.with(|s| s.items.iter().map(|i| i.secret.clone()).collect::<Vec<_>>());
    assert_eq!(items, vec![b"old".to_vec()]);
}

#[test]
fn ss_fake_queued_jobs_of_gone_callers_never_run() {
    let fake = Fake::start();
    fake.add_item(ACC, b"old");
    let c = Arc::new(late_client(&fake));
    // The first job holds the worker for 1 s, longer than any caller waits (600 ms).
    fake.with(|s| {
        s.delays
            .insert("SearchItems".to_owned(), Duration::from_millis(1000));
    });
    let slow = {
        let c = c.clone();
        std::thread::spawn(move || value(c.get(SVC, ACC)))
    };
    // Its job is queued (and started) before the others are submitted.
    std::thread::sleep(Duration::from_millis(100));
    let queued: Vec<_> = [0u8, 1, 2]
        .into_iter()
        .map(|which| {
            let c = c.clone();
            std::thread::spawn(move || match which {
                0 => c.set(SVC, ACC, b"new"),
                1 => c.set(SVC, OTHER, b"new"),
                _ => c.delete(SVC, ACC),
            })
        })
        .collect();
    assert_eq!(slow.join().unwrap(), Err(UNAVAILABLE));
    for t in queued {
        assert_eq!(t.join().unwrap(), Err(UNAVAILABLE));
    }
    // The slow job ends at about 1 s; the queued ones come after it. Flush the queue.
    fake.with(|s| s.delays.clear());
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"old".to_vec())));
    assert_untouched(&fake);
    // Only the slow job and the flush ran a search: the three queued jobs never started.
    assert_eq!(fake.count("SearchItems"), 2);
    fake.assert_signatures();
}

#[test]
fn ss_fake_job_past_its_deadline_sends_no_mutation() {
    let fake = Fake::start();
    fake.add_item(ACC, b"old");
    let c = SsClient::connect_p2p(
        fake.connector(),
        Timeouts {
            call: Duration::from_secs(3),
            op: Duration::from_secs(5),
            caller: Duration::from_millis(400),
        },
    )
    .expect("client connects");
    // Each job starts in time, but its search answers after the caller has given up.
    fake.with(|s| {
        s.delays
            .insert("SearchItems".to_owned(), Duration::from_millis(500));
    });
    assert_eq!(c.set(SVC, ACC, b"new"), Err(UNAVAILABLE)); // SetSecret path
    assert_eq!(c.set(SVC, OTHER, b"new"), Err(UNAVAILABLE)); // CreateItem path
    assert_eq!(c.delete(SVC, ACC), Err(UNAVAILABLE));
    // Let the worker finish the last job, then flush the queue.
    std::thread::sleep(Duration::from_millis(800));
    fake.with(|s| s.delays.clear());
    assert_eq!(value(c.get(SVC, ACC)), Ok(Some(b"old".to_vec())));
    assert_untouched(&fake);
    // Each of the three jobs did start (it searched) and then stopped before the mutation.
    assert_eq!(fake.count("SearchItems"), 4);
    fake.assert_signatures();
}

#[test]
fn ss_fake_unlock_past_its_deadline_sends_no_unlock() {
    let fake = Fake::start();
    let c = SsClient::connect_p2p(
        fake.connector(),
        Timeouts {
            call: Duration::from_secs(3),
            op: Duration::from_secs(5),
            caller: Duration::from_millis(400),
        },
    )
    .expect("client connects");
    fake.with(|s| {
        s.collection_locked = true;
        s.unlock_mode = UnlockMode::Prompt;
        s.prompt_mode = PromptMode::Complete;
        // The caller of `request_unlock(300 ms)` waits 2.3 s; the alias answers after 2.6 s.
        s.delays
            .insert("ReadAlias".to_owned(), Duration::from_millis(2600));
    });
    let start = Instant::now();
    assert_eq!(c.request_unlock(WAIT), Err(UNAVAILABLE));
    assert!(start.elapsed() < Duration::from_millis(2500));
    std::thread::sleep(Duration::from_millis(800));
    fake.with(|s| s.delays.clear());
    assert_eq!(value(c.get(SVC, ACC)), Err(LOCKED));
    // The job went on after the caller left, but sent neither `Unlock` nor `Prompt`.
    assert_eq!(fake.count("Unlock"), 0);
    assert_eq!(fake.count("Prompt"), 0);
    assert!(fake.with(|s| s.collection_locked));
    fake.assert_signatures();
}

#[test]
fn ss_unlock_wait_is_clamped() {
    use crate::os_linux::clamp_unlock_wait;
    assert_eq!(clamp_unlock_wait(Duration::ZERO), Duration::from_secs(1));
    assert_eq!(
        clamp_unlock_wait(Duration::from_millis(1500)),
        Duration::from_millis(1500)
    );
    assert_eq!(
        clamp_unlock_wait(Duration::from_secs(86_400)),
        Duration::from_secs(300)
    );
}

// ---------- L1-L3: live tests against a real Secret Service (CI job `secret-service-live`) ----------

/// Run only by `scripts/ci-secret-service.sh` (`-- --ignored ss_live_`), inside a private session
/// bus with an unlocked gnome-keyring. L3 locks the default collection and so runs in its own
/// invocation, after L1 and L2.
mod live {
    use super::*;

    const LIVE_SERVICE: &str = "chervotochina-live-17a";
    const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
    }

    async fn raw() -> zbus::Connection {
        Builder::session()
            .method_timeout(Duration::from_secs(5))
            .build()
            .await
            .unwrap()
    }

    /// Item path found by the same search as the client (unlocked or locked).
    async fn find_item(c: &zbus::Connection, account: &str) -> OwnedObjectPath {
        let mut attrs: BTreeMap<&str, &str> = BTreeMap::new();
        attrs.insert("service", LIVE_SERVICE);
        attrs.insert("username", account);
        let msg = c
            .call_method(
                Some("org.freedesktop.secrets"),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "SearchItems",
                &attrs,
            )
            .await
            .unwrap();
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            msg.body().deserialize().unwrap();
        assert_eq!(
            unlocked.len() + locked.len(),
            1,
            "exactly one entry per pair"
        );
        unlocked.into_iter().chain(locked).next().unwrap()
    }

    async fn item_property(
        c: &zbus::Connection,
        item: &OwnedObjectPath,
        name: &str,
    ) -> OwnedVariant {
        let msg = c
            .call_method(
                Some("org.freedesktop.secrets"),
                item.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.Secret.Item", name),
            )
            .await
            .unwrap();
        msg.body().deserialize().unwrap()
    }

    fn open() -> OsKeyStore {
        OsKeyStore::open_with_service(LIVE_SERVICE).expect("Secret Service on the session bus")
    }

    #[test]
    #[ignore = "needs a session bus with an unlocked Secret Service (CI job secret-service-live)"]
    fn ss_live_roundtrip() {
        let store = open();
        let pair = PairId::from_bytes([0x17; 16]);
        let blob = [0x44u8; 129];
        assert!(store.read(&pair).unwrap().is_none());
        store.write(&pair, &blob).unwrap();
        assert_eq!(store.read(&pair).unwrap().unwrap().as_slice(), &blob);
        store.write(&pair, &[0x55u8; 129]).unwrap();
        assert_eq!(
            store.read(&pair).unwrap().unwrap().as_slice(),
            &[0x55u8; 129]
        );

        assert!(store.read_list_key().unwrap().is_none());
        store.write_list_key(&[0x5A; 32]).unwrap();
        assert_eq!(
            store.read_list_key().unwrap().unwrap().as_slice(),
            &[0x5A; 32]
        );

        store.write_epoch(0x1717).unwrap();
        assert_eq!(store.read_epoch().unwrap(), Some(0x1717));
        store.write_epoch(0x1718).unwrap();
        assert_eq!(store.read_epoch().unwrap(), Some(0x1718));

        store.delete(&pair).unwrap();
        store.delete_list_key().unwrap();
        assert!(store.read(&pair).unwrap().is_none());
        assert!(store.read_list_key().unwrap().is_none());
        store.delete(&pair).unwrap();
    }

    #[test]
    #[ignore = "needs a session bus with an unlocked Secret Service (CI job secret-service-live)"]
    fn ss_live_attributes_exact() {
        let store = open();
        let pair = PairId::from_bytes([0x18; 16]);
        store.write(&pair, &[0x66u8; 129]).unwrap();
        let account = pair.account_name();
        let (attrs, label) = runtime().block_on(async {
            let c = raw().await;
            let item = find_item(&c, &account).await;
            let attrs = item_property(&c, &item, "Attributes").await;
            let label = item_property(&c, &item, "Label").await;
            let attrs = attrs
                .try_clone()
                .ok()
                .and_then(|v| BTreeMap::<String, String>::try_from(v).ok())
                .expect("Attributes is a{ss}");
            let label = match &*label {
                Variant::Str(s) => s.as_str().to_owned(),
                _ => panic!("Label is not a string"),
            };
            (attrs, label)
        });
        let mut want = BTreeMap::new();
        want.insert("service".to_owned(), LIVE_SERVICE.to_owned());
        want.insert("username".to_owned(), account.clone());
        // The daemon may add `xdg:schema` itself [not verified]; nothing else is allowed.
        let mut got = attrs;
        got.remove("xdg:schema");
        assert_eq!(got, want);
        assert_eq!(label, format!("keyring:{account}@{LIVE_SERVICE}"));
        store.delete(&pair).unwrap();
    }

    /// Locks the default collection: nothing may run after it in the same invocation.
    #[test]
    #[ignore = "locks the default collection; CI job secret-service-live runs it last"]
    fn ss_live_locked_bounded() {
        let store = open();
        let pair = PairId::from_bytes([0x19; 16]);
        store.write(&pair, &[0x77u8; 129]).unwrap();
        runtime().block_on(async {
            let c = raw().await;
            let msg = c
                .call_method(
                    Some("org.freedesktop.secrets"),
                    SERVICE_PATH,
                    Some(SERVICE_IFACE),
                    "ReadAlias",
                    &"default",
                )
                .await
                .unwrap();
            let default: OwnedObjectPath = msg.body().deserialize().unwrap();
            assert_ne!(
                default.as_str(),
                "/",
                "no default collection in this daemon"
            );
            let targets: Vec<&OwnedObjectPath> = vec![&default];
            c.call_method(
                Some("org.freedesktop.secrets"),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "Lock",
                &targets,
            )
            .await
            .unwrap();
        });
        // First runtime observation of the locked behaviour (F8b).
        let start = Instant::now();
        assert_eq!(value(store.read(&pair)), Err(LOCKED));
        assert_fast(start);
        let start = Instant::now();
        assert_eq!(store.write(&pair, &[0x78u8; 129]), Err(LOCKED));
        assert_fast(start);
        let start = Instant::now();
        assert_eq!(store.delete(&pair), Err(LOCKED));
        assert_fast(start);
        let start = Instant::now();
        assert_eq!(store.request_unlock(Duration::from_secs(2)), Err(LOCKED));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
        );
    }
}
