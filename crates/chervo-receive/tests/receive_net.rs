#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Сетевые тесты приёма (спецификация 15, R3): два настоящих движка с `QuinnTransport` на
//! 127.0.0.1, поверх них `Transfers`; у получателя `ReceivePlacement` и `ReceivePolicy`.
//! Имена предложений приходят от «отправителя» как есть (в том числе враждебные).

mod common;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{AddrSource, KnownAddr, RouteSources};
use chervo_connect::{AllowSet, Clock, ConnectConfig, Engine, RouteProbe, SystemClock};
use chervo_friends::{
    AutoAcceptLimits, FriendBook, NewFriend, PendingRole, Permission, TrustConfirmation,
};
use chervo_identity::{IdentityError, ListKeyStore, PairId, PairKey, SecretStore};
use chervo_receive::{
    AcceptIntoError, ChooseRootError, DiskSpace, ReceiveConfig, ReceivePlacement, ReceivePolicy,
    ReceiveRoot, SpaceCheck, accept_into, insufficient_space_text,
};
use chervo_transfer::{
    AskAlways, CompletedFile, FailReason, OfferedFile, PlaceError, Placed, Placement, SourceFile,
    TransferConfig, TransferEvent, TransferEvents, TransferKey, Transfers,
};
use chervo_transport::{Connection, PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use common::{Tmp, tree};
use zeroize::Zeroizing;

// ------------------------------------------------------------------- помощники

#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .list
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = None;
        Ok(())
    }
}

struct Probe;

impl RouteProbe for Probe {
    fn probe(&self) -> RouteSources {
        RouteSources {
            v4: Some(Ipv4Addr::LOCALHOST),
            ..RouteSources::default()
        }
    }
}

fn quinn_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

fn engine_cfg() -> ConnectConfig {
    ConnectConfig {
        tick: Duration::from_millis(100),
        probe_interval: Duration::from_millis(200),
        fast_period: Duration::from_millis(300),
        per_ip_dials: 1000,
        addr_info_out_interval: Duration::from_secs(1),
        ..ConnectConfig::default()
    }
}

struct Bound {
    t: Arc<QuinnTransport>,
    allow: Arc<AllowSet>,
    addr: SocketAddr,
}

fn bind(port: u16) -> Bound {
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let t = Arc::new(
        QuinnTransport::bind(
            SocketAddr::from(([127, 0, 0, 1], port)),
            quinn_cfg(),
            filter,
        )
        .unwrap(),
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], t.local_addrs()[0].port()));
    Bound { t, allow, addr }
}

type Eng = Engine<QuinnTransport, MemStore>;

/// Размещение отправителя: он ничего не принимает.
struct NeverPlace;

impl Placement for NeverPlace {
    fn place(&self, _f: &CompletedFile) -> Result<Placed, PlaceError> {
        Err(PlaceError::Refused)
    }
}

/// Один участник: движок, транспорт, передачи.
struct Side {
    engine: Arc<Eng>,
    t: Arc<QuinnTransport>,
    store: Arc<MemStore>,
    bookdir: Arc<Tmp>,
    tr: Transfers<Eng>,
    ev: TransferEvents,
    addr: SocketAddr,
    tcfg: TransferConfig,
}

fn start_side(
    b: Bound,
    store: Arc<MemStore>,
    bookdir: Arc<Tmp>,
    book: Option<FriendBook>,
    tcfg: TransferConfig,
    policy: Arc<dyn chervo_transfer::AcceptPolicy>,
    placement: Arc<dyn Placement>,
) -> Side {
    let book = book.unwrap_or_else(|| {
        FriendBook::open(&bookdir.path().join("friends.chfl"), &*store).unwrap()
    });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(Probe);
    let (engine, _events) = Engine::start(
        b.t.clone(),
        b.allow,
        book,
        store.clone(),
        clock,
        probe,
        engine_cfg(),
    )
    .unwrap();
    let engine = Arc::new(engine);
    let inbox = engine
        .stream_inbox(&[
            chervo_transfer::STREAM_TRANSFER_CTL,
            chervo_transfer::STREAM_TRANSFER_DATA,
        ])
        .unwrap();
    let (tr, ev) =
        Transfers::start(engine.clone(), inbox, policy, placement, tcfg.clone()).unwrap();
    Side {
        engine,
        t: b.t,
        store,
        bookdir,
        tr,
        ev,
        addr: b.addr,
        tcfg,
    }
}

fn known(addr: SocketAddr) -> KnownAddr {
    KnownAddr {
        addr,
        source: AddrSource::Invite,
        last_seen_unix: SystemClock::new().now_unix(),
        short_lived: false,
        hint: false,
    }
}

fn new_friend(theirs: &PairKey, ours: &PairKey, addr: Option<SocketAddr>) -> NewFriend {
    NewFriend {
        name: "friend".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: addr.map(known).into_iter().collect(),
        now_unix: SystemClock::new().now_unix(),
    }
}

fn tcfg(partial: &Path) -> TransferConfig {
    let mut c = TransferConfig::new(partial.to_path_buf());
    c.progress_interval = Duration::from_millis(20);
    c.checkpoint_interval = Duration::from_millis(100);
    // по умолчанию 6 предложений в минуту от друга; тесты шлют больше
    c.ctl_in_per_min = 10_000;
    c
}

/// Приёмная часть участника `y`.
struct Rx {
    root: ReceiveRoot,
    cfg: ReceiveConfig,
    policy: Arc<ReceivePolicy>,
    place: Arc<ReceivePlacement>,
    /// Свободное место «тома» (том 1 ТиБ): настоящее на Windows узнать нельзя, поэтому в
    /// сетевых тестах место подставное и одинаковое на всех ОС.
    free: Arc<AtomicU64>,
    /// То же для любой другой папки приёма (выбранной для отдельного предложения).
    free2: Arc<AtomicU64>,
}

const TEST_VOLUME: u64 = 1 << 40;

type SpaceFn = dyn Fn(&Path) -> Option<DiskSpace> + Send + Sync;

impl Rx {
    fn new(cfg: ReceiveConfig) -> Self {
        let root = ReceiveRoot::open(&cfg).unwrap();
        let free = Arc::new(AtomicU64::new(TEST_VOLUME));
        let free2 = Arc::new(AtomicU64::new(TEST_VOLUME));
        let (f1, f2, main) = (free.clone(), free2.clone(), root.root().to_path_buf());
        let probe: Arc<SpaceFn> = Arc::new(move |p: &Path| {
            let avail = if p.starts_with(&main) { &f1 } else { &f2 };
            Some(DiskSpace {
                total_bytes: TEST_VOLUME,
                available_bytes: avail.load(Ordering::SeqCst),
            })
        });
        let place =
            Arc::new(ReceivePlacement::new(root.clone(), &cfg).with_space_probe(probe.clone()));
        let policy = Arc::new(ReceivePolicy::with_space_probe(root.clone(), &cfg, probe));
        Self {
            root,
            cfg,
            policy,
            place,
            free,
            free2,
        }
    }
}

struct Duo {
    x: Side,
    y: Side,
    px: PairId,
    py: PairId,
    rx: Rx,
    /// Корень приёма и соседняя папка «снаружи» (должна остаться пустой).
    tmp: Tmp,
    outside: PathBuf,
    src: Tmp,
}

/// Корень приёма `tmp/recv` (Unix: права 0o700) и соседний `tmp/outside`.
fn make_dirs() -> (Tmp, PathBuf, PathBuf) {
    let tmp = Tmp::new("net");
    let recv = tmp.path().join("recv");
    let outside = tmp.path().join("outside");
    fs::create_dir(&recv).unwrap();
    fs::create_dir(&outside).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&recv, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (tmp, recv, outside)
}

async fn duo(perm: Permission, fcfg: impl FnOnce(&mut ReceiveConfig)) -> Duo {
    let (sx, sy) = (Arc::new(MemStore::default()), Arc::new(MemStore::default()));
    let (dx, dy) = (Arc::new(Tmp::new("bx")), Arc::new(Tmp::new("by")));
    let mut bx_book = FriendBook::open(&dx.path().join("friends.chfl"), &*sx).unwrap();
    let mut by_book = FriendBook::open(&dy.path().join("friends.chfl"), &*sy).unwrap();
    let (bx, by) = (bind(0), bind(0));
    let (px, kx) = bx_book
        .begin_pair(&*sx, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (py, ky) = by_book
        .begin_pair(&*sy, PendingRole::Invitee, u64::MAX)
        .unwrap();
    // набирает только получатель `y` (адрес `y` отправителю неизвестен): нет встречного набора
    bx_book
        .finish_pair(&*sx, &px, new_friend(&ky, &kx, None))
        .unwrap();
    by_book
        .finish_pair(&*sy, &py, new_friend(&kx, &ky, Some(bx.addr)))
        .unwrap();
    if perm != Permission::Ask {
        // автоприём включается только с подтверждением доверия (Рев. 4)
        assert!(matches!(perm, Permission::AutoAccept(_)));
        assert_eq!(
            by_book.set_permission(&*sy, &py, perm).err(),
            Some(chervo_friends::FriendsError::TrustRequired)
        );
        by_book
            .enable_auto_accept(&*sy, &py, TrustConfirmation::user_confirmed_trust())
            .unwrap();
    }
    let (tmp, recv, outside) = make_dirs();
    let mut cfg = ReceiveConfig::new(recv);
    fcfg(&mut cfg);
    let rx = Rx::new(cfg);
    let src = Tmp::new("src");
    let xpartial = Tmp::new("xpartial");
    let cx = tcfg(xpartial.path());
    let cy = tcfg(rx.root.partial_dir());
    let x = start_side(
        bx,
        sx,
        dx,
        Some(bx_book),
        cx,
        Arc::new(AskAlways),
        Arc::new(NeverPlace),
    );
    // каталог временных данных отправителя живёт, пока жив тест
    std::mem::forget(xpartial);
    let y = start_side(
        by,
        sy,
        dy,
        Some(by_book),
        cy,
        rx.policy.clone(),
        rx.place.clone(),
    );
    let d = Duo {
        x,
        y,
        px,
        py,
        rx,
        tmp,
        outside,
        src,
    };
    assert!(wait_conn(&d.x.engine, &d.px, 20).await, "x not connected");
    assert!(wait_conn(&d.y.engine, &d.py, 20).await, "y not connected");
    settle(&d).await;
    d
}

async fn settle(d: &Duo) {
    let ids = |d: &Duo| {
        (
            d.x.engine.connection(&d.px).map(|c| c.conn_id()),
            d.y.engine.connection(&d.py).map(|c| c.conn_id()),
        )
    };
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let before = ids(d);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let after = ids(d);
        if before == after && after.0.is_some() && after.1.is_some() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "connections did not settle"
        );
    }
}

async fn wait_conn(engine: &Eng, pair: &PairId, secs: u64) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        if engine.connection(pair).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// ---------------------------------------------------------------------- события

fn key_of(e: &TransferEvent) -> TransferKey {
    match e {
        TransferEvent::OfferReceived { key }
        | TransferEvent::OfferAnswered { key, .. }
        | TransferEvent::Started { key }
        | TransferEvent::Progress { key, .. }
        | TransferEvent::Verifying { key }
        | TransferEvent::Preparing { key, .. }
        | TransferEvent::FileReceived { key, .. }
        | TransferEvent::FileDelivered { key, .. }
        | TransferEvent::FileFailed { key, .. }
        | TransferEvent::Paused { key, .. }
        | TransferEvent::Resumed { key }
        | TransferEvent::Completed { key }
        | TransferEvent::Cancelled { key, .. }
        | TransferEvent::Failed { key, .. } => *key,
        _ => panic!("unknown event"),
    }
}

/// Ждёт `OfferReceived` у получателя (вопрос пользователю).
async fn wait_offer(y: &mut Side) -> TransferKey {
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, y.ev.recv()).await {
            Ok(Some(e @ TransferEvent::OfferReceived { .. })) => return key_of(&e),
            Ok(Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. }))) => {
                panic!("ended while waiting for the offer: {e:?}")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("events closed"),
            Err(_) => panic!("timed out waiting for OfferReceived"),
        }
    }
}

async fn accept(y: &mut Side) -> TransferKey {
    let k = wait_offer(y).await;
    y.tr.respond(&k, true).unwrap();
    k
}

/// Получатель спрашивает, мы отвечаем «нет»; отправитель видит `Failed{Declined}`.
async fn ask_then_decline(d: &mut Duo) {
    let k = wait_offer(&mut d.y).await;
    d.y.tr.respond(&k, false).unwrap();
    wait_sender_failed(&mut d.x, FailReason::Declined).await;
}

/// Отправитель получает `Failed{reason}`; у получателя за это время нет вопроса пользователю.
async fn wait_sender_failed(x: &mut Side, reason: FailReason) {
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, x.ev.recv()).await {
            Ok(Some(TransferEvent::Failed { reason: r, .. })) => {
                assert_eq!(r, reason);
                return;
            }
            Ok(Some(e @ TransferEvent::Cancelled { .. })) => panic!("cancelled: {e:?}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("sender events closed"),
            Err(_) => panic!("timed out waiting for Failed"),
        }
    }
}

/// То же, но следит и за получателем: `OfferReceived` там недопустим (предложение отклонено
/// до вопроса пользователю).
async fn expect_declined_silently(d: &mut Duo) {
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        tokio::select! {
            e = d.x.ev.recv() => match e {
                Some(TransferEvent::Failed { reason, .. }) => {
                    assert_eq!(reason, FailReason::Declined);
                    break;
                }
                Some(_) => {}
                None => panic!("sender events closed"),
            },
            e = d.y.ev.recv() => {
                assert!(
                    !matches!(e, Some(TransferEvent::OfferReceived { .. })),
                    "hostile offer was shown to the user"
                );
            }
            () = tokio::time::sleep(left) => panic!("timed out waiting for Failed{{Declined}}"),
        }
    }
    // что успело прийти к получателю, тоже не вопрос
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(200), d.y.ev.recv()).await {
        assert!(!matches!(e, TransferEvent::OfferReceived { .. }));
    }
}

/// `Completed` на обеих сторонах; возвращает события получателя (кроме `Progress`).
/// `auto`: вопрос пользователю недопустим (паника сразу, а не по таймауту).
#[allow(clippy::too_many_arguments)]
async fn finish(
    x: &mut Side,
    kx: &TransferKey,
    px: &PairId,
    y: &mut Side,
    ky: &TransferKey,
    py: &PairId,
    secs: u64,
    auto: bool,
) -> Vec<TransferEvent> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    let (mut gx, mut gy) = (false, false);
    let mut seen = Vec::new();
    while !(gx && gy) {
        assert!(
            tokio::time::Instant::now() < end,
            "transfer did not complete in time (sender done: {gx}, receiver done: {gy})"
        );
        tokio::select! {
            e = x.ev.recv(), if !gx => match e {
                Some(TransferEvent::Completed { key }) if key == *kx => gx = true,
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("sender side ended: {e:?}"),
                Some(_) => {}
                None => panic!("sender events closed"),
            },
            e = y.ev.recv(), if !gy => match e {
                Some(TransferEvent::Completed { key }) if key == *ky => {
                    seen.push(TransferEvent::Completed { key });
                    gy = true;
                }
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("receiver side ended: {e:?}"),
                Some(TransferEvent::Progress { .. }) => {}
                Some(TransferEvent::OfferReceived { .. }) if auto => panic!("auto-accept asked the user"),
                Some(e) => seen.push(e),
                None => panic!("receiver events closed"),
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                let _ = x.engine.connect_now(px);
                let _ = y.engine.connect_now(py);
            }
        }
    }
    seen
}

// ----------------------------------------------------------------------- данные

fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = vec![0u8; n];
    for c in out.chunks_mut(8) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let k = c.len();
        c.copy_from_slice(&v[..k]);
    }
    out
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// Исходные файлы на диске отправителя под служебными именами; имя предложения свободное.
fn sources(d: &Duo, tag: &str, files: &[(&str, Vec<u8>)]) -> Vec<SourceFile> {
    files
        .iter()
        .enumerate()
        .map(|(i, (name, data))| {
            let path = d.src.path().join(format!("{tag}-{i}.bin"));
            fs::write(&path, data).unwrap();
            SourceFile {
                path,
                name: (*name).to_owned(),
            }
        })
        .collect()
}

/// Отправляет предложение (если отправитель ещё занят прошлым, коротко ждёт).
async fn send(d: &Duo, tag: &str, files: &[(&str, Vec<u8>)]) -> TransferKey {
    let srcs = sources(d, tag, files);
    for _ in 0..50 {
        match d.x.tr.send(&d.px, srcs.clone()) {
            Ok(k) => return k,
            Err(chervo_transfer::TransferError::Busy) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("send failed: {e:?}"),
        }
    }
    panic!("sender stayed busy");
}

/// Полный круг с вопросом пользователю: отправить, принять, дождаться обоих `Completed`.
async fn round_ask(d: &mut Duo, tag: &str, files: &[(&str, Vec<u8>)]) {
    let kx = send(d, tag, files).await;
    let ky = accept(&mut d.y).await;
    assert_eq!(kx.id, ky.id);
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 120, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Полный круг без вопроса (автоприём): вопроса пользователю быть не должно.
async fn round_auto(d: &mut Duo, tag: &str, files: &[(&str, Vec<u8>)]) {
    let kx = send(d, tag, files).await;
    // ключ получателя тот же: у обоих один `id`
    let ky = TransferKey {
        pair: d.py,
        id: kx.id,
    };
    let seen = finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 120, true).await;
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, TransferEvent::OfferReceived { .. })),
        "auto-accept asked the user"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
}

fn first_of(d: &Duo) -> PathBuf {
    d.rx.root.root().to_path_buf()
}

/// Ожидаемое дерево по списку чистых относительных путей (каталоги с `/` на конце).
fn expected_tree(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let mut acc = String::new();
        let parts: Vec<&str> = n.split('/').collect();
        for (i, p) in parts.iter().enumerate() {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(p);
            if i + 1 < parts.len() {
                out.push(format!("{acc}/"));
            } else {
                out.push(acc.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Нет каталогов состояния (32 hex) во временном каталоге: передача убрана (с короткой паузой).
async fn assert_partial_clean(d: &Duo) {
    let part = d.rx.root.partial_dir().to_path_buf();
    for _ in 0..50 {
        let left: Vec<String> = fs::read_dir(&part)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        if left.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("state dirs left in partial dir");
}

fn assert_outside_untouched(d: &Duo) {
    assert!(
        fs::read_dir(&d.outside).unwrap().next().is_none(),
        "something appeared outside the receive root"
    );
    // рядом с корнем приёма (в `tmp`) только сам корень и `outside`
    let mut names: Vec<String> = fs::read_dir(d.tmp.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["outside".to_owned(), "recv".to_owned()]);
}

fn assert_inside_root(d: &Duo, rel: &str) -> PathBuf {
    let mut p = first_of(d);
    for c in rel.split('/') {
        p.push(c);
    }
    let canon = fs::canonicalize(&p).unwrap_or_else(|_| panic!("missing {rel}"));
    assert!(canon.starts_with(d.rx.root.root()), "{rel} outside of root");
    p
}

/// Метки принятого файла: Unix без бита `x`; Windows `Zone.Identifier` ровно как в спецификации.
fn assert_marks(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(p).unwrap().permissions().mode();
        assert_eq!(m & 0o111, 0, "executable bit on a received file");
    }
    #[cfg(windows)]
    {
        let mut s = p.as_os_str().to_os_string();
        s.push(":Zone.Identifier");
        let got = fs::read_to_string(PathBuf::from(s)).expect("Zone.Identifier stream missing");
        assert_eq!(got, "[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    let _ = p;
}

fn assert_content(p: &Path, want: &[u8]) {
    let mut got = Vec::new();
    fs::File::open(p).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), want.len(), "size differs");
    assert!(got == want, "bytes differ");
    assert_eq!(sha256(&got), sha256(want), "sha256 differs");
}

// ------------------------------------------------------------------------ тесты

#[tokio::test]
async fn net_tree_received_inside_root() {
    let mut d = duo(Permission::Ask, |_| {}).await;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..50u64 {
        let name = match i % 3 {
            0 => format!("f{i}.txt"),
            1 => format!("d{}/f{i}.dat", i % 4),
            _ => format!("top{}/mid{}/f{i}.bin", i % 4, i % 3),
        };
        let size = if i % 17 == 0 {
            0
        } else if i == 22 {
            2 << 20
        } else {
            usize::try_from(i).unwrap() * 61 + 5
        };
        files.push((name, rand_bytes(i + 1, size)));
    }
    let offer: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    round_ask(&mut d, "tree", &offer).await;
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(tree(d.rx.root.root()), expected_tree(&names));
    for (n, data) in &files {
        let p = assert_inside_root(&d, n);
        assert_content(&p, data);
        assert_marks(&p);
    }
    println!(
        "net_tree_received_inside_root: os={} files={}",
        std::env::consts::OS,
        files.len()
    );
    assert_partial_clean(&d).await;
    assert_outside_untouched(&d);
}

#[tokio::test]
async fn net_hostile_offer_declined() {
    let mut d = duo(Permission::Ask, |_| {}).await;
    let hostile = [
        "../x",
        "a/../../b",
        "/etc/passwd",
        "C:/Windows/x",
        "a\\b",
        "a//b",
        "a\u{7}b",
        "x/./y",
    ];
    for (i, name) in hostile.iter().enumerate() {
        // честный файл в том же предложении не спасает: отклоняется предложение целиком
        let _ = send(
            &d,
            &format!("h{i}"),
            &[("ok.txt", b"fine".to_vec()), (name, b"evil".to_vec())],
        )
        .await;
        expect_declined_silently(&mut d).await;
        assert_eq!(d.rx.policy.declined_hostile(), (i + 1) as u64);
        assert!(
            tree(d.rx.root.root()).is_empty(),
            "root changed by {name:?}"
        );
        assert_outside_untouched(&d);
    }
    // слишком глубокое
    let deep = vec!["d"; 17].join("/");
    let _ = send(&d, "deep", &[(&deep, b"x".to_vec())]).await;
    expect_declined_silently(&mut d).await;
    assert!(tree(d.rx.root.root()).is_empty());
    assert_partial_clean(&d).await;
}

#[tokio::test]
async fn net_rewritten_names_asked_not_auto() {
    // друг с автоприёмом, но имена изменяются: вопрос пользователю
    let perm = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1 << 30,
        max_files: 100,
    });
    let mut d = duo(perm, |_| {}).await;
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("CON.txt", b"con".to_vec()),
        ("ab:c.txt", b"colon".to_vec()),
        (".hidden", b"hid".to_vec()),
        ("x/y/z.jpg", b"jpg".to_vec()),
    ];
    round_ask(&mut d, "rw", &files).await;
    let want = ["_CON.txt", "ab_c.txt", "_hidden", "x/y/z.jpg"];
    assert_eq!(tree(d.rx.root.root()), expected_tree(&want));
    for ((_, data), rel) in files.iter().zip(want) {
        let p = assert_inside_root(&d, rel);
        assert_content(&p, data);
        assert_marks(&p);
    }
    assert_partial_clean(&d).await;
    assert_outside_untouched(&d);
}

#[tokio::test]
async fn net_auto_accept_clean_offer() {
    let perm = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1 << 30,
        max_files: 100,
    });
    let mut d = duo(perm, |_| {}).await;
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("Photos/IMG_0001.jpg", rand_bytes(1, 300_000)),
        ("Photos/IMG_0002.jpg", rand_bytes(2, 1000)),
        ("notes.txt", b"hello".to_vec()),
    ];
    round_auto(&mut d, "auto", &files).await;
    assert_eq!(
        tree(d.rx.root.root()),
        expected_tree(&["Photos/IMG_0001.jpg", "Photos/IMG_0002.jpg", "notes.txt"])
    );
    for (n, data) in &files {
        let p = assert_inside_root(&d, n);
        assert_content(&p, data);
        assert_marks(&p);
    }
    assert_partial_clean(&d).await;
}

#[tokio::test]
async fn net_collisions_never_overwrite_user_files() {
    let mut d = duo(Permission::Ask, |_| {}).await;
    let root = first_of(&d);
    // файлы и папка пользователя
    fs::write(root.join("report.txt"), b"USER ORIGINAL").unwrap();
    fs::create_dir(root.join("Photos")).unwrap();
    fs::write(root.join("Photos").join("keep.jpg"), b"USER PHOTO").unwrap();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("report.txt", b"from friend".to_vec()),
        ("Photos/1.jpg", b"friend photo".to_vec()),
        ("a.txt", b"lower".to_vec()),
        ("A.txt", b"upper".to_vec()),
    ];
    round_ask(&mut d, "col", &files).await;
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"USER ORIGINAL");
    assert_eq!(
        fs::read(root.join("report (2).txt")).unwrap(),
        b"from friend"
    );
    assert_eq!(
        fs::read(root.join("Photos").join("keep.jpg")).unwrap(),
        b"USER PHOTO"
    );
    assert!(
        !root.join("Photos").join("1.jpg").exists(),
        "entered a user folder"
    );
    assert_eq!(
        fs::read(root.join("Photos (2)").join("1.jpg")).unwrap(),
        b"friend photo"
    );
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"lower");
    assert_eq!(fs::read(root.join("A (2).txt")).unwrap(), b"upper");
    assert_eq!(
        tree(&root),
        expected_tree(&[
            "A (2).txt",
            "Photos/keep.jpg",
            "Photos (2)/1.jpg",
            "a.txt",
            "report (2).txt",
            "report.txt"
        ])
    );
    // второй приём тех же имён: ещё одна копия, прежние файлы целы
    round_ask(&mut d, "col2", &files[..1]).await;
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"USER ORIGINAL");
    assert_eq!(
        fs::read(root.join("report (2).txt")).unwrap(),
        b"from friend"
    );
    assert_eq!(
        fs::read(root.join("report (3).txt")).unwrap(),
        b"from friend"
    );
    assert_partial_clean(&d).await;
    assert_outside_untouched(&d);
}

#[tokio::test]
async fn net_risky_classes_never_auto_accepted() {
    let perm = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1 << 30,
        max_files: 1000,
    });
    let mut d = duo(perm, |_| {}).await;
    let risky = [
        "setup.exe",
        "run.bat",
        "script.ps1",
        "link.lnk",
        "tool.sh",
        "disk.iso",
        "mac.dmg",
        "macro.docm",
        "book.xlsm",
        "page.html",
        "photo.jpg.exe",
        "My.app/Contents/MacOS/My",
        "report.doc",
        "pic.svg",
        "x.vb\u{17F}",
    ];
    for (i, name) in risky.iter().enumerate() {
        let _ = send(&d, &format!("r{i}"), &[(name, b"payload".to_vec())]).await;
        // вопрос пользователю обязателен; отказываем
        ask_then_decline(&mut d).await;
        assert!(tree(d.rx.root.root()).is_empty(), "{name} was stored");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // принятое вручную всё равно не получает бита исполнения и метки
    round_ask(&mut d, "man", &[("setup.exe", b"MZ".to_vec())]).await;
    let p = assert_inside_root(&d, "setup.exe");
    assert_marks(&p);
    // архивы обычные файлы (решение владельца): автоприём без вопроса
    round_auto(&mut d, "zip", &[("photos.zip", rand_bytes(9, 5000))]).await;
    assert_inside_root(&d, "photos.zip");
    assert_partial_clean(&d).await;
    assert_outside_untouched(&d);
}

#[tokio::test]
async fn net_auto_accept_unknown_type_asks() {
    // Рев. 3: от друга с автоприёмом сами принимаются только типы из списка; неизвестное
    // расширение, `.bin` и файл без расширения это вопрос пользователю
    let perm = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1,
        max_files: 1,
    });
    let mut d = duo(perm, |_| {}).await;
    for (i, name) in ["data.dat", "weights.bin", "README", "report.doc", "pic.svg"]
        .iter()
        .enumerate()
    {
        let _ = send(&d, &format!("u{i}"), &[(name, b"payload".to_vec())]).await;
        ask_then_decline(&mut d).await;
        assert!(tree(d.rx.root.root()).is_empty(), "{name} was stored");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // известный тип проходит без вопроса, неизвестный принимается по ответу «да»
    round_auto(&mut d, "u-ok", &[("clip.mp4", rand_bytes(1, 4000))]).await;
    round_ask(&mut d, "u-man", &[("data.dat", rand_bytes(2, 3000))]).await;
    assert_eq!(
        tree(d.rx.root.root()),
        expected_tree(&["clip.mp4", "data.dat"])
    );
    assert_partial_clean(&d).await;
}

#[tokio::test]
async fn net_auto_accept_no_volume_limit_only_free_space() {
    // лимитов объёма и числа файлов нет: подряд несколько приёмов и много файлов без вопроса;
    // единственная защита это свободное место после приёма (по умолчанию 10 %)
    let perm = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1,
        max_files: 1,
    });
    let mut d = duo(perm, |_| {}).await;
    for i in 0..4u8 {
        round_auto(
            &mut d,
            &format!("n{i}"),
            &[(&format!("a{i}.jpg"), rand_bytes(u64::from(i), 20_000))],
        )
        .await;
    }
    let many: Vec<(String, Vec<u8>)> = (0..30u8)
        .map(|i| (format!("m/f{i}.png"), rand_bytes(u64::from(i), 100)))
        .collect();
    let many_ref: Vec<(&str, Vec<u8>)> =
        many.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    round_auto(&mut d, "many", &many_ref).await;
    // свободного места осталось ровно на минимум: любой файл свыше этого это вопрос
    let keep = TEST_VOLUME / 10;
    d.rx.free.store(keep + 1000, Ordering::SeqCst);
    let _ = send(&d, "full", &[("big.mp4", rand_bytes(9, 1001))]).await;
    ask_then_decline(&mut d).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    round_auto(&mut d, "fits", &[("small.mp4", rand_bytes(8, 1000))]).await;
    assert_partial_clean(&d).await;
}

// ------------------------------------------------- перезапуск между ссылкой и `Placed`

/// Оболочка: первый `place` ставит файл (жёсткая ссылка и запись журнала), сообщает о
/// размещении и «зависает» (процесс умер до записи `Placed`). Остальные вызовы проходят.
struct Hold {
    inner: Arc<ReceivePlacement>,
    first: AtomicBool,
    linked: Mutex<mpsc::Sender<PathBuf>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Placement for Hold {
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        let placed = self.inner.place(f)?;
        if self.first.swap(true, Ordering::SeqCst) {
            return Ok(placed);
        }
        let _ = self.linked.lock().unwrap().send(placed.path.clone());
        let _ = self
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(120));
        Err(PlaceError::Io(std::io::ErrorKind::Other))
    }

    fn prepare(&self, key: &TransferKey, files: &[OfferedFile]) -> Result<(), PlaceError> {
        self.inner.prepare(key, files)
    }

    fn forget(&self, key: &TransferKey) {
        self.inner.forget(key);
    }

    fn partial_base(&self, key: &TransferKey) -> Option<PathBuf> {
        self.inner.partial_base(key)
    }

    fn extra_partial_dirs(&self) -> Vec<PathBuf> {
        self.inner.extra_partial_dirs()
    }
}

#[tokio::test]
async fn net_receiver_restart_idempotent_placement() {
    // свой стенд: размещение получателя заменено оболочкой
    let (sx, sy) = (Arc::new(MemStore::default()), Arc::new(MemStore::default()));
    let (dx, dy) = (Arc::new(Tmp::new("bx")), Arc::new(Tmp::new("by")));
    let mut bx_book = FriendBook::open(&dx.path().join("friends.chfl"), &*sx).unwrap();
    let mut by_book = FriendBook::open(&dy.path().join("friends.chfl"), &*sy).unwrap();
    let (bx, by) = (bind(0), bind(0));
    let (px, kx) = bx_book
        .begin_pair(&*sx, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (py, ky) = by_book
        .begin_pair(&*sy, PendingRole::Invitee, u64::MAX)
        .unwrap();
    bx_book
        .finish_pair(&*sx, &px, new_friend(&ky, &kx, None))
        .unwrap();
    by_book
        .finish_pair(&*sy, &py, new_friend(&kx, &ky, Some(bx.addr)))
        .unwrap();
    let (tmp, recv, outside) = make_dirs();
    let rx = Rx::new(ReceiveConfig::new(recv));
    let xpartial = Tmp::new("xpartial");
    let (link_tx, link_rx) = mpsc::channel::<PathBuf>();
    let (rel_tx, rel_rx) = mpsc::channel::<()>();
    let hold = Arc::new(Hold {
        inner: rx.place.clone(),
        first: AtomicBool::new(false),
        linked: Mutex::new(link_tx),
        release: Mutex::new(rel_rx),
    });
    let mut x = start_side(
        bx,
        sx,
        dx,
        Some(bx_book),
        tcfg(xpartial.path()),
        Arc::new(AskAlways),
        Arc::new(NeverPlace),
    );
    let mut y = start_side(
        by,
        sy,
        dy,
        Some(by_book),
        tcfg(rx.root.partial_dir()),
        rx.policy.clone(),
        hold,
    );
    assert!(wait_conn(&x.engine, &px, 20).await);
    assert!(wait_conn(&y.engine, &py, 20).await);
    tokio::time::sleep(Duration::from_millis(3000)).await;

    let src = Tmp::new("src");
    let data: Vec<(&str, Vec<u8>)> = vec![
        ("doc/a.txt", rand_bytes(1, 3 << 20)),
        ("doc/b.txt", rand_bytes(2, 1000)),
    ];
    let srcs: Vec<SourceFile> = data
        .iter()
        .enumerate()
        .map(|(i, (n, b))| {
            let path = src.path().join(format!("s{i}.bin"));
            fs::write(&path, b).unwrap();
            SourceFile {
                path,
                name: (*n).to_owned(),
            }
        })
        .collect();
    let kx_key = x.tr.send(&px, srcs).unwrap();
    let ky_key = accept(&mut y).await;
    assert_eq!(kx_key.id, ky_key.id);
    // ждём, пока первый файл поставлен ссылкой, но `Placed` ещё не записан
    let mut linked: Option<PathBuf> = None;
    for _ in 0..600 {
        if let Ok(p) = link_rx.try_recv() {
            linked = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let linked = linked.expect("no file reached placement");
    assert!(linked.starts_with(rx.root.root()));

    // «убийство» получателя: без ожидания остановки (поток размещения занят)
    let Side {
        engine,
        t,
        store,
        bookdir,
        tr,
        ev,
        addr,
        tcfg: ycfg,
    } = y;
    tr.shutdown();
    drop(tr);
    drop(ev);
    engine.shutdown();
    t.shutdown();
    drop(engine);
    drop(t);

    // запуск на том же порту, размещение и политика создаются заново над той же папкой
    let mut rebound = None;
    for _ in 0..50 {
        let allow = AllowSet::new();
        let filter: Arc<dyn PeerFilter> = allow.clone();
        match QuinnTransport::bind(addr, quinn_cfg(), filter) {
            Ok(t) => {
                rebound = Some(Bound {
                    t: Arc::new(t),
                    allow,
                    addr,
                });
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let rx2 = Rx::new(rx.cfg.clone());
    let mut y2 = start_side(
        rebound.expect("port not freed"),
        store,
        bookdir,
        None,
        ycfg,
        rx2.policy.clone(),
        rx2.place.clone(),
    );
    finish(&mut x, &kx_key, &px, &mut y2, &ky_key, &py, 180, false).await;

    // одна копия на файл, прежний путь, никаких `(2)`
    let root = rx2.root.root().to_path_buf();
    assert_eq!(tree(&root), expected_tree(&["doc/a.txt", "doc/b.txt"]));
    let rel = linked.strip_prefix(&root).unwrap().to_path_buf();
    assert!(
        rel == Path::new("doc").join("a.txt") || rel == Path::new("doc").join("b.txt"),
        "replay chose another name"
    );
    assert_content(&root.join("doc").join("a.txt"), &data[0].1);
    assert_content(&root.join("doc").join("b.txt"), &data[1].1);
    for _ in 0..50 {
        let n = fs::read_dir(rx2.root.partial_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().len() == 32)
            .count();
        if n == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
    // отпускаем «мёртвый» поток размещения: он вернёт ошибку уже после проверок
    let _ = rel_tx.send(());
    drop(tmp);
    drop(xpartial);
    drop(src);
}

// ------------------------------------- Рев. 5: не хватает места, другая папка приёма

/// Вторая папка приёма рядом с основной (Unix: права 0o700).
fn open_second_root(d: &Duo) -> ReceiveRoot {
    let dir = d.tmp.path().join("recv2");
    fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    ReceiveRoot::open(&ReceiveConfig::new(dir)).unwrap()
}

/// В `.chervo-partial` папки нет каталогов состояния (32 hex): передача убрана.
async fn assert_partial_clean_of(root: &ReceiveRoot) {
    for _ in 0..50 {
        let left = fs::read_dir(root.partial_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().len() == 32)
            .count();
        if left == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("state dirs left in a partial dir");
}

fn auto_perm() -> Permission {
    Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1,
        max_files: 1,
    })
}

#[tokio::test]
async fn net_insufficient_space_asks_then_accepts_into_other_folder() {
    // друг с автоприёмом, файл безопасного типа, но в основной папке не хватает места:
    // автоприёма нет, вопрос с числами; пользователь выбирает другую папку, файл лежит там
    let mut d = duo(auto_perm(), |c| c.min_free_percent = 0).await;
    let data = rand_bytes(5, 200_000);
    d.rx.free.store(150_000, Ordering::SeqCst);
    let kx = send(&d, "o", &[("pic.jpg", data.clone())]).await;
    let ky = wait_offer(&mut d.y).await;
    let view = d.y.tr.offer(&ky).unwrap();
    let SpaceCheck::Short(s) = d.rx.policy.space_check(&view) else {
        panic!("expected a shortfall");
    };
    assert_eq!((s.needed, s.available), (200_000, 150_000));
    assert_eq!(s.root, d.rx.root.root());
    let text = insufficient_space_text(&s);
    assert!(
        text.contains("195,3 КБ") && text.contains("146,4 КБ"),
        "{text}"
    );
    assert!(text.contains("другую папку"), "{text}");

    let root2 = open_second_root(&d);
    accept_into(&d.y.tr, &d.rx.place, &ky, root2.clone()).unwrap();
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 120, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // файл в выбранной папке, основная не тронута, временные данные убраны с обоих томов
    assert_eq!(tree(root2.root()), vec!["pic.jpg".to_owned()]);
    let p = root2.root().join("pic.jpg");
    assert!(fs::canonicalize(&p).unwrap().starts_with(root2.root()));
    assert_content(&p, &data);
    assert_marks(&p);
    assert!(tree(d.rx.root.root()).is_empty(), "main root untouched");
    assert_partial_clean(&d).await;
    assert_partial_clean_of(&root2).await;
    assert!(fs::read_dir(&d.outside).unwrap().next().is_none());
}

#[tokio::test]
async fn net_other_folder_rechecks_space_and_offer_stays_pending() {
    let mut d = duo(auto_perm(), |c| c.min_free_percent = 0).await;
    let data = rand_bytes(6, 200_000);
    d.rx.free.store(150_000, Ordering::SeqCst);
    d.rx.free2.store(100_000, Ordering::SeqCst);
    let kx = send(&d, "o", &[("clip.mp4", data.clone())]).await;
    let ky = wait_offer(&mut d.y).await;
    let root2 = open_second_root(&d);

    // на новой папке тоже мало: отказ с числами для новой папки, предложение ждёт ответа
    match accept_into(&d.y.tr, &d.rx.place, &ky, root2.clone()) {
        Err(AcceptIntoError::Root(ChooseRootError::Insufficient(s))) => {
            assert_eq!((s.needed, s.available), (200_000, 100_000));
            assert_eq!(s.root, root2.root());
        }
        other => panic!("expected Insufficient, got {other:?}"),
    }
    assert!(d.y.tr.offer(&ky).is_some(), "the offer is still waiting");
    assert!(tree(root2.root()).is_empty());

    // места прибавилось: тот же вызов проходит, передача идёт в новую папку
    d.rx.free2.store(10_000_000, Ordering::SeqCst);
    accept_into(&d.y.tr, &d.rx.place, &ky, root2.clone()).unwrap();
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 120, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tree(root2.root()), vec!["clip.mp4".to_owned()]);
    assert_content(&root2.root().join("clip.mp4"), &data);
    assert!(tree(d.rx.root.root()).is_empty());
    assert_partial_clean(&d).await;
    assert_partial_clean_of(&root2).await;

    // вторая передача: основная папка снова годится и принимает как обычно (выбор не «прилип»)
    d.rx.free.store(TEST_VOLUME, Ordering::SeqCst);
    round_auto(&mut d, "again", &[("b.jpg", rand_bytes(7, 3000))]).await;
    assert!(tree(d.rx.root.root()).contains(&"b.jpg".to_owned()));
}

#[tokio::test]
async fn net_accept_into_unknown_offer_is_an_error() {
    let d = duo(Permission::Ask, |_| {}).await;
    let root2 = open_second_root(&d);
    let ghost = TransferKey {
        pair: d.py,
        id: chervo_transfer::TransferId([9; 16]),
    };
    assert_eq!(
        accept_into(&d.y.tr, &d.rx.place, &ghost, root2).err(),
        Some(AcceptIntoError::NoSuchOffer)
    );
}
