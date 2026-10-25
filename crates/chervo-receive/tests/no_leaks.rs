#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Тест утечек в журналы (этап 17, B3, решение 1b, C21; BRIEF 7 «не логировать имена файлов,
//! IP и ключи»; T8, T12 L3, T15(в)).
//!
//! Журналов в продукте нет, поэтому «журнал» здесь это всё, что оболочка (CLI, GUI этапа 18)
//! могла бы напечатать: `Debug` и `Display` каждого события, каждой ошибки и каждого
//! возвращаемого значения публичных интерфейсов. Сценарий целиком в одном процессе на
//! 127.0.0.1: приглашение, SAS, соединение, передача двух файлов с именем-меткой, приём,
//! ошибки на каждом шаге, удаление друга с отзывом. Всё напечатанное собирается и
//! сверяется со списком запретного: имена-метки, IP-литералы запуска и порты (`:порт`), ключи
//! (открытые и закрытые; hex, base64, base32, десятичный список байт, префиксы), `PairId`, цифры
//! SAS, текст токена приглашения и отзыва, пути временных каталогов.
//!
//! Почему здесь (`chervo-receive`): единственный крейт, где в одном процессе доступны движок
//! соединений с настоящим `QuinnTransport`, передачи и приём в папку; `chervo-core` по тесту
//! `layout` не может зависеть от транспорта.

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::RouteSources;
use chervo_connect::{
    AllowSet, Clock, ConnectConfig, Engine, EngineEvent, EngineEvents, InviteAddrs, InviteOutcome,
    RouteProbe, SystemClock,
};
use chervo_friends::{FriendBook, FriendState};
use chervo_identity::{IdentityError, ListKeyStore, PairId, SecretStore};
use chervo_receive::{
    DiskSpace, ReceiveConfig, ReceiveLimits, ReceivePlacement, ReceivePolicy, ReceiveRoot,
    plan_offer_for_root, sanitize_path,
};
use chervo_transfer::{
    AskAlways, CompletedFile, PlaceError, Placed, Placement, SourceFile, TransferConfig,
    TransferEvent, TransferEvents, TransferKey, Transfers,
};
use chervo_transport::{Connection, PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use common::{Tmp, tree};
use redact_kit::{Needles, b32, b64, scan};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

// ------------------------------------------------------------------ метки и сборщик

/// Имя-метка файла верхнего уровня и вложенного; каталог-метка; имя друга; путь исходника.
const MARK_FILE: &str = "ZQMARKER";
const MARK_DIR: &str = "ZQMARKDIR";
const MARK_FRIEND: &str = "FRNDMARK";
const MARK_SRC: &str = "ZQSRCDIR";

type Sink = Arc<Mutex<Vec<(String, String)>>>;
type SpaceFn = dyn Fn(&Path) -> Option<DiskSpace> + Send + Sync;

fn rec(sink: &Sink, label: &str, text: String) {
    sink.lock().unwrap().push((label.to_owned(), text));
}

/// Записывает `Debug` (обычный и «красивый»).
fn dbg_rec(sink: &Sink, label: &str, v: &dyn Debug) {
    rec(sink, label, format!("{v:?}"));
    rec(sink, label, format!("{v:#?}"));
}

/// Записывает `Display` и `Debug` ошибки.
fn err_rec<E: Display + Debug>(sink: &Sink, label: &str, e: &E) {
    rec(sink, label, format!("{e}"));
    dbg_rec(sink, label, e);
}

// ---------------------------------------------------------------- узлы сценария

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

    fn source_for(&self, _target: SocketAddr) -> Option<std::net::IpAddr> {
        None
    }
}

type Eng = Engine<QuinnTransport, MemStore>;

struct NeverPlace;

impl Placement for NeverPlace {
    fn place(&self, _f: &CompletedFile) -> Result<Placed, PlaceError> {
        Err(PlaceError::Refused)
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

struct Node {
    engine: Arc<Eng>,
    t: Arc<QuinnTransport>,
    store: Arc<MemStore>,
    tr: Transfers<Eng>,
    ev: mpsc::UnboundedReceiver<EngineEvent>,
    tev: mpsc::UnboundedReceiver<TransferEvent>,
    addr: SocketAddr,
    _dir: Tmp,
}

fn record_engine_event(sink: &Sink, label: &str, e: &EngineEvent) {
    dbg_rec(sink, &format!("{label}:EngineEvent"), e);
    // оболочка может напечатать и поля события по отдельности
    let l = format!("{label}:EngineEvent.field");
    match e {
        EngineEvent::Connected { pair, path } => {
            dbg_rec(sink, &l, pair);
            dbg_rec(sink, &l, path);
        }
        EngineEvent::Disconnected { pair } | EngineEvent::ClockSkew { pair } => {
            dbg_rec(sink, &l, pair);
        }
        EngineEvent::SasReady { pair, sas } => {
            dbg_rec(sink, &l, pair);
            dbg_rec(sink, &l, sas);
        }
        EngineEvent::InviteFinished { pair, outcome } => {
            dbg_rec(sink, &l, pair);
            dbg_rec(sink, &l, outcome);
        }
        EngineEvent::KeyProblem { pair, status } => {
            dbg_rec(sink, &l, pair);
            dbg_rec(sink, &l, status);
        }
        EngineEvent::MappingChanged { status } => dbg_rec(sink, &l, status),
        EngineEvent::Unreachable { pair, diagnosis } => {
            dbg_rec(sink, &l, pair);
            dbg_rec(sink, &l, diagnosis);
        }
        _ => {}
    }
}

fn record_transfer_event(sink: &Sink, label: &str, e: &TransferEvent) {
    dbg_rec(sink, &format!("{label}:TransferEvent"), e);
}

fn pump_engine(
    sink: Sink,
    label: &'static str,
    mut ev: EngineEvents,
) -> mpsc::UnboundedReceiver<EngineEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(e) = ev.recv().await {
            record_engine_event(&sink, label, &e);
            if tx.send(e).is_err() {
                break;
            }
        }
    });
    rx
}

fn pump_transfers(
    sink: Sink,
    label: &'static str,
    mut ev: TransferEvents,
) -> mpsc::UnboundedReceiver<TransferEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(e) = ev.recv().await {
            record_transfer_event(&sink, label, &e);
            if tx.send(e).is_err() {
                break;
            }
        }
    });
    rx
}

fn start_node(
    sink: &Sink,
    label: &'static str,
    policy: Arc<dyn chervo_transfer::AcceptPolicy>,
    placement: Arc<dyn Placement>,
    partial: &Path,
) -> Node {
    let store = Arc::new(MemStore::default());
    let dir = Tmp::new(&format!("leak-{label}"));
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let allow_dbg = allow.clone();
    let qcfg = QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    };
    let t = Arc::new(
        QuinnTransport::bind(SocketAddr::from(([127, 0, 0, 1], 0)), qcfg, filter).unwrap(),
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], t.local_addrs()[0].port()));
    let book = FriendBook::open_unanchored(&dir.path().join("friends.chfl"), &*store).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(Probe);
    let (engine, events) = Engine::start(
        t.clone(),
        allow,
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
    dbg_rec(sink, &format!("{label}:StreamInbox"), &inbox);
    dbg_rec(sink, &format!("{label}:AllowSet"), &*allow_dbg);
    let mut tcfg = TransferConfig::new(partial.to_path_buf());
    tcfg.progress_interval = Duration::from_millis(20);
    tcfg.checkpoint_interval = Duration::from_millis(100);
    tcfg.ctl_in_per_min = 10_000;
    dbg_rec(sink, &format!("{label}:TransferConfig"), &tcfg);
    let (tr, tev) = Transfers::start(engine.clone(), inbox, policy, placement, tcfg).unwrap();
    dbg_rec(sink, &format!("{label}:QuinnTransport"), &*t);
    let ev = pump_engine(sink.clone(), label, events);
    let tev = pump_transfers(sink.clone(), label, tev);
    Node {
        engine,
        t,
        store,
        tr,
        ev,
        tev,
        addr,
        _dir: dir,
    }
}

async fn wait_ev<T>(
    rx: &mut mpsc::UnboundedReceiver<T>,
    secs: u64,
    what: &str,
    mut pick: impl FnMut(&T) -> bool,
) -> T {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(e)) if pick(&e) => return e,
            Ok(Some(_)) => {}
            Ok(None) => panic!("events closed while waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
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

/// Связь с другом устойчива: она есть, не закрыта, и на каждом опросе (50 мс) в течение 1,5 с
/// это одно и то же соединение. Оба движка звонят друг другу в один такт, и одно из двух
/// соединений закрывается как дубль через несколько миллисекунд после публикации; отправка
/// сразу после первой публикации попадала в это окно (этап 14б, отчёт о флаке).
/// `CHERVO_NOLEAKS_NO_SETTLE=1`: ждать только первого попавшегося соединения, как раньше. Это
/// проверка продуктовой правки (повтор предложения) на настоящем стеке без ожидания в тесте.
async fn wait_stable_conn(engine: &Eng, pair: &PairId, secs: u64) -> bool {
    let no_settle = std::env::var("CHERVO_NOLEAKS_NO_SETTLE").as_deref() == Ok("1");
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut seen: Option<(u64, tokio::time::Instant)> = None;
    while tokio::time::Instant::now() < end {
        match engine.connection(pair) {
            Some(_) if no_settle => return true,
            Some(c)
                if tokio::time::timeout(Duration::ZERO, c.closed())
                    .await
                    .is_err() =>
            {
                let id = c.conn_id();
                match seen {
                    Some((sid, since)) if sid == id => {
                        if since.elapsed() >= Duration::from_millis(1500) {
                            return true;
                        }
                    }
                    _ => seen = Some((id, tokio::time::Instant::now())),
                }
            }
            _ => seen = None,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn unix_now() -> u64 {
    SystemClock::new().now_unix()
}

fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 24) as u8
        })
        .collect()
}

// -------------------------------------------------------------------- самопроверка

/// Охрана сама видит утечку: тип с `derive(Debug)` печатает всё, а сборщик это находит.
#[test]
fn scanner_detects_a_leaky_derive() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Leaky {
        name: String,
        addr: SocketAddr,
        key: [u8; 32],
        pair: Vec<u8>,
    }
    let key: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let leaky = Leaky {
        name: format!("{MARK_FILE}-x.txt"),
        addr: "127.0.0.1:40123".parse().unwrap(),
        key: key.clone().try_into().unwrap(),
        pair: vec![1, 2, 3],
    };
    let sink: Sink = Arc::default();
    dbg_rec(&sink, "leaky", &leaky);
    let mut n = Needles::default();
    n.add("mark", MARK_FILE);
    n.add("ip", "127.0.0.1");
    n.add("port", ":40123");
    n.bytes("key", &key);
    let hits = scan(&sink.lock().unwrap(), &n);
    let labels: Vec<&str> = hits.iter().map(|(_, n)| n.as_str()).collect();
    for want in ["mark", "ip", "port", "key/dec-window0"] {
        assert!(
            labels.contains(&want),
            "сборщик не нашёл {want}: {labels:?}"
        );
    }
    // а чистый текст не даёт ложных срабатываний
    let clean: Sink = Arc::default();
    rec(
        &clean,
        "clean",
        "PairId(..) Sas(..) EngineEvent(..)".to_owned(),
    );
    assert!(scan(&clean.lock().unwrap(), &n).is_empty());
    // формы кодирования совпадают с известными значениями
    assert_eq!(b64(b"foobar", false, true), "Zm9vYmFy");
    assert_eq!(b64(b"fooba", false, true), "Zm9vYmE=");
    assert_eq!(b64(b"fooba", false, false), "Zm9vYmE");
    assert_eq!(b32(b"foobar"), "MZXW6YTBOI");
}

// ------------------------------------------------------------------------ сценарий

#[tokio::test]
async fn no_leaks_full_scenario() {
    let sink: Sink = Arc::default();

    // --- приёмная часть Y: настоящая папка приёма, политика «спрашивать»
    let tmp = Tmp::new("leak-root");
    let recv = tmp.path().join("recv");
    std::fs::create_dir(&recv).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&recv, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cfg = ReceiveConfig::new(recv);
    let root = ReceiveRoot::open(&cfg).unwrap();
    let free = Arc::new(AtomicU64::new(1 << 40));
    let probe: Arc<SpaceFn> = {
        let free = free.clone();
        Arc::new(move |_p: &Path| {
            Some(DiskSpace {
                total_bytes: 1 << 40,
                available_bytes: free.load(Ordering::SeqCst),
            })
        })
    };
    let place = Arc::new(ReceivePlacement::new(root.clone(), &cfg).with_space_probe(probe.clone()));
    let policy = Arc::new(ReceivePolicy::with_space_probe(root.clone(), &cfg, probe));
    dbg_rec(&sink, "ReceiveConfig", &cfg);
    dbg_rec(&sink, "ReceiveRoot", &root);
    dbg_rec(&sink, "ReceivePlacement", &*place);
    dbg_rec(&sink, "ReceivePolicy", &*policy);

    let xpartial = Tmp::new("leak-xpartial");
    let mut x = start_node(
        &sink,
        "X",
        Arc::new(AskAlways),
        Arc::new(NeverPlace),
        xpartial.path(),
    );
    let mut y = start_node(
        &sink,
        "Y",
        policy.clone(),
        place.clone(),
        root.partial_dir(),
    );

    // ================================================================ приглашение и SAS
    let (pa, text) = x
        .engine
        .create_invite(300, InviteAddrs::Manual(vec![x.addr]))
        .unwrap();
    dbg_rec(&sink, "create_invite.pair", &pa);
    let pb = y.engine.accept_invite(&text).unwrap();
    dbg_rec(&sink, "accept_invite.pair", &pb);

    let sas_x = match wait_ev(&mut x.ev, 20, "SAS at X", |e| {
        matches!(e, EngineEvent::SasReady { .. })
    })
    .await
    {
        EngineEvent::SasReady { sas, .. } => sas,
        _ => unreachable!(),
    };
    let sas_y = match wait_ev(&mut y.ev, 20, "SAS at Y", |e| {
        matches!(e, EngineEvent::SasReady { .. })
    })
    .await
    {
        EngineEvent::SasReady { sas, .. } => sas,
        _ => unreachable!(),
    };
    assert_eq!(
        sas_x.digits(),
        sas_y.digits(),
        "the two screens show different SAS"
    );
    let sas_digits = sas_x.digits();
    assert_eq!(sas_digits.chars().filter(char::is_ascii_digit).count(), 8);
    let sas_bytes = *sas_x.as_bytes();

    x.engine.confirm_sas(&pa, true, MARK_FRIEND).unwrap();
    y.engine.confirm_sas(&pb, true, MARK_FRIEND).unwrap();
    for (n, what) in [(&mut x, "X"), (&mut y, "Y")] {
        let e = wait_ev(&mut n.ev, 20, what, |e| {
            matches!(e, EngineEvent::InviteFinished { .. })
        })
        .await;
        match e {
            EngineEvent::InviteFinished { outcome, .. } => {
                assert_eq!(outcome, InviteOutcome::Added, "{what}: invite not added");
            }
            _ => unreachable!(),
        }
    }
    assert!(
        wait_stable_conn(&x.engine, &pa, 30).await,
        "X not connected to Y"
    );
    assert!(
        wait_stable_conn(&y.engine, &pb, 30).await,
        "Y not connected to X"
    );

    // возвращаемые значения соединения
    for (n, p, l) in [(&x, pa, "X"), (&y, pb, "Y")] {
        dbg_rec(&sink, &format!("{l}:connection"), &n.engine.connection(&p));
        dbg_rec(&sink, &format!("{l}:diagnose"), &n.engine.diagnose(&p));
        dbg_rec(&sink, &format!("{l}:nat_view"), &n.engine.nat_view());
        dbg_rec(
            &sink,
            &format!("{l}:book"),
            &n.engine.read_book(|b| format!("{b:?}")),
        );
        let st = n
            .engine
            .read_book(|b| b.get(&p).map(|f| (f.state, f.permission)));
        dbg_rec(&sink, &format!("{l}:friend state"), &st);
        let pending = n.engine.read_book(|b| b.pending().to_vec());
        dbg_rec(&sink, &format!("{l}:pending"), &pending);
        let eps = n.engine.read_book(|b| b.epoch());
        dbg_rec(&sink, &format!("{l}:epoch"), &eps);
    }

    // ================================================================ передача и приём
    let srcdir = Tmp::new(MARK_SRC);
    let top = rand_bytes(1, 70_000);
    let inner = rand_bytes(2, 150_000);
    let (f_top, f_inner) = (srcdir.path().join("a.bin"), srcdir.path().join("b.bin"));
    std::fs::write(&f_top, &top).unwrap();
    std::fs::write(&f_inner, &inner).unwrap();
    let name_top = format!("{MARK_FILE}-top.txt");
    let name_inner = format!("{MARK_DIR}/{MARK_FILE}-inner.bin");
    let files = vec![
        SourceFile {
            path: f_top.clone(),
            name: name_top.clone(),
        },
        SourceFile {
            path: f_inner.clone(),
            name: name_inner.clone(),
        },
    ];
    dbg_rec(&sink, "SourceFile", &files[0]);
    dbg_rec(&sink, "SourceFile", &files[1]);

    let key_x: TransferKey = loop {
        match x.tr.send(&pa, files.clone()) {
            Ok(k) => break k,
            Err(chervo_transfer::TransferError::Busy) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("send failed: {e:?}"),
        }
    };
    dbg_rec(&sink, "send.key", &key_x);
    let key_y = match wait_ev(&mut y.tev, 30, "OfferReceived", |e| {
        matches!(e, TransferEvent::OfferReceived { .. })
    })
    .await
    {
        TransferEvent::OfferReceived { key } => key,
        _ => unreachable!(),
    };
    assert_eq!(key_x.id, key_y.id);

    // вопрос пользователю: всё, что экран может напечатать о предложении
    let offer = y.tr.offer(&key_y).expect("offer is waiting");
    dbg_rec(&sink, "OfferView", &offer);
    dbg_rec(&sink, "offer.key", &offer.key);
    dbg_rec(&sink, "space_check", &policy.space_check(&offer));
    dbg_rec(
        &sink,
        "evaluate",
        &policy.evaluate(chervo_friends::Permission::Ask, &offer),
    );
    let limits = ReceiveLimits::default();
    dbg_rec(&sink, "ReceiveLimits", &limits);
    let plan = plan_offer_for_root(&offer.files, &limits, &root).unwrap();
    dbg_rec(&sink, "OfferPlan", &plan);
    for f in &plan.files {
        dbg_rec(&sink, "PlannedFile", f);
    }
    dbg_rec(&sink, "TransferStatus.before", &y.tr.status(&key_y));
    // sanitize_path: результат и ошибка
    for hostile in [
        name_inner.as_str(),
        "ZQMARKER/../../x",
        "C:\\ZQMARKER\\x",
        "",
    ] {
        match sanitize_path(hostile, &limits) {
            Ok(r) => dbg_rec(&sink, "sanitize_path.ok", &r),
            Err(e) => err_rec(&sink, "sanitize_path.err", &e),
        }
    }
    y.tr.respond(&key_y, true).unwrap();

    // оба Completed
    let (mut done_x, mut done_y) = (false, false);
    let end = tokio::time::Instant::now() + Duration::from_secs(120);
    while !(done_x && done_y) {
        assert!(
            tokio::time::Instant::now() < end,
            "transfer did not complete"
        );
        tokio::select! {
            e = x.tev.recv(), if !done_x => match e {
                Some(TransferEvent::Completed { .. }) => done_x = true,
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) => panic!("sender ended: {e:?}"),
                Some(_) => {}
                None => panic!("sender events closed"),
            },
            e = y.tev.recv(), if !done_y => match e {
                Some(TransferEvent::Completed { .. }) => done_y = true,
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) => panic!("receiver ended: {e:?}"),
                Some(_) => {}
                None => panic!("receiver events closed"),
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                let _ = x.engine.connect_now(&pa);
                let _ = y.engine.connect_now(&pb);
            }
        }
    }
    dbg_rec(&sink, "TransferStatus.after_x", &x.tr.status(&key_x));
    dbg_rec(&sink, "TransferStatus.after_y", &y.tr.status(&key_y));

    // контроль сценария: метки в самом деле попали на диск получателя (иначе проверка пуста)
    let received = tree(root.root());
    assert!(
        received.iter().any(|n| n.contains(MARK_FILE))
            && received.iter().any(|n| n.contains(MARK_DIR)),
        "marker names not found in the receive folder: {received:?}"
    );

    // ================================================================ ошибки на каждом шаге
    let unknown = PairId::from_bytes([0x5a; 16]);
    // соединение и приглашения
    match y.engine.accept_invite(&format!("{MARK_FILE}-not-a-token")) {
        Ok(_) => panic!("garbage token accepted"),
        Err(e) => err_rec(&sink, "accept_invite(garbage)", &e),
    }
    let mut tampered: Vec<char> = text.chars().collect();
    let mid = tampered.len() / 2;
    tampered[mid] = if tampered[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = tampered.into_iter().collect();
    match y.engine.accept_invite(&tampered) {
        Ok(_) => panic!("tampered token accepted"),
        Err(e) => err_rec(&sink, "accept_invite(tampered)", &e),
    }
    match y.engine.accept_invite(&text) {
        // тот же токен второй раз: любой исход допустим, важен вывод
        Ok(p) => dbg_rec(&sink, "accept_invite(again).pair", &p),
        Err(e) => err_rec(&sink, "accept_invite(again)", &e),
    }
    if let Err(e) = y.engine.confirm_sas(&unknown, true, MARK_FRIEND) {
        err_rec(&sink, "confirm_sas(unknown)", &e);
    }
    if let Err(e) = y.engine.cancel_invite(&unknown) {
        err_rec(&sink, "cancel_invite(unknown)", &e);
    }
    if let Err(e) = y.engine.connect_now(&unknown) {
        err_rec(&sink, "connect_now(unknown)", &e);
    }
    dbg_rec(&sink, "diagnose(unknown)", &y.engine.diagnose(&unknown));
    match y.engine.create_invite(300, InviteAddrs::Manual(vec![])) {
        Ok((p, t)) => {
            dbg_rec(&sink, "create_invite(empty).pair", &p);
            let _ = t;
        }
        Err(e) => err_rec(&sink, "create_invite(empty)", &e),
    }
    // книга друзей
    let r = y
        .engine
        .update_book(|b, s| b.rename(s, &unknown, MARK_FRIEND));
    if let Err(e) = r {
        err_rec(&sink, "rename(unknown)", &e);
    }
    let r = y.engine.update_book(|b, s| b.block(s, &unknown));
    if let Err(e) = r {
        err_rec(&sink, "block(unknown)", &e);
    }
    let r = y
        .engine
        .update_book(|b, s| b.rename(s, &pb, &"x".repeat(5000)));
    if let Err(e) = r {
        err_rec(&sink, "rename(too long)", &e);
    }
    // передачи
    match x.tr.send(&unknown, files.clone()) {
        Ok(_) => panic!("send to a stranger"),
        Err(e) => err_rec(&sink, "send(stranger)", &e),
    }
    let missing = vec![SourceFile {
        path: srcdir.path().join(format!("{MARK_FILE}-missing.bin")),
        name: format!("{MARK_FILE}-missing.txt"),
    }];
    match x.tr.send(&pa, missing) {
        Ok(k) => dbg_rec(&sink, "send(missing).key", &k),
        Err(e) => err_rec(&sink, "send(missing)", &e),
    }
    let bad_name = vec![SourceFile {
        path: f_top.clone(),
        name: format!("{MARK_DIR}/../{MARK_FILE}\0.txt"),
    }];
    match x.tr.send(&pa, bad_name) {
        Ok(k) => dbg_rec(&sink, "send(bad name).key", &k),
        Err(e) => err_rec(&sink, "send(bad name)", &e),
    }
    if let Err(e) = y.tr.respond(&key_y, true) {
        err_rec(&sink, "respond(finished)", &e);
    }
    if let Err(e) = y.tr.cancel(&TransferKey {
        pair: pb,
        id: chervo_transfer::TransferId([0xEE; 16]),
    }) {
        err_rec(&sink, "cancel(unknown)", &e);
    }
    if let Err(e) = y.tr.retry(&TransferKey {
        pair: pb,
        id: chervo_transfer::TransferId([0xEF; 16]),
    }) {
        err_rec(&sink, "retry(unknown)", &e);
    }
    dbg_rec(
        &sink,
        "offer(unknown)",
        &y.tr.offer(&TransferKey {
            pair: pb,
            id: chervo_transfer::TransferId([0xEE; 16]),
        }),
    );
    // приём: папка приёма
    let bad_roots = [
        PathBuf::from(format!("relative/{MARK_FILE}-dir")),
        srcdir.path().join("a.bin"),
        srcdir.path().join(format!("{MARK_FILE}-nothere")),
    ];
    for p in bad_roots {
        match ReceiveRoot::open(&ReceiveConfig::new(p)) {
            Ok(r) => dbg_rec(&sink, "ReceiveRoot::open(odd).ok", &r),
            Err(e) => err_rec(&sink, "ReceiveRoot::open(odd)", &e),
        }
    }
    // враждебное предложение: ошибки плана
    let hostile = common::offered(&[
        ("../../ZQMARKER", 1),
        ("ZQMARKER\\..\\x", 2),
        ("/etc/ZQMARKER", 3),
    ]);
    match plan_offer_for_root(&hostile, &limits, &root) {
        Ok(p) => dbg_rec(&sink, "hostile plan.ok", &p),
        Err(e) => err_rec(&sink, "hostile plan", &e),
    }
    let too_many: Vec<(String, usize)> =
        (0..2000).map(|i| (format!("{MARK_FILE}-{i}"), 1)).collect();
    let refs: Vec<(&str, usize)> = too_many.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    match plan_offer_for_root(&common::offered(&refs), &limits, &root) {
        Ok(p) => dbg_rec(&sink, "many plan.ok", &p),
        Err(e) => err_rec(&sink, "many plan", &e),
    }

    // ================================================================ отзыв (удаление друга)
    let revocation = x
        .engine
        .update_book(|b, s| b.remove(s, &pa, unix_now()))
        .unwrap();
    let revocation_text = revocation.expect("a key existed, so a signed revocation exists");
    let state_after = x
        .engine
        .read_book(|b| b.get(&pa).map(|f| (f.state, f.retired.clone())));
    dbg_rec(&sink, "X:friend after remove", &state_after);
    assert!(matches!(state_after, Some((FriendState::Retired, Some(_)))));
    dbg_rec(
        &sink,
        "X:book after remove",
        &x.engine.read_book(|b| format!("{b:?}")),
    );
    let pending_revocations = x.engine.read_book(|b| b.retired().len());
    dbg_rec(&sink, "X:retired count", &pending_revocations);
    // события после удаления: разрыв соединения и прочее
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let r = x.engine.update_book(|b, s| b.forget_retired(s, &pa));
    dbg_rec(&sink, "forget_retired", &r.is_ok());

    // ================================================================ запретное
    let mut needles = Needles::default();
    // имена и пути
    needles.add("file name", MARK_FILE);
    needles.add("dir name", MARK_DIR);
    needles.add("friend name", MARK_FRIEND);
    needles.add("source dir name", MARK_SRC);
    needles.add("tmp path", "chervo-rcv-");
    needles.add("received root", root.root().to_string_lossy().into_owned());
    needles.add(
        "partial dir",
        root.partial_dir().to_string_lossy().into_owned(),
    );
    // IP и порты запуска
    needles.add("ip", "127.0.0.1");
    for (n, l) in [(&x, "x"), (&y, "y")] {
        needles.add(&format!("port {l}"), format!(":{}", n.addr.port()));
    }
    // PairId обеих сторон
    needles.bytes("pair X", pa.as_bytes());
    needles.bytes("pair Y", pb.as_bytes());
    needles.add("pair X account", pa.account_name());
    needles.add("pair Y account", pb.account_name());
    // SAS
    needles.add("sas digits", sas_digits.clone());
    needles.add("sas digits compact", sas_digits.replace(' ', ""));
    needles.bytes("sas raw", &sas_bytes);
    // токены
    needles.token("invite text", &text);
    needles.token("tampered invite text", &tampered);
    needles.token("revocation text", &revocation_text);
    // открытые ключи
    for (n, p, l) in [(&x, pa, "X"), (&y, pb, "Y")] {
        let keys = n.engine.read_book(|b| {
            b.get(&p).map(|f| {
                (
                    f.friend_ed.to_bytes(),
                    f.friend_x.to_bytes(),
                    f.our_ed.to_bytes(),
                )
            })
        });
        if let Some((fed, fx, oed)) = keys {
            needles.bytes(&format!("{l}: friend ed public"), &fed);
            needles.bytes(&format!("{l}: friend x public"), &fx);
            needles.bytes(&format!("{l}: our ed public"), &oed);
        } else {
            // у X друг теперь Retired, но запись есть; Y мог остаться без записи
            assert!(l == "X" || l == "Y");
        }
    }
    // закрытые материалы хранилищ (секрет пары и ключ списка друзей)
    for (n, p, l) in [(&x, pa, "X"), (&y, pb, "Y")] {
        let _ = p;
        if let Some(blob) = n.store.read_list_key().unwrap() {
            needles.bytes(&format!("{l}: list key"), &blob);
        }
    }
    for (l, st, p) in [("X", &x.store, pa), ("Y", &y.store, pb)] {
        if let Some(blob) = SecretStore::read(&**st, &p).unwrap() {
            needles.bytes(&format!("{l}: pair secret blob"), &blob);
        }
    }
    // у X ключ пары удалён при отзыве: возьмём секрет Y как «чужой» и убедимся, что он есть
    assert!(
        SecretStore::read(&*y.store, &pb).unwrap().is_some(),
        "control: Y pair secret must exist"
    );

    let outputs = sink.lock().unwrap().clone();
    let hits = scan(&outputs, &needles);
    println!(
        "no_leaks: outputs={} needles={} hits={}",
        outputs.len(),
        needles.0.len(),
        hits.len()
    );
    // подробности только по меткам, содержимое не печатается
    let mut listed: Vec<String> = hits.iter().map(|(s, n)| format!("{s} <- {n}")).collect();
    listed.sort();
    listed.dedup();
    assert!(hits.is_empty(), "утечки в выводе: {listed:#?}");
    // сценарий действительно что-то напечатал (не пустая проверка)
    assert!(
        outputs.len() > 120,
        "слишком мало собранного вывода: {}",
        outputs.len()
    );
    for must in [
        "EngineEvent",
        "TransferEvent",
        "OfferView",
        "accept_invite(garbage)",
        "send(stranger)",
    ] {
        assert!(
            outputs.iter().any(|(l, _)| l.contains(must)),
            "в выводе нет {must}"
        );
    }

    x.tr.shutdown();
    y.tr.shutdown();
    x.engine.shutdown();
    y.engine.shutdown();
    drop(x.t);
    drop(y.t);
}
