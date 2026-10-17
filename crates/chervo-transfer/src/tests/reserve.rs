//! Резерв места под приём (Рев. 5 этапа 15): политика видит ещё не полученные байты остальных
//! идущих, приостановленных и принятых передач; решения идут по одному; после перезапуска
//! восстановленные передачи считаются до первого решения; `Placement::partial_base` и
//! `extra_partial_dirs` переносят временные файлы передачи в другой каталог и находят их после
//! перезапуска.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_friends::Permission;
use chervo_identity::PairId;
use chervo_transport::Connection;

use super::kit::*;
use crate::shared::Hook;
use crate::{
    AcceptPolicy, CompletedFile, GeneratedNames, OfferView, OfferedFile, PlaceError, Placed,
    Placement, PolicyVerdict, TransferConfig, TransferEvent, TransferEvents, TransferKey,
    Transfers,
};

const MIB: u64 = 1 << 20;
/// Места на один файл в 40 МиБ, но не на два.
const AVAIL: u64 = 42 * MIB;

/// Что политика видела при одном решении.
#[derive(Clone)]
struct Seen {
    key: TransferKey,
    total: u64,
    inbound: Vec<(PathBuf, u64)>,
    verdict: PolicyVerdict,
}

/// Модель политики приёма: помещается ли предложение в `avail` за вычетом резерва.
struct Space {
    avail: u64,
    /// Пауза внутри решения (расширяет окно гонки между двумя одновременными решениями).
    delay: Duration,
    seen: Mutex<Vec<Seen>>,
    accepted: AtomicUsize,
}

impl Space {
    fn new(avail: u64, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            avail,
            delay,
            seen: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl AcceptPolicy for Space {
    fn decide(&self, _pair: &PairId, _p: Permission, o: &OfferView) -> PolicyVerdict {
        std::thread::sleep(self.delay);
        let reserved: u64 = o.inbound.iter().map(|r| r.outstanding).sum();
        let verdict = if o.total_size.saturating_add(reserved) <= self.avail {
            self.accepted.fetch_add(1, Ordering::SeqCst);
            PolicyVerdict::Accept
        } else {
            PolicyVerdict::Ask
        };
        self.seen.lock().unwrap().push(Seen {
            key: o.key,
            total: o.total_size,
            inbound: o
                .inbound
                .iter()
                .map(|r| (r.partial_dir.clone(), r.outstanding))
                .collect(),
            verdict,
        });
        verdict
    }
}

/// Размещение с другим каталогом временных данных (как выбранная папка приёма).
struct AltBase {
    inner: Arc<PlaceSpy>,
    alt: PathBuf,
}

impl Placement for AltBase {
    fn place(&self, f: &CompletedFile) -> Result<Placed, PlaceError> {
        self.inner.place(f)
    }

    fn prepare(&self, key: &TransferKey, files: &[OfferedFile]) -> Result<(), PlaceError> {
        self.inner.prepare(key, files)
    }

    fn forget(&self, key: &TransferKey) {
        self.inner.forget(key);
    }

    fn partial_base(&self, _key: &TransferKey) -> Option<PathBuf> {
        Some(self.alt.clone())
    }

    fn extra_partial_dirs(&self) -> Vec<PathBuf> {
        vec![self.alt.clone()]
    }
}

fn spy(dest: &TestDir) -> Arc<PlaceSpy> {
    Arc::new(PlaceSpy {
        inner: GeneratedNames {
            dest_dir: dest.path().to_path_buf(),
        },
        calls: Mutex::new(Vec::new()),
        fail: std::sync::atomic::AtomicBool::new(false),
        mode: std::sync::atomic::AtomicU8::new(PLACE_NORMAL),
        log: Mutex::new(Vec::new()),
        prepare_fail: std::sync::atomic::AtomicBool::new(false),
    })
}

/// Мало потоков и окно 1: пока писатель стоит, запросы упираются в память.
fn narrow(c: &mut TransferConfig) {
    c.streams = 2;
    c.per_stream_window = 1;
    c.recv_buffer_budget = 16 << 20;
}

/// Получатель со своей политикой и размещением.
struct B {
    node: Node,
    tr: Transfers<TEngine>,
    ev: TransferEvents,
    partial: Arc<TestDir>,
    dest: Arc<TestDir>,
    hook: Arc<TestHook>,
    cfg: TransferConfig,
}

fn start_transfers(
    node: &Node,
    cfg: &TransferConfig,
    hook: &Arc<TestHook>,
    policy: Arc<dyn AcceptPolicy>,
    placement: Arc<dyn Placement>,
) -> (Transfers<TEngine>, TransferEvents) {
    let inbox = node
        .engine
        .stream_inbox(&[crate::STREAM_TRANSFER_CTL, crate::STREAM_TRANSFER_DATA])
        .unwrap();
    let h: Arc<dyn Hook> = hook.clone();
    Transfers::start_with(
        node.engine.clone(),
        inbox,
        policy,
        placement,
        cfg.clone(),
        Some(h),
        Duration::from_millis(200),
    )
    .unwrap()
}

impl B {
    fn start(
        node: Node,
        partial: Arc<TestDir>,
        dest: Arc<TestDir>,
        cfg: TransferConfig,
        policy: Arc<dyn AcceptPolicy>,
        placement: Arc<dyn Placement>,
    ) -> B {
        let hook = TestHook::new();
        let (tr, ev) = start_transfers(&node, &cfg, &hook, policy, placement);
        B {
            node,
            tr,
            ev,
            partial,
            dest,
            hook,
            cfg,
        }
    }

    /// Останавливает передачи (писатель отпускается) и запускает заново на тех же каталогах.
    /// Возвращает заслонку на `n`-м записанном блоке после перезапуска: восстановленная
    /// передача не убегает до конца, пока тест смотрит на резерв.
    async fn restart_gated(
        &mut self,
        policy: Arc<dyn AcceptPolicy>,
        placement: Arc<dyn Placement>,
        n: usize,
    ) -> Arc<Gate> {
        self.tr.shutdown();
        self.tr.wait_stopped().await;
        self.hook.log.lock().unwrap().clear();
        self.hook.clear();
        let gate = gate_after_written(&self.hook, n);
        let (tr, ev) = start_transfers(&self.node, &self.cfg, &self.hook, policy, placement);
        self.tr = tr;
        self.ev = ev;
        gate
    }
}

struct Trio {
    a1: Peer,
    a2: Peer,
    b: B,
    pa1: PairId,
    pa2: PairId,
}

async fn link(na: &Node, pa: PairId, nb: &Node, pb: PairId, tag: u8) {
    let (ca, cb) = FakeConn::pair_ids(
        pa,
        addr(&format!("198.51.100.{}:4000", 20 + tag)),
        pb,
        addr(&format!("198.51.100.{}:4000", 10 + tag)),
        None,
    );
    na.t.push_incoming(ca.clone());
    nb.t.push_incoming(cb.clone());
    for _ in 0..500 {
        let ok_a = na
            .engine
            .connection(&pa)
            .is_some_and(|c| c.conn_id() == ca.conn_id());
        let ok_b = nb
            .engine
            .connection(&pb)
            .is_some_and(|c| c.conn_id() == cb.conn_id());
        if ok_a && ok_b {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("connection was not accepted");
}

/// Получатель B с двумя друзьями-отправителями A1 и A2.
async fn trio(
    policy: Arc<dyn AcceptPolicy>,
    placement: impl FnOnce(&TestDir) -> Arc<dyn Placement>,
) -> Trio {
    let (mut pre_a1, mut pre_a2, mut pre_b) = (Pre::new(), Pre::new(), Pre::new());
    let (pa1, pb1) = befriend(&mut pre_a1, &mut pre_b);
    let (pa2, pb2) = befriend(&mut pre_a2, &mut pre_b);
    let (n1, n2, nb) = (Node::start(pre_a1), Node::start(pre_a2), Node::start(pre_b));
    let (d1, d2, db) = (TestDir::new(), TestDir::new(), TestDir::new());
    let (dest1, dest2, destb) = (TestDir::new(), TestDir::new(), TestDir::new());
    let (c1, c2) = (small_cfg(d1.path()), small_cfg(d2.path()));
    let mut cb = small_cfg(db.path());
    narrow(&mut cb);
    let place = placement(&destb);
    let a1 = Peer::start(n1, d1, dest1, c1);
    let a2 = Peer::start(n2, d2, dest2, c2);
    let b = B::start(nb, db, destb, cb, policy, place);
    link(&a1.node, pa1, &b.node, pb1, 1).await;
    link(&a2.node, pa2, &b.node, pb2, 2).await;
    Trio {
        a1,
        a2,
        b,
        pa1,
        pa2,
    }
}

fn default_placement(dest: &TestDir) -> Arc<dyn Placement> {
    spy(dest)
}

/// Предложение одного файла в 40 МиБ (40 блоков по 1 МиБ).
fn big(src: &TestDir, name: &str, seed: u64) -> (Vec<crate::SourceFile>, Vec<u8>) {
    let data = rand_bytes(seed, (40 * MIB) as usize);
    (vec![write_src(src.path(), name, &data)], data)
}

fn is_done_id(id: crate::TransferId) -> impl Fn(&TransferEvent) -> bool {
    move |e| matches!(e, TransferEvent::Completed { key } if key.id == id)
}

#[tokio::test]
async fn second_offer_sees_outstanding_bytes_of_the_first() {
    // места хватает на один файл (42 МиБ на 40), но не на два: второй видит резерв первого
    let policy = Space::new(AVAIL, Duration::ZERO);
    let mut t = trio(policy.clone(), default_placement).await;
    let src = TestDir::new();
    let (f1, data1) = big(&src, "one.bin", 71);
    let (f2, _) = big(&src, "two.bin", 72);
    // первый принят политикой; писатель стоит на первом записанном блоке
    let gate = gate_after_written(&t.b.hook, 1);
    let k1 = t.a1.tr.send(&t.pa1, f1).unwrap();
    gate.wait_reached().await;
    let k2 = t.a2.tr.send(&t.pa2, f2).unwrap();
    let e = wait_ev(&mut t.b.ev, 20, is_offer()).await;
    let kb2 = key_of(&e);
    assert_eq!(kb2.id, k2.id, "the second offer is the one asked");
    let seen = policy.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].key.id, k1.id);
    assert_eq!(seen[0].verdict, PolicyVerdict::Accept);
    assert!(seen[0].inbound.is_empty(), "nothing before the first");
    assert_eq!(seen[1].key.id, k2.id);
    assert_eq!(seen[1].total, 40 * MIB);
    assert_eq!(
        seen[1].verdict,
        PolicyVerdict::Ask,
        "does not fit with the first"
    );
    assert_eq!(seen[1].inbound.len(), 1);
    let (dir, out) = &seen[1].inbound[0];
    assert_eq!(dir, t.b.partial.path(), "partial dir of the first session");
    assert!(*out > 2 * MIB && *out <= 40 * MIB, "outstanding {out}");
    // экран вопроса видит те же числа
    let view = t.b.tr.offer(&kb2).unwrap();
    assert_eq!(view.inbound.len(), 1);
    assert_eq!(view.inbound[0].partial_dir, t.b.partial.path());
    // отказ второму; первый доходит до конца
    t.b.tr.respond(&kb2, false).unwrap();
    gate.release();
    wait_ev(&mut t.b.ev, 60, is_done_id(k1.id)).await;
    let placed = placed_files(&t.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_offers_are_decided_one_at_a_time() {
    // два предложения приходят одновременно, решение занимает время: без очереди оба увидели
    // бы пустой резерв и оба были бы приняты
    let policy = Space::new(AVAIL, Duration::from_millis(150));
    let mut t = trio(policy.clone(), default_placement).await;
    let src = TestDir::new();
    let (f1, _) = big(&src, "one.bin", 73);
    let (f2, _) = big(&src, "two.bin", 74);
    let k1 = t.a1.tr.send(&t.pa1, f1).unwrap();
    let k2 = t.a2.tr.send(&t.pa2, f2).unwrap();
    let e = wait_ev(&mut t.b.ev, 30, is_offer()).await;
    let asked = key_of(&e);
    assert!(asked.id == k1.id || asked.id == k2.id);
    assert_eq!(
        policy.accepted.load(Ordering::SeqCst),
        1,
        "exactly one of two offers fits"
    );
    let seen = policy.seen();
    assert_eq!(seen.len(), 2);
    let verdicts: Vec<PolicyVerdict> = seen.iter().map(|s| s.verdict).collect();
    assert_eq!(verdicts, vec![PolicyVerdict::Accept, PolicyVerdict::Ask]);
    // второе решение видело принятое первое
    assert_eq!(seen[1].inbound.len(), 1);
    assert!(seen[1].inbound[0].1 > 0);
    t.b.tr.respond(&asked, false).unwrap();
    t.a1.tr.shutdown();
    t.a2.tr.shutdown();
}

#[tokio::test]
async fn restored_paused_session_is_counted_before_new_offers() {
    let policy = Space::new(AVAIL, Duration::ZERO);
    let mut t = trio(policy.clone(), default_placement).await;
    let src = TestDir::new();
    let (f1, data1) = big(&src, "one.bin", 75);
    let (f2, _) = big(&src, "two.bin", 76);
    let gate = gate_after_written(&t.b.hook, 10);
    let k1 = t.a1.tr.send(&t.pa1, f1).unwrap();
    gate.wait_reached().await;
    // остановка получателя на середине: на диске остаётся состояние
    t.b.tr.shutdown();
    gate.release();
    t.b.tr.wait_stopped().await;
    assert_eq!(t.b.partial.list().len(), 1, "one saved transfer");
    // перезапуск с новой политикой: восстановленная передача в реестре до первого решения
    let policy2 = Space::new(AVAIL, Duration::ZERO);
    let gate2 =
        t.b.restart_gated(policy2.clone(), default_placement(&t.b.dest), 1)
            .await;
    wait_ev(&mut t.b.ev, 10, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    gate2.wait_reached().await;
    let k2 = t.a2.tr.send(&t.pa2, f2).unwrap();
    let e = wait_ev(&mut t.b.ev, 20, is_offer()).await;
    assert_eq!(key_of(&e).id, k2.id);
    let seen = policy2.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].verdict,
        PolicyVerdict::Ask,
        "the restored session reserves space"
    );
    assert_eq!(seen[0].inbound.len(), 1, "the restored session is counted");
    let (dir, out) = &seen[0].inbound[0];
    assert_eq!(dir, t.b.partial.path());
    assert!(*out > 2 * MIB && *out <= 40 * MIB, "outstanding {out}");
    // порядок: отказ второму, первый возобновляется и доходит до конца
    t.b.tr.respond(&key_of(&e), false).unwrap();
    gate2.release();
    wait_ev(&mut t.b.ev, 60, is_done_id(k1.id)).await;
    let placed = placed_files(&t.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data1);
}

#[tokio::test]
async fn alternate_partial_base_is_used_and_found_after_restart() {
    // `Placement::partial_base`: временные файлы лежат в другом каталоге; после перезапуска
    // `extra_partial_dirs` возвращает его, передача восстанавливается там же и достигает цели
    let alt = TestDir::new();
    let alt_path = alt.path().to_path_buf();
    let mk = {
        let alt_path = alt_path.clone();
        move |dest: &TestDir| -> Arc<dyn Placement> {
            Arc::new(AltBase {
                inner: spy(dest),
                alt: alt_path.clone(),
            })
        }
    };
    let policy = Space::new(AVAIL, Duration::ZERO);
    let mut t = trio(policy.clone(), &mk).await;
    let src = TestDir::new();
    let (f1, data1) = big(&src, "one.bin", 77);
    let (f2, _) = big(&src, "two.bin", 78);
    let gate = gate_after_written(&t.b.hook, 8);
    let k1 = t.a1.tr.send(&t.pa1, f1).unwrap();
    gate.wait_reached().await;
    // каталог передачи в выбранной базе, а не в `partial_dir` из настроек
    assert!(
        t.b.partial.list().is_empty(),
        "config partial dir untouched"
    );
    assert_eq!(alt.list().len(), 1);
    t.b.tr.shutdown();
    gate.release();
    t.b.tr.wait_stopped().await;
    let policy2 = Space::new(AVAIL, Duration::ZERO);
    let gate2 = t.b.restart_gated(policy2.clone(), mk(&t.b.dest), 1).await;
    wait_ev(&mut t.b.ev, 10, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    gate2.wait_reached().await;
    // резерв восстановленной передачи указывает на выбранную базу
    let k2 = t.a2.tr.send(&t.pa2, f2).unwrap();
    let e = wait_ev(&mut t.b.ev, 20, is_offer()).await;
    assert_eq!(key_of(&e).id, k2.id);
    let seen = policy2.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].inbound.len(), 1);
    assert_eq!(seen[0].inbound[0].0, alt_path);
    t.b.tr.respond(&key_of(&e), false).unwrap();
    gate2.release();
    wait_ev(&mut t.b.ev, 60, is_done_id(k1.id)).await;
    let placed = placed_files(&t.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data1);
    assert!(
        t.b.partial.list().is_empty(),
        "config partial dir untouched"
    );
}

#[tokio::test]
async fn lone_offer_sees_no_reservation() {
    let policy = Space::new(u64::MAX, Duration::ZERO);
    let mut t = trio(policy.clone(), default_placement).await;
    let src = TestDir::new();
    let (f1, data1) = big(&src, "one.bin", 79);
    let k1 = t.a1.tr.send(&t.pa1, f1).unwrap();
    wait_ev(&mut t.b.ev, 60, is_done_id(k1.id)).await;
    let seen = policy.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].inbound.is_empty());
    assert!(placed_files(&t.b.dest)[0].1 == data1);
    let _ = t.pa2;
}
