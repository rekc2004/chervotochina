//! Служба маяка: один поток std, без асинхронной среды (этап 13в, L3). Сокетный код только в `net.rs`.
//!
//! Потока и сокетов нет, пока режим `Off` или нет подходящего `set_local`. Режим «слушать»
//! ничего не отправляет и сокета отправки не открывает. Находки (`take_sightings`) только
//! кандидаты для набора: служба ничего не набирает и ничего не пишет на диск.
//! Ничего не печатается и не пишется в журнал.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chervo_addr::{AddrClass, LanDiscovery, LanLocal, LanMode, LanSighting, LanStatus, classify};
use chervo_identity::{KxPeer, LAN_WINDOW_SECS, LanKeys, PairId};

use crate::limits::{
    BURST, FAIL_RETRY, INTERVAL, JITTER, MAX_PEERS, MAX_SIGHTINGS, READ_TIMEOUT, RECV_BUF,
    SEND_BUDGET_COUNT, SEND_BUDGET_WINDOW,
};
use crate::net::{OpenError, Recv, Route, Sockets};
use crate::rate::{RxLimiter, RxVerdict};
use crate::table::IdTable;
use crate::wire::{SrcPolicy, build, parse};

/// Тестовая сеть на петле: юникаст вместо группы. Только под `test` и `test-net`.
#[cfg(any(test, feature = "test-net"))]
#[derive(Clone, Copy)]
pub struct TestNet {
    /// Куда уходят датаграммы.
    pub target: std::net::SocketAddrV4,
    /// Адрес приёма (порт `listen_port`); общий доступ к порту не включается.
    pub bind: std::net::Ipv4Addr,
    pub listen_port: u16,
    /// Принимать источники из `127.0.0.0/8` (адрес самого получателя всё равно отбрасывается).
    pub allow_loopback: bool,
    /// Период раунда; серия после запуска и разброс сжимаются в той же пропорции.
    pub interval: Duration,
}

#[cfg(any(test, feature = "test-net"))]
impl std::fmt::Debug for TestNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNet(..)")
    }
}

#[derive(Clone, Copy)]
struct Cfg {
    interval: Duration,
    policy: SrcPolicy,
    #[cfg(any(test, feature = "test-net"))]
    test: Option<TestNet>,
}

impl Cfg {
    fn product() -> Self {
        Self {
            interval: INTERVAL,
            policy: SrcPolicy::PRODUCT,
            #[cfg(any(test, feature = "test-net"))]
            test: None,
        }
    }

    fn route(&self) -> Route {
        #[cfg(any(test, feature = "test-net"))]
        if let Some(t) = self.test {
            return Route::Test {
                bind: t.bind,
                port: t.listen_port,
                target: t.target,
            };
        }
        Route::Product
    }
}

struct Inbox {
    mode: LanMode,
    local: Option<LanLocal>,
    /// Новый набор пар, ещё не принятый потоком.
    peers: Option<Vec<KxPeer>>,
    /// Растёт при каждом `set_local` (повторная попытка после сбоя).
    local_seq: u64,
}

struct Shared {
    inbox: Mutex<Inbox>,
    cv: Condvar,
    sightings: Mutex<VecDeque<LanSighting>>,
    status: AtomicU8,
    stop: AtomicBool,
    finished: AtomicBool,
    rx_total: AtomicU64,
    rx_passed: AtomicU64,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    cfg: Cfg,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn status_to_u8(s: LanStatus) -> u8 {
    match s {
        LanStatus::Off => 0,
        LanStatus::NoPrivateRoute => 1,
        LanStatus::PortBusy => 2,
        LanStatus::Listening => 3,
        LanStatus::Announcing => 4,
        _ => 5,
    }
}

fn status_from_u8(v: u8) -> LanStatus {
    match v {
        0 => LanStatus::Off,
        1 => LanStatus::NoPrivateRoute,
        2 => LanStatus::PortBusy,
        3 => LanStatus::Listening,
        4 => LanStatus::Announcing,
        _ => LanStatus::Failed,
    }
}

/// Состояние без сокетов: режим выключен или нет адреса.
fn idle_status(mode: LanMode, local_ok: bool) -> LanStatus {
    if mode == LanMode::Off {
        LanStatus::Off
    } else if !local_ok {
        LanStatus::NoPrivateRoute
    } else {
        LanStatus::Failed
    }
}

fn local_ok(cfg: &Cfg, l: Option<LanLocal>) -> Option<LanLocal> {
    let l = l?;
    match classify(IpAddr::V4(l.own)) {
        AddrClass::Private => Some(l),
        AddrClass::Loopback if cfg.policy.allow_loopback => Some(l),
        _ => None,
    }
}

/// `d`, пересчитанное из рабочего периода в заданный (в продукте это тождество).
fn scaled(d: Duration, interval: Duration) -> Duration {
    if interval == INTERVAL {
        return d;
    }
    let n = d.as_nanos().saturating_mul(interval.as_nanos()) / INTERVAL.as_nanos().max(1);
    Duration::from_nanos(u64::try_from(n).unwrap_or(u64::MAX))
}

/// `base ± jitter` случайно; при сбое ГСЧ без разброса.
fn jittered(base: Duration, jitter: Duration) -> Duration {
    let j = u64::try_from(jitter.as_nanos()).unwrap_or(0);
    let mut r = [0u8; 8];
    if j == 0 || getrandom::fill(&mut r).is_err() {
        return base;
    }
    let off = u64::from_le_bytes(r) % j.saturating_mul(2).saturating_add(1);
    base.saturating_add(Duration::from_nanos(off))
        .saturating_sub(Duration::from_nanos(j))
}

pub struct LanBeacon {
    shared: Arc<Shared>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for LanBeacon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LanBeacon(..)")
    }
}

impl LanBeacon {
    /// Потока и сокетов нет, пока режим не `Off` и не вызван `set_local(Some)`.
    pub fn new(mode: LanMode, now_unix: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self::with_cfg(mode, now_unix, Cfg::product())
    }

    #[cfg(any(test, feature = "test-net"))]
    #[doc(hidden)]
    pub fn new_on_loopback(
        mode: LanMode,
        now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
        net: TestNet,
    ) -> Self {
        Self::with_cfg(
            mode,
            now_unix,
            Cfg {
                interval: net.interval,
                policy: if net.allow_loopback {
                    SrcPolicy::LOOPBACK_OK
                } else {
                    SrcPolicy::PRODUCT
                },
                test: Some(net),
            },
        )
    }

    fn with_cfg(mode: LanMode, now_unix: Arc<dyn Fn() -> u64 + Send + Sync>, cfg: Cfg) -> Self {
        let shared = Arc::new(Shared {
            inbox: Mutex::new(Inbox {
                mode,
                local: None,
                peers: None,
                local_seq: 0,
            }),
            cv: Condvar::new(),
            sightings: Mutex::new(VecDeque::new()),
            status: AtomicU8::new(status_to_u8(idle_status(mode, false))),
            stop: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            rx_total: AtomicU64::new(0),
            rx_passed: AtomicU64::new(0),
            now_unix,
            cfg,
        });
        Self {
            shared,
            handle: Mutex::new(None),
        }
    }

    pub fn set_mode(&self, m: LanMode) {
        {
            let mut g = lock(&self.shared.inbox);
            g.mode = m;
        }
        self.after_change();
    }

    /// Только для проверок вручную и тестов: сколько датаграмм принято и сколько прошло
    /// ограничение приёма до разбора.
    #[doc(hidden)]
    pub fn rx_stats(&self) -> (u64, u64) {
        (
            self.shared.rx_total.load(Ordering::Relaxed),
            self.shared.rx_passed.load(Ordering::Relaxed),
        )
    }

    /// Только для тестов: поток службы завершился (или не запускался после `shutdown`).
    #[cfg(any(test, feature = "test-net"))]
    #[doc(hidden)]
    pub fn thread_finished(&self) -> bool {
        self.shared.finished.load(Ordering::SeqCst)
    }

    /// Только для тестов: поток службы запущен.
    #[cfg(any(test, feature = "test-net"))]
    #[doc(hidden)]
    pub fn thread_started(&self) -> bool {
        lock(&self.handle).is_some()
    }

    /// После изменения входных данных: холостое состояние без потока и запуск потока по
    /// необходимости.
    fn after_change(&self) {
        let (mode, local) = {
            let g = lock(&self.shared.inbox);
            (g.mode, g.local)
        };
        let ok = local_ok(&self.shared.cfg, local).is_some();
        let want = mode != LanMode::Off && ok;
        let mut h = lock(&self.handle);
        if h.is_none() {
            if !want {
                self.shared
                    .status
                    .store(status_to_u8(idle_status(mode, ok)), Ordering::SeqCst);
            } else if !self.shared.stop.load(Ordering::SeqCst) {
                let sh = Arc::clone(&self.shared);
                // при сбое запуска потока состояние `Failed`, повтор при следующем изменении
                match thread::Builder::new()
                    .name("chervo-lan".to_owned())
                    .spawn(move || run(&sh))
                {
                    Ok(j) => *h = Some(j),
                    Err(_) => self
                        .shared
                        .status
                        .store(status_to_u8(LanStatus::Failed), Ordering::SeqCst),
                }
            }
        }
        drop(h);
        self.shared.cv.notify_all();
    }
}

impl Drop for LanBeacon {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cv.notify_all();
    }
}

impl LanDiscovery for LanBeacon {
    fn set_local(&self, local: Option<LanLocal>) {
        {
            let mut g = lock(&self.shared.inbox);
            g.local = local;
            g.local_seq = g.local_seq.wrapping_add(1);
        }
        self.after_change();
    }

    fn set_peers(&self, mut peers: Vec<KxPeer>) {
        peers.truncate(MAX_PEERS);
        {
            let mut g = lock(&self.shared.inbox);
            g.peers = Some(peers);
        }
        self.shared.cv.notify_all();
    }

    fn take_sightings(&self) -> Vec<LanSighting> {
        let mut g = lock(&self.shared.sightings);
        std::mem::take(&mut *g).into_iter().collect()
    }

    fn status(&self) -> LanStatus {
        status_from_u8(self.shared.status.load(Ordering::SeqCst))
    }

    fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cv.notify_all();
    }
}

// ----------------------------------------------------------------------------------------
// Поток службы
// ----------------------------------------------------------------------------------------

struct Worker<'a> {
    sh: &'a Shared,
    table: IdTable,
    limiter: RxLimiter,
    net: Option<Sockets>,
    /// Для чего открыты сокеты: адрес и «отправлять ли».
    opened_for: Option<(LanLocal, bool)>,
    /// Для чего открытие не удалось, и когда пробовать снова.
    failed_for: Option<(LanLocal, bool)>,
    fail_until: Option<Instant>,
    seen_seq: u64,
    pair_ids: Vec<[u8; 16]>,
    bursts: VecDeque<Instant>,
    next_regular: Option<Instant>,
    round: u64,
    sent: VecDeque<Instant>,
    /// Окно подсчёта ошибок приёма: начало и число.
    rx_err: (Instant, u32),
    buf: [u8; RECV_BUF],
}

fn run(sh: &Arc<Shared>) {
    let mut w = Worker {
        sh,
        table: IdTable::empty(),
        limiter: RxLimiter::new(Instant::now()),
        net: None,
        opened_for: None,
        failed_for: None,
        fail_until: None,
        seen_seq: 0,
        pair_ids: Vec::new(),
        bursts: VecDeque::new(),
        next_regular: None,
        round: 0,
        sent: VecDeque::new(),
        rx_err: (Instant::now(), 0),
        buf: [0u8; RECV_BUF],
    };
    while !sh.stop.load(Ordering::SeqCst) {
        w.step();
    }
    w.net = None;
    sh.finished.store(true, Ordering::SeqCst);
}

impl Worker<'_> {
    fn set_status(&self, s: LanStatus) {
        self.sh.status.store(status_to_u8(s), Ordering::SeqCst);
    }

    fn window_now(&self) -> u64 {
        (self.sh.now_unix)() / LAN_WINDOW_SECS
    }

    fn step(&mut self) {
        let now = Instant::now();
        let (mode, local, peers, seq) = {
            let mut g = lock(&self.sh.inbox);
            (g.mode, g.local, g.peers.take(), g.local_seq)
        };
        let w = self.window_now();
        if let Some(peers) = peers {
            self.accept_peers(peers, w, now, mode);
        } else if w != self.table.window() {
            self.table.rebuild(w);
        }
        if seq != self.seen_seq {
            self.seen_seq = seq;
            self.fail_until = None;
        }
        self.apply(mode, local_ok(&self.sh.cfg, local), now);
        self.send_if_due(mode, now);
        self.receive(mode, now);
    }

    fn accept_peers(&mut self, peers: Vec<KxPeer>, w: u64, now: Instant, mode: LanMode) {
        let keyed: Vec<(PairId, LanKeys)> = peers
            .into_iter()
            .filter_map(|p| p.lan_keys().ok().map(|k| (p.pair(), k)))
            .collect();
        self.table.set_peers(keyed, w);
        let mut ids: Vec<[u8; 16]> = self.table.peers().map(|(p, _)| *p.as_bytes()).collect();
        ids.sort_unstable();
        if ids != self.pair_ids {
            self.pair_ids = ids;
            if mode == LanMode::Announce && self.net.as_ref().is_some_and(Sockets::can_send) {
                self.schedule_burst(now);
            }
        }
    }

    fn schedule_burst(&mut self, now: Instant) {
        let iv = self.sh.cfg.interval;
        self.bursts = BURST
            .iter()
            .filter_map(|b| now.checked_add(scaled(*b, iv)))
            .collect();
    }

    /// Открыть, закрыть или перекрыть сокеты под текущие режим и адрес.
    fn apply(&mut self, mode: LanMode, local: Option<LanLocal>, now: Instant) {
        let Some(l) = local.filter(|_| mode != LanMode::Off) else {
            self.net = None;
            self.opened_for = None;
            self.failed_for = None;
            self.fail_until = None;
            self.bursts.clear();
            self.next_regular = None;
            self.set_status(idle_status(mode, local.is_some()));
            return;
        };
        let want_send = mode == LanMode::Announce;
        let key = (l, want_send);
        if self.net.is_some() && self.opened_for == Some(key) {
            return;
        }
        if self.failed_for == Some(key) && self.fail_until.is_some_and(|t| now < t) {
            return;
        }
        // порт нужно освободить до повторной привязки
        self.net = None;
        self.opened_for = None;
        self.bursts.clear();
        self.next_regular = None;
        match Sockets::open(l.own, want_send, self.sh.cfg.route()) {
            Ok(n) => {
                self.net = Some(n);
                self.opened_for = Some(key);
                self.failed_for = None;
                self.fail_until = None;
                if want_send {
                    self.schedule_burst(now);
                    self.set_status(LanStatus::Announcing);
                } else {
                    self.set_status(LanStatus::Listening);
                }
            }
            Err(e) => {
                self.failed_for = Some(key);
                self.fail_until = now.checked_add(FAIL_RETRY);
                self.set_status(match e {
                    OpenError::Busy => LanStatus::PortBusy,
                    OpenError::Other => LanStatus::Failed,
                });
            }
        }
    }

    fn due(&self) -> Option<Instant> {
        let b = self.bursts.front().copied();
        match (b, self.next_regular) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    fn send_if_due(&mut self, mode: LanMode, now: Instant) {
        let can = self.net.as_ref().is_some_and(Sockets::can_send);
        let ready = mode == LanMode::Announce && self.table.peer_count() > 0 && can;
        let opened = self.opened_for.filter(|o| o.0.listen_port != 0);
        let Some(opened) = opened.filter(|_| ready) else {
            // отправлять нечего или нельзя: расписание не копится (оно вернётся со сменой
            // набора пар или адреса)
            self.bursts.clear();
            self.next_regular = None;
            return;
        };
        if !self.due().is_some_and(|t| t <= now) {
            return;
        }
        let iv = self.sh.cfg.interval;
        let w = self.window_now();
        let src = self.net.as_ref().map_or(opened.0.own, Sockets::send_ip);
        let round = self.round;
        self.round = self.round.wrapping_add(1);
        let peers: Vec<(PairId, &LanKeys)> = self.table.peers().collect();
        // сбой ГСЧ или сборки: ничего не отправляется, следующий раунд по расписанию
        let dgrams = build(&peers, w, src, opened.0.listen_port, round).unwrap_or_default();
        while self.bursts.front().is_some_and(|t| *t <= now) {
            self.bursts.pop_front();
        }
        self.next_regular = now.checked_add(jittered(iv, scaled(JITTER, iv)));
        for d in &dgrams {
            while self
                .sent
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= SEND_BUDGET_WINDOW)
            {
                self.sent.pop_front();
            }
            if self.sent.len() >= SEND_BUDGET_COUNT {
                break;
            }
            let ok = self.net.as_ref().is_some_and(|n| n.send(d));
            if !ok {
                self.net = None;
                self.opened_for = None;
                self.failed_for = Some(opened);
                self.fail_until = now.checked_add(FAIL_RETRY);
                self.bursts.clear();
                self.next_regular = None;
                self.set_status(LanStatus::Failed);
                return;
            }
            self.sent.push_back(now);
        }
    }

    fn receive(&mut self, mode: LanMode, now: Instant) {
        let Some(opened) = self.opened_for else {
            // сокетов нет: ждём изменения входных данных или остановки
            let g = lock(&self.sh.inbox);
            let _ = self
                .sh
                .cv
                .wait_timeout(g, READ_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            return;
        };
        let wait = if mode == LanMode::Announce {
            self.due()
                .map_or(READ_TIMEOUT, |t| t.saturating_duration_since(now))
        } else {
            READ_TIMEOUT
        };
        let Some(net) = self.net.as_ref() else {
            return;
        };
        match net.recv(&mut self.buf, wait) {
            Recv::Data { len, src } => {
                self.sh.rx_total.fetch_add(1, Ordering::Relaxed);
                let t = Instant::now();
                if self.limiter.check(t, src) != RxVerdict::Pass {
                    return;
                }
                self.sh.rx_passed.fetch_add(1, Ordering::Relaxed);
                let w = self.window_now();
                if w != self.table.window() {
                    self.table.rebuild(w);
                }
                let found = self.buf.get(..len).map_or_else(Vec::new, |d| {
                    parse(d, src, opened.0.own, &self.table, self.sh.cfg.policy)
                });
                self.push_sightings(found);
            }
            Recv::Idle | Recv::Oversize => {}
            Recv::Error => self.rx_error(),
        }
    }

    /// Ошибки приёма считаются; 64 и больше за секунду: пауза в 1 с (с проверкой остановки).
    fn rx_error(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.rx_err.0) >= Duration::from_secs(1) {
            self.rx_err = (now, 0);
        }
        self.rx_err.1 = self.rx_err.1.saturating_add(1);
        if self.rx_err.1 >= 64 {
            self.rx_err = (Instant::now(), 0);
            let end = Instant::now() + Duration::from_secs(1);
            while Instant::now() < end && !self.sh.stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }

    /// Очередь находок: одна на пару (новая вытесняет старую), не больше `MAX_SIGHTINGS`.
    fn push_sightings(&self, found: Vec<LanSighting>) {
        if found.is_empty() {
            return;
        }
        let mut q = lock(&self.sh.sightings);
        for s in found {
            q.retain(|x| x.pair != s.pair);
            q.push_back(s);
            while q.len() > MAX_SIGHTINGS {
                q.pop_front();
            }
        }
    }
}
