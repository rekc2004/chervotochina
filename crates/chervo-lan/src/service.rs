//! Служба маяка: один поток std, без асинхронной среды (этап 13в, L3). Сокетный код только в `net.rs`.
//!
//! Потока и сокетов нет, пока режим `Off` или нет подходящего `set_local`. Режим «слушать»
//! ничего не отправляет и сокета отправки не открывает. Находки (`take_sightings`) только
//! кандидаты для набора: служба ничего не набирает и ничего не пишет на диск.
//! Ничего не печатается и не пишется в журнал.

use std::collections::VecDeque;
#[cfg(any(test, feature = "test-net"))]
use std::net::{IpAddr, SocketAddrV4};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chervo_addr::{LanDiscovery, LanLocal, LanMode, LanSighting, LanStatus, route_source_for};
use chervo_identity::{KxPeer, LAN_WINDOW_SECS, LanKeys, PairId};

use crate::ifaces::select;
use crate::limits::{
    BURST, DGRAM_LEN, FAIL_RETRY, INTERVAL, JITTER, MAX_PEERS, MAX_SIGHTINGS, READ_TIMEOUT,
    RECV_BUF, SEND_BUDGET_COUNT, SEND_BUDGET_WINDOW, SWEEP_INTERVAL,
};
use crate::net::{OpenError, Recv, Route, Sockets};
use crate::rate::{RxLimiter, RxVerdict};
use crate::table::IdTable;
use crate::wire::{SrcPolicy, build, parse};

/// Тестовая сеть на петле: юникаст вместо группы. Только под `test` и `test-net`.
#[cfg(any(test, feature = "test-net"))]
#[derive(Clone)]
pub struct TestNet {
    /// Куда уходят датаграммы.
    pub target: SocketAddrV4,
    /// Адрес приёма (порт `listen_port`); общий доступ к порту не включается.
    pub bind: Ipv4Addr,
    pub listen_port: u16,
    /// Принимать источники из `127.0.0.0/8` (адрес самого получателя всё равно отбрасывается).
    pub allow_loopback: bool,
    /// Период раунда; серия после запуска, разброс и повторный опрос интерфейсов сжимаются в
    /// той же пропорции.
    pub interval: Duration,
    /// Вместо опроса маршрутов системы: «какой свой адрес был бы на пути к цели».
    pub oracle: TestOracle,
}

/// Подставной опрос маршрутов для тестов.
#[cfg(any(test, feature = "test-net"))]
pub type TestOracle = Arc<dyn Fn(SocketAddrV4) -> Option<IpAddr> + Send + Sync>;

#[cfg(any(test, feature = "test-net"))]
impl TestNet {
    /// Опрос, который никогда ничего не находит: интерфейс остаётся один, адрес из `set_local`.
    pub fn no_oracle() -> TestOracle {
        Arc::new(|_| None)
    }
}

#[cfg(any(test, feature = "test-net"))]
impl std::fmt::Debug for TestNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNet(..)")
    }
}

#[derive(Clone)]
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
        if let Some(t) = &self.test {
            return Route::Test {
                bind: t.bind,
                port: t.listen_port,
                target: t.target,
            };
        }
        Route::Product
    }

    /// Опрос маршрутов: набор интерфейсов для адреса по умолчанию `default`. Пакетов не шлёт.
    fn sweep(&self, default: Ipv4Addr, stop: &dyn Fn() -> bool) -> Vec<Ipv4Addr> {
        #[cfg(any(test, feature = "test-net"))]
        if let Some(t) = &self.test {
            let oracle = t.oracle.clone();
            return select(default, &mut |a| oracle(a), self.policy, stop);
        }
        select(
            default,
            &mut |a| route_source_for(SocketAddr::V4(a)),
            self.policy,
            stop,
        )
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
    /// Адреса интерфейсов, на которых идёт поиск (пусто при `Off` и без адреса).
    addrs: Mutex<Vec<Ipv4Addr>>,
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
            addrs: Mutex::new(Vec::new()),
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

    /// Адреса интерфейсов, на которых идёт поиск сейчас (до `MAX_IFACES`); пусто при `Off`,
    /// без адреса и без частных интерфейсов.
    pub fn addrs(&self) -> Vec<Ipv4Addr> {
        lock(&self.shared.addrs).clone()
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
        let ok = local.is_some();
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

/// Для чего открыты (или не открылись) сокеты: адрес, «отправлять ли» и набор интерфейсов.
#[derive(Clone, PartialEq, Eq)]
struct OpenKey {
    local: LanLocal,
    send: bool,
    members: Vec<Ipv4Addr>,
}

struct Worker<'a> {
    sh: &'a Shared,
    table: IdTable,
    limiter: RxLimiter,
    net: Option<Sockets>,
    /// Для чего открыты сокеты.
    opened_for: Option<OpenKey>,
    /// Для чего открытие не удалось, и когда пробовать снова.
    failed_for: Option<OpenKey>,
    fail_until: Option<Instant>,
    seen_seq: u64,
    pair_ids: Vec<[u8; 16]>,
    bursts: VecDeque<Instant>,
    next_regular: Option<Instant>,
    round: u64,
    /// Бюджет отправки отдельно на каждый сокет отправки (по порядку `Sockets::send_ips`).
    sent: Vec<VecDeque<Instant>>,
    /// Интерфейсы по итогу последнего опроса маршрутов.
    members: Vec<Ipv4Addr>,
    /// Для какого адреса и режима и когда сделан последний опрос.
    sweep_for: Option<LanLocal>,
    last_mode: LanMode,
    last_sweep: Option<Instant>,
    /// Фактические адреса приёма (вошли в группу); по ним отбрасываются свои датаграммы.
    effective: Vec<Ipv4Addr>,
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
        sent: Vec::new(),
        members: Vec::new(),
        sweep_for: None,
        last_mode: LanMode::Off,
        last_sweep: None,
        effective: Vec::new(),
        rx_err: (Instant::now(), 0),
        buf: [0u8; RECV_BUF],
    };
    while !sh.stop.load(Ordering::SeqCst) {
        w.step();
    }
    w.net = None;
    w.publish_addrs(&[]);
    sh.finished.store(true, Ordering::SeqCst);
}

impl Worker<'_> {
    fn set_status(&self, s: LanStatus) {
        self.sh.status.store(status_to_u8(s), Ordering::SeqCst);
    }

    fn publish_addrs(&self, addrs: &[Ipv4Addr]) {
        *lock(&self.sh.addrs) = addrs.to_vec();
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
        let mut force_sweep = false;
        if seq != self.seen_seq {
            self.seen_seq = seq;
            self.fail_until = None;
            force_sweep = true;
        }
        self.apply(mode, local, now, force_sweep);
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

    /// Закрыть сокеты и забыть расписание.
    fn close_net(&mut self) {
        self.net = None;
        self.opened_for = None;
        self.bursts.clear();
        self.next_regular = None;
        self.sent.clear();
        self.effective.clear();
        self.publish_addrs(&[]);
    }

    /// Опрос маршрутов (нужен при выходе из `Off`, при `set_local`, при смене режима и раз в
    /// `SWEEP_INTERVAL`): набор интерфейсов. Идёт в потоке службы, пакетов не отправляет.
    fn sweep_if_due(&mut self, mode: LanMode, l: LanLocal, now: Instant, force: bool) {
        let iv = self.sh.cfg.interval;
        let due = force
            || self.sweep_for != Some(l)
            || mode != self.last_mode
            || self
                .last_sweep
                .is_none_or(|t| now.saturating_duration_since(t) >= scaled(SWEEP_INTERVAL, iv));
        if !due {
            return;
        }
        let sh = self.sh;
        let stop = move || sh.stop.load(Ordering::SeqCst);
        self.members = sh.cfg.sweep(l.own, &stop);
        self.sweep_for = Some(l);
        self.last_sweep = Some(Instant::now());
    }

    /// Открыть, закрыть или перекрыть сокеты под текущие режим, адрес и набор интерфейсов.
    fn apply(&mut self, mode: LanMode, local: Option<LanLocal>, now: Instant, force_sweep: bool) {
        let Some(l) = local.filter(|_| mode != LanMode::Off) else {
            self.close_net();
            self.members.clear();
            self.sweep_for = None;
            self.last_sweep = None;
            self.last_mode = mode;
            self.failed_for = None;
            self.fail_until = None;
            self.set_status(idle_status(mode, local.is_some()));
            return;
        };
        self.sweep_if_due(mode, l, now, force_sweep);
        self.last_mode = mode;
        if self.sh.stop.load(Ordering::SeqCst) {
            return;
        }
        if self.members.is_empty() {
            // ни одного частного интерфейса
            self.close_net();
            self.failed_for = None;
            self.fail_until = None;
            self.set_status(LanStatus::NoPrivateRoute);
            return;
        }
        let want_send = mode == LanMode::Announce;
        let key = OpenKey {
            local: l,
            send: want_send,
            members: self.members.clone(),
        };
        if self.net.is_some() && self.opened_for.as_ref() == Some(&key) {
            return;
        }
        if self.failed_for.as_ref() == Some(&key) && self.fail_until.is_some_and(|t| now < t) {
            return;
        }
        // порт нужно освободить до повторной привязки
        self.close_net();
        match Sockets::open(&key.members, want_send, self.sh.cfg.route()) {
            Ok(n) => {
                self.effective = n.members();
                self.sent = n.send_ips().iter().map(|_| VecDeque::new()).collect();
                self.publish_addrs(&self.effective);
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
        let opened = self.opened_for.clone().filter(|o| o.local.listen_port != 0);
        let Some(opened) = opened.filter(|_| ready) else {
            // отправлять нечего или нельзя: расписание не копится (оно вернётся со сменой
            // набора пар, адреса или интерфейсов)
            self.bursts.clear();
            self.next_regular = None;
            return;
        };
        if !self.due().is_some_and(|t| t <= now) {
            return;
        }
        let iv = self.sh.cfg.interval;
        let w = self.window_now();
        let srcs = self.net.as_ref().map_or_else(Vec::new, Sockets::send_ips);
        let round = self.round;
        self.round = self.round.wrapping_add(1);
        while self.bursts.front().is_some_and(|t| *t <= now) {
            self.bursts.pop_front();
        }
        self.next_regular = now.checked_add(jittered(iv, scaled(JITTER, iv)));
        let peers: Vec<(PairId, &LanKeys)> = self.table.peers().collect();
        // слот запечатывается адресом привязки своего сокета, поэтому датаграммы у каждого
        // интерфейса свои; сбой ГСЧ или сборки: ничего не отправляется, следующий раунд по
        // расписанию
        let per_iface: Vec<Vec<[u8; DGRAM_LEN]>> = srcs
            .iter()
            .map(|src| build(&peers, w, *src, opened.local.listen_port, round).unwrap_or_default())
            .collect();
        for (i, dgrams) in per_iface.iter().enumerate() {
            for d in dgrams {
                let Some(log) = self.sent.get_mut(i) else {
                    break;
                };
                while log
                    .front()
                    .is_some_and(|t| now.saturating_duration_since(*t) >= SEND_BUDGET_WINDOW)
                {
                    log.pop_front();
                }
                if log.len() >= SEND_BUDGET_COUNT {
                    break;
                }
                let ok = self.net.as_ref().is_some_and(|n| n.send(i, d));
                if !ok {
                    self.close_net();
                    self.failed_for = Some(opened);
                    self.fail_until = now.checked_add(FAIL_RETRY);
                    self.set_status(LanStatus::Failed);
                    return;
                }
                log.push_back(now);
            }
        }
    }

    fn receive(&mut self, mode: LanMode, now: Instant) {
        if self.opened_for.is_none() {
            if self.sh.stop.load(Ordering::SeqCst) {
                return;
            }
            // сокетов нет: ждём изменения входных данных или остановки
            let g = lock(&self.sh.inbox);
            let _ = self
                .sh
                .cv
                .wait_timeout(g, READ_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            return;
        }
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
                    parse(d, src, &self.effective, &self.table, self.sh.cfg.policy)
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
