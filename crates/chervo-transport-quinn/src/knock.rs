//! «Стук»: обёртка гнезда quinn, таблица допуска, кэш повторов и отправка стука.
//!
//! Порядок на вызываемой стороне: `стук -> допуск -> Retry -> TLS -> KK`. До верного стука адрес
//! не получает от гнезда ни одного пакета: пакеты недопущенных адресов не доходят до quinn
//! (ни Retry, ни сброса, ни согласования версии). Единственное место `try_send(` в крейте.
//! Спецификация: `docs/specs/stage-09b-knock.md`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::pin::Pin as StdPin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_identity::{KNOCK_LEN, KnockKeys, KxPeer, PairId};
use chervo_transport::PeerFilter;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::broadcast;

use crate::limits::Counters;
use crate::{KNOCK_ACCEPT_SPAN, KNOCK_HINT_SPAN, KNOCK_WINDOW_SECS, QuinnConfig, TransportEvent};

/// Сколько раз цикл фильтра опрашивает гнездо подряд без единого пропущенного пакета.
pub(crate) const MAX_FILTER_POLLS: usize = 16;
/// Базовая жизнь записи кэша повторов (4 окна); к ней добавляется модуль поправки часов.
const REPLAY_LIFETIME: Duration = Duration::from_secs(120);
/// Предел добавки к жизни записи за счёт поправки (защита от переполнения `Instant`).
const REPLAY_OFFSET_CAP: Duration = Duration::from_secs(30 * 24 * 3600);
/// Событие «сбиты часы» не чаще раза в минуту на пару.
const SKEW_EVENT_EVERY: Duration = Duration::from_secs(60);
/// Попыток отправки стука при `WouldBlock`.
const SEND_TRIES: usize = 8;

/// Номер окна стука по времени UNIX в миллисекундах; отрицательное время даёт 0.
pub fn window_at(unix_ms: i64) -> u64 {
    if unix_ms < 0 {
        return 0;
    }
    #[allow(clippy::cast_sign_loss)]
    let ms = unix_ms as u64;
    ms / KNOCK_WINDOW_SECS.saturating_mul(1000)
}

/// Адрес источника в каноническом виде: v4-mapped как IPv4.
pub(crate) fn canon(a: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = a
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(IpAddr::V4(v4), v6.port());
    }
    a
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------------
// Таблица поиска по `id`
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Cand {
    idx: usize,
    window: u64,
    /// Окно допуска (иначе «подсказка»: верный стук не допускается, но отмечается).
    accept: bool,
}

#[derive(Default)]
struct Keyring {
    keys: Vec<(PairId, KnockKeys)>,
    generation: u64,
    /// (окно по исправленному времени, окно по системному при ненулевой поправке, поколение).
    built: Option<(u64, Option<u64>, u64)>,
    table: HashMap<[u8; 16], Vec<Cand>>,
}

impl Keyring {
    fn add(&mut self, id: [u8; 16], cand: Cand) {
        let list = self.table.entry(id).or_default();
        if let Some(old) = list
            .iter_mut()
            .find(|c| c.idx == cand.idx && c.window == cand.window)
        {
            old.accept |= cand.accept;
        } else {
            list.push(cand);
        }
    }

    /// Пересборка при смене окна, поправки или набора пар.
    fn ensure(&mut self, w_corr: u64, w_sys: Option<u64>) {
        let want = (w_corr, w_sys, self.generation);
        if self.built == Some(want) {
            return;
        }
        self.table.clear();
        let mut adds: Vec<([u8; 16], Cand)> = Vec::new();
        for (idx, (_, k)) in self.keys.iter().enumerate() {
            let span = i64::try_from(KNOCK_HINT_SPAN).unwrap_or(0);
            for d in -span..=span {
                let Some(window) = w_corr.checked_add_signed(d) else {
                    continue;
                };
                let accept = d.unsigned_abs() <= KNOCK_ACCEPT_SPAN;
                adds.push((
                    k.recv_id(window),
                    Cand {
                        idx,
                        window,
                        accept,
                    },
                ));
            }
            if let Some(ws) = w_sys {
                for d in -1i64..=1 {
                    let Some(window) = ws.checked_add_signed(d) else {
                        continue;
                    };
                    adds.push((
                        k.recv_id(window),
                        Cand {
                            idx,
                            window,
                            accept: true,
                        },
                    ));
                }
            }
        }
        for (id, cand) in adds {
            self.add(id, cand);
        }
        self.built = Some(want);
    }
}

// ---------------------------------------------------------------------------------------------
// Кэш повторов
// ---------------------------------------------------------------------------------------------

pub(crate) type ReplayKey = (PairId, [u8; 16]);

pub(crate) enum ReplayErr {
    Seen,
    Full,
}

pub(crate) struct Replay {
    set: HashSet<ReplayKey>,
    /// (момент, когда запись можно забыть, ключ).
    order: VecDeque<(Instant, ReplayKey)>,
    capacity: usize,
}

/// Срок жизни записи: стук принимается по исправленному и по системному времени, то есть в двух
/// интервалах по 90 с, сдвинутых на поправку; запись держится дольше обоих.
pub(crate) fn replay_lifetime(offset_ms: i64) -> Duration {
    let extra = Duration::from_millis(offset_ms.unsigned_abs()).min(REPLAY_OFFSET_CAP);
    REPLAY_LIFETIME + extra
}

impl Replay {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Новая запись; `offset_ms`: поправка часов на момент приёма.
    pub(crate) fn check_insert(
        &mut self,
        key: ReplayKey,
        now: Instant,
        offset_ms: i64,
    ) -> Result<(), ReplayErr> {
        // Порядок очереди может нарушиться при смене поправки: это лишь задерживает удаление
        // отдельных записей, раньше срока запись не удаляется.
        while let Some((t, k)) = self.order.front().copied() {
            if t > now {
                break;
            }
            self.order.pop_front();
            self.set.remove(&k);
        }
        if self.set.contains(&key) {
            return Err(ReplayErr::Seen);
        }
        if self.set.len() >= self.capacity {
            return Err(ReplayErr::Full);
        }
        let until = now
            .checked_add(replay_lifetime(offset_ms))
            .or_else(|| now.checked_add(REPLAY_LIFETIME))
            .unwrap_or(now);
        self.set.insert(key);
        self.order.push_back((until, key));
        Ok(())
    }

    /// Поправка сменилась: у уже внесённых записей интервал приёма сдвинулся, продлить срок.
    pub(crate) fn extend_for_offset(&mut self, now: Instant, offset_ms: i64) {
        let Some(until) = now.checked_add(replay_lifetime(offset_ms)) else {
            return;
        };
        for (t, _) in &mut self.order {
            if *t < until {
                *t = until;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Таблица допуска
// ---------------------------------------------------------------------------------------------

struct Entry {
    /// Допуск по верному стуку действует до этого момента.
    expires: Option<Instant>,
    /// Сколько подтверждённых `Incoming` ещё допускается.
    attempts: u32,
    /// Закрепления (RAII): собственные звонки, `serve`, аутентифицированные соединения.
    pins: u32,
    /// Сколько раз с этого адреса пропущен пакет (для `connect_silent`).
    rx: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Допуск открыт и попытки остались: пропускать всё.
    Open,
    /// Пропускать, но стук всё равно распознавать (закрепление или допуск без попыток).
    Pass,
    /// Молчать.
    Closed,
}

struct AdmitTable {
    map: HashMap<SocketAddr, Entry>,
    last_purge: Instant,
}

impl AdmitTable {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            last_purge: Instant::now(),
        }
    }

    fn purge(&mut self, now: Instant) {
        self.map
            .retain(|_, e| e.pins > 0 || e.expires.is_some_and(|t| t > now));
        self.last_purge = now;
    }

    fn classify(&mut self, addr: SocketAddr, now: Instant) -> Gate {
        let Some(e) = self.map.get_mut(&addr) else {
            return Gate::Closed;
        };
        let ttl_valid = e.expires.is_some_and(|t| t > now);
        let gate = if ttl_valid && e.attempts > 0 {
            Gate::Open
        } else if ttl_valid || e.pins > 0 {
            Gate::Pass
        } else {
            Gate::Closed
        };
        if gate != Gate::Closed {
            e.rx = e.rx.saturating_add(1);
        }
        gate
    }

    /// Допуск по верному стуку; `false`, если таблица заполнена.
    fn open(
        &mut self,
        addr: SocketAddr,
        now: Instant,
        ttl: Duration,
        attempts: u32,
        cap: usize,
    ) -> bool {
        if !self.map.contains_key(&addr) && self.map.len() >= cap {
            self.purge(now);
            if self.map.len() >= cap {
                return false;
            }
        }
        let e = self.map.entry(addr).or_insert(Entry {
            expires: None,
            attempts: 0,
            pins: 0,
            rx: 0,
        });
        e.expires = Some(now + ttl);
        e.attempts = attempts;
        true
    }

    /// Списать попытку подтверждённого `Incoming`.
    fn consume(&mut self, addr: SocketAddr, now: Instant) -> bool {
        match self.map.get_mut(&addr) {
            Some(e) if e.attempts > 0 && e.expires.is_some_and(|t| t > now) => {
                e.attempts -= 1;
                true
            }
            _ => false,
        }
    }

    fn pin(&mut self, addr: SocketAddr) -> u64 {
        let e = self.map.entry(addr).or_insert(Entry {
            expires: None,
            attempts: 0,
            pins: 0,
            rx: 0,
        });
        e.pins = e.pins.saturating_add(1);
        e.rx
    }

    fn unpin(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(e) = self.map.get_mut(&addr) {
            e.pins = e.pins.saturating_sub(1);
            if e.pins == 0 && !e.expires.is_some_and(|t| t > now) {
                self.map.remove(&addr);
            }
        }
    }

    fn rx_of(&self, addr: SocketAddr) -> u64 {
        self.map.get(&addr).map_or(0, |e| e.rx)
    }
}

/// Закрепление адреса в таблице допуска: пока оно живо, пакеты с адреса проходят.
pub(crate) struct Pin {
    state: Arc<KnockState>,
    addr: SocketAddr,
    rx0: u64,
}

impl Pin {
    /// С адреса после закрепления пришёл хотя бы один пропущенный пакет.
    pub(crate) fn heard(&self) -> bool {
        lock(&self.state.admit).rx_of(self.addr) > self.rx0
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        lock(&self.state.admit).unpin(self.addr, Instant::now());
    }
}

// ---------------------------------------------------------------------------------------------
// Состояние стука
// ---------------------------------------------------------------------------------------------

pub(crate) struct KnockState {
    pub(crate) required: bool,
    ttl: Duration,
    attempts: u32,
    admit_capacity: usize,
    counters: Arc<Counters>,
    filter: Arc<dyn PeerFilter>,
    events: broadcast::Sender<TransportEvent>,
    offset_ms: AtomicI64,
    #[cfg(test)]
    pub(crate) sys_skew_ms: AtomicI64,
    ring: Mutex<Keyring>,
    admit: Mutex<AdmitTable>,
    replay: Mutex<Replay>,
    skew_events: Mutex<HashMap<PairId, Instant>>,
    tx: Mutex<Arc<dyn AsyncUdpSocket>>,
}

impl KnockState {
    pub(crate) fn new(
        cfg: &QuinnConfig,
        counters: Arc<Counters>,
        filter: Arc<dyn PeerFilter>,
        events: broadcast::Sender<TransportEvent>,
        raw: Arc<dyn AsyncUdpSocket>,
    ) -> Arc<Self> {
        Arc::new(Self {
            required: cfg.knock_required,
            ttl: cfg.knock_admit_ttl,
            attempts: cfg.knock_admit_attempts,
            admit_capacity: cfg.admit_capacity.max(1),
            counters,
            filter,
            events,
            offset_ms: AtomicI64::new(0),
            #[cfg(test)]
            sys_skew_ms: AtomicI64::new(0),
            ring: Mutex::new(Keyring::default()),
            admit: Mutex::new(AdmitTable::new()),
            replay: Mutex::new(Replay::new(cfg.replay_capacity)),
            skew_events: Mutex::new(HashMap::new()),
            tx: Mutex::new(raw),
        })
    }

    // --- время ---

    fn system_ms(&self) -> i64 {
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        #[cfg(test)]
        let base = base.saturating_add(self.sys_skew_ms.load(Ordering::Relaxed));
        base
    }

    pub(crate) fn set_offset(&self, offset_ms: i64) {
        let old = self.offset_ms.swap(offset_ms, Ordering::Relaxed);
        if old != offset_ms {
            lock(&self.replay).extend_for_offset(Instant::now(), offset_ms);
        }
    }

    pub(crate) fn offset(&self) -> i64 {
        self.offset_ms.load(Ordering::Relaxed)
    }

    // --- пары ---

    /// Пересобрать ключи стука; пара с непригодным ключом остаётся вне таблицы.
    pub(crate) fn set_peers(&self, peers: &[KxPeer]) {
        let keys: Vec<(PairId, KnockKeys)> = peers
            .iter()
            .filter_map(|p| p.knock_keys().ok().map(|k| (p.pair(), k)))
            .collect();
        let mut ring = lock(&self.ring);
        ring.keys = keys;
        ring.generation = ring.generation.wrapping_add(1);
        ring.built = None;
        ring.table.clear();
    }

    // --- закрепления и допуск ---

    pub(crate) fn pin(self: &Arc<Self>, addr: SocketAddr) -> Pin {
        let addr = canon(addr);
        let rx0 = lock(&self.admit).pin(addr);
        Pin {
            state: self.clone(),
            addr,
            rx0,
        }
    }

    /// Списать попытку допуска подтверждённого `Incoming`; `false`: нет допуска или он исчерпан.
    pub(crate) fn consume_attempt(&self, addr: SocketAddr) -> bool {
        let ok = lock(&self.admit).consume(canon(addr), Instant::now());
        if !ok {
            Counters::bump(&self.counters.admit_exhausted);
        }
        ok
    }

    // --- звонящий ---

    /// Стук для пары. `raw`: по системному времени без поправки.
    pub(crate) fn make_knock(&self, pair: &PairId, raw: bool) -> Option<[u8; KNOCK_LEN]> {
        let sys = self.system_ms();
        let ms = if raw {
            sys
        } else {
            sys.saturating_add(self.offset())
        };
        let ring = lock(&self.ring);
        let (_, keys) = ring.keys.iter().find(|(p, _)| p == pair)?;
        keys.make(window_at(ms)).ok()
    }

    /// Один раз без ожидания (для первого стука после `rebind`).
    pub(crate) fn send_now(&self, dest: SocketAddr, knock: &[u8; KNOCK_LEN]) {
        let sock = lock(&self.tx).clone();
        let dest = family_for(&sock, dest);
        let _ = sock.try_send(&Transmit {
            destination: dest,
            ecn: None,
            contents: knock,
            segment_size: None,
            src_ip: None,
        });
    }

    /// Отправка стука; при `WouldBlock` ожидание готовности гнезда.
    pub(crate) async fn send(&self, dest: SocketAddr, knock: &[u8; KNOCK_LEN]) {
        let sock = lock(&self.tx).clone();
        let dest = family_for(&sock, dest);
        for _ in 0..SEND_TRIES {
            let t = Transmit {
                destination: dest,
                ecn: None,
                contents: knock,
                segment_size: None,
                src_ip: None,
            };
            match sock.try_send(&t) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut poller = sock.clone().create_io_poller();
                    let ready = poll_fn(|cx| poller.as_mut().poll_writable(cx)).await;
                    if ready.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    pub(crate) fn set_tx(&self, raw: Arc<dyn AsyncUdpSocket>) {
        *lock(&self.tx) = raw;
    }

    // --- вызываемый ---

    /// Распознать и обработать стук. `true`: датаграмма опознана как стук (её нельзя отдавать quinn).
    pub(crate) fn try_knock(&self, addr: SocketAddr, seg: &[u8]) -> bool {
        let Some(id) = seg.get(..16).and_then(|s| <[u8; 16]>::try_from(s).ok()) else {
            return false;
        };
        let sys = self.system_ms();
        let off = self.offset();
        let w_corr = window_at(sys.saturating_add(off));
        let w_sys = (off != 0).then(|| window_at(sys));
        let hit = {
            let mut guard = lock(&self.ring);
            guard.ensure(w_corr, w_sys);
            let ring = &*guard;
            let Some(list) = ring.table.get(&id) else {
                return false;
            };
            let mut best: Option<(PairId, bool)> = None;
            for c in list {
                let Some((pair, keys)) = ring.keys.get(c.idx) else {
                    continue;
                };
                if keys.verify(c.window, seg) && (best.is_none() || c.accept) {
                    best = Some((*pair, c.accept));
                }
            }
            best
        };
        let Some((pair, accept)) = hit else {
            Counters::bump(&self.counters.knock_bad);
            return true;
        };
        // подсказка о часах только для пары, прошедшей `PeerFilter`
        if !self.filter.is_allowed(&pair) {
            return true;
        }
        if !accept {
            Counters::bump(&self.counters.knock_skewed);
            self.skew_event(pair);
            return true;
        }
        let Some(nonce) = seg.get(16..32).and_then(|s| <[u8; 16]>::try_from(s).ok()) else {
            return true;
        };
        let now = Instant::now();
        match lock(&self.replay).check_insert((pair, nonce), now, off) {
            Ok(()) => {}
            Err(ReplayErr::Seen) => {
                Counters::bump(&self.counters.knock_replay);
                return true;
            }
            Err(ReplayErr::Full) => {
                Counters::bump(&self.counters.admit_full);
                return true;
            }
        }
        let opened =
            lock(&self.admit).open(addr, now, self.ttl, self.attempts, self.admit_capacity);
        if opened {
            Counters::bump(&self.counters.knock_ok);
        } else {
            Counters::bump(&self.counters.admit_full);
        }
        true
    }

    fn skew_event(&self, pair: PairId) {
        let now = Instant::now();
        let mut map = lock(&self.skew_events);
        let due = map
            .get(&pair)
            .is_none_or(|t| now.saturating_duration_since(*t) >= SKEW_EVENT_EVERY);
        if due {
            map.insert(pair, now);
            let _ = self
                .events
                .send(TransportEvent::ClockSkewSuspected { pair });
        }
    }

    /// Вырезает из датаграммы (с сегментами GRO) опознанные стуки, остальное сдвигает к началу.
    /// Возвращает новую длину.
    fn strip_knocks(&self, addr: SocketAddr, buf: &mut [u8], len: usize, stride: usize) -> usize {
        let len = len.min(buf.len());
        let stride = stride.max(1);
        let (mut out, mut pos) = (0usize, 0usize);
        while pos < len {
            let end = pos.saturating_add(stride).min(len);
            let is_knock = end - pos == KNOCK_LEN
                && buf.get(pos..end).is_some_and(|s| self.try_knock(addr, s));
            if !is_knock {
                if out != pos {
                    buf.copy_within(pos..end, out);
                }
                out += end - pos;
            }
            pos = end;
        }
        out
    }

    /// Фильтр партии: оставляет пропущенные записи в начале срезов, возвращает их число.
    pub(crate) fn filter_batch(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        n: usize,
    ) -> usize {
        let n = n.min(bufs.len()).min(meta.len());
        let mut kept = 0usize;
        for i in 0..n {
            let Some(m) = meta.get(i).copied() else {
                continue;
            };
            let addr = canon(m.addr);
            let now = Instant::now();
            let gate = {
                let mut adm = lock(&self.admit);
                if now.saturating_duration_since(adm.last_purge) >= Duration::from_secs(1) {
                    adm.purge(now);
                }
                adm.classify(addr, now)
            };
            let stride = if m.stride == 0 { m.len } else { m.stride };
            let keep = match gate {
                // Open и Pass: стук тоже распознаётся (досланные стуки, повтор после `rebind`
                // попадают в кэш повторов), опознанные сегменты вырезаются, остальное проходит.
                Gate::Open | Gate::Pass => {
                    let new_len = bufs
                        .get_mut(i)
                        .map_or(m.len, |b| self.strip_knocks(addr, b, m.len, stride));
                    if new_len != m.len
                        && let Some(mm) = meta.get_mut(i)
                    {
                        mm.len = new_len;
                    }
                    new_len > 0
                }
                Gate::Closed => {
                    let data = bufs.get(i).and_then(|b| b.get(..m.len));
                    let mut knocked = false;
                    if let Some(d) = data {
                        for seg in d.chunks(stride.max(1)) {
                            if seg.len() == KNOCK_LEN && self.try_knock(addr, seg) {
                                knocked = true;
                            }
                        }
                    }
                    if !knocked {
                        Counters::bump(&self.counters.dropped_unadmitted);
                    }
                    false
                }
            };
            if keep {
                if kept != i {
                    bufs.swap(kept, i);
                    meta.swap(kept, i);
                }
                kept += 1;
            }
        }
        kept
    }
}

/// Адрес назначения в семействе гнезда (IPv4 на двойном гнезде как v4-mapped).
fn family_for(sock: &Arc<dyn AsyncUdpSocket>, dest: SocketAddr) -> SocketAddr {
    match (sock.local_addr(), dest) {
        (Ok(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => dest,
    }
}

// ---------------------------------------------------------------------------------------------
// Гнездо
// ---------------------------------------------------------------------------------------------

/// Обёртка над гнездом quinn: отбрасывает пакеты недопущенных адресов до quinn.
pub(crate) struct KnockSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    state: Arc<KnockState>,
}

impl KnockSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, state: Arc<KnockState>) -> Self {
        Self { inner, state }
    }
}

impl fmt::Debug for KnockSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KnockSocket(..)")
    }
}

impl AsyncUdpSocket for KnockSocket {
    fn create_io_poller(self: Arc<Self>) -> StdPin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if !self.state.required {
            return self.inner.poll_recv(cx, bufs, meta);
        }
        for _ in 0..MAX_FILTER_POLLS {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => {
                    let kept = self.state.filter_batch(bufs, meta, n);
                    if kept > 0 {
                        return Poll::Ready(Ok(kept));
                    }
                }
                other => return other,
            }
        }
        // Поток не держим: уступить исполнителю и вернуться.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
