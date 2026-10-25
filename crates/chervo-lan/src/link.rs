//! `LanDiscovery`: the production link. One plain std thread owns the sockets and the
//! `LanCore`; contract calls only store the latest value under a lock (bounded memory
//! whatever the call rate) and wake the thread.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use chervo_addr::{LAN_FOUND_MAX, LanFound, LanLink, LanPeer, LanStatus};
use chervo_identity::PairId;

use crate::core::{CoreConfig, LanCore, LanStats, Readiness};
use crate::limits::{BEACON_LEN, BUDGET_PAUSE, MAX_WAIT, MIN_WAIT, REOPEN_AFTER};
use crate::net::{Net, Recv, Sockets};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Latest-value mailbox between the contract calls and the thread.
struct Shared {
    m: Mutex<Mailbox>,
    cv: Condvar,
}

#[derive(Default)]
struct Mailbox {
    local: Option<Option<SocketAddrV4>>,
    peers: Option<Vec<LanPeer>>,
    wanted: Option<Vec<PairId>>,
    trigger: bool,
    stop: bool,
    found: VecDeque<LanFound>,
    status: Option<LanStatus>,
    stats: LanStats,
}

/// Production link: own thread, real multicast sockets on `wants_sockets()`.
pub struct LanDiscovery {
    shared: Arc<Shared>,
}

impl LanDiscovery {
    /// `now_unix`: the engine clock (with the user's NTP offset). Never blocks. A thread spawn
    /// failure gives status `Unavailable`, no panic.
    pub fn start(now_unix: Arc<dyn Fn() -> u64 + Send + Sync>) -> Arc<Self> {
        Self::start_with(Net::production(), CoreConfig::default(), now_unix)
    }

    pub(crate) fn start_with(
        net: Net,
        cfg: CoreConfig,
        now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            m: Mutex::new(Mailbox {
                status: Some(LanStatus::Off),
                ..Mailbox::default()
            }),
            cv: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        // the thread is detached; it ends after `shutdown` and closes its sockets then
        let spawned = std::thread::Builder::new()
            .name("chervo-lan".to_owned())
            .spawn(move || run(&worker, &net, cfg, now_unix.as_ref()));
        if spawned.is_err() {
            lock(&shared.m).status = Some(LanStatus::Unavailable);
        }
        Arc::new(Self { shared })
    }

    pub fn stats(&self) -> LanStats {
        lock(&self.shared.m).stats
    }

    fn put<F: FnOnce(&mut Mailbox)>(&self, f: F) {
        f(&mut lock(&self.shared.m));
        self.shared.cv.notify_all();
    }
}

impl LanLink for LanDiscovery {
    fn set_local(&self, local: Option<SocketAddrV4>) {
        self.put(|m| m.local = Some(local));
    }

    fn set_peers(&self, peers: Vec<LanPeer>) {
        self.put(|m| m.peers = Some(peers));
    }

    fn set_wanted(&self, wanted: Vec<PairId>) {
        self.put(|m| m.wanted = Some(wanted));
    }

    fn trigger(&self) {
        self.put(|m| m.trigger = true);
    }

    fn take_found(&self) -> Vec<LanFound> {
        lock(&self.shared.m).found.drain(..).collect()
    }

    fn status(&self) -> LanStatus {
        lock(&self.shared.m).status.unwrap_or(LanStatus::Off)
    }

    /// Signals the thread to stop and returns at once (no waiting, no sleeping: the caller may be a
    /// runtime worker). The thread notices within one receive timeout (at most `MAX_WAIT`) and
    /// closes both sockets before it ends; the thread is detached.
    fn shutdown(&self) {
        self.put(|m| {
            m.stop = true;
            m.status = Some(LanStatus::Off);
        });
    }
}

impl Drop for LanDiscovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Socket state kept by the thread.
struct Driver {
    sockets: Option<(Sockets, Ipv4Addr)>,
    retry_at: Option<Duration>,
    unavailable: bool,
}

impl Driver {
    /// Makes the sockets follow `wants_sockets()` (opening in D12 order, 30 s retry on failure).
    fn reconcile(&mut self, core: &LanCore, net: &Net, now: Duration) {
        match core.wants_sockets() {
            None => {
                self.sockets = None;
                self.retry_at = None;
                self.unavailable = false;
            }
            Some(ip) => {
                if self.sockets.as_ref().is_some_and(|(_, own)| *own == ip) {
                    return;
                }
                self.sockets = None;
                if self.retry_at.is_some_and(|t| now < t) {
                    return;
                }
                match net.open(ip) {
                    Ok(s) => {
                        self.sockets = Some((s, ip));
                        self.retry_at = None;
                        self.unavailable = false;
                    }
                    Err(_) => {
                        self.retry_at = Some(now + REOPEN_AFTER);
                        self.unavailable = true;
                    }
                }
            }
        }
    }

    fn status(&self, core: &LanCore) -> LanStatus {
        match core.readiness() {
            Readiness::NoLocal => LanStatus::Off,
            Readiness::NoLan => LanStatus::NoLan,
            Readiness::NoPeers => LanStatus::NoPeers,
            Readiness::Ready => {
                if self.sockets.is_some() {
                    LanStatus::Running
                } else if self.unavailable {
                    LanStatus::Unavailable
                } else {
                    LanStatus::Off
                }
            }
        }
    }
}

fn run(shared: &Shared, net: &Net, cfg: CoreConfig, clock: &(dyn Fn() -> u64 + Send + Sync)) {
    let start = Instant::now();
    let mut core = LanCore::new(cfg);
    let mut drv = Driver {
        sockets: None,
        retry_at: None,
        unavailable: false,
    };
    // one byte more than a beacon: a longer datagram is seen as a wrong length
    let mut buf = [0u8; BEACON_LEN + 1];
    let oversize = [0u8; BEACON_LEN + 1];
    let unspecified = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    loop {
        let now = start.elapsed();
        let unix = clock();

        // 1. pending commands, in the order of the engine's calls
        let (local, peers, wanted, trigger, stop) = {
            let mut g = lock(&shared.m);
            (
                g.local.take(),
                g.peers.take(),
                g.wanted.take(),
                std::mem::take(&mut g.trigger),
                g.stop,
            )
        };
        if stop {
            break;
        }
        if let Some(l) = local {
            core.set_local(l, now);
        }
        if let Some(p) = peers {
            core.set_peers(p);
        }
        if let Some(w) = wanted {
            core.set_wanted(w);
        }
        if trigger {
            core.trigger(now);
        }

        // 2. sockets follow the core
        drv.reconcile(&core, net, now);

        // 3. send
        if let Some((sockets, _)) = &drv.sockets
            && let Some(beacon) = core.poll_send(now, unix)
            && !sockets.send(&beacon)
        {
            core.note_send_error();
        }

        // 4. publish found items, statistics and status
        {
            let found = core.take_found();
            let mut g = lock(&shared.m);
            for f in found {
                if g.found.len() >= LAN_FOUND_MAX {
                    g.found.pop_front();
                }
                g.found.push_back(f);
            }
            g.stats = core.stats();
            if !g.stop {
                g.status = Some(drv.status(&core));
            }
        }

        // 5. receive (or wait for commands when there are no sockets)
        let wait = core.next_wakeup(now).clamp(MIN_WAIT, MAX_WAIT);
        match &drv.sockets {
            Some((sockets, _)) => {
                if !core.may_read(now) {
                    std::thread::sleep(BUDGET_PAUSE);
                    continue;
                }
                match sockets.recv(&mut buf, wait) {
                    Recv::Data(n, src) => {
                        let data = buf.get(..n).unwrap_or(&[]);
                        core.on_datagram(src, data, start.elapsed(), clock());
                    }
                    Recv::Oversize => {
                        core.on_datagram(unspecified, &oversize, start.elapsed(), clock());
                    }
                    Recv::Timeout => {}
                    Recv::Error => std::thread::sleep(MIN_WAIT * 10),
                }
            }
            None => {
                let g = lock(&shared.m);
                let idle = g.local.is_none()
                    && g.peers.is_none()
                    && g.wanted.is_none()
                    && !g.trigger
                    && !g.stop;
                if idle {
                    let _ = shared.cv.wait_timeout(g, wait);
                }
            }
        }
    }
    // sockets are closed here, before the thread ends
    drop(drv);
    lock(&shared.m).status = Some(LanStatus::Off);
}
