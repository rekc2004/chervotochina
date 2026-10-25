//! Поиск друзей в локальной сети (этап 13в, часть движка).
//!
//! Движок видит только `Arc<dyn LanLink>` (контракт из `chervo-addr`): сокетов здесь нет.
//! Раз в такт задача передаёт ссылке нашу частную точку входа, набор друзей с ключами поиска
//! и набор «ожидаемых» пар (активные друзья без живого соединения), а найденный адрес
//! превращает в подсказку: запись в памяти, одна на пару, на 180 с. Подсказка идёт только в
//! `plan_dials` перед `friend_plan_confirmed`, строгая (не чаще одного набора на IP за 32 с) и
//! запускает только обычный путь: стук, QUIC, Noise KK. В книгу она не пишется, не
//! публикуется, не отдаётся другим друзьям и не попадает в `own.observe`; адрес сохраняется,
//! только когда KK удался (`note_contact` в `on_connection`).

use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chervo_addr::{
    AddrClass, AddrSource, KnownAddr, LanFound, LanLink, LanPeer, LanStatus, classify,
};
use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::time::Instant;

use crate::engine::{ConnectError, Engine, Inner, State, period};

/// Подсказок в памяти (самые давние вытесняются).
pub(crate) const LAN_HINTS_MAX: usize = 256;
/// Срок жизни подсказки.
pub(crate) const LAN_HINT_TTL: Duration = Duration::from_secs(180);

/// Отпечаток одного друга в наборе ссылки: пара и оба публичных ключа обмена. Меняется при
/// блокировке, удалении, отзыве, смене ключа.
type PeerFp = (PairId, [u8; 32], [u8; 32]);

/// Последнее, что передано ссылке (изменения передаются только по различию).
#[derive(Default)]
struct Pushed {
    local: Option<Option<SocketAddrV4>>,
    peers: Option<Vec<PeerFp>>,
    wanted: Option<Vec<PairId>>,
}

#[derive(Default)]
struct Slot {
    link: Option<Arc<dyn LanLink>>,
    /// Номер подключения: задача прежнего подключения завершается, увидев чужой номер.
    generation: u64,
    pushed: Pushed,
}

/// Состояние поиска в LAN внутри `Inner`.
#[derive(Default)]
pub(crate) struct LanSlot {
    slot: Mutex<Slot>,
}

impl LanSlot {
    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn link(&self) -> Option<Arc<dyn LanLink>> {
        self.lock().link.clone()
    }
}

/// Подсказка перед записями книги: `[Lan, hint, short_lived] ++ usable_known`. Просроченная
/// подсказка не добавляется.
pub(crate) fn prepend_hint<C>(
    st: &State<C>,
    pair: &PairId,
    now: Instant,
    unix: u64,
    entries: Vec<KnownAddr>,
) -> Vec<KnownAddr> {
    let Some((addr, at)) = st.lan_hints.get(pair) else {
        return entries;
    };
    if now.saturating_duration_since(*at) >= LAN_HINT_TTL {
        return entries;
    }
    let mut out = Vec::with_capacity(entries.len() + 1);
    out.push(KnownAddr {
        addr: SocketAddr::V4(*addr),
        source: AddrSource::Lan,
        last_seen_unix: unix,
        short_lived: true,
        hint: true,
    });
    out.extend(entries);
    out
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Одна синхронизация со ссылкой: найденное в подсказки, затем изменения ожидаемых пар,
    /// набора друзей и точки входа (в таком порядке). `false`: ссылки нет или это задача
    /// прежнего подключения. Вызовы ссылки не блокируют; ключи считаются вне замка.
    pub(crate) fn lan_sync(&self, generation: Option<u64>) -> bool {
        let (link, current) = {
            let s = self.lan.lock();
            (s.link.clone(), s.generation)
        };
        let Some(link) = link else {
            return false;
        };
        if generation.is_some_and(|g| g != current) {
            return false;
        }
        let found = link.take_found();
        let now = Instant::now();
        let (local, fps, wanted) = {
            let mut st = self.lock();
            let route = st.own.local().and_then(|l| l.route.v4);
            let local = lan_local(&st);
            self.lan_absorb(&mut st, found, route.map(IpAddr::V4), now);
            let (fps, wanted) = lan_sets(&st);
            (local, fps, wanted)
        };

        // что изменилось с прошлого раза; решение и запись «передано» под замком слота
        let (push_local, push_peers, push_wanted) = {
            let mut s = self.lan.lock();
            if s.generation != current {
                return false;
            }
            let push_local = s.pushed.local != Some(local);
            let push_peers = s.pushed.peers.as_ref() != Some(&fps);
            let push_wanted = s.pushed.wanted.as_ref() != Some(&wanted);
            if push_local {
                s.pushed.local = Some(local);
            }
            if push_peers {
                s.pushed.peers = Some(fps.clone());
            }
            if push_wanted {
                s.pushed.wanted = Some(wanted.clone());
            }
            (push_local, push_peers, push_wanted)
        };
        // порядок важен: ожидаемые пары первыми, чтобы они были известны ссылке к моменту,
        // когда набор друзей и точка входа впервые включают сокеты (иначе маяк между вызовами
        // заморозил бы пустой набор на всю эпоху)
        if push_wanted {
            link.set_wanted(wanted);
        }
        if push_peers {
            link.set_peers(self.lan_peers(&fps));
        }
        if push_local {
            link.set_local(local);
        }
        true
    }

    /// Ключи поиска для друзей из отпечатков. Берутся из набора транспорта (`published`),
    /// считаются вне замка; неудача по паре молчит (проблема ключа сообщается в другом месте).
    fn lan_peers(&self, fps: &[PeerFp]) -> Vec<LanPeer> {
        let peers: Vec<chervo_identity::KxPeer> = {
            let st = self.lock();
            st.published
                .iter()
                .filter(|p| fps.iter().any(|f| f.0 == p.pair()))
                .cloned()
                .collect()
        };
        let mut out: Vec<LanPeer> = peers
            .iter()
            .filter_map(|p| {
                p.lan_keys().ok().map(|keys| LanPeer {
                    pair: p.pair(),
                    keys,
                })
            })
            .collect();
        out.sort_by(|a, b| a.pair.as_bytes().cmp(b.pair.as_bytes()));
        out
    }

    /// Найденное становится подсказкой, только если пара активна, без живого соединения и без
    /// проблем с ключом, адрес частный (в тестах петлевой), порт не 0 и это не наш адрес.
    /// Одна подсказка на пару (последняя), не больше `LAN_HINTS_MAX`; старые и ненужные
    /// удаляются.
    fn lan_absorb(
        &self,
        st: &mut State<T::Conn>,
        found: Vec<LanFound>,
        route: Option<IpAddr>,
        now: Instant,
    ) {
        for f in found {
            let ip = IpAddr::V4(*f.addr.ip());
            let class_ok = matches!(classify(ip), AddrClass::Private | AddrClass::Loopback);
            if !class_ok
                || f.addr.port() == 0
                || route == Some(ip)
                || !st.book.is_active(&f.pair)
                || st.live.contains_key(&f.pair)
                || st.key_problems.contains_key(&f.pair)
            {
                continue;
            }
            if st.lan_hints.len() >= LAN_HINTS_MAX && !st.lan_hints.contains_key(&f.pair) {
                let oldest = st
                    .lan_hints
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(p, _)| *p);
                if let Some(p) = oldest {
                    st.lan_hints.remove(&p);
                }
            }
            st.lan_hints.insert(f.pair, (f.addr, now));
        }
        let State {
            lan_hints,
            book,
            live,
            ..
        } = st;
        lan_hints.retain(|p, (_, at)| {
            now.saturating_duration_since(*at) < LAN_HINT_TTL
                && book.is_active(p)
                && !live.contains_key(p)
        });
    }

    pub(crate) async fn run_lan(self: Arc<Self>, generation: u64) {
        loop {
            tokio::time::sleep(period(self.cfg.tick)).await;
            if self.is_shut() || !self.lan_sync(Some(generation)) {
                return;
            }
        }
    }

    /// Отключение: ссылка закрывается, подсказки забываются. Повторный вызов безвреден.
    pub(crate) fn lan_detach(&self) {
        let link = {
            let mut s = self.lan.lock();
            s.generation = s.generation.wrapping_add(1);
            s.pushed = Pushed::default();
            s.link.take()
        };
        self.lock().lan_hints.clear();
        if let Some(l) = link {
            l.shutdown();
        }
    }

    /// Серия маяков по действию пользователя, если ссылка подключена.
    pub(crate) fn lan_trigger(&self) {
        if let Some(l) = self.lan.link() {
            l.trigger();
        }
    }
}

/// Наша частная точка входа: `route.v4` класса `Private` и первый ненулевой порт IPv4 из
/// адресов прослушивания (то же правило, что у проброса порта).
fn lan_local<C>(st: &State<C>) -> Option<SocketAddrV4> {
    let local = st.own.local()?;
    let ip = local.route.v4?;
    if classify(IpAddr::V4(ip)) != AddrClass::Private {
        return None;
    }
    let port = local
        .listen
        .iter()
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4.port()),
            SocketAddr::V6(_) => None,
        })
        .filter(|p| *p != 0)?;
    Some(SocketAddrV4::new(ip, port))
}

/// Отпечатки друзей для ссылки (только активные, без проблем с ключом, ключ друга из книги;
/// гости исключены) и ожидаемые пары (активные друзья без живого соединения).
fn lan_sets<C>(st: &State<C>) -> (Vec<PeerFp>, Vec<PairId>) {
    let mut fps: Vec<PeerFp> = st
        .published
        .iter()
        .filter(|p| {
            let pair = p.pair();
            !st.key_problems.contains_key(&pair)
                && st.book.is_active(&pair)
                && st.book.get(&pair).is_some_and(|f| f.friend_x == p.theirs())
        })
        .map(|p| (p.pair(), p.ours_public().to_bytes(), p.theirs().to_bytes()))
        .collect();
    fps.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    fps.dedup_by(|a, b| a.0 == b.0);
    let mut wanted: Vec<PairId> = st
        .book
        .friends()
        .iter()
        .map(|f| f.pair)
        .filter(|p| {
            st.book.is_active(p) && !st.key_problems.contains_key(p) && !st.live.contains_key(p)
        })
        .collect();
    wanted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    (fps, wanted)
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Подключает поиск в LAN. Второй вызов: `Internal`; после остановки: `Shutdown`. Сам
    /// ввода-вывода не делает: передаёт ссылке ожидаемые пары, друзей, точку входа, затем
    /// `trigger()`, и запускает задачу (период `cfg.tick`).
    pub fn attach_lan(&self, link: Arc<dyn LanLink>) -> Result<(), ConnectError> {
        if self.inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let generation = {
            let mut s = self.inner.lan.lock();
            if s.link.is_some() {
                return Err(ConnectError::Internal);
            }
            s.generation = s.generation.wrapping_add(1);
            s.pushed = Pushed::default();
            s.link = Some(link.clone());
            s.generation
        };
        self.inner.lan_sync(Some(generation));
        link.trigger();
        self.inner
            .spawn_task(self.inner.clone().run_lan(generation));
        Ok(())
    }

    /// Закрывает ссылку (`shutdown`), забывает подсказки. Повторный вызов безвреден;
    /// после него `attach_lan` снова можно.
    pub fn detach_lan(&self) {
        self.inner.lan_detach();
    }

    /// `None`, пока поиск не подключён.
    pub fn lan_status(&self) -> Option<LanStatus> {
        self.inner.lan.link().map(|l| l.status())
    }
}
