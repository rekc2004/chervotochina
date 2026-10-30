//! Поиск друзей в локальной сети: подключение службы маяка к движку (этап 13в, часть L4).
//!
//! Слой соединения не знает, как устроен маяк: он держит `Arc<dyn LanDiscovery>` (интерфейс из
//! `chervo-addr`) и вызывает его только отсюда. Сокетов здесь нет. Что приходит от службы, то
//! данные недоверенной сети: находка лишь добавляет кандидата для набора. Она не открывает
//! быстрое окно, не сбрасывает ограничитель, не вызывает повторный стук и ADDR_INFO и не
//! записывается в книгу. Набор идёт обычным путём (стук, QUIC, Noise KK) и строгим пределом
//! ограничителя (не чаще раза в `dial_base` + запас на IP в любом режиме). Гости приглашений
//! в службу не передаются и по находкам не набираются.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use chervo_addr::{LanDiscovery, LanLocal, LanStatus, normalize};
use chervo_identity::{KxPeer, ListKeyStore, PairId, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::time::Instant;

use crate::engine::{ConnectError, Engine, EngineEvent, Inner, State};
use crate::plan::{Candidate, Families, Plan, dialable, family_ok};

/// Не больше находок за один такт (служба сама держит очередь не больше 64).
const MAX_SIGHTINGS_PER_TICK: usize = 64;

/// Подключённая служба (одна на движок).
pub(crate) struct LanHook {
    cell: OnceLock<Arc<dyn LanDiscovery>>,
}

impl LanHook {
    pub(crate) fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    fn get(&self) -> Option<&Arc<dyn LanDiscovery>> {
        self.cell.get()
    }
}

/// Наш адрес для службы маяка: маршрутный IPv4 по умолчанию любого класса (петля и неуказанный
/// адрес не годятся) и порт прослушивания IPv4 (не 0). Класс не проверяется: под VPN маршрут
/// по умолчанию идёт в туннель, а какие интерфейсы частные, решает служба опросом маршрутов.
/// Это единственное место, где адрес берётся (источник можно сменить, не трогая остальное).
pub(crate) fn lan_local<C>(st: &State<C>) -> Option<LanLocal> {
    let local = st.own.local()?;
    let own = local
        .route
        .v4
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())?;
    let listen_port = local
        .listen
        .iter()
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4.port()),
            SocketAddr::V6(_) => None,
        })
        .filter(|p| *p != 0)?;
    Some(LanLocal { own, listen_port })
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Действующие друзья набора транспорта без гостей: запись пары должна быть ключом друга
    /// из книги (гостевая запись той же пары после превращения гостя в друга не годится).
    fn lan_peers(st: &State<T::Conn>) -> Vec<KxPeer> {
        st.published
            .iter()
            .filter(|p| {
                let pair = p.pair();
                st.book
                    .get(&pair)
                    .is_some_and(|f| st.book.is_active(&pair) && p.theirs() == f.friend_x)
            })
            .cloned()
            .collect()
    }

    /// После успешной публикации набора пар: службе уходит набор друзей.
    pub(crate) fn lan_sync_peers(&self, st: &State<T::Conn>) {
        if let Some(l) = self.lan.get() {
            l.set_peers(Self::lan_peers(st));
        }
    }

    /// После смены собственных адресов: службе уходит наш адрес (или `None`).
    pub(crate) fn lan_sync_local(&self, st: &State<T::Conn>) {
        if let Some(l) = self.lan.get() {
            l.set_local(lan_local(st));
        }
    }

    /// Такт: срок записей, новые находки службы, смена состояния. Находка принимается только
    /// для действующего друга без проблемы с ключом и без живого соединения.
    pub(crate) fn lan_collect(
        &self,
        st: &mut State<T::Conn>,
        now: Instant,
        events: &mut Vec<EngineEvent>,
    ) {
        let Some(l) = self.lan.get() else {
            return;
        };
        let ttl = self.cfg.lan_seen_ttl;
        st.lan_seen
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < ttl);
        for s in l.take_sightings().into_iter().take(MAX_SIGHTINGS_PER_TICK) {
            let usable = st.book.get(&s.pair).is_some()
                && st.book.is_active(&s.pair)
                && !st.key_problems.contains_key(&s.pair)
                && !st.live.contains_key(&s.pair);
            if usable {
                st.lan_seen.insert(s.pair, (s.addr, now));
            }
        }
        let status = l.status();
        if st.lan_status_last != Some(status) {
            st.lan_status_last = Some(status);
            events.push(EngineEvent::LanStatusChanged { status });
        }
    }

    /// Адрес из маяка идёт первым в наборе друга. Тот же адрес в книге не дублируется: запись
    /// книги переезжает на первое место и сохраняет свою строгость (подтверждённый `Contact`
    /// остаётся нестрогим). Новый адрес строгий, без подсказки.
    pub(crate) fn lan_first(
        st: &State<T::Conn>,
        pair: &PairId,
        plan: &mut Plan,
        fam: &Families<'_>,
    ) {
        let Some((seen, _)) = st.lan_seen.get(pair) else {
            return;
        };
        let addr = normalize(SocketAddr::V4(*seen));
        if !dialable(&addr) || !family_ok(&addr, fam) {
            return;
        }
        let mut c = match plan.cands.iter().position(|c| c.addr == addr) {
            Some(i) => plan.cands.remove(i),
            None => Candidate {
                addr,
                hint: false,
                strict: true,
            },
        };
        // слово друга по маяку, а не его подсказка «так вас видят»
        c.hint = false;
        plan.cands.insert(0, c);
    }

    /// Остановка движка: службе сообщается (без ожидания).
    pub(crate) fn lan_shutdown(&self) {
        if let Some(l) = self.lan.get() {
            l.shutdown();
        }
    }
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Подключает службу поиска в локальной сети. Второй вызов: `ConnectError::Internal`. Служба
    /// сразу получает наш адрес и набор друзей. Сам вызов сети не делает.
    pub fn attach_lan(&self, l: Arc<dyn LanDiscovery>) -> Result<(), ConnectError> {
        if self.inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        if self.inner.lan.cell.set(l.clone()).is_err() {
            return Err(ConnectError::Internal);
        }
        let mut st = self.inner.lock();
        l.set_local(lan_local(&st));
        l.set_peers(Inner::<T, S>::lan_peers(&st));
        // события только по изменениям после подключения
        st.lan_status_last = Some(l.status());
        Ok(())
    }

    /// Состояние службы поиска; `None`, пока она не подключена.
    pub fn lan_status(&self) -> Option<LanStatus> {
        self.inner.lan.get().map(|l| l.status())
    }
}
