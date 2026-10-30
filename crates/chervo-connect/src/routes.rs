//! Источник маршрута к IPv6-целям набора (этап 13г, круг 1 ревью, M; круг 2: вне замка).
//!
//! `RouteProbe::source_for` делает системные вызовы (bind, UDP `connect`) и по решению 16а П2a
//! вызывается только вне замка состояния. Поэтому планировщик и диагноз не зовут пробу сами.
//! Сначала под замком собираются IPv6-цели (`collect_targets`, после `normalize` и `dialable`,
//! без `::1`), для которых нет свежего ответа. Затем замок отпускается, и проба вызывается для
//! каждой цели (не больше `MAX_ROUTE_PROBES` за проход). Наконец под замком ответы кладутся в кэш
//! и из него берётся карта адрес -> источник (`RouteMap`). Адрес, которого нет в карте (нет
//! ответа, проба не уложилась в предел, книга изменилась между замками, маршрута нет), не
//! набирается в этом проходе.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use chervo_addr::{AddrClass, classify, normalize};
use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::time::Instant;

use crate::engine::{Inner, State};
use crate::plan::{MAX_DIAL_ADDRS, dialable};

/// Карта «IPv6-цель -> адрес-источник маршрута к ней» (только цели с ответом пробы).
pub(crate) type RouteMap = HashMap<SocketAddr, IpAddr>;

/// Сколько новых проб маршрута за один проход (такт, диагноз, итог набора): два полных набора.
pub(crate) const MAX_ROUTE_PROBES: usize = 2 * MAX_DIAL_ADDRS;

/// Ответ пробы действует столько; потом проба повторяется (маршрут мог смениться).
const ROUTE_TTL: Duration = Duration::from_secs(30);

/// Предел кэша ответов; сверх него сначала убирается устаревшее, затем всё.
const ROUTE_CACHE_MAX: usize = 256;

/// Кэш ответов пробы (только в памяти, под замком состояния).
#[derive(Default)]
pub(crate) struct RouteCache {
    map: HashMap<SocketAddr, (Option<IpAddr>, Instant)>,
}

impl RouteCache {
    fn is_fresh(&self, a: &SocketAddr, now: Instant) -> bool {
        self.map
            .get(a)
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) < ROUTE_TTL)
    }

    fn put(&mut self, a: SocketAddr, src: Option<IpAddr>, now: Instant) {
        if self.map.len() >= ROUTE_CACHE_MAX && !self.map.contains_key(&a) {
            self.map
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < ROUTE_TTL);
            if self.map.len() >= ROUTE_CACHE_MAX {
                self.map.clear();
            }
        }
        self.map.insert(a, (src, now));
    }

    fn snapshot(&self, now: Instant) -> RouteMap {
        self.map
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) < ROUTE_TTL)
            .filter_map(|(a, (src, _))| src.map(|s| (*a, s)))
            .collect()
    }
}

/// IPv6-цели, которым нужен ответ пробы: адреса друзей без соединения (`scope = None`: все
/// действующие друзья и гости, кроме идущих наборов; `Some(пара)`: только она), нормализованные,
/// `dialable`, без `::1` (петля маршрута не требует), без свежего ответа, без повторов, не больше
/// `MAX_ROUTE_PROBES`. Порядок как у планировщика: давно не набиравшиеся пары первыми.
fn collect_targets<C>(
    st: &State<C>,
    scope: Option<PairId>,
    now: Instant,
    unix: u64,
) -> Vec<SocketAddr> {
    let mut pairs: Vec<(PairId, Option<Instant>)> = Vec::new();
    match scope {
        Some(p) => pairs.push((p, None)),
        None => {
            for f in st.book.friends() {
                if st.book.is_active(&f.pair) && !st.inflight.contains(&f.pair) {
                    pairs.push((f.pair, st.friends.get(&f.pair).and_then(|r| r.last_dial_at)));
                }
            }
            for pair in st.guests.keys() {
                if st.book.get(pair).is_none() && !st.inflight.contains(pair) {
                    pairs.push((*pair, st.friends.get(pair).and_then(|r| r.last_dial_at)));
                }
            }
            pairs.sort_by_key(|(_, last)| *last);
        }
    }
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut out: Vec<SocketAddr> = Vec::new();
    for (pair, _) in pairs {
        if st.live.contains_key(&pair) {
            continue;
        }
        let raw: Vec<SocketAddr> = match st.guests.get(&pair) {
            Some(g) if st.book.get(&pair).is_none() => g.token_addrs.clone(),
            _ => st
                .book
                .usable_known(&pair, unix)
                .iter()
                .map(|k| k.addr)
                .collect(),
        };
        for a in raw {
            let a = normalize(a);
            if !a.is_ipv6()
                || classify(a.ip()) == AddrClass::Loopback
                || !dialable(&a)
                || st.route_cache.is_fresh(&a, now)
                || !seen.insert(a)
            {
                continue;
            }
            if out.len() >= MAX_ROUTE_PROBES {
                return out;
            }
            out.push(a);
        }
    }
    out
}

/// Карта маршрутов под замком: ответы пробы кладутся в кэш, возвращается снимок свежих ответов.
pub(crate) fn route_snapshot<C>(
    st: &mut State<C>,
    fresh: Vec<(SocketAddr, Option<IpAddr>)>,
    now: Instant,
) -> RouteMap {
    for (a, src) in fresh {
        st.route_cache.put(a, src, now);
    }
    st.route_cache.snapshot(now)
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Пробы маршрута к IPv6-целям `scope`. Замок берётся только на сбор целей и отпускается до
    /// вызова `RouteProbe::source_for`. Вызывать, не держа замка состояния.
    pub(crate) fn probe_routes(
        &self,
        scope: Option<PairId>,
        now: Instant,
        unix: u64,
    ) -> Vec<(SocketAddr, Option<IpAddr>)> {
        let targets = collect_targets(&self.lock(), scope, now, unix);
        targets
            .into_iter()
            .map(|a| (a, self.probe.source_for(a)))
            .collect()
    }
}
