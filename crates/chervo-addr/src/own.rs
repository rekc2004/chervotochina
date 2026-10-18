//! Собственные адреса: снимок интерфейсов, сведения шлюза, адреса, увиденные друзьями,
//! и набор для публикации. Времени и сети здесь нет: `now_unix` передаёт вызывающий.
//!
//! Защита U6 v6: подписать и разослать можно только `PublishSet`, а он создаётся лишь
//! из `OwnAddrs::publishable`, то есть из наших собственных источников. Пути от адреса
//! друга к `PublishSet` нет.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use chervo_identity::PairId;

use crate::class::{AddrClass, classify, is_eui64, normalize};
use crate::probe::RouteSources;

pub const OBSERVED_TTL_SECS: u64 = 1_800;
pub const MAX_OBSERVATIONS: usize = 16;
pub const MAX_UPDATE_ADDRS: usize = 8;
/// Сколько друзей с живым соединением помнится одновременно (больше `ConnectConfig::max_live`).
pub const MAX_REPORTERS_UP: usize = 256;

/// Допуск на «будущее» время наблюдения, секунд.
const OBSERVED_FUTURE_SKEW_SECS: u64 = 60;

/// Снимок собственных адресов; `listen` = `transport.local_addrs()`.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalSnapshot {
    pub route: RouteSources,
    pub listen: Vec<SocketAddr>,
}

impl fmt::Debug for LocalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalSnapshot(..)")
    }
}

/// Задаётся только этапом 13 после его собственных проверок (шлюз = маршрут по
/// умолчанию, проброс подтверждён GetSpecificPortMappingEntry; обзор безопасности 8,
/// п. 2). Здесь дополнительно проверяется только класс адреса.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GatewayInfo {
    pub wan_ip: Option<Ipv4Addr>,
    pub mapping: Option<SocketAddrV4>,
}

impl fmt::Debug for GatewayInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayInfo(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveOutcome {
    Accepted,
    IgnoredLocalPath,
    Rejected(ObserveReject),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveReject {
    FamilyMismatch,
    NotGlobal,
    ReporterOwnIp,
    ZeroPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NatView {
    NoIpv4,
    Public,
    PortMapped,
    BehindCgnat,
    DoubleNat,
    Conflicting,
    Symmetric,
    Eim,
    Unknown,
    /// Задан внешний порт ручного проброса (`set_manual_forward`) и есть живое наблюдение
    /// друга: постоянный адрес достижим, IP по-прежнему со слов друга.
    ManualForward,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UpdateAddr {
    pub addr: SocketAddr,
    pub short_lived: bool,
    pub hint: bool,
}

impl fmt::Debug for UpdateAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UpdateAddr(..)")
    }
}

/// Наши собственные публикуемые адреса. Нет публичного конструктора, нет `From`, нет
/// `Default` (защита U6 v6).
///
/// Литерал структуры снаружи крейта не компилируется (поле приватное):
///
/// ```compile_fail
/// let _s = chervo_addr::PublishSet { addrs: Vec::new() };
/// ```
///
/// Преобразования из `Vec` нет:
///
/// ```compile_fail
/// let _s: chervo_addr::PublishSet = Vec::new().into();
/// ```
///
/// Положительный контроль: единственный путь создания компилируется.
///
/// ```
/// let _s = chervo_addr::OwnAddrs::new()
///     .publishable(chervo_addr::PublishCtx::default(), 0);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PublishSet {
    addrs: Vec<UpdateAddr>,
}

impl PublishSet {
    pub fn as_slice(&self) -> &[UpdateAddr] {
        &self.addrs
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.addrs.iter().map(|a| a.addr).collect()
    }
}

impl fmt::Debug for PublishSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublishSet(..)")
    }
}

/// Без адреса пути в отладочной печати (спецификация 16а, разд. 3).
impl fmt::Debug for PublishCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublishCtx(..)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishCtx {
    /// Явный выбор пользователя «в одной сети» (приглашение или токен): частные адреса
    /// маршрута по умолчанию.
    pub include_lan: bool,
    /// Наш адрес на пути конкретного частного соединения (`local_addr` нашего сокета при
    /// маршруте к `remote`); друг выбирает только цель пробы, но не сам адрес.
    pub path_source: Option<IpAddr>,
}

impl PublishCtx {
    /// `include_lan` всегда `false`. `path_source` = `source`, если `remote` (после
    /// `normalize`) частный, `source` тоже частный и того же семейства; иначе `None`.
    pub fn for_connection(remote: SocketAddr, source: Option<IpAddr>) -> Self {
        let remote = normalize(remote);
        let path_source = source.and_then(|ip| {
            let ip = normalize(SocketAddr::new(ip, 0)).ip();
            let private_remote = classify(remote.ip()) == AddrClass::Private;
            let private_src = classify(ip) == AddrClass::Private;
            (private_remote && private_src && ip.is_ipv4() == remote.is_ipv4()).then_some(ip)
        });
        Self {
            include_lan: false,
            path_source,
        }
    }
}

struct Obs {
    reporter: PairId,
    /// Адрес друга на пути соединения; хранится для разбора, наружу не отдаётся.
    #[allow(dead_code)]
    via: SocketAddr,
    observed: SocketAddr,
    at: u64,
    /// Порядковый номер принятия (`OwnAddrs::seq`); сравнивается с отметкой `reporter_up`.
    seq: u64,
}

#[derive(Default)]
pub struct OwnAddrs {
    local: Option<LocalSnapshot>,
    gateway: Option<GatewayInfo>,
    obs: Vec<Obs>,
    /// Внешний порт ручного проброса (настройка пользователя); не сбрасывается `set_local`.
    manual: Option<u16>,
    /// Внутренний счётчик порядка (не время) для наблюдений и отметок `reporter_up`.
    seq: u64,
    /// Друзья с живым соединением: (кто, номер отметки). Наблюдения не новее отметки
    /// не считаются текущими.
    up: Vec<(PairId, u64)>,
}

impl fmt::Debug for OwnAddrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnAddrs(..)")
    }
}

fn same_listen_set(a: &[SocketAddr], b: &[SocketAddr]) -> bool {
    a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
}

fn is_v4(a: &SocketAddr) -> bool {
    matches!(a, SocketAddr::V4(_))
}

fn class_v4(ip: Ipv4Addr) -> AddrClass {
    classify(IpAddr::V4(ip))
}

impl OwnAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true`, если маршрут или набор адресов прослушивания отличается от прошлого снимка
    /// (первый вызов: `true`). Порядок адресов прослушивания значения не имеет. При
    /// изменении наблюдения и сведения шлюза сбрасываются: они описывают старую сеть.
    pub fn set_local(&mut self, snap: LocalSnapshot) -> bool {
        let unchanged = self.local.as_ref().is_some_and(|old| {
            old.route == snap.route && same_listen_set(&old.listen, &snap.listen)
        });
        self.local = Some(snap);
        if unchanged {
            return false;
        }
        self.obs.clear();
        self.gateway = None;
        true
    }

    pub fn local(&self) -> Option<&LocalSnapshot> {
        self.local.as_ref()
    }

    pub fn set_gateway(&mut self, g: Option<GatewayInfo>) {
        self.gateway = g;
    }

    /// Внешний порт ручного проброса (пользователь пробросил внешний порт на наш порт
    /// прослушивания). `Some(0)` равно `None`. Настройка пользователя: смена маршрута
    /// (`set_local`) её не сбрасывает.
    pub fn set_manual_forward(&mut self, port: Option<u16>) {
        self.manual = port.filter(|p| *p != 0);
    }

    /// `via` = `conn.remote_addr()`, `observed` = то, что сообщает друг. Вызывающий
    /// гарантирует, что `reporter` активный друг (`FriendBook::is_active`). Оба адреса
    /// сначала проходят `normalize`. Правила по порядку: порт observed 0 -> `ZeroPort`;
    /// семейства observed и via разные -> `FamilyMismatch`; via не глобальный ->
    /// `IgnoredLocalPath` (ничего не хранится); observed не глобальный -> `NotGlobal`;
    /// IP observed равен IP via -> `ReporterOwnIp`; иначе запись друга заменяется или
    /// добавляется (at = now), сверх `MAX_OBSERVATIONS` вытесняется самая старая.
    pub fn observe(
        &mut self,
        reporter: PairId,
        via: SocketAddr,
        observed: SocketAddr,
        now_unix: u64,
    ) -> ObserveOutcome {
        let via = normalize(via);
        let observed = normalize(observed);
        if observed.port() == 0 {
            return ObserveOutcome::Rejected(ObserveReject::ZeroPort);
        }
        if is_v4(&observed) != is_v4(&via) {
            return ObserveOutcome::Rejected(ObserveReject::FamilyMismatch);
        }
        if classify(via.ip()) != AddrClass::Global {
            return ObserveOutcome::IgnoredLocalPath;
        }
        if classify(observed.ip()) != AddrClass::Global {
            return ObserveOutcome::Rejected(ObserveReject::NotGlobal);
        }
        if observed.ip() == via.ip() {
            return ObserveOutcome::Rejected(ObserveReject::ReporterOwnIp);
        }
        self.obs.retain(|o| o.reporter != reporter);
        self.seq = self.seq.saturating_add(1);
        self.obs.push(Obs {
            reporter,
            via,
            observed,
            at: now_unix,
            seq: self.seq,
        });
        while self.obs.len() > MAX_OBSERVATIONS {
            let oldest = self
                .obs
                .iter()
                .enumerate()
                .min_by_key(|(_, o)| o.at)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    self.obs.remove(i);
                }
                None => break,
            }
        }
        ObserveOutcome::Accepted
    }

    /// Забыть друга: наблюдения и отметка `reporter_up` удаляются.
    pub fn forget_reporter(&mut self, reporter: &PairId) {
        self.obs.retain(|o| &o.reporter != reporter);
        self.reporter_down(reporter);
    }

    /// С этого момента у `reporter` есть живое соединение; его прежние наблюдения перестают
    /// быть текущими. Повторный вызов обновляет отметку. Сверх `MAX_REPORTERS_UP` уходит
    /// отметка с самым старым номером.
    pub fn reporter_up(&mut self, reporter: PairId) {
        self.seq = self.seq.saturating_add(1);
        let mark = self.seq;
        if let Some(slot) = self.up.iter_mut().find(|(p, _)| *p == reporter) {
            slot.1 = mark;
            return;
        }
        self.up.push((reporter, mark));
        while self.up.len() > MAX_REPORTERS_UP {
            let oldest = self
                .up
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, m))| *m)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    self.up.remove(i);
                }
                None => break,
            }
        }
    }

    /// Соединение закрыто: отметка снимается, наблюдения остаются (запасной вариант по TTL).
    pub fn reporter_down(&mut self, reporter: &PairId) {
        self.up.retain(|(p, _)| p != reporter);
    }

    /// Число отметок `reporter_up` (тесты, инварианты; адресов не раскрывает).
    pub fn reporters_up(&self) -> usize {
        self.up.len()
    }

    /// Наблюдение текущее: друг помечен «на связи» и наблюдение принято после последней отметки.
    fn current(&self, o: &Obs) -> bool {
        self.up.iter().any(|(p, m)| *p == o.reporter && o.seq > *m)
    }

    /// Живые IPv4-наблюдения: `now < at + TTL` и `at <= now + 60`.
    fn live_v4(&self, now_unix: u64) -> Vec<(&Obs, SocketAddrV4)> {
        self.obs
            .iter()
            .filter(|o| {
                now_unix < o.at.saturating_add(OBSERVED_TTL_SECS)
                    && o.at <= now_unix.saturating_add(OBSERVED_FUTURE_SKEW_SECS)
            })
            .filter_map(|o| match o.observed {
                SocketAddr::V4(a) => Some((o, a)),
                SocketAddr::V6(_) => None,
            })
            .collect()
    }

    /// Действующий набор IPv4-наблюдений: живые по TTL, а если среди них есть текущие, то
    /// только текущие (старое мнение отключённого друга не спорит со свежим).
    fn effective_v4(&self, now_unix: u64) -> Vec<(&Obs, SocketAddrV4)> {
        let live = self.live_v4(now_unix);
        if live.iter().any(|(o, _)| self.current(o)) {
            live.into_iter().filter(|(o, _)| self.current(o)).collect()
        } else {
            live
        }
    }

    pub fn nat_view(&self, now_unix: u64) -> NatView {
        let route_v4 = match self.local.as_ref().and_then(|l| l.route.v4) {
            Some(a) => a,
            None => return NatView::NoIpv4,
        };
        match class_v4(route_v4) {
            AddrClass::Global => return NatView::Public,
            AddrClass::Shared => return NatView::BehindCgnat,
            _ => {}
        }
        let wan = self.gateway.and_then(|g| g.wan_ip);
        let wan_class = wan.map(class_v4);
        if wan_class == Some(AddrClass::Shared) {
            return NatView::BehindCgnat;
        }
        if wan_class == Some(AddrClass::Private) {
            return NatView::DoubleNat;
        }
        let wan_global = if wan_class == Some(AddrClass::Global) {
            wan
        } else {
            None
        };
        if let (Some(w), Some(m)) = (wan_global, self.gateway.and_then(|g| g.mapping))
            && *m.ip() == w
        {
            return NatView::PortMapped;
        }
        let live = self.effective_v4(now_unix);
        let first_ip = live.first().map(|(_, a)| *a.ip());
        if let Some(first) = first_ip
            && live.iter().any(|(_, a)| *a.ip() != first)
        {
            return NatView::Conflicting;
        }
        if let Some(w) = wan_global
            && live.iter().any(|(_, a)| *a.ip() != w)
        {
            return NatView::DoubleNat;
        }
        if self.manual.is_some() && !live.is_empty() {
            return NatView::ManualForward;
        }
        if let Some((_, first)) = live.first()
            && live.iter().any(|(_, a)| a.port() != first.port())
        {
            return NatView::Symmetric;
        }
        let agreeing = live
            .iter()
            .enumerate()
            .any(|(i, (_, a))| live.iter().skip(i + 1).any(|(_, b)| a == b));
        if agreeing {
            return NatView::Eim;
        }
        NatView::Unknown
    }

    /// Постоянный адрес достижим: вид сети `Public`, `PortMapped` или `ManualForward`.
    pub fn stable_reachable(&self, now_unix: u64) -> bool {
        matches!(
            self.nat_view(now_unix),
            NatView::Public | NatView::PortMapped | NatView::ManualForward
        )
    }

    /// Новейшее живое наблюдение, только если вид сети `Unknown` или `Eim`.
    pub fn observed_v4(&self, now_unix: u64) -> Option<SocketAddrV4> {
        if !matches!(self.nat_view(now_unix), NatView::Unknown | NatView::Eim) {
            return None;
        }
        self.effective_v4(now_unix)
            .into_iter()
            .max_by_key(|(o, _)| o.at)
            .map(|(_, a)| a)
    }

    /// Порядок записей: (1) маршрутный глобальный IPv4, (2) проброс порта при
    /// `PortMapped`, (3) наблюдение друга с флагом `hint`, (4) глобальный IPv6 (не
    /// EUI-64, `short_lived`), (5) при `path_source`: только этот частный адрес пути (если
    /// слушаем на нём или на неуказанном адресе); иначе при `include_lan`: частные IPv4 и
    /// ULA маршрута по умолчанию. Без повторов, не более `MAX_UPDATE_ADDRS`.
    pub fn publishable(&self, ctx: PublishCtx, now_unix: u64) -> PublishSet {
        let mut out: Vec<UpdateAddr> = Vec::new();
        let Some(local) = self.local.as_ref() else {
            return PublishSet { addrs: out };
        };
        let port_of = |want_v4: bool| {
            local
                .listen
                .iter()
                .find(|a| is_v4(a) == want_v4)
                .map(SocketAddr::port)
                .filter(|p| *p != 0)
        };
        let p4 = port_of(true);
        let p6 = port_of(false);
        let mut push = |addr: SocketAddr, short_lived: bool, hint: bool| {
            if out.len() < MAX_UPDATE_ADDRS && !out.iter().any(|u| u.addr == addr) {
                out.push(UpdateAddr {
                    addr,
                    short_lived,
                    hint,
                });
            }
        };
        let route_v4 = local.route.v4;
        let route_v6 = local.route.v6.filter(|a| !is_eui64(a));
        // (1)
        if let (Some(ip), Some(p)) = (route_v4, p4)
            && class_v4(ip) == AddrClass::Global
        {
            push(SocketAddr::new(IpAddr::V4(ip), p), false, false);
        }
        // (2)
        if self.nat_view(now_unix) == NatView::PortMapped
            && let Some(m) = self.gateway.and_then(|g| g.mapping)
            && m.port() != 0
        {
            push(SocketAddr::V4(m), false, false);
        }
        // (2b) ручной проброс: IP со слов друга (новейшее наблюдение), порт задан пользователем;
        // IP не проверен, поэтому `hint`
        if self.nat_view(now_unix) == NatView::ManualForward
            && let Some(port) = self.manual
            && let Some((_, newest)) = self
                .effective_v4(now_unix)
                .into_iter()
                .max_by_key(|(o, _)| o.at)
        {
            push(SocketAddr::new(IpAddr::V4(*newest.ip()), port), false, true);
        }
        // (3)
        if let Some(o) = self.observed_v4(now_unix) {
            push(SocketAddr::V4(o), false, true);
        }
        // (4)
        if let (Some(ip), Some(p)) = (route_v6, p6)
            && classify(IpAddr::V6(ip)) == AddrClass::Global
        {
            push(SocketAddr::new(IpAddr::V6(ip), p), true, false);
        }
        // (5) на пути частного соединения: только наш адрес на этом пути (`local_addr`
        // сокета), и только если слушаем на нём или на неуказанном адресе того же семейства
        if let Some(src) = ctx.path_source {
            let src = normalize(SocketAddr::new(src, 0)).ip();
            let src_ok = classify(src) == AddrClass::Private
                && match src {
                    IpAddr::V4(_) => true,
                    IpAddr::V6(v6) => !is_eui64(&v6),
                };
            let listen = local.listen.iter().find(|a| {
                a.is_ipv4() == src.is_ipv4()
                    && a.port() != 0
                    && (a.ip().is_unspecified() || a.ip() == src)
            });
            if src_ok && let Some(l) = listen {
                push(SocketAddr::new(src, l.port()), src.is_ipv6(), false);
            }
        } else if ctx.include_lan {
            if let (Some(ip), Some(p)) = (route_v4, p4)
                && class_v4(ip) == AddrClass::Private
            {
                push(SocketAddr::new(IpAddr::V4(ip), p), false, false);
            }
            if let (Some(ip), Some(p)) = (route_v6, p6)
                && classify(IpAddr::V6(ip)) == AddrClass::Private
            {
                push(SocketAddr::new(IpAddr::V6(ip), p), true, false);
            }
        }
        PublishSet { addrs: out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_saturates() {
        let who = PairId::from_bytes([1; 16]);
        let mut o = OwnAddrs::new();
        o.set_local(LocalSnapshot {
            route: RouteSources {
                v4: Some(Ipv4Addr::new(192, 168, 1, 2)),
                v6: None,
            },
            listen: vec![SocketAddr::from(([0, 0, 0, 0], 4000))],
        });
        o.seq = u64::MAX - 1;
        o.reporter_up(who);
        assert_eq!(o.seq, u64::MAX);
        let via = SocketAddr::from(([8, 8, 8, 8], 5000));
        let seen = SocketAddr::from(([9, 9, 9, 9], 6000));
        // счётчик на пределе: паники нет, наблюдение принято
        assert_eq!(o.observe(who, via, seen, 100), ObserveOutcome::Accepted);
        assert_eq!(o.seq, u64::MAX);
        o.reporter_up(who);
        assert_eq!(o.seq, u64::MAX);
        assert_eq!(o.reporters_up(), 1);
        // наблюдение не новее отметки: нетекущее, но запасной вариант по TTL его отдаёт
        assert_eq!(
            o.observed_v4(100),
            Some(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 6000))
        );
    }
}
