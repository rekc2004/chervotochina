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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishCtx {
    pub include_lan: bool,
}

impl PublishCtx {
    /// `include_lan` = соединение само идёт по частному адресу.
    pub fn for_connection(remote: SocketAddr) -> Self {
        Self {
            include_lan: classify(normalize(remote).ip()) == AddrClass::Private,
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
}

#[derive(Default)]
pub struct OwnAddrs {
    local: Option<LocalSnapshot>,
    gateway: Option<GatewayInfo>,
    obs: Vec<Obs>,
    /// Внешний порт ручного проброса (настройка пользователя); не сбрасывается `set_local`.
    manual: Option<u16>,
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
        self.obs.push(Obs {
            reporter,
            via,
            observed,
            at: now_unix,
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

    pub fn forget_reporter(&mut self, reporter: &PairId) {
        self.obs.retain(|o| &o.reporter != reporter);
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
        let live = self.live_v4(now_unix);
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
        self.live_v4(now_unix)
            .into_iter()
            .max_by_key(|(o, _)| o.at)
            .map(|(_, a)| a)
    }

    /// Порядок записей: (1) маршрутный глобальный IPv4, (2) проброс порта при
    /// `PortMapped`, (3) наблюдение друга с флагом `hint`, (4) глобальный IPv6 (не
    /// EUI-64, `short_lived`), (5) только при `include_lan`: частные IPv4 и ULA. Без
    /// повторов, не более `MAX_UPDATE_ADDRS`.
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
            && let Some((_, newest)) = self.live_v4(now_unix).into_iter().max_by_key(|(o, _)| o.at)
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
        // (5)
        if ctx.include_lan {
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
