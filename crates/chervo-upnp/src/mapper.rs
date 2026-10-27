//! Жизненный цикл проброса (этап 13а, решения 6-8, шаги 1-7 спецификации).
//!
//! Правила: без списка разрешённых роутеров ни одного пакета; разрешённый роутер определяется
//! по UDN его описания; ровно один кандидат; внутренний клиент это всегда наш IP; аренда не
//! больше часа (ноль только после ошибки 725 и согласия); проброс засчитывается только после
//! `GetSpecificPortMappingEntry`; свой старый проброс удаляется при запуске, смене сети и выходе.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_addr::{AddrClass, GatewayInfo, MapReport, MapRequest, MapStatus, PortMapper, classify};

use crate::desc::{Description, Service, ServiceKind, Udn, parse_description};
use crate::error::{NetError, UpnpError};
use crate::http::{get_request, parse_response, post_request};
use crate::limits::{ALT_PORT_TRIES, LEASE_SECS, MAX_ROUTERS, MIN_RENEW, RELEASE_BUDGET};
use crate::net::Net;
use crate::soap::{
    Action, Entry, Fault, parse_add_any, parse_external_ip, parse_fault, parse_specific,
};
use crate::ssdp::Responder;
use crate::url::{GatewayAddr, Path};

/// Начальная и предельная задержка повтора после отказа и сбоя.
const BACKOFF_MIN: Duration = Duration::from_secs(60);
const BACKOFF_MAX: Duration = Duration::from_secs(1800);
/// Период повторной проверки там, где проброса нет или он бессрочный.
const IDLE_RETRY: Duration = Duration::from_secs(1800);

/// Непрозрачный идентификатор роутера (UDN корневого устройства).
#[derive(Clone, PartialEq, Eq)]
pub struct RouterId(Udn);

impl RouterId {
    pub fn to_setting(&self) -> String {
        self.0.as_str().to_owned()
    }

    pub fn from_setting(s: &str) -> Result<Self, UpnpError> {
        Udn::parse(s).map(RouterId).map_err(|_| UpnpError::Rejected)
    }
}

impl std::fmt::Debug for RouterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RouterId(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AllowedRouter {
    pub id: RouterId,
    /// Пользователь согласился на бессрочную аренду (после ошибки 725).
    pub permanent_ok: bool,
}

impl std::fmt::Debug for AllowedRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AllowedRouter(..)")
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct UpnpSettings {
    /// Больше `MAX_ROUTERS` записей: берутся первые.
    pub routers: Vec<AllowedRouter>,
}

impl std::fmt::Debug for UpnpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpnpSettings(..)")
    }
}

fn clamp_settings(mut s: UpnpSettings) -> UpnpSettings {
    s.routers.truncate(MAX_ROUTERS);
    s
}

/// Подтверждённый проброс: всё, что нужно для продления и удаления без поиска.
#[derive(Clone)]
struct Mapping {
    router: RouterId,
    kind: ServiceKind,
    control: Path,
    gw: GatewayAddr,
    internal: SocketAddrV4,
    ext: u16,
    /// Аренда 0 (после согласия на ошибку 725 или молчаливо от роутера): сама не истечёт.
    permanent: bool,
}

struct Backoff {
    next: Duration,
    internal: Option<SocketAddrV4>,
}

pub struct UpnpMapper {
    settings: Mutex<UpnpSettings>,
    current: Mutex<Option<Mapping>>,
    /// Роутер, ответивший 725 (только в памяти).
    needs_permanent: Mutex<Option<RouterId>>,
    backoff: Mutex<Backoff>,
    /// Занято, пока идёт `refresh`: второй одновременный вызов сразу получает `Failed`.
    busy: Mutex<()>,
    /// Растёт при каждом `release`: незавершённый `refresh` не оставит проброс после выхода.
    epoch: AtomicU64,
    net: Net,
}

impl std::fmt::Debug for UpnpMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpnpMapper(..)")
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Ошибка одного вызова SOAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallErr {
    /// Ответ 500 с кодом ошибки UPnP.
    Fault(u16),
    /// Сеть, срок, разбор, статус, 500 без кода.
    Fail,
}

/// Вызовы SOAP к одной службе одного роутера в пределах общего срока.
struct Sess<'a> {
    net: &'a Net,
    own_ip: Ipv4Addr,
    gw: GatewayAddr,
    control: &'a Path,
    kind: ServiceKind,
    overall: Instant,
}

impl<'a> Sess<'a> {
    fn new(
        net: &'a Net,
        own_ip: Ipv4Addr,
        gw: GatewayAddr,
        svc: &'a Service,
        overall: Instant,
    ) -> Self {
        Sess {
            net,
            own_ip,
            gw,
            control: &svc.control,
            kind: svc.kind,
            overall,
        }
    }

    fn call(&self, action: Action) -> Result<Vec<u8>, CallErr> {
        // `AddAnyPortMapping` существует только в WANIPConnection:2
        if matches!(action, Action::AddAny { .. }) && self.kind != ServiceKind::WanIp2 {
            return Err(CallErr::Fail);
        }
        let body = action.body(self.kind);
        let req = post_request(
            &self.gw,
            self.control,
            self.kind.urn(),
            action.name(),
            &body,
        );
        let bytes = self
            .net
            .http(&self.gw, self.own_ip, &req, self.overall)
            .map_err(|_: NetError| CallErr::Fail)?;
        let reply = parse_response(&bytes).map_err(|_| CallErr::Fail)?;
        match reply.status {
            200 => Ok(reply.body),
            500 => match parse_fault(&reply.body) {
                Fault::Upnp(code) => Err(CallErr::Fault(code)),
                Fault::NoCode => Err(CallErr::Fail),
            },
            _ => Err(CallErr::Fail),
        }
    }

    fn external_ip(&self) -> Result<Option<Ipv4Addr>, CallErr> {
        let body = self.call(Action::GetExternalIp)?;
        parse_external_ip(&body).map_err(|_| CallErr::Fail)
    }

    fn add(&self, ext: u16, internal: SocketAddrV4, lease: u32) -> Result<(), CallErr> {
        self.call(Action::Add {
            ext,
            internal,
            lease,
        })
        .map(|_| ())
    }

    fn add_any(&self, ext: u16, internal: SocketAddrV4, lease: u32) -> Result<u16, CallErr> {
        let body = self.call(Action::AddAny {
            ext,
            internal,
            lease,
        })?;
        parse_add_any(&body).map_err(|_| CallErr::Fail)
    }

    /// 714 (записи нет) это `Ok(None)`.
    fn get_specific(&self, ext: u16) -> Result<Option<Entry>, CallErr> {
        match self.call(Action::GetSpecific { ext }) {
            Ok(body) => parse_specific(&body).map(Some).map_err(|_| CallErr::Fail),
            Err(CallErr::Fault(714)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 714 (записи нет) это успех.
    fn delete(&self, ext: u16) -> Result<(), CallErr> {
        match self.call(Action::Delete { ext }) {
            Ok(_) | Err(CallErr::Fault(714)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Запись роутера наша: клиент, порт и описание совпадают (UDP задан запросом).
fn is_ours(e: &Entry, internal: SocketAddrV4) -> bool {
    e.internal_client == *internal.ip()
        && e.internal_port == internal.port()
        && e.description_is_ours
}

enum AddRes {
    Done,
    Conflict,
    NeedPermanent,
    Refused(u16),
    Failed,
}

/// Роутер, найденный в сети: ответивший и разобранное описание.
struct Found {
    resp: Responder,
    desc: Description,
}

impl UpnpMapper {
    pub fn new(settings: UpnpSettings) -> Self {
        Self::with_net(settings, Net::production())
    }

    pub(crate) fn with_net(settings: UpnpSettings, net: Net) -> Self {
        UpnpMapper {
            settings: Mutex::new(clamp_settings(settings)),
            current: Mutex::new(None),
            needs_permanent: Mutex::new(None),
            busy: Mutex::new(()),
            backoff: Mutex::new(Backoff {
                next: BACKOFF_MIN,
                internal: None,
            }),
            epoch: AtomicU64::new(0),
            net,
        }
    }

    /// Новый список разрешённых роутеров. Бессрочный проброс (аренда 0) роутера, которого в новом
    /// списке нет (в том числе список очищен), сам не истечёт: перед применением списка делается
    /// ОДНО подтверждённое удаление по СТАРОМУ списку по тем же правилам, что у `release()`
    /// (единственный кандидат, тот же UDN, адрес и служба, `RELEASE_BUDGET`). Роутер не подтверждён:
    /// ничего не шлётся (остаточный риск T16). Проброс с арендой забывается без отправки и истекает
    /// сам не позже чем через час.
    pub fn set_settings(&self, s: UpnpSettings) {
        let new = clamp_settings(s);
        let doomed = {
            let mut cur = lock(&self.current);
            if cur
                .as_ref()
                .is_some_and(|m| m.permanent && !new.routers.iter().any(|a| a.id == m.router))
            {
                cur.take()
            } else {
                None
            }
        };
        if let Some(m) = doomed {
            // незавершённый refresh не оставит этот проброс после смены списка
            self.epoch.fetch_add(1, Ordering::SeqCst);
            let old = lock(&self.settings).clone();
            self.delete_confirmed(&m, &old);
        }
        *lock(&self.settings) = new;
        lock(&self.backoff).next = BACKOFF_MIN;
    }

    /// Ничего не шлём, пока сохранённый роутер не подтверждён заново как единственный
    /// разрешённый кандидат в сети (иначе запрос ушёл бы постороннему устройству). Затем одно
    /// удаление (если запись всё ещё наша) в пределах `RELEASE_BUDGET`.
    fn delete_confirmed(&self, m: &Mapping, settings: &UpnpSettings) {
        let own_ip = *m.internal.ip();
        if settings.routers.is_empty() || !self.own_ip_ok(own_ip) {
            return;
        }
        let overall = Instant::now() + RELEASE_BUDGET;
        let Ok(found) = self.find_routers(own_ip, overall) else {
            return;
        };
        if let [one] = Self::candidates(&found, settings).as_slice()
            && Self::is_same_router(m, one)
        {
            self.delete_if_ours(m, overall);
        }
    }

    /// Явное действие пользователя: один поиск и одно описание. Нужен ровно один ответчик IGD.
    pub fn identify(&self, own_ip: Ipv4Addr) -> Result<RouterId, UpnpError> {
        if !self.own_ip_ok(own_ip) {
            return Err(UpnpError::NoGateway);
        }
        let overall = Instant::now() + self.net.max_refresh;
        let found = self.find_routers(own_ip, overall)?;
        match found.as_slice() {
            [] => Err(UpnpError::NoGateway),
            [one] => Ok(RouterId(one.desc.udn.clone())),
            _ => Err(UpnpError::Ambiguous),
        }
    }

    fn own_ip_ok(&self, ip: Ipv4Addr) -> bool {
        match classify(IpAddr::V4(ip)) {
            AddrClass::Private => true,
            AddrClass::Loopback => self.net.allow_loopback,
            _ => false,
        }
    }

    /// Поиск и описания. Ответчик с неудачным описанием пропускается. Отказ по умолчанию
    /// (ред. 2 по ревью безопасности): `Ambiguous`, если поиск неоднозначен (конфликт LOCATION,
    /// предел датаграмм, слишком много ответчиков) или какой-то ответчик не успел пройти
    /// проверку до срока.
    fn find_routers(&self, own_ip: Ipv4Addr, overall: Instant) -> Result<Vec<Found>, UpnpError> {
        let sel = self.net.discover(own_ip, overall)?;
        if sel.ambiguous {
            return Err(UpnpError::Ambiguous);
        }
        let mut out = Vec::new();
        for resp in sel.responders {
            if Instant::now() >= overall {
                return Err(UpnpError::Ambiguous);
            }
            let req = get_request(&resp.target.gw, &resp.target.path);
            let Ok(bytes) = self.net.http(&resp.target.gw, own_ip, &req, overall) else {
                if Instant::now() >= overall {
                    return Err(UpnpError::Ambiguous);
                }
                continue;
            };
            let Ok(reply) = parse_response(&bytes) else {
                continue;
            };
            if reply.status != 200 {
                continue;
            }
            let Ok(desc) = parse_description(&reply.body, &resp.target) else {
                continue;
            };
            out.push(Found { resp, desc });
        }
        Ok(out)
    }

    /// Найденные роутеры из списка разрешённых.
    fn candidates<'f>(found: &'f [Found], settings: &UpnpSettings) -> Vec<&'f Found> {
        found
            .iter()
            .filter(|f| settings.routers.iter().any(|a| a.id.0 == f.desc.udn))
            .collect()
    }

    /// Сохранённый проброс принадлежит именно этому, только что найденному роутеру.
    fn is_same_router(m: &Mapping, cand: &Found) -> bool {
        m.router.0 == cand.desc.udn
            && m.gw == cand.resp.target.gw
            && cand
                .desc
                .services
                .iter()
                .any(|svc| svc.kind == m.kind && svc.control == m.control)
    }

    /// Забыть сохранённый проброс, ничего не отправляя (аренда не дольше часа сама истечёт).
    fn forget_current(&self) {
        *lock(&self.current) = None;
    }

    /// При смене сети (другой внутренний адрес) задержка повтора начинается заново.
    fn note_network(&self, internal: SocketAddrV4) {
        let mut b = lock(&self.backoff);
        if b.internal != Some(internal) {
            b.internal = Some(internal);
            b.next = BACKOFF_MIN;
        }
    }

    fn report(status: MapStatus, gateway: Option<GatewayInfo>, retry_after: Duration) -> MapReport {
        MapReport {
            status,
            gateway,
            retry_after,
        }
    }

    /// Состояние без повторов по расписанию отказов.
    fn quiet(status: MapStatus, gateway: Option<GatewayInfo>) -> MapReport {
        Self::report(status, gateway, IDLE_RETRY)
    }

    /// Отказ или сбой: задержка 60 с с удвоением до 1800 с.
    fn failure(&self, status: MapStatus) -> MapReport {
        let mut b = lock(&self.backoff);
        let wait = b.next;
        b.next = (b.next * 2).min(BACKOFF_MAX);
        Self::report(status, None, wait)
    }

    fn reset_backoff(&self) {
        lock(&self.backoff).next = BACKOFF_MIN;
    }

    /// Удаляет проброс, если роутер всё ещё показывает его нашим. Без поиска, по сохранённому
    /// адресу и службе, не позже `deadline`. Вызывать только после подтверждения роутера.
    fn delete_if_ours(&self, m: &Mapping, deadline: Instant) {
        let s = Sess {
            net: &self.net,
            own_ip: *m.internal.ip(),
            gw: m.gw,
            control: &m.control,
            kind: m.kind,
            overall: deadline,
        };
        if let Ok(Some(e)) = s.get_specific(m.ext)
            && is_ours(&e, m.internal)
        {
            let _ = s.delete(m.ext);
        }
    }

    /// Одна попытка `AddPortMapping` с разбором кода ошибки.
    fn try_add(s: &Sess<'_>, ext: u16, internal: SocketAddrV4, lease: u32) -> AddRes {
        match s.add(ext, internal, lease) {
            Ok(()) => AddRes::Done,
            Err(CallErr::Fault(718)) => AddRes::Conflict,
            Err(CallErr::Fault(725)) => AddRes::NeedPermanent,
            Err(CallErr::Fault(code)) => AddRes::Refused(code),
            Err(CallErr::Fail) => AddRes::Failed,
        }
    }

    /// Шаг 5. Итог: внешний порт и запрошенная аренда либо готовый статус.
    fn open(
        &self,
        s: &Sess<'_>,
        router: &RouterId,
        permanent_ok: bool,
        first_ext: u16,
        internal: SocketAddrV4,
    ) -> Result<(u16, u32), MapStatus> {
        let port = internal.port();
        let known_permanent = lock(&self.needs_permanent).as_ref() == Some(router);
        let mut lease = if known_permanent && permanent_ok {
            0
        } else {
            LEASE_SECS
        };
        let mut ext = first_ext;
        let mut res = Self::try_add(s, ext, internal, lease);

        if let AddRes::NeedPermanent = res {
            *lock(&self.needs_permanent) = Some(router.clone());
            if !permanent_ok {
                return Err(MapStatus::NeedPermanentConsent);
            }
            if lease == 0 {
                return Err(MapStatus::Refused(725));
            }
            lease = 0;
            ext = port;
            res = Self::try_add(s, ext, internal, 0);
            if let AddRes::NeedPermanent = res {
                return Err(MapStatus::Refused(725));
            }
        }

        if let AddRes::Conflict = res {
            if lease == 0 {
                return Err(MapStatus::Refused(718));
            }
            if s.kind == ServiceKind::WanIp2 {
                match s.add_any(port, internal, lease) {
                    Ok(reserved) => {
                        ext = reserved;
                        res = AddRes::Done;
                    }
                    Err(CallErr::Fault(code)) => return Err(MapStatus::Refused(code)),
                    Err(CallErr::Fail) => return Err(MapStatus::Failed),
                }
            } else {
                for attempt in 0..ALT_PORT_TRIES {
                    let alt = random_port(attempt, port);
                    match Self::try_add(s, alt, internal, lease) {
                        AddRes::Done => {
                            ext = alt;
                            res = AddRes::Done;
                            break;
                        }
                        AddRes::Conflict => {}
                        AddRes::NeedPermanent => return Err(MapStatus::Refused(725)),
                        AddRes::Refused(code) => return Err(MapStatus::Refused(code)),
                        AddRes::Failed => return Err(MapStatus::Failed),
                    }
                }
            }
        }

        match res {
            AddRes::Done => Ok((ext, lease)),
            AddRes::Conflict => Err(MapStatus::Refused(718)),
            AddRes::NeedPermanent => Err(MapStatus::Refused(725)),
            AddRes::Refused(code) => Err(MapStatus::Refused(code)),
            AddRes::Failed => Err(MapStatus::Failed),
        }
    }
}

/// Случайный внешний порт 49152..=65535 без внешних пакетов: хеш `RandomState` от времени и
/// номера попытки. Не равен внутреннему порту.
fn random_port(attempt: usize, internal_port: u16) -> u16 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let h = RandomState::new().hash_one((now, attempt));
    let offset = u16::try_from(h % 16384).unwrap_or(0);
    let mut p = 49152 + offset;
    if p == internal_port {
        p = 49152 + (offset + 1) % 16384;
    }
    p
}

impl PortMapper for UpnpMapper {
    fn refresh(&self, req: MapRequest) -> MapReport {
        // один refresh за раз: пока идёт первый (в том числе брошенный по таймауту), второй не
        // начинается и не шлёт ни одного пакета
        let _busy = match self.busy.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Self::report(MapStatus::Failed, None, BACKOFF_MIN);
            }
        };
        let overall = Instant::now() + self.net.max_refresh;
        let internal = req.internal;
        let own_ip = *internal.ip();
        let port = internal.port();
        self.note_network(internal);
        if port == 0 || !self.own_ip_ok(own_ip) {
            return self.failure(MapStatus::Failed);
        }
        let epoch = self.epoch.load(Ordering::SeqCst);
        let settings = lock(&self.settings).clone();

        // 1. пустой список: ни одного пакета, сохранённый проброс забывается без отправки
        if settings.routers.is_empty() {
            self.forget_current();
            return Self::quiet(MapStatus::Off, None);
        }

        // 2. поиск, описания, разрешённый роутер. Если он не единственный кандидат, сохранённый
        // проброс забывается без отправки: адрес мог оказаться чужой сетью с той же адресацией
        let found = match self.find_routers(own_ip, overall) {
            Ok(f) => f,
            Err(UpnpError::Ambiguous) => {
                self.forget_current();
                // политика спецификации (U0): Ambiguous это 1800 с без удвоения, как при двух кандидатах
                return Self::quiet(MapStatus::Ambiguous, None);
            }
            Err(_) => return self.failure(MapStatus::Failed),
        };
        if found.is_empty() {
            self.forget_current();
            return self.failure(MapStatus::NoGateway);
        }
        let candidates = Self::candidates(&found, &settings);
        let cand = match candidates.as_slice() {
            [] => {
                self.forget_current();
                return Self::quiet(MapStatus::NotHomeNetwork, None);
            }
            [one] => *one,
            _ => {
                self.forget_current();
                return Self::quiet(MapStatus::Ambiguous, None);
            }
        };
        let router = RouterId(cand.desc.udn.clone());
        let gw = cand.resp.target.gw;
        let permanent_ok = settings
            .routers
            .iter()
            .any(|a| a.id == router && a.permanent_ok);

        // сохранённый проброс: удаляется только если это тот же только что найденный роутер
        // (смена внутреннего адреса); иначе забывается без отправки
        let prev = lock(&self.current).clone();
        if let Some(m) = &prev
            && (!Self::is_same_router(m, cand) || m.internal != internal)
        {
            if Self::is_same_router(m, cand) {
                self.delete_if_ours(m, overall);
            }
            self.forget_current();
        }
        let renew = lock(&self.current)
            .as_ref()
            .filter(|m| m.router == router && m.gw == gw && m.internal == internal)
            .cloned();

        // 3. внешний адрес: первая служба, ответившая 200
        let sess = |svc| Sess::new(&self.net, own_ip, gw, svc, overall);
        let mut chosen: Option<(&Service, Option<Ipv4Addr>)> = None;
        for svc in &cand.desc.services {
            if let Ok(wan) = sess(svc).external_ip() {
                chosen = Some((svc, wan));
                break;
            }
        }
        let Some((svc, wan)) = chosen else {
            return self.failure(MapStatus::Failed);
        };
        let Some(wan) = wan else {
            return self.failure(MapStatus::WanUnknown);
        };
        let wan_info = Some(GatewayInfo {
            wan_ip: Some(wan),
            mapping: None,
        });
        match classify(IpAddr::V4(wan)) {
            AddrClass::Global => {}
            AddrClass::Shared => return Self::quiet(MapStatus::BehindCgnat, wan_info),
            AddrClass::Private => return Self::quiet(MapStatus::DoubleNat, wan_info),
            _ => return self.failure(MapStatus::Failed),
        }
        let s = sess(svc);

        // 4. запуск или смена сети: удалить свою старую запись на нашем порту
        if renew.is_none() {
            match s.get_specific(port) {
                Ok(Some(e)) if is_ours(&e, internal) => {
                    let _ = s.delete(port);
                }
                Ok(_) | Err(CallErr::Fault(_)) => {}
                Err(CallErr::Fail) => return self.failure(MapStatus::Failed),
            }
        }

        // 5. добавление
        let first_ext = renew.as_ref().map_or(port, |m| m.ext);
        let (ext, lease_asked) = match self.open(&s, &router, permanent_ok, first_ext, internal) {
            Ok(v) => v,
            Err(MapStatus::NeedPermanentConsent) => {
                return Self::quiet(MapStatus::NeedPermanentConsent, wan_info);
            }
            Err(status) => return self.failure(status),
        };

        // 6. подтверждение: проброс засчитывается только после GetSpecificPortMappingEntry
        let confirmed = match s.get_specific(ext) {
            Ok(Some(e)) if e.internal_client == own_ip && e.internal_port == port && e.enabled => {
                Some(e)
            }
            Ok(Some(e)) if is_ours(&e, internal) => {
                let _ = s.delete(ext);
                None
            }
            _ => None,
        };
        let Some(entry) = confirmed else {
            return self.failure(MapStatus::Failed);
        };
        let permanent = entry.lease == 0;
        // бессрочная аренда, которую не просили, допустима только на нашем порту (найдётся
        // проверкой при старте); на запасном порту её убираем и считаем сбоем
        if permanent && lease_asked != 0 && ext != port {
            if is_ours(&entry, internal) {
                let _ = s.delete(ext);
            }
            return self.failure(MapStatus::Failed);
        }
        let lease = if permanent {
            0
        } else if lease_asked > 0 {
            entry.lease.min(lease_asked)
        } else {
            entry.lease
        };

        // 7. запись и отчёт; после `release` проброс не остаётся
        let mapping = Mapping {
            router,
            kind: svc.kind,
            control: svc.control.clone(),
            gw,
            internal,
            ext,
            permanent,
        };
        {
            let mut cur = lock(&self.current);
            if self.epoch.load(Ordering::SeqCst) != epoch {
                drop(cur);
                self.delete_if_ours(&mapping, overall);
                return self.failure(MapStatus::Failed);
            }
            *cur = Some(mapping);
        }
        self.reset_backoff();
        let gateway = Some(GatewayInfo {
            wan_ip: Some(wan),
            mapping: Some(SocketAddrV4::new(wan, ext)),
        });
        if permanent {
            Self::report(MapStatus::MappedPermanent, gateway, IDLE_RETRY)
        } else {
            let retry = Duration::from_secs(u64::from(lease / 2)).max(MIN_RENEW);
            Self::report(MapStatus::Mapped, gateway, retry)
        }
    }

    fn release(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let cur = lock(&self.current).take();
        let Some(m) = cur else { return };
        let settings = lock(&self.settings).clone();
        self.delete_confirmed(&m, &settings);
    }
}
