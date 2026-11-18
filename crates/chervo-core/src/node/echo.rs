//! Адрес в интернете для приглашения и помощник доступа (этап 13д, Р6 и Р10.2-3).
//!
//! Сеть трогается только по действию человека: `echo_probe` («Создать приглашение», «Получить
//! свой IP»), `reach_check` («Проверить») и поддержание адреса у ждущего приглашения (Н1). Пока
//! сервера в настройках нет, к нему ни одного пакета. Результат эхо НЕ попадает в `OwnAddrs`,
//! `nat_view`, книгу адресов, новый адрес друга, `AddressUpdate`, `ADDR_INFO` и ограничитель: он
//! идёт только в приглашение (`create_invite_ext`) и в ручной проброс (`set_manual_forward`).
//!
//! Спецификация: `docs/specs/stage-13d-echo.md`.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chervo_addr::{AddrClass, MapStatus, NatView, classify, route_source_for};
use chervo_connect::{InviteAddrs, RouteProbe as _};
use chervo_transport::Transport as _;
use chervo_transport_quinn::{ECHO_DEADLINE, EchoError, EchoPathResult, QuinnTransport};
use chervo_upnp::RouterId;
use tokio::sync::Notify;
use tokio::time::Instant as TokioInstant;

use super::Node;
use super::core::{Core, lock};
use super::error::{EchoFailure, NodeError};
use super::events::{EventSink, NodeEvent};
use super::runtime::run_timeout;
use super::settings::{EchoHost, parse_echo_server};
use super::views::{AddrToken, InviteRef};

/// Повторная проба раньше этого срока отдаёт сохранённый отчёт (сеть не трогается).
pub const ECHO_COOLDOWN: Duration = Duration::from_secs(10);
/// Раз в столько у ждущего приглашения с внешним адресом уходит один запрос эхо (Н1).
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(25);
/// Из ответа DNS берутся не больше стольких адресов, первый IPv4.
const MAX_RESOLVED: usize = 8;
/// Путей кроме пути по умолчанию.
const MAX_CANDIDATES: usize = 3;
/// Предел ожидания DNS.
const RESOLVE_LIMIT: Duration = Duration::from_secs(5);
/// Запас к сроку пробы транспорта на постановку задачи и разбор.
const PROBE_SLACK: Duration = Duration::from_secs(1);
/// Столько проб подряд без ответа поддержание считает потерей адреса.
const MISSES_BEFORE_EVENT: u32 = 3;
/// Домашних адресов компьютера для помощника не больше.
const MAX_HOME: usize = 4;

/// `Debug` без адресов: печатается только имя типа (и вариант там, где он безопасен).
macro_rules! redacted_debug {
    ($($t:ty => $name:literal),+ $(,)?) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($name)
            }
        }
    )+};
}

/// Каким путём ушёл запрос: по умолчанию или с адреса источника этого интерфейса.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EchoVia {
    DefaultRoute,
    Interface(Ipv4Addr),
}

/// Итог одного пути.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EchoResult {
    Observed(SocketAddrV4),
    NoAnswer,
    SendFailed,
}

/// Один путь пробы.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EchoPath {
    pub via: EchoVia,
    pub result: EchoResult,
}

/// Вердикт по всем путям (Р3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EchoVerdict {
    /// Кандидат дал другой IP (или путь по умолчанию молчит): VPN обойдён, `real` настоящий.
    Bypassed {
        real: SocketAddrV4,
    },
    Single,
    /// Похоже на VPN, обойти не удалось.
    MaybeVpn,
    /// Сервер видит частный адрес (он в той же сети): внешнего адреса не узнать.
    ServerSeesPrivate,
    NoAnswer,
}

/// Отчёт пробы.
#[derive(Clone, PartialEq, Eq)]
pub struct EchoReport {
    /// Порт нашего гнезда (порт прослушивания).
    pub local_port: u16,
    pub paths: Vec<EchoPath>,
    pub verdict: EchoVerdict,
    /// Порт проверки доступа, который назвал сервер; 0: проверки нет.
    pub reach_port: u16,
}

/// Почему адрес в приглашение не вписан.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NoAnswer,
    ServerLocal,
    Symmetric,
}

/// Что делать с адресом от эхо при создании приглашения.
#[derive(Clone, PartialEq, Eq)]
pub enum ExternalPlan {
    /// Вписать `addrs` (первым наблюдённый адрес). `vpn_on`: VPN включён, но обойдён.
    Add {
        addrs: Vec<SocketAddr>,
        vpn_on: bool,
    },
    /// Похоже на VPN: спросить человека, вписывать ли адрес.
    AskVpn {
        addrs: Vec<SocketAddr>,
    },
    Skip(SkipReason),
}

/// Значения для ручных шагов помощника (без сети).
#[derive(Clone, PartialEq, Eq)]
pub struct ForwardHelp {
    /// Порт программы (и внешний, и внутренний).
    pub port: u16,
    /// Адреса этого компьютера в домашней сети (не больше четырёх).
    pub home: Vec<Ipv4Addr>,
    /// Адрес страницы роутера, если известен или угадан.
    pub gw: Option<Ipv4Addr>,
    /// Адрес роутера назвал сам роутер (иначе это догадка `a.b.c.1`).
    pub gw_exact: bool,
    /// Последняя проба показала VPN (`Bypassed` или `MaybeVpn`).
    pub vpn: bool,
    /// Провайдер выдаёт общий адрес (CGNAT или двойной NAT).
    pub cgnat: bool,
}

/// Итог «Проверить».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachResult {
    /// Проверочный ответ сервера дошёл до этого компьютера на `port`.
    Reachable {
        port: u16,
    },
    NotReachable {
        port: u16,
    },
    /// Сервера нет или он не отвечает: автоматически не проверить.
    NoServer,
    /// Сервер отвечает, но проверки доступа не поддерживает.
    ServerNoReach,
}

redacted_debug! {
    EchoVia => "EchoVia(..)",
    EchoResult => "EchoResult(..)",
    EchoPath => "EchoPath(..)",
    EchoVerdict => "EchoVerdict(..)",
    EchoReport => "EchoReport(..)",
    ExternalPlan => "ExternalPlan(..)",
    ForwardHelp => "ForwardHelp(..)",
}

// ---------------------------------------------------------------------------------------------
// Чистая логика: вердикт, план приглашения, значения помощника
// ---------------------------------------------------------------------------------------------

fn observed_of(r: &EchoResult) -> Option<SocketAddrV4> {
    match r {
        EchoResult::Observed(a) => Some(*a),
        _ => None,
    }
}

/// Вердикт по порядку Р3. `default_class`: класс адреса источника маршрута к серверу;
/// `strong_host`: ОС держит маршрут по адресу источника (Windows).
pub(crate) fn echo_verdict(
    paths: &[EchoPath],
    default_class: Option<AddrClass>,
    strong_host: bool,
) -> EchoVerdict {
    let default = paths
        .iter()
        .find(|p| p.via == EchoVia::DefaultRoute)
        .and_then(|p| observed_of(&p.result));
    let candidates: Vec<&EchoPath> = paths
        .iter()
        .filter(|p| matches!(p.via, EchoVia::Interface(_)))
        .collect();
    let cand_answers: Vec<SocketAddrV4> = candidates
        .iter()
        .filter_map(|p| observed_of(&p.result))
        .collect();
    // 1. нет ответов
    if default.is_none() && cand_answers.is_empty() {
        return EchoVerdict::NoAnswer;
    }
    // 2. сервер видит не глобальный адрес
    let any_private = default
        .iter()
        .chain(cand_answers.iter())
        .any(|a| classify(IpAddr::V4(*a.ip())) != AddrClass::Global);
    if any_private {
        return EchoVerdict::ServerSeesPrivate;
    }
    // 3. VPN обойдён: кандидат дал другой IP или путь по умолчанию молчит
    match default {
        None => {
            if let Some(real) = cand_answers.first() {
                return EchoVerdict::Bypassed { real: *real };
            }
        }
        Some(d) => {
            if let Some(real) = cand_answers.iter().find(|c| c.ip() != d.ip()) {
                return EchoVerdict::Bypassed { real: *real };
            }
        }
    }
    // 4. путь по умолчанию ответил; признаки VPN, который обойти не удалось
    let tunnel_class = matches!(
        default_class,
        Some(AddrClass::Benchmark | AddrClass::Shared)
    );
    let none_answered = !candidates.is_empty() && cand_answers.is_empty();
    let all_same = !strong_host && !candidates.is_empty() && cand_answers.len() == candidates.len();
    if tunnel_class || none_answered || all_same {
        return EchoVerdict::MaybeVpn;
    }
    // 5.
    EchoVerdict::Single
}

/// Наблюдённый адрес, который идёт в приглашение: настоящий при обходе VPN, иначе с пути по
/// умолчанию (при молчащем пути по умолчанию вердикт был бы `Bypassed`).
fn invite_observed(r: &EchoReport) -> Option<SocketAddrV4> {
    if let EchoVerdict::Bypassed { real } = r.verdict {
        return Some(real);
    }
    r.paths
        .iter()
        .find(|p| p.via == EchoVia::DefaultRoute)
        .and_then(|p| observed_of(&p.result))
        .or_else(|| r.paths.iter().find_map(|p| observed_of(&p.result)))
}

/// Интерфейс, с которого получен настоящий адрес при `Bypassed` (путь для следующих запросов).
fn bypass_candidate(r: &EchoReport) -> Option<Ipv4Addr> {
    let EchoVerdict::Bypassed { real } = r.verdict else {
        return None;
    };
    r.paths.iter().find_map(|p| match (p.via, p.result) {
        (EchoVia::Interface(c), EchoResult::Observed(a)) if a.ip() == real.ip() => Some(c),
        _ => None,
    })
}

/// План адреса для приглашения (Р6): по порядку проверок.
pub fn plan_invite_external(
    r: &EchoReport,
    nat: NatView,
    manual_forward: Option<u16>,
) -> ExternalPlan {
    match r.verdict {
        EchoVerdict::NoAnswer => return ExternalPlan::Skip(SkipReason::NoAnswer),
        EchoVerdict::ServerSeesPrivate => return ExternalPlan::Skip(SkipReason::ServerLocal),
        _ => {}
    }
    if nat == NatView::Symmetric {
        return ExternalPlan::Skip(SkipReason::Symmetric);
    }
    let Some(seen) = invite_observed(r) else {
        return ExternalPlan::Skip(SkipReason::NoAnswer);
    };
    let mut addrs = vec![SocketAddr::V4(seen)];
    if let Some(p) = manual_forward
        && p != seen.port()
    {
        addrs.push(SocketAddr::V4(SocketAddrV4::new(*seen.ip(), p)));
    }
    match r.verdict {
        EchoVerdict::MaybeVpn => ExternalPlan::AskVpn { addrs },
        v => ExternalPlan::Add {
            addrs,
            vpn_on: matches!(v, EchoVerdict::Bypassed { .. }),
        },
    }
}

/// Адрес роутера, которому человек нажал «Разрешить», с адресом нашего источника маршрута к нему
/// на тот момент. Только по такому адресу помощник говорит «адрес сообщил сам роутер».
pub(crate) struct AllowedAddr {
    id: RouterId,
    pub(crate) ip: Ipv4Addr,
    source: Option<Ipv4Addr>,
}

impl AllowedAddr {
    pub(crate) fn new(id: RouterId, ip: Ipv4Addr) -> Self {
        let source = v4_of(route_source_for(SocketAddr::V4(SocketAddrV4::new(ip, 1))));
        Self { id, ip, source }
    }

    pub(crate) fn is_router(&self, id: &RouterId) -> bool {
        self.id == *id
    }

    /// Источник маршрута к роутеру тот же, что при «Разрешить» (сеть не менялась). Источник тогда
    /// неизвестен: сказать нечего, считаем сеть другой.
    pub(crate) fn same_network(&self, now: Option<Ipv4Addr>) -> bool {
        self.source.is_some() && self.source == now
    }

    /// Запись с заданным источником маршрута (тесты без сети).
    #[cfg(any(test, feature = "test-store"))]
    pub(crate) fn with_source(id: RouterId, ip: Ipv4Addr, source: Option<Ipv4Addr>) -> Self {
        Self { id, ip, source }
    }
}

/// Исходные данные `forward_help` (собираются без сети; отдельно для проверки чистой логики).
pub(crate) struct HelpInputs<'a> {
    pub port: u16,
    /// Адрес роутера из последнего «Найти роутер».
    pub lan_ip: Option<Ipv4Addr>,
    /// `route_source_for(lan_ip:1)`, когда `lan_ip` известен.
    pub lan_route_source: Option<Ipv4Addr>,
    pub report: Option<&'a EchoReport>,
    /// Адрес источника маршрута по умолчанию.
    pub default_src: Option<Ipv4Addr>,
    /// `private_sources(default_src)`.
    pub private_srcs: Vec<Ipv4Addr>,
    pub nat: NatView,
}

pub(crate) fn forward_help_from(i: &HelpInputs<'_>) -> ForwardHelp {
    let verdict = i.report.map(|r| r.verdict);
    let vpn = matches!(
        verdict,
        Some(EchoVerdict::Bypassed { .. } | EchoVerdict::MaybeVpn)
    );
    let cgnat = matches!(i.nat, NatView::BehindCgnat | NatView::DoubleNat);
    let mut home: Vec<Ipv4Addr> = if let (Some(_), Some(src)) = (i.lan_ip, i.lan_route_source) {
        // роутер назвал себя: адрес источника маршрута к нему точен
        vec![src]
    } else if let Some(c) = i.report.and_then(bypass_candidate) {
        vec![c]
    } else {
        let d_class = i.default_src.map(|d| classify(IpAddr::V4(d)));
        let tunnel = d_class.is_some_and(|c| c != AddrClass::Private)
            || matches!(verdict, Some(EchoVerdict::MaybeVpn));
        let mut v = i.private_srcs.clone();
        match i.default_src {
            Some(d) if tunnel => v.retain(|a| *a != d),
            Some(d) if d_class == Some(AddrClass::Private) => {
                v.retain(|a| *a != d);
                v.insert(0, d);
            }
            _ => {}
        }
        v
    };
    home.truncate(MAX_HOME);
    let (gw, gw_exact) = match (i.lan_ip, home.first()) {
        (Some(ip), _) => (Some(ip), true),
        (None, Some(h)) => {
            let o = h.octets();
            (Some(Ipv4Addr::new(o[0], o[1], o[2], 1)), false)
        }
        (None, None) => (None, false),
    };
    ForwardHelp {
        port: i.port,
        home,
        gw,
        gw_exact,
        vpn,
        cgnat,
    }
}

// ---------------------------------------------------------------------------------------------
// Состояние узла
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Cached {
    at: Instant,
    server_text: String,
    server: SocketAddrV4,
    report: EchoReport,
}

#[derive(Default)]
pub(crate) struct ProbeState {
    busy: bool,
    last: Option<Cached>,
}

/// Состояние эхо в `Core`: последняя проба, занятость, поддержание адреса ждущих приглашений.
#[derive(Default)]
pub(crate) struct EchoState {
    pub(crate) probe: Mutex<ProbeState>,
    pub(crate) keepalives: Mutex<HashMap<InviteRef, Arc<Notify>>>,
    /// Идёт разрешение имени сервера (поток может пережить предел ожидания).
    pub(crate) dns_busy: Arc<AtomicBool>,
    /// Только тесты: интервал поддержания вместо `KEEPALIVE_EVERY`.
    pub(crate) every_override: Mutex<Option<Duration>>,
}

/// Снимает флаг «проба идёт» при любом выходе.
struct BusyGuard<'a>(&'a Mutex<ProbeState>);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        lock(self.0).busy = false;
    }
}

/// Снимает флаг «разрешение имени идёт» при любом выходе потока DNS.
struct FlagGuard(Arc<AtomicBool>);

impl Drop for FlagGuard {
    fn drop(&mut self) {
        self.0.store(false, AtomicOrdering::Release);
    }
}

fn echo_err(e: EchoFailure) -> NodeError {
    NodeError::Echo(e)
}

fn map_transport_err(e: EchoError) -> NodeError {
    echo_err(match e {
        EchoError::Busy => EchoFailure::Busy,
        EchoError::BadServer => EchoFailure::BadAddress,
        EchoError::TooManyPaths | EchoError::SocketFamily | EchoError::Random => {
            EchoFailure::Internal
        }
    })
}

/// Имя или литерал в адрес IPv4 сервера. DNS на отдельном потоке с пределом ожидания.
/// Не больше одного разрешения имени одновременно (`dns_busy`): поток, не уложившийся в
/// `RESOLVE_LIMIT`, продолжает висеть, и новое разрешение до его конца отвечает `Busy`.
pub(crate) fn resolve(
    host: EchoHost,
    port: u16,
    dns_busy: &Arc<AtomicBool>,
) -> Result<SocketAddrV4, NodeError> {
    let server = match host {
        EchoHost::Ip(ip) => SocketAddrV4::new(ip, port),
        EchoHost::Name(name) => {
            if dns_busy.swap(true, AtomicOrdering::AcqRel) {
                return Err(echo_err(EchoFailure::Busy));
            }
            let (tx, rx) = std::sync::mpsc::channel();
            let flag = Arc::clone(dns_busy);
            let spawned = std::thread::Builder::new()
                .name("chervo-dns".to_owned())
                .spawn(move || {
                    // флаг снимается при любом выходе потока, в том числе при панике
                    let free = FlagGuard(flag);
                    let found: Result<Vec<SocketAddr>, ()> = (name.as_str(), port)
                        .to_socket_addrs()
                        .map(|it| it.take(MAX_RESOLVED).collect())
                        .map_err(|_| ());
                    // до отправки: получивший ответ уже видит снятый флаг
                    drop(free);
                    let _ = tx.send(found);
                });
            if spawned.is_err() {
                dns_busy.store(false, AtomicOrdering::Release);
                return Err(echo_err(EchoFailure::Internal));
            }
            let list = match rx.recv_timeout(RESOLVE_LIMIT) {
                Ok(Ok(list)) if !list.is_empty() => list,
                _ => return Err(echo_err(EchoFailure::Resolve)),
            };
            list.into_iter()
                .find_map(|a| match a {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                })
                .ok_or_else(|| echo_err(EchoFailure::NoIpv4))?
        }
    };
    let ip = server.ip();
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || server.port() == 0 {
        return Err(echo_err(EchoFailure::BadAddress));
    }
    Ok(server)
}

fn v4_of(ip: Option<IpAddr>) -> Option<Ipv4Addr> {
    match ip {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    }
}

impl Node {
    /// Фактический порт гнезда узла (порт прослушивания); `None`, если транспорт остановлен.
    pub fn listen_port(&self) -> Option<u16> {
        self.core
            .transport
            .local_addrs()
            .first()
            .map(SocketAddr::port)
    }

    /// Сервер эхо (`None`: убрать). Только проверка строки и запись настроек, без сети.
    /// Сохранённый отчёт пробы сбрасывается.
    pub fn set_echo_server(&self, server: Option<&str>) -> Result<(), NodeError> {
        let value = match server {
            None => None,
            Some(s) => {
                let s = s.trim();
                if parse_echo_server(s).is_none() {
                    return Err(echo_err(EchoFailure::BadAddress));
                }
                Some(s.to_owned())
            }
        };
        let mut changed = false;
        self.update_settings(|s| {
            changed = s.echo_server != value;
            s.echo_server = value;
            Ok(())
        })?;
        lock(&self.core.echo.probe).last = None;
        // Р9: без сохранённого сервера (или со сменой сервера) старое поддержание адреса не живёт
        if changed {
            self.core.stop_all_keepalives();
        }
        Ok(())
    }

    /// Проба: «как меня видно из интернета». Блокирует поток (до ~9 с вместе с DNS).
    /// Нет сервера: `NotConfigured`, без сети. Идёт другая проба: `Busy`. Меньше
    /// `ECHO_COOLDOWN` с прошлой пробы: сохранённый отчёт.
    pub fn echo_probe(&self) -> Result<EchoReport, NodeError> {
        let text = lock(&self.core.settings)
            .echo_server
            .clone()
            .ok_or_else(|| echo_err(EchoFailure::NotConfigured))?;
        {
            let mut st = lock(&self.core.echo.probe);
            if st.busy {
                return Err(echo_err(EchoFailure::Busy));
            }
            if let Some(c) = &st.last
                && c.server_text == text
                && c.at.elapsed() < ECHO_COOLDOWN
            {
                return Ok(c.report.clone());
            }
            st.busy = true;
        }
        let _busy = BusyGuard(&self.core.echo.probe);
        let (server, report) = self.run_probe(&text)?;
        lock(&self.core.echo.probe).last = Some(Cached {
            at: Instant::now(),
            server_text: text,
            server,
            report: report.clone(),
        });
        Ok(report)
    }

    fn run_probe(&self, text: &str) -> Result<(SocketAddrV4, EchoReport), NodeError> {
        let (host, port) =
            parse_echo_server(text).ok_or_else(|| echo_err(EchoFailure::BadAddress))?;
        let server = resolve(host, port, &self.core.echo.dns_busy)?;
        let local_port = self
            .listen_port()
            .ok_or_else(|| echo_err(EchoFailure::Internal))?;
        // пути: по умолчанию и до трёх домашних адресов источника (обход VPN)
        let d = v4_of(route_source_for(SocketAddr::V4(server)));
        let mut vias = vec![EchoVia::DefaultRoute];
        let mut sources: Vec<Option<Ipv4Addr>> = vec![None];
        if let Some(d) = d {
            for c in chervo_lan::private_sources(d)
                .into_iter()
                .filter(|c| *c != d)
                .take(MAX_CANDIDATES)
            {
                vias.push(EchoVia::Interface(c));
                sources.push(Some(c));
            }
        }
        let transport = self.core.transport.clone();
        let results = run_timeout(
            &self.core.rt,
            async move { transport.echo_probe(server, &sources).await },
            ECHO_DEADLINE + PROBE_SLACK,
        )
        .ok_or_else(|| echo_err(EchoFailure::Internal))?
        .map_err(map_transport_err)?;
        let mut reach_port = 0;
        let paths: Vec<EchoPath> = vias
            .into_iter()
            .zip(results)
            .map(|(via, r)| EchoPath {
                via,
                result: match r {
                    EchoPathResult::Observed {
                        addr,
                        reach_port: rp,
                    } => {
                        if reach_port == 0 {
                            reach_port = rp;
                        }
                        EchoResult::Observed(addr)
                    }
                    EchoPathResult::NoAnswer => EchoResult::NoAnswer,
                    EchoPathResult::SendFailed => EchoResult::SendFailed,
                },
            })
            .collect();
        let class = d.map(|d| classify(IpAddr::V4(d)));
        let verdict = echo_verdict(&paths, class, cfg!(windows));
        Ok((
            server,
            EchoReport {
                local_port,
                paths,
                verdict,
                reach_port,
            },
        ))
    }

    /// Приглашение с адресами из `extra` (адрес от эхо, `plan_invite_external`) впереди
    /// собственных. Пока приглашение ждёт, раз в `KEEPALIVE_EVERY` один запрос эхо тем же путём
    /// следит за адресом: изменился — `NodeEvent::InviteAddressChanged`.
    pub fn create_invite_ext(
        &self,
        same_network: bool,
        extra: &[SocketAddr],
    ) -> Result<(InviteRef, AddrToken), NodeError> {
        let ttl = lock(&self.core.settings).invite_ttl_secs;
        let addrs = InviteAddrs::AutoWith {
            same_network,
            extra: extra.to_vec(),
        };
        let _g = self.enter();
        let (pair, text) = self.core.engine.create_invite(ttl, addrs)?;
        let invite = InviteRef::new(pair);
        self.start_keepalive(invite, ttl, extra);
        Ok((invite, AddrToken::new(text)))
    }

    /// Поддержание адреса только если в приглашение вписан адрес, полученный последней пробой.
    fn start_keepalive(&self, invite: InviteRef, ttl_secs: u64, extra: &[SocketAddr]) {
        let Some(cached) = lock(&self.core.echo.probe).last.clone() else {
            return;
        };
        let Some(baseline) = invite_observed(&cached.report) else {
            return;
        };
        if !extra.contains(&SocketAddr::V4(baseline)) {
            return;
        }
        let every = (*lock(&self.core.echo.every_override)).unwrap_or(KEEPALIVE_EVERY);
        let stop = Arc::new(Notify::new());
        lock(&self.core.echo.keepalives).insert(invite, stop.clone());
        // Гонка с `set_echo_server`: настройки пишутся раньше, чем сбрасываются поддержания. Если
        // сервер уже сменили или убрали, запись снимается здесь, иначе её снимет тот, кто пришёл
        // позже нас.
        if lock(&self.core.settings).echo_server.as_deref() != Some(cached.server_text.as_str()) {
            self.core.stop_keepalive(&invite);
            return;
        }
        let job = KeepaliveJob {
            transport: self.core.transport.clone(),
            sink: self.core.sink.clone(),
            invite,
            server: cached.server,
            via: bypass_candidate(&cached.report),
            baseline,
            every,
            lifetime: Duration::from_secs(ttl_secs),
        };
        let core = self.core.clone();
        drop(self.core.rt.spawn(async move {
            keepalive_loop(job, stop.clone()).await;
            // запись убирается, только если она всё ещё эта (не заменена новым приглашением)
            let mut map = lock(&core.echo.keepalives);
            if map.get(&invite).is_some_and(|n| Arc::ptr_eq(n, &stop)) {
                map.remove(&invite);
            }
        }));
    }

    /// Адрес роутера, разрешённого человеком, и адрес нашего источника маршрута к нему. Если
    /// источник маршрута с тех пор изменился (другая сеть), запись сбрасывается.
    fn allowed_router_now(&self) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        self.allowed_router_with(|ip| {
            v4_of(route_source_for(SocketAddr::V4(SocketAddrV4::new(ip, 1))))
        })
    }

    /// То же с подставляемым определением источника маршрута (тесты без сети).
    pub(crate) fn allowed_router_with(
        &self,
        route: impl FnOnce(Ipv4Addr) -> Option<Ipv4Addr>,
    ) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        let mut slot = lock(&self.core.allowed_router);
        let Some(a) = slot.as_ref() else {
            return (None, None);
        };
        let now = route(a.ip);
        if a.same_network(now) {
            (Some(a.ip), now)
        } else {
            *slot = None;
            (None, None)
        }
    }

    /// Значения для ручных шагов помощника. Сети не трогает (только опрос маршрутов без
    /// отправки пакетов).
    pub fn forward_help(&self) -> ForwardHelp {
        let port = self
            .listen_port()
            .unwrap_or_else(|| lock(&self.core.settings).port);
        let (lan_ip, lan_route_source) = self.allowed_router_now();
        let report = lock(&self.core.echo.probe)
            .last
            .as_ref()
            .map(|c| c.report.clone());
        let default_src = self.core.probe.probe().v4;
        let private_srcs = default_src.map_or_else(Vec::new, chervo_lan::private_sources);
        forward_help_from(&HelpInputs {
            port,
            lan_ip,
            lan_route_source,
            report: report.as_ref(),
            default_src,
            private_srcs,
            nat: self.core.engine.nat_view(),
        })
    }

    /// «Проверить»: сервер присылает проверочный ответ со второго порта на порт, который мы
    /// проверяем. Блокирует поток (до ~9 с). После удачи для ручного правила запоминается
    /// `manual_forward` (П3).
    pub fn reach_check(&self) -> Result<ReachResult, NodeError> {
        if lock(&self.core.settings).echo_server.is_none() {
            return Ok(ReachResult::NoServer);
        }
        let report = self.echo_probe()?;
        if report.verdict == EchoVerdict::NoAnswer {
            return Ok(ReachResult::NoServer);
        }
        if report.reach_port == 0 {
            return Ok(ReachResult::ServerNoReach);
        }
        let Some(server) = lock(&self.core.echo.probe).last.as_ref().map(|c| c.server) else {
            return Err(echo_err(EchoFailure::Internal));
        };
        let listen = self
            .listen_port()
            .ok_or_else(|| echo_err(EchoFailure::Internal))?;
        // внешний порт: у UPnP-проброса это порт программы (движок номер не отдаёт), у ручного
        // правила порт из настроек, иначе порт программы
        let mapped = matches!(
            self.core.engine.mapping_status(),
            Some(MapStatus::Mapped | MapStatus::MappedPermanent)
        );
        let manual = lock(&self.core.settings).manual_forward;
        let port = if mapped {
            listen
        } else {
            manual.unwrap_or(listen)
        };
        let via = bypass_candidate(&report);
        let transport = self.core.transport.clone();
        let reachable = run_timeout(
            &self.core.rt,
            async move { transport.reach_probe(server, via, port).await },
            ECHO_DEADLINE + PROBE_SLACK,
        )
        .ok_or_else(|| echo_err(EchoFailure::Internal))?
        .map_err(map_transport_err)?;
        if !reachable {
            return Ok(ReachResult::NotReachable { port });
        }
        if !mapped {
            self.set_manual_forward(Some(port))?;
        }
        Ok(ReachResult::Reachable { port })
    }

    /// «Правило создано»: ручной проброс с внешним портом, равным порту программы (П3).
    pub fn confirm_manual_forward(&self) -> Result<(), NodeError> {
        let port = self
            .listen_port()
            .ok_or_else(|| echo_err(EchoFailure::Internal))?;
        self.set_manual_forward(Some(port))
    }
}

impl Core {
    /// Остановить поддержание адреса приглашения, если оно идёт.
    pub(crate) fn stop_keepalive(&self, invite: &InviteRef) {
        let stop = lock(&self.echo.keepalives).remove(invite);
        if let Some(n) = stop {
            n.notify_one();
        }
    }

    /// Остановить все поддержания адреса (сервер эхо убран или заменён).
    pub(crate) fn stop_all_keepalives(&self) {
        let all: Vec<Arc<Notify>> = lock(&self.echo.keepalives)
            .drain()
            .map(|(_, n)| n)
            .collect();
        for n in all {
            n.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Поддержание адреса (Н1)
// ---------------------------------------------------------------------------------------------

pub(crate) struct KeepaliveJob {
    pub(crate) transport: Arc<QuinnTransport>,
    pub(crate) sink: Arc<EventSink>,
    pub(crate) invite: InviteRef,
    pub(crate) server: SocketAddrV4,
    pub(crate) via: Option<Ipv4Addr>,
    pub(crate) baseline: SocketAddrV4,
    pub(crate) every: Duration,
    /// Не дольше срока приглашения.
    pub(crate) lifetime: Duration,
}

/// Раз в `every` один запрос эхо тем же путём. Изменился наблюдённый адрес: событие. Без ответа
/// поддержание продолжается до срока; три пробы подряд без ответа: событие (один раз за серию).
/// Заканчивается по `stop` или по сроку.
pub(crate) async fn keepalive_loop(job: KeepaliveJob, stop: Arc<Notify>) {
    let ends = TokioInstant::now() + job.lifetime;
    let mut current = job.baseline;
    let mut misses = 0u32;
    loop {
        tokio::select! {
            () = stop.notified() => return,
            () = tokio::time::sleep(job.every) => {}
        }
        if TokioInstant::now() >= ends {
            return;
        }
        let sources = [job.via];
        let probe = job.transport.echo_probe(job.server, &sources);
        let result = tokio::select! {
            () = stop.notified() => return,
            r = probe => r,
        };
        match result.map(|v| v.first().copied()) {
            Ok(Some(EchoPathResult::Observed { addr, .. })) => {
                misses = 0;
                if addr != current {
                    current = addr;
                    job.sink
                        .emit(NodeEvent::InviteAddressChanged { invite: job.invite });
                }
            }
            Ok(_) => {
                misses = misses.saturating_add(1);
                if misses == MISSES_BEFORE_EVENT {
                    job.sink
                        .emit(NodeEvent::InviteAddressChanged { invite: job.invite });
                }
            }
            // занято (человек сам нажал «Получить свой IP») или сбой запуска: пропуск
            Err(_) => {}
        }
    }
}
