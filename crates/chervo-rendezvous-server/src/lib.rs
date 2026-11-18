//! Эхо-сервер Червоточины (этап 13д, Р4): по UDP говорит клиенту, с какого адреса и порта его
//! видно, и по просьбе проверяет, доходит ли ответ с другого порта этого же сервера.
//!
//! Сервер маленький и немой: на диск ничего не пишет, IP клиентов не печатает и не хранит дольше
//! окна лимита, секретов у него нет. Ответ всегда короче запроса и уходит только на IP источника
//! запроса. Зависимости: наш протокол `chervo-rendezvous-wire` и классификация адресов
//! `chervo-addr`.
//!
//! Порядок разбора недоверенной датаграммы: источник, затем лимит, затем формат (раздел 5
//! спецификации).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

mod limiter;

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use chervo_addr::{AddrClass, classify};
use chervo_rendezvous_wire::{
    RESPONSE_LEN, Request, encode_echo_response, encode_reach_response, parse_request,
};

use limiter::{Limiter, key_of};

/// Ответов одному ключу (IPv4 /32, IPv6 /64) за окно; общий счёт эхо и проверок.
pub const PER_IP_BURST: u32 = 16;
pub const PER_IP_WINDOW: Duration = Duration::from_secs(10);
/// Ключей в таблице лимитов; когда полна, новый ключ сразу считается превысившим лимит.
pub const MAX_TRACKED: usize = 65_536;
/// Ответов в секунду всего.
pub const GLOBAL_PER_SEC: u32 = 1000;

/// Буфер приёма и срок ожидания одного `recv`.
const RECV_BUF: usize = 2048;
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Не больше стольких адресов `--listen`.
const MAX_LISTEN: usize = 16;
/// Шаг главного цикла: проверка `stop` и срока отчёта.
const TICK: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: Vec<SocketAddr>,
    /// Порт второго сокета (тот же IP) для проверки доступа. `None`: проверки нет.
    pub reach_port: Option<u16>,
    /// Отвечать и непубличным адресам (для тестов и закрытых сетей).
    pub allow_private: bool,
    pub report_every: Duration,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Все принятые датаграммы.
    pub requests: u64,
    pub replies: u64,
    pub reach_replies: u64,
    pub malformed: u64,
    pub limited: u64,
    pub refused_source: u64,
    pub recv_errors: u64,
}

/// Строка счётчиков для stderr. Адресов в ней нет.
pub fn report_line(c: &Counters) -> String {
    format!(
        "counters requests={} replies={} reach_replies={} malformed={} limited={} refused_source={} recv_errors={}",
        c.requests,
        c.replies,
        c.reach_replies,
        c.malformed,
        c.limited,
        c.refused_source,
        c.recv_errors
    )
}

/// Строка старта для stderr: версия и собственные адреса сервера.
pub fn start_line(version: &str, listen: &[SocketAddr]) -> String {
    let addrs: Vec<String> = listen.iter().map(ToString::to_string).collect();
    format!(
        "chervo-rendezvous {version} listening on {}",
        addrs.join(", ")
    )
}

/// Что делать с принятой датаграммой.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Drop,
    Echo([u8; RESPONSE_LEN]),
    Reach([u8; RESPONSE_LEN], u16),
}

pub(crate) struct Shared {
    allow_private: bool,
    reach_port: Option<u16>,
    limiter: Mutex<Limiter>,
    counters: Mutex<Counters>,
}

/// Источник годится для ответа: порт не 0, адрес не неуказанный, не групповой, не
/// широковещательный; без `allow_private` ещё и только публичный.
fn source_ok(src: SocketAddr, allow_private: bool) -> bool {
    if src.port() == 0 {
        return false;
    }
    let ip = src.ip().to_canonical();
    let bad = match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast(),
    };
    if bad {
        return false;
    }
    allow_private || classify(ip) == AddrClass::Global
}

impl Shared {
    pub(crate) fn new(cfg: &ServerConfig, limiter: Limiter) -> Self {
        Self {
            allow_private: cfg.allow_private,
            reach_port: cfg.reach_port,
            limiter: Mutex::new(limiter),
            counters: Mutex::new(Counters::default()),
        }
    }

    pub(crate) fn snapshot(&self) -> Counters {
        *self.counters.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn count(&self, f: impl FnOnce(&mut Counters)) {
        f(&mut self.counters.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Разбор одной датаграммы. Порядок: источник, лимит, формат.
    pub(crate) fn handle(&self, src: SocketAddr, data: &[u8], now: Instant) -> Action {
        self.count(|c| c.requests += 1);
        if !source_ok(src, self.allow_private) {
            self.count(|c| c.refused_source += 1);
            return Action::Drop;
        }
        let allowed = self
            .limiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(key_of(src.ip()), now);
        if !allowed {
            self.count(|c| c.limited += 1);
            return Action::Drop;
        }
        match parse_request(data) {
            Err(_) => {
                self.count(|c| c.malformed += 1);
                Action::Drop
            }
            Ok(Request::Echo(nonce)) => Action::Echo(encode_echo_response(
                &nonce,
                src,
                self.reach_port.unwrap_or(0),
            )),
            Ok(Request::Reach { nonce, target_port }) => {
                if self.reach_port.is_none() {
                    self.count(|c| c.malformed += 1);
                    Action::Drop
                } else {
                    Action::Reach(encode_reach_response(&nonce, src), target_port)
                }
            }
        }
    }
}

struct Listener {
    main: UdpSocket,
    reach: Option<UdpSocket>,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Привязать сокеты (основной и, если нужно, проверочный на том же IP).
fn bind_all(cfg: &ServerConfig) -> io::Result<Vec<Listener>> {
    if cfg.listen.is_empty() || cfg.listen.len() > MAX_LISTEN {
        return Err(invalid("listen list"));
    }
    if cfg.reach_port == Some(0) {
        return Err(invalid("reach port"));
    }
    if cfg.report_every.is_zero() {
        return Err(invalid("report interval"));
    }
    let mut out = Vec::new();
    for addr in &cfg.listen {
        let main = UdpSocket::bind(addr)?;
        main.set_read_timeout(Some(RECV_TIMEOUT))?;
        let reach = match cfg.reach_port {
            Some(port) => {
                let mut ra = *addr;
                ra.set_port(port);
                Some(UdpSocket::bind(ra)?)
            }
            None => None,
        };
        out.push(Listener { main, reach });
    }
    Ok(out)
}

/// Цикл приёма одного основного сокета.
fn worker(l: &Listener, shared: &Shared, stop: &AtomicBool) {
    let mut buf = [0u8; RECV_BUF];
    while !stop.load(Ordering::Relaxed) {
        match l.main.recv_from(&mut buf) {
            Ok((n, src)) => {
                let data = buf.get(..n).unwrap_or(&[]);
                match shared.handle(src, data, Instant::now()) {
                    Action::Drop => {}
                    Action::Echo(pkt) => {
                        if l.main.send_to(&pkt, src).is_ok() {
                            shared.count(|c| c.replies += 1);
                        }
                    }
                    Action::Reach(pkt, port) => {
                        if let Some(r) = &l.reach
                            && r.send_to(&pkt, SocketAddr::new(src.ip(), port)).is_ok()
                        {
                            shared.count(|c| c.reach_replies += 1);
                        }
                    }
                }
            }
            Err(e) => match classify_recv_error(e.kind()) {
                RecvErrorKind::Quiet => {}
                RecvErrorKind::PeerReset => {
                    // ICMP «порт недоступен» после нашего ответа поддельному источнику (Windows):
                    // ошибка не про этот сокет, пауза дала бы атакующему способ тормозить приём
                }
                RecvErrorKind::Other => {
                    // настоящая ошибка приёма: считаем и не крутимся вхолостую
                    shared.count(|c| c.recv_errors += 1);
                    thread::sleep(Duration::from_millis(5));
                }
            },
        }
    }
}

/// Что делать с ошибкой `recv_from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvErrorKind {
    /// Тайм-аут чтения или прерывание: просто следующий круг.
    Quiet,
    /// Сброс «соединения» из-за ICMP от закрытого порта (WSAECONNRESET): пропустить без паузы.
    PeerReset,
    /// Всё остальное: счётчик и короткая пауза.
    Other,
}

fn classify_recv_error(kind: io::ErrorKind) -> RecvErrorKind {
    match kind {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
            RecvErrorKind::Quiet
        }
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused => {
            RecvErrorKind::PeerReset
        }
        _ => RecvErrorKind::Other,
    }
}

/// Запустить сервер и работать, пока `stop` не станет `true`. `bound` получает фактические адреса
/// основных сокетов (удобно при порте 0); `report` вызывается раз в `report_every` и один раз при
/// остановке. Ошибка привязки возвращается сразу, до `bound`.
pub fn serve(
    cfg: ServerConfig,
    stop: Arc<AtomicBool>,
    bound: impl FnOnce(Vec<SocketAddr>),
    mut report: impl FnMut(&Counters) + Send,
) -> io::Result<()> {
    let listeners = bind_all(&cfg)?;
    let mut local = Vec::new();
    for l in &listeners {
        local.push(l.main.local_addr()?);
    }
    bound(local);
    let shared = Shared::new(&cfg, Limiter::new(Instant::now()));
    thread::scope(|s| {
        for l in &listeners {
            let shared = &shared;
            let stop = &*stop;
            s.spawn(move || worker(l, shared, stop));
        }
        let mut last = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(TICK);
            if last.elapsed() >= cfg.report_every {
                report(&shared.snapshot());
                last = Instant::now();
            }
        }
        report(&shared.snapshot());
    });
    Ok(())
}

#[cfg(test)]
mod tests;
