//! Минимальный клиент SNTP для кнопки «синхронизировать время».
//!
//! Только `std` и `getrandom`. Ничего не вызывается автоматически: единственный вход это
//! `sync_clock`, а его зовёт приложение по явному действию пользователя. Системные часы не
//! меняются; результат это поправка (мс), которую приложение сохраняет и передаёт транспорту.
//! Спецификация: `docs/specs/stage-09b-knock.md`, п.9 и «Интерфейс».
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

use std::collections::HashSet;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Серверы по умолчанию. `ru.pool.ntp.org`: [П] по ntppool.org/zone/ru; `vniiftri.ru`: [НП],
/// не подтверждены (сайт был на обслуживании), проверить на реальной машине. Список можно
/// заменить в настройках (`SyncConfig::servers`).
pub const DEFAULT_SERVERS: &[&str] = &[
    "0.ru.pool.ntp.org",
    "1.ru.pool.ntp.org",
    "2.ru.pool.ntp.org",
    "3.ru.pool.ntp.org",
    "ntp1.vniiftri.ru",
    "ntp2.vniiftri.ru",
    "ntp3.vniiftri.ru",
    "ntp4.vniiftri.ru",
    "ntp21.vniiftri.ru",
];

/// Порт NTP по умолчанию.
const NTP_PORT: u16 = 123;
/// Секунд между 1900 и 1970.
const NTP_UNIX_DELTA: u64 = 2_208_988_800;
/// Имён серверов не больше.
const MAX_NAMES: usize = 16;
/// Длина имени не больше.
const MAX_NAME_LEN: usize = 253;
/// Длина пакета SNTP.
const PACKET_LEN: usize = 48;
/// Принимаемая длина ответа: 48..=1024 (читаются первые 48 байт).
const MAX_RESPONSE_LEN: usize = 1024;
/// Один «секунда» в формате 16.16.
const ONE_SECOND_16_16: u32 = 0x1_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    pub servers: Vec<String>,
    /// Ожидание ответа одного сервера.
    pub timeout: Duration,
    /// Сколько серверов должны дать допустимый и согласованный ответ.
    pub min_valid: usize,
    /// Допустимый разброс ответов вокруг медианы.
    pub max_spread: Duration,
    /// Предел модуля поправки.
    pub max_abs_offset: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            servers: DEFAULT_SERVERS.iter().map(|s| (*s).to_owned()).collect(),
            timeout: Duration::from_secs(2),
            min_valid: 2,
            max_spread: Duration::from_secs(1),
            max_abs_offset: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

/// Результат: поправка к системному времени, мс (истинное время = системное + поправка).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOffset {
    pub offset_ms: i64,
    /// Сколько серверов дали допустимый ответ.
    pub valid: u8,
    /// Сколько серверов опрошено.
    pub queried: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncError {
    NoServers,
    TooFewValid,
    Disagree,
    TooLarge,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NoServers => "no time servers configured",
            Self::TooFewValid => "too few valid time server answers",
            Self::Disagree => "time servers disagree",
            Self::TooLarge => "clock offset too large",
        };
        f.write_str(text)
    }
}

impl std::error::Error for SyncError {}

/// Время «сейчас» в формате NTP 32.32 (секунды с 1900 по модулю 2^32, дробь).
fn ntp_now() -> u64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    ntp_from_unix(d)
}

fn ntp_from_unix(d: Duration) -> u64 {
    let secs = d.as_secs().wrapping_add(NTP_UNIX_DELTA) & 0xFFFF_FFFF;
    let frac = (u64::from(d.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(s.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(s.try_into().ok()?))
}

/// Разбор ответа SNTP. `origin`: 8 случайных байт запроса (сервер обязан вернуть их в «originate»);
/// `t1` и `t4`: время отправки запроса и получения ответа по нашим часам (NTP 32.32).
/// Возвращает поправку в миллисекундах `((T2-T1)+(T3-T4))/2`. Любое несоответствие даёт `Err(())`.
#[allow(clippy::result_unit_err)]
pub fn parse_response(buf: &[u8], origin: [u8; 8], t1: u64, t4: u64) -> Result<i64, ()> {
    if buf.len() < PACKET_LEN || buf.len() > MAX_RESPONSE_LEN {
        return Err(());
    }
    let b0 = *buf.first().ok_or(())?;
    let li = b0 >> 6;
    let vn = (b0 >> 3) & 7;
    let mode = b0 & 7;
    if li == 3 || !(vn == 3 || vn == 4) || mode != 4 {
        return Err(());
    }
    let stratum = *buf.get(1).ok_or(())?;
    if !(1..=15).contains(&stratum) {
        return Err(());
    }
    let root_delay = be32(buf, 4).ok_or(())?;
    let root_disp = be32(buf, 8).ok_or(())?;
    if root_delay > ONE_SECOND_16_16 || root_disp > ONE_SECOND_16_16 {
        return Err(());
    }
    let got_origin = buf.get(24..32).ok_or(())?;
    // сравнение без раннего выхода: не раскрывать, сколько байт совпало
    let diff = got_origin
        .iter()
        .zip(origin.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(());
    }
    let t2 = be64(buf, 32).ok_or(())?;
    let t3 = be64(buf, 40).ok_or(())?;
    if t3 == 0 {
        return Err(());
    }
    Ok(offset_ms(t1, t2, t3, t4))
}

/// `((T2-T1)+(T3-T4))/2` в 32.32 с обёрточными разностями (без эр 1900 и 2036), в миллисекундах.
fn offset_ms(t1: u64, t2: u64, t3: u64, t4: u64) -> i64 {
    // разность по модулю 2^64, затем как знаковая: верно в пределах ±68 лет
    let d1 = i128::from(t2.wrapping_sub(t1).cast_signed());
    let d2 = i128::from(t3.wrapping_sub(t4).cast_signed());
    let half = (d1 + d2) / 2;
    let ms = (half * 1000) / (1i128 << 32);
    i64::try_from(ms).unwrap_or(if ms < 0 { i64::MIN } else { i64::MAX })
}

/// Ошибка одного сервера не раскрывается: его ответ просто не учитывается.
fn query_one(addr: SocketAddr, timeout: Duration) -> Option<i64> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    // подключённое гнездо принимает датаграммы только с адреса сервера
    sock.connect(addr).ok()?;
    let mut origin = [0u8; 8];
    getrandom::fill(&mut origin).ok()?;
    let mut req = [0u8; PACKET_LEN];
    *req.first_mut()? = 0x23; // LI 0, VN 4, mode 3
    req.get_mut(40..48)?.copy_from_slice(&origin);
    let start = Instant::now();
    let t1 = ntp_now();
    sock.send(&req).ok()?;
    let mut buf = [0u8; 2048];
    loop {
        let left = timeout.checked_sub(start.elapsed())?;
        if left.is_zero() {
            return None;
        }
        sock.set_read_timeout(Some(left)).ok()?;
        let n = sock.recv(&mut buf).ok()?;
        let t4 = ntp_now();
        if start.elapsed() > timeout {
            return None;
        }
        if let Some(resp) = buf.get(..n)
            && let Ok(off) = parse_response(resp, origin, t1, t4)
        {
            return Some(off);
        }
        // чужой или испорченный ответ: ждать дальше до срока
    }
}

/// Первый адрес IPv4 имени; имя без порта получает порт 123.
fn resolve_v4(name: &str) -> Option<SocketAddr> {
    let target = if name.contains(':') {
        name.to_owned()
    } else {
        format!("{name}:{NTP_PORT}")
    };
    target
        .to_socket_addrs()
        .ok()?
        .find(std::net::SocketAddr::is_ipv4)
}

/// Занять адрес сервера; `false`, если другое имя уже дало тот же адрес.
fn claim(claimed: &Mutex<HashSet<SocketAddr>>, addr: SocketAddr) -> bool {
    claimed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(addr)
}

/// Свёртка ответов: допустимых не меньше порога, медиана, разброс, предел.
fn aggregate(
    mut values: Vec<i64>,
    names: usize,
    queried: usize,
    cfg: &SyncConfig,
) -> Result<ClockOffset, SyncError> {
    let need = cfg.min_valid.min(names).max(1);
    if values.len() < need {
        return Err(SyncError::TooFewValid);
    }
    values.sort_unstable();
    let n = values.len();
    let mid = n / 2;
    let median = if n % 2 == 1 {
        *values.get(mid).ok_or(SyncError::TooFewValid)?
    } else {
        let a = i128::from(*values.get(mid - 1).ok_or(SyncError::TooFewValid)?);
        let b = i128::from(*values.get(mid).ok_or(SyncError::TooFewValid)?);
        i64::try_from((a + b) / 2).map_err(|_| SyncError::TooLarge)?
    };
    let spread_ms = i128::try_from(cfg.max_spread.as_millis()).unwrap_or(i128::MAX);
    let close = values
        .iter()
        .filter(|v| (i128::from(**v) - i128::from(median)).abs() <= spread_ms)
        .count();
    if close < need {
        return Err(SyncError::Disagree);
    }
    let limit = i128::try_from(cfg.max_abs_offset.as_millis()).unwrap_or(i128::MAX);
    if i128::from(median).abs() > limit {
        return Err(SyncError::TooLarge);
    }
    Ok(ClockOffset {
        offset_ms: median,
        valid: u8::try_from(n).unwrap_or(u8::MAX),
        queried: u8::try_from(queried).unwrap_or(u8::MAX),
    })
}

/// Блокирующая синхронизация: параллельный опрос серверов (первый IPv4 каждого имени),
/// медиана, проверки; повторяющиеся адреса считаются одним сервером (порог `min_valid` при этом
/// считается по настроенным именам). Вызывать только по явному действию пользователя.
pub fn sync_clock(cfg: &SyncConfig) -> Result<ClockOffset, SyncError> {
    let names: Vec<&str> = cfg
        .servers
        .iter()
        .map(String::as_str)
        .filter(|n| !n.is_empty() && n.len() <= MAX_NAME_LEN)
        .take(MAX_NAMES)
        .collect();
    if names.is_empty() {
        return Err(SyncError::NoServers);
    }
    // Разные имена пула могут дать один сервер: каждый адрес опрашивается и учитывается один раз.
    let claimed: Mutex<HashSet<SocketAddr>> = Mutex::new(HashSet::new());
    let results: Vec<(bool, Option<i64>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = names
            .iter()
            .map(|name| {
                let claimed = &claimed;
                scope.spawn(move || match resolve_v4(name) {
                    Some(addr) if claim(claimed, addr) => (true, query_one(addr, cfg.timeout)),
                    _ => (false, None),
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or((false, None)))
            .collect()
    });
    let queried = results.iter().filter(|(asked, _)| *asked).count();
    let values: Vec<i64> = results.iter().filter_map(|(_, v)| *v).collect();
    aggregate(values, names.len(), queried, cfg)
}

#[cfg(test)]
mod tests;
