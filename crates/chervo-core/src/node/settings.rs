//! Файл настроек `settings.v1` (этап 18а, A1.3): собственный строгий формат `ключ=значение`,
//! по одному значению в строке, без serde. Файл читает только тот же пользователь, но разбор
//! всё равно строгий: любое отклонение это `SettingsCorrupt`, файл молча не переписывается.
//!
//! В файле нет имён друзей, адресов и ключей. Запись атомарная (временный файл, fsync,
//! переименование), права 0600 там, где они есть.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chervo_upnp::{AllowedRouter, RouterId};

use super::error::NodeError;

/// Имя файла настроек в каталоге данных.
pub(crate) const FILE_NAME: &str = "settings.v1";
/// Первая строка файла.
pub(crate) const HEADER: &str = "chervo-settings 1";
/// Размер файла не больше, байт.
pub(crate) const MAX_FILE_BYTES: usize = 64 * 1024;
/// Длина строки не больше, байт (без перевода строки).
pub(crate) const MAX_LINE_BYTES: usize = 4 * 1024;
/// Папок приёма всего (основная и дополнительные).
pub(crate) const MAX_ROOTS: usize = 16;
pub(crate) const MAX_ROUTERS: usize = 16;
/// Столько имён серверов времени принимает `chervo_timesync` (`MAX_NAMES`).
pub(crate) const MAX_NTP_SERVERS: usize = 16;
const MAX_NTP_NAME: usize = 253;
pub(crate) const DEFAULT_INVITE_TTL_SECS: u64 = 900;
pub(crate) const MIN_INVITE_TTL_SECS: u64 = 60;
pub(crate) const MAX_INVITE_TTL_SECS: u64 = 86_400;
pub(crate) const DEFAULT_MIN_FREE_PERCENT: u8 = 10;
/// Предел поправки часов, мс: 7 суток, как у `SystemClock` и транспорта.
pub(crate) const MAX_CLOCK_OFFSET_MS: i64 = 7 * 24 * 3600 * 1000;
/// Порты ниже этого значения узел сам не выбирает и в `set_port` не принимает.
pub(crate) const MIN_USER_PORT: u16 = 1024;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) port: u16,
    pub(crate) receive_root: PathBuf,
    pub(crate) shared_root_confirmed: bool,
    pub(crate) extra_roots: Vec<PathBuf>,
    pub(crate) min_free_percent: u8,
    pub(crate) invite_ttl_secs: u64,
    pub(crate) manual_forward: Option<u16>,
    pub(crate) routers: Vec<AllowedRouter>,
    pub(crate) clock_offset_ms: i64,
    pub(crate) clock_offset_at: u64,
    /// Пусто: серверы по умолчанию из `chervo_timesync::SyncConfig`.
    pub(crate) ntp_servers: Vec<String>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Settings(..)")
    }
}

impl Settings {
    /// Настройки первого запуска.
    pub(crate) fn new(port: u16, receive_root: PathBuf, shared_root_confirmed: bool) -> Self {
        Self {
            port,
            receive_root,
            shared_root_confirmed,
            extra_roots: Vec::new(),
            min_free_percent: DEFAULT_MIN_FREE_PERCENT,
            invite_ttl_secs: DEFAULT_INVITE_TTL_SECS,
            manual_forward: None,
            routers: Vec::new(),
            clock_offset_ms: 0,
            clock_offset_at: 0,
            ntp_servers: Vec::new(),
        }
    }
}

/// Новая основная папка. Прежняя основная остаётся среди дополнительных, чтобы недокачанные там
/// передачи не потерялись; новая из дополнительных убирается. Места в списке нет:
/// `LimitReached`, настройки не меняются. Подтверждение «других пользователей нет» только
/// накапливается.
pub(crate) fn replace_root(
    s: &mut Settings,
    root: &Path,
    confirm_shared: bool,
) -> Result<(), NodeError> {
    if s.receive_root != root {
        let mut next = s.clone();
        let old = std::mem::replace(&mut next.receive_root, root.to_path_buf());
        next.extra_roots.retain(|r| r != root);
        if next.extra_roots.len() + 1 >= MAX_ROOTS {
            return Err(NodeError::LimitReached);
        }
        next.extra_roots.push(old);
        *s = next;
    }
    s.shared_root_confirmed |= confirm_shared;
    Ok(())
}

fn bad<T>() -> Result<T, NodeError> {
    Err(NodeError::SettingsCorrupt)
}

/// Десятичное число без знака в каноническом виде: только цифры, без ведущих нулей.
fn parse_u64(s: &str) -> Result<u64, NodeError> {
    let digits_only = !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    let canonical = s == "0" || !s.starts_with('0');
    if !(digits_only && canonical) {
        return bad();
    }
    s.parse::<u64>().or_else(|_| bad())
}

fn parse_i64(s: &str) -> Result<i64, NodeError> {
    match s.strip_prefix('-') {
        Some(rest) => {
            // `-0` не каноническая запись нуля
            if rest == "0" {
                return bad();
            }
            let n = parse_u64(rest)?;
            i64::try_from(n).map(|v| -v).or_else(|_| {
                // i64::MIN по модулю не помещается; такие значения всё равно вне предела
                bad()
            })
        }
        None => i64::try_from(parse_u64(s)?).or_else(|_| bad()),
    }
}

fn parse_bool(s: &str) -> Result<bool, NodeError> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => bad(),
    }
}

fn parse_port(s: &str) -> Result<u16, NodeError> {
    let n = parse_u64(s)?;
    match u16::try_from(n) {
        Ok(p) if p >= 1 => Ok(p),
        _ => bad(),
    }
}

/// Путь: абсолютный, не длиннее строки, без управляющих символов (их отсекает разбор строки).
fn parse_path(s: &str) -> Result<PathBuf, NodeError> {
    let p = PathBuf::from(s);
    if s.is_empty() || !p.is_absolute() {
        return bad();
    }
    Ok(p)
}

/// Имя сервера времени: ASCII буквы, цифры, точка и дефис.
pub(crate) fn valid_ntp_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NTP_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn parse_router(s: &str) -> Result<AllowedRouter, NodeError> {
    let (udn, flag) = s.rsplit_once(';').ok_or(NodeError::SettingsCorrupt)?;
    let permanent_ok = parse_bool(flag)?;
    let id = RouterId::from_setting(udn).or_else(|_| bad())?;
    Ok(AllowedRouter { id, permanent_ok })
}

fn set_once<T>(slot: &mut Option<T>, v: T) -> Result<(), NodeError> {
    if slot.is_some() {
        return bad();
    }
    *slot = Some(v);
    Ok(())
}

/// Разбор файла. Любое отклонение даёт `SettingsCorrupt`.
pub(crate) fn parse(bytes: &[u8]) -> Result<Settings, NodeError> {
    if bytes.len() > MAX_FILE_BYTES {
        return bad();
    }
    let text = std::str::from_utf8(bytes).or_else(|_| bad())?;
    // Файл целиком заканчивается переводом строки; пустых строк нет.
    let body = text.strip_suffix('\n').ok_or(NodeError::SettingsCorrupt)?;
    let mut lines = body.split('\n');
    if lines.next() != Some(HEADER) {
        return bad();
    }
    let mut port = None;
    let mut receive_root = None;
    let mut shared = None;
    let mut min_free = None;
    let mut ttl = None;
    let mut forward = None;
    let mut offset = None;
    let mut offset_at = None;
    let mut extra_roots: Vec<PathBuf> = Vec::new();
    let mut routers: Vec<AllowedRouter> = Vec::new();
    let mut ntp: Vec<String> = Vec::new();
    for line in lines {
        if line.len() > MAX_LINE_BYTES || line.is_empty() {
            return bad();
        }
        // управляющие символы (в том числе NUL, CR, табуляция) в файле недопустимы
        if line.chars().any(|c| c.is_control()) {
            return bad();
        }
        let (key, value) = line.split_once('=').ok_or(NodeError::SettingsCorrupt)?;
        match key {
            "port" => set_once(&mut port, parse_port(value)?)?,
            "receive_root" => set_once(&mut receive_root, parse_path(value)?)?,
            "shared_root_confirmed" => set_once(&mut shared, parse_bool(value)?)?,
            "min_free_percent" => {
                let n = parse_u64(value)?;
                if n > 100 {
                    return bad();
                }
                set_once(&mut min_free, u8::try_from(n).or_else(|_| bad())?)?;
            }
            "invite_ttl_secs" => {
                let n = parse_u64(value)?;
                if !(MIN_INVITE_TTL_SECS..=MAX_INVITE_TTL_SECS).contains(&n) {
                    return bad();
                }
                set_once(&mut ttl, n)?;
            }
            "manual_forward" => set_once(&mut forward, parse_port(value)?)?,
            "clock_offset_ms" => {
                let n = parse_i64(value)?;
                if n.unsigned_abs() > MAX_CLOCK_OFFSET_MS.unsigned_abs() {
                    return bad();
                }
                set_once(&mut offset, n)?;
            }
            "clock_offset_at" => set_once(&mut offset_at, parse_u64(value)?)?,
            "extra_root" => {
                let p = parse_path(value)?;
                // повтор той же папки не копится
                if extra_roots.contains(&p) {
                    return bad();
                }
                extra_roots.push(p);
            }
            "upnp_router" => {
                let r = parse_router(value)?;
                if routers.iter().any(|x| x.id == r.id) {
                    return bad();
                }
                routers.push(r);
            }
            "ntp_server" => {
                if !valid_ntp_name(value) || ntp.iter().any(|x| x == value) {
                    return bad();
                }
                ntp.push(value.to_owned());
            }
            _ => return bad(),
        }
    }
    let receive_root = receive_root.ok_or(NodeError::SettingsCorrupt)?;
    let port = port.ok_or(NodeError::SettingsCorrupt)?;
    if 1 + extra_roots.len() > MAX_ROOTS
        || extra_roots.contains(&receive_root)
        || routers.len() > MAX_ROUTERS
        || ntp.len() > MAX_NTP_SERVERS
    {
        return bad();
    }
    Ok(Settings {
        port,
        receive_root,
        shared_root_confirmed: shared.unwrap_or(false),
        extra_roots,
        min_free_percent: min_free.unwrap_or(DEFAULT_MIN_FREE_PERCENT),
        invite_ttl_secs: ttl.unwrap_or(DEFAULT_INVITE_TTL_SECS),
        manual_forward: forward,
        routers,
        clock_offset_ms: offset.unwrap_or(0),
        clock_offset_at: offset_at.unwrap_or(0),
        ntp_servers: ntp,
    })
}

fn path_text(p: &Path) -> Result<&str, NodeError> {
    // путь не UTF-8 или с управляющим символом в файл не записать
    match p.to_str() {
        Some(s) if !s.is_empty() && !s.chars().any(|c| c.is_control()) => Ok(s),
        _ => bad(),
    }
}

/// Текст файла. Ошибка, если значение нельзя записать так, чтобы `parse` его принял.
pub(crate) fn serialize(s: &Settings) -> Result<String, NodeError> {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    let mut line = |k: &str, v: &str| {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    };
    line("port", &s.port.to_string());
    line("receive_root", path_text(&s.receive_root)?);
    line(
        "shared_root_confirmed",
        if s.shared_root_confirmed { "1" } else { "0" },
    );
    for r in &s.extra_roots {
        line("extra_root", path_text(r)?);
    }
    line("min_free_percent", &s.min_free_percent.to_string());
    line("invite_ttl_secs", &s.invite_ttl_secs.to_string());
    if let Some(p) = s.manual_forward {
        line("manual_forward", &p.to_string());
    }
    for r in &s.routers {
        line(
            "upnp_router",
            &format!("{};{}", r.id.to_setting(), u8::from(r.permanent_ok)),
        );
    }
    line("clock_offset_ms", &s.clock_offset_ms.to_string());
    line("clock_offset_at", &s.clock_offset_at.to_string());
    for n in &s.ntp_servers {
        line("ntp_server", n);
    }
    // то, что записали, должно читаться обратно тем же разбором
    if parse(out.as_bytes()).as_ref() != Ok(s) {
        return bad();
    }
    Ok(out)
}

/// Windows: `FILE_FLAG_OPEN_REPARSE_POINT` (значение 0x00200000 из winbase.h): открыть саму точку
/// повторной обработки (символьную ссылку, junction), а не то, на что она указывает.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// Windows: `FILE_ATTRIBUTE_REPARSE_POINT` (значение 0x400 из winnt.h).
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Открывает файл настроек, не следуя ссылкам и не блокируясь. Unix: `O_NOFOLLOW` (ссылка на
/// конце пути не открывается) и `O_NONBLOCK` (подставленный FIFO не повесит открытие; обычному
/// файлу флаг безразличен). Windows: открывается сама точка повторной обработки; обычный файл
/// открывается как всегда. Вид файла проверяет вызывающий по уже открытому дескриптору
/// (`is_regular_handle`).
// тип `bits()` зависит от ОС (u32 или i32): приведение нужно не везде
#[allow(clippy::unnecessary_cast, clippy::cast_possible_wrap)]
pub(crate) fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut opts,
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
    );
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut opts, FILE_FLAG_OPEN_REPARSE_POINT);
    opts.open(path)
}

/// Открытый дескриптор это обычный файл, а не ссылка, точка повторной обработки, FIFO,
/// устройство или каталог.
pub(crate) fn is_regular_handle(m: &fs::Metadata) -> bool {
    #[cfg(windows)]
    if m.file_type().is_symlink()
        || std::os::windows::fs::MetadataExt::file_attributes(m) & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return false;
    }
    m.is_file()
}

/// Читает `<dir>/settings.v1`. `Ok(None)`: файла нет. Размер проверяется до чтения.
pub(crate) fn load(dir: &Path) -> Result<Option<Settings>, NodeError> {
    let path = dir.join(FILE_NAME);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(NodeError::Io),
    };
    if !meta.file_type().is_file() || meta.len() > MAX_FILE_BYTES as u64 {
        return bad();
    }
    // один раз открываем (на Unix с O_NOFOLLOW: подмена обычного файла ссылкой между проверкой и
    // чтением не пройдёт), проверяем уже открытый файл и читаем не больше предела плюс байт
    let file = open_nofollow(&path).map_err(|_| NodeError::Io)?;
    let on_handle = file.metadata().map_err(|_| NodeError::Io)?;
    if !is_regular_handle(&on_handle) || on_handle.len() > MAX_FILE_BYTES as u64 {
        return bad();
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NodeError::Io)?;
    parse(&bytes).map(Some)
}

fn tmp_name() -> String {
    format!("{FILE_NAME}.tmp")
}

/// Атомарная запись: временный файл рядом (режим 0600), fsync, переименование, fsync каталога.
pub(crate) fn save(dir: &Path, s: &Settings) -> Result<(), NodeError> {
    let text = serialize(s)?;
    let tmp = dir.join(tmp_name());
    let target = dir.join(FILE_NAME);
    // старый временный файл (в том числе ссылка) убирается, не открывается
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(NodeError::Io),
        _ => {}
    }
    let written = (|| -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &target)?;
        #[cfg(unix)]
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(NodeError::Io);
    }
    Ok(())
}

/// Убирает испорченный файл в сторону (`settings.v1.bad-<t>`): копия остаётся у пользователя.
pub(crate) fn set_aside(dir: &Path, now_unix: u64) -> Result<(), NodeError> {
    let from = dir.join(FILE_NAME);
    let to = dir.join(format!("{FILE_NAME}.bad-{now_unix}"));
    match fs::rename(&from, &to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NodeError::Io),
    }
}

/// Точка входа для libFuzzer и `fuzz_smoke`: любой байтовый ввод не паникует; принятый файл
/// записывается и читается обратно в те же настройки.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz_settings(bytes: &[u8]) -> bool {
    let Ok(s) = parse(bytes) else {
        return false;
    };
    // принятые разбором настройки всегда записываются, и запись читается обратно в те же
    let Ok(text) = serialize(&s) else {
        panic!("accepted settings cannot be written");
    };
    let again = parse(text.as_bytes());
    assert!(again.as_ref() == Ok(&s), "parse after write differs");
    // и запись во второй раз даёт тот же текст (идемпотентность)
    if let Ok(s2) = again
        && let Ok(t2) = serialize(&s2)
    {
        assert!(t2 == text, "write after parse differs");
    }
    true
}
