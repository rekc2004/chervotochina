//! Передача файла по quinn и докачка (спайк этапа 8, только вариант B). В продукт не идёт.
//! Протокол: после аутентификации звонящий открывает управляющий bi-поток и шлёт XFER1 или HELLO1.
//! Все сообщения разбираются с проверкой длины до среза; неизвестное = ошибка, паники нет.
use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::time::{Instant, sleep, timeout};

use crate::ev;
use crate::keys::rand16;
use crate::tlsb;
use crate::util::{BoxErr, err, hex, now_ms};

pub const MAGIC: &[u8; 4] = b"CHX8";
pub const VER: u8 = 1;
pub const T_XFER: u8 = 1;
pub const T_HELLO: u8 = 2;
pub const T_RESUME: u8 = 3;
pub const T_OBS: u8 = 4;
pub const T_DONE: u8 = 5;
/// Магия (4) + версия (1) + тип (1). Спецификация даёт для XFER1 «30 Б», но по полям выходит 31.
pub const HDR_LEN: usize = 6;
pub const XFER1_LEN: usize = 31;
pub const HELLO1_LEN: usize = 6;
pub const OBS_LEN: usize = 13;
pub const DONE_LEN: usize = 14;
pub const DATA_HDR_LEN: usize = 17;
/// Лимит чтения управляющего потока вызываемым.
pub const CTRL_LIMIT: usize = 64;
pub const CTRL_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_STREAMS: u8 = 16;
/// Не больше стольких одновременно живых файлов в памяти процесса-получателя (недоверенный ввод).
pub const MAX_LIVE_FILES: usize = 4;
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XferErr {
    Len,
    Magic,
    Ver,
    Type,
    Streams,
    Size,
    Slice,
    Offset,
}

impl std::fmt::Display for XferErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for XferErr {}

// ---------------------------------------------------------------- сообщения

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xfer1 {
    pub id: [u8; 16],
    pub size: u64,
    pub streams: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctrl {
    Xfer(Xfer1),
    Hello,
}

fn hdr(t: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(MAGIC);
    v.push(VER);
    v.push(t);
    v
}

/// Проверяет магию и версию, возвращает тип. Длина не короче `HDR_LEN`.
pub fn parse_hdr(b: &[u8]) -> Result<u8, XferErr> {
    let (Some(m), Some(&v), Some(&t)) = (b.get(..4), b.get(4), b.get(5)) else {
        return Err(XferErr::Len);
    };
    if m != MAGIC {
        return Err(XferErr::Magic);
    }
    if v != VER {
        return Err(XferErr::Ver);
    }
    Ok(t)
}

/// Полная длина управляющего сообщения звонящего по первым шести байтам.
pub fn ctrl_total_len(h: &[u8]) -> Result<usize, XferErr> {
    match parse_hdr(h)? {
        T_XFER => Ok(XFER1_LEN),
        T_HELLO => Ok(HELLO1_LEN),
        _ => Err(XferErr::Type),
    }
}

pub fn enc_xfer1(x: &Xfer1) -> Vec<u8> {
    let mut v = hdr(T_XFER);
    v.extend_from_slice(&x.id);
    v.extend_from_slice(&x.size.to_be_bytes());
    v.push(x.streams);
    v
}

pub fn enc_hello1() -> Vec<u8> {
    hdr(T_HELLO)
}

/// Разбор управляющего сообщения звонящего. `size ≤ max_bytes`, `1 ≤ streams ≤ 16`.
pub fn parse_ctrl(b: &[u8], max_bytes: u64) -> Result<Ctrl, XferErr> {
    let t = parse_hdr(b)?;
    match t {
        T_HELLO => {
            if b.len() != HELLO1_LEN {
                return Err(XferErr::Len);
            }
            Ok(Ctrl::Hello)
        }
        T_XFER => {
            if b.len() != XFER1_LEN {
                return Err(XferErr::Len);
            }
            let (Some(id), Some(size), Some(&streams)) = (b.get(6..22), b.get(22..30), b.get(30)) else {
                return Err(XferErr::Len);
            };
            let id = <[u8; 16]>::try_from(id).map_err(|_| XferErr::Len)?;
            let size = u64::from_be_bytes(<[u8; 8]>::try_from(size).map_err(|_| XferErr::Len)?);
            if size > max_bytes {
                return Err(XferErr::Size);
            }
            if !(1..=MAX_STREAMS).contains(&streams) {
                return Err(XferErr::Streams);
            }
            Ok(Ctrl::Xfer(Xfer1 { id, size, streams }))
        }
        _ => Err(XferErr::Type),
    }
}

pub fn enc_resume(rec: &[u64]) -> Vec<u8> {
    let mut v = hdr(T_RESUME);
    v.push(u8::try_from(rec.len()).unwrap_or(0));
    for r in rec {
        v.extend_from_slice(&r.to_be_bytes());
    }
    v
}

/// RESUME для `n` долей: длина ровно `7 + 8n`.
pub fn parse_resume(b: &[u8], n: u8) -> Result<Vec<u64>, XferErr> {
    if parse_hdr(b)? != T_RESUME {
        return Err(XferErr::Type);
    }
    if b.len() != 7 + 8 * usize::from(n) {
        return Err(XferErr::Len);
    }
    if b.get(6) != Some(&n) {
        return Err(XferErr::Streams);
    }
    let mut out = Vec::with_capacity(usize::from(n));
    for ch in b.get(7..).ok_or(XferErr::Len)?.chunks_exact(8) {
        out.push(u64::from_be_bytes(<[u8; 8]>::try_from(ch).map_err(|_| XferErr::Len)?));
    }
    Ok(out)
}

pub fn enc_done(total: u64) -> Vec<u8> {
    let mut v = hdr(T_DONE);
    v.extend_from_slice(&total.to_be_bytes());
    v
}

pub fn parse_done(b: &[u8]) -> Result<u64, XferErr> {
    if parse_hdr(b)? != T_DONE {
        return Err(XferErr::Type);
    }
    if b.len() != DONE_LEN {
        return Err(XferErr::Len);
    }
    let t = b.get(6..14).ok_or(XferErr::Len)?;
    Ok(u64::from_be_bytes(<[u8; 8]>::try_from(t).map_err(|_| XferErr::Len)?))
}

/// OBS: только IPv4 (семейство 04). Для IPv6 `None`.
pub fn enc_obs(a: SocketAddr) -> Option<Vec<u8>> {
    let IpAddr::V4(ip) = a.ip() else {
        return None;
    };
    let mut v = hdr(T_OBS);
    v.push(4);
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&a.port().to_be_bytes());
    Some(v)
}

pub fn parse_obs(b: &[u8]) -> Result<SocketAddr, XferErr> {
    if parse_hdr(b)? != T_OBS {
        return Err(XferErr::Type);
    }
    if b.len() != OBS_LEN || b.get(6) != Some(&4) {
        return Err(XferErr::Len);
    }
    let (Some(ip), Some(port)) = (b.get(7..11), b.get(11..13)) else {
        return Err(XferErr::Len);
    };
    let ip = <[u8; 4]>::try_from(ip).map_err(|_| XferErr::Len)?;
    let port = u16::from_be_bytes(<[u8; 2]>::try_from(port).map_err(|_| XferErr::Len)?);
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
}

/// Границы доли `i` из `n` для файла `size`: `[i*size/n, (i+1)*size/n)`.
pub fn slice_bounds(size: u64, n: u8, i: u8) -> Option<(u64, u64)> {
    if n == 0 || i >= n {
        return None;
    }
    let (s, nn, ii) = (u128::from(size), u128::from(n), u128::from(i));
    let a = u64::try_from(ii * s / nn).ok()?;
    let b = u64::try_from((ii + 1) * s / nn).ok()?;
    Some((a, b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHdr {
    pub slice: u8,
    pub offset: u64,
    pub len: u64,
}

pub fn enc_data_hdr(h: &DataHdr) -> [u8; DATA_HDR_LEN] {
    let mut o = [0u8; DATA_HDR_LEN];
    o[0] = h.slice;
    o[1..9].copy_from_slice(&h.offset.to_be_bytes());
    o[9..17].copy_from_slice(&h.len.to_be_bytes());
    o
}

pub fn parse_data_hdr(b: &[u8]) -> Result<DataHdr, XferErr> {
    if b.len() != DATA_HDR_LEN {
        return Err(XferErr::Len);
    }
    let (Some(&slice), Some(off), Some(len)) = (b.first(), b.get(1..9), b.get(9..17)) else {
        return Err(XferErr::Len);
    };
    Ok(DataHdr {
        slice,
        offset: u64::from_be_bytes(<[u8; 8]>::try_from(off).map_err(|_| XferErr::Len)?),
        len: u64::from_be_bytes(<[u8; 8]>::try_from(len).map_err(|_| XferErr::Len)?),
    })
}

/// `slice < n`, `offset` = начало доли + принятое, `offset + len` (с проверкой переполнения) = конец доли.
pub fn check_data_hdr(h: &DataHdr, size: u64, n: u8, received_in_slice: u64) -> Result<(), XferErr> {
    let (start, end) = slice_bounds(size, n, h.slice).ok_or(XferErr::Slice)?;
    let want = start.checked_add(received_in_slice).ok_or(XferErr::Offset)?;
    if h.offset != want {
        return Err(XferErr::Offset);
    }
    let stop = h.offset.checked_add(h.len).ok_or(XferErr::Offset)?;
    if stop != end {
        return Err(XferErr::Offset);
    }
    Ok(())
}

// ---------------------------------------------------------------- настройки транспорта

/// Тики процесса (utime+stime) из `/proc/self/stat`, поля 14 и 15.
pub fn cpu_ticks_self() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    let Some(pos) = s.rfind(')') else {
        return 0;
    };
    let f: Vec<&str> = s.get(pos + 1..).unwrap_or("").split_whitespace().collect();
    let p = |i: usize| f.get(i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    p(11) + p(12)
}

/// W0 = умолчания quinn; W1 = поток 16 МиБ, соединение 64 МиБ, send_window 64 МиБ.
pub fn transport(win: &str, cc: &str, idle_s: u64, keepalive_s: u64) -> Result<Arc<TransportConfig>, BoxErr> {
    let mut t = TransportConfig::default();
    match win {
        "W0" => {}
        "W1" => {
            t.stream_receive_window(VarInt::from_u32(16 << 20));
            t.receive_window(VarInt::from_u32(64 << 20));
            t.send_window(64 << 20);
        }
        other => return Err(err(format!("--win: ожидается W0|W1, получено {other}"))),
    }
    match cc {
        "cubic" => {
            t.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        "bbr" => {
            t.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        other => return Err(err(format!("--cc: ожидается cubic|bbr, получено {other}"))),
    }
    if idle_s > 0 {
        let it = IdleTimeout::try_from(Duration::from_secs(idle_s)).map_err(|e| err(format!("--idle-s: {e}")))?;
        t.max_idle_timeout(Some(it));
    }
    if keepalive_s > 0 {
        t.keep_alive_interval(Some(Duration::from_secs(keepalive_s)));
    }
    Ok(Arc::new(t))
}

/// Одноразовый серверный конфиг (новый ключ Ed25519 на каждое входящее).
pub fn fresh_server_config(t: Arc<TransportConfig>) -> Result<(quinn::ServerConfig, Vec<u8>), BoxErr> {
    let issued = tlsb::ephemeral_server(false)?;
    let qc = QuicServerConfig::try_from(issued.cfg).map_err(|e| err(format!("QuicServerConfig: {e}")))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qc));
    sc.transport_config(t);
    Ok((sc, issued.spki))
}

pub fn client_config(t: Arc<TransportConfig>) -> Result<quinn::ClientConfig, BoxErr> {
    let qc = QuicClientConfig::try_from(tlsb::client_tls()?).map_err(|e| err(format!("QuicClientConfig: {e}")))?;
    let mut cc = quinn::ClientConfig::new(Arc::new(qc));
    cc.transport_config(t);
    Ok(cc)
}

// ---------------------------------------------------------------- получатель

pub struct RecvFile {
    pub id: [u8; 16],
    pub size: u64,
    pub n: u8,
    file: File,
    pub path: PathBuf,
    recv: Vec<AtomicU64>,
    active: Vec<AtomicBool>,
    total: AtomicU64,
    started: AtomicBool,
    done: AtomicBool,
    conns: AtomicU64,
    first: Mutex<Option<Instant>>,
}

impl RecvFile {
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }
    pub fn conns(&self) -> u64 {
        self.conns.load(Ordering::SeqCst)
    }
    fn per_slice(&self) -> Vec<u64> {
        self.recv.iter().map(|a| a.load(Ordering::SeqCst)).collect()
    }
}

pub struct RecvState {
    dir: PathBuf,
    max_bytes: u64,
    files: Mutex<HashMap<[u8; 16], Arc<RecvFile>>>,
}

impl RecvState {
    pub fn new(dir: &Path, max_bytes: u64) -> Self {
        Self { dir: dir.to_path_buf(), max_bytes, files: Mutex::new(HashMap::new()) }
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Находит файл по `id` или создаёт (RESUME нули). Параметры существующего должны совпасть.
    fn open(&self, x: &Xfer1) -> Result<Arc<RecvFile>, BoxErr> {
        let mut m = self.files.lock().map_err(|_| err("lock"))?;
        if let Some(f) = m.get(&x.id) {
            if f.size != x.size || f.n != x.streams {
                return Err(err("XFER1: id известен, но размер или число потоков другие"));
            }
            return Ok(f.clone());
        }
        if m.len() >= MAX_LIVE_FILES {
            return Err(err("слишком много живых передач"));
        }
        let path = self.dir.join(format!("rx-{}.bin", hex(&x.id)));
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| err(format!("создание файла: {e}")))?;
        file.set_len(x.size).map_err(|e| err(format!("set_len: {e}")))?;
        let f = Arc::new(RecvFile {
            id: x.id,
            size: x.size,
            n: x.streams,
            file,
            path,
            recv: (0..x.streams).map(|_| AtomicU64::new(0)).collect(),
            active: (0..x.streams).map(|_| AtomicBool::new(false)).collect(),
            total: AtomicU64::new(0),
            started: AtomicBool::new(false),
            done: AtomicBool::new(false),
            conns: AtomicU64::new(0),
            first: Mutex::new(None),
        });
        m.insert(x.id, f.clone());
        let tick = f.clone();
        tokio::spawn(async move {
            while !tick.done.load(Ordering::SeqCst) {
                sleep(Duration::from_millis(250)).await;
                ev!("xfer_progress", "bytes={}", tick.total());
            }
        });
        Ok(f)
    }
}

/// Снимает флаг занятости доли при выходе.
struct ActiveSlice(Arc<RecvFile>, usize);

impl Drop for ActiveSlice {
    fn drop(&mut self) {
        if let Some(a) = self.0.active.get(self.1) {
            a.store(false, Ordering::SeqCst);
        }
    }
}

fn mark_start(f: &RecvFile) {
    if f.started.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        if let Ok(mut g) = f.first.lock() {
            *g = Some(Instant::now());
        }
        ev!("cpu_ticks", "phase=start ticks={}", cpu_ticks_self());
    }
}

fn mark_done(f: &RecvFile) {
    if f.done.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        let ms = f
            .first
            .lock()
            .ok()
            .and_then(|g| g.map(|t| t.elapsed().as_millis()))
            .unwrap_or(0);
        ev!("cpu_ticks", "phase=end ticks={}", cpu_ticks_self());
        ev!("xfer_done", "bytes={} ms={ms} conns={}", f.total(), f.conns());
    }
}

async fn read_ctrl(r: &mut RecvStream) -> Result<Vec<u8>, BoxErr> {
    let mut h = [0u8; HDR_LEN];
    timeout(CTRL_TIMEOUT, r.read_exact(&mut h)).await.map_err(|_| err("ctrl: тайм-аут"))??;
    let total = ctrl_total_len(&h)?;
    if total > CTRL_LIMIT {
        return Err(err("ctrl: больше лимита"));
    }
    let mut v = h.to_vec();
    let mut rest = vec![0u8; total - HDR_LEN];
    if !rest.is_empty() {
        timeout(CTRL_TIMEOUT, r.read_exact(&mut rest)).await.map_err(|_| err("ctrl: тайм-аут"))??;
    }
    v.extend_from_slice(&rest);
    Ok(v)
}

async fn recv_data_stream(mut r: RecvStream, f: Arc<RecvFile>) -> Result<(), BoxErr> {
    let mut h = [0u8; DATA_HDR_LEN];
    timeout(CTRL_TIMEOUT, r.read_exact(&mut h)).await.map_err(|_| err("data: тайм-аут заголовка"))??;
    let h = parse_data_hdr(&h)?;
    let idx = usize::from(h.slice);
    let (Some(rec), Some(act)) = (f.recv.get(idx), f.active.get(idx)) else {
        return Err(XferErr::Slice.into());
    };
    if act.swap(true, Ordering::SeqCst) {
        return Err(err("доля уже принимается другим потоком"));
    }
    let _guard = ActiveSlice(f.clone(), idx);
    check_data_hdr(&h, f.size, f.n, rec.load(Ordering::SeqCst))?;
    mark_start(&f);
    let mut got = 0u64;
    while got < h.len {
        let Some(c) = r.read_chunk(CHUNK, true).await? else {
            return Err(err("data: поток закрыт раньше времени"));
        };
        let n = c.bytes.len() as u64;
        if got.checked_add(n).is_none_or(|g| g > h.len) {
            return Err(err("data: лишние байты"));
        }
        let at = h.offset.checked_add(got).ok_or(XferErr::Offset)?;
        f.file.write_all_at(&c.bytes, at).map_err(|e| err(format!("write_at: {e}")))?;
        got += n;
        rec.fetch_add(n, Ordering::SeqCst);
        if f.total.fetch_add(n, Ordering::SeqCst) + n == f.size {
            mark_done(&f);
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum Served {
    Hello,
    Done(u64),
    Dropped,
    Rejected(String),
}

/// Обслуживает аутентифицированное соединение на стороне вызываемого (получателя).
pub async fn serve_conn(conn: Connection, st: Arc<RecvState>) -> Served {
    let w = conn.clone();
    tokio::spawn(async move {
        let mut last = w.remote_address();
        while w.close_reason().is_none() {
            sleep(Duration::from_millis(100)).await;
            let now = w.remote_address();
            if now != last {
                ev!("peer_addr_change", "old={last} new={now}");
                last = now;
            }
        }
    });
    let (mut cs, mut cr) = match timeout(CTRL_TIMEOUT, conn.accept_bi()).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return Served::Rejected(format!("accept_bi: {e}")),
        Err(_) => {
            conn.close(VarInt::from_u32(1), b"");
            return Served::Rejected("ctrl: тайм-аут".into());
        }
    };
    let msg = match read_ctrl(&mut cr).await {
        Ok(m) => m,
        Err(e) => {
            conn.close(VarInt::from_u32(1), b"");
            return Served::Rejected(e.to_string());
        }
    };
    match parse_ctrl(&msg, st.max_bytes) {
        Ok(Ctrl::Hello) => {
            let addr = conn.remote_address();
            match enc_obs(addr) {
                Some(o) => {
                    let _ = cs.write_all(&o).await;
                    let _ = cs.finish();
                    ev!("hello_served", "peer={addr}");
                    let _ = timeout(Duration::from_secs(2), conn.closed()).await;
                    Served::Hello
                }
                None => {
                    conn.close(VarInt::from_u32(1), b"");
                    Served::Rejected("hello: не IPv4".into())
                }
            }
        }
        Ok(Ctrl::Xfer(x)) => serve_xfer(conn, cs, x, st).await,
        Err(e) => {
            conn.close(VarInt::from_u32(1), b"");
            Served::Rejected(format!("ctrl: {e}"))
        }
    }
}

async fn serve_xfer(conn: Connection, mut cs: SendStream, x: Xfer1, st: Arc<RecvState>) -> Served {
    let f = match st.open(&x) {
        Ok(f) => f,
        Err(e) => {
            conn.close(VarInt::from_u32(1), b"");
            return Served::Rejected(e.to_string());
        }
    };
    f.conns.fetch_add(1, Ordering::SeqCst);
    let rec = f.per_slice();
    ev!(
        "xfer_start",
        "id={} size={} streams={} resume_from={}",
        hex(&f.id),
        f.size,
        f.n,
        rec.iter().sum::<u64>()
    );
    if cs.write_all(&enc_resume(&rec)).await.is_err() {
        return Served::Dropped;
    }
    loop {
        if f.total() >= f.size {
            if cs.write_all(&enc_done(f.total())).await.is_err() {
                return Served::Dropped;
            }
            let _ = cs.finish();
            mark_done(&f);
            let _ = timeout(Duration::from_secs(5), conn.closed()).await;
            return Served::Done(f.total());
        }
        tokio::select! {
            r = conn.accept_uni() => match r {
                Ok(s) => {
                    let ff = f.clone();
                    let c2 = conn.clone();
                    tokio::spawn(async move {
                        if let Err(e) = recv_data_stream(s, ff).await {
                            ev!("data_stream_error", "msg={}", crate::util::q(&e.to_string()));
                            c2.close(VarInt::from_u32(2), b"");
                        }
                    });
                }
                Err(_) => return Served::Dropped,
            },
            _ = conn.closed() => return Served::Dropped,
            _ = sleep(Duration::from_millis(20)) => {}
        }
    }
}

// ---------------------------------------------------------------- отправитель

pub struct SendOpts {
    pub addrs: Vec<SocketAddr>,
    pub file: PathBuf,
    pub streams: u8,
    /// Сколько ждать нового соединения после обрыва (и первого соединения).
    pub reconnect_deadline: Duration,
    /// Тайм-аут одной попытки соединения (рукопожатие + аутентификация).
    pub attempt: Duration,
    /// Для теста: закрыть первое соединение после стольких отправленных байт.
    pub test_abort_after: Option<u64>,
}

#[derive(Debug)]
pub struct SendReport {
    pub app_bytes_sent: u64,
    pub conns: u32,
    pub size: u64,
    pub first_resume_from: u64,
    pub max_resume_from: u64,
}

async fn read_slice_task(
    conn: Connection,
    f: Arc<File>,
    slice: u8,
    from: u64,
    to: u64,
    sent: Arc<AtomicU64>,
    abort: Option<(u64, Arc<AtomicBool>)>,
) -> Result<(), BoxErr> {
    let mut s = conn.open_uni().await?;
    let h = DataHdr { slice, offset: from, len: to - from };
    s.write_all(&enc_data_hdr(&h)).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut off = from;
    while off < to {
        let n = usize::try_from(to - off).map_or(CHUNK, |r| r.min(CHUNK));
        let b = buf.get_mut(..n).ok_or_else(|| err("буфер"))?;
        f.read_exact_at(b, off)?;
        s.write_all(b).await?;
        off += n as u64;
        let total = sent.fetch_add(n as u64, Ordering::SeqCst) + n as u64;
        if let Some((lim, armed)) = &abort
            && total >= *lim
            && armed.swap(false, Ordering::SeqCst)
        {
            sleep(Duration::from_millis(300)).await;
            conn.close(VarInt::from_u32(9), b"test-abort");
            return Err(err("test: обрыв"));
        }
    }
    s.finish()?;
    Ok(())
}

enum Outcome {
    Done,
    Lost(String),
}

#[allow(clippy::too_many_arguments)]
async fn run_one(
    conn: &Connection,
    file: &Arc<File>,
    id: [u8; 16],
    size: u64,
    streams: u8,
    sent: &Arc<AtomicU64>,
    abort: &Option<(u64, Arc<AtomicBool>)>,
    first: &mut bool,
    resumes: &mut Vec<u64>,
) -> Outcome {
    let (mut cs, mut cr) = match conn.open_bi().await {
        Ok(p) => p,
        Err(e) => return Outcome::Lost(format!("open_bi: {e}")),
    };
    if let Err(e) = cs.write_all(&enc_xfer1(&Xfer1 { id, size, streams })).await {
        return Outcome::Lost(format!("xfer1: {e}"));
    }
    let want = 7 + 8 * usize::from(streams);
    let mut rb = vec![0u8; want];
    match timeout(CTRL_TIMEOUT, cr.read_exact(&mut rb)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Outcome::Lost(format!("resume: {e}")),
        Err(_) => return Outcome::Lost("resume: тайм-аут".into()),
    }
    let rec = match parse_resume(&rb, streams) {
        Ok(r) => r,
        Err(e) => return Outcome::Lost(format!("resume: {e}")),
    };
    let resume_from: u64 = rec.iter().sum();
    resumes.push(resume_from);
    ev!("xfer_start", "id={} size={size} streams={streams} resume_from={resume_from}", hex(&id));
    if *first {
        *first = false;
        ev!("cpu_ticks", "phase=start ticks={}", cpu_ticks_self());
    }
    let mut set = tokio::task::JoinSet::new();
    for (i, got) in rec.iter().enumerate() {
        let Ok(i8) = u8::try_from(i) else { continue };
        let Some((a, b)) = slice_bounds(size, streams, i8) else { continue };
        let from = a.saturating_add(*got);
        if from >= b {
            continue;
        }
        set.spawn(read_slice_task(conn.clone(), file.clone(), i8, from, b, sent.clone(), abort.clone()));
    }
    let done = async {
        let mut d = [0u8; DONE_LEN];
        match cr.read_exact(&mut d).await {
            Ok(()) => parse_done(&d).map_err(|e| format!("done: {e}")),
            Err(e) => Err(format!("done: {e}")),
        }
    };
    tokio::pin!(done);
    loop {
        tokio::select! {
            d = &mut done => {
                return match d {
                    Ok(_) => Outcome::Done,
                    Err(e) => Outcome::Lost(e),
                };
            }
            r = set.join_next(), if !set.is_empty() => {
                match r {
                    Some(Ok(Err(e))) => return Outcome::Lost(format!("slice: {e}")),
                    Some(Err(e)) => return Outcome::Lost(format!("join: {e}")),
                    _ => {}
                }
            }
            c = conn.closed() => return Outcome::Lost(format!("closed: {c}")),
        }
    }
}

/// Отправка файла с докачкой. `dial` возвращает уже аутентифицированное соединение.
pub async fn send_file<D, Fut>(dial: D, o: &SendOpts) -> Result<SendReport, BoxErr>
where
    D: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<Connection, BoxErr>>,
{
    if !(1..=MAX_STREAMS).contains(&o.streams) {
        return Err(err("--streams: 1..16"));
    }
    if o.addrs.is_empty() {
        return Err(err("нет адресов --connect"));
    }
    let file = Arc::new(File::open(&o.file).map_err(|e| err(format!("файл: {e}")))?);
    let size = file.metadata()?.len();
    let id = rand16()?;
    let sent = Arc::new(AtomicU64::new(0));
    let abort = o.test_abort_after.map(|l| (l, Arc::new(AtomicBool::new(true))));
    let mut conns = 0u32;
    let mut idx = 0usize;
    let mut deadline = Instant::now() + o.reconnect_deadline;
    let mut lost_at: Option<Instant> = None;
    let mut first = true;
    let mut resumes: Vec<u64> = Vec::new();
    loop {
        let conn = loop {
            if Instant::now() >= deadline {
                return Err(err("reconnect-deadline: соединение не восстановлено"));
            }
            let a = *o.addrs.get(idx % o.addrs.len()).ok_or_else(|| err("адрес"))?;
            idx += 1;
            let t0 = Instant::now();
            match timeout(o.attempt, dial(a)).await {
                Ok(Ok(c)) => break c,
                Ok(Err(e)) => ev!("dial_fail", "to={a} msg={}", crate::util::q(&e.to_string())),
                Err(_) => ev!("dial_fail", "to={a} msg=timeout"),
            }
            let spent = t0.elapsed();
            if spent < Duration::from_millis(500) {
                sleep(Duration::from_millis(500) - spent).await;
            }
        };
        conns += 1;
        if let Some(t) = lost_at.take() {
            ev!("reconnect", "n={} after_ms={}", conns - 1, t.elapsed().as_millis());
        }
        match run_one(&conn, &file, id, size, o.streams, &sent, &abort, &mut first, &mut resumes).await {
            Outcome::Done => {
                ev!("cpu_ticks", "phase=end ticks={}", cpu_ticks_self());
                let p = conn.stats().path;
                ev!(
                    "qstats",
                    "rtt_ms={} min_rtt_ms={} cwnd={} lost_packets={} sent_packets={} congestion_events={} mtu={}",
                    p.rtt.as_millis(),
                    conn.min_rtt().as_millis(),
                    p.cwnd,
                    p.lost_packets,
                    p.sent_packets,
                    p.congestion_events,
                    p.current_mtu
                );
                let app = sent.load(Ordering::SeqCst);
                ev!("send_done", "app_bytes_sent={app} conns={conns}");
                conn.close(VarInt::from_u32(0), b"");
                let _ = timeout(Duration::from_secs(2), conn.closed()).await;
                return Ok(SendReport {
                    app_bytes_sent: app,
                    conns,
                    size,
                    first_resume_from: resumes.first().copied().unwrap_or(0),
                    max_resume_from: resumes.iter().copied().max().unwrap_or(0),
                });
            }
            Outcome::Lost(why) => {
                ev!("conn_lost", "n={conns} t_ms={} why={}", now_ms(), crate::util::q(&why));
                conn.close(VarInt::from_u32(3), b"");
                lost_at = Some(Instant::now());
                deadline = Instant::now() + o.reconnect_deadline;
            }
        }
    }
}

/// HELLO1 → OBS: адрес звонящего, каким его видит вызываемый (G6).
pub async fn hello(conn: &Connection) -> Result<SocketAddr, BoxErr> {
    let (mut cs, mut cr) = conn.open_bi().await?;
    cs.write_all(&enc_hello1()).await?;
    let mut b = [0u8; OBS_LEN];
    timeout(CTRL_TIMEOUT, cr.read_exact(&mut b)).await.map_err(|_| err("obs: тайм-аут"))??;
    Ok(parse_obs(&b)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xfer_msg(size: u64, streams: u8) -> Vec<u8> {
        enc_xfer1(&Xfer1 { id: [7; 16], size, streams })
    }

    #[test]
    fn slices_cover_file_exactly() {
        for size in [0u64, 1, 7, (1 << 20) + 3] {
            for n in 1..=16u8 {
                let mut pos = 0u64;
                for i in 0..n {
                    let (a, b) = slice_bounds(size, n, i).expect("bounds");
                    assert_eq!(a, pos, "size={size} n={n} i={i}");
                    assert!(b >= a);
                    pos = b;
                }
                assert_eq!(pos, size, "size={size} n={n}");
                assert!(slice_bounds(size, n, n).is_none());
            }
        }
        assert!(slice_bounds(10, 0, 0).is_none());
    }

    #[test]
    fn xfer_rejects_bad_slice() {
        // slice >= n отвергается, как и неверное число потоков и обрезанные сообщения.
        let h = DataHdr { slice: 4, offset: 0, len: 10 };
        assert_eq!(check_data_hdr(&h, 100, 4, 0), Err(XferErr::Slice));
        let ok = DataHdr { slice: 3, offset: 75, len: 25 };
        assert_eq!(check_data_hdr(&ok, 100, 4, 0), Ok(()));
        assert_eq!(parse_ctrl(&xfer_msg(100, 0), 1000), Err(XferErr::Streams));
        assert_eq!(parse_ctrl(&xfer_msg(100, 17), 1000), Err(XferErr::Streams));
        assert_eq!(parse_ctrl(&xfer_msg(100, 16), 1000).map(|_| ()), Ok(()));
        let m = xfer_msg(100, 2);
        for n in 0..m.len() {
            assert!(parse_ctrl(&m[..n], 1000).is_err(), "n={n}");
        }
        let mut long = m.clone();
        long.push(0);
        assert_eq!(parse_ctrl(&long, 1000), Err(XferErr::Len));
        let mut bad = m.clone();
        bad[0] = b'X';
        assert_eq!(parse_ctrl(&bad, 1000), Err(XferErr::Magic));
        let mut bad = m.clone();
        bad[4] = 2;
        assert_eq!(parse_ctrl(&bad, 1000), Err(XferErr::Ver));
        let mut bad = m;
        bad[5] = 9;
        assert_eq!(parse_ctrl(&bad, 1000), Err(XferErr::Type));
        let bad_hdr = enc_data_hdr(&ok);
        assert!(parse_data_hdr(&bad_hdr[..16]).is_err());
    }

    #[test]
    fn xfer_rejects_offset_overflow() {
        // offset + len переполняет u64.
        let h = DataHdr { slice: 0, offset: u64::MAX - 5, len: 10 };
        assert_eq!(check_data_hdr(&h, 100, 1, 0), Err(XferErr::Offset));
        // received_in_slice переполняет начало доли.
        let h = DataHdr { slice: 1, offset: 50, len: 50 };
        assert_eq!(check_data_hdr(&h, 100, 2, u64::MAX), Err(XferErr::Offset));
        // offset не равен началу + принятое.
        let h = DataHdr { slice: 1, offset: 51, len: 49 };
        assert_eq!(check_data_hdr(&h, 100, 2, 0), Err(XferErr::Offset));
        // конец не равен концу доли.
        let h = DataHdr { slice: 1, offset: 50, len: 51 };
        assert_eq!(check_data_hdr(&h, 100, 2, 0), Err(XferErr::Offset));
        let h = DataHdr { slice: 1, offset: 60, len: 40 };
        assert_eq!(check_data_hdr(&h, 100, 2, 10), Ok(()));
    }

    #[test]
    fn xfer_rejects_size_over_max() {
        assert_eq!(parse_ctrl(&xfer_msg(1001, 1), 1000), Err(XferErr::Size));
        assert!(parse_ctrl(&xfer_msg(1000, 1), 1000).is_ok());
        assert_eq!(parse_ctrl(&xfer_msg(u64::MAX, 1), 1000), Err(XferErr::Size));
    }

    #[test]
    fn xfer_resume_roundtrip() {
        let r = vec![0u64, 5, u64::MAX, 1 << 40];
        let b = enc_resume(&r);
        assert_eq!(b.len(), 7 + 8 * r.len());
        assert_eq!(parse_resume(&b, 4), Ok(r));
        assert_eq!(parse_resume(&b, 3), Err(XferErr::Len));
        assert!(parse_resume(&b[..b.len() - 1], 4).is_err());
        assert_eq!(parse_done(&enc_done(77)), Ok(77));
        assert!(parse_done(&enc_done(77)[..13]).is_err());
        let a: SocketAddr = "198.51.100.10:4433".parse().expect("addr");
        assert_eq!(enc_obs(a).as_deref().map(parse_obs), Some(Ok(a)));
        assert_eq!(enc_obs(a).map(|v| v.len()), Some(OBS_LEN));
        assert!(enc_obs("[::1]:1".parse().expect("v6")).is_none());
    }

    fn pseudo(len: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Обрыв посреди передачи (отправитель закрывает соединение), докачка по RESUME, байты равны.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn xfer_loopback_resume_after_drop() {
        let dir = std::env::temp_dir().join(format!("chv8-xfer-test-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).expect("dir");
        let src = dir.join("src.bin");
        let data = pseudo(3 * 1024 * 1024 + 13);
        std::fs::write(&src, &data).expect("write src");
        let st = Arc::new(RecvState::new(&dir, 64 << 20));
        let t = transport("W0", "cubic", 5, 0).expect("transport");
        let (base, _) = fresh_server_config(t.clone()).expect("server cfg");
        let sep = quinn::Endpoint::server(base, "127.0.0.1:0".parse().expect("addr")).expect("server");
        let addr = sep.local_addr().expect("local addr");
        let st2 = st.clone();
        let t2 = t.clone();
        let server = tokio::spawn(async move {
            while let Some(inc) = sep.accept().await {
                let Ok((sc, _)) = fresh_server_config(t2.clone()) else { continue };
                let Ok(c) = inc.accept_with(Arc::new(sc)) else { continue };
                let Ok(conn) = c.await else { continue };
                if let Served::Done(_) = serve_conn(conn, st2.clone()).await {
                    break;
                }
            }
        });
        let cep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client");
        let cc = client_config(t).expect("client cfg");
        let dial = |a: SocketAddr| {
            let ep = cep.clone();
            let cc = cc.clone();
            async move {
                let c = ep.connect_with(cc, a, tlsb::SERVER_NAME)?.await?;
                Ok::<Connection, BoxErr>(c)
            }
        };
        let o = SendOpts {
            addrs: vec![addr],
            file: src.clone(),
            streams: 3,
            reconnect_deadline: Duration::from_secs(15),
            attempt: Duration::from_secs(3),
            test_abort_after: Some(1 << 20),
        };
        let rep = send_file(dial, &o).await.expect("send");
        let _ = timeout(Duration::from_secs(5), server).await;
        assert!(rep.conns >= 2, "ожидалась докачка, conns={}", rep.conns);
        assert!(rep.max_resume_from > 0, "RESUME должен быть ненулевым");
        assert!(rep.app_bytes_sent >= rep.size);
        let rx: Vec<PathBuf> = std::fs::read_dir(&dir)
            .expect("ls")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("rx-")))
            .collect();
        assert_eq!(rx.len(), 1);
        let got = std::fs::read(&rx[0]).expect("read rx");
        assert_eq!(got.len(), data.len());
        assert!(got == data, "байты расходятся");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
