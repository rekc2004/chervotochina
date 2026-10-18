//! Узел стенда этапа 16 (`tools/netns/stage16.sh`) и ручной проверки на двух процессах:
//! `node14` (передача файлов) плюс метки друзей, UPnP, ручной токен адреса `CHA1`, диагноз и
//! замер CPU. Настоящий `QuinnTransport`, движок `chervo-connect` и `chervo-transfer` в одном
//! процессе. Только для стенда и ручной проверки, не для работы с настоящими ключами.
//!
//! Ключи пар и ключ списка лежат в простых файлах каталога `--book-dir/keys` (без защиты ОС):
//! иначе нельзя перезапустить процесс с теми же друзьями. Пары, созданные здесь, одноразовые
//! для стенда: каталог `--book-dir` удалить после использования.
//!
//! Метки: друг, созданный k-м `--invite-out`, зовётся `o<k>`, k-м `--invite-in` зовётся `i<k>`
//! (k с единицы); соответствие хранится в `BOOKDIR/labels` (режим 600), переживает перезапуск.
//! Вывод: одна строка на событие, в конце каждой `t=<мс с запуска>`. Идентификаторы пар, SAS,
//! тексты токенов и приглашений и имена файлов не печатаются. Адреса печатает только строка
//! `STATE` (журналы стенда, в репозиторий не попадают).
//!
//! Аргументы как у `node14` (`--port`, `--book-dir`, `--invite-out`, `--invite-in`,
//! `--invite-addr`, `--sas-auto-confirm`, `--send`, `--dest`, `--partial`, `--accept`,
//! `--hash-sources`, `--streams`, `--window`, `--expect-connected`, `--expect-complete`,
//! `--deadline`, `--hold`) и новые: `--invite-lan` (в приглашение адреса своей сети),
//! `--udp-window S` (окно эвристики «UDP закрыт»), `--upnp-router UDN` (подключить UPnP с этим
//! роутером, подтверждённым пользователем), `--token-to L --token-out F [--token-lan]` (когда
//! появляется файл `F.go`: удалить его и выпустить токен для друга `L` в файл `F`, затем
//! `connect_now`), `--token-in F` (при каждом изменении содержимого `F` применить токен, затем
//! `connect_now`), `--send-to L` (получатель для `--send`), `--stop-file F` (чистое завершение,
//! когда файл есть), `--diag-every S` (период строк `DIAG`, по умолчанию 5).
//! Выход: 0 — ожидание выполнено или остановка по файлу, 1 — нет, 2 — ошибка запуска или
//! аргументов.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::PortMapper;
use chervo_connect::{
    AllowSet, Clock, ConnectConfig, ConnectError, Engine, EngineEvent, InviteAddrs, RouteProbe,
    SystemClock, SystemProbe,
};
use chervo_friends::{FriendBook, FriendState};
use chervo_identity::{IdentityError, ListKeyStore, PairId, SecretStore};
use chervo_transfer::{
    AskAlways, GeneratedNames, SourceFile, TransferConfig, TransferEvent, TransferKey, Transfers,
    state_dir_name,
};
use chervo_transport::{PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use chervo_upnp::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings};
use tokio::time::{Instant, MissedTickBehavior, interval};
use zeroize::Zeroizing;

/// Сколько секунд повторять выпуск токена при `NoAddresses` (наблюдения друзей могут не успеть).
const TOKEN_RETRY_SECS: u64 = 30;
/// Предел читаемого из файла токена: токен короче 400 байт, всё сверх этого движок отвергает.
const TOKEN_FILE_READ_CAP: u64 = 4096;

/// Хранилище ключей в файлах каталога: только для этого примера.
struct FileStore {
    dir: PathBuf,
    // сериализует записи внутри процесса
    lock: Mutex<()>,
}

impl FileStore {
    fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn pair_path(&self, pair: &PairId) -> PathBuf {
        self.dir.join(format!("pair-{}", hex(pair.as_bytes())))
    }

    fn list_path(&self) -> PathBuf {
        self.dir.join("list-key")
    }
}

fn read_opt(p: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
    match std::fs::read(p) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(IdentityError::StorageUnavailable),
    }
}

fn write_atomic_bytes(p: &Path, data: &[u8]) -> Result<(), IdentityError> {
    let mut tmp = p.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, data).map_err(|_| IdentityError::StorageUnavailable)?;
    std::fs::rename(&tmp, p).map_err(|_| IdentityError::StorageUnavailable)
}

fn remove_opt(p: &Path) -> Result<(), IdentityError> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IdentityError::StorageUnavailable),
    }
}

impl SecretStore for FileStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        read_opt(&self.pair_path(pair))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic_bytes(&self.pair_path(pair), blob)
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        remove_opt(&self.pair_path(pair))
    }
}

impl ListKeyStore for FileStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        read_opt(&self.list_path())
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic_bytes(&self.list_path(), key)
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        remove_opt(&self.list_path())
    }
}

struct Args {
    port: u16,
    book_dir: PathBuf,
    invite_out: Vec<PathBuf>,
    invite_in: Vec<PathBuf>,
    invite_addr: Option<SocketAddr>,
    invite_lan: bool,
    auto_confirm: bool,
    send: Vec<PathBuf>,
    send_to: Option<String>,
    dest: Option<PathBuf>,
    partial: Option<PathBuf>,
    accept: bool,
    hash_sources: bool,
    streams: Option<u8>,
    window: Option<u8>,
    udp_window: Option<u64>,
    upnp_router: Option<String>,
    token_to: Option<String>,
    token_out: Option<PathBuf>,
    token_lan: bool,
    token_in: Option<PathBuf>,
    stop_file: Option<PathBuf>,
    diag_every: Duration,
    expect_connected: usize,
    expect_complete: usize,
    deadline: Duration,
    hold: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        port: 4433,
        book_dir: PathBuf::new(),
        invite_out: Vec::new(),
        invite_in: Vec::new(),
        invite_addr: None,
        invite_lan: false,
        auto_confirm: false,
        send: Vec::new(),
        send_to: None,
        dest: None,
        partial: None,
        accept: false,
        hash_sources: false,
        streams: None,
        window: None,
        udp_window: None,
        upnp_router: None,
        token_to: None,
        token_out: None,
        token_lan: false,
        token_in: None,
        stop_file: None,
        diag_every: Duration::from_secs(5),
        expect_connected: 0,
        expect_complete: 0,
        deadline: Duration::from_secs(120),
        hold: Duration::ZERO,
    };
    let mut it = std::env::args().skip(1).peekable();
    while let Some(k) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name}: no value"));
        match k.as_str() {
            "--port" => a.port = val("--port")?.parse().map_err(|_| "--port")?,
            "--book-dir" => a.book_dir = PathBuf::from(val("--book-dir")?),
            "--invite-out" => a.invite_out.push(PathBuf::from(val("--invite-out")?)),
            "--invite-in" => a.invite_in.push(PathBuf::from(val("--invite-in")?)),
            "--invite-addr" => {
                a.invite_addr = Some(val("--invite-addr")?.parse().map_err(|_| "--invite-addr")?);
            }
            "--invite-lan" => a.invite_lan = true,
            "--sas-auto-confirm" => a.auto_confirm = true,
            "--send" => {
                // все следующие аргументы до очередного `--флага` это файлы
                while let Some(next) = it.peek() {
                    if next.starts_with("--") {
                        break;
                    }
                    a.send.push(PathBuf::from(it.next().unwrap_or_default()));
                }
                if a.send.is_empty() {
                    return Err("--send: no files".to_owned());
                }
            }
            "--send-to" => a.send_to = Some(val("--send-to")?),
            "--dest" => a.dest = Some(PathBuf::from(val("--dest")?)),
            "--partial" => a.partial = Some(PathBuf::from(val("--partial")?)),
            "--accept" => a.accept = true,
            "--hash-sources" => a.hash_sources = true,
            "--streams" => a.streams = Some(val("--streams")?.parse().map_err(|_| "--streams")?),
            "--window" => a.window = Some(val("--window")?.parse().map_err(|_| "--window")?),
            "--udp-window" => {
                a.udp_window = Some(val("--udp-window")?.parse().map_err(|_| "--udp-window")?);
            }
            "--upnp-router" => a.upnp_router = Some(val("--upnp-router")?),
            "--token-to" => a.token_to = Some(val("--token-to")?),
            "--token-out" => a.token_out = Some(PathBuf::from(val("--token-out")?)),
            "--token-lan" => a.token_lan = true,
            "--token-in" => a.token_in = Some(PathBuf::from(val("--token-in")?)),
            "--stop-file" => a.stop_file = Some(PathBuf::from(val("--stop-file")?)),
            "--diag-every" => {
                let s: u64 = val("--diag-every")?.parse().map_err(|_| "--diag-every")?;
                a.diag_every = Duration::from_secs(s.max(1));
            }
            "--expect-connected" => {
                a.expect_connected = val("--expect-connected")?
                    .parse()
                    .map_err(|_| "--expect-connected")?;
            }
            "--expect-complete" => {
                a.expect_complete = val("--expect-complete")?
                    .parse()
                    .map_err(|_| "--expect-complete")?;
            }
            "--deadline" => {
                a.deadline =
                    Duration::from_secs(val("--deadline")?.parse().map_err(|_| "--deadline")?);
            }
            "--hold" => a.hold = Duration::from_secs(val("--hold")?.parse().map_err(|_| "--hold")?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.book_dir.as_os_str().is_empty() {
        return Err("--book-dir is required".to_owned());
    }
    if a.token_to.is_some() != a.token_out.is_some() {
        return Err("--token-to and --token-out go together".to_owned());
    }
    if a.token_lan && a.token_out.is_none() {
        return Err("--token-lan needs --token-out".to_owned());
    }
    Ok(a)
}

type Eng = Engine<QuinnTransport, FileStore>;

/// Строка вывода: текст и `t=<мс с запуска>` в конце.
macro_rules! out {
    ($t0:expr, $($arg:tt)*) => {{
        println!("{} t={}", format_args!($($arg)*), $t0.elapsed().as_millis());
    }};
}

/// Запись файла атомарно (временный файл и переименование), режим 600 там, где он есть.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex_pair(s: &str) -> Option<PairId> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(PairId::from_bytes(out))
}

/// SHA-256 файла (потоком) и его размер.
fn sha256_file(p: &Path) -> std::io::Result<(String, u64)> {
    let mut f = std::fs::File::open(p)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(ctx.finish().as_ref()), total))
}

/// Тики процессора (utime + stime) из `/proc/self/stat`; поля 14 и 15 считаются после
/// последней `)` (имя процесса может содержать пробелы и скобки). Не Linux: `None`.
fn cpu_ticks() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = s.get(s.rfind(')')?.checked_add(1)?..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    // после `)` первое поле это состояние (поле 3), поэтому utime имеет индекс 11, stime 12
    let user: u64 = f.get(11)?.parse().ok()?;
    let sys: u64 = f.get(12)?.parse().ok()?;
    user.checked_add(sys)
}

fn print_cpu(t0: Instant, phase: &str) {
    if let Some(ticks) = cpu_ticks() {
        out!(t0, "EVENT cpu phase={phase} ticks={ticks}");
    }
}

/// Метки друзей: пара -> метка, файл `BOOKDIR/labels` (`<hex пары> <метка>` в строке).
struct Labels {
    path: PathBuf,
    map: Vec<(PairId, String)>,
}

impl Labels {
    fn load(path: PathBuf) -> Self {
        let mut map = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some((h, l)) = line.split_once(' ')
                    && let Some(p) = unhex_pair(h)
                    && !l.is_empty()
                {
                    map.push((p, l.to_owned()));
                }
            }
        }
        Self { path, map }
    }

    fn label(&self, pair: &PairId) -> String {
        self.map
            .iter()
            .find(|(p, _)| p == pair)
            .map_or_else(|| "?".to_owned(), |(_, l)| l.clone())
    }

    fn pair_of(&self, label: &str) -> Option<PairId> {
        self.map.iter().find(|(_, l)| l == label).map(|(p, _)| *p)
    }

    /// Новая метка; прежняя запись с той же меткой или той же парой заменяется.
    fn set(&mut self, pair: PairId, label: String) {
        self.map.retain(|(p, l)| *p != pair && *l != label);
        self.map.push((pair, label));
        let text: String = self
            .map
            .iter()
            .map(|(p, l)| format!("{} {l}\n", hex(p.as_bytes())))
            .collect();
        let _ = write_private(&self.path, &text);
    }
}

/// Содержимое файла токена (не больше `TOKEN_FILE_READ_CAP` байт); `None`: нет файла или пуст.
fn read_token_file(p: &Path) -> Option<String> {
    let f = std::fs::File::open(p).ok()?;
    let mut s = String::new();
    f.take(TOKEN_FILE_READ_CAP).read_to_string(&mut s).ok()?;
    (!s.trim().is_empty()).then_some(s)
}

/// Рядом с `F` лежит сигнал `F.go`.
fn go_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".go");
    PathBuf::from(s)
}

/// Активные друзья и их известные адреса: только для строки `STATE` и выбора получателя.
fn active_friends(engine: &Eng) -> Vec<(PairId, Vec<SocketAddr>)> {
    engine.read_book(|b| {
        b.friends()
            .iter()
            .filter(|f| f.state == FriendState::Active)
            .map(|f| (f.pair, f.known_addrs.iter().map(|k| k.addr).collect()))
            .collect()
    })
}

struct TokenJob {
    since: Instant,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("node16: {e}");
            return ExitCode::from(2);
        }
    };
    if std::fs::create_dir_all(&args.book_dir).is_err() {
        eprintln!("node16: book dir");
        return ExitCode::from(2);
    }
    let Ok(store) = FileStore::new(args.book_dir.join("keys")).map(Arc::new) else {
        eprintln!("node16: key dir");
        return ExitCode::from(2);
    };
    let Ok(book) = FriendBook::open(&args.book_dir.join("friends.chfl"), &*store) else {
        eprintln!("node16: book");
        return ExitCode::from(2);
    };
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let Ok(transport) = QuinnTransport::bind(
        SocketAddr::from(([0, 0, 0, 0], args.port)),
        QuinnConfig::default(),
        filter,
    )
    .map(Arc::new) else {
        eprintln!("node16: bind");
        return ExitCode::from(2);
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(SystemProbe);
    let mut cfg = ConnectConfig::default();
    if let Some(s) = args.udp_window {
        cfg.udp_blocked_window = Duration::from_secs(s);
    }
    let started = Engine::start(transport.clone(), allow, book, store, clock, probe, cfg);
    let Ok((engine, mut events)) = started else {
        eprintln!("node16: engine");
        return ExitCode::from(2);
    };
    let engine: Arc<Eng> = Arc::new(engine);
    // UPnP: только роутер, названный пользователем (UDN), других нет
    let mapper: Option<Arc<UpnpMapper>> = match args.upnp_router.as_deref() {
        None => None,
        Some(udn) => {
            let Ok(id) = RouterId::from_setting(udn) else {
                eprintln!("node16: upnp router");
                return ExitCode::from(2);
            };
            let m = Arc::new(UpnpMapper::new(UpnpSettings {
                routers: vec![AllowedRouter {
                    id,
                    permanent_ok: false,
                }],
            }));
            let dynamic: Arc<dyn PortMapper> = m.clone();
            if engine.attach_mapper(dynamic).is_err() {
                eprintln!("node16: attach mapper");
                return ExitCode::from(2);
            }
            Some(m)
        }
    };
    let Ok(inbox) = engine.stream_inbox(&[
        chervo_transfer::STREAM_TRANSFER_CTL,
        chervo_transfer::STREAM_TRANSFER_DATA,
    ]) else {
        eprintln!("node16: inbox");
        return ExitCode::from(2);
    };
    // приём возможен только с `--dest`; без него каталоги временных данных не создаются
    let dest = args
        .dest
        .clone()
        .unwrap_or_else(|| args.book_dir.join("dest"));
    let partial = args
        .partial
        .clone()
        .unwrap_or_else(|| dest.join("chervo-partial"));
    if std::fs::create_dir_all(&dest).is_err() || std::fs::create_dir_all(&partial).is_err() {
        eprintln!("node16: dest or partial dir");
        return ExitCode::from(2);
    }
    let (Ok(dest_abs), Ok(partial_abs)) = (
        std::fs::canonicalize(&dest),
        std::fs::canonicalize(&partial),
    ) else {
        eprintln!("node16: dir path");
        return ExitCode::from(2);
    };
    let mut tcfg = TransferConfig::new(partial_abs);
    if let Some(s) = args.streams {
        tcfg.streams = s;
    }
    if let Some(w) = args.window {
        tcfg.per_stream_window = w;
    }
    tcfg.progress_interval = Duration::from_secs(1);
    let placement = Arc::new(GeneratedNames {
        dest_dir: dest_abs.clone(),
    });
    let Ok((transfers, mut tevents)) =
        Transfers::start(engine.clone(), inbox, Arc::new(AskAlways), placement, tcfg)
    else {
        eprintln!("node16: transfers");
        return ExitCode::from(2);
    };

    let t0 = Instant::now();
    out!(
        t0,
        "EVENT started listen_port={}",
        transport.local_addrs().first().map_or(0, SocketAddr::port)
    );

    let give_up = t0 + args.deadline;
    let mut labels = Labels::load(args.book_dir.join("labels"));
    let mut connected: HashSet<PairId> = HashSet::new();
    let mut in_next = 0usize;
    let mut out_next = 0usize;
    let mut sent = args.send.is_empty();
    let mut completes = 0usize;
    // принятые предложения: пара ключа -> размер; начало приёма для `RESULT xfer`
    let mut offers: HashMap<TransferKey, u64> = HashMap::new();
    let mut recv_started: HashMap<TransferKey, Instant> = HashMap::new();
    let mut met_at: Option<Instant> = None;
    let mut token_job: Option<TokenJob> = None;
    let mut token_in_last: Option<String> = None;
    let mut last_state = Instant::now() - Duration::from_secs(60);
    let mut last_diag = Instant::now();
    let mut tick = interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let code: u8 = loop {
        let mut stop_requested = false;
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break 1 };
                match ev {
                    EngineEvent::Connected { pair, path } => {
                        connected.insert(pair);
                        out!(t0, "EVENT connected pair={} path={path:?}", labels.label(&pair));
                    }
                    EngineEvent::Disconnected { pair } => {
                        connected.remove(&pair);
                        out!(t0, "EVENT disconnected pair={}", labels.label(&pair));
                    }
                    EngineEvent::SasReady { pair, .. } => {
                        out!(t0, "EVENT sas_ready pair={}", labels.label(&pair));
                        if args.auto_confirm {
                            let r = engine.confirm_sas(&pair, true, "peer");
                            out!(t0, "EVENT sas_confirmed ok={}", r.is_ok());
                        }
                    }
                    EngineEvent::InviteFinished { pair, outcome } => {
                        out!(t0, "EVENT invite_finished pair={} outcome={outcome:?}", labels.label(&pair));
                    }
                    EngineEvent::Unreachable { pair, diagnosis } => {
                        out!(
                            t0,
                            "EVENT unreachable pair={} reason={:?} rendezvous_could_help={}",
                            labels.label(&pair),
                            diagnosis.reason,
                            diagnosis.rendezvous_could_help
                        );
                    }
                    _ => {}
                }
            }
            te = tevents.recv() => {
                let Some(te) = te else { break 1 };
                match te {
                    TransferEvent::OfferReceived { key } => {
                        let view = transfers.offer(&key);
                        let total = view.as_ref().map_or(0, |v| v.total_size);
                        out!(
                            t0,
                            "EVENT offer_received files={} total={total}",
                            view.as_ref().map_or(0, |v| v.files.len())
                        );
                        let r = transfers.respond(&key, args.accept);
                        out!(t0, "EVENT offer_answered accepted={} ok={}", args.accept, r.is_ok());
                        offers.insert(key, total);
                    }
                    TransferEvent::Started { key } => {
                        print_cpu(t0, "start");
                        if offers.contains_key(&key) {
                            recv_started.insert(key, Instant::now());
                        }
                        out!(t0, "EVENT started_transfer");
                    }
                    TransferEvent::Progress { done, total, .. } => {
                        out!(t0, "EVENT progress done={done} total={total}");
                    }
                    TransferEvent::Verifying { .. } => out!(t0, "EVENT verifying"),
                    TransferEvent::FileReceived { key, index } => {
                        // имя итогового файла: сгенерированное, без недоверенных байт
                        let name = format!("chervo-{}-{index}", state_dir_name(&key.pair, &key.id));
                        let p = dest_abs.join(name);
                        let r = tokio::task::spawn_blocking(move || sha256_file(&p)).await;
                        match r {
                            Ok(Ok((h, n))) => out!(t0, "RESULT received index={index} size={n} sha256={h}"),
                            _ => out!(t0, "RESULT received index={index} hash_failed"),
                        }
                    }
                    TransferEvent::FileDelivered { index, .. } => out!(t0, "EVENT file_delivered index={index}"),
                    TransferEvent::FileFailed { index, reason, .. } => {
                        out!(t0, "EVENT file_failed index={index} reason={reason:?}");
                    }
                    TransferEvent::Paused { reason, .. } => out!(t0, "EVENT paused reason={reason:?}"),
                    TransferEvent::Resumed { .. } => out!(t0, "EVENT resumed"),
                    TransferEvent::Completed { key } => {
                        print_cpu(t0, "end");
                        completes += 1;
                        // приёмник: от начала до конца, с итоговой проверкой всего файла
                        if let (Some(total), Some(at)) = (offers.get(&key), recv_started.remove(&key)) {
                            out!(t0, "RESULT xfer bytes={total} ms={}", at.elapsed().as_millis());
                        }
                        out!(t0, "EVENT completed n={completes}");
                    }
                    TransferEvent::Cancelled { by, .. } => out!(t0, "EVENT cancelled by={by:?}"),
                    TransferEvent::Failed { reason, .. } => out!(t0, "EVENT failed reason={reason:?}"),
                    _ => {}
                }
            }
            _ = tick.tick() => {
                if args.stop_file.as_deref().is_some_and(Path::exists) {
                    stop_requested = true;
                }
                if let Some(path) = args.invite_in.get(in_next)
                    && let Some(text) = std::fs::read_to_string(path).ok().filter(|t| !t.trim().is_empty())
                {
                    match engine.accept_invite(text.trim()) {
                        Ok(p) => {
                            labels.set(p, format!("i{}", in_next + 1));
                            out!(t0, "EVENT invite_accepted pair={}", labels.label(&p));
                        }
                        Err(e) => out!(t0, "EVENT invite_accept_failed error={e}"),
                    }
                    in_next += 1;
                }
                if let Some(path) = args.invite_out.get(out_next) {
                    let addrs = match args.invite_addr {
                        Some(a) => InviteAddrs::Manual(vec![a]),
                        None => InviteAddrs::Auto { same_network: args.invite_lan },
                    };
                    match engine.create_invite(900, addrs) {
                        Ok((p, text)) => {
                            labels.set(p, format!("o{}", out_next + 1));
                            let ok = write_private(path, &text).is_ok();
                            out!(t0, "EVENT invite_issued pair={} written={ok}", labels.label(&p));
                            out_next += 1;
                        }
                        Err(ConnectError::NoAddresses) => {}
                        Err(e) => {
                            out!(t0, "EVENT invite_issue_failed error={e}");
                            out_next += 1;
                        }
                    }
                }
                // отправка: названному другу или единственному активному, когда соединение есть
                if !sent {
                    let friend = match args.send_to.as_deref() {
                        Some(l) => labels.pair_of(l),
                        None => active_friends(&engine).first().map(|f| f.0),
                    };
                    if let Some(pair) = friend && connected.contains(&pair) {
                        if args.hash_sources {
                            for (i, p) in args.send.iter().enumerate() {
                                match sha256_file(p) {
                                    Ok((h, n)) => out!(t0, "RESULT source index={i} size={n} sha256={h}"),
                                    Err(_) => out!(t0, "RESULT source index={i} hash_failed"),
                                }
                            }
                        }
                        let files: Vec<SourceFile> = args
                            .send
                            .iter()
                            .enumerate()
                            .map(|(i, p)| SourceFile { path: p.clone(), name: format!("file{i}") })
                            .collect();
                        match transfers.send(&pair, files) {
                            Ok(_) => out!(t0, "EVENT send_started files={}", args.send.len()),
                            Err(e) => out!(t0, "EVENT send_failed error={e}"),
                        }
                        sent = true;
                    }
                }
                // выпуск токена адреса для друга: по сигналу `F.go`
                if let (Some(label), Some(file)) = (args.token_to.as_deref(), args.token_out.as_deref()) {
                    if token_job.is_none() {
                        let go = go_path(file);
                        if go.exists() && std::fs::remove_file(&go).is_ok() {
                            token_job = Some(TokenJob { since: Instant::now() });
                        }
                    }
                    if let Some(job) = &token_job {
                        let mut done = false;
                        match labels.pair_of(label) {
                            None => {
                                out!(t0, "EVENT token_failed to={label} error=UnknownLabel");
                                done = true;
                            }
                            Some(pair) => match engine.issue_addr_update_text(&pair, args.token_lan) {
                                Ok(text) => {
                                    if write_private(file, &text).is_ok() {
                                        out!(t0, "EVENT token_issued to={label}");
                                        let _ = engine.connect_now(&pair);
                                    } else {
                                        out!(t0, "EVENT token_failed to={label} error=WriteFailed");
                                    }
                                    done = true;
                                }
                                Err(ConnectError::NoAddresses)
                                    if job.since.elapsed() < Duration::from_secs(TOKEN_RETRY_SECS) => {}
                                Err(e) => {
                                    out!(t0, "EVENT token_failed to={label} error={e:?}");
                                    done = true;
                                }
                            },
                        }
                        if done {
                            token_job = None;
                        }
                    }
                }
                // применение токена от друга: при каждом изменении содержимого `F`
                if let Some(file) = args.token_in.as_deref()
                    && let Some(text) = read_token_file(file)
                    && token_in_last.as_deref() != Some(text.as_str())
                {
                    match engine.apply_addr_update_text(&text) {
                        Ok(pair) => {
                            out!(t0, "EVENT token_applied pair={}", labels.label(&pair));
                            let _ = engine.connect_now(&pair);
                        }
                        Err(e) => out!(t0, "EVENT token_rejected error={e:?}"),
                    }
                    token_in_last = Some(text);
                }
                // состояние и диагноз
                if last_state.elapsed() >= Duration::from_secs(2) {
                    last_state = Instant::now();
                    let mut line = format!(
                        "STATE connected={} nat_view={:?} mapping={}",
                        connected.len(),
                        engine.nat_view(),
                        engine.mapping_status().map_or_else(|| "none".to_owned(), |m| format!("{m:?}"))
                    );
                    for (pair, addrs) in active_friends(&engine) {
                        let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                        line.push_str(&format!(" friend:{}=[{}]", labels.label(&pair), list.join(",")));
                    }
                    out!(t0, "{line}");
                }
                if last_diag.elapsed() >= args.diag_every {
                    last_diag = Instant::now();
                    for (pair, _) in active_friends(&engine) {
                        if let Ok(d) = engine.diagnose(&pair) {
                            let (reason, help) = d.map_or_else(
                                || ("none".to_owned(), false),
                                |d| (format!("{:?}", d.reason), d.rendezvous_could_help),
                            );
                            out!(
                                t0,
                                "DIAG pair={} reason={reason} rendezvous_could_help={help}",
                                labels.label(&pair)
                            );
                        }
                    }
                }
            }
        }
        let ready = in_next >= args.invite_in.len()
            && out_next >= args.invite_out.len()
            && connected.len() >= args.expect_connected
            && completes >= args.expect_complete
            && sent;
        if ready && met_at.is_none() {
            met_at = Some(Instant::now());
            out!(
                t0,
                "RESULT ok connected={} completed={completes}",
                connected.len()
            );
        }
        if stop_requested {
            out!(
                t0,
                "RESULT stopped connected={} completed={completes}",
                connected.len()
            );
            break 0;
        }
        let now = Instant::now();
        if args.stop_file.is_some() {
            // со стоп-файлом узел живёт до файла; срок только страхует от зависшего стенда
            if now >= give_up {
                out!(
                    t0,
                    "RESULT fail connected={} completed={completes} deadline",
                    connected.len()
                );
                break 1;
            }
        } else {
            match met_at {
                Some(t) if t.elapsed() >= args.hold => break 0,
                None if now >= give_up => {
                    out!(
                        t0,
                        "RESULT fail connected={} completed={completes}",
                        connected.len()
                    );
                    break 1;
                }
                _ => {}
            }
        }
    };
    transfers.shutdown();
    transfers.wait_stopped().await;
    engine.shutdown();
    transport.shutdown();
    // проброс снимается явно: движок сам `release` при выходе не вызывает
    if let Some(m) = mapper {
        let _ = tokio::time::timeout(
            Duration::from_secs(8),
            tokio::task::spawn_blocking(move || m.release()),
        )
        .await;
    }
    ExitCode::from(code)
}
