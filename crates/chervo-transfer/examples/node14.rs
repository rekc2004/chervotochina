//! Узел стенда этапа 14 (`tools/netns/stage14.sh`) и ручной проверки на двух процессах:
//! настоящий `QuinnTransport`, движок `chervo-connect` и `chervo-transfer` в одном процессе.
//! Только для стенда и ручной проверки, не для работы с настоящими ключами.
//!
//! Ключи пар и ключ списка лежат в простых файлах каталога `--book-dir/keys` (без защиты ОС):
//! иначе нельзя перезапустить процесс (строка KILLRECV) с теми же друзьями. Пары, созданные
//! здесь, одноразовые для стенда. Вывод содержит только числа и итоговые SHA-256 принятых
//! файлов: ни имён файлов, ни путей, ни адресов, ни SAS.
//!
//! Аргументы: `--port P` (UDP, 0.0.0.0), `--book-dir DIR`, `--invite-out FILE` /
//! `--invite-in FILE` (как в `node13`), `--invite-addr IP:PORT`, `--sas-auto-confirm`,
//! `--send FILE...` (файлы единственному активному другу, когда соединение есть),
//! `--dest DIR` (куда класть принятое; обязателен для приёма), `--partial DIR` (временные
//! данные; по умолчанию `DEST/chervo-partial`, тот же том), `--accept` (явно: отвечать
//! «принять» на предложения; без флага предложения отклоняются), `--hash-sources` (перед
//! отправкой напечатать SHA-256 исходных файлов), `--streams N`, `--window N`,
//! `--expect-connected N`, `--expect-complete N` (сколько `Completed` ждать, обе стороны),
//! `--deadline S`, `--hold S`.
//! Выход: 0 — ожидание выполнено, 1 — нет, 2 — ошибка запуска или аргументов.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use tokio::time::{Instant, MissedTickBehavior, interval};
use zeroize::Zeroizing;

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
        let hex: String = pair.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("pair-{hex}"))
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
    auto_confirm: bool,
    send: Vec<PathBuf>,
    dest: Option<PathBuf>,
    partial: Option<PathBuf>,
    accept: bool,
    hash_sources: bool,
    streams: Option<u8>,
    window: Option<u8>,
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
        auto_confirm: false,
        send: Vec::new(),
        dest: None,
        partial: None,
        accept: false,
        hash_sources: false,
        streams: None,
        window: None,
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
            "--dest" => a.dest = Some(PathBuf::from(val("--dest")?)),
            "--partial" => a.partial = Some(PathBuf::from(val("--partial")?)),
            "--accept" => a.accept = true,
            "--hash-sources" => a.hash_sources = true,
            "--streams" => a.streams = Some(val("--streams")?.parse().map_err(|_| "--streams")?),
            "--window" => a.window = Some(val("--window")?.parse().map_err(|_| "--window")?),
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
    Ok(a)
}

type Eng = Engine<QuinnTransport, FileStore>;

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// Номер друга по порядку появления: пары в выводе не печатаются.
fn index_of(pairs: &mut Vec<PairId>, p: PairId) -> usize {
    if let Some(i) = pairs.iter().position(|x| *x == p) {
        return i + 1;
    }
    pairs.push(p);
    pairs.len()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("node14: {e}");
            return ExitCode::from(2);
        }
    };
    if std::fs::create_dir_all(&args.book_dir).is_err() {
        eprintln!("node14: book dir");
        return ExitCode::from(2);
    }
    let Ok(store) = FileStore::new(args.book_dir.join("keys")).map(Arc::new) else {
        eprintln!("node14: key dir");
        return ExitCode::from(2);
    };
    let Ok(book) = FriendBook::open_unanchored(&args.book_dir.join("friends.chfl"), &*store) else {
        eprintln!("node14: book");
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
        eprintln!("node14: bind");
        return ExitCode::from(2);
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(SystemProbe);
    let started = Engine::start(
        transport.clone(),
        allow,
        book,
        store,
        clock,
        probe,
        ConnectConfig::default(),
    );
    let Ok((engine, mut events)) = started else {
        eprintln!("node14: engine");
        return ExitCode::from(2);
    };
    let engine: Arc<Eng> = Arc::new(engine);
    let Ok(inbox) = engine.stream_inbox(&[
        chervo_transfer::STREAM_TRANSFER_CTL,
        chervo_transfer::STREAM_TRANSFER_DATA,
    ]) else {
        eprintln!("node14: inbox");
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
        eprintln!("node14: dest or partial dir");
        return ExitCode::from(2);
    }
    let (Ok(dest_abs), Ok(partial_abs)) = (
        std::fs::canonicalize(&dest),
        std::fs::canonicalize(&partial),
    ) else {
        eprintln!("node14: dir path");
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
        eprintln!("node14: transfers");
        return ExitCode::from(2);
    };
    println!(
        "EVENT started listen_port={}",
        transport.local_addrs().first().map_or(0, SocketAddr::port)
    );

    let t0 = Instant::now();
    let give_up = t0 + args.deadline;
    let mut pairs: Vec<PairId> = Vec::new();
    let mut connected: HashSet<PairId> = HashSet::new();
    let mut in_next = 0usize;
    let mut out_next = 0usize;
    let mut sent = args.send.is_empty();
    let mut completes = 0usize;
    let mut keys: HashMap<TransferKey, ()> = HashMap::new();
    let mut met_at: Option<Instant> = None;
    let mut tick = interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    EngineEvent::Connected { pair, .. } => {
                        connected.insert(pair);
                        println!("EVENT connected pair=#{}", index_of(&mut pairs, pair));
                    }
                    EngineEvent::Disconnected { pair } => {
                        connected.remove(&pair);
                        println!("EVENT disconnected pair=#{}", index_of(&mut pairs, pair));
                    }
                    EngineEvent::SasReady { pair, .. } => {
                        println!("EVENT sas_ready pair=#{}", index_of(&mut pairs, pair));
                        if args.auto_confirm {
                            let r = engine.confirm_sas(&pair, true, "peer");
                            println!("EVENT sas_confirmed ok={}", r.is_ok());
                        }
                    }
                    EngineEvent::InviteFinished { pair, outcome } => {
                        println!("EVENT invite_finished pair=#{} outcome={outcome:?}", index_of(&mut pairs, pair));
                    }
                    _ => {}
                }
            }
            te = tevents.recv() => {
                let Some(te) = te else { break };
                match te {
                    TransferEvent::OfferReceived { key } => {
                        let view = transfers.offer(&key);
                        println!(
                            "EVENT offer_received files={} total={}",
                            view.as_ref().map_or(0, |v| v.files.len()),
                            view.as_ref().map_or(0, |v| v.total_size)
                        );
                        let r = transfers.respond(&key, args.accept);
                        println!("EVENT offer_answered accepted={} ok={}", args.accept, r.is_ok());
                        keys.insert(key, ());
                    }
                    TransferEvent::Started { .. } => println!("EVENT started_transfer"),
                    TransferEvent::Progress { done, total, .. } => {
                        println!("EVENT progress done={done} total={total}");
                    }
                    TransferEvent::Verifying { .. } => println!("EVENT verifying"),
                    TransferEvent::FileReceived { key, index } => {
                        // имя итогового файла: сгенерированное, без недоверенных байт
                        let name = format!("chervo-{}-{index}", state_dir_name(&key.pair, &key.id));
                        let p = dest_abs.join(name);
                        let r = tokio::task::spawn_blocking(move || sha256_file(&p)).await;
                        match r {
                            Ok(Ok((h, n))) => println!("RESULT received index={index} size={n} sha256={h}"),
                            _ => println!("RESULT received index={index} hash_failed"),
                        }
                    }
                    TransferEvent::FileDelivered { index, .. } => println!("EVENT file_delivered index={index}"),
                    TransferEvent::FileFailed { index, reason, .. } => {
                        println!("EVENT file_failed index={index} reason={reason:?}");
                    }
                    TransferEvent::Paused { reason, .. } => println!("EVENT paused reason={reason:?}"),
                    TransferEvent::Resumed { .. } => println!("EVENT resumed"),
                    TransferEvent::Completed { .. } => {
                        completes += 1;
                        println!("EVENT completed n={completes}");
                    }
                    TransferEvent::Cancelled { by, .. } => println!("EVENT cancelled by={by:?}"),
                    TransferEvent::Failed { reason, .. } => println!("EVENT failed reason={reason:?}"),
                    _ => {}
                }
            }
            _ = tick.tick() => {
                if let Some(path) = args.invite_in.get(in_next)
                    && let Some(text) = std::fs::read_to_string(path).ok().filter(|t| !t.trim().is_empty())
                {
                    match engine.accept_invite(text.trim()) {
                        Ok(p) => println!("EVENT invite_accepted pair=#{}", index_of(&mut pairs, p)),
                        Err(e) => println!("EVENT invite_accept_failed error={e}"),
                    }
                    in_next += 1;
                }
                if let Some(path) = args.invite_out.get(out_next) {
                    let addrs = args
                        .invite_addr
                        .map_or(InviteAddrs::Auto { same_network: false }, |a| InviteAddrs::Manual(vec![a]));
                    match engine.create_invite(900, addrs) {
                        Ok((p, text)) => {
                            let ok = write_atomic(path, &text).is_ok();
                            println!("EVENT invite_issued pair=#{} written={ok}", index_of(&mut pairs, p));
                            out_next += 1;
                        }
                        Err(ConnectError::NoAddresses) => {}
                        Err(e) => {
                            println!("EVENT invite_issue_failed error={e}");
                            out_next += 1;
                        }
                    }
                }
                // отправка: единственному активному другу, когда соединение с ним есть
                if !sent {
                    let friend = engine.read_book(|b| {
                        b.friends().iter().find(|f| f.state == FriendState::Active).map(|f| f.pair)
                    });
                    if let Some(pair) = friend && connected.contains(&pair) {
                        if args.hash_sources {
                            for (i, p) in args.send.iter().enumerate() {
                                match sha256_file(p) {
                                    Ok((h, n)) => println!("RESULT source index={i} size={n} sha256={h}"),
                                    Err(_) => println!("RESULT source index={i} hash_failed"),
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
                            Ok(_) => println!("EVENT send_started files={}", args.send.len()),
                            Err(e) => println!("EVENT send_failed error={e}"),
                        }
                        sent = true;
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
            println!(
                "RESULT ok connected={} completed={completes} t={}",
                connected.len(),
                t0.elapsed().as_secs()
            );
        }
        match met_at {
            Some(t) if t.elapsed() >= args.hold => {
                transfers.shutdown();
                transfers.wait_stopped().await;
                engine.shutdown();
                transport.shutdown();
                return ExitCode::SUCCESS;
            }
            None if Instant::now() >= give_up => {
                println!(
                    "RESULT fail connected={} completed={completes} t={}",
                    connected.len(),
                    t0.elapsed().as_secs()
                );
                transfers.shutdown();
                transfers.wait_stopped().await;
                engine.shutdown();
                transport.shutdown();
                return ExitCode::from(1);
            }
            _ => {}
        }
    }
    println!("RESULT fail events_closed");
    ExitCode::from(1)
}
