//! Узел стенда этапа 13 (`tools/netns/stage13.sh`): настоящий `QuinnTransport` и движок
//! `chervo-connect` в одном процессе. Только для стенда.
//!
//! Ключи пар и ключ списка лежат в оперативной памяти и пропадают вместе с процессом:
//! поэтому процесс живёт всё время строки стенда (приглашения проходят в нём же). Вывод
//! стенда содержит адреса друзей и виды путей: библиотека `chervo-connect` ничего не
//! печатает, печатает только этот пример. SAS и имена не печатаются никогда.
//!
//! Аргументы: `--port P` (UDP, 0.0.0.0), `--forward F` (внешний порт проброса),
//! `--book-dir DIR` (файл списка), `--invite-out FILE` (выдать приглашение и записать
//! текст), `--invite-in FILE` (дождаться файла и принять приглашение; оба аргумента можно
//! повторять, приглашения идут по очереди), `--udp-window S` (окно эвристики «UDP закрыт»
//! вместо 600 с, только для стенда), `--invite-addr
//! IP:PORT` (адрес приглашения вручную вместо `Auto`), `--sas-auto-confirm`,
//! `--expect-connected N --deadline S` (ждать N соединённых друзей не дольше S секунд),
//! `--hold S` (после выполнения остаться ещё S секунд для действий стенда),
//! `--lan` (этап 13в: запустить поиск в LAN и подключить его к движку после запуска),
//! `--expect-path lan` (ожидание выполнено, только если все соединённые друзья пришли по
//! пути LAN; других значений нет).
//! Выход: 0 — ожидание выполнено, 1 — нет, 2 — ошибка запуска или аргументов.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_connect::{
    AllowSet, Clock, ConnectConfig, ConnectError, Engine, EngineEvent, InviteAddrs, PathKind,
    RouteProbe, SystemClock, SystemProbe,
};
use chervo_friends::FriendBook;
use chervo_identity::{IdentityError, ListKeyStore, PairId, SecretStore};
use chervo_transport::{PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use tokio::time::{Instant, MissedTickBehavior, interval};
use zeroize::Zeroizing;

/// Хранилище ключей в памяти: только для этого примера.
#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(lock(&self.map)
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        lock(&self.map).insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        lock(&self.map).remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(lock(&self.list)
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *lock(&self.list) = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *lock(&self.list) = None;
        Ok(())
    }
}

struct Args {
    port: u16,
    forward: Option<u16>,
    book_dir: PathBuf,
    invite_out: Vec<PathBuf>,
    invite_in: Vec<PathBuf>,
    udp_window: Option<Duration>,
    invite_addr: Option<SocketAddr>,
    auto_confirm: bool,
    expect: usize,
    deadline: Duration,
    hold: Duration,
    lan: bool,
    expect_path: Option<PathKind>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        port: 4433,
        forward: None,
        book_dir: PathBuf::new(),
        invite_out: Vec::new(),
        invite_in: Vec::new(),
        udp_window: None,
        invite_addr: None,
        auto_confirm: false,
        expect: 0,
        deadline: Duration::from_secs(60),
        hold: Duration::ZERO,
        lan: false,
        expect_path: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name}: no value"));
        match k.as_str() {
            "--port" => a.port = val("--port")?.parse().map_err(|_| "--port")?,
            "--forward" => a.forward = Some(val("--forward")?.parse().map_err(|_| "--forward")?),
            "--book-dir" => a.book_dir = PathBuf::from(val("--book-dir")?),
            "--invite-out" => a.invite_out.push(PathBuf::from(val("--invite-out")?)),
            "--invite-in" => a.invite_in.push(PathBuf::from(val("--invite-in")?)),
            "--udp-window" => {
                a.udp_window = Some(Duration::from_secs(
                    val("--udp-window")?.parse().map_err(|_| "--udp-window")?,
                ));
            }
            "--invite-addr" => {
                a.invite_addr = Some(val("--invite-addr")?.parse().map_err(|_| "--invite-addr")?);
            }
            "--sas-auto-confirm" => a.auto_confirm = true,
            "--expect-connected" => {
                a.expect = val("--expect-connected")?
                    .parse()
                    .map_err(|_| "--expect-connected")?;
            }
            "--deadline" => {
                a.deadline =
                    Duration::from_secs(val("--deadline")?.parse().map_err(|_| "--deadline")?);
            }
            "--hold" => a.hold = Duration::from_secs(val("--hold")?.parse().map_err(|_| "--hold")?),
            "--lan" => a.lan = true,
            "--expect-path" => {
                a.expect_path = match val("--expect-path")?.as_str() {
                    "lan" => Some(PathKind::Lan),
                    _ => return Err("--expect-path: only `lan` is known".to_owned()),
                };
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.book_dir.as_os_str().is_empty() {
        return Err("--book-dir is required".to_owned());
    }
    Ok(a)
}

type Eng = Engine<QuinnTransport, MemStore>;

/// Номер друга по порядку появления: пары в выводе не печатаются.
fn index_of(pairs: &mut Vec<PairId>, p: PairId) -> usize {
    if let Some(i) = pairs.iter().position(|x| *x == p) {
        return i + 1;
    }
    pairs.push(p);
    pairs.len()
}

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

fn print_state(engine: &Eng, pairs: &mut Vec<PairId>, connected: &HashSet<PairId>, t0: Instant) {
    let friends: Vec<(PairId, Vec<SocketAddr>)> = engine.read_book(|b| {
        b.friends()
            .iter()
            .map(|f| (f.pair, f.known_addrs.iter().map(|k| k.addr).collect()))
            .collect()
    });
    let mut line = format!(
        "STATE t={} connected={} nat_view={:?}",
        t0.elapsed().as_secs(),
        connected.len(),
        engine.nat_view()
    );
    if let Some(s) = engine.lan_status() {
        line.push_str(&format!(" lan={s:?}"));
    }
    for (p, addrs) in friends {
        let i = index_of(pairs, p);
        let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
        line.push_str(&format!(" friend#{i}=[{}]", list.join(",")));
    }
    println!("{line}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("node13: {e}");
            return ExitCode::from(2);
        }
    };
    if std::fs::create_dir_all(&args.book_dir).is_err() {
        eprintln!("node13: book dir");
        return ExitCode::from(2);
    }
    let store = Arc::new(MemStore::default());
    let book = match FriendBook::open_unanchored(&args.book_dir.join("friends.chfl"), &*store) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("node13: book");
            return ExitCode::from(2);
        }
    };
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let transport = match QuinnTransport::bind(
        SocketAddr::from(([0, 0, 0, 0], args.port)),
        QuinnConfig::default(),
        filter,
    ) {
        Ok(t) => Arc::new(t),
        Err(_) => {
            eprintln!("node13: bind");
            return ExitCode::from(2);
        }
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let lan_clock = clock.clone();
    let probe: Arc<dyn RouteProbe> = Arc::new(SystemProbe);
    let mut cfg = ConnectConfig {
        manual_forward: args.forward,
        ..ConnectConfig::default()
    };
    if let Some(w) = args.udp_window {
        // сокращённое окно для стенда: иначе строка «UDP закрыт» ждёт десять минут
        cfg.udp_blocked_window = w;
    }
    let started = Engine::start(transport.clone(), allow, book, store, clock, probe, cfg);
    let Ok((engine, mut events)) = started else {
        eprintln!("node13: engine");
        return ExitCode::from(2);
    };
    if args.lan {
        // поиск в LAN: часы те же, что у движка (с поправкой пользователя)
        let lan_clock = lan_clock.clone();
        let link = chervo_lan::LanDiscovery::start(Arc::new(move || lan_clock.now_unix()));
        let attached = engine.attach_lan(link);
        println!("EVENT lan_attached ok={}", attached.is_ok());
    }
    println!(
        "EVENT started listen_port={}",
        transport.local_addrs().first().map_or(0, SocketAddr::port)
    );

    let t0 = Instant::now();
    let give_up = t0 + args.deadline;
    let mut pairs: Vec<PairId> = Vec::new();
    let mut connected: HashSet<PairId> = HashSet::new();
    let mut paths: HashMap<PairId, PathKind> = HashMap::new();
    let mut in_next = 0usize;
    let mut out_next = 0usize;
    let mut met_at: Option<Instant> = None;
    let mut tick = interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut n_ticks: u64 = 0;
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    EngineEvent::Connected { pair, path } => {
                        connected.insert(pair);
                        paths.insert(pair, path);
                        println!("EVENT connected pair=#{} path={path:?}", index_of(&mut pairs, pair));
                    }
                    EngineEvent::Disconnected { pair } => {
                        connected.remove(&pair);
                        paths.remove(&pair);
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
                    EngineEvent::Unreachable { pair, diagnosis } => {
                        println!(
                            "EVENT unreachable pair=#{} reason={:?} rendezvous_could_help={}",
                            index_of(&mut pairs, pair),
                            diagnosis.reason,
                            diagnosis.rendezvous_could_help
                        );
                    }
                    EngineEvent::OwnAddrsChanged => println!("EVENT own_addrs_changed"),
                    EngineEvent::KeyProblem { .. } => println!("EVENT key_problem"),
                    EngineEvent::ClockSkew { .. } => println!("EVENT clock_skew"),
                    EngineEvent::Internal => println!("EVENT internal"),
                    _ => println!("EVENT other"),
                }
            }
            _ = tick.tick() => {
                n_ticks += 1;
                // приглашения принимаются и выдаются по очереди, в порядке аргументов
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
                        // адрес ещё не известен (нужно наблюдение друга): повтор на следующем такте
                        Err(ConnectError::NoAddresses) => {}
                        Err(e) => {
                            println!("EVENT invite_issue_failed error={e}");
                            out_next += 1;
                        }
                    }
                }
                if n_ticks.is_multiple_of(4) {
                    print_state(&engine, &mut pairs, &connected, t0);
                }
            }
        }
        let ready = in_next >= args.invite_in.len()
            && out_next >= args.invite_out.len()
            && connected.len() >= args.expect
            && args
                .expect_path
                .is_none_or(|want| connected.iter().all(|p| paths.get(p) == Some(&want)));
        if ready && met_at.is_none() {
            met_at = Some(Instant::now());
            println!(
                "RESULT ok connected={} t={}",
                connected.len(),
                t0.elapsed().as_secs()
            );
        }
        match met_at {
            Some(t) if t.elapsed() >= args.hold => {
                print_state(&engine, &mut pairs, &connected, t0);
                engine.shutdown();
                transport.shutdown();
                return ExitCode::SUCCESS;
            }
            None if Instant::now() >= give_up => {
                println!(
                    "RESULT fail connected={} t={}",
                    connected.len(),
                    t0.elapsed().as_secs()
                );
                print_state(&engine, &mut pairs, &connected, t0);
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
