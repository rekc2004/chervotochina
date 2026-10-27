//! Фоновый поток: единственный владелец узла. Методы узла синхронные и могут блокироваться
//! (до ~12 с на Secret Service, остановка до `deadline` + 11 с), поэтому поток окна их не
//! вызывает никогда. Здесь команды выполняются по порядку, события узла превращаются в
//! сообщения окну, а окно будится запросом перерисовки.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use chervo_core::{HardenReport, Node, NodeConfig, NodeError, NodeEvents, ReceiveLimits};

use crate::model::{Command, OpenMode, Outcome};
use crate::worker_ops::{self, Refs};

/// Срок мягкой остановки передач при закрытии окна (экран 10).
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
/// Сколько ждать ответа на просьбу разблокировать хранилище (Linux).
const UNLOCK_WAIT: Duration = Duration::from_secs(60);
/// Как часто поток смотрит очередь команд, пока событий нет.
const POLL: Duration = Duration::from_millis(100);

/// Связь окна с фоновым потоком.
pub struct Worker {
    commands: Sender<Command>,
    outcomes: Receiver<Outcome>,
    _thread: JoinHandle<()>,
}

impl Worker {
    /// `wake` вызывается после каждого сообщения окну (запрос перерисовки).
    pub fn spawn(hardening: HardenReport, wake: impl Fn() + Send + Sync + 'static) -> Option<Self> {
        let (cmd_tx, commands) = channel::<Command>();
        let (out_tx, outcomes) = channel::<Outcome>();
        let thread = std::thread::Builder::new()
            .name("chervo-gui-worker".to_owned())
            .spawn(move || run(hardening, commands, out_tx, std::sync::Arc::new(wake)))
            .ok()?;
        Some(Self {
            commands: cmd_tx,
            outcomes,
            _thread: thread,
        })
    }

    pub fn send(&self, cmd: Command) {
        // поток мог уже завершиться после Shutdown: команда тогда не нужна
        let _ = self.commands.send(cmd);
    }

    pub fn try_recv(&self) -> Option<Outcome> {
        self.outcomes.try_recv().ok()
    }
}

type Wake = std::sync::Arc<dyn Fn() + Send + Sync>;

fn config(port: Option<u16>) -> NodeConfig {
    NodeConfig {
        data_dir: None,
        receive_limits: ReceiveLimits::default(),
        port_override: port,
    }
}

struct State {
    hardening: HardenReport,
    node: Option<(Node, NodeEvents)>,
    refs: Refs,
    out: Sender<Outcome>,
    wake: Wake,
}

impl State {
    fn post(&self, o: Outcome) {
        let _ = self.out.send(o);
        (self.wake)();
    }

    fn post_snapshot(&mut self) {
        let snap = self
            .node
            .as_ref()
            .map(|(node, _)| worker_ops::snapshot(node, &mut self.refs));
        if let Some(snap) = snap {
            self.post(Outcome::Snapshot(snap));
        }
    }

    /// Возвращает `false`, когда поток должен завершиться.
    fn handle(&mut self, cmd: Command) -> bool {
        match cmd {
            Command::Open { mode, port } => self.open(mode, port),
            Command::FirstRunSetup {
                root,
                confirm_shared,
            } => {
                let r =
                    Node::first_run_setup(&config(None), &self.hardening, &root, confirm_shared);
                self.post(match r {
                    Ok(()) => Outcome::SetupDone,
                    Err(e) => Outcome::SetupFailed(e),
                });
            }
            Command::ResetSettings => {
                let r = Node::reset_settings(&config(None), &self.hardening);
                self.post(Outcome::SettingsReset(r));
            }
            Command::RequestUnlock => {
                let r = Node::request_unlock(&config(None), UNLOCK_WAIT);
                self.post(Outcome::Unlocked(r));
            }
            Command::Shutdown => {
                if let Some((node, _events)) = self.node.take() {
                    node.shutdown(SHUTDOWN_DEADLINE);
                }
                self.post(Outcome::Stopped);
                return false;
            }
            other => {
                let out = self
                    .node
                    .as_ref()
                    .and_then(|(node, _)| worker_ops::exec(node, &mut self.refs, other));
                // узла нет (ещё не открыт или уже остановлен): действие невозможно
                self.post(out.unwrap_or(Outcome::Done(Err(NodeError::Shutdown))));
            }
        }
        true
    }

    fn open(&mut self, mode: OpenMode, port: Option<u16>) {
        if self.node.is_some() {
            return;
        }
        let cfg = config(port);
        let r: Result<(Node, NodeEvents), NodeError> = match mode {
            OpenMode::Normal => Node::open(cfg, &self.hardening),
            OpenMode::AcceptOlder => Node::open_accept_older(cfg, &self.hardening),
            OpenMode::StartOver => Node::open_start_over(cfg, &self.hardening),
        };
        match r {
            Ok((node, events)) => {
                let wake = self.wake.clone();
                node.set_waker(Box::new(move || wake()));
                // порт, выбранный после `PortInUse`, запоминается для следующих запусков
                let port_saved = match port {
                    Some(p) => node.set_port(p).is_ok(),
                    None => true,
                };
                self.node = Some((node, events));
                self.post(Outcome::Opened { port_saved });
                self.post_snapshot();
            }
            Err(e) => self.post(Outcome::OpenFailed(e)),
        }
    }

    /// Пересылает события узла окну. Возвращает `true`, если что-то пришло.
    fn pump_events(&mut self) -> bool {
        let mut got = false;
        let mut batch = Vec::new();
        if let Some((_, events)) = &self.node {
            while batch.len() < 256 {
                let Ok(ev) = events.try_recv() else {
                    break;
                };
                batch.push(ev);
            }
        }
        for ev in batch {
            got = true;
            let outcome = worker_ops::event_outcome(&mut self.refs, ev);
            self.post(outcome);
        }
        if got {
            self.post_snapshot();
        }
        got
    }
}

fn run(hardening: HardenReport, commands: Receiver<Command>, out: Sender<Outcome>, wake: Wake) {
    let mut st = State {
        hardening,
        node: None,
        refs: Refs::default(),
        out,
        wake,
    };
    loop {
        match commands.recv_timeout(POLL) {
            Ok(cmd) => {
                if !st.handle(cmd) {
                    return;
                }
                // состояние могло измениться командой
                st.post_snapshot();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // окно исчезло без команды остановки: остановить узел по порядку
                if let Some((node, _events)) = st.node.take() {
                    node.shutdown(SHUTDOWN_DEADLINE);
                }
                return;
            }
        }
        st.pump_events();
    }
}
