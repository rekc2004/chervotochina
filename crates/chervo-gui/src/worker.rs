//! Фоновый поток: единственный владелец узла. Методы узла синхронные и могут блокироваться
//! (до ~12 с на Secret Service, остановка до `deadline` + 11 с), поэтому поток окна их не
//! вызывает никогда. Здесь команды выполняются по порядку, события узла превращаются в
//! сообщения окну, а окно будится запросом перерисовки.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Поток шлёт сюда один знак, когда выходит (для ограниченного ожидания в `finish`).
    exited: Receiver<()>,
    /// Остановка запрошена: поток не начинает новых команд, кроме `Shutdown`.
    stop: Arc<AtomicBool>,
    _thread: JoinHandle<()>,
}

/// Потолок одной долгой операции, которая уже идёт в момент закрытия (она не прерывается):
/// `Node::open` (до ~12 с на Secret Service и запуск сети), «Найти роутер» (поиск 2 с и запросы
/// по 3 с), «Сверить часы» (на каждый сервер времени 2 с плюс разрешение имён). Число 30 с это
/// инженерный запас, а не доказанная граница: разрешение имён в «Сверить часы» ядром по времени
/// не ограничено [не проверено].
pub const LONG_OP_BOUND: Duration = Duration::from_secs(30);

/// Сколько `main` ждёт фоновый поток после закрытия окна: самая долгая начатая операция
/// (`LONG_OP_BOUND`) + срок мягкой остановки передач (`SHUTDOWN_DEADLINE`, 10 с) + потолок
/// остановки узла сверх срока (11 с, SPEC 2.3 п.7) + запас 1 с. Новых долгих операций после
/// запроса остановки поток не начинает (флаг `stop`), поэтому больше этой суммы ждать нечего.
pub const JOIN_BOUND: Duration =
    Duration::from_secs(LONG_OP_BOUND.as_secs() + SHUTDOWN_DEADLINE.as_secs() + 11 + 1);

impl Worker {
    /// `wake` вызывается после каждого сообщения окну (запрос перерисовки).
    pub fn spawn(hardening: HardenReport, wake: impl Fn() + Send + Sync + 'static) -> Option<Self> {
        let (cmd_tx, commands) = channel::<Command>();
        let (out_tx, outcomes) = channel::<Outcome>();
        let (exit_tx, exited) = channel::<()>();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("chervo-gui-worker".to_owned())
            .spawn(move || {
                run(hardening, commands, out_tx, Arc::new(wake), &thread_stop);
                let _ = exit_tx.send(());
            })
            .ok()?;
        Some(Self {
            commands: cmd_tx,
            outcomes,
            exited,
            stop,
            _thread: thread,
        })
    }

    /// Последний шаг `main` на любом пути выхода: просит остановить узел (если уже остановлен,
    /// просьба ничего не меняет) и ждёт выхода потока не дольше `JOIN_BOUND`. Так `release()`
    /// проброса порта и снятие замка выполняются, даже если окно закрыли мимо нашего диалога.
    pub fn finish(&self) -> bool {
        // сначала флаг: очередь команд после него отбрасывается, долгие операции не стартуют
        self.stop.store(true, Ordering::SeqCst);
        self.send(Command::Shutdown);
        self.exited.recv_timeout(JOIN_BOUND).is_ok()
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
            self.post(Outcome::Snapshot(Box::new(snap)));
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
            let outcome =
                worker_ops::event_outcome(self.node.as_ref().map(|(n, _)| n), &mut self.refs, ev);
            self.post(outcome);
        }
        if got {
            self.post_snapshot();
        }
        got
    }
}

fn run(
    hardening: HardenReport,
    commands: Receiver<Command>,
    out: Sender<Outcome>,
    wake: Wake,
    stop: &AtomicBool,
) {
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
                // остановка запрошена: всё, кроме `Shutdown`, отбрасывается без выполнения
                if stop.load(Ordering::SeqCst) && !matches!(cmd, Command::Shutdown) {
                    continue;
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_bound_covers_longest_op_plus_shutdown() {
        // 30 (долгая операция) + 10 (передачи) + 11 (потолок остановки узла) + 1 (запас)
        assert_eq!(JOIN_BOUND, Duration::from_secs(52));
        assert!(JOIN_BOUND > LONG_OP_BOUND + SHUTDOWN_DEADLINE + Duration::from_secs(11));
    }
}
