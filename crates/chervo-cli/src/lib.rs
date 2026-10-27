//! Консольная оболочка узла (этап 18в). Зависит только от `chervo-core`: вся работа идёт через
//! публичный API `chervo_core::Node`. Нет демона, нет сокетов управления, нет флагов в обход
//! хранилища ключей ОС, нет журналов. Весь вывод в терминал проходит через модуль `out`.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo
)]

pub mod input;
pub mod out;
pub mod recovery;
pub mod repl;
mod view;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use chervo_core::texts::{FIRST_RUN_TEXT, ROOT_OUTSIDE_PROFILE_TEXT};
use chervo_core::{HardenReport, Node, NodeConfig, NodeError, ReceiveLimits, RootError};

const USAGE: &str = "Использование:\n  chervo --version\n  chervo init --receive ПАПКА [--shared-root-ok]\n  chervo unlock\n  chervo run\n  chervo recover accept-older|start-over [--yes]\n  chervo reset-settings [--yes]";
/// Сколько ждать разблокировки хранилища ключей.
const UNLOCK_WAIT: Duration = Duration::from_secs(60);

fn config() -> NodeConfig {
    NodeConfig {
        data_dir: None,
        receive_limits: ReceiveLimits::default(),
        port_override: None,
    }
}

/// Точка входа `chervo`. `h`: доказательство, что укрепление процесса уже выполнено.
pub fn run_cli(h: &HardenReport, args: Vec<OsString>) -> ExitCode {
    let mut it = args.into_iter();
    let Some(first) = it.next() else {
        out::err(USAGE);
        return ExitCode::from(2);
    };
    match first.to_str() {
        Some("--version") => {
            out::line(&format!("chervo {}", chervo_core::VERSION));
            ExitCode::SUCCESS
        }
        Some("init") => init(h, it.collect()),
        Some("unlock") => unlock(),
        Some("run") if it.next().is_none() => run(h, Node::open),
        Some("recover") => recover(h, it.collect()),
        Some("reset-settings") => reset_settings(h, it.collect()),
        _ => {
            out::err(USAGE);
            ExitCode::from(2)
        }
    }
}

fn init(h: &HardenReport, args: Vec<OsString>) -> ExitCode {
    let mut receive: Option<PathBuf> = None;
    let mut shared_ok = false;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--receive") => match it.next() {
                Some(p) if receive.is_none() => receive = Some(PathBuf::from(p)),
                _ => return usage_error("chervo init --receive ПАПКА [--shared-root-ok]"),
            },
            Some("--shared-root-ok") => shared_ok = true,
            _ => return usage_error("chervo init --receive ПАПКА [--shared-root-ok]"),
        }
    }
    let Some(receive) = receive else {
        return usage_error("chervo init --receive ПАПКА [--shared-root-ok]");
    };
    let receive = std::path::absolute(&receive).unwrap_or(receive);
    match Node::first_run_setup(&config(), h, &receive, shared_ok) {
        Ok(()) => {
            out::line("Готово: настройки записаны, ключи не создавались. Запуск: chervo run");
            ExitCode::SUCCESS
        }
        Err(e) => {
            out::err(e.user_text());
            if e == NodeError::ReceiveRoot(RootError::OutsideProfile) {
                out::err(ROOT_OUTSIDE_PROFILE_TEXT);
                out::err(
                    "Если других пользователей на этом компьютере нет: добавьте --shared-root-ok.",
                );
            }
            ExitCode::from(1)
        }
    }
}

fn unlock() -> ExitCode {
    match Node::request_unlock(&config(), UNLOCK_WAIT) {
        Ok(()) => {
            out::line("Хранилище ключей разблокировано.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            out::err(e.user_text());
            ExitCode::from(1)
        }
    }
}

/// Способ открыть узел (`Node::open` и его варианты восстановления).
type Opener = fn(NodeConfig, &HardenReport) -> Result<(Node, chervo_core::NodeEvents), NodeError>;

/// Только `--yes` или ничего.
fn yes_flag(args: &[OsString]) -> Option<bool> {
    match args {
        [] => Some(false),
        [a] if a.to_str() == Some("--yes") => Some(true),
        _ => None,
    }
}

/// Подтверждение с терминала (одна строка со стандартного ввода).
fn confirmed(what: recovery::Recovery, yes: bool) -> bool {
    let stdin = std::io::stdin();
    recovery::confirm(what, yes, stdin.is_terminal(), || {
        match input::read_line(&mut stdin.lock()) {
            input::Input::Line(s) => Some(s),
            _ => None,
        }
    })
}

fn recover(h: &HardenReport, args: Vec<OsString>) -> ExitCode {
    let usage = "chervo recover accept-older|start-over [--yes]";
    let Some((kind, rest)) = args.split_first() else {
        return usage_error(usage);
    };
    let Some(yes) = yes_flag(rest) else {
        return usage_error(usage);
    };
    match kind.to_str() {
        Some("accept-older") => {
            if !confirmed(recovery::Recovery::AcceptOlder, yes) {
                return ExitCode::from(2);
            }
            run(h, Node::open_accept_older)
        }
        Some("start-over") => {
            if !confirmed(recovery::Recovery::StartOver, yes) {
                return ExitCode::from(2);
            }
            run(h, Node::open_start_over)
        }
        _ => usage_error(usage),
    }
}

fn reset_settings(h: &HardenReport, args: Vec<OsString>) -> ExitCode {
    let Some(yes) = yes_flag(&args) else {
        return usage_error("chervo reset-settings [--yes]");
    };
    if !confirmed(recovery::Recovery::ResetSettings, yes) {
        return ExitCode::from(2);
    }
    match Node::reset_settings(&config(), h) {
        Ok(()) => {
            out::line("Настройки сброшены. Дальше: chervo init --receive ПАПКА");
            ExitCode::SUCCESS
        }
        Err(e) => {
            out::err(e.user_text());
            ExitCode::from(1)
        }
    }
}

fn run(h: &HardenReport, open: Opener) -> ExitCode {
    match open(config(), h) {
        Ok((node, events)) => {
            repl::run(node, events, input::stdin_lines());
            ExitCode::SUCCESS
        }
        Err(e) => {
            out::err(e.user_text());
            match e {
                NodeError::FirstRun => {
                    out::err(FIRST_RUN_TEXT);
                    out::err("Выполните: chervo init --receive ПАПКА");
                }
                NodeError::KeyStoreLocked => out::err("На Linux можно попробовать: chervo unlock"),
                NodeError::RolledBack => {
                    out::err("Принять старый список: chervo recover accept-older");
                }
                NodeError::KeysLost => out::err("Начать список заново: chervo recover start-over"),
                NodeError::SettingsCorrupt => out::err("Сбросить настройки: chervo reset-settings"),
                _ => {}
            }
            ExitCode::from(1)
        }
    }
}

fn usage_error(usage: &str) -> ExitCode {
    out::err(&format!("Использование: {usage}"));
    ExitCode::from(2)
}
