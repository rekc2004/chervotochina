//! Редакция вывода фасада (этап 17, B3, решение 1c): `NodeConfig` не печатает путь каталога
//! данных (в нём имя пользователя), отчёт укрепления и ошибка фасада фиксированные.

#[path = "support/redact_kit.rs"]
mod redact_kit;

use std::path::PathBuf;

use chervo_core::{CoreError, HardenReport, NodeConfig, harden_process};
use chervo_receive::ReceiveLimits;
use redact_kit::{Needles, Out, assert_fixed_text, check};

#[test]
fn core_types_hide_paths() {
    let cfg = NodeConfig {
        data_dir: PathBuf::from("/home/COREMARK-user/.local/share/chervo"),
        receive_limits: ReceiveLimits::default(),
    };
    let mut out = Out::new();
    out.dbg("NodeConfig", &cfg);
    out.dbg("HardenReport", &HardenReport::default());
    out.dbg("harden_process", &harden_process());
    out.err("CoreError", &CoreError::NotImplemented);
    let mut n = Needles::new();
    n.add("path mark", "COREMARK");
    n.add("home", "/home/");
    n.add("data dir", ".local/share");
    check(&out, &n);
    assert_fixed_text("CoreError", &CoreError::NotImplemented.to_string());
}
