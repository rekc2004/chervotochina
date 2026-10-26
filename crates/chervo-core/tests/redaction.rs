//! Редакция вывода фасада (этап 17, B3, решение 1c; этап 18а, инвариант 4): `NodeConfig` не
//! печатает путь каталога данных (в нём имя пользователя), отчёт укрепления и ошибки узла
//! фиксированные. `Debug` событий, ссылок и видов проверяется рядом с их кодом
//! (`src/node/tests.rs`, `events_debug_redacted`): снаружи их не построить.

#[path = "support/redact_kit.rs"]
mod redact_kit;

use std::path::PathBuf;

use chervo_core::{
    FriendsError, HardenReport, NodeConfig, NodeError, NodeWarning, ReceiveLimits, harden_process,
};
use redact_kit::{Needles, Out, assert_fixed_text, check};

#[test]
fn core_types_hide_paths() {
    let cfg = NodeConfig {
        data_dir: Some(PathBuf::from("/home/COREMARK-user/.local/share/chervo")),
        receive_limits: ReceiveLimits::default(),
        port_override: Some(51234),
    };
    let mut out = Out::new();
    out.dbg("NodeConfig", &cfg);
    let report: HardenReport = harden_process();
    out.dbg("harden_process", &report);
    out.err("NodeError", &NodeError::DataDir);
    let mut n = Needles::new();
    n.add("path mark", "COREMARK");
    n.add("home", "/home/");
    n.add("data dir", ".local/share");
    check(&out, &n);
    assert_fixed_text("NodeError", &NodeError::DataDir.to_string());
}

fn all_errors() -> Vec<NodeError> {
    use NodeError::*;
    vec![
        FirstRun,
        AlreadyRunning,
        DataDir,
        SettingsCorrupt,
        KeyStoreLocked,
        KeysLost,
        RolledBack,
        StaleInstance,
        PortInUse,
        ReceiveRoot(chervo_core::RootError::OutsideProfile),
        BadName(7),
        InputTooLong,
        Friends(FriendsError::BadRevocation),
        Connect(chervo_core::ConnectError::NoAddresses),
        Transfer(chervo_core::TransferError::Io),
        Upnp(chervo_core::UpnpError::NoGateway),
        Clock(chervo_core::SyncError::Disagree),
        Unsupported,
        Shutdown,
        Io,
        NoSpace,
        InvalidValue,
        LimitReached,
    ]
}

#[test]
fn node_errors_have_fixed_text_and_russian_user_text() {
    for e in all_errors() {
        assert_fixed_text("NodeError", &e.to_string());
        let user = e.user_text();
        assert!(
            user.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)),
            "нет русского текста для {e:?}"
        );
        // подстановок нет: ни пути, ни числа из варианта
        assert!(!user.contains('{') && !user.contains('/'), "{user}");
    }
    for w in [
        NodeWarning::AnchorNotUpdated,
        NodeWarning::RootUnavailable,
        NodeWarning::SettingsNotSaved,
        NodeWarning::HostileOfferDeclined,
    ] {
        assert!(!w.user_text().is_empty());
    }
}
