#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода синхронизации времени (этап 17, B3, T15(в)): поправка часов и имена
//! серверов (свой сервер может быть задан IP-адресом) не печатаются через `Debug`; поправку
//! читают из поля. Ошибки фиксированные.

#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::time::Duration;

use chervo_timesync::{ClockOffset, SyncConfig, SyncError};
use redact_kit::{Needles, Out, assert_fixed_text, check};

#[test]
fn timesync_debug_hides_offset_and_servers() {
    let offset = ClockOffset {
        offset_ms: 7_654_321,
        valid: 3,
        queried: 4,
    };
    let cfg = SyncConfig {
        servers: vec!["10.9.8.77".to_owned(), "ntp.example-secret.test".to_owned()],
        timeout: Duration::from_millis(1_234_567),
        min_valid: 2,
        max_spread: Duration::from_secs(1),
        max_abs_offset: Duration::from_secs(7 * 24 * 3600),
    };
    let mut out = Out::new();
    out.dbg("ClockOffset", &offset);
    out.dbg("SyncConfig", &cfg);
    out.dbg("SyncConfig::default", &SyncConfig::default());
    out.dbg("Ok(ClockOffset)", &Ok::<_, SyncError>(offset));
    for e in all_errors() {
        out.err("SyncError", &e);
    }
    let mut n = Needles::new();
    n.add("offset ms", "7654321");
    n.add("offset ms (grouped)", "7_654_321");
    n.add("server ip", "10.9.8.77");
    n.add("server name", "example-secret");
    n.add("pool name", "pool.ntp.org");
    n.add("vniiftri", "vniiftri");
    check(&out, &n);
    // значение по-прежнему доступно через поле
    assert_eq!(offset.offset_ms, 7_654_321);
}

fn all_errors() -> [SyncError; 4] {
    [
        SyncError::NoServers,
        SyncError::TooFewValid,
        SyncError::Disagree,
        SyncError::TooLarge,
    ]
}

#[test]
fn timesync_errors_have_fixed_text() {
    for e in all_errors() {
        assert_fixed_text("SyncError display", &e.to_string());
        assert_fixed_text("SyncError debug", &format!("{e:?}"));
    }
}
