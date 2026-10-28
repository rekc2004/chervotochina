//! Тексты и Debug без утечек.

use chervo_addr::{LanMode, LanStatus};

use super::fixture;
use crate::rate::{RxLimiter, TokenBucket};
use crate::table::IdTable;
use crate::texts::{
    MODE_ANNOUNCE_TEXT, MODE_LISTEN_TEXT, MODE_OFF_TEXT, STATUS_ANNOUNCING_TEXT,
    STATUS_FAILED_TEXT, STATUS_LISTENING_TEXT, STATUS_NO_PRIVATE_ROUTE_TEXT, STATUS_OFF_TEXT,
    STATUS_PORT_BUSY_TEXT, mode_text, status_text,
};
use crate::wire::SrcPolicy;

#[test]
fn texts_present() {
    let statuses = [
        LanStatus::Off,
        LanStatus::NoPrivateRoute,
        LanStatus::PortBusy,
        LanStatus::Listening,
        LanStatus::Announcing,
        LanStatus::Failed,
    ];
    let mut seen = Vec::new();
    for s in statuses {
        let t = status_text(s);
        assert!(!t.is_empty());
        assert!(
            t.chars()
                .any(|c| ('а'..='я').contains(&c) || ('А'..='Я').contains(&c))
        );
        assert!(!t.contains('{') && !t.contains('%'), "подстановки в тексте");
        seen.push(t);
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), statuses.len(), "тексты состояний различны");
    for m in [LanMode::Off, LanMode::Listen, LanMode::Announce] {
        let t = mode_text(m);
        assert!(!t.is_empty());
        assert!(!t.contains('{') && !t.contains('%'));
    }
    assert_eq!(mode_text(LanMode::Off), MODE_OFF_TEXT);
    assert_eq!(mode_text(LanMode::Listen), MODE_LISTEN_TEXT);
    assert_eq!(mode_text(LanMode::Announce), MODE_ANNOUNCE_TEXT);
    assert_eq!(status_text(LanStatus::Off), STATUS_OFF_TEXT);
    assert_eq!(
        status_text(LanStatus::NoPrivateRoute),
        STATUS_NO_PRIVATE_ROUTE_TEXT
    );
    assert_eq!(status_text(LanStatus::PortBusy), STATUS_PORT_BUSY_TEXT);
    assert_eq!(status_text(LanStatus::Listening), STATUS_LISTENING_TEXT);
    assert_eq!(status_text(LanStatus::Announcing), STATUS_ANNOUNCING_TEXT);
    assert_eq!(status_text(LanStatus::Failed), STATUS_FAILED_TEXT);
    // режим «сообщать» честно говорит, что видно в сети, и не обещает лишнего
    assert!(MODE_ANNOUNCE_TEXT.contains("Червоточина"));
    assert!(MODE_ANNOUNCE_TEXT.contains("Только слушать"));
    assert!(MODE_LISTEN_TEXT.contains("ничего в сеть не рассылает"));
}

#[test]
fn debug_redacted() {
    let mut fx = fixture(2);
    let keys = &fx.sender[0].1;
    assert_eq!(format!("{keys:?}"), "LanKeys(..)");
    let t: IdTable = fx.table(1000);
    assert_eq!(format!("{t:?}"), "IdTable(..)");
    assert_eq!(format!("{t:#?}"), "IdTable(..)");
    let now = std::time::Instant::now();
    assert_eq!(format!("{:?}", RxLimiter::new(now)), "RxLimiter(..)");
    assert_eq!(
        format!("{:?}", TokenBucket::new(1, 1, now)),
        "TokenBucket(..)"
    );
    // политика источника и ошибки не содержат данных
    assert!(format!("{:?}", SrcPolicy::PRODUCT).contains("allow_loopback"));
}
