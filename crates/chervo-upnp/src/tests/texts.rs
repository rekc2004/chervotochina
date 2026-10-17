//! Тексты: у каждого состояния есть русский текст без подстановок.

use chervo_addr::MapStatus;

use crate::texts::*;

#[test]
fn texts_cover_all_statuses() {
    let all = [
        MapStatus::Off,
        MapStatus::NotHomeNetwork,
        MapStatus::NoGateway,
        MapStatus::Ambiguous,
        MapStatus::WanUnknown,
        MapStatus::BehindCgnat,
        MapStatus::DoubleNat,
        MapStatus::NeedPermanentConsent,
        MapStatus::Refused(606),
        MapStatus::Failed,
        MapStatus::Mapped,
        MapStatus::MappedPermanent,
    ];
    let mut seen = Vec::new();
    for s in all {
        let t = status_text(s);
        assert!(!t.is_empty());
        assert!(!t.contains(['{', '}', '%']), "{t}");
        assert!(t.chars().any(|c| ('а'..='я').contains(&c)), "{t}");
        seen.push(t);
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), all.len(), "тексты состояний различаются");
    assert_eq!(
        status_text(MapStatus::NeedPermanentConsent),
        NEED_PERMANENT_TEXT
    );
    assert_eq!(status_text(MapStatus::Ambiguous), AMBIGUOUS_TEXT);
    assert!(ENABLE_ON_ROUTER_TEXT.starts_with("Открывать порт автоматически на этом роутере?"));
}
