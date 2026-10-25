//! Тексты и часы.

use chervo_friends::FriendsError;

use crate::{
    Clock, DOUBLE_NAT_TEXT, LAN_DISCOVERY_TEXT, LAN_FIRST_RUN_TEXT, NoDirectPath,
    PEER_UNREACHABLE_INVITE_TEXT, REVOCATION_FAILED_TEXT, REVOCATION_NOT_SENT_TEXT, SystemClock,
    revocation_error_text, user_text,
};

fn has_cyrillic(s: &str) -> bool {
    s.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
}

#[test]
fn texts_present() {
    let reasons = [
        NoDirectPath::NoKnownAddress,
        NoDirectPath::NeedToken,
        NoDirectPath::BehindCgnat,
        NoDirectPath::DoubleNat,
        NoDirectPath::SymmetricNat,
        NoDirectPath::UdpBlockedSuspected,
        NoDirectPath::NoIpv6,
        NoDirectPath::Unknown,
    ];
    let mut all: Vec<&str> = reasons.iter().map(|r| user_text(*r)).collect();
    all.extend([
        REVOCATION_NOT_SENT_TEXT,
        REVOCATION_FAILED_TEXT,
        PEER_UNREACHABLE_INVITE_TEXT,
        LAN_DISCOVERY_TEXT,
        LAN_FIRST_RUN_TEXT,
    ]);
    for t in &all {
        assert!(!t.is_empty());
        assert!(has_cyrillic(t), "{t}");
        assert!(!t.contains('{'), "no placeholders: {t}");
    }
    // у разных причин разные тексты
    let mut distinct = all[..8].to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 8);
    assert_eq!(
        user_text(NoDirectPath::NeedToken),
        chervo_addr::NEED_TOKEN_TEXT
    );
    assert_eq!(user_text(NoDirectPath::DoubleNat), DOUBLE_NAT_TEXT);
}

#[test]
fn revocation_io_text() {
    assert_eq!(
        revocation_error_text(FriendsError::Io),
        REVOCATION_NOT_SENT_TEXT
    );
    assert_eq!(REVOCATION_NOT_SENT_TEXT, "Отзыв не отправлен, повторите.");
    assert_eq!(
        revocation_error_text(FriendsError::KeyStorageUnavailable),
        REVOCATION_FAILED_TEXT
    );
    assert_ne!(REVOCATION_FAILED_TEXT, REVOCATION_NOT_SENT_TEXT);
}

#[test]
fn clock_offset_range() {
    let c = SystemClock::new();
    let base = c.now_unix();
    assert!(c.set_offset_ms(7 * 24 * 3600 * 1000).is_ok());
    assert!(c.set_offset_ms(-7 * 24 * 3600 * 1000).is_ok());
    assert!(c.set_offset_ms(7 * 24 * 3600 * 1000 + 1).is_err());
    assert!(c.set_offset_ms(i64::MIN).is_err());
    c.set_offset_ms(60_000).unwrap();
    let shifted = c.now_unix();
    assert!((60..=62).contains(&(shifted - base)), "{}", shifted - base);
}
