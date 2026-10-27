//! Тексты и часы.

use chervo_friends::FriendsError;

use crate::{
    Clock, REVOCATION_FAILED_TEXT, REVOCATION_NOT_SENT_TEXT, SystemClock, revocation_error_text,
};

#[test]
fn revocation_io_text() {
    assert_eq!(
        revocation_error_text(FriendsError::Io),
        REVOCATION_NOT_SENT_TEXT
    );
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
