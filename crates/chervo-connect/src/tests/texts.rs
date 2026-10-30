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

#[test]
fn texts_no_ipv6_new_wording() {
    use crate::{NO_IPV6_TEXT, NoDirectPath, user_text};
    assert_eq!(
        NO_IPV6_TEXT,
        "Для друга известны только адреса IPv6, а у вас сейчас нет связи по IPv6: её не даёт провайдер или роутер, либо IPv6 выключен на компьютере. Попросите друга прислать токен обновления адреса с адресом IPv4 или подключитесь к сети с IPv6."
    );
    assert!(!NO_IPV6_TEXT.contains("только по IPv4"));
    assert_eq!(user_text(NoDirectPath::NoIpv6), NO_IPV6_TEXT);
}
