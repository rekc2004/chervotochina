#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода слоя соединения (этап 17, B3, решение 1c; T15(в): поправка часов не
//! печатается): `Debug` часов, набора допуска, конфигурации и все ошибки и тексты диагноза.
//! Событие `EngineEvent` с SAS и `PairId` проверяется в сквозном сценарии
//! `chervo-receive/tests/no_leaks.rs` (типы `Sas` и `PairId` приходят только из живого движка).

#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use chervo_connect::{
    AllowSet, CGNAT_TEXT, ClockRangeError, ConnectConfig, ConnectError, DOUBLE_NAT_TEXT, Diagnosis,
    NO_IPV6_TEXT, NO_KNOWN_ADDRESS_TEXT, NoDirectPath, PEER_UNREACHABLE_INVITE_TEXT,
    REVOCATION_FAILED_TEXT, REVOCATION_NOT_SENT_TEXT, SYMMETRIC_TEXT, SystemClock,
    UDP_BLOCKED_TEXT, UNKNOWN_TEXT, user_text,
};
use chervo_friends::FriendsError;
use chervo_identity::PairId;
use chervo_token::{InviteError, TokenError};
use redact_kit::{Needles, Out, assert_fixed_text, check};

fn all_connect_errors() -> Vec<ConnectError> {
    use ConnectError::*;
    vec![
        Friends(FriendsError::Io),
        Friends(FriendsError::RolledBack),
        Friends(FriendsError::StaleInstance),
        Token(TokenError::BadSignature),
        Invite(InviteError::Used),
        NoAddresses,
        UnknownPair,
        NotActive,
        InviteSessionsExhausted,
        Internal,
        Shutdown,
        InvalidKind,
        KindTaken,
    ]
}

fn all_reasons() -> [NoDirectPath; 8] {
    use NoDirectPath::*;
    [
        NoKnownAddress,
        NeedToken,
        BehindCgnat,
        DoubleNat,
        SymmetricNat,
        UdpBlockedSuspected,
        NoIpv6,
        Unknown,
    ]
}

#[test]
fn connect_types_hide_clock_offset_and_state() {
    let clock = SystemClock::new();
    clock.set_offset_ms(4_242_424).unwrap();
    let range_err = clock.set_offset_ms(i64::MAX).unwrap_err();
    let allow = AllowSet::new();
    let pair = PairId::from_bytes([0x44; 16]);

    let mut out = Out::new();
    out.dbg("SystemClock", &clock);
    out.dbg("AllowSet", &*allow);
    out.dbg("ConnectConfig", &ConnectConfig::default());
    out.err("ClockRangeError", &range_err);
    for e in all_connect_errors() {
        out.err("ConnectError", &e);
    }
    for r in all_reasons() {
        out.dbg("NoDirectPath", &r);
        out.dbg(
            "Diagnosis",
            &Diagnosis {
                reason: r,
                rendezvous_could_help: false,
            },
        );
        out.rec("user_text", user_text(r).to_owned());
    }

    let mut n = Needles::new();
    n.add("clock offset", "4242424");
    n.bytes("pair", pair.as_bytes());
    check(&out, &n);
}

#[test]
fn connect_errors_have_fixed_text() {
    for e in all_connect_errors() {
        assert_fixed_text("ConnectError display", &e.to_string());
    }
    assert_fixed_text("ClockRangeError", &ClockRangeError.to_string());
    for r in all_reasons() {
        assert_fixed_text("NoDirectPath debug", &format!("{r:?}"));
    }
    // тексты для экрана статические и без адресов (в них нет ни одного IP-литерала и порта)
    for t in [
        CGNAT_TEXT,
        DOUBLE_NAT_TEXT,
        NO_IPV6_TEXT,
        NO_KNOWN_ADDRESS_TEXT,
        PEER_UNREACHABLE_INVITE_TEXT,
        REVOCATION_FAILED_TEXT,
        REVOCATION_NOT_SENT_TEXT,
        SYMMETRIC_TEXT,
        UDP_BLOCKED_TEXT,
        UNKNOWN_TEXT,
    ] {
        assert!(!t.is_empty());
        assert!(
            !t.split(|c: char| !c.is_ascii_digit() && c != '.')
                .any(|w| w.matches('.').count() == 3),
            "IP-литерал в тексте: {t}"
        );
    }
}
