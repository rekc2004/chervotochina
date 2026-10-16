//! Публичные типы слоя соединения (этап 13, C3): значения по умолчанию, перечисления,
//! скрытый `Debug`, закрытый по умолчанию набор разрешённых пар.

use std::time::Duration;

use chervo_connect::{
    AllowSet, ConnectConfig, ConnectError, Diagnosis, EngineEvent, NoDirectPath, PathKind,
    user_text,
};
use chervo_identity::PairId;
use chervo_transport::PeerFilter;

/// Исчерпывающий match без `_`: новый вариант PathKind сломает компиляцию теста.
fn path_label(kind: PathKind) -> &'static str {
    match kind {
        PathKind::Lan => "lan",
        PathKind::Ipv6 => "ipv6",
        PathKind::PortMapped => "port-mapped",
        PathKind::SimultaneousOpen => "simultaneous-open",
    }
}

/// `NoDirectPath` помечен `non_exhaustive`: снаружи нужна ветка `_`.
fn reason_label(r: NoDirectPath) -> &'static str {
    match r {
        NoDirectPath::NoKnownAddress => "no-known-address",
        NoDirectPath::NeedToken => "need-token",
        NoDirectPath::BehindCgnat => "cgnat",
        NoDirectPath::SymmetricNat => "symmetric",
        NoDirectPath::UdpBlockedSuspected => "udp-blocked",
        NoDirectPath::NoIpv6 => "no-ipv6",
        NoDirectPath::Unknown => "unknown",
        _ => "other",
    }
}

#[test]
fn path_and_reason_names_are_pinned() {
    let labels = [
        path_label(PathKind::Lan),
        path_label(PathKind::Ipv6),
        path_label(PathKind::PortMapped),
        path_label(PathKind::SimultaneousOpen),
    ];
    assert_eq!(labels, ["lan", "ipv6", "port-mapped", "simultaneous-open"]);
    assert_eq!(reason_label(NoDirectPath::BehindCgnat), "cgnat");
    assert_eq!(
        reason_label(NoDirectPath::UdpBlockedSuspected),
        "udp-blocked"
    );
    // у каждой причины свой непустой текст
    let reasons = [
        NoDirectPath::NoKnownAddress,
        NoDirectPath::NeedToken,
        NoDirectPath::BehindCgnat,
        NoDirectPath::SymmetricNat,
        NoDirectPath::UdpBlockedSuspected,
        NoDirectPath::NoIpv6,
        NoDirectPath::Unknown,
    ];
    let mut texts: Vec<&str> = reasons.iter().map(|r| user_text(*r)).collect();
    assert!(texts.iter().all(|t| !t.is_empty()));
    texts.sort_unstable();
    texts.dedup();
    assert_eq!(texts.len(), reasons.len());
}

#[test]
fn config_defaults_match_the_spec() {
    let c = ConnectConfig::default();
    assert_eq!(c.manual_forward, None);
    assert_eq!(c.probe_interval, Duration::from_secs(2));
    assert_eq!(c.tick, Duration::from_secs(1));
    assert_eq!(c.fast_window, Duration::from_secs(120));
    assert_eq!(c.fast_period, Duration::from_secs(5));
    assert_eq!(
        (c.dial_base, c.dial_cap),
        (Duration::from_secs(30), Duration::from_secs(600))
    );
    assert_eq!(
        (c.hint_base, c.hint_cap),
        (Duration::from_secs(60), Duration::from_secs(1800))
    );
    assert_eq!(
        (c.per_ip_dials, c.per_ip_window),
        (4, Duration::from_secs(10))
    );
    assert_eq!(
        (c.max_concurrent_dials, c.max_live, c.limiter_capacity),
        (16, 64, 4096)
    );
    assert_eq!(c.addr_info_timeout, Duration::from_secs(5));
    assert_eq!(c.addr_info_in_per_min, 4);
    assert_eq!(c.addr_info_out_interval, Duration::from_secs(10));
    assert_eq!(c.invite_session, Duration::from_secs(300));
    assert_eq!(c.expire_interval, Duration::from_secs(60));
    assert_eq!(c.unreachable_after_fails, 3);
    assert_eq!(c.udp_blocked_window, Duration::from_secs(600));
    assert_eq!(c.udp_blocked_min_friends, 2);
}

#[test]
fn diagnosis_flag_and_debug_are_safe() {
    let d = Diagnosis {
        reason: NoDirectPath::BehindCgnat,
        rendezvous_could_help: true,
    };
    assert!(d.rendezvous_could_help);
    let pair = PairId::from_bytes([7; 16]);
    let ev = EngineEvent::Connected {
        pair,
        path: PathKind::Lan,
    };
    assert_eq!(format!("{ev:?}"), "EngineEvent(..)");
    assert_eq!(
        format!("{:?}", EngineEvent::Unreachable { pair, diagnosis: d }),
        "EngineEvent(..)"
    );
    assert_eq!(ConnectError::Internal.to_string(), "internal error");
}

#[test]
fn allow_set_denies_by_default() {
    let allow = AllowSet::new();
    assert!(!allow.is_allowed(&PairId::from_bytes([1; 16])));
}
