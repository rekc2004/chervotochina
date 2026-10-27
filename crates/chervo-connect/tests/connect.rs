//! Публичные типы слоя соединения (этап 13, C3): значения по умолчанию, закрытый по умолчанию
//! набор разрешённых пар.

use std::time::Duration;

use chervo_connect::{AllowSet, ConnectConfig};
use chervo_identity::PairId;
use chervo_transport::PeerFilter;

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
    assert_eq!(
        (
            c.extra_streams_in_per_min,
            c.stream_inbox_capacity,
            c.max_pending_kind_reads
        ),
        (60, 32, 4)
    );
    assert_eq!(c.invite_session, Duration::from_secs(300));
    assert_eq!(c.expire_interval, Duration::from_secs(60));
    assert_eq!(c.unreachable_after_fails, 3);
    assert_eq!(c.udp_blocked_window, Duration::from_secs(600));
    assert_eq!(c.udp_blocked_min_friends, 2);
}

#[test]
fn allow_set_denies_by_default() {
    let allow = AllowSet::new();
    assert!(!allow.is_allowed(&PairId::from_bytes([1; 16])));
}
