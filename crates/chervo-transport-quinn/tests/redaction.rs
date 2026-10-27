#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода транспорта (этап 17, B3, решение 1c; BRIEF 7, T8, T15(в)): `Debug` и
//! `Display` транспорта, конфигурации, счётчиков, событий и ошибок не содержат адреса
//! прослушивания, порта, поправки часов. Живое соединение `QuinnConn` проверяется в сквозном
//! сценарии `chervo-receive/tests/no_leaks.rs`.

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::sync::Arc;

use chervo_identity::PairId;
use chervo_transport::{DuplicatePairError, PeerFilter, Transport, TransportError, TransportEvent};
use chervo_transport_quinn::{ClockOffsetError, QuinnConfig, QuinnTransport};
use common::AllowAll;
use redact_kit::{Needles, Out, assert_fixed_text, check};

#[tokio::test]
async fn quinn_types_hide_addresses_and_clock_offset() {
    let filter: Arc<dyn PeerFilter> = Arc::new(AllowAll);
    let t = QuinnTransport::bind(
        "127.0.0.1:0".parse().unwrap(),
        QuinnConfig::default(),
        filter,
    )
    .unwrap();
    let port = t.local_addrs()[0].port();
    t.set_clock_offset(3_141_592).unwrap();
    let range_err = t.set_clock_offset(i64::MAX).unwrap_err();
    let pair = PairId::from_bytes([0x24; 16]);

    let mut out = Out::new();
    out.dbg("QuinnTransport", &t);
    out.dbg("QuinnConfig", &QuinnConfig::default());
    out.dbg("TransportStats", &t.stats());
    out.err("ClockOffsetError", &range_err);
    out.dbg(
        "TransportEvent",
        &TransportEvent::RemoteAddrChanged { pair },
    );
    out.dbg("TransportEvent", &TransportEvent::PeerRemoved { pair });
    out.dbg(
        "TransportEvent",
        &TransportEvent::ClockSkewSuspected { pair },
    );
    out.dbg(
        "TransportEvent",
        &TransportEvent::ConnectionReplaced { pair },
    );
    out.dbg("TransportEvent", &TransportEvent::Lagged);
    out.err("DuplicatePairError", &DuplicatePairError);
    for e in all_transport_errors() {
        out.err("TransportError", &e);
    }

    let mut n = Needles::new();
    n.add("ip", "127.0.0.1");
    n.add("port", format!(":{port}"));
    n.add("clock offset", "3141592");
    n.bytes("pair", pair.as_bytes());
    check(&out, &n);
}

fn all_transport_errors() -> Vec<TransportError> {
    use TransportError::*;
    vec![
        NotImplemented,
        PeerNotAllowed,
        Closed,
        AuthFailed,
        TimedOut,
        UnknownPair,
        Io,
        Duplicate,
        Busy,
        NoResponse,
    ]
}

#[test]
fn transport_errors_have_fixed_text() {
    for e in all_transport_errors() {
        assert_fixed_text("TransportError display", &e.to_string());
        assert_fixed_text("TransportError debug", &format!("{e:?}"));
    }
    assert_fixed_text("DuplicatePairError", &DuplicatePairError.to_string());
    assert_fixed_text("ClockOffsetError", &ClockOffsetError.to_string());
}
