use std::future::Future;
use std::task::{Context, Poll, Waker};

use chervo_connect::{ConnectError, PathKind, connect_direct};
use chervo_identity::DeviceId;
use chervo_transport::{NullTransport, PeerAddr};

fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    f.as_mut().poll(&mut cx)
}

/// Исчерпывающий match без `_`: новый вариант PathKind сломает компиляцию теста.
fn path_label(kind: PathKind) -> &'static str {
    match kind {
        PathKind::Lan => "lan",
        PathKind::Ipv6 => "ipv6",
        PathKind::PortMapped => "port-mapped",
        PathKind::SimultaneousOpen => "simultaneous-open",
    }
}

#[test]
fn connect_direct_fails_closed() {
    let peer = PeerAddr {
        id: DeviceId::from_bytes([2; 32]),
        addrs: Vec::new(),
    };
    assert!(matches!(
        poll_once(connect_direct(&NullTransport, &peer)),
        Poll::Ready(Err(ConnectError::NotImplemented))
    ));
    let labels = [
        path_label(PathKind::Lan),
        path_label(PathKind::Ipv6),
        path_label(PathKind::PortMapped),
        path_label(PathKind::SimultaneousOpen),
    ];
    assert_eq!(labels, ["lan", "ipv6", "port-mapped", "simultaneous-open"]);
}
