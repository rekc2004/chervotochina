use std::future::Future;
use std::task::{Context, Poll, Waker};

use chervo_identity::DeviceId;
use chervo_transport::{DenyAll, NullTransport, PeerAddr, PeerFilter, Transport, TransportError};

fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    f.as_mut().poll(&mut cx)
}

#[test]
fn deny_all_denies() {
    assert!(!DenyAll.is_allowed(&DeviceId::from_bytes([1; 32])));
}

#[test]
fn null_transport_fails_closed() {
    let t = NullTransport;
    let peer = PeerAddr {
        id: DeviceId::from_bytes([1; 32]),
        addrs: Vec::new(),
    };
    assert!(matches!(
        poll_once(t.connect(&peer)),
        Poll::Ready(Err(TransportError::NotImplemented))
    ));
    assert!(matches!(
        poll_once(t.accept()),
        Poll::Ready(Err(TransportError::NotImplemented))
    ));
    assert!(t.local_addrs().is_empty());
}
