use std::future::Future;
use std::task::{Context, Poll, Waker};

use chervo_identity::PairId;
use chervo_transport::{DenyAll, NullTransport, PeerAddr, PeerFilter, Transport, TransportError};

fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    f.as_mut().poll(&mut cx)
}

#[test]
fn deny_all_denies() {
    assert!(!DenyAll.is_allowed(&PairId::from_bytes([1; 16])));
}

#[test]
fn null_transport_fails_closed() {
    let t = NullTransport;
    let peer = PeerAddr {
        pair: PairId::from_bytes([1; 16]),
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
