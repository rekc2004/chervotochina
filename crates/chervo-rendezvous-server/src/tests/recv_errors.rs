//! Разбор ошибок `recv_from`: сброс из-за ICMP пропускается без паузы (круг 1, находка 4).

use std::io::ErrorKind;

use crate::{RecvErrorKind, classify_recv_error};

#[test]
fn peer_reset_is_skipped_without_pause() {
    // WSAECONNRESET на Windows приходит как ConnectionReset; на других системах возможен Refused
    assert_eq!(
        classify_recv_error(ErrorKind::ConnectionReset),
        RecvErrorKind::PeerReset
    );
    assert_eq!(
        classify_recv_error(ErrorKind::ConnectionRefused),
        RecvErrorKind::PeerReset
    );
}

#[test]
fn timeouts_are_quiet_and_others_pause() {
    for k in [
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
        ErrorKind::Interrupted,
    ] {
        assert_eq!(classify_recv_error(k), RecvErrorKind::Quiet, "{k:?}");
    }
    for k in [
        ErrorKind::PermissionDenied,
        ErrorKind::OutOfMemory,
        ErrorKind::Other,
        ErrorKind::BrokenPipe,
    ] {
        assert_eq!(classify_recv_error(k), RecvErrorKind::Other, "{k:?}");
    }
}
