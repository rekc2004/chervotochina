//! Обмен по `chervo_transport::Connection` на потоках в памяти (без tokio): честный путь,
//! обрывы, неверные сообщения. Сетевые сквозные тесты через quinn лежат в `chervo-friends`.

mod common;

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use chervo_identity::PairId;
use chervo_token::flow::{InviteChannel, exchange_decision, invitee_exchange, inviter_exchange};
use chervo_token::{FlowError, InviteError, InviteeSession, M1_LEN, PendingInvite, issue_invite};
use chervo_transport::{Connection, NullConnection, RecvStream, SendStream, TransportError};
use common::*;

#[derive(Default)]
struct Pipe {
    buf: Mutex<VecDeque<u8>>,
    finished: AtomicBool,
}

struct MemTx(Arc<Pipe>);
struct MemRx(Arc<Pipe>);

impl SendStream for MemTx {
    fn write_all(&mut self, b: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send {
        self.0.buf.lock().unwrap().extend(b.iter().copied());
        std::future::ready(Ok(()))
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        self.0.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl RecvStream for MemRx {
    fn read(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, TransportError>> + Send {
        let pipe = self.0.clone();
        std::future::poll_fn(move |cx| {
            let mut q = pipe.buf.lock().unwrap();
            if q.is_empty() {
                if pipe.finished.load(Ordering::SeqCst) {
                    return Poll::Ready(Ok(None));
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut n = 0;
            while n < buf.len() {
                match q.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            Poll::Ready(Ok(Some(n)))
        })
    }
}

struct MemConn {
    pair: PairId,
    streams: Mutex<Option<(MemTx, MemRx)>>,
}

impl Connection for MemConn {
    type Tx = MemTx;
    type Rx = MemRx;

    fn remote_pair(&self) -> PairId {
        self.pair
    }

    fn remote_addr(&self) -> std::net::SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    fn open_bi(&self) -> impl Future<Output = Result<(MemTx, MemRx), TransportError>> + Send {
        std::future::ready(
            self.streams
                .lock()
                .unwrap()
                .take()
                .ok_or(TransportError::Closed),
        )
    }

    fn accept_bi(&self) -> impl Future<Output = Result<(MemTx, MemRx), TransportError>> + Send {
        std::future::ready(
            self.streams
                .lock()
                .unwrap()
                .take()
                .ok_or(TransportError::Closed),
        )
    }

    fn close(&self) {}
}

/// Пара концов: (A принимает поток, B открывает поток) и трубы, чтобы вмешиваться снаружи.
struct Link {
    a: MemConn,
    b: MemConn,
    a_to_b: Arc<Pipe>,
    b_to_a: Arc<Pipe>,
}

fn link() -> Link {
    let a_to_b = Arc::new(Pipe::default());
    let b_to_a = Arc::new(Pipe::default());
    let pair = PairId::generate().unwrap();
    Link {
        a: MemConn {
            pair,
            streams: Mutex::new(Some((MemTx(a_to_b.clone()), MemRx(b_to_a.clone())))),
        },
        b: MemConn {
            pair,
            streams: Mutex::new(Some((MemTx(b_to_a.clone()), MemRx(a_to_b.clone())))),
        },
        a_to_b,
        b_to_a,
    }
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

type InviterOut = Result<bool, FlowError>;

fn run_inviter(
    conn: MemConn,
    mut pending: PendingInvite,
    confirm: bool,
) -> std::thread::JoinHandle<(InviterOut, Option<String>)> {
    std::thread::spawn(move || {
        block_on(async {
            pending.begin_session(1_000_100).unwrap();
            let (mut ch, sas, _keys) = match inviter_exchange(&conn, &mut pending).await {
                Ok(v) => v,
                Err(e) => return (Err(e), None),
            };
            let theirs = exchange_decision(&mut ch, confirm).await;
            (theirs, Some(sas.digits()))
        })
    })
}

fn run_invitee(
    conn: MemConn,
    session: InviteeSession,
    m1: [u8; M1_LEN],
    confirm: bool,
) -> std::thread::JoinHandle<(InviterOut, Option<String>)> {
    std::thread::spawn(move || {
        block_on(async {
            let (mut ch, sas) = match invitee_exchange(&conn, session, &m1).await {
                Ok(v) => v,
                Err(e) => return (Err(e), None),
            };
            let theirs = exchange_decision(&mut ch, confirm).await;
            (theirs, Some(sas.digits()))
        })
    })
}

#[test]
fn flow_honest_both_confirm() {
    let h = honest();
    let l = link();
    let ta = run_inviter(l.a, h.pending, true);
    let tb = run_invitee(l.b, h.session, h.m1, true);
    let (ra, sa) = ta.join().unwrap();
    let (rb, sb) = tb.join().unwrap();
    assert_eq!(ra, Ok(true));
    assert_eq!(rb, Ok(true));
    assert_eq!(sa, sb);
    assert!(sa.is_some());
}

#[test]
fn flow_reject_is_visible_to_peer() {
    for (ca, cb) in [(false, true), (true, false), (false, false)] {
        let h = honest();
        let l = link();
        let ta = run_inviter(l.a, h.pending, ca);
        let tb = run_invitee(l.b, h.session, h.m1, cb);
        assert_eq!(ta.join().unwrap().0, Ok(cb));
        assert_eq!(tb.join().unwrap().0, Ok(ca));
    }
}

#[test]
fn flow_truncated_m1_and_m2() {
    // B прислал половину M1 и закрыл поток
    let h = honest();
    let l = link();
    l.a_to_b.finished.store(false, Ordering::SeqCst);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(h.m1.iter().take(100).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let mut pending = h.pending;
    pending.begin_session(1_000_100).unwrap();
    let r = block_on(inviter_exchange(&l.a, &mut pending));
    assert_eq!(r.err(), Some(FlowError::Truncated));
    // состояние не потрачено: настоящий M1 ещё принимается
    assert!(pending.on_m1(&h.m1).is_ok());

    // A прислал неполный M2
    let h = honest();
    let l = link();
    l.a_to_b.buf.lock().unwrap().extend([0x12u8, 0x01, 0, 0]);
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    let r = block_on(invitee_exchange(&l.b, h.session, &h.m1));
    assert_eq!(r.err(), Some(FlowError::Truncated));
}

#[test]
fn flow_wrong_messages() {
    // M1 от другого приглашения
    let h = honest();
    let other = honest();
    let l = link();
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(other.m1.iter().copied());
    let mut pending = h.pending;
    pending.begin_session(1_000_100).unwrap();
    let r = block_on(inviter_exchange(&l.a, &mut pending));
    assert_eq!(r.err(), Some(FlowError::Invite(InviteError::WrongToken)));
    // ничего не записано в ответ
    assert!(l.a_to_b.buf.lock().unwrap().is_empty());

    // неверный M2 (чужое раскрытие)
    let h = honest();
    let mut other = honest();
    other.pending.begin_session(1_000_100).unwrap();
    let (other_m2, _, _) = other.pending.on_m1(&other.m1).unwrap();
    let l = link();
    l.a_to_b
        .buf
        .lock()
        .unwrap()
        .extend(other_m2.iter().copied());
    let r = block_on(invitee_exchange(&l.b, h.session, &h.m1));
    assert_eq!(
        r.err(),
        Some(FlowError::Invite(InviteError::CommitMismatch))
    );
}

#[test]
fn flow_decision_errors() {
    let h = honest();
    let l = link();
    let ta = {
        let mut pending = h.pending;
        let conn = l.a;
        std::thread::spawn(move || {
            block_on(async {
                pending.begin_session(1_000_100).unwrap();
                let (mut ch, _sas, _k) = inviter_exchange(&conn, &mut pending).await.unwrap();
                let r = exchange_decision(&mut ch, true).await;
                (r, ())
            })
            .0
        })
    };
    // B проходит обмен, но вместо решения закрывает поток
    let (_ch, _sas): (InviteChannel<MemConn>, _) =
        block_on(invitee_exchange(&l.b, h.session, &h.m1)).unwrap();
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    assert_eq!(ta.join().unwrap(), Err(FlowError::Truncated));
}

/// Фьючерсы обмена пригодны для `tokio::spawn`: должны быть `Send`.
#[allow(dead_code)]
fn futures_are_send(
    c: &NullConnection,
    p: &mut PendingInvite,
    s: InviteeSession,
    m: &[u8; M1_LEN],
) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&inviter_exchange(c, p));
    is_send(&invitee_exchange(c, s, m));
    let _ = issue_invite;
}
