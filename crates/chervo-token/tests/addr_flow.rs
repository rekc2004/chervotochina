//! Кадр ADDR_INFO и обмен по `chervo_transport::Connection` на потоках в памяти (без tokio).
//! Сетевой сквозной тест через quinn лежит в `chervo-friends` (часть A5).

mod common;

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use chervo_addr::{LocalSnapshot, OwnAddrs, PublishCtx, PublishSet, RouteSources};
use chervo_identity::{PairId, PairKey, PublicKey};
use chervo_token::addr_flow::{
    PeerAddrInfo, answer_addr_info, decode_addr_info, encode_addr_info, exchange_addr_info,
};
use chervo_token::{
    ADDR_INFO_MAX_LEN, ADDR_UPDATE_MAX_LEN, ADDR_UPDATE_MIN_LEN, AddrFlowError, IssuedAddrUpdate,
    PROTO_V1, STREAM_ADDR_INFO, issue_addr_update,
};
use chervo_transport::{Connection, RecvStream, SendStream, TransportError};
use common::*;

const NOW: u64 = 1_000_000;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn set_of(v4: &str) -> PublishSet {
    let mut o = OwnAddrs::new();
    o.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some(v4.parse().unwrap()),
            v6: None,
        },
        listen: vec![sa("0.0.0.0:4000")],
    });
    o.publishable(PublishCtx::default(), NOW)
}

fn issued(from: &PairKey, to: &PublicKey, seq: u64, v4: &str) -> IssuedAddrUpdate {
    issue_addr_update(from, to, seq, &set_of(v4)).unwrap()
}

// ---------- потоки и соединение в памяти (как в tests/flow.rs) ----------

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

/// Номера соединений тестовых заглушек: по возрастанию, без повторов (контракт `conn_id`).
fn next_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

struct MemConn {
    id: u64,
    pair: PairId,
    remote: SocketAddr,
    streams: Mutex<Option<(MemTx, MemRx)>>,
}

impl MemConn {
    fn streams_untouched(&self) -> bool {
        self.streams.lock().unwrap().is_some()
    }
}

impl Connection for MemConn {
    type Tx = MemTx;
    type Rx = MemRx;

    fn remote_pair(&self) -> PairId {
        self.pair
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
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

    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_initiator(&self) -> bool {
        false
    }

    fn closed(&self) -> impl Future<Output = ()> + Send {
        std::future::pending()
    }
}

struct Link {
    /// Принимающая сторона; видит друга по адресу `a_sees_b`.
    a: MemConn,
    /// Открывающая сторона; видит друга по адресу `b_sees_a`.
    b: MemConn,
    a_to_b: Arc<Pipe>,
    b_to_a: Arc<Pipe>,
}

const A_SEES_B: &str = "8.8.8.8:1111";
const B_SEES_A: &str = "9.9.9.9:2222";

fn link(pair: PairId) -> Link {
    let a_to_b = Arc::new(Pipe::default());
    let b_to_a = Arc::new(Pipe::default());
    Link {
        a: MemConn {
            id: next_id(),
            pair,
            remote: sa(A_SEES_B),
            streams: Mutex::new(Some((MemTx(a_to_b.clone()), MemRx(b_to_a.clone())))),
        },
        b: MemConn {
            id: next_id(),
            pair,
            remote: sa(B_SEES_A),
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

/// Диспетчер принимающей стороны: принять поток, прочитать нулевой байт, вызвать `answer`.
async fn dispatch_answer(
    conn: &MemConn,
    pair: &PairId,
    ours: Option<&IssuedAddrUpdate>,
) -> Result<PeerAddrInfo, AddrFlowError> {
    let (tx, mut rx) = conn.accept_bi().await?;
    let mut kind = [0u8; 1];
    let n = rx.read(&mut kind).await?;
    assert_eq!(n, Some(1));
    assert_eq!(kind[0], STREAM_ADDR_INFO);
    answer_addr_info(conn, pair, tx, rx, ours).await
}

fn queued(p: &Pipe) -> usize {
    p.buf.lock().unwrap().len()
}

fn frame_v4(update: Option<&IssuedAddrUpdate>) -> Vec<u8> {
    encode_addr_info(sa("203.0.113.5:4443"), update).unwrap()
}

// ---------- кадр ----------

#[test]
fn addr_info_roundtrip() {
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 5, "8.8.4.4");
    // без обновления
    let f = encode_addr_info(sa("8.8.8.8:443"), None).unwrap();
    assert_eq!(f.len(), 11);
    assert_eq!(f[0], STREAM_ADDR_INFO);
    assert_eq!(f[1], PROTO_V1);
    let (obs, u) = decode_addr_info(&f).unwrap();
    assert_eq!(obs, sa("8.8.8.8:443"));
    assert!(u.is_none());
    // с обновлением, IPv6
    let f = encode_addr_info(sa("[2606:4700::1]:443"), Some(&upd)).unwrap();
    assert_eq!(f.len(), 2 + 19 + 2 + upd.bytes().len());
    let (obs, u) = decode_addr_info(&f).unwrap();
    assert_eq!(obs, sa("[2606:4700::1]:443"));
    let verified = u.unwrap().verify(&a.public_key(), &b.public_key()).unwrap();
    assert_eq!(verified.seq(), 5);
    // петлевой наблюдаемый адрес допустим (сквозные тесты идут по loopback)
    let f = encode_addr_info(sa("127.0.0.1:5000"), None).unwrap();
    assert_eq!(decode_addr_info(&f).unwrap().0, sa("127.0.0.1:5000"));
    // наибольший кадр: IPv6 и 235 байт обновления
    let mut f = vec![STREAM_ADDR_INFO, PROTO_V1, 6];
    f.extend_from_slice(
        &"2606:4700::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    f.extend_from_slice(&443u16.to_be_bytes());
    f.extend_from_slice(&u16::try_from(ADDR_UPDATE_MAX_LEN).unwrap().to_be_bytes());
    let mut body = vec![1u8, 3];
    body.extend_from_slice(&7u64.to_be_bytes());
    body.push(8);
    for i in 0..8 {
        body.extend(enc_addr(&sa(&format!("[2606:4700::{}]:4000", i + 1))));
        body.push(1);
    }
    body.extend_from_slice(&[0u8; 64]);
    assert_eq!(body.len(), ADDR_UPDATE_MAX_LEN);
    f.extend_from_slice(&body);
    assert_eq!(f.len(), ADDR_INFO_MAX_LEN);
    assert!(decode_addr_info(&f).is_ok());
}

#[test]
fn addr_info_every_truncation() {
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 5, "8.8.4.4");
    for ours in [None, Some(&upd)] {
        for obs in ["8.8.8.8:443", "[2606:4700::1]:443"] {
            let f = encode_addr_info(sa(obs), ours).unwrap();
            assert!(decode_addr_info(&f).is_ok());
            for len in 0..f.len() {
                assert_eq!(
                    decode_addr_info(&f[..len]).err(),
                    Some(AddrFlowError::Malformed),
                    "{obs} префикс {len}"
                );
            }
        }
    }
}

#[test]
fn addr_info_len_field_bounds() {
    // заголовок IPv4 и произвольное поле длины
    let header = |declared: u16| {
        let mut f = vec![STREAM_ADDR_INFO, PROTO_V1, 4, 8, 8, 8, 8, 0x01, 0xBB];
        f.extend_from_slice(&declared.to_be_bytes());
        f
    };
    let mut declared: Vec<u16> = (1..=82).collect();
    declared.extend(
        (236..=65_535u32)
            .step_by(37)
            .map(|v| u16::try_from(v).unwrap()),
    );
    declared.extend([
        236, 237, 258, 259, 300, 1000, 0x7FFF, 0x8000, 65_534, 65_535,
    ]);
    for d in declared {
        // поле длины без тела
        assert_eq!(
            decode_addr_info(&header(d)).err(),
            Some(AddrFlowError::Malformed),
            "declared {d}"
        );
        // поле длины и ровно столько байт тела (кадр не длиннее предела)
        let mut f = header(d);
        let body = usize::from(d).min(300);
        f.extend(std::iter::repeat_n(0u8, body));
        assert_eq!(
            decode_addr_info(&f).err(),
            Some(AddrFlowError::Malformed),
            "declared {d} с телом"
        );
    }
    // длина 0 допустима, 83 с нулевым телом разбирается и отвергается как обновление
    assert!(decode_addr_info(&header(0)).is_ok());
    let mut f = header(u16::try_from(ADDR_UPDATE_MIN_LEN).unwrap());
    f.extend(std::iter::repeat_n(0u8, ADDR_UPDATE_MIN_LEN));
    assert_eq!(decode_addr_info(&f).err(), Some(AddrFlowError::Malformed));
    // заявленная длина не совпадает с остатком кадра
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 1, "8.8.4.4");
    let good = frame_v4(Some(&upd));
    let n = good.len();
    let mut short = good.clone();
    short[n - upd.bytes().len() - 1] = short[n - upd.bytes().len() - 1].wrapping_add(1);
    assert_eq!(
        decode_addr_info(&short).err(),
        Some(AddrFlowError::Malformed)
    );
}

#[test]
fn addr_info_trailing_rejected() {
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 1, "8.8.4.4");
    for ours in [None, Some(&upd)] {
        let good = frame_v4(ours);
        for extra in [1usize, 2, 8, 64] {
            let mut f = good.clone();
            f.extend(std::iter::repeat_n(0u8, extra));
            assert_eq!(
                decode_addr_info(&f).err(),
                Some(AddrFlowError::Malformed),
                "+{extra}"
            );
        }
    }
}

#[test]
fn addr_info_bad_header() {
    let good = encode_addr_info(sa("8.8.8.8:443"), None).unwrap();
    assert!(decode_addr_info(&good).is_ok());
    let patch = |i: usize, v: u8| {
        let mut f = good.clone();
        f[i] = v;
        decode_addr_info(&f).err()
    };
    for v in [0u8, 0x20, 0x22, 0x11, 0xFF] {
        assert_eq!(patch(0, v), Some(AddrFlowError::Malformed), "kind {v:#x}");
    }
    for v in [0u8, 2, 0xFF] {
        assert_eq!(patch(1, v), Some(AddrFlowError::Malformed), "proto {v:#x}");
    }
    for v in [0u8, 3, 5, 7, 0xFF] {
        assert_eq!(patch(2, v), Some(AddrFlowError::Malformed), "family {v:#x}");
    }
    // порт 0
    let mut f = good.clone();
    f[7] = 0;
    f[8] = 0;
    assert_eq!(decode_addr_info(&f).err(), Some(AddrFlowError::Malformed));
    // неуказанный, multicast, широковещательный IPv4
    for ip in [
        [0u8, 0, 0, 0],
        [224, 0, 0, 1],
        [239, 1, 1, 1],
        [255, 255, 255, 255],
    ] {
        let mut f = good.clone();
        f[3..7].copy_from_slice(&ip);
        assert_eq!(
            decode_addr_info(&f).err(),
            Some(AddrFlowError::Malformed),
            "{ip:?}"
        );
    }
    // IPv6: неуказанный, multicast, v4-mapped
    for ip in ["::", "ff02::1", "::ffff:8.8.8.8"] {
        let mut f = vec![STREAM_ADDR_INFO, PROTO_V1, 6];
        f.extend_from_slice(&ip.parse::<std::net::Ipv6Addr>().unwrap().octets());
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            decode_addr_info(&f).err(),
            Some(AddrFlowError::Malformed),
            "{ip}"
        );
    }
    // кодирование отвергает то же самое
    for bad in [
        "8.8.8.8:0",
        "0.0.0.0:1",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "[::]:1",
        "[ff02::1]:1",
        "[::ffff:8.8.8.8]:1",
    ] {
        assert_eq!(
            encode_addr_info(sa(bad), None).err(),
            Some(AddrFlowError::Malformed),
            "{bad}"
        );
    }
}

// ---------- обмен ----------

#[test]
fn addr_flow_memconn_exchange() {
    let (a_key, b_key) = (key(), key());
    let pair = PairId::generate().unwrap();
    let l = link(pair);
    let a_upd = issued(&a_key, &b_key.public_key(), 10, "8.8.4.4").for_pair(pair);
    let b_upd = issued(&b_key, &a_key.public_key(), 20, "1.1.1.1").for_pair(pair);
    let (ua, ub) = (a_upd.clone(), b_upd.clone());
    let ta = std::thread::spawn(move || block_on(dispatch_answer(&l.a, &pair, Some(&ua))));
    let tb = std::thread::spawn(move || block_on(exchange_addr_info(&l.b, &pair, Some(&ub))));
    let ra = ta.join().unwrap().unwrap();
    let rb = tb.join().unwrap().unwrap();
    // каждая сторона узнала, как её видит друг, и откуда пришёл друг
    assert_eq!(ra.observed_me, sa(B_SEES_A));
    assert_eq!(ra.via, sa(A_SEES_B));
    assert_eq!(rb.observed_me, sa(A_SEES_B));
    assert_eq!(rb.via, sa(B_SEES_A));
    // и получила его обновление
    let at_a = ra
        .update
        .unwrap()
        .verify(&b_key.public_key(), &a_key.public_key())
        .unwrap();
    assert_eq!(at_a.seq(), 20);
    let at_b = rb
        .update
        .unwrap()
        .verify(&a_key.public_key(), &b_key.public_key())
        .unwrap();
    assert_eq!(at_b.seq(), 10);
    assert!(l.a_to_b.finished.load(Ordering::SeqCst));
    assert!(l.b_to_a.finished.load(Ordering::SeqCst));
}

#[test]
fn addr_flow_memconn_exchange_without_updates() {
    let pair = PairId::generate().unwrap();
    let l = link(pair);
    let ta = std::thread::spawn(move || block_on(dispatch_answer(&l.a, &pair, None)));
    let tb = std::thread::spawn(move || block_on(exchange_addr_info(&l.b, &pair, None)));
    let (ra, rb) = (ta.join().unwrap().unwrap(), tb.join().unwrap().unwrap());
    assert!(ra.update.is_none() && rb.update.is_none());
    assert_eq!(ra.observed_me, sa(B_SEES_A));
    assert_eq!(rb.observed_me, sa(A_SEES_B));
    assert_eq!(format!("{ra:?}"), "PeerAddrInfo(..)");
}

#[test]
fn addr_flow_mapped_remote_is_normalized() {
    let pair = PairId::generate().unwrap();
    let mut l = link(pair);
    l.a.remote = sa("[::ffff:8.8.8.8]:1111");
    let ta = std::thread::spawn(move || block_on(dispatch_answer(&l.a, &pair, None)));
    let tb = std::thread::spawn(move || block_on(exchange_addr_info(&l.b, &pair, None)));
    let (ra, rb) = (ta.join().unwrap().unwrap(), tb.join().unwrap().unwrap());
    assert_eq!(ra.via, sa("8.8.8.8:1111"));
    assert_eq!(rb.observed_me, sa("8.8.8.8:1111"));
}

#[test]
fn addr_flow_wrong_peer_sends_nothing() {
    let (p1, p2) = (PairId::generate().unwrap(), PairId::generate().unwrap());
    // соединяющая сторона
    let l = link(p1);
    let r = block_on(exchange_addr_info(&l.b, &p2, None));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert!(l.b.streams_untouched(), "поток не открывался");
    assert_eq!(queued(&l.a_to_b), 0);
    assert_eq!(queued(&l.b_to_a), 0);
    assert!(!l.b_to_a.finished.load(Ordering::SeqCst));
    // принимающая сторона: вход уже подан, ответ не пишется
    let l = link(p1);
    let f = frame_v4(None);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(f.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    let r = block_on(answer_addr_info(&l.a, &p2, tx, rx, None));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert_eq!(queued(&l.a_to_b), 0);
    assert!(!l.a_to_b.finished.load(Ordering::SeqCst));
}

#[test]
fn addr_flow_unbound_update_sends_nothing() {
    let pair = PairId::generate().unwrap();
    let (a, b) = (key(), key());
    let unbound = issued(&a, &b.public_key(), 5, "8.8.4.4");
    // соединяющая сторона: токен без пары не уходит
    let l = link(pair);
    let r = block_on(exchange_addr_info(&l.b, &pair, Some(&unbound)));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert!(l.b.streams_untouched(), "поток не открывался");
    assert_eq!(queued(&l.b_to_a), 0);
    // принимающая сторона: ответ не пишется
    let l = link(pair);
    let f = frame_v4(None);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(f.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    let r = block_on(answer_addr_info(&l.a, &pair, tx, rx, Some(&unbound)));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert_eq!(queued(&l.a_to_b), 0);
}

#[test]
fn addr_flow_update_for_other_pair_sends_nothing() {
    let (f_pair, g_pair) = (PairId::generate().unwrap(), PairId::generate().unwrap());
    let (a, b) = (key(), key());
    // обновление выпущено для друга G, а соединение принадлежит F
    let for_g = issued(&a, &b.public_key(), 5, "8.8.4.4").for_pair(g_pair);
    assert_eq!(for_g.pair(), Some(g_pair));
    // привязка не меняет формат: те же байты, что и без неё
    assert_eq!(
        for_g.bytes(),
        issued(&a, &b.public_key(), 5, "8.8.4.4").bytes()
    );
    // соединяющая сторона
    let l = link(f_pair);
    let r = block_on(exchange_addr_info(&l.b, &f_pair, Some(&for_g)));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert!(l.b.streams_untouched(), "поток не открывался");
    assert_eq!(queued(&l.a_to_b), 0);
    assert_eq!(queued(&l.b_to_a), 0);
    assert!(!l.b_to_a.finished.load(Ordering::SeqCst));
    // принимающая сторона: вход подан, ответ не пишется
    let l = link(f_pair);
    let f = frame_v4(None);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(f.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    let r = block_on(answer_addr_info(&l.a, &f_pair, tx, rx, Some(&for_g)));
    assert_eq!(r.err(), Some(AddrFlowError::WrongPeer));
    assert_eq!(queued(&l.a_to_b), 0);
    assert!(!l.a_to_b.finished.load(Ordering::SeqCst));
    // положительный контроль: токен, выпущенный для F, уходит по соединению F
    let for_f = issued(&a, &b.public_key(), 6, "8.8.4.4").for_pair(f_pair);
    let l = link(f_pair);
    let f = frame_v4(None);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(f.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    block_on(answer_addr_info(&l.a, &f_pair, tx, rx, Some(&for_f))).unwrap();
    assert!(queued(&l.a_to_b) > 0);
}

#[test]
fn addr_flow_trailing_after_frame() {
    let pair = PairId::generate().unwrap();
    // принимающая сторона: после кадра ещё байт, ответ не пишется
    let l = link(pair);
    let mut f = frame_v4(None);
    f.push(0);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(f.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    let r = block_on(answer_addr_info(&l.a, &pair, tx, rx, None));
    assert_eq!(r.err(), Some(AddrFlowError::TrailingData));
    assert_eq!(queued(&l.a_to_b), 0);
    // соединяющая сторона: то же в ответе
    let l = link(pair);
    let mut f = frame_v4(None);
    f.extend([1u8, 2, 3]);
    l.a_to_b.buf.lock().unwrap().extend(f.iter().copied());
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    let r = block_on(exchange_addr_info(&l.b, &pair, None));
    assert_eq!(r.err(), Some(AddrFlowError::TrailingData));
    // кадр с обновлением и лишний байт
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 1, "8.8.4.4");
    let l = link(pair);
    let mut f = frame_v4(Some(&upd));
    f.push(9);
    l.a_to_b.buf.lock().unwrap().extend(f.iter().copied());
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    let r = block_on(exchange_addr_info(&l.b, &pair, None));
    assert_eq!(r.err(), Some(AddrFlowError::TrailingData));
}

#[test]
fn addr_flow_truncated_and_bad_streams() {
    let pair = PairId::generate().unwrap();
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 1, "8.8.4.4");
    let good = frame_v4(Some(&upd));
    // поток закончился раньше кадра: каждая длина короче полного
    for len in 0..good.len() {
        let l = link(pair);
        l.a_to_b
            .buf
            .lock()
            .unwrap()
            .extend(good[..len].iter().copied());
        l.a_to_b.finished.store(true, Ordering::SeqCst);
        let r = block_on(exchange_addr_info(&l.b, &pair, None));
        let e = r.err();
        // до заголовка и поля длины поток просто короче; ошибки разбора по содержимому
        // здесь невозможны, потому что префикс корректного кадра корректен
        assert_eq!(e, Some(AddrFlowError::Truncated), "префикс {len}");
    }
    // неверный заголовок: ошибка до чтения остального
    let mut bad = good.clone();
    bad[1] = 9;
    let l = link(pair);
    l.a_to_b.buf.lock().unwrap().extend(bad.iter().copied());
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(exchange_addr_info(&l.b, &pair, None)).err(),
        Some(AddrFlowError::Malformed)
    );
    // длина вне границ: Malformed без чтения тела
    let mut over = vec![
        STREAM_ADDR_INFO,
        PROTO_V1,
        4,
        8,
        8,
        8,
        8,
        1,
        187,
        0xFF,
        0xFF,
    ];
    over.extend(std::iter::repeat_n(0u8, 5));
    let l = link(pair);
    l.a_to_b.buf.lock().unwrap().extend(over.iter().copied());
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(exchange_addr_info(&l.b, &pair, None)).err(),
        Some(AddrFlowError::Malformed)
    );
    // кадр структурно верный, но обновление не разбирается: Malformed
    let mut broken = good.clone();
    let start = broken.len() - upd.bytes().len();
    broken[start] = 2; // неизвестная версия обновления
    let l = link(pair);
    l.a_to_b.buf.lock().unwrap().extend(broken.iter().copied());
    l.a_to_b.finished.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(exchange_addr_info(&l.b, &pair, None)).err(),
        Some(AddrFlowError::Malformed)
    );
    // принимающая сторона: свой кадр после разбора ошибки не пишется
    let l = link(pair);
    l.b_to_a
        .buf
        .lock()
        .unwrap()
        .extend(broken.iter().skip(1).copied());
    l.b_to_a.finished.store(true, Ordering::SeqCst);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    assert_eq!(
        block_on(answer_addr_info(&l.a, &pair, tx, rx, None)).err(),
        Some(AddrFlowError::Malformed)
    );
    assert_eq!(queued(&l.a_to_b), 0);
    assert!(!l.a_to_b.finished.load(Ordering::SeqCst));
}

#[test]
fn addr_flow_futures_are_send() {
    fn is_send<T: Send>(_: &T) {}
    let pair = PairId::generate().unwrap();
    let l = link(pair);
    let f = exchange_addr_info(&l.b, &pair, None);
    is_send(&f);
    drop(f);
    let (tx, rx) = block_on(l.a.accept_bi()).unwrap();
    let g = answer_addr_info(&l.a, &pair, tx, rx, None);
    is_send(&g);
    drop(g);
    // и вместе с обновлением по ссылке
    let (a, b) = (key(), key());
    let upd = issued(&a, &b.public_key(), 1, "8.8.4.4");
    let l2 = link(pair);
    let h = exchange_addr_info(&l2.b, &pair, Some(&upd));
    is_send(&h);
}
