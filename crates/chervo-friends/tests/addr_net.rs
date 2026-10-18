#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Сквозные сетевые тесты обмена адресами (этап 12, часть A5): две `QuinnTransport` на
//! loopback со стуком; кадр ADDR_INFO идёт только по соединению, прошедшему Noise KK.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chervo_addr::{LocalSnapshot, ObserveOutcome, OwnAddrs, PublishCtx, PublishSet, RouteSources};
use chervo_friends::{FriendBook, FriendsError, NewFriend, PendingRole};
use chervo_identity::{KxPeer, PairId, PairKey, create};
use chervo_token::addr_flow::{PeerAddrInfo, answer_addr_info, exchange_addr_info};
use chervo_token::{AddrFlowError, IssuedAddrUpdate, STREAM_ADDR_INFO, decode_addr_update_bin};
use chervo_transport::{Connection, PeerAddr, PeerFilter, RecvStream, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnConn, QuinnTransport};
use common::*;

struct AllowAll;

impl PeerFilter for AllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cfg(deadline: Duration) -> QuinnConfig {
    QuinnConfig {
        auth_deadline: deadline,
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

struct Party {
    dir: TestDir,
    store: MemStore,
    book: FriendBook,
    t: QuinnTransport,
    addr: SocketAddr,
}

impl Party {
    fn new() -> Self {
        Self::with(cfg(Duration::from_secs(5)))
    }

    fn with(cfg: QuinnConfig) -> Self {
        let dir = TestDir::new();
        let store = MemStore::default();
        let book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
        let t =
            QuinnTransport::bind("127.0.0.1:0".parse().unwrap(), cfg, Arc::new(AllowAll)).unwrap();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), t.local_addrs()[0].port());
        Self {
            dir,
            store,
            book,
            t,
            addr,
        }
    }

    /// `set_peers(kx_peers)`: после любого изменения книги.
    fn publish(&self) {
        let (peers, bad) = self.book.kx_peers(&self.store).unwrap();
        assert!(bad.is_empty());
        self.t.set_peers(peers).unwrap();
    }

    fn file(&self) -> Vec<u8> {
        std::fs::read(self.dir.file()).unwrap()
    }
}

fn new_f(theirs: &PairKey, ours: &PairKey) -> NewFriend {
    NewFriend {
        name: "friend".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: Vec::new(),
        now_unix: 1,
    }
}

/// Дружба без приглашения: у каждой стороны своя запись пары и зеркальные ключи
/// (приглашение проверено в `invite_net.rs`). Возвращает (пара у `a`, пара у `b`).
fn befriend(a: &mut Party, b: &mut Party) -> (PairId, PairId) {
    let (pa, ka) = a
        .book
        .begin_pair(&a.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (pb, kb) = b
        .book
        .begin_pair(&b.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    a.book.finish_pair(&a.store, &pa, new_f(&kb, &ka)).unwrap();
    b.book.finish_pair(&b.store, &pb, new_f(&ka, &kb)).unwrap();
    a.publish();
    b.publish();
    (pa, pb)
}

/// Набор для публикации, построенный только через `OwnAddrs` (адреса не контактируются).
fn publish_set(route_v4: &str, port: u16) -> PublishSet {
    let mut o = OwnAddrs::new();
    o.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some(route_v4.parse().unwrap()),
            v6: None,
        },
        listen: vec![format!("0.0.0.0:{port}").parse().unwrap()],
    });
    let set = o.publishable(PublishCtx::default(), now_unix());
    assert!(!set.is_empty());
    set
}

/// `from` звонит `to`: (соединение звонящего, соединение принявшего).
async fn link(from: &Party, from_pair: PairId, to: &Party) -> (QuinnConn, QuinnConn) {
    let addr = PeerAddr {
        pair: from_pair,
        addrs: vec![to.addr],
    };
    let (c, s) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(from.t.connect(&addr), to.t.accept())
    })
    .await
    .expect("соединение не установлено за 10 с");
    (c.unwrap(), s.unwrap())
}

/// Диспетчер принимающей стороны: поток, нулевой байт вида, `answer_addr_info`.
async fn answer(
    conn: &QuinnConn,
    pair: &PairId,
    ours: Option<&IssuedAddrUpdate>,
) -> Result<PeerAddrInfo, AddrFlowError> {
    let (tx, mut rx) = conn.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    assert_eq!(rx.read(&mut kind).await.unwrap(), Some(1));
    assert_eq!(kind[0], STREAM_ADDR_INFO);
    answer_addr_info(conn, pair, tx, rx, ours).await
}

/// Один обмен: `caller` открывает поток, `callee` отвечает. Возвращает (итог звонящего,
/// итог принявшего).
async fn run_exchange(
    caller: &QuinnConn,
    caller_pair: &PairId,
    caller_update: Option<&IssuedAddrUpdate>,
    callee: &QuinnConn,
    callee_pair: &PairId,
    callee_update: Option<&IssuedAddrUpdate>,
) -> (
    Result<PeerAddrInfo, AddrFlowError>,
    Result<PeerAddrInfo, AddrFlowError>,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            exchange_addr_info(caller, caller_pair, caller_update),
            answer(callee, callee_pair, callee_update)
        )
    })
    .await
    .expect("обмен ADDR_INFO завис")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addr_info_end_to_end_quinn() {
    let (mut a, mut b) = (Party::new(), Party::new());
    let (pa, pb) = befriend(&mut a, &mut b);
    let now = now_unix();
    let (conn_b, conn_a) = link(&b, pb, &a).await;
    assert_eq!(conn_a.remote_pair(), pa);
    assert_eq!(conn_b.remote_pair(), pb);
    let set_a = publish_set("8.8.8.8", 4000);
    let set_b = publish_set("1.1.1.1", 4001);
    let ua = a
        .book
        .issue_addr_update(&a.store, &pa, &set_a, now)
        .unwrap();
    let ub = b
        .book
        .issue_addr_update(&b.store, &pb, &set_b, now)
        .unwrap();
    let (rb, ra) = run_exchange(&conn_b, &pb, Some(&ub), &conn_a, &pa, Some(&ua)).await;
    let (info_b, info_a) = (rb.unwrap(), ra.unwrap());
    // каждая сторона узнала, как её видит друг: это адрес её собственного сокета
    assert_eq!(info_b.observed_me, b.addr);
    assert_eq!(info_a.observed_me, a.addr);
    assert_eq!(info_b.via, a.addr);
    assert_eq!(info_a.via, b.addr);
    // loopback-путь: наблюдение не принимается (IgnoredLocalPath)
    let mut own_a = OwnAddrs::new();
    own_a.set_local(LocalSnapshot {
        route: RouteSources::default(),
        listen: vec![a.addr],
    });
    assert!(a.book.is_active(&pa));
    assert_eq!(
        own_a.observe(pa, info_a.via, info_a.observed_me, now),
        ObserveOutcome::IgnoredLocalPath
    );
    assert!(!own_a.stable_reachable(now));
    // обновление друга применяется; номер и адреса сохранены
    a.book
        .apply_addr_update(&a.store, &pa, &info_a.update.unwrap(), now)
        .unwrap();
    b.book
        .apply_addr_update(&b.store, &pb, &info_b.update.unwrap(), now)
        .unwrap();
    assert_eq!(a.book.get(&pa).unwrap().last_addr_seq, ub.seq());
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, ua.seq());
    assert_eq!(a.book.usable_addrs(&pa, now), set_b.socket_addrs());
    assert_eq!(b.book.usable_addrs(&pb, now), set_a.socket_addrs());
    // адрес, с которого друг подключился, запоминается как контакт
    a.book
        .note_contact(&a.store, &pa, conn_a.remote_addr(), now)
        .unwrap();
    assert!(a.book.usable_addrs(&pa, now).contains(&b.addr));
    let reopened = FriendBook::open_unanchored(&a.dir.file(), &a.store).unwrap();
    assert_eq!(reopened.get(&pa).unwrap().last_addr_seq, ub.seq());
    assert!(reopened.usable_addrs(&pa, now).contains(&b.addr));
    // соединение после обмена живо: второй обмен без обновлений
    let (rb, ra) = run_exchange(&conn_b, &pb, None, &conn_a, &pa, None).await;
    assert!(rb.unwrap().update.is_none() && ra.unwrap().update.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addr_info_replay_is_stale() {
    let (mut a, mut b) = (Party::new(), Party::new());
    let (pa, pb) = befriend(&mut a, &mut b);
    let now = now_unix();
    let (conn_b, conn_a) = link(&b, pb, &a).await;
    let set_b = publish_set("1.1.1.1", 4001);
    let ub = b
        .book
        .issue_addr_update(&b.store, &pb, &set_b, now)
        .unwrap();
    let (rb, ra) = run_exchange(&conn_b, &pb, Some(&ub), &conn_a, &pa, None).await;
    rb.unwrap();
    let first = ra.unwrap().update.unwrap();
    a.book
        .apply_addr_update(&a.store, &pa, &first, now)
        .unwrap();
    let file = a.file();
    // тот же выпущенный токен ещё раз: номер не выше принятого
    let (rb, ra) = run_exchange(&conn_b, &pb, Some(&ub), &conn_a, &pa, None).await;
    rb.unwrap();
    let again = ra.unwrap().update.unwrap();
    assert_eq!(
        a.book.apply_addr_update(&a.store, &pa, &again, now).err(),
        Some(FriendsError::StaleSeq)
    );
    // и спустя интервал ограничителя
    assert_eq!(
        a.book
            .apply_addr_update(&a.store, &pa, &again, now + 3600)
            .err(),
        Some(FriendsError::StaleSeq)
    );
    assert_eq!(a.file(), file, "повтор изменил файл списка");
    assert_eq!(a.book.get(&pa).unwrap().last_addr_seq, ub.seq());
    assert_eq!(a.book.usable_addrs(&pa, now), set_b.socket_addrs());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addr_info_other_pairs_update_rejected() {
    let (mut a, mut b, mut c) = (Party::new(), Party::new(), Party::new());
    let (pa_b, pb) = befriend(&mut a, &mut b);
    let (pa_c, pc) = befriend(&mut a, &mut c);
    let now = now_unix();
    // C выпускает обновление для своей пары с A; B пересылает его по СВОЕМУ соединению
    let set_c = publish_set("9.9.9.9", 4002);
    let from_c = c
        .book
        .issue_addr_update(&c.store, &pc, &set_c, now)
        .unwrap();
    let (conn_b, conn_a) = link(&b, pb, &a).await;
    assert_eq!(conn_a.remote_pair(), pa_b);
    assert_eq!(from_c.pair(), Some(pc));
    // честный помощник такой токен по соединению B не отправит (L2)
    assert_eq!(
        exchange_addr_info(&conn_b, &pb, Some(&from_c)).await.err(),
        Some(AddrFlowError::WrongPeer)
    );
    // злонамеренный B шлёт те же байты мимо помощника: A всё равно отвергает
    let forwarded = decode_addr_update_bin(from_c.bytes()).unwrap();
    let file = a.file();
    assert_eq!(
        a.book
            .apply_addr_update(&a.store, &pa_b, &forwarded, now)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    // ничего не записано ни под парой B, ни под парой C
    assert_eq!(a.file(), file);
    assert_eq!(a.book.get(&pa_b).unwrap().last_addr_seq, 0);
    assert!(a.book.usable_addrs(&pa_b, now).is_empty());
    assert!(a.book.usable_addrs(&pa_c, now).is_empty());
    // положительный контроль: то же обновление в своей паре проходит
    a.book
        .apply_addr_update(&a.store, &pa_c, &forwarded, now)
        .unwrap();
    assert_eq!(a.book.usable_addrs(&pa_c, now), set_c.socket_addrs());
    assert!(a.book.usable_addrs(&pa_b, now).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addr_info_only_after_auth() {
    let mut a = Party::new();
    let mut b = Party::new();
    let (_pa, _pb) = befriend(&mut a, &mut b);
    // посторонний: свой ключ пары и чужой публичный X вместо ключа A
    let s = Party::with(cfg(Duration::from_millis(1500)));
    let pair_s = PairId::generate().unwrap();
    let key_s = create(&MemStore::default(), &pair_s).unwrap();
    let not_a = create(&MemStore::default(), &PairId::generate().unwrap()).unwrap();
    s.t.set_peers(vec![KxPeer::new(
        pair_s,
        key_s.into_kx(),
        not_a.kx_public(),
    )])
    .unwrap();
    let r =
        s.t.connect(&PeerAddr {
            pair: pair_s,
            addrs: vec![a.addr],
        })
        .await;
    assert!(r.is_err(), "посторонний соединился без пары");
    // A не получил ни соединения, ни потока: кадр ADDR_INFO читать не из чего
    assert!(
        tokio::time::timeout(Duration::from_millis(300), a.t.accept())
            .await
            .is_err(),
        "A получил соединение от постороннего"
    );
    let st = a.t.stats();
    assert_eq!(st.auth_ok, 0);
    // друг при этом соединяется и обменивается
    let (pa, pb) = (a.book.friends()[0].pair, b.book.friends()[0].pair);
    let (conn_b, conn_a) = link(&b, pb, &a).await;
    let (rb, ra) = run_exchange(&conn_b, &pb, None, &conn_a, &pa, None).await;
    assert!(rb.is_ok() && ra.is_ok());
}
