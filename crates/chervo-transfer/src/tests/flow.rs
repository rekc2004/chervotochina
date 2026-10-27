//! Предложение, ответ, перенос и лимиты входящих потоков.

use std::time::Duration;

use super::fake::{Fake, FakeFile};
use super::kit::*;
use crate::{FailReason, TransferEvent, TransferKey, Verdict, state_dir_name};

fn final_name(k: &TransferKey, index: u32) -> String {
    format!("chervo-{}-{index}", state_dir_name(&k.pair, &k.id))
}

#[tokio::test]
async fn offer_accept_transfer_identical() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let sizes = [0usize, 1, 1 << 20, (1 << 20) + 1, 37 << 20];
    let datas: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| rand_bytes(i as u64 + 1, *n))
        .collect();
    let files: Vec<_> = datas
        .iter()
        .enumerate()
        .map(|(i, d)| write_src(src.path(), &format!("f{i}.bin"), d))
        .collect();
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    assert_eq!(kb.id, key.id);
    let view = rig.b.tr.offer(&kb).unwrap();
    assert_eq!(view.files.len(), sizes.len());
    assert_eq!(
        view.total_size,
        sizes.iter().map(|n| *n as u64).sum::<u64>()
    );
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    // каждый файл на месте и совпадает побайтно; лишнего нет
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), sizes.len());
    for (i, d) in datas.iter().enumerate() {
        let name = final_name(&kb, i as u32);
        let got = placed.iter().find(|(n, _)| *n == name).unwrap();
        assert!(&got.1 == d, "file {i} differs");
    }
    // все проверки корня прошли до размещения
    let calls = rig.b.spy.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), sizes.len());
    assert!(calls.iter().all(|(_, ok)| *ok));
    // временные данные убраны
    assert!(
        rig.b.partial.list().is_empty(),
        "{:?}",
        rig.b.partial.list()
    );
}

#[tokio::test]
async fn decline_writes_nothing() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(1, 3000))];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    rig.b.tr.respond(&kb, false).unwrap();
    let f = wait_ev(&mut rig.a.ev, 10, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::Failed {
            reason: FailReason::Declined,
            ..
        }
    ));
    assert_eq!(key_of(&f), key);
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
}

#[tokio::test]
async fn no_disk_write_before_accept() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(1, 3000))];
    rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
    rig.b.tr.respond(&kb, false).unwrap();
}

#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn offer_expires_after_ttl() {
    let _t = timing_shared();
    let mut rig = Rig::with(|_| {}, |c| c.offer_ttl = Duration::from_secs(600)).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(1, 3000))];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    tokio::time::advance(Duration::from_secs(601)).await;
    let f = wait_ev(&mut rig.a.ev, 30, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::Failed {
            reason: FailReason::Expired,
            ..
        }
    ));
    assert_eq!(key_of(&f), key);
    // у получателя предложение снято
    assert!(rig.b.tr.offer(&kb).is_none());
    assert!(rig.b.tr.respond(&kb, true).is_err());
}

#[tokio::test]
async fn second_offer_same_friend_busy() {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let cfg = small_cfg(partial.path());
    let mut p = Peer::start(node, partial, dest, cfg);
    let conn = FakeConn::lonely(pair);
    p.node.t.push_incoming(conn.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let peer = conn.peer();
    let f1 = Fake::new(pair, vec![FakeFile::new("a", rand_bytes(1, 100))]);
    let (_tx1, mut rx1) = f1.offer(&peer).await;
    wait_ev(&mut p.ev, 10, is_offer()).await;
    let f2 = Fake::new(pair, vec![FakeFile::new("b", rand_bytes(2, 100))]);
    let (_tx2, mut rx2) = f2.offer(&peer).await;
    assert_eq!(Fake::decision(&mut rx2, 10).await, Some(Verdict::Busy));
    // первое предложение живо
    assert!(try_recv_none(&mut rx1).await);
}

async fn try_recv_none(rx: &mut FakeRx) -> bool {
    recv_frame(rx, 0).await.is_none()
}
