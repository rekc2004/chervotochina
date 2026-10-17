//! Проверка блоков, лимиты перезапросов, привязка потоков данных, изменение источника.

use std::time::Duration;

use chervo_transport::{Connection, RecvStream, SendStream};

use super::fake::{Fake, FakeFile, Req, Resp};
use super::kit::*;
use crate::{
    BlockErrCode, CancelReason, FailReason, FileFailure, Message, TransferConfig, TransferEvent,
    TransferId, TransferKey, Verdict, read_exact, state_dir_name,
};

/// Настоящий получатель против поддельного отправителя. Предложение уже получено.
struct FakeSenderRig {
    p: Peer,
    fake: Fake,
    peer: FakeConn,
    ctl: Option<(FakeTx, FakeRx)>,
    key: TransferKey,
}

async fn fake_sender_rig(
    files: Vec<FakeFile>,
    tweak: impl FnOnce(&mut TransferConfig),
) -> FakeSenderRig {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    tweak(&mut cfg);
    let mut p = Peer::start(node, partial, dest, cfg);
    let conn = FakeConn::lonely(pair);
    p.node.t.push_incoming(conn.clone());
    wait_connected(&p, &pair).await;
    let peer = conn.peer();
    let fake = Fake::new(pair, files);
    let ctl = fake.offer(&peer).await;
    let e = wait_ev(&mut p.ev, 10, is_offer()).await;
    let key = key_of(&e);
    FakeSenderRig {
        p,
        fake,
        peer,
        ctl: Some(ctl),
        key,
    }
}

async fn wait_connected(p: &Peer, pair: &chervo_identity::PairId) {
    for _ in 0..500 {
        if p.node.engine.connection(pair).is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not connected");
}
impl FakeSenderRig {
    /// Принять и запустить обслуживание.
    async fn accept(&mut self) {
        self.p.tr.respond(&self.key, true).unwrap();
        let mut ctl = self.ctl.take().unwrap();
        assert_eq!(Fake::decision(&mut ctl.1, 10).await, Some(Verdict::Accept));
        self.fake.run(self.peer.clone(), Some(ctl));
    }
}

fn written(p: &Peer) -> Vec<(u32, u32)> {
    p.hook
        .events()
        .iter()
        .filter_map(|e| match e {
            Ev::Written(f, b) => Some((*f, *b)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn substituted_block_rejected_and_refetched() {
    let data = rand_bytes(7, 6 << 20);
    let mut r = fake_sender_rig(vec![FakeFile::new("a.bin", data.clone())], |_| {}).await;
    r.fake.respond_with(|q| match q {
        Req::Block(0, 3, 1) => Resp::Flip,
        _ => Resp::Normal,
    });
    r.accept().await;
    wait_ev(&mut r.p.ev, 30, is_completed(r.key)).await;
    // побайтно тот же файл
    let placed = placed_files(&r.p.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // каждый блок записан ровно один раз; подменённый запрошен дважды
    let mut w = written(&r.p);
    w.sort_unstable();
    assert_eq!(w, (0..6).map(|b| (0, b)).collect::<Vec<_>>());
    let reqs = r.fake.log.lock().unwrap().requests.clone();
    assert_eq!(
        reqs.iter()
            .filter(|q| matches!(q, Req::Block(0, 3, _)))
            .count(),
        2
    );
}

#[tokio::test]
async fn persistent_bad_block_fails_file() {
    let data = rand_bytes(8, 6 << 20);
    let mut r = fake_sender_rig(vec![FakeFile::new("a.bin", data)], |_| {}).await;
    r.fake.respond_with(|q| match q {
        Req::Block(0, 3, _) => Resp::Flip,
        _ => Resp::Normal,
    });
    r.accept().await;
    let f = wait_ev(&mut r.p.ev, 30, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::FileFailed {
            index: 0,
            reason: FileFailure::Damaged,
            ..
        }
    ));
    wait_ev(&mut r.p.ev, 30, is_completed(r.key)).await;
    // 1 запрос и 3 перезапроса, затем отказ
    let reqs = r.fake.log.lock().unwrap().requests.clone();
    assert_eq!(
        reqs.iter()
            .filter(|q| matches!(q, Req::Block(0, 3, _)))
            .count(),
        4
    );
    // итогового файла нет, временные данные удалены
    assert!(r.p.dest.list().is_empty());
    assert!(r.p.partial.list().is_empty(), "{:?}", r.p.partial.list());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        r.fake
            .log
            .lock()
            .unwrap()
            .ctl
            .iter()
            .any(|l| l == "file_error 0 Damaged")
    );
}

#[tokio::test]
async fn refetch_cap_per_transfer() {
    let data = rand_bytes(9, 8 << 20);
    let mut r = fake_sender_rig(vec![FakeFile::new("a.bin", data)], |c| {
        c.max_refetch_per_transfer = 5;
    })
    .await;
    // каждый блок портится один раз: на блок хватает лимита, на передачу нет
    r.fake.respond_with(|q| match q {
        Req::Block(0, _, 1) => Resp::Flip,
        _ => Resp::Normal,
    });
    r.accept().await;
    let f = wait_ev(&mut r.p.ev, 30, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::FileFailed {
            reason: FileFailure::Damaged,
            ..
        }
    ));
    wait_ev(&mut r.p.ev, 30, is_completed(r.key)).await;
    assert!(r.p.dest.list().is_empty());
}

#[tokio::test]
async fn block_written_only_after_verify() {
    let data = rand_bytes(10, 6 << 20);
    let file = FakeFile::new("a.bin", data);
    let leaves = file.leaves.clone();
    let mut r = fake_sender_rig(vec![file], |_| {}).await;
    r.fake.respond_with(|q| match q {
        Req::Block(0, 2, n) if *n <= 2 => Resp::Flip,
        Req::Block(0, 4, 1) => Resp::Custom(vec![0u8; 1 << 20]),
        _ => Resp::Normal,
    });
    r.accept().await;
    wait_ev(&mut r.p.ev, 30, is_completed(r.key)).await;
    let log = r.p.hook.events();
    let writes: Vec<_> = log
        .iter()
        .filter_map(|e| match e {
            Ev::Write(f, b, h) => Some((*f, *b, *h)),
            _ => None,
        })
        .collect();
    // на диск попадало только то, что совпало с хэшем блока из манифеста
    for (f, b, h) in &writes {
        assert_eq!(*f, 0);
        assert_eq!(*h, leaves[*b as usize], "block {b} written unverified");
    }
    assert_eq!(writes.iter().filter(|w| w.1 == 2).count(), 1);
    assert_eq!(writes.iter().filter(|w| w.1 == 4).count(), 1);
}

#[tokio::test]
async fn block_len_lie_rejected_before_read() {
    let data = rand_bytes(11, 3 << 20);
    let mut r = fake_sender_rig(vec![FakeFile::new("a.bin", data)], |_| {}).await;
    r.fake.respond_with(|q| match q {
        // верная длина 1 MiB; заявлена на байт больше, тело не отправляется
        Req::Block(0, 1, 1) => Resp::LieLen((1 << 20) + 1),
        _ => Resp::Normal,
    });
    r.accept().await;
    // отказ приходит сразу, а не после срока молчания потока (60 с): тело не читалось
    let f = wait_ev(&mut r.p.ev, 10, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::Failed {
            reason: FailReason::Protocol,
            ..
        }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        r.fake
            .log
            .lock()
            .unwrap()
            .ctl
            .iter()
            .any(|l| l == "cancel Protocol")
    );
    assert!(r.p.dest.list().is_empty());
    assert!(r.p.partial.list().is_empty());
}

#[tokio::test]
async fn manifest_block_err_fails_file() {
    let mut r = fake_sender_rig(
        vec![FakeFile::new("a.bin", rand_bytes(12, 2 << 20))],
        |_| {},
    )
    .await;
    r.fake.respond_with(|q| match q {
        Req::Manifest(_) => Resp::BlockErr(BlockErrCode::SourceChanged),
        _ => Resp::Normal,
    });
    r.accept().await;
    let f = wait_ev(&mut r.p.ev, 10, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::FileFailed {
            reason: FileFailure::SourceChanged,
            ..
        }
    ));
    wait_ev(&mut r.p.ev, 10, is_completed(r.key)).await;
    assert!(r.p.dest.list().is_empty());
}

// --------------------------------------------------- враждебный получатель (против отправителя)

struct HostileRx {
    a: Peer,
    _src: std::sync::Arc<TestDir>,
    key: TransferKey,
    peer: FakeConn,
    ctl_tx: FakeTx,
    ctl_rx: FakeRx,
    id: TransferId,
}

async fn read_u8(rx: &mut FakeRx) -> u8 {
    let mut b = [0u8; 1];
    assert_eq!(rx.read(&mut b).await.unwrap(), Some(1));
    b[0]
}

/// Принимает предложение от настоящего отправителя на стороне поддельного получателя.
async fn accept_offer(peer: &FakeConn) -> (FakeTx, FakeRx, TransferId) {
    let (mut tx, mut rx) = peer.accept_bi().await.unwrap();
    assert_eq!(read_u8(&mut rx).await, crate::STREAM_TRANSFER_CTL);
    let Some(Message::OfferHead { id, .. }) = recv_frame(&mut rx, 10).await else {
        panic!("no offer head");
    };
    let Some(Message::OfferFiles(_)) = recv_frame(&mut rx, 10).await else {
        panic!("no offer files");
    };
    send_frame(
        &mut tx,
        &Message::Decision {
            id,
            verdict: Verdict::Accept,
        },
    )
    .await;
    (tx, rx, id)
}

async fn hostile_receiver(sizes: &[usize], tweak: impl FnOnce(&mut TransferConfig)) -> HostileRx {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    tweak(&mut cfg);
    let mut a = Peer::start(node, partial, dest, cfg);
    let conn = FakeConn::lonely(pair);
    a.node.t.push_incoming(conn.clone());
    wait_connected(&a, &pair).await;
    let src = TestDir::new();
    let files: Vec<_> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            write_src(
                src.path(),
                &format!("s{i}.bin"),
                &rand_bytes(i as u64 + 20, *n),
            )
        })
        .collect();
    let key = a.tr.send(&pair, files).unwrap();
    let peer = conn.peer();
    let (ctl_tx, ctl_rx, id) = accept_offer(&peer).await;
    wait_ev(&mut a.ev, 10, |e| {
        matches!(e, TransferEvent::Started { .. })
    })
    .await;
    HostileRx {
        a,
        _src: src,
        key,
        peer,
        ctl_tx,
        ctl_rx,
        id,
    }
}

/// Поток данных с BIND.
async fn bind(peer: &FakeConn, id: TransferId) -> (FakeTx, FakeRx) {
    let (mut tx, rx) = peer.open_bi().await.unwrap();
    tx.write_all(&[crate::STREAM_TRANSFER_DATA]).await.unwrap();
    send_frame(&mut tx, &Message::Bind { id }).await;
    (tx, rx)
}

async fn expect_cancel(rx: &mut FakeRx, want: CancelReason) {
    for _ in 0..10 {
        match recv_frame(rx, 10).await {
            Some(Message::Cancel { reason, .. }) => {
                assert_eq!(reason, want);
                return;
            }
            Some(_) => {}
            None => panic!("no cancel"),
        }
    }
    panic!("no cancel");
}

#[tokio::test]
async fn out_of_range_get_is_protocol_error() {
    let mut h = hostile_receiver(&[3 << 20], |_| {}).await;
    let (mut dtx, _drx) = bind(&h.peer, h.id).await;
    send_frame(
        &mut dtx,
        &Message::GetBlock {
            index: 0,
            block: 99,
        },
    )
    .await;
    expect_cancel(&mut h.ctl_rx, CancelReason::Protocol).await;
    let f = wait_ev(&mut h.a.ev, 10, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::Failed {
            reason: FailReason::Protocol,
            ..
        }
    ));
    // индекс файла вне предложения: так же
    let mut h = hostile_receiver(&[3 << 20], |_| {}).await;
    let (mut dtx, _drx) = bind(&h.peer, h.id).await;
    send_frame(&mut dtx, &Message::GetManifest { index: 7 }).await;
    expect_cancel(&mut h.ctl_rx, CancelReason::Protocol).await;
}

#[tokio::test]
async fn serve_cap_per_block() {
    let mut h = hostile_receiver(&[3 << 20], |_| {}).await;
    let (mut dtx, mut drx) = bind(&h.peer, h.id).await;
    for _ in 0..4 {
        send_frame(&mut dtx, &Message::GetBlock { index: 0, block: 1 }).await;
        let Some(Message::Block { len, .. }) = recv_frame(&mut drx, 10).await else {
            panic!("no block");
        };
        let mut body = vec![0u8; len as usize];
        read_exact(&mut drx, &mut body, Duration::from_secs(10))
            .await
            .unwrap();
    }
    // пятый запрос того же блока за сессию
    send_frame(&mut dtx, &Message::GetBlock { index: 0, block: 1 }).await;
    expect_cancel(&mut h.ctl_rx, CancelReason::Limits).await;
    let f = wait_ev(&mut h.a.ev, 10, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::Failed {
            reason: FailReason::Limits,
            ..
        }
    ));
}

#[tokio::test]
async fn get_pipeline_cap() {
    let mut h = hostile_receiver(&[12 << 20], |_| {}).await;
    let (mut dtx, _drx) = bind(&h.peer, h.id).await;
    // окно 2: двенадцать запросов подряд без чтения ответов
    let mut raw = Vec::new();
    for b in 0..12u32 {
        crate::encode(&Message::GetBlock { index: 0, block: b }, &mut raw).unwrap();
    }
    dtx.write_all(&raw).await.unwrap();
    expect_cancel(&mut h.ctl_rx, CancelReason::Protocol).await;
}

#[tokio::test]
async fn bind_unknown_transfer_dropped() {
    let h = hostile_receiver(&[1 << 20], |_| {}).await;
    let (mut tx, mut rx) = bind(&h.peer, TransferId([9; 16])).await;
    send_frame(&mut tx, &Message::GetManifest { index: 0 }).await;
    assert!(recv_frame(&mut rx, 3).await.is_none());
}

#[tokio::test]
async fn bind_other_pairs_transfer_dropped() {
    // два друга на одном узле; передача идёт первому, второй пытается к ней привязаться
    let mut pre = Pre::new();
    let (p1, p2) = (pre.solo_friend(), pre.solo_friend());
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let cfg = small_cfg(partial.path());
    let mut a = Peer::start(node, partial, dest, cfg);
    let (c1, c2) = (FakeConn::lonely(p1), FakeConn::lonely(p2));
    a.node.t.push_incoming(c1.clone());
    a.node.t.push_incoming(c2.clone());
    wait_connected(&a, &p1).await;
    wait_connected(&a, &p2).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "s.bin", &rand_bytes(1, 2 << 20))];
    a.tr.send(&p1, files).unwrap();
    let (_ctl_tx, _ctl_rx, id) = accept_offer(&c1.peer()).await;
    wait_ev(&mut a.ev, 10, |e| {
        matches!(e, TransferEvent::Started { .. })
    })
    .await;
    // чужая пара
    let (mut tx2, mut rx2) = bind(&c2.peer(), id).await;
    send_frame(&mut tx2, &Message::GetManifest { index: 0 }).await;
    assert!(recv_frame(&mut rx2, 3).await.is_none());
    // своя пара получает ответ
    let (mut tx1, mut rx1) = bind(&c1.peer(), id).await;
    send_frame(&mut tx1, &Message::GetManifest { index: 0 }).await;
    assert!(matches!(
        recv_frame(&mut rx1, 10).await,
        Some(Message::Manifest { .. })
    ));
}

#[tokio::test]
async fn data_streams_cap() {
    let h = hostile_receiver(&[2 << 20], |c| c.max_data_streams = 2).await;
    for _ in 0..2 {
        let (mut tx, mut rx) = bind(&h.peer, h.id).await;
        send_frame(&mut tx, &Message::GetManifest { index: 0 }).await;
        assert!(matches!(
            recv_frame(&mut rx, 10).await,
            Some(Message::Manifest { .. })
        ));
        // потоки остаются открытыми
        std::mem::forget((tx, rx));
    }
    let (mut tx, mut rx) = bind(&h.peer, h.id).await;
    send_frame(&mut tx, &Message::GetManifest { index: 0 }).await;
    assert!(recv_frame(&mut rx, 3).await.is_none());
}

// ------------------------------------------------------------------ два настоящих узла

#[tokio::test]
async fn source_changed_detected_by_sender() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(31, 3 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    // хэширование идёт, пока получатель решает; дать ему закончиться, затем подменить файл
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut changed = data.clone();
    changed[1 << 20] ^= 0xFF;
    std::fs::write(src.path().join("a.bin"), &changed).unwrap();
    rig.b.tr.respond(&kb, true).unwrap();
    let fa = wait_ev(&mut rig.a.ev, 20, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        fa,
        TransferEvent::FileFailed {
            reason: FileFailure::SourceChanged,
            ..
        }
    ));
    let fb = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        fb,
        TransferEvent::FileFailed {
            reason: FileFailure::SourceChanged,
            ..
        }
    ));
    wait_ev(&mut rig.b.ev, 20, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 20, is_completed(key)).await;
    assert!(rig.b.dest.list().is_empty());
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn final_check_mismatch_refetches_block() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(41, 4 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    // перед итоговым перечитыванием портим блок 1 в .part (один раз)
    let partial = rig.b.partial.path().to_path_buf();
    let mut done = false;
    rig.b.hook.set(move |ev| {
        if let Ev::FinalVerify(0) = ev
            && !done
        {
            done = true;
            let sdir = std::fs::read_dir(&partial)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let part = sdir.join("0.part");
            let mut bytes = std::fs::read(&part).unwrap();
            bytes[(1 << 20) + 5] ^= 0x01;
            std::fs::write(&part, bytes).unwrap();
        }
        Ok(())
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 30, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // блок 1 записан дважды, остальные по разу
    let log = rig.b.hook.events();
    let w: Vec<u32> = log
        .iter()
        .filter_map(|e| match e {
            Ev::Written(0, b) => Some(*b),
            _ => None,
        })
        .collect();
    assert_eq!(w.iter().filter(|b| **b == 1).count(), 2);
    assert_eq!(w.len(), 5);
    // размещение вызвано один раз и только после совпадения корня
    let calls = rig.b.spy.calls.lock().unwrap().clone();
    assert_eq!(calls, vec![(0, true)]);
    let last_written = log
        .iter()
        .rposition(|e| matches!(e, Ev::Written(0, 1)))
        .unwrap();
    let place_at = log
        .iter()
        .position(|e| matches!(e, Ev::BeforePlace(0)))
        .unwrap();
    assert!(place_at > last_written);
    let _ = state_dir_name;
}

#[tokio::test]
async fn final_name_only_after_root_match() {
    // размещение зовётся с совпавшим корнем на диске для каждого файла
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files = vec![
        write_src(src.path(), "a.bin", &rand_bytes(51, 2 << 20)),
        write_src(src.path(), "b.bin", &rand_bytes(52, 100)),
    ];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 30, is_completed(key)).await;
    let calls = rig.b.spy.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|(_, ok)| *ok));
    // в журнале BeforePlace каждого файла идёт после всех его Written
    let log = rig.b.hook.events();
    for f in 0..2u32 {
        let place_at = log.iter().position(|e| *e == Ev::BeforePlace(f)).unwrap();
        assert!(
            log.iter()
                .enumerate()
                .filter(|(_, e)| matches!(e, Ev::Written(x, _) if *x == f))
                .all(|(i, _)| i < place_at)
        );
    }
}
