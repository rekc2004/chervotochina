//! Этап 14б: предложение переживает потерю или замену соединения. Настоящий `Engine` над
//! `FakeTransport`; где нужен враждебный или управляемый собеседник, он говорит по проводу
//! напрямую (кодек крейта). Тесты с остановленными часами не трогают диск получателя.

use std::time::Duration;

use chervo_identity::PairId;
use chervo_transport::{Connection, RecvStream, SendStream};

use super::fake::{Fake, FakeFile};
use super::kit::*;
use crate::receiver::Reoffer;
use crate::{
    CancelReason, FailReason, MAX_OFFER_RELINKS, Message, OfferedFile, Side, TransferConfig,
    TransferEvent, TransferEvents, TransferId, TransferKey, UntrustedName, Verdict,
};

// ----------------------------------------------------------------------------- помощники

/// Все события до первого, подходящего под `stop` (включая его).
async fn collect_until(
    ev: &mut TransferEvents,
    secs: u64,
    stop: impl Fn(&TransferEvent) -> bool,
) -> Vec<TransferEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut out = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ev.recv()).await {
            Ok(Some(e)) => {
                let last = stop(&e);
                out.push(e);
                if last {
                    return out;
                }
            }
            _ => panic!("timed out; events so far: {out:?}"),
        }
    }
}

fn is_bad(e: &TransferEvent) -> bool {
    matches!(
        e,
        TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. }
    )
}

fn count_offers(v: &[TransferEvent]) -> usize {
    v.iter()
        .filter(|e| matches!(e, TransferEvent::OfferReceived { .. }))
        .count()
}

fn count(v: &[TransferEvent], f: impl Fn(&TransferEvent) -> bool) -> usize {
    v.iter().filter(|e| f(e)).count()
}

fn is_failed(reason: FailReason) -> impl Fn(&TransferEvent) -> bool {
    move |e| matches!(e, TransferEvent::Failed { reason: r, .. } if *r == reason)
}

fn is_answered(accepted: bool) -> impl Fn(&TransferEvent) -> bool {
    move |e| matches!(e, TransferEvent::OfferAnswered { accepted: a, .. } if *a == accepted)
}

fn is_started(e: &TransferEvent) -> bool {
    matches!(e, TransferEvent::Started { .. })
}

fn is_resumed(e: &TransferEvent) -> bool {
    matches!(e, TransferEvent::Resumed { .. })
}

fn is_cancel(reason: CancelReason) -> impl Fn(Option<Message>) -> bool {
    move |m| matches!(m, Some(Message::Cancel { reason: r, .. }) if r == reason)
}

/// Даёт задачам выполниться, не двигая часы.
async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

/// Поток закрыт собеседником (а не просто молчит).
async fn is_eof(rx: &mut FakeRx) -> bool {
    let mut b = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_millis(500), rx.read(&mut b)).await,
        Ok(Ok(None))
    )
}

fn big_cfg(c: &mut TransferConfig) {
    c.ctl_in_per_min = 10_000;
}

/// Получатель и тестовый собеседник на «одинокой» связи.
struct Raw {
    p: Peer,
    pair: PairId,
    /// Конец связи, которым управляет тест (открывает потоки к получателю).
    peer: FakeConn,
}

async fn raw_receiver(tweak: impl FnOnce(&mut TransferConfig)) -> Raw {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    big_cfg(&mut cfg);
    tweak(&mut cfg);
    let p = Peer::start(node, partial, dest, cfg);
    let conn = FakeConn::lonely(pair);
    p.node.t.push_incoming(conn.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    Raw {
        p,
        pair,
        peer: conn.peer(),
    }
}

/// Предложение вручную: заголовок и одна пачка записей (можно соврать в сумме).
async fn raw_offer(
    conn: &FakeConn,
    id: TransferId,
    files: &[(&str, u64)],
    total: u64,
) -> (FakeTx, FakeRx) {
    let (mut tx, rx) = conn.open_bi().await.unwrap();
    let list: Vec<OfferedFile> = files
        .iter()
        .map(|(n, s)| OfferedFile {
            name: UntrustedName::new(n).unwrap(),
            size: *s,
        })
        .collect();
    let bytes: u32 = list.iter().map(|f| 10 + f.name.len() as u32).sum();
    tx.write_all(&[crate::STREAM_TRANSFER_CTL]).await.unwrap();
    send_frame(
        &mut tx,
        &Message::OfferHead {
            id,
            file_count: list.len() as u32,
            total_size: total,
            offer_bytes: bytes,
        },
    )
    .await;
    send_frame(&mut tx, &Message::OfferFiles(list)).await;
    (tx, rx)
}

const BASE: [(&str, u64); 2] = [("a.bin", 100), ("b.bin", 200)];

fn fake_two(pair: PairId) -> Fake {
    Fake::new(
        pair,
        vec![
            FakeFile::new("a.bin", rand_bytes(1, 100)),
            FakeFile::new("b.bin", rand_bytes(2, 200)),
        ],
    )
}

// ----------------------------------------------------------- воспроизведения из отчёта

/// Вариант A отчёта: связь закрыта, но движок ещё отдаёт её как живую, и предложение уходит
/// в неё. После появления рабочей связи оно должно дойти.
#[tokio::test]
async fn offer_survives_link_closed_before_open() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(7, 300_000);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    // без `.await` между закрытием и отправкой: `on_closed` движка ещё не выполнялся
    rig.cur.0.close();
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let (_ca, _cb) = rig.link().await;
    let first_b = collect_until(&mut rig.b.ev, 20, is_offer()).await;
    assert_eq!(count_offers(&first_b), 1, "{first_b:?}");
    let kb = key_of(first_b.last().unwrap());
    assert_eq!(kb.id, key.id);
    rig.b.tr.respond(&kb, true).unwrap();
    let on_b = collect_until(&mut rig.b.ev, 60, is_completed(kb)).await;
    let on_a = collect_until(&mut rig.a.ev, 60, is_completed(key)).await;
    assert!(!first_b.iter().any(is_bad), "{first_b:?}");
    assert!(!on_b.iter().any(is_bad), "{on_b:?}");
    assert!(!on_a.iter().any(is_bad), "{on_a:?}");
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
}

/// Вариант B отчёта: связь потеряна, пока получатель решает. Окно решения остаётся,
/// отправитель повторяет то же предложение по новой связи.
#[tokio::test]
async fn pending_offer_survives_link_loss() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(9, 300_000);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb: TransferKey = key_of(&e);
    rig.cur.0.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rig.b.tr.offer(&kb).is_some(), "pending offer was dropped");
    let (_ca, _cb) = rig.link().await;
    // второго приглашения нет; затем ответ пользователя
    tokio::time::sleep(Duration::from_millis(500)).await;
    rig.b.tr.respond(&kb, true).unwrap();
    let on_b = collect_until(&mut rig.b.ev, 60, is_completed(kb)).await;
    let on_a = collect_until(&mut rig.a.ev, 60, is_completed(key)).await;
    assert_eq!(count_offers(&on_b), 0, "{on_b:?}");
    assert!(!on_b.iter().any(is_bad), "{on_b:?}");
    assert!(!on_a.iter().any(is_bad), "{on_a:?}");
    assert!(!on_a.iter().any(is_failed(FailReason::Protocol)));
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
}

// ------------------------------------------------------------------- связь и ответ

/// Получатель сам закрывает свой конец (так дубль разрешается в движке): то же самое.
#[tokio::test]
async fn pending_offer_survives_receiver_side_close() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(11, 200_000);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    rig.cur.1.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rig.b.tr.offer(&kb).is_some());
    let (_ca, _cb) = rig.link().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    rig.b.tr.respond(&kb, true).unwrap();
    let on_b = collect_until(&mut rig.b.ev, 60, is_completed(kb)).await;
    let on_a = collect_until(&mut rig.a.ev, 60, is_completed(key)).await;
    assert_eq!(count_offers(&on_b), 0, "{on_b:?}");
    assert!(!on_b.iter().any(is_bad), "{on_b:?}");
    assert!(!on_a.iter().any(is_bad), "{on_a:?}");
    assert!(placed_files(&rig.b.dest)[0].1 == data);
}

/// Принято без связи: ответ уходит отправителю по RESUME, когда связь вернулась.
#[tokio::test]
async fn accept_while_detached_completes_via_resume() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(13, 400_000);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let first_b = collect_until(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(first_b.last().unwrap());
    rig.cur.0.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    rig.b.tr.respond(&kb, true).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_ca, _cb) = rig.link().await;
    let on_b = collect_until(&mut rig.b.ev, 60, is_completed(kb)).await;
    let on_a = collect_until(&mut rig.a.ev, 60, is_completed(key)).await;
    assert!(!on_b.iter().any(is_bad), "{on_b:?}");
    assert!(!on_a.iter().any(is_bad), "{on_a:?}");
    assert_eq!(count(&on_a, is_answered(true)), 1, "{on_a:?}");
    assert_eq!(count(&on_a, is_started), 1, "{on_a:?}");
    assert_eq!(count(&on_b, is_answered(true)), 1, "{on_b:?}");
    assert_eq!(count_offers(&on_b), 0);
    assert!(placed_files(&rig.b.dest)[0].1 == data);
}

/// Сторона отправителя без участия настоящего получателя: RESUME на предложении, ждущем
/// ответа, это принятие (OfferAnswered{true}, Started, без Resumed).
#[tokio::test]
async fn resume_in_offering_is_acceptance() {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    big_cfg(&mut cfg);
    let mut p = Peer::start(node, partial, dest, cfg);
    let c0 = FakeConn::lonely(pair);
    p.node.t.push_incoming(c0.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let src = TestDir::new();
    let key =
        p.tr.send(
            &pair,
            vec![write_src(src.path(), "a.bin", &rand_bytes(3, 1000))],
        )
        .unwrap();
    // предложение пришло; ответа нет, связь пропала
    let t0 = c0.peer();
    let (_tx0, mut rx0) = t0.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    rx0.read(&mut kind).await.unwrap();
    assert!(matches!(
        recv_frame(&mut rx0, 5).await,
        Some(Message::OfferHead { .. })
    ));
    c0.close();
    let c1 = FakeConn::lonely(pair);
    p.node.t.push_incoming(c1.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t1 = c1.peer();
    let (mut tx, mut rx) = t1.open_bi().await.unwrap();
    tx.write_all(&[crate::STREAM_TRANSFER_CTL]).await.unwrap();
    send_frame(&mut tx, &Message::Resume { id: key.id }).await;
    // ответ RESUME_OK приходит на этот же поток; потоки предложения повтора идут отдельно
    let got = recv_frame(&mut rx, 5).await;
    assert!(
        matches!(got, Some(Message::ResumeOk { .. })),
        "no RESUME_OK"
    );
    let ev = collect_until(&mut p.ev, 10, is_started).await;
    assert_eq!(count(&ev, is_answered(true)), 1, "{ev:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rest = drain(&mut p.ev).await;
    assert!(!ev.iter().chain(rest.iter()).any(is_resumed));
    assert!(!ev.iter().chain(rest.iter()).any(is_bad), "{ev:?} {rest:?}");
    assert_eq!(count(&rest, is_answered(true)), 0);
}

/// Отказ без связи: ответ узнаёт отправитель при повторе предложения, окна решения второй раз
/// нет.
#[tokio::test]
async fn decline_while_detached_answered_on_relink() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(15, 5000))];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let first_b = collect_until(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(first_b.last().unwrap());
    rig.cur.0.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    rig.b.tr.respond(&kb, false).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_ca, _cb) = rig.link().await;
    let on_a = collect_until(&mut rig.a.ev, 20, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(on_a.iter().any(is_failed(FailReason::Declined)), "{on_a:?}");
    assert_eq!(key_of(on_a.last().unwrap()), key);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let on_b = drain(&mut rig.b.ev).await;
    assert_eq!(count_offers(&on_b), 0, "{on_b:?}");
    assert!(rig.b.tr.offer(&kb).is_none());
}

// ----------------------------------------------------------------- повтор и согласие

/// Повтор принятого предложения получает `DECISION{Accept}` (согласие уже есть), а RESUME
/// после этого работает.
#[tokio::test]
async fn reoffer_for_accepted_key_gets_accept() {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (tx1, mut rx1) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    assert_eq!(k, f.key);
    r.p.tr.respond(&k, true).unwrap();
    assert_eq!(Fake::decision(&mut rx1, 10).await, Some(Verdict::Accept));
    let (_tx2, mut rx2) = f.offer(&r.peer).await;
    assert_eq!(Fake::decision(&mut rx2, 10).await, Some(Verdict::Accept));
    // старый поток управления брошен: получатель возобновляет передачу сам
    drop(tx1);
    drop(rx1);
    let mut resumed = false;
    for _ in 0..20 {
        let Ok(Ok((_t, mut rr))) =
            tokio::time::timeout(Duration::from_secs(5), r.peer.accept_bi()).await
        else {
            break;
        };
        let mut kind = [0u8; 1];
        let _ = rr.read(&mut kind).await;
        if kind[0] != crate::STREAM_TRANSFER_CTL {
            continue;
        }
        let m = recv_frame(&mut rr, 5).await;
        assert!(
            matches!(m, Some(Message::Resume { id }) if id == k.id),
            "no RESUME for this id"
        );
        resumed = true;
        break;
    }
    assert!(resumed, "no RESUME after the re-offer");
}

/// Повтор, отличающийся хоть чем-то, закрывает ожидающее предложение нарушением.
#[tokio::test]
async fn reoffer_mismatch_ends_pending() {
    let mut r = raw_receiver(|_| {}).await;
    type Case<'a> = (&'a str, Vec<(&'a str, u64)>, u64);
    let cases: [Case<'_>; 5] = [
        ("name byte", vec![("a.bin", 100), ("c.bin", 200)], 300),
        ("size", vec![("a.bin", 101), ("b.bin", 200)], 301),
        ("order", vec![("b.bin", 200), ("a.bin", 100)], 300),
        (
            "extra file",
            vec![("a.bin", 100), ("b.bin", 200), ("c.bin", 1)],
            301,
        ),
        ("total size", BASE.to_vec(), 301),
    ];
    let mut last = None;
    for (what, files, total) in cases {
        let f = fake_two(r.pair);
        let (_tx1, _rx1) = f.offer(&r.peer).await;
        let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
        let k = key_of(&e);
        assert_eq!(k, f.key, "{what}");
        let (_tx2, mut rx2) = raw_offer(&r.peer, k.id, &files, total).await;
        assert!(
            is_cancel(CancelReason::Protocol)(recv_frame(&mut rx2, 5).await),
            "{what}"
        );
        wait_ev(&mut r.p.ev, 10, is_failed(FailReason::Protocol)).await;
        assert!(r.p.tr.offer(&k).is_none(), "{what}");
        assert!(r.p.tr.respond(&k, true).is_err(), "{what}");
        assert!(r.p.partial.list().is_empty(), "{what}");
        last = Some(f);
    }
    // тот же ключ с исходным содержимым: ответ из надгробия, нового окна решения нет
    let f = last.unwrap();
    let (_tx3, mut rx3) = f.offer(&r.peer).await;
    assert!(is_cancel(CancelReason::Protocol)(
        recv_frame(&mut rx3, 5).await
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rest = drain(&mut r.p.ev).await;
    assert_eq!(count_offers(&rest), 0, "{rest:?}");
    assert!(r.p.tr.offer(&f.key).is_none());
}

/// Несовпадающий повтор принятого предложения обрывает передачу, временные данные убраны.
#[tokio::test]
async fn reoffer_mismatch_after_accept_fails_transfer() {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (_tx1, mut rx1) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    r.p.tr.respond(&k, true).unwrap();
    assert_eq!(Fake::decision(&mut rx1, 10).await, Some(Verdict::Accept));
    wait_ev(&mut r.p.ev, 10, |e| {
        matches!(e, TransferEvent::Started { .. })
    })
    .await;
    assert!(!r.p.partial.list().is_empty());
    let (_tx2, mut rx2) = raw_offer(&r.peer, k.id, &[("a.bin", 100), ("x.bin", 200)], 300).await;
    assert!(is_cancel(CancelReason::Protocol)(
        recv_frame(&mut rx2, 5).await
    ));
    wait_ev(&mut r.p.ev, 10, is_failed(FailReason::Protocol)).await;
    for _ in 0..100 {
        if r.p.partial.list().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(r.p.partial.list().is_empty(), "{:?}", r.p.partial.list());
    assert!(r.p.dest.list().is_empty());
}

/// Согласие даёт только пользователь: повторы ничего не принимают.
#[tokio::test]
async fn reoffer_never_accepts_by_itself() {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (_tx, mut first_rx) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    let mut held = Vec::new();
    for _ in 0..MAX_OFFER_RELINKS {
        let s = f.offer(&r.peer).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        held.push(s);
    }
    for (_tx, rx) in &mut held {
        let m = recv_frame(rx, 0).await;
        assert!(
            !matches!(
                m,
                Some(Message::Decision {
                    verdict: Verdict::Accept,
                    ..
                })
            ),
            "re-offer got an Accept decision"
        );
    }
    assert!(recv_frame(&mut first_rx, 0).await.is_none());
    let rest = drain(&mut r.p.ev).await;
    assert_eq!(count_offers(&rest), 0, "{rest:?}");
    assert_eq!(count(&rest, is_started), 0);
    assert!(rest.iter().all(|e| !is_bad(e)), "{rest:?}");
    assert!(r.p.tr.offer(&k).is_some());
    assert!(r.p.partial.list().is_empty());
    assert!(r.p.dest.list().is_empty());
}

/// Девятый повтор: `DECISION{Limits}` и `Failed{Limits}`.
#[tokio::test]
async fn reoffer_cap() {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (_tx, _rx) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    let mut held = Vec::new();
    for _ in 0..MAX_OFFER_RELINKS {
        held.push(f.offer(&r.peer).await);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(r.p.tr.offer(&k).is_some());
    let (_tx9, mut rx9) = f.offer(&r.peer).await;
    assert_eq!(Fake::decision(&mut rx9, 10).await, Some(Verdict::Limits));
    wait_ev(&mut r.p.ev, 10, is_failed(FailReason::Limits)).await;
    assert!(r.p.tr.offer(&k).is_none());
}

/// Повтор не продлевает срок предложения: `Expired` ровно в исходный срок.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn reoffer_does_not_extend_ttl() {
    let _t = timing_shared();
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (_tx1, _rx1) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    settle().await;
    // исходный срок: от первого появления предложения
    let deadline = r.p.tr.inner().find_inb(&k).unwrap().offer_deadline;
    let left = deadline - tokio::time::Instant::now();
    tokio::time::advance(left - Duration::from_secs(10)).await;
    settle().await;
    let (_tx2, mut rx2) = f.offer(&r.peer).await;
    settle().await;
    tokio::time::advance(Duration::from_secs(10) - Duration::from_millis(1)).await;
    settle().await;
    assert!(recv_frame(&mut rx2, 0).await.is_none());
    assert!(r.p.tr.offer(&k).is_some());
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(Fake::decision(&mut rx2, 0).await, Some(Verdict::Expired));
    let rest = drain(&mut r.p.ev).await;
    assert!(rest.iter().any(is_failed(FailReason::Expired)), "{rest:?}");
    assert!(r.p.tr.offer(&k).is_none());
}

// -------------------------------------------------------------------------- сроки

/// Без связи ожидающее предложение живёт ровно `offer_relink_grace`.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn detached_pending_ends_after_grace() {
    let _t = timing_shared();
    let mut r = raw_receiver(|_| {}).await;
    let grace = r.p.cfg.offer_relink_grace;
    let f = fake_two(r.pair);
    let (_tx, _rx) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    settle().await;
    r.peer.close();
    settle().await;
    assert!(r.p.tr.offer(&k).is_some());
    tokio::time::advance(grace - Duration::from_millis(1)).await;
    settle().await;
    let early = drain(&mut r.p.ev).await;
    assert!(early.iter().all(|e| !is_bad(e)), "{early:?}");
    assert!(r.p.tr.offer(&k).is_some());
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
    let late = drain(&mut r.p.ev).await;
    assert!(
        late.iter().any(is_failed(FailReason::Disconnected)),
        "{late:?}"
    );
    assert!(r.p.tr.offer(&k).is_none());
}

/// Отправитель без связи: `Disconnected` ровно через `offer_relink_grace`, не `Protocol`.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn sender_without_link_fails_disconnected_after_grace() {
    let _t = timing_shared();
    let mut rig = Rig::new().await;
    let grace = rig.a.cfg.offer_relink_grace;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(5, 100))];
    rig.cur.0.close();
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    settle().await;
    tokio::time::advance(grace - Duration::from_millis(1)).await;
    settle().await;
    let early = drain(&mut rig.a.ev).await;
    assert!(early.iter().all(|e| !is_bad(e)), "{early:?}");
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
    let late = drain(&mut rig.a.ev).await;
    assert!(
        late.iter().any(is_failed(FailReason::Disconnected)),
        "{late:?}"
    );
    assert!(!late.iter().any(is_failed(FailReason::Protocol)));
    assert_eq!(key_of(late.iter().find(|e| is_bad(e)).unwrap()), key);
}

/// Связи, которые умирают сразу после открытия потока: не больше 1 + 8 заголовков.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn sender_relink_tries_capped() {
    let _t = timing_shared();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    big_cfg(&mut cfg);
    let mut p = Peer::start(node, partial, dest, cfg);
    let c0 = FakeConn::lonely(pair);
    p.node.t.push_incoming(c0.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let src = TestDir::new();
    let key =
        p.tr.send(
            &pair,
            vec![write_src(src.path(), "a.bin", &rand_bytes(1, 100))],
        )
        .unwrap();
    let mut heads = 0u32;
    let mut cur = c0;
    loop {
        let t = cur.peer();
        let got = tokio::time::timeout(Duration::from_secs(30), async {
            let (_tx, mut rx) = t.accept_bi().await.ok()?;
            let mut kind = [0u8; 1];
            rx.read(&mut kind).await.ok()?;
            matches!(
                recv_frame(&mut rx, 5).await,
                Some(Message::OfferHead { .. })
            )
            .then_some(())
        })
        .await;
        if !matches!(got, Ok(Some(()))) {
            break;
        }
        heads += 1;
        cur.close();
        let next = FakeConn::lonely(pair);
        p.node.t.push_incoming(next.clone());
        cur = next;
    }
    assert_eq!(heads, 1 + u32::from(MAX_OFFER_RELINKS));
    let ev = collect_until(&mut p.ev, 10, |e| matches!(e, TransferEvent::Failed { .. })).await;
    assert!(ev.iter().any(is_failed(FailReason::Disconnected)), "{ev:?}");
    assert_eq!(key_of(ev.last().unwrap()), key);
}

// ----------------------------------------------------------- правило прикрепления

/// Закрытое соединение живое не вытесняет; из двух живых остаётся новое.
#[tokio::test]
async fn reoffer_on_closed_conn_does_not_replace_live() {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let (_tx1, mut rx1) = f.offer(&r.peer).await;
    wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let ch =
        r.p.tr
            .inner()
            .relink
            .lock()
            .unwrap()
            .get(&f.key)
            .cloned()
            .unwrap();
    // повтор по уже закрытому соединению отбрасывается, прежний поток остаётся
    let c2 = FakeConn::lonely(r.pair);
    let p2 = c2.peer();
    let (_ptx2, mut prx2) = p2.open_bi().await.unwrap();
    let (tx2, rx2) = c2.accept_bi().await.unwrap();
    c2.close();
    assert!(
        ch.try_send(Reoffer {
            conn: c2.clone(),
            tx: tx2,
            rx: rx2,
            buf: Vec::new()
        })
        .is_ok()
    );
    assert!(is_eof(&mut prx2).await);
    assert!(!is_eof(&mut rx1).await);
    // живое соединение заменяет прежнее: старый поток закрыт, новым управляет отправитель
    let c3 = FakeConn::lonely(r.pair);
    let p3 = c3.peer();
    let (mut ptx3, _prx3) = p3.open_bi().await.unwrap();
    let (tx3, rx3) = c3.accept_bi().await.unwrap();
    assert!(
        ch.try_send(Reoffer {
            conn: c3.clone(),
            tx: tx3,
            rx: rx3,
            buf: Vec::new()
        })
        .is_ok()
    );
    assert!(is_eof(&mut rx1).await);
    // отмена по старому потоку уже ничего не значит, по новому закрывает предложение
    send_frame(
        &mut ptx3,
        &Message::Cancel {
            id: f.key.id,
            reason: CancelReason::User,
        },
    )
    .await;
    let ev = collect_until(&mut r.p.ev, 10, is_bad).await;
    assert!(
        matches!(
            ev.last(),
            Some(TransferEvent::Cancelled {
                by: Side::Sender,
                ..
            })
        ),
        "{ev:?}"
    );
}

// ------------------------------------------------------------------ надгробия, ключи

/// Таблица надгробий ограничена: вытесненный ключ получает новое окно решения (безопасный
/// исход), свежий отвечается из таблицы.
#[tokio::test]
async fn tombstones_bounded() {
    let mut r = raw_receiver(|c| c.max_pending_offers = 2).await;
    let mut fakes = Vec::new();
    for i in 0..3u64 {
        let f = Fake::new(r.pair, vec![FakeFile::new("a.bin", rand_bytes(i + 1, 100))]);
        let (_tx, mut rx) = f.offer(&r.peer).await;
        let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
        let k = key_of(&e);
        r.p.tr.respond(&k, false).unwrap();
        assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Decline));
        wait_ev(&mut r.p.ev, 10, is_answered(false)).await;
        fakes.push(f);
    }
    // свежее надгробие: ответ без окна решения
    let (_tx, mut rx) = fakes[2].offer(&r.peer).await;
    assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Decline));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rest = drain(&mut r.p.ev).await;
    assert_eq!(count_offers(&rest), 0, "{rest:?}");
    // вытесненное: новое окно решения
    let (_tx0, _rx0) = fakes[0].offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    assert_eq!(key_of(&e), fakes[0].key);
}

/// Тот же `TransferId` от другого друга это другое предложение со своим окном решения.
#[tokio::test]
async fn same_id_from_other_pair_is_separate() {
    let mut pre = Pre::new();
    let (p1, p2) = (pre.solo_friend(), pre.solo_friend());
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    big_cfg(&mut cfg);
    let mut p = Peer::start(node, partial, dest, cfg);
    let (c1, c2) = (FakeConn::lonely(p1), FakeConn::lonely(p2));
    p.node.t.push_incoming(c1.clone());
    p.node.t.push_incoming(c2.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let f1 = Fake::new(p1, vec![FakeFile::new("a.bin", rand_bytes(1, 100))]);
    let mut f2 = Fake::new(p2, vec![FakeFile::new("a.bin", rand_bytes(1, 100))]);
    f2.key = TransferKey {
        pair: p2,
        id: f1.key.id,
    };
    let (_t1, _r1) = f1.offer(&c1.peer()).await;
    let k1 = key_of(&wait_ev(&mut p.ev, 10, is_offer()).await);
    let (_t2, _r2) = f2.offer(&c2.peer()).await;
    let k2 = key_of(&wait_ev(&mut p.ev, 10, is_offer()).await);
    assert_eq!(k1, f1.key);
    assert_eq!(k2, f2.key);
    assert_ne!(k1, k2);
    assert!(p.tr.offer(&k1).is_some());
    assert!(p.tr.offer(&k2).is_some());
    p.tr.respond(&k2, false).unwrap();
    wait_ev(&mut p.ev, 10, is_answered(false)).await;
    assert!(p.tr.offer(&k1).is_some());
    assert!(p.tr.offer(&k2).is_none());
}

/// Хэширование один раз на сессию, сколько бы раз предложение ни повторялось.
#[tokio::test]
async fn relink_hashes_once() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let data = rand_bytes(17, 5 << 20);
    let blocks = crate::layout(data.len() as u64).unwrap().block_count as usize;
    let files = vec![write_src(src.path(), "a.bin", &data)];
    rig.cur.0.close();
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    rig.cur = rig.link().await;
    let first_b = collect_until(&mut rig.b.ev, 20, is_offer()).await;
    let kb = key_of(first_b.last().unwrap());
    // ещё одна замена связи, пока предложение ждёт
    rig.cur.0.close();
    tokio::time::sleep(Duration::from_millis(100)).await;
    rig.cur = rig.link().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    rig.b.tr.respond(&kb, true).unwrap();
    collect_until(&mut rig.b.ev, 60, is_completed(kb)).await;
    collect_until(&mut rig.a.ev, 60, is_completed(key)).await;
    let n = rig
        .a
        .hook
        .events()
        .iter()
        .filter(|e| matches!(e, Ev::HashBlock(..)))
        .count();
    assert_eq!(n, blocks);
}

// ------------------------------------------------- круг правок 1 после ревью безопасности

/// Сколько записей предела `ctl_in_per_min` сейчас занято у друга.
fn ctl_used(r: &Raw) -> usize {
    crate::shared::lock(&r.p.tr.inner().reg)
        .ctl_recent
        .get(&r.pair)
        .map_or(0, std::collections::VecDeque::len)
}

/// Честные повторы (1 предложение + 8 повторов за секунды) не тратят общий предел потоков
/// (6 в минуту): все доходят до ожидающего предложения.
#[tokio::test]
async fn relinks_do_not_spend_ctl_budget() {
    let mut r = raw_receiver(|c| c.ctl_in_per_min = 6).await;
    let f = fake_two(r.pair);
    let (_tx0, _rx0) = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    let mut held = Vec::new();
    for _ in 0..MAX_OFFER_RELINKS {
        held.push(f.offer(&r.peer).await);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    r.p.tr.respond(&k, true).unwrap();
    // последний повтор прикреплён: ответ идёт ему
    let (_tx, rx) = held.last_mut().unwrap();
    assert_eq!(Fake::decision(rx, 10).await, Some(Verdict::Accept));
    assert_eq!(ctl_used(&r), 1, "re-offers must be refunded");
    let rest = drain(&mut r.p.ev).await;
    assert_eq!(count_offers(&rest), 0, "{rest:?}");
}

/// Поток с неизвестным ключом возвращать нельзя: наводнение чужих ID по-прежнему упирается в
/// предел, лишние потоки закрываются без ответа.
#[tokio::test]
async fn unknown_id_flood_stays_limited() {
    let mut r = raw_receiver(|c| c.ctl_in_per_min = 6).await;
    let mut held = Vec::new();
    for i in 0..10u64 {
        let f = Fake::new(r.pair, vec![FakeFile::new("a.bin", rand_bytes(i + 1, 100))]);
        let s = f.offer(&r.peer).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        held.push(s);
    }
    wait_ev(&mut r.p.ev, 10, is_offer()).await;
    for (i, (_tx, rx)) in held.iter_mut().enumerate() {
        match i {
            0 => {}
            1..=5 => assert_eq!(Fake::decision(rx, 5).await, Some(Verdict::Busy), "{i}"),
            _ => assert!(recv_frame(rx, 1).await.is_none(), "{i}"),
        }
    }
    assert_eq!(ctl_used(&r), 6);
    let rest = drain(&mut r.p.ev).await;
    assert_eq!(count_offers(&rest), 0, "{rest:?}");
}

/// Ожидающее предложение, у которого ответ уже взят другим (имитация победителя гонки).
async fn pending_with_winner() -> (
    Raw,
    TransferKey,
    std::sync::Arc<crate::receiver::RecvSession>,
    tokio::sync::oneshot::Sender<bool>,
    (FakeTx, FakeRx),
) {
    let mut r = raw_receiver(|_| {}).await;
    let f = fake_two(r.pair);
    let ctl = f.offer(&r.peer).await;
    let e = wait_ev(&mut r.p.ev, 10, is_offer()).await;
    let k = key_of(&e);
    settle().await;
    let inner = r.p.tr.inner();
    let s = inner.find_inb(&k).unwrap();
    // победитель: взял ответ и записал своё надгробие, но ещё не остановил `pending_task`
    let ans = s.take_answer().unwrap();
    inner.remove_inb_tomb(&k, crate::inner::Tomb::Protocol);
    (r, k, s, ans, ctl)
}

/// Проигравший конец не выдаёт события, не пишет в поток и не затирает надгробие; победитель
/// потом спокойно закрывает задачу.
async fn assert_loser_quiet(
    r: &mut Raw,
    k: &TransferKey,
    s: &crate::receiver::RecvSession,
    ans: tokio::sync::oneshot::Sender<bool>,
    rx: &mut FakeRx,
) {
    settle().await;
    let quiet = drain(&mut r.p.ev).await;
    assert!(quiet.is_empty(), "loser emitted: {quiet:?}");
    assert_eq!(
        r.p.tr.inner().tomb_get(k),
        Some(crate::inner::Tomb::Protocol)
    );
    assert!(recv_frame(rx, 0).await.is_none(), "loser wrote to the peer");
    s.end.stop();
    drop(ans);
    settle().await;
    let after = drain(&mut r.p.ev).await;
    assert!(after.is_empty(), "{after:?}");
    assert!(crate::shared::lock(&r.p.tr.inner().relink).get(k).is_none());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn deadline_loses_to_answer_winner() {
    let _t = timing_shared();
    let (mut r, k, s, ans, (_tx, mut rx)) = pending_with_winner().await;
    let left = s.offer_deadline - tokio::time::Instant::now();
    tokio::time::advance(left - Duration::from_millis(1)).await;
    // надгробие победителя за срок устарело: победитель записывает его заново перед самым сроком
    r.p.tr
        .inner()
        .remove_inb_tomb(&k, crate::inner::Tomb::Protocol);
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_loser_quiet(&mut r, &k, &s, ans, &mut rx).await;
}

#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn grace_loses_to_answer_winner() {
    let _t = timing_shared();
    let (mut r, k, s, ans, (_tx, mut rx)) = pending_with_winner().await;
    r.peer.close();
    settle().await;
    let grace = r.p.cfg.offer_relink_grace;
    tokio::time::advance(grace + Duration::from_millis(1)).await;
    assert_loser_quiet(&mut r, &k, &s, ans, &mut rx).await;
}

#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn sender_cancel_and_violation_lose_to_answer_winner() {
    let _t = timing_shared();
    // CANCEL от отправителя
    let (mut r, k, s, ans, (mut tx, mut rx)) = pending_with_winner().await;
    super::fake::cancel(&mut tx, k.id, CancelReason::User).await;
    assert_loser_quiet(&mut r, &k, &s, ans, &mut rx).await;
    // нарушение на потоке управления
    let (mut r, k, s, ans, (mut tx, mut rx)) = pending_with_winner().await;
    let other = TransferId::generate().unwrap();
    super::fake::cancel(&mut tx, other, CancelReason::User).await;
    assert_loser_quiet(&mut r, &k, &s, ans, &mut rx).await;
}

/// Отправитель в `Offering` с живым потоком: сырой получатель прочитал предложение целиком.
async fn offered_sender() -> (
    Peer,
    TransferKey,
    (FakeConn, std::sync::Arc<TestDir>),
    FakeTx,
    FakeRx,
    std::sync::Arc<crate::sender::SendSession>,
) {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    big_cfg(&mut cfg);
    let p = Peer::start(node, partial, dest, cfg);
    let c0 = FakeConn::lonely(pair);
    p.node.t.push_incoming(c0.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let src = TestDir::new();
    let key =
        p.tr.send(
            &pair,
            vec![write_src(src.path(), "a.bin", &rand_bytes(3, 1000))],
        )
        .unwrap();
    let t0 = c0.peer();
    let (tx, mut rx) = t0.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    rx.read(&mut kind).await.unwrap();
    assert!(matches!(
        recv_frame(&mut rx, 5).await,
        Some(Message::OfferHead { .. })
    ));
    assert!(matches!(
        recv_frame(&mut rx, 5).await,
        Some(Message::OfferFiles(_))
    ));
    let s = p.tr.inner().find_out(&key).unwrap();
    (p, key, (c0, src), tx, rx, s)
}

fn pick_disconnected(_: Option<&crate::sender::SAttempt>) -> crate::receiver::Finish {
    crate::receiver::Finish::Failed(FailReason::Disconnected)
}

/// Порядок 1: принятие раньше срока. Условное завершение ничего не делает, срок предложения
/// принятую передачу не обрывает.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn ttl_and_limits_lose_to_accept() {
    let _t = timing_shared();
    let (mut p, key, _c0, mut tx, _rx, s) = offered_sender().await;
    send_frame(
        &mut tx,
        &Message::Decision {
            id: key.id,
            verdict: Verdict::Accept,
        },
    )
    .await;
    collect_until(&mut p.ev, 10, is_started).await;
    assert!(!crate::sender::finish_offering(
        p.tr.inner(),
        &s,
        pick_disconnected
    ));
    assert!(!s.is_finished());
    let ttl = p.cfg.offer_ttl + Duration::from_secs(31);
    tokio::time::advance(ttl).await;
    settle().await;
    let rest = drain(&mut p.ev).await;
    assert!(!rest.iter().any(is_failed(FailReason::Expired)), "{rest:?}");
    assert!(
        !rest.iter().any(is_failed(FailReason::Disconnected)),
        "{rest:?}"
    );
}

/// Порядок 2: срок раньше принятия. Ровно одно итоговое событие, а запоздалое принятие
/// закончившуюся передачу не оживляет.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn accept_loses_to_ttl_and_finished_stays_finished() {
    let _t = timing_shared();
    let (mut p, key, _c0, mut tx, mut rx, s) = offered_sender().await;
    let ttl = p.cfg.offer_ttl + Duration::from_secs(31);
    tokio::time::advance(ttl).await;
    settle().await;
    let ev = drain(&mut p.ev).await;
    assert_eq!(count(&ev, is_failed(FailReason::Expired)), 1, "{ev:?}");
    assert!(
        recv_frame(&mut rx, 1).await.is_some_and(|m| matches!(
            m,
            Message::Cancel {
                reason: CancelReason::User,
                ..
            }
        )),
        "no CANCEL(User) on the stream"
    );
    assert!(s.is_finished());
    // условное завершение второй раз и запоздалое принятие ничего не меняют
    assert!(!crate::sender::finish_offering(
        p.tr.inner(),
        &s,
        pick_disconnected
    ));
    let mut out = Vec::new();
    crate::encode(
        &Message::Decision {
            id: key.id,
            verdict: Verdict::Accept,
        },
        &mut out,
    )
    .unwrap();
    let _ = tx.write_all(&out).await;
    settle().await;
    let late = drain(&mut p.ev).await;
    assert!(late.is_empty(), "{late:?}");
    assert!(s.is_finished());
}

/// Условное завершение из `Offering` срабатывает ровно один раз.
#[tokio::test(start_paused = true)]
#[allow(clippy::await_holding_lock)]
async fn finish_offering_wins_once() {
    let _t = timing_shared();
    let (mut p, key, _c0, _tx, _rx, s) = offered_sender().await;
    assert!(crate::sender::finish_offering(
        p.tr.inner(),
        &s,
        pick_disconnected
    ));
    assert!(!crate::sender::finish_offering(
        p.tr.inner(),
        &s,
        pick_disconnected
    ));
    let ev = drain(&mut p.ev).await;
    assert_eq!(count(&ev, is_failed(FailReason::Disconnected)), 1, "{ev:?}");
    assert_eq!(key_of(ev.last().unwrap()), key);
}

/// Окно в `handle_resume` между снятием старой попытки и постановкой новой: попытка, которую
/// предложение поставило в этом окне, при замене останавливается и не остаётся брошенной.
#[tokio::test]
async fn resume_stops_attempt_installed_in_window() {
    let (p, key, (_c0, _src), _tx, _rx, s) = offered_sender().await;
    let old = s.current_attempt().expect("offer attempt");
    // держим старую попытку «занятой»: RESUME снимет её и будет ждать, окно открыто
    let guard = old.tracker.guard();
    let c1 = FakeConn::lonely(key.pair);
    p.node.t.push_incoming(c1.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t1 = c1.peer();
    let (mut tx, mut rx) = t1.open_bi().await.unwrap();
    tx.write_all(&[crate::STREAM_TRANSFER_CTL]).await.unwrap();
    send_frame(&mut tx, &Message::Resume { id: key.id }).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while s.current_attempt().is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "RESUME did not take"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(old.stop.is_stopped());
    // предложение ставит свою попытку в окне
    let cb = FakeConn::lonely(key.pair);
    let (btx, brx) = cb.open_bi().await.unwrap();
    assert!(crate::sender::install_offer_attempt(
        p.tr.inner(),
        &s,
        cb.clone(),
        None,
        btx,
        brx
    ));
    let mid = s.current_attempt().expect("installed");
    assert!(!mid.stop.is_stopped());
    drop(guard);
    let got = recv_frame(&mut rx, 5).await;
    assert!(
        matches!(got, Some(Message::ResumeOk { .. })),
        "no RESUME_OK"
    );
    assert!(mid.stop.is_stopped(), "replaced attempt left running");
    let cur = s.current_attempt().expect("resume attempt");
    assert!(!std::sync::Arc::ptr_eq(&cur, &mid));
    assert!(!cur.stop.is_stopped());
}
