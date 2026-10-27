//! HASH_PROGRESS (R2-1): получатель не просит манифест файла, пока отправитель не сообщил, что
//! файл захэширован, и ждёт хэширования по продвижению, а не по фиксированному сроку.
//! Точка подмены `HookPoint::HashBlock` держит хэширование на нужном блоке. Тесты с остановкой
//! времени двигают часы только явным `advance`: пока работает блокирующая задача (писатель,
//! хэширование), tokio сам время не переводит.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_transport::{Connection, RecvStream, SendStream};

use super::fake::{Fake, FakeFile};
use super::kit::*;
use crate::{
    CancelReason, FailReason, Message, PauseReason, TransferConfig, TransferEvent, TransferEvents,
    TransferKey, Verdict, encode, read_message,
};

const MIB: u64 = 1 << 20;

/// Страховка от зависания при остановленном времени: по истечении реального срока процесс
/// завершается (иначе упавший тест ждал бы вечно).
pub(super) struct Failsafe(
    std::sync::mpsc::Sender<()>,
    std::sync::RwLockReadGuard<'static, ()>,
);

pub(super) fn failsafe(secs: u64) -> Failsafe {
    // общий доступ берётся до запуска таймера: ожидание за исключительным тестом (10 000
    // файлов, под нагрузкой минуты) не должно съедать срок страховки
    let shared = timing_shared();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if rx.recv_timeout(Duration::from_secs(secs))
            == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        {
            std::process::exit(101);
        }
    });
    Failsafe(tx, shared)
}

/// Ждёт условие, отдавая ход задачам и реальное время потокам (до 30 с реального времени).
pub(super) async fn until(mut f: impl FnMut() -> bool) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(30) {
        if f() {
            return true;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// Даёт всем задачам и потокам разойтись.
pub(super) async fn settle() {
    for _ in 0..30 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Двигает часы и даёт задачам отработать.
pub(super) async fn tick(d: Duration) {
    tokio::time::advance(d).await;
    settle().await;
}

/// Ждёт `Paused(Stalled)` по реальному времени (до 30 с); виртуальные часы при этом стоят.
async fn wait_stalled(ev: &mut TransferEvents, seen: &mut Vec<TransferEvent>) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(30) {
        if stalled_seen(ev, seen).await {
            return true;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// Ждёт `Preparing` с `hashed >= at_least` по реальному времени (до 60 с); виртуальные часы
/// при этом стоят. `false` и при паузе: роста после неё не будет.
async fn until_preparing(
    ev: &mut TransferEvents,
    seen: &mut Vec<TransferEvent>,
    at_least: u64,
) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        seen.extend(drain(ev).await);
        if seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Paused { .. }))
        {
            return false;
        }
        if seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Preparing { hashed, .. } if *hashed >= at_least))
        {
            return true;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// Ждёт паузу «обрыв связи» по реальному времени (до 30 с); виртуальные часы при этом стоят.
/// Обрыв замечается задачами приёмника, и под нагрузкой это отстаёт от тиков.
async fn wait_disconnected(ev: &mut TransferEvents, seen: &mut Vec<TransferEvent>) {
    let t0 = std::time::Instant::now();
    let is_it = |e: &TransferEvent| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )
    };
    while !seen.iter().any(is_it) && t0.elapsed() < Duration::from_secs(30) {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
        seen.extend(drain(ev).await);
    }
}

async fn stalled_seen(ev: &mut TransferEvents, seen: &mut Vec<TransferEvent>) -> bool {
    seen.extend(drain(ev).await);
    seen.iter().any(|e| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Stalled,
                ..
            }
        )
    })
}

/// Хэширование отправителя по блокам: первые `free_from` блоков (по общему счёту) ждут
/// `release`, остальные идут свободно.
struct HashGate {
    allowed: AtomicUsize,
    entered: AtomicUsize,
    free_from: usize,
    blocks: usize,
}

impl HashGate {
    /// `open`: сколько первых блоков проходит сразу.
    fn install(hook: &TestHook, open: usize, free_from: usize, blocks: usize) -> Arc<Self> {
        let g = Arc::new(Self {
            allowed: AtomicUsize::new(open),
            entered: AtomicUsize::new(0),
            free_from,
            blocks,
        });
        let g2 = g.clone();
        hook.set(move |ev| {
            if matches!(ev, Ev::HashBlock(..)) {
                let n = g2.entered.fetch_add(1, Ordering::SeqCst);
                if n < g2.free_from {
                    let t0 = std::time::Instant::now();
                    while g2.allowed.load(Ordering::SeqCst) <= n {
                        if t0.elapsed() > Duration::from_secs(60) {
                            return Err(io::Error::other("hash gate timeout"));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            Ok(())
        });
        g
    }

    /// Отпускает ещё один блок и ждёт, пока хэширование дойдёт до следующей остановки.
    async fn release(&self) {
        let n = self.allowed.fetch_add(1, Ordering::SeqCst) + 1;
        let want = (n + 1).min(self.blocks);
        assert!(
            until(|| self.entered.load(Ordering::SeqCst) >= want).await,
            "hashing did not advance"
        );
    }
}

// ------------------------------------------------------------------ поддельный отправитель

/// Настоящий получатель против поддельного отправителя, который шлёт кадры потока управления
/// вручную. Предложение уже получено.
struct Raw {
    p: Peer,
    fake: Fake,
    peer: FakeConn,
    tx: FakeTx,
    rx: FakeRx,
    key: TransferKey,
}

async fn raw(files: Vec<FakeFile>, tweak: impl FnOnce(&mut TransferConfig)) -> Raw {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    tweak(&mut cfg);
    let mut p = Peer::start(node, partial, dest, cfg);
    let conn = FakeConn::lonely(pair);
    p.node.t.push_incoming(conn.clone());
    for _ in 0..500 {
        if p.node.engine.connection(&pair).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let peer = conn.peer();
    let fake = Fake::new(pair, files);
    let (tx, rx) = fake.offer(&peer).await;
    let key = key_of(&wait_ev(&mut p.ev, 60, is_offer()).await);
    Raw {
        p,
        fake,
        peer,
        tx,
        rx,
        key,
    }
}

impl Raw {
    /// Принять и запустить обслуживание потоков данных (поток управления ведёт тест).
    async fn accept(&mut self) {
        self.p.tr.respond(&self.key, true).unwrap();
        // DECISION уходит после блокирующей записи каталога и состояния: под сильной нагрузкой
        // это дольше 10 с реального времени. Срок только от зависания, на проверку не влияет.
        assert_eq!(
            Fake::decision(&mut self.rx, 60).await,
            Some(Verdict::Accept)
        );
        self.fake.run(self.peer.clone(), None);
    }

    async fn progress(&mut self, hashed: u64) {
        send_frame(&mut self.tx, &Message::HashProgress { hashed }).await;
        settle().await;
    }

    /// Как `progress`, но `false`, если получатель уже закрыл поток управления (передача на
    /// паузе, а событие об этом ещё в пути).
    async fn progress_open(&mut self, hashed: u64) -> bool {
        let mut out = Vec::new();
        encode(&Message::HashProgress { hashed }, &mut out).unwrap();
        let open = self.tx.write_all(&out).await.is_ok();
        settle().await;
        open
    }

    /// Закрыл ли получатель поток управления (чтение даёт конец потока); пришедшие байты
    /// отбрасываются.
    async fn ctl_closed(&mut self) -> bool {
        let mut b = [0u8; 64];
        loop {
            match tokio::time::timeout(Duration::ZERO, self.rx.read(&mut b)).await {
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None) | Err(_)) => return true,
                Err(_) => return false,
            }
        }
    }

    fn manifests(&self) -> Vec<u32> {
        self.fake
            .log
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter_map(|r| match r {
                super::fake::Req::Manifest(i) => Some(*i),
                _ => None,
            })
            .collect()
    }

    /// Ждёт CANCEL{Protocol} от получателя.
    async fn protocol_cancel(&mut self) -> bool {
        loop {
            match recv_frame(&mut self.rx, 10).await {
                Some(Message::Cancel {
                    reason: CancelReason::Protocol,
                    ..
                }) => return true,
                Some(_) => {}
                None => return false,
            }
        }
    }
}

// --------------------------------------------------------------------------------- тесты

#[tokio::test(start_paused = true)]
async fn manifest_waits_for_hash_progress() {
    let _fs = failsafe(120);
    let files = vec![
        FakeFile::new("a", rand_bytes(1, (2 * MIB) as usize)),
        FakeFile::new("b", rand_bytes(2, (2 * MIB) as usize)),
    ];
    let (p0, p1) = (2 * MIB, 4 * MIB);
    let mut r = raw(files, |_| {}).await;
    r.accept().await;
    // кадров нет: манифестов нет ни на одном потоке данных
    tick(Duration::from_secs(5)).await;
    assert!(r.manifests().is_empty(), "{:?}", r.manifests());
    // файл 0 ещё не покрыт
    r.progress(p0 - 1).await;
    assert!(r.manifests().is_empty());
    r.progress(p0).await;
    assert!(until(|| r.manifests().contains(&0)).await);
    // файл 0 передан целиком; файл 1 не покрыт: манифеста нет
    loop {
        match recv_frame(&mut r.rx, 30).await {
            Some(Message::FileDone { index: 0 }) => break,
            Some(_) => {}
            None => panic!("no FILE_DONE for file 0"),
        }
    }
    tick(Duration::from_secs(5)).await;
    assert_eq!(r.manifests(), vec![0]);
    r.progress(p1 - 1).await;
    assert_eq!(r.manifests(), vec![0], "file 1 is not covered yet");
    r.progress(p1).await;
    assert!(until(|| r.manifests().contains(&1)).await);
}

#[tokio::test(start_paused = true)]
async fn slow_hash_longer_than_stall_completes() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(3);
    let mut rig = Rig::with(
        |_| {},
        move |c| {
            c.stall_timeout = stall;
            c.min_hash_rate = MIB;
        },
    )
    .await;
    let src = TestDir::new();
    let data = rand_bytes(81, (37 * MIB) as usize);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    // 20 блоков по одному за `stall / 2`: хэширование длится 10 `stall_timeout`
    let gate = HashGate::install(&rig.a.hook, 0, 20, 37);
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let kb = key_of(&wait_ev(&mut rig.b.ev, 10, is_offer()).await);
    rig.b.tr.respond(&kb, true).unwrap();
    let mut seen: Vec<TransferEvent> = Vec::new();
    for i in 0..20u64 {
        tick(stall / 2).await;
        // часы двигаются дальше, только когда получатель увидел рост от прошлого шага: иначе
        // под нагрузкой его отставание (блокирующая запись при принятии, задачи) складывалось
        // бы с виртуальными секундами, и он видел бы молчание, которого у отправителя не было
        if i > 0 {
            assert!(
                until_preparing(&mut rig.b.ev, &mut seen, i * MIB).await,
                "receiver did not see {i} MiB hashed: {seen:?}"
            );
        }
        gate.release().await;
    }
    // остальные блоки хэшируются без задержки, но в реальном времени, зависящем от нагрузки:
    // часы стоят, пока отправитель не сообщит, что захэшировал всё (иначе молчание считалось бы
    // по виртуальным секундам, ушедшим на чужую работу процессора)
    let t_hash = std::time::Instant::now();
    loop {
        let evs = drain(&mut rig.a.ev).await;
        if evs
            .iter()
            .any(|e| matches!(e, TransferEvent::Preparing { hashed, total, .. } if hashed == total))
        {
            break;
        }
        assert!(t_hash.elapsed() < Duration::from_secs(60), "hashing stuck");
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    // дальше события идут сами: часы двигаем понемногу, пока не завершится
    let mut done = false;
    for _ in 0..600 {
        seen.extend(drain(&mut rig.b.ev).await);
        if seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Completed { .. }))
        {
            done = true;
            break;
        }
        tick(Duration::from_millis(200)).await;
    }
    assert!(done, "transfer did not complete: {seen:?}");
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Paused { .. })),
        "paused: {seen:?}"
    );
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // `Preparing`: значения растут, последнее равно размеру предложения
    let prep: Vec<u64> = seen
        .iter()
        .filter_map(|e| match e {
            TransferEvent::Preparing { hashed, total, .. } => {
                assert_eq!(*total, 37 * MIB);
                Some(*hashed)
            }
            _ => None,
        })
        .collect();
    assert!(prep.len() >= 5, "{prep:?}");
    assert!(prep.windows(2).all(|w| w[0] < w[1]), "{prep:?}");
    assert_eq!(prep.last().copied(), Some(37 * MIB));
}

#[tokio::test(start_paused = true)]
async fn hash_progress_silence_pauses_stalled() {
    let _fs = failsafe(120);
    let stall = Duration::from_secs(10);
    // большое предложение: правило скорости далеко, действует только молчание
    let files = vec![FakeFile::new("a", vec![0u8; (64 * MIB) as usize])];
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.accept().await;
    tick(Duration::from_secs(3)).await;
    // один кадр, затем тишина: срок считается от кадра, а не от начала попытки
    r.progress(1000).await;
    let mut seen = Vec::new();
    tick(stall - Duration::from_millis(1)).await;
    assert!(
        !stalled_seen(&mut r.p.ev, &mut seen).await,
        "one tick early"
    );
    tick(Duration::from_millis(2)).await;
    let ok = until_stalled(&mut r.p.ev, &mut seen).await;
    assert!(ok, "no Paused(Stalled) at stall_timeout after the frame");
}

async fn until_stalled(ev: &mut TransferEvents, seen: &mut Vec<TransferEvent>) -> bool {
    for _ in 0..2000 {
        if stalled_seen(ev, seen).await {
            return true;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

#[tokio::test(start_paused = true)]
async fn hash_progress_trickle_capped() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(10);
    let files = vec![FakeFile::new("big", vec![0u8; (64 * MIB) as usize])];
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.accept().await;
    let t0 = tokio::time::Instant::now();
    let mut seen = Vec::new();
    let mut k = 0u64;
    let mut at = None;
    'outer: while t0.elapsed() < stall + Duration::from_secs(80) {
        k += 1;
        // +1 байт раз в `stall / 2`
        if !r.progress_open(k).await {
            // поток закрыт получателем: пауза наступила, событие о ней под нагрузкой могло
            // отстать от тика. Часы стоят, так что `at` не вырастет, пока ждём его по событию.
            at = Some(t0.elapsed());
            assert!(
                wait_stalled(&mut r.p.ev, &mut seen).await,
                "stream closed without Paused(Stalled): {seen:?}"
            );
            break 'outer;
        }
        for _ in 0..5 {
            tick(stall / 10).await;
            // закрытие потока управления идёт раньше события о паузе и не отстаёт от тика
            let paused = stalled_seen(&mut r.p.ev, &mut seen).await;
            if paused || r.ctl_closed().await {
                at = Some(t0.elapsed());
                assert!(
                    paused || wait_stalled(&mut r.p.ev, &mut seen).await,
                    "stream closed without Paused(Stalled): {seen:?}"
                );
                break 'outer;
            }
        }
    }
    let at = at.expect("no Paused(Stalled)");
    assert!(
        at <= stall + Duration::from_secs(64 + 1),
        "paused too late: {at:?}"
    );
    assert!(
        at >= stall + Duration::from_secs(60),
        "paused too early (rate rule only): {at:?}"
    );
}

#[tokio::test]
async fn hash_progress_rules() {
    let one = || vec![FakeFile::new("a", rand_bytes(4, (2 * MIB) as usize))];
    let total = 2 * MIB;
    // уменьшение
    let mut r = raw(one(), |_| {}).await;
    r.accept().await;
    r.progress(5).await;
    r.progress(3).await;
    assert!(r.protocol_cancel().await, "decrease");
    // повтор в пределах попытки
    let mut r = raw(one(), |_| {}).await;
    r.accept().await;
    r.progress(5).await;
    r.progress(5).await;
    assert!(r.protocol_cancel().await, "repeat");
    // больше размера предложения
    let mut r = raw(one(), |_| {}).await;
    r.accept().await;
    r.progress(total + 1).await;
    assert!(r.protocol_cancel().await, "over total");
    // кадр после достижения размера
    let mut r = raw(one(), |_| {}).await;
    r.accept().await;
    r.progress(total).await;
    r.progress(total).await;
    assert!(r.protocol_cancel().await, "after total");
    // до DECISION
    let mut r = raw(one(), |_| {}).await;
    r.progress(1).await;
    assert!(r.protocol_cancel().await, "before DECISION");
    // длина тела 8 и 10 байт: Malformed
    for body_len in [8usize, 10] {
        let mut r = raw(one(), |_| {}).await;
        r.accept().await;
        let mut f = u32::try_from(body_len).unwrap().to_be_bytes().to_vec();
        f.push(0x0A);
        f.extend(vec![0u8; body_len - 1]);
        r.tx.write_all(&f).await.unwrap();
        assert!(r.protocol_cancel().await, "body of {body_len} bytes");
    }
    // допустимая последовательность не вызывает отмены
    let mut r = raw(one(), |_| {}).await;
    r.accept().await;
    r.progress(1).await;
    r.progress(2).await;
    r.progress(total).await;
    assert!(
        try_ev(&mut r.p.ev, 300, |e| matches!(
            e,
            TransferEvent::Failed {
                reason: FailReason::Protocol,
                ..
            }
        ))
        .await
        .is_none()
    );
}

#[tokio::test]
async fn hash_progress_across_resume() {
    // Событие `Preparing` получателя ограничено `progress_interval` и не повторяется, пока
    // `hashed` не растёт (хэширование стоит на заслонке): первый кадр новой попытки, пришедший
    // раньше чем через интервал после прежнего события, не дал бы события никогда. Нулевой
    // интервал делает событие на каждый принятый кадр, и тест не зависит от скорости машины.
    let mut rig = Rig::with(|_| {}, |c| c.progress_interval = Duration::ZERO).await;
    let src = TestDir::new();
    let data = rand_bytes(82, (20 * MIB) as usize);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    // хэширование держится на блоке 5 (блоки 0..4 готовы)
    let gate = HashGate::install(&rig.a.hook, 5, 6, 20);
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let kb = key_of(&wait_ev(&mut rig.b.ev, 60, is_offer()).await);
    rig.b.tr.respond(&kb, true).unwrap();
    let before = wait_ev(
        &mut rig.b.ev,
        60,
        |e| matches!(e, TransferEvent::Preparing { hashed, .. } if *hashed >= 5 * MIB),
    )
    .await;
    let TransferEvent::Preparing { hashed: h1, .. } = before else {
        panic!("not Preparing");
    };
    // обрыв, пока хэширование стоит
    rig.cur.0.close();
    wait_ev(&mut rig.b.ev, 60, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    wait_ev(&mut rig.a.ev, 60, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    rig.cur = rig.link().await;
    wait_ev(&mut rig.b.ev, 60, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    // первый кадр новой попытки не меньше прежнего значения (иначе получатель отменил бы)
    let after = wait_ev(&mut rig.b.ev, 60, |e| {
        matches!(e, TransferEvent::Preparing { .. })
    })
    .await;
    let TransferEvent::Preparing { hashed: h2, .. } = after else {
        panic!("not Preparing");
    };
    assert!(h2 >= h1, "{h2} < {h1}");
    // хэширование продолжается с того места, где стояло
    gate.release().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // каждый блок источника захэширован ровно один раз
    let mut hashed: Vec<(u32, u32)> = rig
        .a
        .hook
        .events()
        .iter()
        .filter_map(|e| match e {
            Ev::HashBlock(f, b) => Some((*f, *b)),
            _ => None,
        })
        .collect();
    hashed.sort_unstable();
    assert_eq!(hashed, (0..20).map(|b| (0, b)).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn sender_hash_progress_frames_bounded() {
    let _fs = failsafe(120);
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let p = Peer::start(node, partial.clone(), dest, small_cfg(partial.path()));
    let conn = FakeConn::lonely(pair);
    p.node.t.push_incoming(conn.clone());
    for _ in 0..500 {
        if p.node.engine.connection(&pair).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let peer = conn.peer();
    let src = TestDir::new();
    let files = vec![write_src(
        src.path(),
        "a.bin",
        &rand_bytes(83, (4 * MIB) as usize),
    )];
    // четыре блока: три отпускаются по секунде, последний на полпути между кадрами
    let gate = HashGate::install(&p.hook, 0, 4, 4);
    let _key = p.tr.send(&pair, files).unwrap();
    // получатель играет тест: принимает предложение и считает кадры HASH_PROGRESS
    let (mut tx, mut rx) = peer.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    assert_eq!(rx.read(&mut kind).await.unwrap(), Some(1));
    let mut buf = Vec::new();
    let head = read_message(&mut rx, &mut buf, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(head, Some(Message::OfferHead { .. })));
    let files_msg = read_message(&mut rx, &mut buf, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(files_msg, Some(Message::OfferFiles(_))));
    let Some(Message::OfferHead { id, .. }) = head else {
        panic!("no OFFER_HEAD");
    };
    send_frame(
        &mut tx,
        &Message::Decision {
            id,
            verdict: Verdict::Accept,
        },
    )
    .await;
    let frames: Arc<Mutex<Vec<(tokio::time::Instant, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let f2 = frames.clone();
    tokio::spawn(async move {
        let mut buf = Vec::new();
        while let Ok(Some(m)) = read_message(&mut rx, &mut buf, Duration::from_secs(30)).await {
            if let Message::HashProgress { hashed } = m {
                f2.lock()
                    .unwrap()
                    .push((tokio::time::Instant::now(), hashed));
            }
        }
    });
    settle().await;
    let t0 = tokio::time::Instant::now();
    for _ in 0..3 {
        tick(Duration::from_secs(1)).await;
        gate.release().await;
    }
    tick(Duration::from_millis(500)).await;
    gate.release().await;
    let t_last = tokio::time::Instant::now();
    // последний блок хэшируется в блокирующей задаче, её время зависит от нагрузки процессора:
    // кадр с полным размером ждём по событию, а не по фиксированной паузе. Часы стоят, так что
    // кадр, дожидавшийся тика, не появился бы никогда.
    let total_seen = until(|| {
        frames
            .lock()
            .unwrap()
            .last()
            .is_some_and(|f| f.1 == 4 * MIB)
    })
    .await;
    assert!(
        total_seen,
        "no total frame: {:?}",
        frames.lock().unwrap().clone()
    );
    settle().await;
    tick(Duration::from_millis(500)).await;
    let got = frames.lock().unwrap().clone();
    assert!(got.len() <= 6, "{} frames in 4 s: {got:?}", got.len());
    // значения растут, последнее равно размеру предложения и ушло сразу, а не по тику
    assert!(got.windows(2).all(|w| w[0].1 < w[1].1), "{got:?}");
    let (t_total, v_total) = *got.last().unwrap();
    assert_eq!(v_total, 4 * MIB);
    assert!(
        t_total.saturating_duration_since(t_last) < Duration::from_millis(100),
        "total frame waited for a tick: {:?}",
        t_total.saturating_duration_since(t_last)
    );
    assert!(t_total > t0);
}

#[test]
fn preparing_text_has_no_placeholders() {
    assert!(!crate::PREPARING_TEXT.contains('{'));
    assert!(!crate::PREPARING_TEXT.is_empty());
}

// ------------------------------------------------ N1: отправитель перезапускает попытки

/// Играет за враждебного отправителя на уже принятой передаче: каждую новую попытку получателя
/// (RESUME на новом потоке управления) встречает RESUME_OK и одним кадром HASH_PROGRESS, держит
/// поток управления `hold` и закрывает его. Потоки данных остаются открытыми и молчат.
fn restarting_sender(
    peer: FakeConn,
    key: TransferKey,
    files: u32,
    total: u64,
    hold: Duration,
    frame: impl Fn(u32) -> u64 + Send + 'static,
) -> Arc<AtomicUsize> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let n = attempts.clone();
    tokio::spawn(async move {
        let mut held: Vec<(FakeTx, FakeRx)> = Vec::new();
        while let Ok((mut tx, mut rx)) = peer.accept_bi().await {
            let mut kind = [0u8; 1];
            if !matches!(rx.read(&mut kind).await, Ok(Some(1))) {
                continue;
            }
            if kind[0] == crate::STREAM_TRANSFER_DATA {
                held.push((tx, rx));
                continue;
            }
            let mut buf = Vec::new();
            let Ok(Some(Message::Resume { .. })) =
                read_message(&mut rx, &mut buf, Duration::from_secs(5)).await
            else {
                continue;
            };
            let k = u32::try_from(n.fetch_add(1, Ordering::SeqCst) + 1).unwrap();
            send_frame(
                &mut tx,
                &Message::ResumeOk {
                    id: key.id,
                    file_count: files,
                    total_size: total,
                },
            )
            .await;
            send_frame(&mut tx, &Message::HashProgress { hashed: frame(k) }).await;
            tokio::time::sleep(hold).await;
            let _ = tx.finish();
            held.push((tx, rx));
        }
    });
    attempts
}

impl Raw {
    /// Принять предложение, но потоки данных и поток управления ведёт тест.
    async fn respond_only(&mut self) {
        self.p.tr.respond(&self.key, true).unwrap();
        // срок как в `accept`
        assert_eq!(
            Fake::decision(&mut self.rx, 60).await,
            Some(Verdict::Accept)
        );
    }

    /// Первая попытка: кадр, пауза `hold`, поток управления закрывается.
    async fn first_attempt(&mut self, frame: u64, hold: Duration) {
        self.progress(frame).await;
        tick(hold).await;
        let _ = self.tx.finish();
    }
}

/// Двигает часы шагами, пока не появится `Paused{Stalled}` или не пройдёт `limit`. Возвращает
/// виртуальное время, прошедшее с `t0`.
async fn until_stalled_within(
    r: &mut Raw,
    t0: tokio::time::Instant,
    limit: Duration,
    seen: &mut Vec<TransferEvent>,
) -> Option<Duration> {
    while t0.elapsed() < limit {
        tick(Duration::from_millis(100)).await;
        // конец попытки уже назван, а уборка за ней (ожидание её задач и записи состояния) идёт
        // в реальном времени; решение о паузе принимается после уборки. Пока она идёт, часы
        // стоят: иначе под нагрузкой пауза приходила бы на тики позже своего срока
        assert!(
            until(|| !attempt_tearing_down(r)).await,
            "attempt teardown stuck"
        );
        if stalled_seen(&mut r.p.ev, seen).await {
            return Some(t0.elapsed());
        }
    }
    None
}

/// Попытка получателя закончена (`finish`), но ещё не убрана из сессии.
fn attempt_tearing_down(r: &Raw) -> bool {
    r.p.tr.inner().find_inb(&r.key).is_some_and(|s| {
        crate::shared::lock(&s.core)
            .att
            .as_ref()
            .is_some_and(|a| a.is_over())
    })
}

#[tokio::test(start_paused = true)]
async fn restarting_attempts_with_repeated_progress_end_stalled() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(10);
    let files = vec![FakeFile::new("a", vec![0u8; (64 * MIB) as usize])];
    let total = 64 * MIB;
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.respond_only().await;
    let t0 = tokio::time::Instant::now();
    let hold = Duration::from_secs(1);
    // отправитель каждый раз присылает одно и то же значение и закрывает поток управления
    let attempts = restarting_sender(r.peer.clone(), r.key, 1, total, hold, |_| 1000);
    r.first_attempt(1000, hold).await;
    let mut seen = Vec::new();
    let at = until_stalled_within(&mut r, t0, Duration::from_secs(60), &mut seen).await;
    let at = at.expect("restarting the control stream must not reset the timers");
    // молчание считается от первого роста (сессия), а не от начала каждой попытки
    assert!(
        at >= stall - Duration::from_millis(500),
        "too early: {at:?}"
    );
    assert!(at <= stall + Duration::from_secs(2), "too late: {at:?}");
    assert!(
        attempts.load(Ordering::SeqCst) >= 2,
        "not a restarting sender"
    );
}

#[tokio::test(start_paused = true)]
async fn restarting_attempts_with_tiny_growth_end_stalled_by_rate() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(10);
    let total = 8 * MIB;
    let files = vec![FakeFile::new("a", vec![0u8; total as usize])];
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.respond_only().await;
    let t0 = tokio::time::Instant::now();
    let hold = Duration::from_secs(1);
    // +1 байт в каждой попытке: рост настоящий, молчания нет, но предел по скорости сессии
    // (stall + total / min_hash_rate = 18 с) не сбрасывается новой попыткой
    let attempts = restarting_sender(r.peer.clone(), r.key, 1, total, hold, |k| u64::from(k) + 1);
    r.first_attempt(1, hold).await;
    let mut seen = Vec::new();
    let at = until_stalled_within(&mut r, t0, Duration::from_secs(90), &mut seen).await;
    let at = at.expect("tiny growth with restarts must end Stalled");
    let bound = stall + Duration::from_secs(8);
    assert!(
        at >= bound - Duration::from_millis(500),
        "too early: {at:?}"
    );
    assert!(at <= bound + Duration::from_secs(2), "too late: {at:?}");
    assert!(attempts.load(Ordering::SeqCst) >= 4);
}

#[tokio::test(start_paused = true)]
async fn restarting_attempts_without_blocks_end_stalled() {
    let _fs = failsafe(240);
    let total = 2 * MIB;
    let files = vec![FakeFile::new("a", rand_bytes(5, total as usize))];
    let mut r = raw(files, |c| c.stall_timeout = Duration::from_secs(10)).await;
    r.respond_only().await;
    let t0 = tokio::time::Instant::now();
    let hold = Duration::from_secs(1);
    // всё захэшировано, манифест просят, но отправитель его не отдаёт и каждый раз закрывает
    // поток управления: обрывы без продвижения копятся в сессии (3 на поток данных)
    let attempts = restarting_sender(r.peer.clone(), r.key, 1, total, hold, move |_| total);
    r.first_attempt(total, hold).await;
    let mut seen = Vec::new();
    let at = until_stalled_within(&mut r, t0, Duration::from_secs(120), &mut seen).await;
    assert!(at.is_some(), "attempts without progress must end Stalled");
    let n = attempts.load(Ordering::SeqCst);
    assert!((8..=16).contains(&n), "{n} attempts before the pause");
}

#[tokio::test(start_paused = true)]
async fn honest_resume_after_long_outage_is_not_stalled() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(10);
    let total = 8 * MIB;
    let data = rand_bytes(6, total as usize);
    let files = vec![FakeFile::new("a", data.clone())];
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.accept().await;
    r.progress(MIB).await;
    let mut seen = Vec::new();
    // настоящий обрыв, связи нет намного дольше любого срока ожидания хэширования
    r.peer.close();
    for _ in 0..10 {
        tick(Duration::from_secs(6)).await;
        seen.extend(drain(&mut r.p.ev).await);
    }
    wait_disconnected(&mut r.p.ev, &mut seen).await;
    assert!(
        seen.iter().any(|e| matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )),
        "{seen:?}"
    );
    // новое соединение; отправитель честно закончил хэширование за это время
    let pair = r.key.pair;
    let conn2 = FakeConn::lonely(pair);
    r.p.node.t.push_incoming(conn2.clone());
    let peer2 = conn2.peer();
    let (mut tx, mut rx) = peer2.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    assert_eq!(rx.read(&mut kind).await.unwrap(), Some(1));
    let mut buf = Vec::new();
    let got = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await;
    assert!(matches!(got, Ok(Some(Message::Resume { .. }))));
    send_frame(
        &mut tx,
        &Message::ResumeOk {
            id: r.key.id,
            file_count: 1,
            total_size: total,
        },
    )
    .await;
    r.fake.run(peer2, Some((tx, rx)));
    let mut done = false;
    for _ in 0..400 {
        tick(Duration::from_millis(100)).await;
        seen.extend(drain(&mut r.p.ev).await);
        if seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Completed { .. }))
        {
            done = true;
            break;
        }
    }
    assert!(done, "transfer did not complete after the outage: {seen:?}");
    assert!(
        !seen.iter().any(|e| matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Stalled,
                ..
            }
        )),
        "stalled after an honest resume: {seen:?}"
    );
    let placed = placed_files(&r.p.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
}

/// Честный отправитель ещё хэширует, когда связь возвращается после долгого обрыва: время без
/// связи не идёт ни в предел по скорости, ни в молчание, иначе первый же кадр после
/// возобновления дал бы `Stalled`.
#[tokio::test(start_paused = true)]
async fn honest_partial_hash_after_long_outage_is_not_stalled() {
    let _fs = failsafe(240);
    let stall = Duration::from_secs(10);
    let total = 8 * MIB;
    let data = rand_bytes(7, total as usize);
    let files = vec![FakeFile::new("a", data.clone())];
    let mut r = raw(files, move |c| {
        c.stall_timeout = stall;
        c.min_hash_rate = MIB;
    })
    .await;
    r.accept().await;
    r.progress(MIB).await;
    let mut seen = Vec::new();
    r.peer.close();
    for _ in 0..10 {
        tick(Duration::from_secs(6)).await;
        seen.extend(drain(&mut r.p.ev).await);
    }
    wait_disconnected(&mut r.p.ev, &mut seen).await;
    assert!(
        seen.iter().any(|e| matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )),
        "{seen:?}"
    );
    let pair = r.key.pair;
    let conn2 = FakeConn::lonely(pair);
    r.p.node.t.push_incoming(conn2.clone());
    let peer2 = conn2.peer();
    let (mut tx, mut rx) = peer2.accept_bi().await.unwrap();
    let mut kind = [0u8; 1];
    assert_eq!(rx.read(&mut kind).await.unwrap(), Some(1));
    let mut buf = Vec::new();
    let got = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await;
    assert!(matches!(got, Ok(Some(Message::Resume { .. }))));
    send_frame(
        &mut tx,
        &Message::ResumeOk {
            id: r.key.id,
            file_count: 1,
            total_size: total,
        },
    )
    .await;
    r.fake.run(peer2, None);
    // за время обрыва отправитель захэшировал часть файла и продолжает со скоростью выше
    // минимальной (2 МиБ/с против 1 МиБ/с)
    let mut hashed = 3 * MIB;
    r.tx = tx;
    r.rx = rx;
    let mut done = false;
    for _ in 0..200 {
        if hashed <= total {
            r.progress(hashed).await;
            hashed = if hashed == total {
                total + 1
            } else {
                (hashed + 2 * MIB).min(total)
            };
        }
        tick(Duration::from_secs(1)).await;
        seen.extend(drain(&mut r.p.ev).await);
        if seen
            .iter()
            .any(|e| matches!(e, TransferEvent::Completed { .. }))
        {
            done = true;
            break;
        }
    }
    assert!(done, "transfer did not complete after the outage: {seen:?}");
    assert!(
        !seen.iter().any(|e| matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Stalled,
                ..
            }
        )),
        "stalled after an honest partial resume: {seen:?}"
    );
    let placed = placed_files(&r.p.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
}
