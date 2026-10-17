//! Обрыв и возобновление, перезапуск, пауза по диску, отмена, права друга, бюджет памяти.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chervo_transport::Connection;

use super::fake::{Fake, FakeFile, Req, Resp};
use super::kit::*;
use crate::paths::{part_path, session_dir, write_hashes, write_state};
use crate::state::{FileStatus, Progress, decode_state, encode_state};
use crate::util::Bits;
use crate::{
    FailReason, PauseReason, Side, TransferEvent, TransferKey, Verdict, encode_hashes, file_root,
    layout, leaf_hash, state_dir_name,
};

/// Мало потоков и окно 1: в полёте не больше двух блоков, обрыв приходится на середину.
fn narrow(c: &mut crate::TransferConfig) {
    c.streams = 2;
    c.per_stream_window = 1;
    // малый бюджет: пока писатель стоит, запросы упираются в память и передача не убегает вперёд
    c.recv_buffer_budget = 16 << 20;
}

/// Предложение от A к B: ключи на обеих сторонах.
async fn start_transfer(
    rig: &mut Rig,
    files: Vec<crate::SourceFile>,
) -> (TransferKey, TransferKey) {
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    assert_eq!(kb.id, key.id);
    (key, kb)
}

fn written_blocks(p: &Peer) -> Vec<(u32, u32)> {
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
async fn disconnect_mid_transfer_resumes() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(61, 40 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    // примерно на половине обрыв
    let conn = rig.cur.0.clone();
    let mut n = 0;
    rig.b.hook.set(move |ev| {
        if matches!(ev, Ev::Written(..)) {
            n += 1;
            if n == 20 {
                conn.close();
            }
        }
        Ok(())
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )
    })
    .await;
    wait_ev(&mut rig.a.ev, 30, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    rig.cur = rig.link().await;
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // записанные блоки заново не запрашивались: каждый записан ровно один раз
    let mut w = written_blocks(&rig.b);
    w.sort_unstable();
    assert_eq!(w, (0..40).map(|b| (0, b)).collect::<Vec<_>>());
}

#[tokio::test]
async fn resume_waits_for_old_writers() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(62, 40 << 20))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let conn = rig.cur.0.clone();
    let finished = Arc::new(AtomicBool::new(false));
    let f2 = finished.clone();
    let mut writes = 0;
    rig.b.hook.set(move |ev| {
        match ev {
            Ev::Write(..) => {
                writes += 1;
                if writes == 10 {
                    // обрыв, а писатель ещё занят этим блоком
                    conn.close();
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            Ev::Written(..) if writes >= 10 => f2.store(true, Ordering::SeqCst),
            _ => {}
        }
        Ok(())
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    rig.cur = rig.link().await;
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    // возобновление началось только после остановки писателя прежнего соединения
    assert!(finished.load(Ordering::SeqCst));
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
}

/// Останавливает получателя примерно на середине (писатель стоит на `n`-м блоке),
/// возвращает каталог состояния.
async fn stop_midway(rig: &mut Rig, kb: &TransferKey, n: usize) -> std::path::PathBuf {
    let gate = gate_after_written(&rig.b.hook, n);
    rig.b.tr.respond(kb, true).unwrap();
    gate.wait_reached().await;
    rig.b.tr.shutdown();
    gate.release();
    rig.b.tr.wait_stopped().await;
    session_dir(rig.b.partial.path(), &state_dir_name(&kb.pair, &kb.id))
}

#[tokio::test]
async fn resume_root_mismatch_restarts_file() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(63, 40 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let sdir = stop_midway(&mut rig, &kb, 8).await;
    // состояние и список хэшей согласованы между собой, но описывают другую версию файла
    let raw = std::fs::read(sdir.join("state")).unwrap();
    let mut st = decode_state(&raw).unwrap();
    let size = data.len() as u64;
    let l = layout(size).unwrap();
    let fake: Vec<_> = (0..l.block_count).map(|i| leaf_hash(i, b"other")).collect();
    let fake_root = file_root(size, l, &fake).unwrap();
    st.files[0].status = FileStatus::InProgress(Progress {
        layout: l,
        root: fake_root,
        bitmap: Bits::ones(l.block_count).bytes().to_vec(),
    });
    write_state(&sdir, &encode_state(&st)).unwrap();
    write_hashes(&sdir, 0, &encode_hashes(&fake)).unwrap();
    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // файл начат заново: все блоки записаны снова
    let mut w = written_blocks(&rig.b);
    w.sort_unstable();
    assert_eq!(w, (0..40).map(|b| (0, b)).collect::<Vec<_>>());
}

#[tokio::test]
async fn receiver_restart_resumes_with_reverify() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(64, 40 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let sdir = stop_midway(&mut rig, &kb, 10).await;
    let st = decode_state(&std::fs::read(sdir.join("state")).unwrap()).unwrap();
    let FileStatus::InProgress(p) = &st.files[0].status else {
        panic!("file is not in progress");
    };
    let bits = Bits::from_bytes(p.layout.block_count, &p.bitmap);
    let done: Vec<u32> = (0..p.layout.block_count).filter(|b| bits.get(*b)).collect();
    if done.len() < 5 {
        let log = rig.b.hook.events();
        let summary: Vec<String> = log
            .iter()
            .map(|e| match e {
                Ev::Written(f, b) => format!("W{f}/{b}"),
                Ev::Synced(f) => format!("S{f}"),
                Ev::StateWrite(b) => {
                    let st = decode_state(b).unwrap();
                    match &st.files[0].status {
                        FileStatus::InProgress(p) => format!(
                            "ST({})",
                            Bits::from_bytes(p.layout.block_count, &p.bitmap).count_ones()
                        ),
                        _ => "ST(other)".to_owned(),
                    }
                }
                Ev::Manifest(f) => format!("M{f}"),
                _ => "?".to_owned(),
            })
            .collect();
        panic!("only {} blocks done; log {:?}", done.len(), summary);
    }
    assert!(done.len() >= 5, "only {} blocks done", done.len());
    // один из готовых блоков портится на диске
    let bad = done[done.len() / 2];
    let part = part_path(&sdir, 0);
    let mut bytes = std::fs::read(&part).unwrap();
    bytes[(bad as usize) * (1 << 20) + 17] ^= 0x80;
    std::fs::write(&part, bytes).unwrap();
    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 10, |e| {
        matches!(e, TransferEvent::Verifying { .. })
    })
    .await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // из готовых заново получен только испорченный блок
    let w = written_blocks(&rig.b);
    let again: Vec<u32> = w
        .iter()
        .map(|(_, b)| *b)
        .filter(|b| done.contains(b))
        .collect();
    assert_eq!(again, vec![bad]);
    // остальные записаны по разу
    let mut all: Vec<u32> = w.iter().map(|(_, b)| *b).collect();
    all.sort_unstable();
    let mut want: Vec<u32> = (0..40).filter(|b| !done.contains(b) || *b == bad).collect();
    want.sort_unstable();
    assert_eq!(all, want);
}

#[tokio::test]
async fn checkpoint_order_sync_before_state() {
    let mut rig = Rig::with(|_| {}, |c| c.checkpoint_bytes = 3 << 20).await;
    let src = TestDir::new();
    let files = vec![
        write_src(src.path(), "a.bin", &rand_bytes(65, 20 << 20)),
        write_src(src.path(), "b.bin", &rand_bytes(66, 3 << 20)),
    ];
    let (key, kb) = start_transfer(&mut rig, files).await;
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    // состояние никогда не заявляет блок, у которого не было `sync_data` после записи
    let log = rig.b.hook.events();
    let mut written: std::collections::HashSet<(u32, u32)> = Default::default();
    let mut synced: std::collections::HashSet<(u32, u32)> = Default::default();
    let mut state_writes = 0;
    let mut claimed_total = 0;
    for ev in &log {
        match ev {
            Ev::Written(f, b) => {
                written.insert((*f, *b));
            }
            Ev::Synced(f) => {
                let moved: Vec<_> = written.iter().filter(|(x, _)| x == f).copied().collect();
                for m in moved {
                    written.remove(&m);
                    synced.insert(m);
                }
            }
            Ev::StateWrite(bytes) => {
                state_writes += 1;
                let st = decode_state(bytes).unwrap();
                for (i, f) in st.files.iter().enumerate() {
                    let l = layout(f.size).unwrap();
                    let claimed: Vec<u32> = match &f.status {
                        FileStatus::InProgress(p) => {
                            let bits = Bits::from_bytes(l.block_count, &p.bitmap);
                            (0..l.block_count).filter(|b| bits.get(*b)).collect()
                        }
                        FileStatus::Verified(_) => (0..l.block_count).collect(),
                        _ => vec![],
                    };
                    for b in claimed {
                        claimed_total += 1;
                        assert!(
                            synced.contains(&(i as u32, b)),
                            "state claims unsynced block {i}/{b}"
                        );
                    }
                }
            }
            _ => {}
        }
    }
    assert!(state_writes >= 3, "only {state_writes} state writes");
    assert!(claimed_total > 0);
}

#[tokio::test]
async fn interrupted_file_not_visible_under_final_name() {
    for stage in 0..4 {
        let mut rig = Rig::with(|_| {}, narrow).await;
        let src = TestDir::new();
        let files = vec![write_src(src.path(), "a.bin", &rand_bytes(67, 6 << 20))];
        let (_key, kb) = start_transfer(&mut rig, files).await;
        // остановка писателя на заданном этапе
        let gate = Gate::new();
        let g = gate.clone();
        let mut written = 0;
        rig.b.hook.set(move |ev| {
            let hit = match (stage, ev) {
                (0, Ev::Manifest(0)) => true,
                (1, Ev::Written(..)) => {
                    written += 1;
                    written == 3
                }
                (2, Ev::FinalVerify(0)) => true,
                (3, Ev::BeforePlace(0)) => true,
                _ => false,
            };
            if hit {
                g.hold();
            }
            Ok(())
        });
        rig.b.tr.respond(&kb, true).unwrap();
        gate.wait_reached().await;
        // до размещения под итоговым именем ничего нет; временные данные только в partial_dir
        assert!(rig.b.dest.list().is_empty(), "stage {stage}");
        let dirs = rig.b.partial.list();
        assert_eq!(dirs.len(), 1);
        rig.b.tr.shutdown();
        gate.release();
        rig.b.tr.wait_stopped().await;
        assert!(rig.b.dest.list().is_empty(), "stage {stage} after stop");
        let sdir = rig.b.partial.path().join(&dirs[0]);
        for e in std::fs::read_dir(&sdir).unwrap() {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(crate::paths::is_ours_file(&n), "unexpected file {n}");
        }
    }
}

#[tokio::test]
async fn disk_full_pauses_and_retry_resumes() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(68, 8 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let mut fail = true;
    rig.b.hook.set(move |ev| {
        if let Ev::Write(0, 2, _) = ev
            && fail
        {
            fail = false;
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        Ok(())
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::DiskFull,
                ..
            }
        )
    })
    .await;
    // уже принятое сохранено; передача ждёт `retry`
    tokio::time::sleep(Duration::from_millis(300)).await;
    let st = rig.b.tr.status(&kb).unwrap();
    assert_eq!(
        st.state,
        crate::TransferState::Paused(PauseReason::DiskFull)
    );
    assert!(rig.b.dest.list().is_empty());
    rig.b.tr.retry(&kb).unwrap();
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert!(placed[0].1 == data);
    let mut w = written_blocks(&rig.b);
    w.sort_unstable();
    assert_eq!(w, (0..8).map(|b| (0, b)).collect::<Vec<_>>());
}

#[tokio::test]
async fn cancel_by_receiver_cleans_partial() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(69, 40 << 20))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    rig.b.tr.cancel(&kb).unwrap();
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Receiver,
            ..
        }
    ));
    let e = wait_ev(&mut rig.a.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Receiver,
            ..
        }
    ));
    assert_eq!(key_of(&e), key);
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
    assert!(rig.b.tr.status(&kb).is_none());
}

#[tokio::test]
async fn cancel_by_sender_cleans_partial() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(70, 40 << 20))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    rig.a.tr.cancel(&key).unwrap();
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Sender,
            ..
        }
    ));
    let e = wait_ev(&mut rig.a.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Sender,
            ..
        }
    ));
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
}

#[tokio::test]
async fn cancel_pending_offer() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(71, 1000))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    rig.a.tr.cancel(&key).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Sender,
            ..
        }
    ));
    assert!(rig.b.tr.offer(&kb).is_none());
    assert!(rig.b.tr.respond(&kb, true).is_err());
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn resume_unknown_session_peer_forgot() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(72, 40 << 20))];
    let (_key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    // отправитель «перезапущен»: его сессии в памяти пропали
    let release = gate.clone();
    let restart = rig.a.restart();
    tokio::pin!(restart);
    tokio::select! {
        () = &mut restart => {}
        () = tokio::time::sleep(Duration::from_millis(100)) => {
            release.release();
            restart.await;
        }
    }
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Failed {
            reason: FailReason::PeerForgot,
            ..
        }
    ));
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
}

#[tokio::test]
async fn sender_drops_session_after_resume_hold() {
    let mut rig = Rig::with(|c| c.resume_hold = Duration::from_millis(300), narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(73, 40 << 20))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    rig.cur.0.close();
    gate.release();
    wait_ev(&mut rig.a.ev, 10, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    // `resume_hold` истёк: отправитель забыл передачу
    let e = wait_ev(&mut rig.a.ev, 10, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Failed {
            reason: FailReason::Expired,
            ..
        }
    ));
    assert_eq!(key_of(&e), key);
    rig.cur = rig.link().await;
    let e = wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Failed {
            reason: FailReason::PeerForgot,
            ..
        }
    ));
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn stall_timeout_requeues() {
    let data = rand_bytes(74, 4 << 20);
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    cfg.streams = 1;
    cfg.per_stream_window = 1;
    cfg.stall_timeout = Duration::from_millis(300);
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
    let fake = Fake::new(pair, vec![FakeFile::new("a.bin", data.clone())]);
    // блок 1 при первом запросе молчит
    fake.respond_with(|q| match q {
        Req::Block(0, 1, 1) => Resp::Silent,
        _ => Resp::Normal,
    });
    let (tx, mut rx) = fake.offer(&peer).await;
    let e = wait_ev(&mut p.ev, 10, is_offer()).await;
    let key = key_of(&e);
    p.tr.respond(&key, true).unwrap();
    assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Accept));
    fake.run(peer, Some((tx, rx)));
    wait_ev(&mut p.ev, 30, is_completed(key)).await;
    let placed = placed_files(&p.dest);
    assert!(placed[0].1 == data);
    let log = fake.log.lock().unwrap();
    assert_eq!(
        log.requests
            .iter()
            .filter(|q| matches!(q, Req::Block(0, 1, _)))
            .count(),
        2
    );
    assert!(log.binds >= 2, "binds {}", log.binds);
}

#[tokio::test]
async fn buffer_budget_respected() {
    // бюджет 16 MiB при окнах 8 x 8 блоков по 1 MiB: запросы упираются в бюджет
    let mut rig = Rig::with(
        |_| {},
        |c| {
            c.streams = 8;
            c.per_stream_window = 8;
            c.recv_buffer_budget = 16 << 20;
        },
    )
    .await;
    let src = TestDir::new();
    let data = rand_bytes(75, 37 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let budget = rig.b.tr.inner().sh.recv_budget.clone();
    let min_free = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    let mf = min_free.clone();
    let sampler = tokio::spawn(async move {
        loop {
            mf.fetch_min(budget.available_permits(), Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    sampler.abort();
    let placed = placed_files(&rig.b.dest);
    assert!(placed[0].1 == data);
    // бюджет использовался (не меньше 2 MiB одновременно), но не был превышен, и всё вернулось
    let used_peak = (16usize << 10) - min_free.load(Ordering::SeqCst);
    assert!(used_peak >= 2 << 10, "peak {used_peak} KiB");
    let free = rig.b.tr.inner().sh.recv_budget.available_permits();
    assert_eq!(free, 16 << 10);
}

#[tokio::test]
async fn friend_blocked_cancels_transfers() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(76, 40 << 20))];
    let (_key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    let pb = rig.pb;
    rig.b
        .node
        .engine
        .update_book(|book, s| book.block(s, &pb))
        .unwrap();
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Receiver,
            ..
        }
    ));
    assert!(rig.b.partial.list().is_empty());
    assert!(rig.b.dest.list().is_empty());
}

#[tokio::test]
async fn two_way_simultaneous() {
    let mut rig = Rig::new().await;
    let (sa, sb) = (TestDir::new(), TestDir::new());
    let da = rand_bytes(77, 9 << 20);
    let db = rand_bytes(78, 5 << 20);
    let ka = rig
        .a
        .tr
        .send(&rig.pa, vec![write_src(sa.path(), "x.bin", &da)])
        .unwrap();
    let kb_out = rig
        .b
        .tr
        .send(&rig.pb, vec![write_src(sb.path(), "y.bin", &db)])
        .unwrap();
    let e1 = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let e2 = wait_ev(&mut rig.a.ev, 10, is_offer()).await;
    let (in_b, in_a) = (key_of(&e1), key_of(&e2));
    rig.b.tr.respond(&in_b, true).unwrap();
    rig.a.tr.respond(&in_a, true).unwrap();
    // события двух передач одного узла приходят вперемешку: ждём оба `Completed`
    for (ev, want) in [(&mut rig.b.ev, [in_b, kb_out]), (&mut rig.a.ev, [in_a, ka])] {
        let mut left: Vec<TransferKey> = want.to_vec();
        while !left.is_empty() {
            let e = wait_ev(ev, 60, |e| matches!(e, TransferEvent::Completed { .. })).await;
            left.retain(|k| *k != key_of(&e));
        }
    }
    assert!(placed_files(&rig.b.dest)[0].1 == da);
    assert!(placed_files(&rig.a.dest)[0].1 == db);
}

/// R2-2: новое соединение получает тот же номер, что имело погибшее (так вёл себя адрес в
/// памяти у прежнего адаптера quinn). Получатель не сравнивает номер с погибшим и
/// возобновляет передачу по живому соединению.
#[tokio::test]
async fn resume_over_new_conn_with_reused_id() {
    const REUSED: u64 = 7_000_007;
    let mut rig = Rig::with(|_| {}, narrow).await;
    // первое соединение получателя уже имеет номер REUSED
    rig.relink_ids((7_100_001, REUSED)).await;
    let src = TestDir::new();
    let data = rand_bytes(71, 40 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let conn = rig.cur.0.clone();
    let mut n = 0;
    rig.b.hook.set(move |ev| {
        if matches!(ev, Ev::Written(..)) {
            n += 1;
            if n == 20 {
                conn.close();
            }
        }
        Ok(())
    });
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )
    })
    .await;
    wait_ev(&mut rig.a.ev, 30, |e| {
        matches!(e, TransferEvent::Paused { .. })
    })
    .await;
    // новое соединение B: тот же номер
    rig.relink_ids((7_100_002, REUSED)).await;
    assert_eq!(
        rig.b.node.engine.connection(&rig.pb).unwrap().conn_id(),
        REUSED
    );
    // `poll` (200 мс в тестах) + `msg_timeout` (10 с)
    wait_ev(&mut rig.b.ev, 15, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
}

/// R2-2: эхо DONE потеряно, соединение живо. Получатель не зависает: по истечении `msg_timeout`
/// передача завершена как `Completed` (все файлы уже проверены и размещены), соединение цело.
/// Продолжение после закрытия соединения (`RESUME`, ответ `DONE`) проверяется в
/// `resume_over_new_conn_with_reused_id`.
#[tokio::test]
async fn resume_after_lost_done_echo_same_conn() {
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    cfg.msg_timeout = Duration::from_millis(500);
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
    let fake = Fake::new(pair, vec![FakeFile::new("a.bin", rand_bytes(72, 3 << 20))]);
    fake.drop_done_echo.store(true, Ordering::SeqCst);
    let mut ctl = fake.offer(&peer).await;
    let key = key_of(&wait_ev(&mut p.ev, 10, is_offer()).await);
    p.tr.respond(&key, true).unwrap();
    assert_eq!(Fake::decision(&mut ctl.1, 10).await, Some(Verdict::Accept));
    fake.run(peer.clone(), Some(ctl));
    wait_ev(&mut p.ev, 30, is_completed(key)).await;
    assert!(fake.log.lock().unwrap().ctl.contains(&"done".to_owned()));
    assert!(!conn.is_closed(), "the connection stayed live");
    assert_eq!(placed_files(&p.dest).len(), 1);
}
