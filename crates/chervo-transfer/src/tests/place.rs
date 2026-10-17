//! Размещение без перезаписи, служебные каталоги при запуске, лимиты друга, охрана исходников.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use chervo_identity::PairId;

use super::fake::{Fake, FakeFile};
use super::kit::*;
use crate::fsio::hash_source;
use crate::placement::{PlaceMethod, place_no_clobber_with};
use crate::sched::Run;
use crate::state::{FileStatus, RecvState, StateFile, encode_state};
use crate::util::now_unix;
use crate::{
    CompletedFile, FileFailure, GeneratedNames, Message, PlaceError, Placement, TransferConfig,
    TransferEvent, TransferId, TransferKey, UntrustedName, Verdict, place_no_clobber,
    state_dir_name,
};

fn put(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn place_no_clobber_existing_kept() {
    let d = TestDir::new();
    let temp = put(d.path(), "t.part", b"new");
    let fin = put(d.path(), "final", b"old");
    for force in [false, true] {
        let e = place_no_clobber_with(&temp, &fin, force).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "force={force}");
        assert_eq!(std::fs::read(&fin).unwrap(), b"old");
        assert_eq!(std::fs::read(&temp).unwrap(), b"new");
    }
    let e = place_no_clobber(&temp, &fin).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn place_no_clobber_normal_path() {
    let d = TestDir::new();
    let temp = put(d.path(), "t.part", b"payload");
    let fin = d.path().join("final");
    let m = place_no_clobber(&temp, &fin).unwrap();
    assert!(matches!(
        m,
        PlaceMethod::HardLink | PlaceMethod::ReserveRename
    ));
    assert_eq!(std::fs::read(&fin).unwrap(), b"payload");
    assert!(!temp.exists());
}

#[test]
fn place_no_clobber_fallback_path() {
    let d = TestDir::new();
    let temp = put(d.path(), "t.part", b"payload");
    let fin = d.path().join("final");
    let m = place_no_clobber_with(&temp, &fin, true).unwrap();
    assert_eq!(m, PlaceMethod::ReserveRename);
    assert_eq!(std::fs::read(&fin).unwrap(), b"payload");
    assert!(!temp.exists());
    // кроме итогового файла ничего не осталось
    assert_eq!(d.list(), vec!["final".to_owned()]);
}

fn completed(temp: &Path, data: &[u8], index: u32) -> CompletedFile {
    let stop = AtomicBool::new(false);
    let (_, _, root) = hash_source(temp, data.len() as u64, &stop, &AtomicU64::new(0), &|_| {
        Ok(())
    })
    .unwrap();
    CompletedFile::new(
        TransferKey {
            pair: PairId::from_bytes([3; 16]),
            id: TransferId([4; 16]),
        },
        index,
        UntrustedName::new("whatever/../name").unwrap(),
        data.len() as u64,
        root,
        temp.to_path_buf(),
    )
}

#[test]
fn generated_names_idempotent() {
    let src = TestDir::new();
    let dest = TestDir::new();
    let data = rand_bytes(5, 3000);
    let temp = put(src.path(), "0.part", &data);
    let cf = completed(&temp, &data, 0);
    let g = GeneratedNames {
        dest_dir: dest.path().to_path_buf(),
    };
    let first = g.place(&cf).unwrap();
    assert!(!temp.exists());
    // повторный вызов (сбой между размещением и записью состояния): тот же результат
    let second = g.place(&cf).unwrap();
    assert_eq!(first.path, second.path);
    assert_eq!(dest.list().len(), 1);
    // под этим именем уже лежит другой файл: отказ, ничего не затёрто
    std::fs::write(&first.path, b"someone else").unwrap();
    assert_eq!(g.place(&cf).unwrap_err(), PlaceError::Refused);
    assert_eq!(std::fs::read(&first.path).unwrap(), b"someone else");
    // имя файла не повлияло на итоговое имя
    let name = first
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(name.starts_with("chervo-"));
    assert!(!name.contains("whatever"));
}

fn hex32(c: char) -> String {
    std::iter::repeat_n(c, 32).collect()
}

async fn start_empty(partial: Arc<TestDir>) -> Peer {
    let pre = Pre::new();
    let node = Node::start(pre);
    let dest = TestDir::new();
    let cfg = small_cfg(partial.path());
    Peer::start(node, partial, dest, cfg)
}

use std::sync::Arc;

#[tokio::test]
async fn startup_sweep_deletes_only_ours() {
    let partial = TestDir::new();
    let p = partial.path();
    // наш каталог без годного состояния, но с чужим файлом: наши файлы уходят, чужой остаётся
    let a = p.join(hex32('a'));
    std::fs::create_dir(&a).unwrap();
    put(&a, "state", b"garbage");
    put(&a, "0.part", b"data");
    put(&a, "1.hashes", b"data");
    put(&a, "2.hashes.tmp", b"data");
    put(&a, "keep.txt", b"foreign");
    // каталог только с нашими файлами исчезает целиком
    let b = p.join(hex32('b'));
    std::fs::create_dir(&b).unwrap();
    put(&b, "state", b"garbage");
    put(&b, "0.part", b"data");
    // чужой каталог (имя не из 32 hex-цифр) не трогается
    let c = p.join("not-ours");
    std::fs::create_dir(&c).unwrap();
    put(&c, "state", b"mine");
    // файл с именем из 32 hex-цифр (не каталог) не трогается
    put(p, &hex32('d'), b"just a file");
    #[cfg(unix)]
    {
        let target = TestDir::new();
        put(target.path(), "state", b"outside");
        std::os::unix::fs::symlink(target.path(), p.join(hex32('e'))).unwrap();
        let t2 = target.clone();
        let peer = start_empty(partial.clone()).await;
        assert_eq!(std::fs::read(t2.path().join("state")).unwrap(), b"outside");
        drop(peer);
        return;
    }
    #[cfg(not(unix))]
    {
        let peer = start_empty(partial.clone()).await;
        drop(peer);
        assert!(a.is_dir());
        assert_eq!(std::fs::read(a.join("keep.txt")).unwrap(), b"foreign");
        assert!(!a.join("state").exists());
        assert!(!a.join("0.part").exists());
        assert!(!a.join("1.hashes").exists());
        assert!(!a.join("2.hashes.tmp").exists());
        assert!(!b.exists());
        assert_eq!(std::fs::read(c.join("state")).unwrap(), b"mine");
        assert_eq!(std::fs::read(p.join(hex32('d'))).unwrap(), b"just a file");
    }
}

fn waiting_state(pair: PairId, id: TransferId, last: u64) -> (String, Vec<u8>) {
    let st = RecvState {
        pair,
        id,
        created_unix: last,
        last_progress_unix: last,
        total_size: 100,
        files: vec![StateFile {
            name: UntrustedName::new("a.bin").unwrap(),
            size: 100,
            status: FileStatus::Waiting,
        }],
    };
    (state_dir_name(&pair, &id), encode_state(&st))
}

#[tokio::test]
async fn partial_ttl_expiry() {
    let partial = TestDir::new();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let now = now_unix();
    let week = 7 * 24 * 3600;
    let (old_dir, old) = waiting_state(pair, TransferId([1; 16]), now - week - 3600);
    let (new_dir, fresh) = waiting_state(pair, TransferId([2; 16]), now - 3600);
    for (dir, bytes) in [(&old_dir, old), (&new_dir, fresh)] {
        let sd = partial.path().join(dir);
        std::fs::create_dir(&sd).unwrap();
        put(&sd, "state", &bytes);
        put(&sd, "0.part", b"partial");
    }
    let dest = TestDir::new();
    let cfg = small_cfg(partial.path());
    let mut p = Peer::start(node, partial.clone(), dest, cfg);
    // просроченное удалено, свежее загружено на паузу
    assert!(!partial.path().join(&old_dir).exists());
    assert!(partial.path().join(&new_dir).is_dir());
    let key = TransferKey {
        pair,
        id: TransferId([2; 16]),
    };
    let e = wait_ev(&mut p.ev, 5, |e| matches!(e, TransferEvent::Paused { .. })).await;
    assert_eq!(key_of(&e), key);
    assert!(p.tr.status(&key).is_some());
    let _ = Run::Failed;
}

#[tokio::test]
async fn progress_rate_limited() {
    let mut rig = Rig::with(
        |_| {},
        |c| {
            c.progress_interval = Duration::from_millis(100);
        },
    )
    .await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(81, 37 << 20))];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    let started = std::time::Instant::now();
    rig.b.tr.respond(&kb, true).unwrap();
    let mut n = 0u32;
    loop {
        let e = wait_ev(&mut rig.b.ev, 60, |_| true).await;
        match e {
            TransferEvent::Progress { done, total, .. } => {
                n += 1;
                assert!(done <= total);
            }
            TransferEvent::Completed { .. } => break,
            _ => {}
        }
    }
    let ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    assert!(n >= 1);
    // не чаще раза в 100 мс (плюс запас на границы)
    assert!(n <= ms / 100 + 3, "{n} progress events in {ms} ms");
}

// ------------------------------------------------------------- лимиты друга и политика

/// Узел с `n` друзьями-заглушками, соединения от каждого уже приняты.
async fn node_with_friends(
    n: usize,
    tweak: impl FnOnce(&mut TransferConfig),
) -> (Peer, Vec<(PairId, FakeConn)>) {
    let mut pre = Pre::new();
    let pairs: Vec<PairId> = (0..n).map(|_| pre.solo_friend()).collect();
    let node = Node::start(pre);
    let (partial, dest) = (TestDir::new(), TestDir::new());
    let mut cfg = small_cfg(partial.path());
    tweak(&mut cfg);
    let p = Peer::start(node, partial, dest, cfg);
    let mut out = Vec::new();
    for pair in pairs {
        let c = FakeConn::lonely(pair);
        p.node.t.push_incoming(c.clone());
        out.push((pair, c));
    }
    for (pair, _) in &out {
        for _ in 0..500 {
            if p.node.engine.connection(pair).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    (p, out)
}

fn one_file(tag: u8) -> Fake {
    let _ = tag;
    Fake::new(
        PairId::from_bytes([0; 16]),
        vec![FakeFile::new("a", rand_bytes(u64::from(tag), 100))],
    )
}

#[tokio::test]
async fn pending_offers_global_cap() {
    let (mut p, friends) = node_with_friends(3, |c| c.max_pending_offers = 2).await;
    let mut rxs = Vec::new();
    for (i, (pair, conn)) in friends.iter().enumerate() {
        let f = Fake::new(
            *pair,
            vec![FakeFile::new("a", rand_bytes(i as u64 + 1, 100))],
        );
        let (tx, mut rx) = f.offer(&conn.peer()).await;
        if i < 2 {
            wait_ev(&mut p.ev, 10, is_offer()).await;
        } else {
            // третье предложение при двух ожидающих
            assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Busy));
        }
        rxs.push((tx, rx));
    }
    let _ = one_file;
}

#[tokio::test]
async fn ctl_streams_per_min_cap() {
    let (mut p, friends) = node_with_friends(1, |_| {}).await;
    let (pair, conn) = &friends[0];
    let peer = conn.peer();
    let mut streams = Vec::new();
    for i in 0..7u8 {
        let f = Fake::new(
            *pair,
            vec![FakeFile::new("a", rand_bytes(u64::from(i) + 1, 100))],
        );
        let (tx, mut rx) = f.offer(&peer).await;
        if i == 0 {
            wait_ev(&mut p.ev, 10, is_offer()).await;
        } else if i < 6 {
            // потоки со 2-го по 6-й дошли до разбора: Busy (первое предложение ещё ждёт)
            assert_eq!(
                Fake::decision(&mut rx, 10).await,
                Some(Verdict::Busy),
                "stream {i}"
            );
        } else {
            // седьмой за минуту: поток сброшен без ответа
            assert!(recv_frame(&mut rx, 2).await.is_none());
        }
        streams.push((tx, rx));
    }
}

#[tokio::test]
async fn always_ask_even_with_auto_accept_permission() {
    let (mut p, friends) = node_with_friends(1, |_| {}).await;
    let (pair, conn) = &friends[0];
    let pair = *pair;
    p.node
        .engine
        .update_book(|book, s| book.set_permission(s, &pair, auto_accept()))
        .unwrap();
    let f = Fake::new(pair, vec![FakeFile::new("a", rand_bytes(1, 100))]);
    let (_tx, mut rx) = f.offer(&conn.peer()).await;
    let e = wait_ev(&mut p.ev, 10, is_offer()).await;
    let key = key_of(&e);
    // решает пользователь: ответа нет, на диске ничего
    assert!(p.tr.offer(&key).is_some());
    assert!(recv_frame(&mut rx, 1).await.is_none());
    assert!(p.partial.list().is_empty());
    let _ = Message::Done {
        id: TransferId([0; 16]),
    };
}

#[tokio::test]
async fn place_failure_keeps_temp() {
    let mut rig = Rig::new().await;
    rig.b.spy.fail.store(true, Ordering::SeqCst);
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(91, 2 << 20))];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    let kb = key_of(&e);
    rig.b.tr.respond(&kb, true).unwrap();
    let f = wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::FileFailed {
            reason: FileFailure::PlaceFailed,
            ..
        }
    ));
    let f = wait_ev(&mut rig.a.ev, 30, |e| {
        matches!(e, TransferEvent::FileFailed { .. })
    })
    .await;
    assert!(matches!(
        f,
        TransferEvent::FileFailed {
            reason: FileFailure::PlaceFailed,
            ..
        }
    ));
    wait_ev(&mut rig.b.ev, 30, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 30, is_completed(key)).await;
    // итогового файла нет, временный файл остался под служебным именем
    assert!(rig.b.dest.list().is_empty());
    let dirs = rig.b.partial.list();
    assert_eq!(dirs.len(), 1);
    assert!(rig.b.partial.path().join(&dirs[0]).join("0.part").is_file());
}

#[test]
fn config_validate_rejects_bad() {
    let d = TestDir::new();
    let ok = TransferConfig::new(d.path().to_path_buf());
    assert!(ok.validate().is_ok());
    let mut c = ok.clone();
    c.streams = 0;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.streams = 9;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.per_stream_window = 9;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.recv_buffer_budget = 1024;
    assert!(c.validate().is_err());
    let mut c = ok.clone();
    c.partial_dir = PathBuf::from("relative/dir");
    assert!(c.validate().is_err());
    let mut c = ok;
    c.partial_dir = d.path().join("missing");
    assert!(c.validate().is_err());
}

#[tokio::test]
async fn startup_clears_failures() {
    let partial = TestDir::new();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let node = Node::start(pre);
    let id = TransferId([7; 16]);
    let st = RecvState {
        pair,
        id,
        created_unix: now_unix(),
        last_progress_unix: now_unix(),
        total_size: 300,
        files: vec![
            StateFile {
                name: UntrustedName::new("a.bin").unwrap(),
                size: 100,
                status: FileStatus::Failed,
            },
            StateFile {
                name: UntrustedName::new("b.bin").unwrap(),
                size: 200,
                status: FileStatus::Placed(crate::FileRoot([5; 32])),
            },
        ],
    };
    let sd = partial.path().join(state_dir_name(&pair, &id));
    std::fs::create_dir(&sd).unwrap();
    put(&sd, "state", &encode_state(&st));
    put(&sd, "0.part", b"stale");
    let dest = TestDir::new();
    let cfg = small_cfg(partial.path());
    let p = Peer::start(node, partial.clone(), dest, cfg);
    let s =
        p.tr.inner()
            .find_inb(&TransferKey { pair, id })
            .expect("session loaded");
    {
        let c = s.core.lock().unwrap();
        // провал сброшен (файл снова ждёт), размещённое осталось размещённым
        assert!(matches!(c.sched.run(0), Some(Run::Waiting(None))));
        assert!(matches!(c.sched.run(1), Some(Run::Placed(_))));
    }
    assert!(!sd.join("0.part").exists());
}
