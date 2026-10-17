//! Круг правок 2: размещение через `<i>.placing` (крах между ссылкой и записью `Placed`) и
//! доли памяти с округлением вверх. Сроки отправителя (N1) в `hashprog.rs`.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use super::fake::FakeFile;
use super::kit::*;
use crate::paths::{part_path, placing_path, session_dir, write_hashes, write_state};
use crate::shared::{Acquired, acquire_pair, buffer_floor, kib, permits, share_semaphore};
use crate::state::{FileStatus, RecvState, StateFile, decode_state, encode_names, encode_state};
use crate::util::{Stop, now_unix};
use crate::{TransferId, TransferKey, UntrustedName, encode_hashes, layout, state_dir_name};

/// Мало потоков и окно 1: передача идёт неторопливо, ничего не мешает остановке.
fn narrow(c: &mut crate::TransferConfig) {
    c.streams = 2;
    c.per_stream_window = 1;
    c.recv_buffer_budget = 16 << 20;
    // записи состояния делят один ограничитель (`reserve_state_write`): с долгим интервалом
    // первую запись `Placed` делает именно размещающий поток, а не контрольная точка писателя
    // (тест останавливает размещающий поток на этой записи, имитируя крах)
    c.checkpoint_interval = Duration::from_secs(30);
}

fn placed_in(bytes: &[u8]) -> bool {
    decode_state(bytes).is_ok_and(|st| {
        st.files
            .iter()
            .any(|f| matches!(f.status, FileStatus::Placed(_)))
    })
}

/// Крах получателя сразу после размещения файла: запись состояния с `Placed` не удаётся, а
/// сама передача останавливается раньше, чем получатель успеет что-то убрать. Режим
/// `Placement` задаёт, что успело произойти (ссылка есть или нет). Возвращает каталог сессии.
async fn crash_at_placed(rig: &mut Rig, kb: &TransferKey, mode: u8) -> PathBuf {
    rig.b.spy.mode.store(mode, Ordering::SeqCst);
    let inner = rig.b.tr.inner().clone();
    let fired = Arc::new(AtomicBool::new(false));
    rig.b.hook.set(move |ev| {
        if let Ev::StateWrite(bytes) = ev
            && placed_in(bytes)
        {
            if !fired.swap(true, Ordering::SeqCst) {
                // остановка происходит здесь, до продолжения размещающего потока: пока он спит,
                // попытка успевает увидеть остановку
                inner.stop_all();
                std::thread::sleep(Duration::from_millis(300));
            }
            return Err(io::Error::other("crash"));
        }
        Ok(())
    });
    rig.b.tr.respond(kb, true).unwrap();
    for _ in 0..2000 {
        if rig
            .b
            .hook
            .events()
            .iter()
            .any(|e| matches!(e, Ev::StateWrite(b) if placed_in(b)))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    rig.b.tr.wait_stopped().await;
    rig.b.spy.mode.store(PLACE_NORMAL, Ordering::SeqCst);
    session_dir(rig.b.partial.path(), &state_dir_name(&kb.pair, &kb.id))
}

fn writes(p: &Peer) -> Vec<(u32, u32)> {
    p.hook
        .events()
        .iter()
        .filter_map(|e| match e {
            Ev::Write(f, b, _) => Some((*f, *b)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn crash_after_link_never_writes_into_placed_file() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(71, 3 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let kb = key_of(&wait_ev(&mut rig.b.ev, 10, is_offer()).await);
    // ссылка на итоговое имя создана, временное имя ещё на месте, `Placed` не записан
    let sdir = crash_at_placed(&mut rig, &kb, PLACE_LINK_ONLY).await;
    let placed = rig.b.dest.list();
    assert_eq!(placed.len(), 1, "{placed:?}");
    let fin = rig.b.dest.path().join(&placed[0]);
    assert_eq!(std::fs::read(&fin).unwrap(), data);
    assert!(placing_path(&sdir, 0).is_file(), "crash left no .placing");
    assert!(
        !part_path(&sdir, 0).exists(),
        ".part must not exist next to .placing"
    );
    let before = std::fs::metadata(&fin).unwrap();
    let st = decode_state(&std::fs::read(sdir.join("state")).unwrap()).unwrap();
    assert!(
        !matches!(st.files[0].status, FileStatus::Placed(_)),
        "state must not claim Placed"
    );

    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    // в размещённый файл не писали: ни блоков, ни `set_len`/`sync_all` (точка Synced)
    assert!(writes(&rig.b).is_empty(), "{:?}", writes(&rig.b));
    assert!(
        !rig.b
            .hook
            .events()
            .iter()
            .any(|e| matches!(e, Ev::Synced(_))),
        "the placed file was opened for writing"
    );
    let after = std::fs::metadata(&fin).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(std::fs::read(&fin).unwrap(), data);
    assert_eq!(rig.b.dest.list().len(), 1);
    // файл перепроверен чтением с диска и размещён повторно (идемпотентно)
    assert_eq!(rig.b.spy.calls.lock().unwrap().clone(), vec![(0, true)]);
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn restored_placing_file_is_verified_and_placed() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(72, 3 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let kb = key_of(&wait_ev(&mut rig.b.ev, 10, is_offer()).await);
    // крах между переименованием и ссылкой: итогового файла нет
    let sdir = crash_at_placed(&mut rig, &kb, PLACE_NOTHING).await;
    assert!(rig.b.dest.list().is_empty());
    assert!(placing_path(&sdir, 0).is_file());
    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // готовое не качалось заново и не записывалось
    assert!(writes(&rig.b).is_empty(), "{:?}", writes(&rig.b));
    assert_eq!(rig.b.spy.calls.lock().unwrap().clone(), vec![(0, true)]);
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn restored_placing_file_with_bad_hash_is_refetched() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let data = rand_bytes(73, 3 << 20);
    let files = vec![write_src(src.path(), "a.bin", &data)];
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let kb = key_of(&wait_ev(&mut rig.b.ev, 10, is_offer()).await);
    let sdir = crash_at_placed(&mut rig, &kb, PLACE_NOTHING).await;
    // `.placing` повреждён: ссылки на него нет, портить безопасно
    let p = placing_path(&sdir, 0);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[(1 << 20) + 5] ^= 0x40;
    std::fs::write(&p, bytes).unwrap();
    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    // повреждённое не размещено: итог точный, файл получен заново
    let placed = placed_files(&rig.b.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    let mut w = writes(&rig.b);
    w.sort_unstable();
    assert_eq!(w, vec![(0, 0), (0, 1), (0, 2)]);
    assert!(
        rig.b.spy.calls.lock().unwrap().iter().all(|c| c.1),
        "placement was called on a file that did not match"
    );
    assert!(rig.b.partial.list().is_empty());
}

#[tokio::test]
async fn stale_leftovers_of_placed_file_are_removed_on_restore() {
    // состояние говорит `Placed`, а остатки (`.placing`, хэши, старый `.part`) ещё лежат
    let partial = TestDir::new();
    let dest = TestDir::new();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let id = TransferId([6; 16]);
    let f = FakeFile::new("a.bin", rand_bytes(74, 2 << 20));
    let names = vec![UntrustedName::new("a.bin").unwrap()];
    let (nb, sum) = encode_names(&pair, &id, &names);
    let st = RecvState {
        pair,
        id,
        created_unix: now_unix(),
        last_progress_unix: now_unix(),
        total_size: f.size,
        names_sum: sum,
        files: vec![StateFile {
            size: f.size,
            status: FileStatus::Placed(f.root),
        }],
    };
    let sd = partial.path().join(state_dir_name(&pair, &id));
    std::fs::create_dir(&sd).unwrap();
    std::fs::write(sd.join("names"), nb).unwrap();
    write_state(&sd, &encode_state(&st)).unwrap();
    write_hashes(&sd, 0, &encode_hashes(&f.leaves)).unwrap();
    std::fs::write(placing_path(&sd, 0), &f.data).unwrap();
    std::fs::write(part_path(&sd, 0), b"old").unwrap();
    let node = Node::start(pre);
    let p = Peer::start(node, partial.clone(), dest, small_cfg(partial.path()));
    let s =
        p.tr.inner()
            .find_inb(&TransferKey { pair, id })
            .expect("session loaded");
    drop(s);
    assert!(!placing_path(&sd, 0).exists());
    assert!(!part_path(&sd, 0).exists());
    assert!(!sd.join("0.hashes").exists());
}

#[test]
fn placing_files_are_ours() {
    assert!(crate::paths::is_ours_file("0.placing"));
    assert!(crate::paths::is_ours_file("123.placing"));
    assert!(!crate::paths::is_ours_file("x.placing"));
    assert!(!crate::paths::is_ours_file(".placing"));
}

// ------------------------------------------------------------------ N3: доли памяти

#[tokio::test]
async fn share_rounds_up_so_request_equal_to_share_fits() {
    // 64 ГиБ: блоки по 1 МиБ, 65536 блоков, список хэшей 2 МиБ + 64 Б. Бюджет 16 МиБ на 8
    // активных передач: доля 2 МиБ меньше списка, берётся список. Раньше разрешений было
    // 2048 (округление вниз), а запрос на 2049: ожидание вечно.
    let size = 64u64 << 30;
    let l = layout(size).unwrap();
    assert_eq!((l.block_size, l.block_count), (1 << 20, 65536));
    let manifest = u64::from(l.block_count) * 32 + 64;
    assert_eq!(manifest, (2 << 20) + 64);
    let floor = buffer_floor(&[size]);
    assert_eq!(floor, manifest);
    let need = kib(u32::try_from(manifest).unwrap());
    assert_eq!(need, 2049);
    let budget = 16u64 << 20;
    let share = share_semaphore(budget, 8, floor);
    assert!(share.available_permits() >= need as usize);
    let global = Arc::new(Semaphore::new(permits(budget)));
    let stop = Stop::new();
    let got = tokio::time::timeout(
        Duration::from_secs(5),
        acquire_pair(&share, &global, need, true, &mut stop.watcher()),
    )
    .await;
    assert!(matches!(got, Ok(Acquired::Got(_))), "request waits forever");
}

#[test]
fn share_never_smaller_than_any_buffer_of_the_transfer() {
    // для любого буфера (блок или список хэшей) доля в разрешениях не меньше запроса
    for budget in [16u64 << 20, 24 << 20, 128 << 20] {
        for active in [1usize, 3, 4, 8] {
            for size in [
                0u64,
                1,
                (1 << 20) + 1,
                (3 << 30) + 12345,
                64 << 30,
                (64 << 30) + 1,
                1 << 40,
            ] {
                let floor = buffer_floor(&[size]);
                let share = share_semaphore(budget, active, floor);
                let need = u64::from(kib(u32::try_from(floor.min(u64::from(u32::MAX))).unwrap()));
                assert!(
                    share.available_permits() as u64 >= need,
                    "budget {budget} active {active} size {size}: {} < {need}",
                    share.available_permits()
                );
            }
        }
    }
}
