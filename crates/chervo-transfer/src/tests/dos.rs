//! Исправления по ревью безопасности этапа 14 (круг 1, часть B): запись состояния, жёсткие
//! ссылки, доли памяти и сроки на блок, пределы враждебного друга, места среди активных.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use chervo_identity::PairId;
use chervo_transport::Connection;

use super::fake::{Fake, FakeFile, Req, Resp};
use super::kit::*;
use super::place::node_with_friends;
use crate::paths::part_path;
use crate::placement::{PlaceMethod, place_impl};
use crate::receiver::prepare;
use crate::sched::Prior;
use crate::state::{FileStatus, RecvState, StateFile, encode_names, encode_state};
use crate::util::{Bits, now_unix};
use crate::{
    PauseReason, TransferEvent, TransferId, TransferKey, UntrustedName, Verdict, state_dir_name,
};

/// Имя ровно `len` байт: номер и заполнитель.
fn long_name(i: usize, len: usize) -> String {
    let mut s = format!("{i:05}-");
    while s.len() < len {
        s.push('x');
    }
    s
}

// ------------------------------------------------------------ 1. запись состояния

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn state_writes_coalesced_for_many_empty_files() {
    let _heavy = timing_exclusive();
    // 10 000 пустых файлов с именами ~2 МиБ: раньше файл состояния с именами переписывался
    // на каждое событие файла (десятки тысяч записей по несколько МиБ)
    let interval = Duration::from_millis(200);
    let (mut p, friends) = node_with_friends(1, |c| c.checkpoint_interval = interval).await;
    let (pair, conn) = &friends[0];
    let n = 10_000usize;
    let files: Vec<FakeFile> = (0..n)
        .map(|i| FakeFile::new(&long_name(i, 190), Vec::new()))
        .collect();
    let fake = Fake::new(*pair, files);
    let peer = conn.peer();
    let ctl = fake.offer(&peer).await;
    let e = wait_ev(&mut p.ev, 30, is_offer()).await;
    let key = key_of(&e);
    let started = std::time::Instant::now();
    p.tr.respond(&key, true).unwrap();
    let (tx, mut rx) = ctl;
    assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Accept));
    fake.run(peer, Some((tx, rx)));
    wait_ev(&mut p.ev, 280, is_completed(key)).await;
    let elapsed = started.elapsed();

    // все файлы размещены
    assert_eq!(p.dest.list().len(), n);

    let log = p.hook.events();
    let names_writes: Vec<usize> = log
        .iter()
        .filter_map(|e| match e {
            Ev::NamesWrite(l) => Some(*l),
            _ => None,
        })
        .collect();
    let states: Vec<usize> = log
        .iter()
        .filter_map(|e| match e {
            Ev::StateWrite(b) => Some(b.len()),
            _ => None,
        })
        .collect();
    // имена записаны один раз, и это большая часть предложения
    assert_eq!(names_writes.len(), 1);
    assert!(names_writes[0] > 1_900_000, "{}", names_writes[0]);
    // каждое состояние компактно и не зависит от имён: заголовок + 41 байт на файл (Placed)
    let state_cap = 100 + 41 * n + 32;
    assert!(states.iter().all(|l| *l <= state_cap), "{states:?}");
    // число записей ограничено таймером контрольной точки, а не числом файлов
    let allowed = 4 + usize::try_from(elapsed.as_millis() / interval.as_millis()).unwrap();
    assert!(
        states.len() <= allowed,
        "{} state writes in {elapsed:?} (allowed {allowed})",
        states.len()
    );
    // записано всего: имена один раз плюс состояния, которых мало
    let total: usize = names_writes[0] + states.iter().sum::<usize>();
    assert!(total <= names_writes[0] + allowed * state_cap);
    // раньше: >= 2 записи на файл, каждая с именами
    assert!(states.len() < n / 10);
}

/// Каталог сеанса на 10 000 файлов, написанный вручную (как после перезапуска).
fn big_session(
    partial: &std::path::Path,
    pair: PairId,
    id: TransferId,
    n: usize,
) -> (std::path::PathBuf, Vec<UntrustedName>) {
    let names: Vec<UntrustedName> = (0..n)
        .map(|i| UntrustedName::new(&long_name(i, 190)).unwrap())
        .collect();
    let (nb, sum) = encode_names(&pair, &id, &names);
    let st = RecvState {
        pair,
        id,
        created_unix: now_unix(),
        last_progress_unix: now_unix(),
        total_size: 0,
        names_sum: sum,
        files: (0..n)
            .map(|_| StateFile {
                size: 0,
                status: FileStatus::Waiting,
            })
            .collect(),
    };
    let sd = partial.join(state_dir_name(&pair, &id));
    std::fs::create_dir(&sd).unwrap();
    std::fs::write(sd.join("names"), nb).unwrap();
    std::fs::write(sd.join("state"), encode_state(&st)).unwrap();
    (sd, names)
}

#[tokio::test]
async fn restart_restores_names_from_immutable_file() {
    let partial = TestDir::new();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let id = TransferId([9; 16]);
    let (sd, names) = big_session(partial.path(), pair, id, 10_000);
    let node = Node::start(pre);
    let dest = TestDir::new();
    let cfg = small_cfg(partial.path());
    let p = Peer::start(node, partial.clone(), dest, cfg);
    let s =
        p.tr.inner()
            .find_inb(&TransferKey { pair, id })
            .expect("session loaded");
    assert_eq!(s.names.len(), 10_000);
    assert!(s.names[0] == names[0] && s.names[9_999] == names[9_999]);
    assert!(sd.join("names").is_file());
    drop(p);

    // подмена файла имён (даже с верной суммой самого файла) разрывает привязку состояния:
    // сеанс не загружается, наши файлы убраны
    let partial2 = TestDir::new();
    let mut pre2 = Pre::new();
    let pair2 = pre2.solo_friend();
    let (sd2, names2) = big_session(partial2.path(), pair2, id, 50);
    let other: Vec<UntrustedName> = names2.iter().rev().cloned().collect();
    let (forged, _) = encode_names(&pair2, &id, &other);
    std::fs::write(sd2.join("names"), forged).unwrap();
    let node2 = Node::start(pre2);
    let p2 = Peer::start(
        node2,
        partial2.clone(),
        TestDir::new(),
        small_cfg(partial2.path()),
    );
    assert!(
        p2.tr
            .inner()
            .find_inb(&TransferKey { pair: pair2, id })
            .is_none()
    );
    assert!(!sd2.exists());

    // повреждённый файл имён и его отсутствие: то же
    for damage in 0..2 {
        let partial3 = TestDir::new();
        let mut pre3 = Pre::new();
        let pair3 = pre3.solo_friend();
        let (sd3, _) = big_session(partial3.path(), pair3, id, 5);
        if damage == 0 {
            let mut b = std::fs::read(sd3.join("names")).unwrap();
            b[40] ^= 1;
            std::fs::write(sd3.join("names"), b).unwrap();
        } else {
            std::fs::remove_file(sd3.join("names")).unwrap();
        }
        let node3 = Node::start(pre3);
        let p3 = Peer::start(
            node3,
            partial3.clone(),
            TestDir::new(),
            small_cfg(partial3.path()),
        );
        assert!(
            p3.tr
                .inner()
                .find_inb(&TransferKey { pair: pair3, id })
                .is_none(),
            "damage {damage}"
        );
        assert!(!sd3.exists(), "damage {damage}");
    }
}

// ------------------------------------------------------------- 2. жёсткие ссылки

#[test]
#[allow(clippy::print_stderr)]
fn hard_link_placement_ok_even_if_unlink_fails() {
    let d = TestDir::new();
    let temp = d.path().join("t.part");
    std::fs::write(&temp, b"payload").unwrap();
    let fin = d.path().join("final");
    let denied = |_: &std::path::Path| -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    };
    // поддерживает ли файловая система временной папки жёсткие ссылки (FAT, часть сетевых
    // дисков нет): от этого зависит, какой путь размещения должен быть пройден
    let probe = d.path().join("probe");
    std::fs::write(&probe, b"x").unwrap();
    let links = std::fs::hard_link(&probe, d.path().join("probe2")).is_ok();
    let m = place_impl(&temp, &fin, false, &denied).unwrap();
    assert_eq!(std::fs::read(&fin).unwrap(), b"payload");
    if links {
        assert_eq!(
            m,
            PlaceMethod::HardLink,
            "жёсткие ссылки есть, а путь другой"
        );
        // размещено: успех, хотя временное имя осталось вторым именем того же файла
        assert!(temp.exists());
    } else {
        eprintln!(
            "hard_link_placement_ok_even_if_unlink_fails: жёстких ссылок нет, проверен запасной путь"
        );
        assert_eq!(m, PlaceMethod::ReserveRename);
        assert!(!temp.exists());
    }
}

#[tokio::test]
async fn failed_part_removal_pauses_and_never_writes_into_placed_file() {
    // Состояние на диске: файл 0 (3 МиБ) был в процессе; его `0.part` остался второй ссылкой
    // на уже размещённый файл (удаление временного имени не удалось).
    let partial = TestDir::new();
    let dest = TestDir::new();
    let mut pre = Pre::new();
    let pair = pre.solo_friend();
    let id = TransferId([5; 16]);
    let old = FakeFile::new("a.bin", rand_bytes(1, 3 << 20));
    let new = FakeFile::new("a.bin", rand_bytes(2, 3 << 20));
    let names = vec![UntrustedName::new("a.bin").unwrap()];
    let (nb, sum) = encode_names(&pair, &id, &names);
    let st = RecvState {
        pair,
        id,
        created_unix: now_unix(),
        last_progress_unix: now_unix(),
        total_size: 3 << 20,
        names_sum: sum,
        files: vec![StateFile {
            size: 3 << 20,
            status: FileStatus::Waiting,
        }],
    };
    let sd = partial.path().join(state_dir_name(&pair, &id));
    std::fs::create_dir(&sd).unwrap();
    std::fs::write(sd.join("names"), nb).unwrap();
    std::fs::write(sd.join("state"), encode_state(&st)).unwrap();
    let placed = dest.path().join("placed");
    std::fs::write(&placed, &old.data).unwrap();
    if std::fs::hard_link(&placed, part_path(&sd, 0)).is_err() {
        // файловая система без жёстких ссылок: проверять нечего
        return;
    }

    let node = Node::start(pre);
    let p = Peer::start(
        node,
        partial.clone(),
        dest.clone(),
        small_cfg(partial.path()),
    );
    p.hook.set(|ev| match ev {
        Ev::RemovePart(_) => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        _ => Ok(()),
    });
    let s =
        p.tr.inner()
            .find_inb(&TransferKey { pair, id })
            .expect("session loaded");
    let prior = Prior {
        layout: old.layout,
        root: old.root,
        bits: Bits::ones(old.layout.block_count),
    };
    let leaves = Arc::new(new.leaves.clone());
    assert_ne!(new.root, old.root);

    // корень сменился, старый `.part` не удаляется: пауза (ошибка), запись не началась
    let Err((e, back)) = prepare(&s, 0, new.layout, new.root, leaves.clone(), Some(prior)) else {
        panic!("prepare continued next to an unremovable .part");
    };
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert!(back.is_some(), "прежний прогресс возвращён");
    assert_eq!(std::fs::read(&placed).unwrap(), old.data);
    assert_eq!(std::fs::read(part_path(&sd, 0)).unwrap(), old.data);
    // то же без прежнего прогресса
    let Err((e, _)) = prepare(&s, 0, new.layout, new.root, leaves.clone(), None) else {
        panic!("prepare continued next to an unremovable .part");
    };
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read(&placed).unwrap(), old.data);

    // удаление снова возможно: `.part` новый и отдельный, размещённый файл не затронут
    p.hook.clear();
    let Ok(a) = prepare(&s, 0, new.layout, new.root, leaves, back) else {
        panic!("prepare failed after removal became possible");
    };
    assert_eq!(a.remaining, new.layout.block_count);
    let fresh = std::fs::OpenOptions::new()
        .write(true)
        .open(part_path(&sd, 0))
        .unwrap();
    fresh.set_len(0).unwrap();
    drop(fresh);
    std::fs::write(part_path(&sd, 0), b"new data").unwrap();
    assert_eq!(std::fs::read(&placed).unwrap(), old.data);
}

// --------------------------------------------- 3. доли памяти и сроки на блок (получатель)

#[tokio::test]
async fn trickling_sender_cannot_block_another_friend() {
    let (mut p, friends) = node_with_friends(2, |_| {}).await;
    let ((hp, hc), (gp, gc)) = (&friends[0], &friends[1]);
    // враждебный друг объявляет 1 ТиБ (блоки по 16 МиБ): без доли восемь запросов
    // (4 потока по 2) заняли бы весь бюджет в 128 МиБ, а тела блоков он не отдаёт
    let bad = Fake::new(*hp, vec![FakeFile::huge("big.bin", 1 << 40)]);
    bad.respond_with(|q| match q {
        Req::Block(..) => Resp::HeadOnly,
        _ => Resp::Normal,
    });
    let bpeer = hc.peer();
    let (btx, mut brx) = bad.offer(&bpeer).await;
    let e = wait_ev(&mut p.ev, 30, is_offer()).await;
    let kb = key_of(&e);
    p.tr.respond(&kb, true).unwrap();
    assert_eq!(Fake::decision(&mut brx, 10).await, Some(Verdict::Accept));
    bad.run(bpeer, Some((btx, brx)));
    // дать ему занять всё, что можно
    for _ in 0..500 {
        let n = bad
            .log
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|q| matches!(q, Req::Block(..)))
            .count();
        if n >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // честный друг, другая передача на том же узле
    let data = rand_bytes(3, 6 << 20);
    let good = Fake::new(*gp, vec![FakeFile::new("g.bin", data.clone())]);
    let gpeer = gc.peer();
    let (gtx, mut grx) = good.offer(&gpeer).await;
    let e = wait_ev(
        &mut p.ev,
        30,
        |e| matches!(e, TransferEvent::OfferReceived { key } if key.pair == *gp),
    )
    .await;
    let kg = key_of(&e);
    p.tr.respond(&kg, true).unwrap();
    assert_eq!(Fake::decision(&mut grx, 10).await, Some(Verdict::Accept));
    good.run(gpeer, Some((gtx, grx)));
    // раньше этот друг ждал бы, пока потоки злого не оборвутся по stall_timeout (60 с)
    wait_ev(&mut p.ev, 25, is_completed(kg)).await;
    let placed = placed_files(&p.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // враждебная передача держит не больше своей доли: 32 МиБ из 128
    let held = 128 * 1024 - p.tr.inner().sh.recv_budget.available_permits();
    assert!(held <= 32 * 1024, "{held} KiB still held");
}

#[tokio::test]
async fn trickled_block_payload_is_cut_by_block_deadline() {
    // 1 байт раз в 300 мс < stall_timeout 1 с: таймер потока никогда не срабатывает; срок на
    // блок 1 с + 1 МиБ / (512 КиБ/с) = 3 с обрывает поток, блок запрашивается заново
    let (mut p, friends) = node_with_friends(1, |c| {
        c.stall_timeout = Duration::from_secs(1);
        c.min_block_rate = 512 << 10;
    })
    .await;
    let (pair, conn) = &friends[0];
    let data = rand_bytes(4, 3 << 20);
    let f = Fake::new(*pair, vec![FakeFile::new("a.bin", data.clone())]);
    f.respond_with(|q| match q {
        Req::Block(0, 0, 1) => Resp::Trickle(Duration::from_millis(300)),
        _ => Resp::Normal,
    });
    let peer = conn.peer();
    let (tx, mut rx) = f.offer(&peer).await;
    let e = wait_ev(&mut p.ev, 30, is_offer()).await;
    let key = key_of(&e);
    p.tr.respond(&key, true).unwrap();
    assert_eq!(Fake::decision(&mut rx, 10).await, Some(Verdict::Accept));
    f.run(peer, Some((tx, rx)));
    let started = std::time::Instant::now();
    wait_ev(&mut p.ev, 60, is_completed(key)).await;
    assert!(started.elapsed() < Duration::from_secs(20));
    let placed = placed_files(&p.dest);
    assert_eq!(placed.len(), 1);
    assert!(placed[0].1 == data);
    // блок, застрявший на капающем потоке, запрошен заново
    assert!(
        f.log
            .lock()
            .unwrap()
            .requests
            .contains(&Req::Block(0, 0, 2))
    );
}

// ---------------------------------------------------------- 6. места среди активных

#[tokio::test]
async fn paused_inbound_does_not_block_new_receive() {
    let (mut p, friends) = node_with_friends(2, |c| c.max_inbound_active = 1).await;
    let ((xp, xc), (yp, yc)) = (&friends[0], &friends[1]);
    // X принят и идёт; затем связь обрывается, передача на паузе
    let fx = Fake::new(*xp, vec![FakeFile::new("x.bin", rand_bytes(5, 2 << 20))]);
    let xpeer = xc.peer();
    let (xtx, mut xrx) = fx.offer(&xpeer).await;
    let e = wait_ev(&mut p.ev, 30, is_offer()).await;
    let kx = key_of(&e);
    p.tr.respond(&kx, true).unwrap();
    assert_eq!(Fake::decision(&mut xrx, 10).await, Some(Verdict::Accept));
    fx.respond_with(|_| Resp::Silent);
    fx.run(xpeer, Some((xtx, xrx)));
    xc.close();
    wait_ev(
        &mut p.ev,
        30,
        |e| matches!(e, TransferEvent::Paused { key, .. } if *key == kx),
    )
    .await;
    // Y: новое предложение принимается, хотя X ещё в списке (на паузе)
    let fy = Fake::new(*yp, vec![FakeFile::new("y.bin", rand_bytes(6, 2 << 20))]);
    let ypeer = yc.peer();
    let (ytx, mut yrx) = fy.offer(&ypeer).await;
    let e = wait_ev(
        &mut p.ev,
        30,
        |e| matches!(e, TransferEvent::OfferReceived { key } if key.pair == *yp),
    )
    .await;
    let ky = key_of(&e);
    p.tr.respond(&ky, true).unwrap();
    assert_eq!(Fake::decision(&mut yrx, 10).await, Some(Verdict::Accept));
    assert!(p.tr.status(&kx).is_some(), "X остаётся в списке");

    // пока Y идёт, X не может вернуться на место; когда Y кончил, может
    let inner = p.tr.inner().clone();
    let sx = inner.find_inb(&kx).unwrap();
    assert!(inner.claim_slot(&sx).is_none());
    fy.run(ypeer, Some((ytx, yrx)));
    p.tr.cancel(&ky).unwrap();
    wait_ev(
        &mut p.ev,
        30,
        |e| matches!(e, TransferEvent::Cancelled { key, .. } if *key == ky),
    )
    .await;
    let prev = inner.claim_slot(&sx).expect("место свободно");
    assert_eq!(prev, Some(PauseReason::Disconnected));
    if let Some(r) = prev {
        sx.unclaim(r);
    }
}
