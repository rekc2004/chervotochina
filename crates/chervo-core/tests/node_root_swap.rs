#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Этап 18д, п.1: новая папка приёма действует сразу, без перезапуска. Два настоящих узла по
//! петле: передача, принятая до смены, дописывается в старую папку; предложение, принятое после
//! смены, ложится в новую; неудачная смена оставляет прежнюю. Запуск: `--test-threads=1`.

#[path = "support/harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use chervo_core::TransferResult;
use chervo_core::{FriendRef, InviteOutcome, Node, NodeError, NodeEvent, TransferRef};
use harness::{Rig, Watch};

const LONG: Duration = Duration::from_secs(40);

struct Side {
    rig: Rig,
    node: Node,
    w: Watch,
}

fn start(tag: &str) -> Side {
    let rig = Rig::new(tag);
    let (node, ev) = rig.start_with_min_free(0);
    Side {
        rig,
        node,
        w: Watch::new(ev),
    }
}

fn lo(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn befriend(a: &mut Side, b: &mut Side) -> (FriendRef, FriendRef) {
    a.w.clear();
    b.w.clear();
    let (inv_a, token) = a.node.create_invite(false, Some(lo(a.rig.port))).unwrap();
    let inv_b = b.node.accept_invite(token.as_str()).unwrap();
    a.w.wait(LONG, |e| match e {
        NodeEvent::InviteSas { invite, .. } if *invite == inv_a => Some(()),
        _ => None,
    })
    .expect("SAS у приглашающего");
    b.w.wait(LONG, |e| match e {
        NodeEvent::InviteSas { invite, .. } if *invite == inv_b => Some(()),
        _ => None,
    })
    .expect("SAS у принимающего");
    a.node.confirm_sas(inv_a, true, "Боб").unwrap();
    b.node.confirm_sas(inv_b, true, "Анна").unwrap();
    for (s, inv) in [(&mut *a, inv_a), (&mut *b, inv_b)] {
        let out =
            s.w.wait(LONG, |e| match e {
                NodeEvent::InviteFinished { invite, outcome } if *invite == inv => Some(*outcome),
                _ => None,
            })
            .expect("итог приглашения");
        assert_eq!(out, InviteOutcome::Added);
    }
    (a.node.friends()[0].friend, b.node.friends()[0].friend)
}

fn online(s: &mut Side, f: FriendRef) {
    s.w.wait(LONG, |e| match e {
        NodeEvent::FriendOnline { friend, .. } if *friend == f => Some(()),
        _ => None,
    })
    .expect("друг не появился в сети");
}

fn pseudo(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

fn finished(s: &mut Side, t: TransferRef) -> TransferResult {
    s.w.wait(LONG, |e| match e {
        NodeEvent::TransferFinished { transfer, result } if *transfer == t => Some(*result),
        _ => None,
    })
    .expect("передача не завершилась")
}

fn offer_named(b: &mut Side, name: &str) -> TransferRef {
    // предложения приходят по одному; берём то, где есть файл с этим именем
    loop {
        let t =
            b.w.wait(LONG, |e| match e {
                NodeEvent::OfferIncoming { transfer } => Some(*transfer),
                _ => None,
            })
            .expect("предложения нет");
        if b.node
            .offer(t)
            .unwrap()
            .files
            .iter()
            .any(|f| f.name == name)
        {
            return t;
        }
    }
}

#[test]
fn new_receive_root_works_at_once_and_running_transfer_keeps_the_old_one() {
    let mut a = start("rootA");
    let mut b = start("rootB");
    let (fb_on_a, fa_on_b) = befriend(&mut a, &mut b);
    online(&mut a, fb_on_a);
    online(&mut b, fa_on_b);

    let src = a.rig.dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("first.dat"), pseudo(4 * 1024 * 1024 + 5, 11)).unwrap();
    std::fs::write(src.join("second.txt"), b"after the switch").unwrap();
    let t1 = a.node.send(fb_on_a, &[src.join("first.dat")]).unwrap();
    let in1 = offer_named(&mut b, "first.dat");

    // принята в прежнюю папку, и сразу папку меняют: передача дописывается в прежнюю
    let old_root = b.rig.recv.clone();
    let new_root = b.rig.dir.join("recv-new");
    std::fs::create_dir_all(&new_root).unwrap();
    // неудачная смена (папки нет) живую папку не трогает: принятая после неё уйдёт в прежнюю
    let missing = b.rig.dir.join("no-such-folder");
    assert!(matches!(
        b.node.set_receive_root(&missing, false).err(),
        Some(NodeError::ReceiveRoot(_))
    ));
    // ожидающее предложение из списка убрать нельзя
    assert!(b.node.forget_transfer(in1).is_err());
    assert!(b.node.transfers().iter().any(|v| v.transfer == in1));
    b.node.accept(in1).unwrap();
    b.node.set_receive_root(&new_root, false).unwrap();
    assert!(
        !b.node.settings().restart_needed,
        "смена папки не требует перезапуска"
    );
    assert_eq!(finished(&mut b, in1), TransferResult::Completed);
    assert_eq!(finished(&mut a, t1), TransferResult::Completed);

    // предложение после смены: в новую
    let t2 = a.node.send(fb_on_a, &[src.join("second.txt")]).unwrap();
    let in2 = offer_named(&mut b, "second.txt");
    b.node.accept(in2).unwrap();
    assert_eq!(finished(&mut b, in2), TransferResult::Completed);
    assert_eq!(finished(&mut a, t2), TransferResult::Completed);
    assert!(old_root.join("first.dat").is_file(), "идущая ушла не туда");
    assert!(!new_root.join("first.dat").exists());
    assert_eq!(
        std::fs::read(new_root.join("second.txt")).unwrap(),
        b"after the switch"
    );
    assert!(!old_root.join("second.txt").exists());
    let views = b.node.transfers();
    let dest = |t: TransferRef| {
        views
            .iter()
            .find(|v| v.transfer == t)
            .and_then(|v| v.dest_root.clone())
            .expect("нет папки назначения")
    };
    assert!(dest(in1).ends_with("recv"), "{}", dest(in1));
    assert!(dest(in2).ends_with("recv-new"), "{}", dest(in2));
    // прежняя основная осталась среди дополнительных
    assert_eq!(b.node.settings().extra_roots.len(), 1);

    // завершённую можно убрать из списка; файлы на диске остаются
    b.node.forget_transfer(in1).unwrap();
    assert!(!b.node.transfers().iter().any(|v| v.transfer == in1));
    assert_eq!(b.node.forget_finished(), 1, "осталась только вторая");
    assert!(b.node.transfers().is_empty());
    assert!(old_root.join("first.dat").is_file());
    assert!(new_root.join("second.txt").is_file());

    // следующий приём (без перезапуска) тоже в новую
    std::fs::write(src.join("third.txt"), b"third").unwrap();
    let t3 = a.node.send(fb_on_a, &[src.join("third.txt")]).unwrap();
    let in3 = offer_named(&mut b, "third.txt");
    b.node.accept(in3).unwrap();
    assert_eq!(finished(&mut b, in3), TransferResult::Completed);
    assert_eq!(finished(&mut a, t3), TransferResult::Completed);
    assert_eq!(std::fs::read(new_root.join("third.txt")).unwrap(), b"third");

    // смена обратно на прежнюю тоже сразу
    b.node.set_receive_root(&old_root, false).unwrap();
    assert!(!b.node.settings().restart_needed);
    std::fs::write(src.join("fourth.txt"), b"fourth").unwrap();
    let t4 = a.node.send(fb_on_a, &[src.join("fourth.txt")]).unwrap();
    let in4 = offer_named(&mut b, "fourth.txt");
    b.node.accept(in4).unwrap();
    assert_eq!(finished(&mut b, in4), TransferResult::Completed);
    assert_eq!(finished(&mut a, t4), TransferResult::Completed);
    assert_eq!(
        std::fs::read(old_root.join("fourth.txt")).unwrap(),
        b"fourth"
    );

    let d = Duration::from_secs(5);
    a.node.shutdown(d);
    b.node.shutdown(d);
}

#[test]
fn failed_switch_keeps_the_old_root() {
    let rig = Rig::new("rootFail");
    let (node, _ev) = rig.start();
    let before = node.settings();
    // папка не открывается: ошибка, настройки и живая папка прежние
    let missing = rig.dir.join("no-such-folder");
    assert!(matches!(
        node.set_receive_root(&missing, false).err(),
        Some(NodeError::ReceiveRoot(_))
    ));
    let s = node.settings();
    assert_eq!(s.receive_root, before.receive_root);
    assert!(s.extra_roots.is_empty() && !s.restart_needed);

    // список папок полон: до сохранения отказ, живая папка прежняя
    let mut last: Option<std::path::PathBuf> = None;
    for i in 0..15 {
        let p = rig.dir.join(&format!("r{i}"));
        std::fs::create_dir_all(&p).unwrap();
        node.set_receive_root(&p, false).unwrap();
        last = Some(p);
    }
    let last = last.unwrap();
    let full = rig.dir.join("one-too-many");
    std::fs::create_dir_all(&full).unwrap();
    assert_eq!(
        node.set_receive_root(&full, false).err(),
        Some(NodeError::LimitReached)
    );
    let s = node.settings();
    assert!(!s.restart_needed);
    assert!(
        Path::new(&s.receive_root).ends_with(last.file_name().unwrap()),
        "основная папка в настройках изменилась"
    );
    node.shutdown(Duration::from_secs(5));
}

/// Повторный `accept` после `accept_into` не снимает привязку папки; на убранной записи `accept`
/// даёт ошибку и записи не создаёт.
#[test]
fn repeated_accept_keeps_the_chosen_folder_and_forgotten_id_stays_gone() {
    let mut a = start("bindA");
    let mut b = start("bindB");
    let (fb_on_a, fa_on_b) = befriend(&mut a, &mut b);
    online(&mut a, fb_on_a);
    online(&mut b, fa_on_b);
    let src = a.rig.dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("big.dat"), pseudo(3 * 1024 * 1024 + 1, 5)).unwrap();
    let t = a.node.send(fb_on_a, &[src.join("big.dat")]).unwrap();
    let inc = offer_named(&mut b, "big.dat");
    let other = b.rig.dir.join("recv-other");
    std::fs::create_dir_all(&other).unwrap();
    b.node.accept_into(inc, &other).unwrap();
    // второй `accept` отвергнут и чужую привязку к `other` не трогает
    assert!(b.node.accept(inc).is_err());
    assert_eq!(finished(&mut b, inc), TransferResult::Completed);
    assert_eq!(finished(&mut a, t), TransferResult::Completed);
    assert!(other.join("big.dat").is_file());
    assert!(!b.rig.recv.join("big.dat").exists());
    // убранная запись: `accept` ошибка, в списке её нет
    b.node.forget_transfer(inc).unwrap();
    assert!(b.node.accept(inc).is_err());
    assert!(b.node.transfers().is_empty());
    let d = Duration::from_secs(5);
    a.node.shutdown(d);
    b.node.shutdown(d);
}
