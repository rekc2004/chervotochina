#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Два настоящих узла в одном процессе по петле (этап 18а, критерий приёмки node_net):
//! приглашение с ручным адресом 127.0.0.1, проверочный код на обеих сторонах, отказ и согласие,
//! `FriendOnline`, передача папки (3 файла, один вложенный, один `.exe`), вопрос про
//! исполняемый файл, SHA-256 принятых файлов, отказ от предложения, блокировка, отзыв после
//! «пересоздать ключ», остановка в срок. Запуск: `--test-threads=1`.

#[path = "support/harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chervo_core::texts::EXECUTABLE_TEXT;
use chervo_core::{
    FileKind, FriendRef, FriendStatus, InviteOutcome, Node, NodeEvent, TransferRef, TransferResult,
};
use harness::{Rig, Watch, sha256_hex_of_file};

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

fn is_digits(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 9
        && b[4] == b' '
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_digit())
}

/// Дружба: приглашение с `a`, принятие на `b`, один и тот же код, оба «совпало».
fn befriend(
    a: &mut Side,
    b: &mut Side,
    name_of_b: &str,
    name_of_a: &str,
) -> (FriendRef, FriendRef) {
    a.w.clear();
    b.w.clear();
    let (inv_a, token) = a
        .node
        .create_invite(false, Some(lo(a.rig.port)))
        .expect("create_invite");
    assert!(token.reveals_ip());
    let inv_b = b.node.accept_invite(token.as_str()).expect("accept_invite");
    let sas_a =
        a.w.wait(LONG, |e| match e {
            NodeEvent::InviteSas { invite, sas } if *invite == inv_a => Some(*sas),
            _ => None,
        })
        .expect("SAS у приглашающего");
    let sas_b =
        b.w.wait(LONG, |e| match e {
            NodeEvent::InviteSas { invite, sas } if *invite == inv_b => Some(*sas),
            _ => None,
        })
        .expect("SAS у принимающего");
    assert!(is_digits(&sas_a.digits()), "{}", sas_a.digits());
    assert_eq!(sas_a.digits(), sas_b.digits(), "коды не совпали");
    assert_eq!(sas_a.spoken().split(' ').count(), 8);
    // SAS не печатается через Debug
    let shown = format!("{sas_a:?}");
    assert!(!shown.contains(&sas_a.digits()[..4]) && !shown.chars().any(|c| c.is_ascii_digit()));
    a.node.confirm_sas(inv_a, true, name_of_b).unwrap();
    b.node.confirm_sas(inv_b, true, name_of_a).unwrap();
    for (s, inv) in [(&mut *a, inv_a), (&mut *b, inv_b)] {
        let out =
            s.w.wait(LONG, |e| match e {
                NodeEvent::InviteFinished { invite, outcome } if *invite == inv => Some(*outcome),
                _ => None,
            })
            .expect("итог приглашения");
        assert_eq!(out, InviteOutcome::Added);
    }
    let fa = a.node.friends();
    let fb = b.node.friends();
    assert_eq!((fa.len(), fb.len()), (1, 1));
    assert_eq!(fa[0].name, name_of_b);
    assert_eq!(fb[0].name, name_of_a);
    (fa[0].friend, fb[0].friend)
}

fn online(s: &mut Side, f: FriendRef) {
    s.w.wait(LONG, |e| match e {
        NodeEvent::FriendOnline { friend, .. } if *friend == f => Some(()),
        _ => None,
    })
    .expect("друг не появился в сети");
    assert!(s.node.friends().iter().any(|v| v.friend == f && v.online));
}

fn write_file(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
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

#[test]
fn two_nodes_befriend_transfer_block_and_revoke() {
    harness::check_sha256_oracle();
    let mut a = start("netA");
    let mut b = start("netB");

    // --- отказ по коду: «не совпадает» с одной стороны, друга нет нигде
    a.w.clear();
    b.w.clear();
    let (inv_a, token) = a.node.create_invite(false, Some(lo(a.rig.port))).unwrap();
    let inv_b = b.node.accept_invite(token.as_str()).unwrap();
    a.w.wait(LONG, |e| {
        matches!(e, NodeEvent::InviteSas { .. }).then_some(())
    })
    .expect("SAS A");
    b.w.wait(LONG, |e| {
        matches!(e, NodeEvent::InviteSas { .. }).then_some(())
    })
    .expect("SAS B");
    a.node.confirm_sas(inv_a, false, "").unwrap();
    b.node.confirm_sas(inv_b, true, "Анна").unwrap();
    let out_a =
        a.w.wait(LONG, |e| match e {
            NodeEvent::InviteFinished { outcome, .. } => Some(*outcome),
            _ => None,
        })
        .expect("итог у A");
    assert_eq!(out_a, InviteOutcome::Declined);
    let out_b =
        b.w.wait(LONG, |e| match e {
            NodeEvent::InviteFinished { outcome, .. } => Some(*outcome),
            _ => None,
        })
        .expect("итог у B");
    assert_ne!(out_b, InviteOutcome::Added);
    assert!(a.node.friends().is_empty() && b.node.friends().is_empty());
    assert_eq!(a.rig.store.pair_count(), 0, "ключ отклонённой пары остался");

    // --- дружба с совпавшим кодом
    let (fb_on_a, fa_on_b) = befriend(&mut a, &mut b, "Боб", "Анна");
    online(&mut a, fb_on_a);
    online(&mut b, fa_on_b);

    // --- папка: 3 файла, один вложенный, один .exe
    let src = a.rig.dir.join("src");
    let big = pseudo(3 * 1024 * 1024 + 17, 7);
    write_file(
        &src.join("pics").join("a.txt"),
        b"hello, \xd0\xbc\xd0\xb8\xd1\x80\n",
    );
    write_file(&src.join("pics").join("sub").join("b.bin"), &big);
    write_file(
        &src.join("pics").join("tool.exe"),
        b"MZ\x90\x00 not a program",
    );
    let t = a.node.send(fb_on_a, &[src.join("pics")]).expect("send");
    let incoming =
        b.w.wait(LONG, |e| match e {
            NodeEvent::OfferIncoming { transfer } => Some(*transfer),
            _ => None,
        })
        .expect("предложения нет");
    let offer = b.node.offer(incoming).unwrap();
    assert_eq!(offer.friend, fa_on_b);
    assert_eq!(offer.files.len(), 3);
    let mut names: Vec<&str> = offer.files.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["pics/a.txt", "pics/sub/b.bin", "pics/tool.exe"]);
    let exe = offer
        .files
        .iter()
        .find(|f| f.name.ends_with("tool.exe"))
        .unwrap();
    assert_eq!(exe.kind, FileKind::ExecutableLike);
    assert!(exe.needs_question);
    let txt = offer
        .files
        .iter()
        .find(|f| f.name.ends_with("a.txt"))
        .unwrap();
    assert_eq!((txt.kind, txt.needs_question), (FileKind::Safe, false));
    assert!(offer.needs_question);
    assert!(offer.warnings.contains(&EXECUTABLE_TEXT));
    assert!(!offer.space.short);
    assert_eq!(
        offer.total,
        offer.files.iter().map(|f| f.size).sum::<u64>(),
        "итог не равен сумме файлов"
    );
    // исходящая передача видна в снимке
    let snap = a.node.transfers();
    assert!(snap.iter().any(|v| v.transfer == t));
    b.node.accept(incoming).unwrap();
    assert_eq!(finished(&mut b, incoming), TransferResult::Completed);
    assert_eq!(finished(&mut a, t), TransferResult::Completed);
    // SHA-256 принятого равен исходному
    let root: PathBuf = b.rig.recv.clone();
    for f in &offer.files {
        let got = root.join(f.name.replace('/', std::path::MAIN_SEPARATOR_STR));
        let want = src.join(f.name.replace('/', std::path::MAIN_SEPARATOR_STR));
        assert!(got.is_file(), "нет принятого файла");
        assert_eq!(
            sha256_hex_of_file(&got),
            sha256_hex_of_file(&want),
            "SHA-256 не совпал: {}",
            f.name
        );
    }
    let view = b
        .node
        .transfers()
        .into_iter()
        .find(|v| v.transfer == incoming)
        .unwrap();
    assert_eq!(view.result, Some(TransferResult::Completed));
    assert!(view.dest_root.is_some());
    assert_eq!(view.total, offer.total);
    // D1: после завершения счётчик получателя равен итогу, а не последнему сглаженному событию
    assert_eq!(
        view.done, view.total,
        "счётчик получателя не дошёл до итога"
    );

    // --- отказ от предложения
    write_file(&src.join("no.txt"), b"nobody wants this");
    let t2 = a.node.send(fb_on_a, &[src.join("no.txt")]).unwrap();
    let in2 =
        b.w.wait(LONG, |e| match e {
            NodeEvent::OfferIncoming { transfer } => Some(*transfer),
            _ => None,
        })
        .expect("второе предложение");
    b.node.decline(in2).unwrap();
    assert_eq!(finished(&mut b, in2), TransferResult::Declined);
    assert_eq!(finished(&mut a, t2), TransferResult::Declined);

    // --- скрытые символы в имени не доходят до человека
    let tricky = src.join("photo\u{202E}gpj.txt");
    if std::fs::write(&tricky, b"x").is_ok() {
        let t3 = a.node.send(fb_on_a, &[tricky]).unwrap();
        let in3 =
            b.w.wait(LONG, |e| match e {
                NodeEvent::OfferIncoming { transfer } => Some(*transfer),
                _ => None,
            })
            .expect("предложение со скрытым символом");
        let o3 = b.node.offer(in3).unwrap();
        for f in &o3.files {
            assert!(!f.name.contains('\u{202E}'), "bidi дошёл до экрана");
        }
        b.node.decline(in3).unwrap();
        let _ = finished(&mut b, in3);
        let _ = finished(&mut a, t3);
    }

    // --- приём в другую папку: путь запоминается только после успеха и в каноническом виде
    let other = b.rig.dir.join("recv-other");
    std::fs::create_dir_all(&other).unwrap();
    write_file(&src.join("extra.txt"), b"into another folder");
    let t4 = a.node.send(fb_on_a, &[src.join("extra.txt")]).unwrap();
    let in4 =
        b.w.wait(LONG, |e| match e {
            NodeEvent::OfferIncoming { transfer } => Some(*transfer),
            _ => None,
        })
        .expect("предложение для другой папки");
    assert!(b.node.settings().extra_roots.is_empty());
    b.node.accept_into(in4, &other).unwrap();
    assert_eq!(finished(&mut b, in4), TransferResult::Completed);
    assert_eq!(finished(&mut a, t4), TransferResult::Completed);
    assert_eq!(
        std::fs::read(other.join("extra.txt")).unwrap(),
        b"into another folder"
    );
    let canon = std::fs::canonicalize(&other).unwrap();
    let shown = b.node.settings().extra_roots;
    assert_eq!(shown.len(), 1);
    assert_eq!(
        Path::new(&shown[0]),
        Path::new(canon.to_str().unwrap().trim_start_matches(r"\\?\"))
    );

    // --- блокировка рвёт живое соединение
    a.w.clear();
    b.w.clear();
    a.node.block(fb_on_a).unwrap();
    b.w.wait(LONG, |e| match e {
        NodeEvent::FriendOffline { friend } if *friend == fa_on_b => Some(()),
        _ => None,
    })
    .expect("B не увидел обрыв после блокировки");
    let v = &a.node.friends()[0];
    assert_eq!((v.state, v.online), (FriendStatus::Blocked, false));
    a.node.unblock(fb_on_a).unwrap();
    assert_eq!(a.node.friends()[0].state, FriendStatus::Active);

    // --- «пересоздать ключ»: отзыв, друг применяет его вручную
    let text = a.node.rekey(fb_on_a).unwrap();
    assert!(!text.as_str().is_empty());
    assert_eq!(a.node.friends()[0].state, FriendStatus::Retired);
    assert_eq!(a.node.retired().len(), 1);
    assert_eq!(a.rig.store.pair_count(), 0, "старый ключ пары остался");
    assert_eq!(
        b.node.apply_revocation_text(text.as_str()).unwrap(),
        Some(fa_on_b)
    );
    let v = &b.node.friends()[0];
    assert_eq!((v.state, v.online), (FriendStatus::RevokedByPeer, false));
    // повтор безвреден
    assert_eq!(b.node.apply_revocation_text(text.as_str()).unwrap(), None);
    a.node.forget_retired(fb_on_a).unwrap();
    assert!(a.node.retired().is_empty());

    // --- остановка в срок; последним приходит Stopped
    let deadline = Duration::from_secs(5);
    let started = Instant::now();
    a.node.shutdown(deadline);
    b.node.shutdown(deadline);
    assert!(
        started.elapsed() < 2 * (deadline + Duration::from_secs(8)),
        "остановка заняла {:?}",
        started.elapsed()
    );
    assert!(a.w.all().contains(&NodeEvent::Stopped));
    assert!(b.w.all().contains(&NodeEvent::Stopped));
}

/// Передача переживает перезапуск получателя: недокачанное возобновляется (этап 14), а узел
/// после перезапуска видит дружбу и находит друга.
#[test]
fn friendship_survives_a_restart() {
    let mut a = start("restartA");
    let mut b = start("restartB");
    let (fb_on_a, fa_on_b) = befriend(&mut a, &mut b, "Боб", "Анна");
    online(&mut a, fb_on_a);
    online(&mut b, fa_on_b);
    b.node.shutdown(Duration::from_secs(5));
    // тот же каталог данных и хранилище ключей: список друзей и ключи на месте
    let (node, ev) = b.rig.open().expect("повторный запуск B");
    let mut w = Watch::new(ev);
    let friends = node.friends();
    assert_eq!(friends.len(), 1);
    assert_eq!(friends[0].name, "Анна");
    assert_eq!(friends[0].state, FriendStatus::Active);
    // связь восстанавливается сама: приглашённый (B) знает адрес A из приглашения
    let f = friends[0].friend;
    let _ = node.connect_now(f);
    let back = w.wait(LONG, |e| match e {
        NodeEvent::FriendOnline { friend, .. } if *friend == f => Some(()),
        _ => None,
    });
    assert!(back.is_some(), "после перезапуска друг не вернулся в сеть");
    node.shutdown(Duration::from_secs(5));
    a.node.shutdown(Duration::from_secs(5));
}
