#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Этап 17, B1 (решение владельца Q1 = A): счётчик изменений безопасности в файле и якорь
//! в хранилище ОС. Откат файла к старой копии не должен молча вернуть заблокированного или
//! удалённого друга.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use chervo_addr::{LocalSnapshot, OwnAddrs, PublishCtx, PublishSet, RouteSources};
use chervo_friends::{FriendBook, FriendState, FriendsError, NewFriend, PendingRole};
use chervo_identity::PairKey;
use chervo_token::{RevocationReason, issue_revocation};
use common::*;

const NOW: u64 = 1_700_000_000;

fn anchored() -> (TestDir, MemStore, Arc<MemEpoch>, FriendBook) {
    let dir = TestDir::new();
    let store = MemStore::default();
    let ep = MemEpoch::new();
    let book = FriendBook::open_anchored(&dir.file(), &store, ep.clone()).unwrap();
    (dir, store, ep, book)
}

fn reopen(dir: &TestDir, store: &MemStore, ep: &Arc<MemEpoch>) -> Result<FriendBook, FriendsError> {
    FriendBook::open_anchored(&dir.file(), store, ep.clone())
}

#[test]
fn epoch_grows_only_on_security_changes() {
    let (dir, store, ep, mut book) = anchored();
    assert_eq!((book.epoch(), ep.get()), (0, None));
    // незавершённая пара, имя и права не относятся к безопасности
    let (pair, key) = book
        .begin_pair(&store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    assert_eq!((book.epoch(), ep.get()), (0, None));
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    drop(key);
    let r = remote();
    book.finish_pair(&store, &pair, new_friend("А", &r, our_ed, our_x))
        .unwrap();
    assert_eq!((book.epoch(), ep.get()), (1, Some(1)), "новый друг");
    book.rename(&store, &pair, "Аня").unwrap();
    book.set_permission(&store, &pair, chervo_friends::Permission::Ask)
        .unwrap();
    assert_eq!((book.epoch(), ep.get()), (1, Some(1)));
    book.block(&store, &pair).unwrap();
    assert_eq!((book.epoch(), ep.get()), (2, Some(2)));
    book.unblock(&store, &pair).unwrap();
    assert_eq!((book.epoch(), ep.get()), (3, Some(3)));
    let text = issue_revocation(&r.key, RevocationReason::Removed, 5).unwrap();
    book.apply_revocation(&store, &text).unwrap();
    assert_eq!((book.epoch(), ep.get()), (4, Some(4)), "отзыв от друга");
    let b = add_friend_anchored(&mut book, &store);
    assert_eq!((book.epoch(), ep.get()), (5, Some(5)));
    book.remove(&store, &b, 1).unwrap();
    assert_eq!((book.epoch(), ep.get()), (6, Some(6)), "удаление");
    let c = add_friend_anchored(&mut book, &store);
    assert_eq!(book.epoch(), 7);
    book.rekey(&store, &c, 1).unwrap();
    assert_eq!((book.epoch(), ep.get()), (8, Some(8)), "смена ключа");
    book.forget_retired(&store, &c).unwrap();
    assert_eq!((book.epoch(), ep.get()), (8, Some(8)));
    // файл несёт тот же счётчик
    assert_eq!(reopen(&dir, &store, &ep).unwrap().epoch(), 8);
}

fn add_friend_anchored(book: &mut FriendBook, store: &MemStore) -> chervo_identity::PairId {
    add_friend(book, store, "Друг").pair
}

#[test]
fn rollback_detected() {
    let (dir, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    let old = std::fs::read(dir.file()).unwrap(); // копия: А активен, счётчик 1
    book.block(&store, &a.pair).unwrap();
    assert_eq!(ep.get(), Some(2));
    // «восстановили старую копию списка»: А снова активен
    std::fs::write(dir.file(), &old).unwrap();
    assert_eq!(
        reopen(&dir, &store, &ep).err(),
        Some(FriendsError::RolledBack)
    );
    // файл не изменён, якорь не понижен
    assert_eq!(std::fs::read(dir.file()).unwrap(), old);
    assert_eq!(ep.get(), Some(2));
    // книга без якоря откат не видит (так и задумано: защита только с якорем)
    let plain = FriendBook::open(&dir.file(), &store).unwrap();
    assert!(plain.is_active(&a.pair));
}

#[test]
fn rollback_detected_while_running() {
    // якорь ушёл вперёд при открытой книге (другая копия программы): изменения отклоняются
    let (_d, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    ep.set(Some(50));
    assert_eq!(
        book.block(&store, &a.pair).err(),
        Some(FriendsError::RolledBack)
    );
    assert!(book.is_active(&a.pair), "ничего не изменилось");
    assert_eq!(book.epoch(), 1);
    assert_eq!(ep.get(), Some(50));
}

#[test]
fn file_newer_than_store_repaired() {
    let (dir, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    book.block(&store, &a.pair).unwrap();
    book.unblock(&store, &a.pair).unwrap();
    assert_eq!(ep.get(), Some(3));
    // сбой между записью файла и записью в хранилище: в хранилище осталось старое значение
    ep.set(Some(2));
    let again = reopen(&dir, &store, &ep).unwrap();
    assert_eq!(again.epoch(), 3);
    assert_eq!(ep.get(), Some(3), "запись исправлена молча");
}

#[test]
fn store_write_failure_applies_change_and_later_repairs() {
    let (dir, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    ep.fail_write.store(true, Ordering::SeqCst);
    assert_eq!(
        book.block(&store, &a.pair).err(),
        Some(FriendsError::KeyStorageUnavailable)
    );
    // файл уже сохранён: блокировка не потеряна, якорь отстаёт на 1
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Blocked);
    assert_eq!((book.epoch(), ep.get()), (2, Some(1)));
    ep.fail_write.store(false, Ordering::SeqCst);
    let again = reopen(&dir, &store, &ep).unwrap();
    assert_eq!(again.get(&a.pair).unwrap().state, FriendState::Blocked);
    assert_eq!(ep.get(), Some(2));
}

#[test]
fn store_unavailable_fails_security_change_untouched() {
    let (dir, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    let before = std::fs::read(dir.file()).unwrap();
    ep.fail_read.store(true, Ordering::SeqCst);
    assert_eq!(
        book.block(&store, &a.pair).err(),
        Some(FriendsError::KeyStorageUnavailable)
    );
    assert_eq!(
        reopen(&dir, &store, &ep).err(),
        Some(FriendsError::KeyStorageUnavailable)
    );
    assert!(book.is_active(&a.pair));
    assert_eq!(std::fs::read(dir.file()).unwrap(), before);
}

#[test]
fn epoch_missing_with_data_is_rollback() {
    let (dir, store, ep, mut book) = anchored();
    add_friend(&mut book, &store, "А");
    assert_eq!(ep.get(), Some(1));
    // записи счётчика нет, а в файле он больше нуля: как откат
    ep.set(None);
    assert_eq!(
        reopen(&dir, &store, &ep).err(),
        Some(FriendsError::RolledBack)
    );
    // файла с изменениями безопасности нет (только незавершённые пары): записи может и не быть
    let (dir2, store2, ep2, mut book2) = anchored();
    book2
        .begin_pair(&store2, PendingRole::Inviter, u64::MAX)
        .unwrap();
    assert_eq!(ep2.get(), None);
    assert_eq!(reopen(&dir2, &store2, &ep2).unwrap().epoch(), 0);
    // файла нет, запись есть: пустая книга продолжает счёт, а не падает назад
    let dir3 = TestDir::new();
    let store3 = MemStore::default();
    let ep3 = MemEpoch::new();
    ep3.set(Some(5));
    let b3 = FriendBook::open_anchored(&dir3.file(), &store3, ep3.clone()).unwrap();
    assert_eq!(b3.epoch(), 5);
}

#[test]
fn accept_older_explicit_only() {
    let (dir, store, ep, mut book) = anchored();
    let a = add_friend(&mut book, &store, "А");
    let old = std::fs::read(dir.file()).unwrap();
    book.block(&store, &a.pair).unwrap();
    std::fs::write(dir.file(), &old).unwrap();
    // сколько ни открывай, молча не принимается
    for _ in 0..3 {
        assert_eq!(
            reopen(&dir, &store, &ep).err(),
            Some(FriendsError::RolledBack)
        );
        assert_eq!(ep.get(), Some(2));
    }
    // явное решение пользователя: якорь приравнивается к файлу
    let accepted = FriendBook::accept_older(&dir.file(), &store, ep.clone()).unwrap();
    assert!(accepted.is_active(&a.pair));
    assert_eq!((accepted.epoch(), ep.get()), (1, Some(1)));
    // дальше обычное открытие работает, а новые изменения снова растят счётчик
    let mut again = reopen(&dir, &store, &ep).unwrap();
    again.block(&store, &a.pair).unwrap();
    assert_eq!((again.epoch(), ep.get()), (2, Some(2)));
    // и принять «старое» ещё и без отката ничего не ломает (счётчик файла = якорь)
    let same = FriendBook::accept_older(&dir.file(), &store, ep.clone()).unwrap();
    assert_eq!((same.epoch(), ep.get()), (2, Some(2)));
}

#[test]
fn start_over_anchored_keeps_counter() {
    let (dir, store, ep, mut book) = anchored();
    add_friend(&mut book, &store, "А");
    add_friend(&mut book, &store, "Б");
    assert_eq!(ep.get(), Some(2));
    let fresh = FriendBook::start_over_anchored(&dir.file(), &store, ep.clone(), 77).unwrap();
    assert_eq!(fresh.epoch(), 2, "счётчик не падает назад");
    assert!(fresh.friends().is_empty());
}

// --- обновления адреса не трогают счётчик ----------------------------------------------

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn publish_set(route_v4: &str, port: u16) -> PublishSet {
    let mut o = OwnAddrs::new();
    o.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some(route_v4.parse().unwrap()),
            v6: None,
        },
        listen: vec![sa(&format!("0.0.0.0:{port}"))],
    });
    let set = o.publishable(PublishCtx::default(), NOW);
    assert!(!set.is_empty());
    set
}

fn new_f(theirs: &PairKey, ours: &PairKey) -> NewFriend {
    NewFriend {
        name: "peer".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: Vec::new(),
        now_unix: 1,
    }
}

#[test]
fn addr_update_does_not_bump_epoch() {
    // A: книга с якорем; B: обычная книга. Зеркальные ключи пары.
    let (dir_a, store_a, ep, mut a) = anchored();
    let dir_b = TestDir::new();
    let store_b = MemStore::default();
    let mut b = FriendBook::open(&dir_b.file(), &store_b).unwrap();
    let (pa, ka) = a
        .begin_pair(&store_a, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (pb, kb) = b
        .begin_pair(&store_b, PendingRole::Invitee, u64::MAX)
        .unwrap();
    a.finish_pair(&store_a, &pa, new_f(&kb, &ka)).unwrap();
    b.finish_pair(&store_b, &pb, new_f(&ka, &kb)).unwrap();
    assert_eq!((a.epoch(), ep.get()), (1, Some(1)));
    let before = std::fs::read(dir_a.file()).unwrap();

    // A принимает обновление от B (текстом и по соединению), выпускает своё, видит контакт
    let tok_b = b
        .issue_addr_update(&store_b, &pb, &publish_set("8.8.8.8", 4000), NOW)
        .unwrap();
    assert_eq!(
        a.apply_addr_update_text(&store_a, &tok_b.text(), NOW + 1)
            .unwrap(),
        pa
    );
    let tok_b2 = b
        .issue_addr_update(&store_b, &pb, &publish_set("1.1.1.1", 4001), NOW + 60)
        .unwrap();
    let signed = chervo_token::decode(&tok_b2.text()).unwrap();
    let chervo_token::Token::AddrUpdate(signed) = signed else {
        panic!("не обновление адреса")
    };
    a.apply_addr_update(&store_a, &pa, &signed, NOW + 61)
        .unwrap();
    a.issue_addr_update(&store_a, &pa, &publish_set("9.9.9.9", 4002), NOW + 62)
        .unwrap();
    a.note_contact(&store_a, &pa, sa("198.51.100.9:5000"), NOW + 63)
        .unwrap();

    // файл изменился (адреса, номера), счётчик и якорь нет
    assert_ne!(std::fs::read(dir_a.file()).unwrap(), before);
    assert_eq!((a.epoch(), ep.get()), (1, Some(1)));
    assert_eq!(reopen(&dir_a, &store_a, &ep).unwrap().epoch(), 1);

    // поэтому «откат» к копии со старыми адресами счётчиком не виден (остаток T5:
    // только устаревшие адреса, отказ в соединении, не обход блокировки)
    std::fs::write(dir_a.file(), &before).unwrap();
    assert!(reopen(&dir_a, &store_a, &ep).is_ok());
}
