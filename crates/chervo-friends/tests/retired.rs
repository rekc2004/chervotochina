#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Этап 17, B1: состояние `Retired`. Текст отзыва сохраняется в записи друга ДО удаления
//! ключа пары; запись не участвует ни в наборе, ни в наборе адресов.

mod common;

use std::sync::atomic::Ordering;

use chervo_addr::{AddrSource, KnownAddr};
use chervo_friends::{FriendBook, FriendState, FriendsError, PendingRole};
use chervo_token::{RevocationReason, Token, decode, issue_revocation};
use common::*;

const ADDR: &str = "203.0.113.7:4455";

fn notice_of(text: &str) -> chervo_token::RevocationNotice {
    match decode(text).unwrap() {
        Token::Revocation(n) => n,
        _ => panic!("не отзыв"),
    }
}

/// Друг с известным адресом.
fn add_with_addr(book: &mut FriendBook, store: &MemStore, name: &str) -> Added {
    let (pair, key) = book
        .begin_pair(store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    drop(key);
    let r = remote();
    let mut nf = new_friend(name, &r, our_ed, our_x);
    nf.addrs = vec![KnownAddr {
        addr: ADDR.parse().unwrap(),
        source: AddrSource::Invite,
        last_seen_unix: 1234,
        short_lived: false,
        hint: false,
    }];
    book.finish_pair(store, &pair, nf).unwrap();
    Added {
        pair,
        remote: r,
        our_ed,
        our_x,
    }
}

#[test]
fn crash_after_retired_save_deletes_key_on_open() {
    let dir = TestDir::new();
    let store = FlakyDeleteStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    let a = add_friend(&mut book, &store.inner, "А");
    assert!(store.inner.has(&a.pair));
    // запись `Retired` сохранена, удаление ключа падает: «сбой после шага 2»
    store.fail_delete.store(true, Ordering::SeqCst);
    assert_eq!(
        book.remove(&store, &a.pair, 55).err(),
        Some(FriendsError::KeyStorageUnavailable)
    );
    assert!(store.inner.has(&a.pair), "ключ остался");
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Retired);
    let saved = book.retired();
    assert_eq!(saved.len(), 1);
    let n = notice_of(&saved[0].1);
    assert_eq!(n.revoked_ed, a.our_ed);
    assert_eq!(n.reason, RevocationReason::Removed);
    assert_eq!(n.issued_at, 55);
    // «перезапуск»: запись `Retired` с ключом -> `open` удаляет ключ
    store.fail_delete.store(false, Ordering::SeqCst);
    drop(book);
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert!(!store.inner.has(&a.pair), "ключ не удалён при открытии");
    assert_eq!(again.get(&a.pair).unwrap().state, FriendState::Retired);
    assert_eq!(again.retired(), saved, "текст отзыва пережил перезапуск");
    // открытие повторно: идемпотентно
    drop(again);
    let third = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert_eq!(third.retired(), saved);
}

#[test]
fn retry_after_failed_key_delete_returns_same_text() {
    let dir = TestDir::new();
    let store = FlakyDeleteStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    let a = add_friend(&mut book, &store.inner, "А");
    store.fail_delete.store(true, Ordering::SeqCst);
    assert!(book.rekey(&store, &a.pair, 66).is_err());
    store.fail_delete.store(false, Ordering::SeqCst);
    // повтор: тот же подписанный текст (время подписи прежнее), ключ удалён
    let text = book.rekey(&store, &a.pair, 999).unwrap();
    assert_eq!(notice_of(&text).issued_at, 66);
    assert_eq!(notice_of(&text).reason, RevocationReason::Rekey);
    assert!(!store.inner.has(&a.pair));
    assert_eq!(book.retired(), vec![(a.pair, text)]);
}

#[test]
fn retired_not_in_kx_peers_nor_dialed() {
    let (dir, store, mut book) = {
        let dir = TestDir::new();
        let store = MemStore::default();
        let book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
        (dir, store, book)
    };
    let keep = add_with_addr(&mut book, &store, "Остаётся");
    let gone = add_with_addr(&mut book, &store, "Уходит");
    let now = 1300;
    assert_eq!(
        book.usable_addrs(&gone.pair, now).len(),
        1,
        "до удаления адрес виден"
    );
    assert_eq!(book.kx_peers(&store).unwrap().0.len(), 2);

    book.remove(&store, &gone.pair, 5).unwrap().unwrap();
    let (peers, bad) = book.kx_peers(&store).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].pair(), keep.pair);
    assert!(bad.is_empty(), "Retired не считается потерянным ключом");
    assert!(book.usable_addrs(&gone.pair, now).is_empty());
    assert!(book.usable_known(&gone.pair, now).is_empty());
    assert!(book.get(&gone.pair).unwrap().known_addrs.is_empty());
    assert!(!book.is_active(&gone.pair));
    assert_eq!(
        book.note_contact(&store, &gone.pair, ADDR.parse().unwrap(), now)
            .err(),
        Some(FriendsError::NotActive)
    );
    // блокировка и разблокировка к `Retired` не применимы
    assert_eq!(
        book.block(&store, &gone.pair).err(),
        Some(FriendsError::UnknownPair)
    );
    assert_eq!(
        book.unblock(&store, &gone.pair).err(),
        Some(FriendsError::UnknownPair)
    );
    // отзыв от бывшего друга ничего не меняет
    let text = issue_revocation(&gone.remote.key, RevocationReason::Removed, 9).unwrap();
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), None);
    assert_eq!(book.get(&gone.pair).unwrap().state, FriendState::Retired);
    // то же после перезапуска
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert_eq!(again.kx_peers(&store).unwrap().0.len(), 1);
    assert!(again.usable_addrs(&gone.pair, now).is_empty());
    assert_eq!(again.usable_addrs(&keep.pair, now).len(), 1);
}

#[test]
fn forget_retired_clears() {
    let dir = TestDir::new();
    let store = MemStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    let a = add_friend(&mut book, &store, "А");
    let b = add_friend(&mut book, &store, "Б");
    // только `Retired`: активный друг и неизвестная пара отклоняются
    assert_eq!(
        book.forget_retired(&store, &a.pair).err(),
        Some(FriendsError::UnknownPair)
    );
    assert!(store.has(&a.pair), "ключ активного друга не тронут");
    book.rekey(&store, &a.pair, 1).unwrap();
    assert_eq!(book.retired().len(), 1);
    let epoch = book.epoch();
    book.forget_retired(&store, &a.pair).unwrap();
    assert!(book.retired().is_empty());
    assert!(book.get(&a.pair).is_none());
    assert_eq!(book.friends().len(), 1);
    assert_eq!(
        book.epoch(),
        epoch,
        "забыть отзыв это не изменение безопасности"
    );
    assert!(store.has(&b.pair));
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert!(again.retired().is_empty() && again.friends().len() == 1);
    assert_eq!(
        book.forget_retired(&store, &a.pair).err(),
        Some(FriendsError::UnknownPair)
    );
}

#[test]
fn forget_retired_deletes_leftover_key() {
    let dir = TestDir::new();
    let store = FlakyDeleteStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    let a = add_friend(&mut book, &store.inner, "А");
    store.fail_delete.store(true, Ordering::SeqCst);
    assert!(book.remove(&store, &a.pair, 1).is_err());
    assert!(store.inner.has(&a.pair));
    // ключ остался: пока удалить его нельзя, запись не забывается
    assert_eq!(
        book.forget_retired(&store, &a.pair).err(),
        Some(FriendsError::KeyStorageUnavailable)
    );
    assert_eq!(book.retired().len(), 1);
    store.fail_delete.store(false, Ordering::SeqCst);
    book.forget_retired(&store, &a.pair).unwrap();
    assert!(!store.inner.has(&a.pair));
    assert!(book.friends().is_empty());
}
