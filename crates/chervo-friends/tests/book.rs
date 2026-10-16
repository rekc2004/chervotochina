#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Книга друзей (часть О1): ключ списка, незавершённые пары, CRUD, права, отзывы.

mod common;

use std::fmt::Write as _;

use chervo_addr::{AddrSource, KnownAddr};
use chervo_friends::{
    AutoAcceptLimits, FriendBook, FriendState, FriendsError, KeyStatus, PendingRole, Permission,
};
use chervo_identity::{PairId, SecretStore, create};
use chervo_token::{InviteDraft, RevocationReason, Token, decode, issue_invite, issue_revocation};
use common::*;

fn fresh() -> (TestDir, MemStore, FriendBook) {
    let dir = TestDir::new();
    let store = MemStore::default();
    let book = FriendBook::open(&dir.file(), &store).unwrap();
    (dir, store, book)
}

#[test]
fn open_missing_file_empty() {
    let (dir, store, book) = fresh();
    assert!(book.friends().is_empty() && book.pending().is_empty());
    assert!(!dir.file().exists());
    assert!(store.list_key().is_none(), "ключ списка создан без записи");
}

#[test]
fn list_key_created_on_first_save_only() {
    let (dir, store, mut book) = fresh();
    assert!(store.list_key().is_none());
    let (_p, _k) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let key = store.list_key().expect("ключ создан при первой записи");
    assert_eq!(key.len(), 32);
    assert!(dir.file().exists());
    // повторное открытие и ещё одна запись ключ не меняют
    let mut again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(again.pending().len(), 1);
    again.begin_pair(&store, PendingRole::Invitee, 200).unwrap();
    assert_eq!(store.list_key().unwrap(), key);
}

#[test]
fn file_without_key_is_error_and_untouched() {
    let (dir, store, mut book) = fresh();
    add_friend(&mut book, &store, "Аня");
    let before = std::fs::read(dir.file()).unwrap();
    let empty = MemStore::default();
    assert_eq!(
        FriendBook::open(&dir.file(), &empty).err(),
        Some(FriendsError::ListKeyMissing)
    );
    assert_eq!(std::fs::read(dir.file()).unwrap(), before);
    assert!(empty.list_key().is_none(), "ключ молча создан");
    // другой ключ: файл нечитаем, но не тронут
    chervo_identity::ListKeyStore::write_list_key(&empty, &[7u8; 32]).unwrap();
    assert_eq!(
        FriendBook::open(&dir.file(), &empty).err(),
        Some(FriendsError::Corrupt)
    );
    assert_eq!(std::fs::read(dir.file()).unwrap(), before);
}

#[test]
fn start_over_renames() {
    let (dir, store, mut book) = fresh();
    add_friend(&mut book, &store, "Аня");
    let before = std::fs::read(dir.file()).unwrap();
    let empty = MemStore::default();
    let mut fresh_book = FriendBook::start_over(&dir.file(), &empty, 77).unwrap();
    assert!(fresh_book.friends().is_empty());
    assert!(!dir.file().exists());
    let moved = dir.0.join("friends.chfl.unreadable-77");
    assert_eq!(std::fs::read(&moved).unwrap(), before);
    // новая книга сохраняется, ключ создаётся (файла и ключа нет)
    fresh_book
        .begin_pair(&empty, PendingRole::Inviter, 5)
        .unwrap();
    assert!(empty.list_key().is_some());
    assert!(dir.file().exists());
}

#[test]
fn begin_pair_saves_pending_before_create() {
    let dir = TestDir::new();
    let store = ProbeStore::new(dir.file());
    let mut book = FriendBook::open(&dir.file(), &store).unwrap();
    let (pair, _k) = book.begin_pair(&store, PendingRole::Inviter, 10).unwrap();
    // в момент записи ключа пары запись pending уже была в файле
    assert_eq!(*store.pending_seen.lock().unwrap(), vec![1]);
    assert!(store.inner.has(&pair));
}

#[test]
fn begin_pair_create_error_cleans_up() {
    let dir = TestDir::new();
    let store = FailingCreateStore::default();
    let mut book = FriendBook::open(&dir.file(), &store).unwrap();
    let r = book.begin_pair(&store, PendingRole::Inviter, 10);
    assert_eq!(r.err(), Some(FriendsError::KeyStorageUnavailable));
    assert!(book.pending().is_empty());
    assert!(
        store
            .inner
            .deletes
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "ключ не удалялся"
    );
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert!(again.pending().is_empty());
}

#[test]
fn expire_deletes_key_and_pending() {
    let (dir, store, mut book) = fresh();
    let (p1, _k1) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let (p2, _k2) = book.begin_pair(&store, PendingRole::Invitee, 200).unwrap();
    assert_eq!(book.expire(&store, 99).unwrap(), 0);
    assert_eq!(book.expire(&store, 100).unwrap(), 1);
    assert!(!store.has(&p1) && store.has(&p2));
    assert_eq!(book.pending().len(), 1);
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(again.pending().len(), 1);
}

#[test]
fn drop_all_pending_on_start() {
    let (dir, store, mut book) = fresh();
    let (p1, _k1) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let (p2, _k2) = book
        .begin_pair(&store, PendingRole::Invitee, 1 << 40)
        .unwrap();
    let friend = add_friend(&mut book, &store, "Аня");
    let mut reopened = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(reopened.drop_all_pending(&store).unwrap(), 2);
    assert!(!store.has(&p1) && !store.has(&p2));
    assert!(reopened.pending().is_empty());
    assert!(store.has(&friend.pair), "ключ настоящего друга не тронут");
    assert_eq!(reopened.friends().len(), 1);
}

#[test]
fn finish_pair_creates_active_ask() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "Аня");
    assert!(book.pending().is_empty());
    let f = book.get(&a.pair).unwrap();
    assert_eq!(f.state, FriendState::Active);
    assert_eq!(f.permission, Permission::Ask);
    assert_eq!(f.last_addr_seq, 0);
    assert_eq!(f.added_at_unix, 1234);
    assert_eq!(f.friend_ed, a.remote.ed);
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(again.get(&a.pair).unwrap().name, "Аня");
}

#[test]
fn finish_pair_rules() {
    let (_dir, store, mut book) = fresh();
    let (pair, key) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    let r = remote();
    let nf = |name: &str| new_friend(name, &r, our_ed, our_x);
    for bad in ["", &"я".repeat(33), "a\nb", "a\u{7}"] {
        assert_eq!(
            book.finish_pair(&store, &pair, nf(bad)).err(),
            Some(FriendsError::InvalidName),
            "{bad:?}"
        );
    }
    assert!(book.finish_pair(&store, &pair, nf(&"x".repeat(64))).is_ok());

    // тот же ключ у друга и у нас
    let (pair2, key2) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let (e2, x2) = (key2.public_key(), key2.kx_public());
    let same_ed = new_friend("Б", &remote(), e2, x2);
    let mut same_ed = same_ed;
    same_ed.friend_ed = e2;
    assert_eq!(
        book.finish_pair(&store, &pair2, same_ed).err(),
        Some(FriendsError::KeyMissingOrChanged)
    );
    let mut same_x = new_friend("Б", &remote(), e2, x2);
    same_x.friend_x = x2;
    assert_eq!(
        book.finish_pair(&store, &pair2, same_x).err(),
        Some(FriendsError::KeyMissingOrChanged)
    );
    // повторное завершение уже завершённой пары и неизвестная пара: нет pending
    assert_eq!(
        book.finish_pair(&store, &pair, nf("В")).err(),
        Some(FriendsError::UnknownPair)
    );
    let stranger = PairId::generate().unwrap();
    assert_eq!(
        book.finish_pair(&store, &stranger, nf("Г")).err(),
        Some(FriendsError::UnknownPair)
    );
    // адреса обрезаются до 16
    let mut many = new_friend("Д", &remote(), e2, x2);
    many.addrs = (1..=20u16)
        .map(|p| KnownAddr {
            addr: format!("203.0.113.9:{}", 1000 + p).parse().unwrap(),
            source: AddrSource::Invite,
            last_seen_unix: 1,
            short_lived: false,
        })
        .collect();
    book.finish_pair(&store, &pair2, many).unwrap();
    assert_eq!(book.get(&pair2).unwrap().known_addrs.len(), 16);
}

#[test]
fn locked_and_unavailable_same_error() {
    let dir = TestDir::new();
    for st in [locked_store(), unavailable_store()] {
        assert_eq!(
            FriendBook::open(&dir.file(), &st).err(),
            Some(FriendsError::KeyStorageUnavailable)
        );
    }
    // книга открыта на рабочем хранилище, затем хранилище пар недоступно
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "Аня");
    for st in [locked_store(), unavailable_store()] {
        assert_eq!(
            book.begin_pair(&st, PendingRole::Inviter, 1).err(),
            Some(FriendsError::KeyStorageUnavailable)
        );
        assert_eq!(
            book.kx_peers(&st).err(),
            Some(FriendsError::KeyStorageUnavailable)
        );
        assert_eq!(
            book.remove(&st, &a.pair, 1).err(),
            Some(FriendsError::KeyStorageUnavailable)
        );
    }
    assert_eq!(book.friends().len(), 1, "запись не должна пропасть");
}

#[test]
fn kx_peers_reports_missing_and_mismatch() {
    let (_d, store, mut book) = fresh();
    let ok = add_friend(&mut book, &store, "Ок");
    let missing = add_friend(&mut book, &store, "Нет");
    let changed = add_friend(&mut book, &store, "Другой");
    store.delete(&missing.pair).unwrap();
    store.delete(&changed.pair).unwrap();
    create(&store, &changed.pair).unwrap(); // другой ключ под тем же PairId
    let (peers, bad) = book.kx_peers(&store).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].pair(), ok.pair);
    assert_eq!(peers[0].theirs(), ok.remote.x);
    assert_eq!(bad.len(), 2);
    assert!(bad.contains(&(missing.pair, KeyStatus::MissingOrChanged)));
    assert!(bad.contains(&(changed.pair, KeyStatus::MissingOrChanged)));
    assert!(!store.has(&missing.pair), "ключ создан молча");
}

#[test]
fn kx_peers_unsupported_version_needs_decision() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "Аня");
    let blob = vec![1u8; 129];
    store.put_raw(&a.pair, &blob);
    let (peers, bad) = book.kx_peers(&store).unwrap();
    assert!(peers.is_empty());
    assert_eq!(bad, vec![(a.pair, KeyStatus::NeedsDecision)]);
    assert_eq!(store.read(&a.pair).unwrap().unwrap().as_slice(), &blob[..]);
}

#[test]
fn kx_peers_excludes_blocked_and_revoked() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let b = add_friend(&mut book, &store, "Б");
    let c = add_friend(&mut book, &store, "В");
    book.block(&store, &b.pair).unwrap();
    let text = issue_revocation(&c.remote.key, RevocationReason::Removed, 5).unwrap();
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), Some(c.pair));
    let (peers, bad) = book.kx_peers(&store).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].pair(), a.pair);
    assert!(bad.is_empty());
}

#[test]
fn permission_default_ask() {
    assert_eq!(Permission::default(), Permission::Ask);
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    assert_eq!(book.get(&a.pair).unwrap().permission, Permission::Ask);
}

#[test]
fn autoaccept_requires_limits() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    for l in [(0u64, 5u32), (5, 0), (0, 0)] {
        let p = Permission::AutoAccept(AutoAcceptLimits {
            max_total_bytes: l.0,
            max_files: l.1,
        });
        assert_eq!(
            book.set_permission(&store, &a.pair, p).err(),
            Some(FriendsError::InvalidLimits)
        );
    }
    assert_eq!(book.get(&a.pair).unwrap().permission, Permission::Ask);
    let good = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1 << 20,
        max_files: 3,
    });
    book.set_permission(&store, &a.pair, good).unwrap();
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(again.get(&a.pair).unwrap().permission, good);
    assert_eq!(
        book.set_permission(&store, &PairId::generate().unwrap(), Permission::Ask)
            .err(),
        Some(FriendsError::UnknownPair)
    );
}

#[test]
fn block_unblock() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    assert_eq!(
        book.unblock(&store, &a.pair).err(),
        Some(FriendsError::UnknownPair)
    );
    book.block(&store, &a.pair).unwrap();
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Blocked);
    assert_eq!(
        book.block(&store, &a.pair).err(),
        Some(FriendsError::UnknownPair)
    );
    assert!(store.has(&a.pair), "блокировка ключ не удаляет");
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(again.get(&a.pair).unwrap().state, FriendState::Blocked);
    book.unblock(&store, &a.pair).unwrap();
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Active);
    book.rename(&store, &a.pair, "Новое имя").unwrap();
    assert_eq!(book.get(&a.pair).unwrap().name, "Новое имя");
    assert_eq!(
        book.rename(&store, &a.pair, "").err(),
        Some(FriendsError::InvalidName)
    );
}

fn revocation_of(text: &str) -> chervo_token::RevocationNotice {
    match decode(text).unwrap() {
        Token::Revocation(n) => n,
        _ => panic!("не отзыв"),
    }
}

#[test]
fn remove_returns_revocation_and_deletes_key() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let text = book.remove(&store, &a.pair, 55).unwrap().unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.revoked_ed, a.our_ed);
    assert_eq!(n.revoked_x, a.our_x);
    assert_eq!(n.reason, RevocationReason::Removed);
    assert_eq!(n.issued_at, 55);
    assert!(!store.has(&a.pair));
    assert!(book.friends().is_empty());
    assert!(
        FriendBook::open(&dir.file(), &store)
            .unwrap()
            .friends()
            .is_empty()
    );
    // ключа нет: запись всё равно убирается, отзыва нет
    let b = add_friend(&mut book, &store, "Б");
    store.delete(&b.pair).unwrap();
    assert_eq!(book.remove(&store, &b.pair, 1).unwrap(), None);
    assert!(book.friends().is_empty());
    assert_eq!(
        book.remove(&store, &b.pair, 1).err(),
        Some(FriendsError::UnknownPair)
    );
}

#[test]
fn rekey_returns_revocation_and_deletes_key() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let text = book.rekey(&store, &a.pair, 66).unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.revoked_ed, a.our_ed);
    assert_eq!(n.reason, RevocationReason::Rekey);
    assert!(!store.has(&a.pair));
    assert!(book.friends().is_empty());
    assert_eq!(store.pair_count(), 0);
}

#[test]
fn rekey_key_missing_keeps_record() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    store.delete(&a.pair).unwrap();
    assert_eq!(
        book.rekey(&store, &a.pair, 1).err(),
        Some(FriendsError::KeyMissingOrChanged)
    );
    assert_eq!(book.friends().len(), 1);
    // версия записи неизвестна: решение за пользователем
    store.put_raw(&a.pair, &[1u8; 129]);
    assert_eq!(
        book.rekey(&store, &a.pair, 1).err(),
        Some(FriendsError::KeyNeedsDecision)
    );
    assert_eq!(book.friends().len(), 1);
    assert!(store.has(&a.pair));
}

#[test]
fn apply_revocation_marks_and_deletes_key() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let text = issue_revocation(&a.remote.key, RevocationReason::Rekey, 9).unwrap();
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), Some(a.pair));
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::RevokedByPeer);
    assert!(!store.has(&a.pair), "наш ключ пары остался");
    // повтор ничего не делает
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), None);
    let again = FriendBook::open(&dir.file(), &store).unwrap();
    assert_eq!(
        again.get(&a.pair).unwrap().state,
        FriendState::RevokedByPeer
    );
}

#[test]
fn apply_revocation_unknown_ignored() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let stranger = remote();
    let text = issue_revocation(&stranger.key, RevocationReason::Removed, 9).unwrap();
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), None);
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Active);
    assert!(store.has(&a.pair));
}

#[test]
fn apply_revocation_forged_rejected() {
    let (_d, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    let text = issue_revocation(&a.remote.key, RevocationReason::Removed, 9).unwrap();
    // испорченный символ внутри подписанной части
    let mut bytes = text.clone().into_bytes();
    bytes[30] = if bytes[30] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(bytes).unwrap();
    assert_eq!(
        book.apply_revocation(&store, &forged).err(),
        Some(FriendsError::BadRevocation)
    );
    assert_eq!(
        book.apply_revocation(&store, "мусор").err(),
        Some(FriendsError::BadRevocation)
    );
    // приглашение вместо отзыва
    let k = remote();
    let (_p, invite) = issue_invite(
        &InviteDraft {
            issued_at: 1000,
            ttl_secs: 900,
            addrs: vec!["203.0.113.7:4455".parse().unwrap()],
        },
        &k.key,
    )
    .unwrap();
    assert_eq!(
        book.apply_revocation(&store, &invite).err(),
        Some(FriendsError::BadRevocation)
    );
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Active);
    assert!(store.has(&a.pair));
}

#[test]
fn save_overwrites_existing() {
    let (dir, store, mut book) = fresh();
    for i in 0..5 {
        add_friend(&mut book, &store, &format!("Друг {i}"));
        let again = FriendBook::open(&dir.file(), &store).unwrap();
        assert_eq!(again.friends().len(), i + 1);
    }
    assert!(!dir.0.join("friends.chfl.tmp").exists(), "остался .tmp");
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn no_plaintext_on_disk() {
    let (dir, store, mut book) = fresh();
    let (pair, key) = book.begin_pair(&store, PendingRole::Inviter, 100).unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    let r = remote();
    let mut nf = new_friend("СекретноеИмяДруга", &r, our_ed, our_x);
    nf.addrs = vec![KnownAddr {
        addr: "198.51.100.77:48151".parse().unwrap(),
        source: AddrSource::Invite,
        last_seen_unix: 1,
        short_lived: false,
    }];
    book.finish_pair(&store, &pair, nf).unwrap();
    let file = std::fs::read(dir.file()).unwrap();
    let file_hex = hex(&file);
    let file_b64 = b64(&file);
    let secrets: Vec<(&str, Vec<u8>)> = vec![
        ("имя", "СекретноеИмяДруга".as_bytes().to_vec()),
        ("ed друга", r.ed.to_bytes().to_vec()),
        ("x друга", r.x.to_bytes().to_vec()),
        ("наш ed", our_ed.to_bytes().to_vec()),
        ("адрес текстом", b"198.51.100.77".to_vec()),
        ("адрес байтами", vec![198, 51, 100, 77]),
    ];
    for (what, s) in &secrets {
        assert!(!contains(&file, s), "{what}: сырые байты");
        assert!(!file_hex.contains(&hex(s)), "{what}: hex");
        // base64 ищем по всем трём сдвигам выравнивания: берём середину кодировки
        for shift in 0..3 {
            let mut padded = vec![0u8; shift];
            padded.extend_from_slice(s);
            let enc = b64(&padded);
            let mid = &enc[(enc.len() / 4)..(enc.len() * 3 / 4).max(enc.len() / 4 + 4)];
            assert!(!file_b64.contains(mid), "{what}: base64 сдвиг {shift}");
        }
    }
    // и нет открытого текста во всём каталоге
    for e in std::fs::read_dir(&dir.0).unwrap() {
        let data = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!contains(&data, "СекретноеИмяДруга".as_bytes()));
    }
}

/// Сбой записи списка: на месте файла каталог, `rename` не проходит (`Io`).
fn break_file(dir: &TestDir) {
    std::fs::remove_file(dir.file()).unwrap();
    std::fs::create_dir(dir.file()).unwrap();
}

#[test]
fn rekey_save_failure_keeps_revocation_text() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    break_file(&dir);
    assert_eq!(
        book.rekey(&store, &a.pair, 66).err(),
        Some(FriendsError::Io)
    );
    // ключ удалён, запись осталась
    assert!(!store.has(&a.pair));
    assert_eq!(book.friends().len(), 1);
    std::fs::remove_dir(dir.file()).unwrap();
    // повтор отдаёт тот же подписанный текст, а не KeyMissingOrChanged
    let text = book.rekey(&store, &a.pair, 99).unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.revoked_ed, a.our_ed);
    assert_eq!(n.reason, RevocationReason::Rekey);
    assert_eq!(n.issued_at, 66);
    assert!(book.friends().is_empty());
    // текст выдан один раз: дальше пара неизвестна
    assert_eq!(
        book.rekey(&store, &a.pair, 1).err(),
        Some(FriendsError::UnknownPair)
    );
}

#[test]
fn remove_save_failure_keeps_revocation_text() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    break_file(&dir);
    assert_eq!(
        book.remove(&store, &a.pair, 55).err(),
        Some(FriendsError::Io)
    );
    assert!(!store.has(&a.pair));
    std::fs::remove_dir(dir.file()).unwrap();
    let text = book.remove(&store, &a.pair, 77).unwrap().unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.reason, RevocationReason::Removed);
    assert_eq!(n.issued_at, 55);
    assert!(book.friends().is_empty());
}

#[test]
fn apply_revocation_save_failure_is_retryable() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    // отзыв от друга: его ключи, подпись его ключом пары
    let text = issue_revocation(&a.remote.key, RevocationReason::Removed, 5).unwrap();
    break_file(&dir);
    assert_eq!(
        book.apply_revocation(&store, &text).err(),
        Some(FriendsError::Io)
    );
    std::fs::remove_dir(dir.file()).unwrap();
    // текст у вызывающего остался, повтор применяется
    assert_eq!(book.apply_revocation(&store, &text).unwrap(), Some(a.pair));
}

#[cfg(unix)]
#[test]
fn save_uses_0600_and_does_not_follow_tmp_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (dir, store, mut book) = fresh();
    let victim = dir.file().with_file_name("victim.txt");
    std::fs::write(&victim, b"keep").unwrap();
    let mut tmp = dir.file().into_os_string();
    tmp.push(".tmp");
    symlink(&victim, &tmp).unwrap();
    add_friend(&mut book, &store, "А");
    // симлинк не открыт: чужой файл цел, список записан
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    let mode = std::fs::metadata(dir.file()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(
        std::fs::symlink_metadata(&tmp).is_err(),
        ".tmp остался после rename"
    );
    assert_eq!(
        FriendBook::open(&dir.file(), &store)
            .unwrap()
            .friends()
            .len(),
        1
    );
}
