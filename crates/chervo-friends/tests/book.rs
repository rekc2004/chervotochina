#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Книга друзей (часть О1): ключ списка, незавершённые пары, CRUD, права, отзывы.

mod common;

use std::fmt::Write as _;

use chervo_addr::{AddrSource, KnownAddr};
use chervo_friends::{
    AutoAcceptLimits, FriendBook, FriendState, FriendsError, KeyStatus, PendingRole, Permission,
    TrustConfirmation,
};
use chervo_identity::{PairId, SecretStore, create};
use chervo_token::{InviteDraft, RevocationReason, Token, decode, issue_invite, issue_revocation};
use common::*;

fn fresh() -> (TestDir, MemStore, FriendBook) {
    let dir = TestDir::new();
    let store = MemStore::default();
    let book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    let mut again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
        FriendBook::open_unanchored(&dir.file(), &empty).err(),
        Some(FriendsError::ListKeyMissing)
    );
    assert_eq!(std::fs::read(dir.file()).unwrap(), before);
    assert!(empty.list_key().is_none(), "ключ молча создан");
    // другой ключ: файл нечитаем, но не тронут
    chervo_identity::ListKeyStore::write_list_key(&empty, &[7u8; 32]).unwrap();
    assert_eq!(
        FriendBook::open_unanchored(&dir.file(), &empty).err(),
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
    let mut fresh_book = FriendBook::start_over_unanchored(&dir.file(), &empty, 77).unwrap();
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
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    let (pair, _k) = book.begin_pair(&store, PendingRole::Inviter, 10).unwrap();
    // в момент записи ключа пары запись pending уже была в файле
    assert_eq!(*store.pending_seen.lock().unwrap(), vec![1]);
    assert!(store.inner.has(&pair));
}

#[test]
fn begin_pair_create_error_cleans_up() {
    let dir = TestDir::new();
    let store = FailingCreateStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    let mut reopened = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
            hint: false,
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
            FriendBook::open_unanchored(&dir.file(), &st).err(),
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
fn autoaccept_requires_trust_confirmation() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    // set_permission никогда не включает автоприём: ни с хорошими, ни с нулевыми лимитами
    for l in [
        (0u64, 5u32),
        (5, 0),
        (0, 0),
        (1 << 20, 3),
        (u64::MAX, u32::MAX),
    ] {
        let p = Permission::AutoAccept(AutoAcceptLimits {
            max_total_bytes: l.0,
            max_files: l.1,
        });
        assert_eq!(
            book.set_permission(&store, &a.pair, p).err(),
            Some(FriendsError::TrustRequired)
        );
    }
    assert_eq!(book.get(&a.pair).unwrap().permission, Permission::Ask);
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert_eq!(again.get(&a.pair).unwrap().permission, Permission::Ask);

    // с подтверждением включается и переживает перезапуск
    book.enable_auto_accept(&store, &a.pair, TrustConfirmation::user_confirmed_trust())
        .unwrap();
    assert!(matches!(
        book.get(&a.pair).unwrap().permission,
        Permission::AutoAccept(_)
    ));
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert_eq!(
        again.get(&a.pair).unwrap().permission,
        book.get(&a.pair).unwrap().permission
    );
    assert_eq!(
        book.enable_auto_accept(
            &store,
            &PairId::generate().unwrap(),
            TrustConfirmation::user_confirmed_trust()
        )
        .err(),
        Some(FriendsError::UnknownPair)
    );
    // выключение (Ask) подтверждения не требует
    book.set_permission(&store, &a.pair, Permission::Ask)
        .unwrap();
    assert_eq!(book.get(&a.pair).unwrap().permission, Permission::Ask);
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
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
    // запись `Retired` с текстом остаётся до `forget_retired`
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Retired);
    assert_eq!(book.retired(), vec![(a.pair, text.clone())]);
    let reopened = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    assert_eq!(reopened.retired(), vec![(a.pair, text.clone())]);
    book.forget_retired(&store, &a.pair).unwrap();
    assert!(book.friends().is_empty());
    assert!(
        FriendBook::open_unanchored(&dir.file(), &store)
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
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Retired);
    assert_eq!(book.retired(), vec![(a.pair, text)]);
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
    let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
        let again = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
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
        hint: false,
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
fn rekey_save_fails_key_kept() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    break_file(&dir);
    assert_eq!(
        book.rekey(&store, &a.pair, 66).err(),
        Some(FriendsError::Io)
    );
    // сохранить запись не удалось: ключ на месте, друг прежний, отзыва нигде нет
    assert!(store.has(&a.pair));
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Active);
    assert!(book.retired().is_empty());
    assert_eq!(store.deletes.load(std::sync::atomic::Ordering::SeqCst), 0);
    std::fs::remove_dir(dir.file()).unwrap();
    // повтор подписывает заново (прежнего текста не было)
    let text = book.rekey(&store, &a.pair, 99).unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.revoked_ed, a.our_ed);
    assert_eq!(n.reason, RevocationReason::Rekey);
    assert_eq!(n.issued_at, 99);
    assert!(!store.has(&a.pair));
    assert_eq!(book.retired(), vec![(a.pair, text.clone())]);
    // повтор после успеха отдаёт тот же текст, не подписывая заново
    assert_eq!(book.rekey(&store, &a.pair, 123).unwrap(), text);
}

#[test]
fn remove_save_fails_key_kept() {
    let (dir, store, mut book) = fresh();
    let a = add_friend(&mut book, &store, "А");
    break_file(&dir);
    assert_eq!(
        book.remove(&store, &a.pair, 55).err(),
        Some(FriendsError::Io)
    );
    assert!(store.has(&a.pair));
    assert_eq!(book.get(&a.pair).unwrap().state, FriendState::Active);
    assert!(book.retired().is_empty());
    assert_eq!(store.deletes.load(std::sync::atomic::Ordering::SeqCst), 0);
    std::fs::remove_dir(dir.file()).unwrap();
    let text = book.remove(&store, &a.pair, 77).unwrap().unwrap();
    let n = revocation_of(&text);
    assert_eq!(n.reason, RevocationReason::Removed);
    assert_eq!(n.issued_at, 77);
    assert!(!store.has(&a.pair));
    assert_eq!(book.retired(), vec![(a.pair, text.clone())]);
    assert_eq!(book.remove(&store, &a.pair, 78).unwrap(), Some(text));
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
        FriendBook::open_unanchored(&dir.file(), &store)
            .unwrap()
            .friends()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------------------
// Этап 12, часть A4: номера обновлений адреса, применение, контакты, U6 v6.
// ---------------------------------------------------------------------------------------

use std::net::SocketAddr;

use chervo_addr::{
    Findability, LocalSnapshot, OwnAddrs, PublishCtx, PublishSet, RouteSources, UpdateAddr,
};
use chervo_friends::{BookData, MIN_INBAND_UPDATE_INTERVAL_SECS, NewFriend, vault};
use chervo_identity::PairKey;
use chervo_token::decode_addr_update_bin;

const NOW: u64 = 1_700_000_000;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Набор для публикации, построенный только через `OwnAddrs`: глобальный маршрутный адрес и порт.
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

struct Side {
    dir: TestDir,
    store: MemStore,
    book: FriendBook,
}

fn side() -> Side {
    let dir = TestDir::new();
    let store = MemStore::default();
    let book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();
    Side { dir, store, book }
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

/// Ещё один друг у `me`: возвращает (сторона друга, пара у друга, пара у `me`).
/// У каждой стороны свой `MemStore`; ключи зеркальные.
fn add_peer(me: &mut Side) -> (Side, PairId, PairId) {
    let mut other = side();
    let (pm, km) = me
        .book
        .begin_pair(&me.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (po, ko) = other
        .book
        .begin_pair(&other.store, PendingRole::Invitee, u64::MAX)
        .unwrap();
    me.book
        .finish_pair(&me.store, &pm, new_f(&ko, &km))
        .unwrap();
    other
        .book
        .finish_pair(&other.store, &po, new_f(&km, &ko))
        .unwrap();
    (other, po, pm)
}

/// Пара A-B. Возвращает (A, pair у A, B, pair у B).
fn duo() -> (Side, PairId, Side, PairId) {
    let mut a = side();
    let (b, pb, pa) = add_peer(&mut a);
    (a, pa, b, pb)
}

fn stranger_pair() -> PairId {
    PairId::generate().unwrap()
}

fn seq_out(s: &Side, pair: &PairId) -> u64 {
    s.book.get(pair).unwrap().addr_seq_out
}

fn file_bytes(s: &Side) -> Vec<u8> {
    std::fs::read(s.dir.file()).unwrap()
}

/// Подменяет данные в файле списка (для крайних значений счётчиков): взять, изменить,
/// запечатать, открыть заново.
fn rewrite(s: &mut Side, edit: impl FnOnce(&mut BookData)) {
    let mut data = BookData {
        epoch: s.book.epoch(),
        friends: s.book.friends().to_vec(),
        pending: s.book.pending().to_vec(),
    };
    edit(&mut data);
    let key: [u8; 32] = s.store.list_key().unwrap().try_into().unwrap();
    std::fs::write(s.dir.file(), vault::seal(&key, &data).unwrap()).unwrap();
    s.book = FriendBook::open_unanchored(&s.dir.file(), &s.store).unwrap();
}

#[test]
fn issue_persists_seq_before_returning() {
    let (mut a, pa, _b, _pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    // каталог файла списка удалён: сохранить нельзя -> Io, токена нет, значение прежнее
    let before = seq_out(&a, &pa);
    std::fs::remove_dir_all(&a.dir.0).unwrap();
    assert_eq!(
        a.book.issue_addr_update(&a.store, &pa, &set, NOW).err(),
        Some(FriendsError::Io)
    );
    assert_eq!(seq_out(&a, &pa), before, "значение в памяти изменилось");
    std::fs::create_dir_all(&a.dir.0).unwrap();
    // нормальный путь: после выдачи свежее открытие видит ровно выданный номер
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    assert_eq!(tok.seq(), NOW * 1000);
    assert_eq!(seq_out(&a, &pa), tok.seq());
    let reopened = FriendBook::open_unanchored(&a.dir.file(), &a.store).unwrap();
    assert_eq!(reopened.get(&pa).unwrap().addr_seq_out, tok.seq());
}

#[test]
fn issue_seq_strictly_increasing_across_reopen() {
    let (mut a, pa, _b, _pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let mut last = 0u64;
    for round in 0..4 {
        let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
        assert!(tok.seq() > last, "раунд {round}");
        last = tok.seq();
        // то же время, перезапуск: номер всё равно растёт на единицу
        a.book = FriendBook::open_unanchored(&a.dir.file(), &a.store).unwrap();
        assert_eq!(seq_out(&a, &pa), last);
    }
    assert_eq!(last, NOW * 1000 + 3);
    // время ушло назад: всё равно +1
    let tok = a
        .book
        .issue_addr_update(&a.store, &pa, &set, NOW - 1000)
        .unwrap();
    assert_eq!(tok.seq(), last + 1);
}

#[test]
fn issue_seq_survives_file_rollback() {
    let (mut a, pa, _b, _pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let backup = file_bytes(&a);
    let t1 = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let t2 = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    // файл откатили к копии: счётчик снова 0
    std::fs::write(a.dir.file(), &backup).unwrap();
    a.book = FriendBook::open_unanchored(&a.dir.file(), &a.store).unwrap();
    assert_eq!(seq_out(&a, &pa), 0);
    let t3 = a
        .book
        .issue_addr_update(&a.store, &pa, &set, NOW + 1)
        .unwrap();
    assert!(t3.seq() > t1.seq() && t3.seq() > t2.seq());
}

#[test]
fn issue_requires_active_and_nonempty() {
    let (mut a, pa, _b, _pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let empty = OwnAddrs::new().publishable(PublishCtx::default(), NOW);
    assert!(empty.is_empty());
    assert_eq!(
        a.book
            .issue_addr_update(&a.store, &stranger_pair(), &set, NOW)
            .err(),
        Some(FriendsError::UnknownPair)
    );
    assert_eq!(
        a.book.issue_addr_update(&a.store, &pa, &empty, NOW).err(),
        Some(FriendsError::NoAddresses)
    );
    // потерянный ключ: номер не тратится
    let backup = a.store.read(&pa).unwrap().unwrap().to_vec();
    a.store.delete(&pa).unwrap();
    assert_eq!(
        a.book.issue_addr_update(&a.store, &pa, &set, NOW).err(),
        Some(FriendsError::KeyMissingOrChanged)
    );
    a.store.put_raw(&pa, &backup);
    assert_eq!(seq_out(&a, &pa), 0);
    // неактивный друг
    a.book.block(&a.store, &pa).unwrap();
    assert_eq!(
        a.book.issue_addr_update(&a.store, &pa, &set, NOW).err(),
        Some(FriendsError::NotActive)
    );
    assert_eq!(seq_out(&a, &pa), 0);
    a.book.unblock(&a.store, &pa).unwrap();
    assert!(a.book.issue_addr_update(&a.store, &pa, &set, NOW).is_ok());
    // переполнение номера
    rewrite(&mut a, |d| d.friends[0].addr_seq_out = u64::MAX);
    assert_eq!(
        a.book.issue_addr_update(&a.store, &pa, &set, NOW).err(),
        Some(FriendsError::SeqExhausted)
    );
    assert_eq!(seq_out(&a, &pa), u64::MAX);
    rewrite(&mut a, |d| d.friends[0].addr_seq_out = u64::MAX - 1);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, 1).unwrap();
    assert_eq!(tok.seq(), u64::MAX);
}

#[test]
fn apply_text_roundtrip() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    // пробелы и регистр не мешают
    let spaced = format!("  {}  ", tok.text().to_lowercase());
    let got = b
        .book
        .apply_addr_update_text(&b.store, &spaced, NOW + 5)
        .unwrap();
    assert_eq!(got, pb);
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, tok.seq());
    assert_eq!(b.book.usable_addrs(&pb, NOW + 6), set.socket_addrs());
    let known = &b.book.get(&pb).unwrap().known_addrs;
    assert!(
        known
            .iter()
            .all(|k| k.source == chervo_addr::AddrSource::AddressUpdate
                && k.last_seen_unix == NOW + 5)
    );
    // на диске
    let reopened = FriendBook::open_unanchored(&b.dir.file(), &b.store).unwrap();
    assert_eq!(reopened.get(&pb).unwrap().last_addr_seq, tok.seq());
    assert_eq!(reopened.usable_addrs(&pb, NOW + 6), set.socket_addrs());
    // постоянный глобальный адрес друга: найдёмся и без своего
    assert_eq!(
        b.book.findability(&pb, false, NOW + 6).unwrap(),
        Findability::Ok
    );
    assert_eq!(
        b.book.findability(&stranger_pair(), false, NOW).err(),
        Some(FriendsError::UnknownPair)
    );
    assert!(b.book.usable_addrs(&stranger_pair(), NOW).is_empty());
}

#[test]
fn apply_text_old_seq_rejected() {
    let (mut a, pa, mut b, pb) = duo();
    let set1 = publish_set("8.8.8.8", 4000);
    let set2 = publish_set("1.1.1.1", 4001);
    let t1 = a.book.issue_addr_update(&a.store, &pa, &set1, NOW).unwrap();
    let t2 = a.book.issue_addr_update(&a.store, &pa, &set2, NOW).unwrap();
    assert!(t2.seq() > t1.seq());
    b.book
        .apply_addr_update_text(&b.store, &t2.text(), NOW)
        .unwrap();
    let file_after = file_bytes(&b);
    // меньше
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &t1.text(), NOW + 1)
            .err(),
        Some(FriendsError::StaleSeq)
    );
    // равно
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &t2.text(), NOW + 1)
            .err(),
        Some(FriendsError::StaleSeq)
    );
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, t2.seq());
    assert_eq!(b.book.usable_addrs(&pb, NOW + 2), set2.socket_addrs());
    assert_eq!(
        file_bytes(&b),
        file_after,
        "отклонённый токен не пишет файл"
    );
    // номер выше принимается
    let t3 = a.book.issue_addr_update(&a.store, &pa, &set1, NOW).unwrap();
    b.book
        .apply_addr_update_text(&b.store, &t3.text(), NOW + 3)
        .unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW + 4), set1.socket_addrs());
}

#[test]
fn apply_text_foreign_pair_rejected() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    // второй друг у A: токен, выпущенный для него, не подходит первому и наоборот
    let (mut b2, pb2, pa2) = add_peer(&mut a);
    let for_b = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let for_b2 = a.book.issue_addr_update(&a.store, &pa2, &set, NOW).unwrap();
    let (b_file, b2_file) = (file_bytes(&b), file_bytes(&b2));
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &for_b2.text(), NOW)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    assert_eq!(
        b2.book
            .apply_addr_update_text(&b2.store, &for_b.text(), NOW)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    assert_eq!(file_bytes(&b), b_file);
    assert_eq!(file_bytes(&b2), b2_file);
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, 0);
    assert_eq!(b2.book.get(&pb2).unwrap().last_addr_seq, 0);
    // свои принимаются
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &for_b.text(), NOW)
            .unwrap(),
        pb
    );
    assert_eq!(
        b2.book
            .apply_addr_update_text(&b2.store, &for_b2.text(), NOW)
            .unwrap(),
        pb2
    );
    // токен совсем постороннего: у него другая пара ключей
    let (mut c, pc, _d, _pd) = duo();
    let alien = c.book.issue_addr_update(&c.store, &pc, &set, NOW).unwrap();
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &alien.text(), NOW)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
}

#[test]
fn apply_text_blocked_friend_rejected() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    b.book.block(&b.store, &pb).unwrap();
    let file = file_bytes(&b);
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &tok.text(), NOW)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    assert_eq!(file_bytes(&b), file);
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, 0);
    b.book.unblock(&b.store, &pb).unwrap();
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &tok.text(), NOW)
            .unwrap(),
        pb
    );
}

#[test]
fn apply_text_modified_byte_rejected() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let text = tok.text();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let file = file_bytes(&b);
    // любая замена любого символа после префикса
    for i in 4..text.len() {
        let mut bytes = text.clone().into_bytes();
        let old = bytes[i];
        bytes[i] = alphabet.iter().copied().find(|c| *c != old).unwrap();
        let bad = String::from_utf8(bytes).unwrap();
        assert_eq!(
            b.book.apply_addr_update_text(&b.store, &bad, NOW).err(),
            Some(FriendsError::BadAddrUpdate),
            "позиция {i}"
        );
    }
    // замена в префиксе
    for bad in ["CHB1", "CHV1", "CHR1", "XHA1"] {
        let t = format!("{bad}{}", &text[4..]);
        assert_eq!(
            b.book.apply_addr_update_text(&b.store, &t, NOW).err(),
            Some(FriendsError::BadAddrUpdate),
            "{bad}"
        );
    }
    assert_eq!(file_bytes(&b), file);
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, 0);
    // положительный контроль: неизменённый токен проходит
    assert!(b.book.apply_addr_update_text(&b.store, &text, NOW).is_ok());
}

#[test]
fn apply_text_bad_length_rejected() {
    let (mut a, pa, mut b, _pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let text = tok.text();
    let file = file_bytes(&b);
    // приглашение вместо обновления адреса
    let k = remote();
    let (_p, invite_text) = issue_invite(
        &InviteDraft {
            issued_at: NOW,
            ttl_secs: 900,
            addrs: vec![sa("8.8.8.8:4000")],
        },
        &k.key,
    )
    .unwrap();
    let cases: Vec<String> = vec![
        String::new(),
        "CHA1".into(),
        "CHA".into(),
        text[..text.len() - 1].to_owned(),
        text[..text.len() / 2].to_owned(),
        format!("{text}A"),
        format!("{text}{text}"),
        "A".repeat(2049),
        format!("CHA1{}", "A".repeat(4000)),
        "ЧА1".into(),
        invite_text,
    ];
    for bad in cases {
        assert_eq!(
            b.book.apply_addr_update_text(&b.store, &bad, NOW).err(),
            Some(FriendsError::BadAddrUpdate),
            "{}",
            bad.len()
        );
    }
    assert_eq!(file_bytes(&b), file);
}

#[test]
fn apply_inband_wrong_pair_rejected() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let (mut b2, pb2, pa2) = add_peer(&mut a);
    let for_b2 = a.book.issue_addr_update(&a.store, &pa2, &set, NOW).unwrap();
    let for_b = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let signed_b2 = decode_addr_update_bin(for_b2.bytes()).unwrap();
    let signed_b = decode_addr_update_bin(for_b.bytes()).unwrap();
    let file = file_bytes(&b);
    // обновление для B2, подсунутое по соединению B
    assert_eq!(
        b.book
            .apply_addr_update(&b.store, &pb, &signed_b2, NOW)
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    assert_eq!(
        b.book
            .apply_addr_update(&b.store, &stranger_pair(), &signed_b, NOW)
            .err(),
        Some(FriendsError::UnknownPair)
    );
    assert_eq!(file_bytes(&b), file);
    // верная пара
    b.book
        .apply_addr_update(&b.store, &pb, &signed_b, NOW)
        .unwrap();
    b2.book
        .apply_addr_update(&b2.store, &pb2, &signed_b2, NOW)
        .unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW), set.socket_addrs());
    // блокированный друг: не Active
    b2.book.block(&b2.store, &pb2).unwrap();
    let newer = a.book.issue_addr_update(&a.store, &pa2, &set, NOW).unwrap();
    let signed_newer = decode_addr_update_bin(newer.bytes()).unwrap();
    assert_eq!(
        b2.book
            .apply_addr_update(&b2.store, &pb2, &signed_newer, NOW + 100)
            .err(),
        Some(FriendsError::NotActive)
    );
}

#[test]
fn apply_inband_rate_limited() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let next = |a: &mut Side| {
        let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
        decode_addr_update_bin(tok.bytes()).unwrap()
    };
    let (u1, u2, u3) = (next(&mut a), next(&mut a), next(&mut a));
    let text = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    b.book.apply_addr_update(&b.store, &pb, &u1, NOW).unwrap();
    // меньше интервала: отказ, номер не принят
    for dt in [0, 1, MIN_INBAND_UPDATE_INTERVAL_SECS - 1] {
        assert_eq!(
            b.book.apply_addr_update(&b.store, &pb, &u2, NOW + dt).err(),
            Some(FriendsError::RateLimited),
            "dt {dt}"
        );
    }
    // устаревший номер сообщается как StaleSeq, а не RateLimited
    assert_eq!(
        b.book.apply_addr_update(&b.store, &pb, &u1, NOW + 1).err(),
        Some(FriendsError::StaleSeq)
    );
    // отказ не сдвигает окно: ровно через интервал от ПРИНЯТОГО
    b.book
        .apply_addr_update(&b.store, &pb, &u2, NOW + MIN_INBAND_UPDATE_INTERVAL_SECS)
        .unwrap();
    assert_eq!(
        b.book
            .apply_addr_update(
                &b.store,
                &pb,
                &u3,
                NOW + MIN_INBAND_UPDATE_INTERVAL_SECS + 1
            )
            .err(),
        Some(FriendsError::RateLimited)
    );
    // часы ушли назад (now < момента принятого): лимит не отключается
    for back in [1, 1000] {
        assert_eq!(
            b.book
                .apply_addr_update(
                    &b.store,
                    &pb,
                    &u3,
                    NOW + MIN_INBAND_UPDATE_INTERVAL_SECS - back
                )
                .err(),
            Some(FriendsError::RateLimited),
            "назад на {back}"
        );
    }
    // через интервал от принятого обновление проходит
    b.book
        .apply_addr_update(
            &b.store,
            &pb,
            &u3,
            NOW + 2 * MIN_INBAND_UPDATE_INTERVAL_SECS,
        )
        .unwrap();
    // токен из буфера обмена окном не ограничен
    b.book
        .apply_addr_update_text(&b.store, &text.text(), NOW - 999)
        .unwrap();
}

/// Копия токена с испорченной подписью (структура верна, подпись не сойдётся).
fn with_bad_signature(bytes: &[u8]) -> chervo_token::SignedAddrUpdate {
    let mut bad = bytes.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    decode_addr_update_bin(&bad).unwrap()
}

#[test]
fn apply_inband_stale_and_rate_limit_checked_before_signature() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let t1 = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let t2 = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let u1 = decode_addr_update_bin(t1.bytes()).unwrap();
    b.book.apply_addr_update(&b.store, &pb, &u1, NOW).unwrap();
    let file = file_bytes(&b);
    // повтор принятого номера с испорченной подписью: StaleSeq, а не BadAddrUpdate
    // (подпись до проверки номера не смотрится)
    assert_eq!(
        b.book
            .apply_addr_update(&b.store, &pb, &with_bad_signature(t1.bytes()), NOW + 1)
            .err(),
        Some(FriendsError::StaleSeq)
    );
    // новый номер внутри интервала с испорченной подписью: RateLimited
    assert_eq!(
        b.book
            .apply_addr_update(&b.store, &pb, &with_bad_signature(t2.bytes()), NOW + 1)
            .err(),
        Some(FriendsError::RateLimited)
    );
    // после интервала испорченная подпись замечена
    assert_eq!(
        b.book
            .apply_addr_update(
                &b.store,
                &pb,
                &with_bad_signature(t2.bytes()),
                NOW + MIN_INBAND_UPDATE_INTERVAL_SECS
            )
            .err(),
        Some(FriendsError::BadAddrUpdate)
    );
    assert_eq!(file_bytes(&b), file, "отказы не пишут файл");
    // отказы не сдвинули окно и не заняли номер: честный токен проходит
    let u2 = decode_addr_update_bin(t2.bytes()).unwrap();
    b.book
        .apply_addr_update(&b.store, &pb, &u2, NOW + MIN_INBAND_UPDATE_INTERVAL_SECS)
        .unwrap();
    assert_eq!(b.book.get(&pb).unwrap().last_addr_seq, t2.seq());
}

#[test]
fn issued_update_carries_its_pair() {
    let (mut a, pa, _b, _pb) = duo();
    let (_c, _pc, pa2) = add_peer(&mut a);
    let set = publish_set("8.8.8.8", 4000);
    let t = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    let t2 = a.book.issue_addr_update(&a.store, &pa2, &set, NOW).unwrap();
    assert_eq!(t.pair(), Some(pa));
    assert_eq!(t2.pair(), Some(pa2));
    // формат не изменился: токен разбирается как обычно
    assert!(decode_addr_update_bin(t.bytes()).is_ok());
}

#[test]
fn inactive_friend_has_no_usable_addrs() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    b.book
        .apply_addr_update_text(&b.store, &tok.text(), NOW)
        .unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW + 1), set.socket_addrs());
    assert_eq!(
        b.book.findability(&pb, false, NOW + 1).unwrap(),
        Findability::Ok
    );
    // заблокирован: пусто, не найдём; адреса в списке целы
    b.book.block(&b.store, &pb).unwrap();
    assert!(b.book.usable_addrs(&pb, NOW + 1).is_empty());
    assert_eq!(
        b.book.findability(&pb, false, NOW + 1).unwrap(),
        Findability::NeedToken
    );
    assert_eq!(
        b.book.findability(&pb, true, NOW + 1).unwrap(),
        Findability::Ok
    );
    assert!(!b.book.get(&pb).unwrap().known_addrs.is_empty());
    // разблокирован: адреса вернулись
    b.book.unblock(&b.store, &pb).unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW + 1), set.socket_addrs());
    assert_eq!(
        b.book.findability(&pb, false, NOW + 1).unwrap(),
        Findability::Ok
    );
    // отозван другом: пусто
    let revoke = a.book.remove(&a.store, &pa, NOW + 2).unwrap().unwrap();
    assert_eq!(
        b.book.apply_revocation(&b.store, &revoke).unwrap(),
        Some(pb)
    );
    assert_eq!(b.book.get(&pb).unwrap().state, FriendState::RevokedByPeer);
    assert!(b.book.usable_addrs(&pb, NOW + 3).is_empty());
    assert_eq!(
        b.book.findability(&pb, false, NOW + 3).unwrap(),
        Findability::NeedToken
    );
    assert!(!b.book.get(&pb).unwrap().known_addrs.is_empty());
}

#[test]
fn apply_save_error_rolls_back() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let t1 = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    b.book
        .apply_addr_update_text(&b.store, &t1.text(), NOW)
        .unwrap();
    let before = b.book.get(&pb).unwrap().clone();
    let set2 = publish_set("1.1.1.1", 4001);
    let t2 = a.book.issue_addr_update(&a.store, &pa, &set2, NOW).unwrap();
    let t3 = a.book.issue_addr_update(&a.store, &pa, &set2, NOW).unwrap();
    let u3 = decode_addr_update_bin(t3.bytes()).unwrap();
    break_file(&b.dir);
    // текстовый путь
    assert_eq!(
        b.book
            .apply_addr_update_text(&b.store, &t2.text(), NOW + 50)
            .err(),
        Some(FriendsError::Io)
    );
    // путь по соединению
    assert_eq!(
        b.book.apply_addr_update(&b.store, &pb, &u3, NOW + 50).err(),
        Some(FriendsError::Io)
    );
    let after = b.book.get(&pb).unwrap();
    assert_eq!(
        after.last_addr_seq, before.last_addr_seq,
        "номер не откатился"
    );
    assert!(
        after.known_addrs == before.known_addrs,
        "адреса не откатились"
    );
    assert_eq!(b.book.usable_addrs(&pb, NOW + 50), set.socket_addrs());
    // файл починен: тот же токен принимается (окно не занято неудачей)
    std::fs::remove_dir(b.dir.file()).unwrap();
    b.book
        .apply_addr_update(&b.store, &pb, &u3, NOW + 51)
        .unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW + 52), set2.socket_addrs());
}

#[test]
fn note_contact_persists_only_on_change() {
    let (_a, _pa, mut b, pb) = duo();
    let c1 = sa("203.0.114.9:5000");
    b.book.note_contact(&b.store, &pb, c1, NOW).unwrap();
    assert_eq!(b.book.usable_addrs(&pb, NOW), vec![c1]);
    let file = file_bytes(&b);
    // без изменения (тот же адрес в пределах часа): файл не переписывается
    b.book.note_contact(&b.store, &pb, c1, NOW + 60).unwrap();
    assert_eq!(file_bytes(&b), file, "лишняя запись на диск");
    // даже если запись сломана, отсутствие изменения не обращается к диску
    break_file(&b.dir);
    b.book.note_contact(&b.store, &pb, c1, NOW + 120).unwrap();
    // изменение при сломанной записи: ошибка и откат
    assert_eq!(
        b.book
            .note_contact(&b.store, &pb, sa("203.0.114.10:5001"), NOW + 130)
            .err(),
        Some(FriendsError::Io)
    );
    assert_eq!(b.book.usable_addrs(&pb, NOW + 130), vec![c1]);
    std::fs::remove_dir(b.dir.file()).unwrap();
    // обновление по сроку: пишет
    let later = NOW + chervo_addr::CONTACT_REFRESH_SECS;
    b.book.note_contact(&b.store, &pb, c1, later).unwrap();
    let reopened = FriendBook::open_unanchored(&b.dir.file(), &b.store).unwrap();
    assert_eq!(
        reopened.get(&pb).unwrap().known_addrs[0].last_seen_unix,
        later
    );
    // неизвестная и блокированная пара
    assert_eq!(
        b.book
            .note_contact(&b.store, &stranger_pair(), c1, NOW)
            .err(),
        Some(FriendsError::UnknownPair)
    );
    b.book.block(&b.store, &pb).unwrap();
    assert_eq!(
        b.book.note_contact(&b.store, &pb, c1, NOW).err(),
        Some(FriendsError::NotActive)
    );
}

#[test]
fn contact_addresses_do_not_overflow_the_list() {
    // 16 адресов из приглашения + контакт: лишнее убирается, файл остаётся записываемым
    let (_a, _pa, mut b, pb) = duo();
    rewrite(&mut b, |d| {
        d.friends[0].known_addrs = (1..=16u16)
            .map(|p| chervo_addr::KnownAddr {
                addr: sa(&format!("8.8.8.8:{}", 1000 + p)),
                source: chervo_addr::AddrSource::Invite,
                last_seen_unix: NOW,
                short_lived: false,
                hint: false,
            })
            .collect();
    });
    b.book
        .note_contact(&b.store, &pb, sa("9.9.9.9:77"), NOW + 1)
        .unwrap();
    let f = b.book.get(&pb).unwrap();
    assert_eq!(f.known_addrs.len(), 16);
    assert!(f.known_addrs.iter().any(|k| k.addr == sa("9.9.9.9:77")));
}

/// U6 v6: чужие адреса другим друзьям не рассылаются. A знает адрес друга F и получил от F
/// наблюдение; набор, подписанный для G, состоит только из собственных адресов A (наблюдение F
/// только как hint), адресов из `known_addrs` F в нём нет.
#[test]
fn observation_not_published_to_others() {
    let (mut a, pa_f, mut f, pf) = duo();
    let (mut g, pg, pa_g) = add_peer(&mut a);
    // F сообщает A свой адрес (попадает в known_addrs друга F у A)
    let f_own = publish_set("5.5.5.5", 5555);
    let from_f = f
        .book
        .issue_addr_update(&f.store, &pf, &f_own, NOW)
        .unwrap();
    a.book
        .apply_addr_update_text(&a.store, &from_f.text(), NOW)
        .unwrap();
    let f_addrs: Vec<SocketAddr> = a.book.usable_addrs(&pa_f, NOW);
    assert_eq!(f_addrs, f_own.socket_addrs());
    // F видит A по адресу 9.9.9.9:6000
    let mut own = OwnAddrs::new();
    own.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some("192.168.1.2".parse().unwrap()),
            v6: None,
        },
        listen: vec![sa("0.0.0.0:4000")],
    });
    assert!(a.book.is_active(&pa_f));
    own.observe(pa_f, sa("1.0.0.1:5000"), sa("9.9.9.9:6000"), NOW);
    let set = own.publishable(PublishCtx::default(), NOW);
    let published: Vec<(SocketAddr, bool)> = set
        .as_slice()
        .iter()
        .map(|u: &UpdateAddr| (u.addr, u.hint))
        .collect();
    assert_eq!(published, vec![(sa("9.9.9.9:6000"), true)]);
    // подписано для G, принято у G
    let for_g = a
        .book
        .issue_addr_update(&a.store, &pa_g, &set, NOW)
        .unwrap();
    g.book
        .apply_addr_update_text(&g.store, &for_g.text(), NOW)
        .unwrap();
    let seen_by_g = g.book.usable_addrs(&pg, NOW);
    assert_eq!(seen_by_g, vec![sa("9.9.9.9:6000")]);
    for fa in &f_addrs {
        assert!(!seen_by_g.contains(fa), "адрес друга F ушёл другу G");
    }
    assert!(g.book.get(&pg).unwrap().known_addrs.iter().all(|k| k.hint));
    // в токене для G ровно набор A
    let signed = decode_addr_update_bin(for_g.bytes()).unwrap();
    let fr = g.book.get(&pg).unwrap();
    let verified = signed.verify(&fr.friend_ed, &fr.our_ed).unwrap();
    let in_token: Vec<SocketAddr> = verified.addrs().iter().map(|u| u.addr).collect();
    assert_eq!(in_token, set.socket_addrs());
}

#[test]
fn usable_known_empty_for_blocked() {
    let (mut a, pa, mut b, pb) = duo();
    let set = publish_set("8.8.8.8", 4000);
    let tok = a.book.issue_addr_update(&a.store, &pa, &set, NOW).unwrap();
    b.book
        .apply_addr_update_text(&b.store, &tok.text(), NOW)
        .unwrap();
    // Active: записи с флагами, адреса и порядок как у `usable_addrs`
    let known = b.book.usable_known(&pb, NOW + 1);
    assert!(!known.is_empty());
    assert_eq!(
        known.iter().map(|k| k.addr).collect::<Vec<_>>(),
        b.book.usable_addrs(&pb, NOW + 1)
    );
    assert!(known.iter().all(|k| k.source == AddrSource::AddressUpdate));
    // неизвестная пара: пусто
    assert!(b.book.usable_known(&stranger_pair(), NOW).is_empty());
    // Blocked: пусто, записи сохранены и после unblock снова видны
    b.book.block(&b.store, &pb).unwrap();
    assert!(b.book.usable_known(&pb, NOW + 1).is_empty());
    assert!(!b.book.get(&pb).unwrap().known_addrs.is_empty());
    b.book.unblock(&b.store, &pb).unwrap();
    assert_eq!(b.book.usable_known(&pb, NOW + 1).len(), known.len());
}
