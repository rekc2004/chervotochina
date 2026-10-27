#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода списка друзей (этап 17, B3, решение 1c; BRIEF 7, T8, T12 L3): `Debug` и
//! `Display` типов списка и всех ошибок не содержат имени друга, адресов, ключей, `PairId`,
//! текста отзыва и секретов хранилища. У записей `Friend`, `NewFriend`, `BookData` нет `Debug`
//! вовсе (и это зафиксировано).

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use chervo_addr::{AddrSource, KnownAddr};
use chervo_friends::{
    AutoAcceptLimits, BookData, Friend, FriendBook, FriendState, FriendsError, NewFriend,
    PendingRole, Permission, Retired, TrustConfirmation,
};
use chervo_identity::SecretStore;
use common::*;
use redact_kit::{Needles, NoDebug, Out, Probe, assert_fixed_text, check};

fn all_errors() -> Vec<FriendsError> {
    use FriendsError::*;
    vec![
        KeyStorageUnavailable,
        ListKeyMissing,
        Corrupt,
        UnsupportedVersion,
        Io,
        LimitExceeded,
        InvalidName,
        InvalidLimits,
        TrustRequired,
        UnknownPair,
        AlreadyExists,
        KeyMissingOrChanged,
        KeyNeedsDecision,
        RandomUnavailable,
        BadRevocation,
        StaleSeq,
        BadAddrUpdate,
        NoAddresses,
        SeqExhausted,
        RateLimited,
        NotActive,
        RolledBack,
        StaleInstance,
    ]
}

const NAME: &str = "FRNDNAME-secret";
const ADDR: &str = "203.0.113.7:4455";

#[test]
fn friends_types_hide_names_addrs_keys_and_revocation() {
    let dir = TestDir::new();
    let store = MemStore::default();
    let mut book = FriendBook::open_unanchored(&dir.file(), &store).unwrap();

    // друг с именем и адресом
    let (pair, key) = book
        .begin_pair(&store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    drop(key);
    let r = remote();
    let mut nf = new_friend(NAME, &r, our_ed, our_x);
    nf.addrs = vec![KnownAddr {
        addr: ADDR.parse().unwrap(),
        source: AddrSource::Invite,
        last_seen_unix: 1234,
        short_lived: false,
        hint: false,
    }];
    book.finish_pair(&store, &pair, nf).unwrap();
    let secret_blob = store.read(&pair).unwrap().unwrap().to_vec();
    let list_key = store.list_key().unwrap();
    book.enable_auto_accept(&store, &pair, TrustConfirmation::user_confirmed_trust())
        .unwrap();

    let mut out = Out::new();
    out.dbg("FriendBook", &book);
    out.dbg("PendingEntry", &book.pending().to_vec());
    out.dbg(
        "friend state/permission",
        &book.get(&pair).map(|f| (f.state, f.permission)),
    );
    out.dbg(
        "Permission",
        &Permission::AutoAccept(AutoAcceptLimits {
            max_total_bytes: 1,
            max_files: 1,
        }),
    );
    out.dbg("PendingRole", &PendingRole::Invitee);
    out.dbg(
        "TrustConfirmation",
        &TrustConfirmation::user_confirmed_trust(),
    );
    out.dbg(
        "kx_peers",
        &book.kx_peers(&store).map(|(p, bad)| (p.len(), bad)),
    );
    out.dbg("epoch", &book.epoch());
    out.dbg("usable_addrs.len", &book.usable_addrs(&pair, 1234).len());

    // удаление: подписанный отзыв хранится в записи
    let revocation = book.remove(&store, &pair, 5000).unwrap().unwrap();
    let retired: Option<Retired> = book.get(&pair).and_then(|f| f.retired.clone());
    out.dbg("Retired", &retired);
    out.dbg("state after remove", &book.get(&pair).map(|f| f.state));
    out.dbg("FriendBook after remove", &book);
    out.dbg(
        "remove(unknown)",
        &book
            .remove(&store, &chervo_identity::PairId::from_bytes([3; 16]), 1)
            .map(|o| o.is_some()),
    );
    out.dbg(
        "rename(unknown)",
        &book.rename(&store, &chervo_identity::PairId::from_bytes([3; 16]), "x"),
    );
    out.dbg("forget_retired", &book.forget_retired(&store, &pair));
    assert_eq!(book.get(&pair).map(|f| f.state), None::<FriendState>);
    for e in all_errors() {
        out.err("FriendsError", &e);
    }

    let mut n = Needles::new();
    n.add("friend name", NAME);
    n.add("addr", ADDR);
    n.add("ip", "203.0.113.7");
    n.bytes("pair", pair.as_bytes());
    n.add("pair account", pair.account_name());
    n.bytes("friend ed", &r.ed.to_bytes());
    n.bytes("friend x", &r.x.to_bytes());
    n.bytes("our ed", &our_ed.to_bytes());
    n.bytes("our x", &our_x.to_bytes());
    n.bytes("pair secret blob", &secret_blob);
    n.bytes("list key", &list_key);
    n.token("revocation text", &revocation);
    check(&out, &n);
}

#[test]
fn friends_records_have_no_debug() {
    assert!(!Probe::<Friend>::new().has_debug());
    assert!(!Probe::<NewFriend>::new().has_debug());
    assert!(!Probe::<BookData>::new().has_debug());
    assert!(Probe::<FriendBook>::new().has_debug());
    assert!(Probe::<Retired>::new().has_debug());
}

#[test]
fn friends_errors_have_fixed_text() {
    for e in all_errors() {
        assert_fixed_text("FriendsError display", &e.to_string());
        assert_fixed_text("FriendsError debug", &format!("{e:?}"));
    }
}
