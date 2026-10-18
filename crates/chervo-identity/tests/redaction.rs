#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода типов ключей (этап 17, B3, решение 1c; BRIEF 7, T12 L3): `Debug` и `Display`
//! каждого типа, где есть ключи или `PairId`, не содержат ни байтов ключей (hex, base64, base32,
//! десятичный список, окна), ни `PairId`, ни секретных записей хранилища. Тексты ошибок
//! фиксированные.

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use chervo_identity::{
    BINDING_LEN, ChannelBinding, GuestSecret, IdentityError, KxPeer, PairId, create, kk_initiate,
    kk_respond, load,
};
use common::MemStore;
use redact_kit::{Needles, Out, Probe, assert_fixed_text, check};

fn all_errors() -> Vec<IdentityError> {
    use IdentityError::*;
    vec![
        NotImplemented,
        StorageUnavailable,
        StorageLocked,
        StorageInconsistent,
        KeyMissing,
        KeyAlreadyExists,
        KeyMismatch,
        CorruptKey,
        UnsupportedKeyVersion,
        RandomUnavailable,
        InvalidPublicKey,
        BadSignature,
        SigningFailed,
        InvalidKxPublicKey,
        AuthFailed,
        InvalidGuestSecret,
    ]
}

#[test]
fn identity_types_hide_keys_and_pair_id() {
    // две стороны одной пары
    let (store_a, store_b) = (MemStore::new(), MemStore::new());
    let pair = PairId::generate().unwrap();
    let key_a = create(&store_a, &pair).unwrap();
    let key_b = create(&store_b, &pair).unwrap();
    let (ed_a, x_a) = (key_a.public_key(), key_a.kx_public());
    let (ed_b, x_b) = (key_b.public_key(), key_b.kx_public());
    let blob_a = store_a.raw(&pair).unwrap();
    let blob_b = store_b.raw(&pair).unwrap();

    let loaded_a = load(&store_a, &pair, &ed_a).unwrap();
    let loaded_b = load(&store_b, &pair, &ed_b).unwrap();
    let kx_a = loaded_a.into_kx();
    let kx_b = loaded_b.into_kx();
    let kx_a_public = kx_a.public();
    let peer_a = KxPeer::new(pair, kx_a, x_b);
    let peer_b = KxPeer::new(pair, kx_b, x_a);
    let knock = peer_a.knock_keys().unwrap();
    let guest = GuestSecret::generate().unwrap();
    let guest_bytes = guest.to_token_bytes();
    let guest_public = guest.public();
    let binding_bytes = [0x6Bu8; BINDING_LEN];
    let binding = ChannelBinding::from_bytes(binding_bytes);
    let (init, msg1) = kk_initiate(&peer_a, &binding).unwrap();
    let (resp, msg2) = kk_respond(&[&peer_b], &binding, &msg1).unwrap();

    let mut out = Out::new();
    out.dbg("PairId", &pair);
    out.dbg("PublicKey", &ed_a);
    out.dbg("KxPublicKey", &x_a);
    out.dbg("PairKey", &key_a);
    out.dbg("PairKx.public", &kx_a_public);
    out.dbg("KxPeer", &peer_a);
    out.dbg("KnockKeys", &knock);
    out.dbg("GuestSecret", &guest);
    out.dbg("GuestSecret.public", &guest_public);
    out.dbg("ChannelBinding", &binding);
    out.dbg("KkInitiator", &init);
    out.dbg("KkResponder", &resp);
    out.dbg("kk_initiate result", &Ok::<_, IdentityError>(msg1.len()));
    // результаты, которые оболочка могла бы напечатать целиком
    out.dbg("create twice", &create(&store_a, &pair).map(|_| ()));
    out.dbg("load wrong key", &load(&store_a, &pair, &ed_b).map(|_| ()));
    out.dbg(
        "verify",
        &ed_a.verify(chervo_identity::SignDomain::InviteAccept, b"m", &[0u8; 64]),
    );
    for e in all_errors() {
        out.err("IdentityError", &e);
    }
    let finish = init.finish(&msg2).unwrap();
    out.dbg("KkResponder.finish", &resp.finish(&finish));

    let mut n = Needles::new();
    n.bytes("pair", pair.as_bytes());
    n.add("pair account", pair.account_name());
    n.bytes("ed A", &ed_a.to_bytes());
    n.bytes("x A", &x_a.to_bytes());
    n.bytes("ed B", &ed_b.to_bytes());
    n.bytes("x B", &x_b.to_bytes());
    n.bytes("secret blob A", &blob_a);
    n.bytes("secret blob B", &blob_b);
    n.bytes("guest secret", &guest_bytes[..]);
    n.bytes("guest public", &guest_public.to_bytes());
    n.bytes("binding", &binding_bytes);
    n.bytes("msg1", &msg1);
    n.bytes("msg2", &msg2);
    check(&out, &n);
}

#[test]
fn identity_errors_have_fixed_text() {
    for e in all_errors() {
        assert_fixed_text("IdentityError display", &e.to_string());
        assert_fixed_text("IdentityError debug", &format!("{e:?}"));
    }
}

/// Типы с секретами не получают `Debug` молча: если он появится, его надо проверить выше.
#[test]
fn identity_secret_types_debug_is_known() {
    // у этих типов `Debug` есть и проверен в тесте выше
    assert!(Probe::<PairId>::new().has_debug());
    assert!(Probe::<chervo_identity::PairKey>::new().has_debug());
    assert!(Probe::<KxPeer>::new().has_debug());
    assert!(Probe::<GuestSecret>::new().has_debug());
}
