#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода токенов, SAS и сессий приглашения (этап 17, B3, решение 1c; BRIEF 7, T8):
//! `Debug` и `Display` ничего из этого не печатают: текст приглашения, отзыва и обновления
//! адреса, цифры и байты SAS, ключи, `PairId`, адреса токена. Все ошибки имеют фиксированный
//! текст. У типов, разобранных из токена, `Debug` нет вовсе (и это зафиксировано).

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use chervo_addr::{LocalSnapshot, OwnAddrs, PublishCtx, RouteSources};
use chervo_token::{
    AddrFlowError, FlowError, InviteError, InviteToken, InviteeKeys, InviteeSession, PendingInvite,
    RevocationNotice, RevocationReason, Sas, Token, TokenError, decode, decode_addr_update_bin,
    issue_addr_update, issue_revocation,
};
use common::*;
use redact_kit::{Needles, NoDebug, Out, Probe, assert_fixed_text, check};

fn token_errors() -> Vec<TokenError> {
    use TokenError::*;
    vec![
        TooLong,
        BadEncoding,
        BadPrefix,
        UnsupportedVersion,
        BadKind,
        Malformed,
        BadAddress,
        BadTtl,
        BadKey,
        BadSignature,
        Expired,
        NotYetValid,
        RandomUnavailable,
        SigningFailed,
    ]
}

fn invite_errors() -> Vec<InviteError> {
    use InviteError::*;
    vec![
        Malformed,
        WrongToken,
        BadKey,
        BadSignature,
        CommitMismatch,
        Expired,
        TooManySessions,
        Used,
        NoSession,
        RandomUnavailable,
        SigningFailed,
    ]
}

#[test]
fn token_types_hide_texts_keys_and_sas() {
    let h = honest();
    let a_pub = h.a_key.public_key();
    let a_x = h.a_key.kx_public();
    let b_pub = h.b_key.public_key();
    let b_x = h.b_key.kx_public();

    // M1/M2 и SAS
    let mut pending = h.pending;
    pending.begin_session(1_000_100).unwrap();
    let (m2, sas_a, keys) = pending.on_m1(&h.m1, 1_000_100).unwrap();
    let sas_b = h.session.on_m2(&m2).unwrap();
    assert_eq!(sas_a, sas_b);

    // отзыв и обновление адреса
    let revocation = issue_revocation(&h.a_key, RevocationReason::Removed, 1_000_000).unwrap();
    let notice: RevocationNotice = match decode(&revocation).unwrap() {
        Token::Revocation(n) => n,
        _ => panic!("не отзыв"),
    };
    let mut own = OwnAddrs::new();
    own.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some("8.8.4.4".parse().unwrap()),
            v6: None,
        },
        listen: vec!["0.0.0.0:4000".parse().unwrap()],
    });
    let set = own.publishable(PublishCtx::default(), 1_000_000);
    let issued = issue_addr_update(&h.a_key, &b_pub, 7, &set).unwrap();
    let update_text = issued.text();
    let signed = match decode(&update_text).unwrap() {
        Token::AddrUpdate(s) => s,
        _ => panic!("не обновление адреса"),
    };
    let verified = signed.verify(&a_pub, &b_pub).unwrap();
    let bin = decode_addr_update_bin(issued.bytes()).unwrap();

    let mut n_extra = Needles::new();
    let mut out = Out::new();
    out.dbg("Sas", &sas_a);
    out.dbg("PendingInvite", &pending);
    out.dbg("InviteeKeys", &keys);
    let h2 = honest();
    out.dbg("InviteeSession", &h2.session);
    out.dbg("PendingInvite (fresh)", &h2.pending);
    n_extra.token("second invite text", &h2.text);
    out.dbg("RevocationNotice", &notice);
    out.dbg("RevocationReason", &notice.reason);
    out.dbg("SignedAddrUpdate", &signed);
    out.dbg("SignedAddrUpdate(bin)", &bin);
    out.dbg("AddrUpdate", &verified);
    out.dbg("IssuedAddrUpdate", &issued);
    out.dbg("verify result", &signed.verify(&b_pub, &a_pub).map(|_| ()));
    out.dbg("decode(garbage)", &decode("CHV1garbage").map(|_| ()));
    out.dbg("decode(invite).is_ok", &decode(&h.text).is_ok());
    for e in token_errors() {
        out.err("TokenError", &e);
    }
    for e in invite_errors() {
        out.err("InviteError", &e);
    }

    let mut n = Needles::new();
    n.token("invite text", &h.text);
    n.token("revocation text", &revocation);
    n.token("addr update text", &update_text);
    n.bytes("addr update bytes", issued.bytes());
    n.add("sas digits", sas_a.digits());
    n.add("sas digits compact", sas_a.digits().replace(' ', ""));
    n.bytes("sas raw", sas_a.as_bytes());
    n.bytes("ed A", &a_pub.to_bytes());
    n.bytes("x A", &a_x.to_bytes());
    n.bytes("ed B", &b_pub.to_bytes());
    n.bytes("x B", &b_x.to_bytes());
    n.bytes("m1", &h.m1);
    n.bytes("m2", &m2);
    n.add("addr ip in invite", "203.0.113.7");
    n.add("addr ip in update", "8.8.4.4");
    n.add("addr in invite", "203.0.113.7:4455");
    n.add("addr in update", "8.8.4.4:4000");
    n.0.extend(n_extra.0);
    check(&out, &n);
}

/// Типы, разобранные из токена, без `Debug`: ни адреса, ни ключи не попадут в `{:?}` по ошибке.
/// Если появится `Debug`, тест упадёт, и его придётся проверить выше.
#[test]
fn token_parsed_types_have_no_debug() {
    assert!(!Probe::<Token>::new().has_debug());
    assert!(!Probe::<InviteToken>::new().has_debug());
    assert!(!Probe::<chervo_token::InviteDraft>::new().has_debug());
    assert!(Probe::<chervo_token::addr_flow::PeerAddrInfo>::new().has_debug());
    // типы с `Debug` без содержимого
    assert!(Probe::<Sas>::new().has_debug());
    assert!(Probe::<PendingInvite>::new().has_debug());
    assert!(Probe::<InviteeKeys>::new().has_debug());
    assert!(Probe::<InviteeSession>::new().has_debug());
}

#[test]
fn token_errors_have_fixed_text() {
    for e in token_errors() {
        assert_fixed_text("TokenError display", &e.to_string());
        assert_fixed_text("TokenError debug", &format!("{e:?}"));
    }
    for e in invite_errors() {
        assert_fixed_text("InviteError display", &e.to_string());
        assert_fixed_text("InviteError debug", &format!("{e:?}"));
    }
    use AddrFlowError as A;
    for e in [A::Truncated, A::Malformed, A::TrailingData, A::WrongPeer] {
        assert_fixed_text("AddrFlowError display", &e.to_string());
        assert_fixed_text("AddrFlowError debug", &format!("{e:?}"));
    }
    let e = FlowError::Truncated;
    assert_fixed_text("FlowError display", &e.to_string());
    assert_fixed_text("FlowError debug", &format!("{e:?}"));
}
