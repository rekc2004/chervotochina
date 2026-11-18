#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Единая точка для текста от друга (`Node::apply_friend_text`, этап 18б, В2 и В3): два
//! настоящих узла по петле. Приглашение, новый адрес и уведомление об удалении попадают каждое в
//! свой существующий путь; мусор, слишком длинный текст и чужой вид дают ошибку без паники, а
//! текст ошибки не повторяет вставленное. Запуск: `--test-threads=1`.

#[path = "support/harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use chervo_core::texts::{BAD_TOKEN_TEXT, INPUT_TOO_LONG_TEXT, NOT_FROM_US_TEXT};
use chervo_core::{
    FriendRef, FriendStatus, FriendText, InviteOutcome, InviteRef, Node, NodeError, NodeEvent,
};
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

fn sas_of(s: &mut Side, inv: InviteRef) -> String {
    s.w.wait(LONG, |e| match e {
        NodeEvent::InviteSas { invite, sas } if *invite == inv => Some(sas.digits()),
        _ => None,
    })
    .expect("проверочный код не пришёл")
}

/// Дружба, где приглашение вставлено через `apply_friend_text` (с пробелами и переводами строк
/// по краям, как из мессенджера).
fn befriend_by_text(a: &mut Side, b: &mut Side) -> (FriendRef, FriendRef) {
    let (inv_a, token) = a
        .node
        .create_invite(false, Some(lo(a.rig.port)))
        .expect("create_invite");
    let padded = format!("  \r\n{}\n  ", token.as_str());
    let inv_b = match b.node.apply_friend_text(&padded).expect("приглашение") {
        FriendText::InviteAccepted { invite } => invite,
        other => panic!("ожидалось приглашение, получено {other:?}"),
    };
    // обязательная сверка кода остаётся: без «совпадает» друга нет
    assert!(b.node.friends().is_empty());
    let da = sas_of(a, inv_a);
    let db = sas_of(b, inv_b);
    assert_eq!(da, db, "коды не совпали");
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

#[test]
fn one_entry_point_for_invite_address_and_revocation_text() {
    let mut a = start("ftA");
    let mut b = start("ftB");

    // --- приглашение: вид определён по тексту, сверка кода обязательна
    let (fb_on_a, fa_on_b) = befriend_by_text(&mut a, &mut b);
    assert_eq!(b.node.friends().len(), 1);

    // --- мусор, чужой вид, слишком длинный текст: ошибка, без паники, без повтора ввода
    let secret_like = "ЦЕЛЫЙ-СЕКРЕТНЫЙ-ТЕКСТ-123";
    for junk in [
        "",
        "   ",
        "привет, это не токен",
        "hello world",
        "CHV",
        "CHV1",
        "CHV1!!!!",
        "CHX1ABCDEFGH",
        secret_like,
    ] {
        let err = b.node.apply_friend_text(junk).expect_err(junk);
        let shown = format!("{err} {err:?} {}", err.user_text());
        assert!(!shown.contains(secret_like), "{shown}");
        assert!(
            err.user_text() == NOT_FROM_US_TEXT || err.user_text() == BAD_TOKEN_TEXT,
            "{junk:?}: {}",
            err.user_text()
        );
    }
    // нераспознанное: ровно предписанная фраза
    let err = b.node.apply_friend_text("hello world").unwrap_err();
    assert_eq!(err.user_text(), NOT_FROM_US_TEXT);
    assert_eq!(
        NOT_FROM_US_TEXT,
        "Это не похоже на текст из Червоточины. Попросите друга скопировать его целиком кнопкой «Копировать»."
    );
    // с правильным началом, но не текст программы: повреждён, а не «чужой»
    let err = b.node.apply_friend_text("CHV1AAAA").unwrap_err();
    assert_eq!(err.user_text(), BAD_TOKEN_TEXT);

    // слишком длинный: до разбора (предел узла 4096) и по пределу `chervo-token` (2048)
    let too_long = "A".repeat(4097);
    let err = b.node.apply_friend_text(&too_long).unwrap_err();
    assert_eq!(err, NodeError::InputTooLong);
    assert_eq!(err.user_text(), INPUT_TOO_LONG_TEXT);
    let long_invite_like = format!("CHV1{}", "A".repeat(3000));
    assert_eq!(
        b.node.apply_friend_text(&long_invite_like).unwrap_err(),
        NodeError::InputTooLong
    );
    // мусор ничего не изменил
    assert_eq!(b.node.friends().len(), 1);
    assert_eq!(b.node.friends()[0].state, FriendStatus::Active);

    // --- приглашение после уже добавленного друга: снова приглашение, друг не прибавляется до
    // сверки кода; отмена возвращает всё как было
    let (inv_a2, token2) = a
        .node
        .create_invite(false, Some(lo(a.rig.port)))
        .expect("второе приглашение");
    match b.node.apply_friend_text(token2.as_str()) {
        Ok(FriendText::InviteAccepted { invite }) => {
            assert_eq!(b.node.friends().len(), 1, "до сверки друзей не прибавилось");
            let _ = b.node.cancel_invite(invite);
        }
        other => panic!("ожидалось приглашение, получено {other:?}"),
    }
    let _ = a.node.cancel_invite(inv_a2);
    assert_eq!(b.node.friends().len(), 1);
    assert_eq!(a.node.friends().len(), 1);

    // --- новый адрес: идёт в `apply_addr_update_text`
    // «Мы в одной сети» добавляет адреса домашней сети узла; без них выпустить текст нельзя. Тогда
    // тест явно падает (а не пропускает проверку): нужна машина хотя бы с одним частным адресом.
    let text = a
        .node
        .issue_addr_update_text(fb_on_a, true)
        .expect("у узла A нет ни одного адреса для нового адреса: нужен адрес локальной сети");
    match b.node.apply_friend_text(text.as_str()) {
        Ok(FriendText::AddressUpdated { friend }) => assert_eq!(friend, fa_on_b),
        other => panic!("ожидался новый адрес, получено {other:?}"),
    }

    // --- уведомление об удалении: идёт в `apply_revocation_text`
    let rev = a.node.rekey(fb_on_a).unwrap();
    assert_eq!(
        b.node.apply_friend_text(rev.as_str()).unwrap(),
        FriendText::Revoked {
            friend: Some(fa_on_b)
        }
    );
    assert_eq!(b.node.friends()[0].state, FriendStatus::RevokedByPeer);
    // повтор безвреден: подлинный, но уже никому не подходит
    assert_eq!(
        b.node.apply_friend_text(rev.as_str()).unwrap(),
        FriendText::Revoked { friend: None }
    );

    a.node.shutdown(Duration::from_secs(5));
    b.node.shutdown(Duration::from_secs(5));
}
