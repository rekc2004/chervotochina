//! Публикация набора пар и разрешений; пары, переставшие быть `Active`.

use chervo_addr::NatView;
use chervo_friends::KeyStatus;
use chervo_identity::SecretStore;
use chervo_transport::{PeerFilter, TransportError};

use super::kit::*;
use crate::{ConnectConfig, ConnectError, EngineEvent};

#[tokio::test(start_paused = true)]
async fn publish_after_every_book_change() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    assert_eq!(n.t.peers_call_count(), 1);
    assert_eq!(n.t.last_peers(), vec![x]);

    n.engine
        .update_book(|b, s| b.rename(s, &x, "Другой"))
        .unwrap();
    assert_eq!(n.t.peers_call_count(), 2);

    let y = n
        .engine
        .update_book(|b, s| add_solo_friend(b, s, vec![inv("6.6.6.6:4000")]))
        .unwrap();
    assert_eq!(n.t.peers_call_count(), 3);
    let mut peers = n.t.last_peers();
    peers.sort_by_key(|p| *p.as_bytes());
    let mut want = vec![x, y];
    want.sort_by_key(|p| *p.as_bytes());
    assert_eq!(peers, want);
    assert!(n.allow.is_allowed(&x) && n.allow.is_allowed(&y));

    n.engine.update_book(|b, s| b.block(s, &x)).unwrap();
    assert_eq!(n.t.peers_call_count(), 4);
    assert_eq!(n.t.last_peers(), vec![y]);
    assert!(!n.allow.is_allowed(&x));

    n.engine
        .update_book(|b, s| b.remove(s, &y, BASE_UNIX).map(|_| ()))
        .unwrap();
    assert_eq!(n.t.peers_call_count(), 5);
    assert!(n.t.last_peers().is_empty());

    // ошибка в `f`: публикация всё равно выполняется, ошибка возвращается
    let err = n
        .engine
        .update_book(|b, s| b.rename(s, &x, ""))
        .unwrap_err();
    assert!(matches!(err, ConnectError::Friends(_)));
    assert_eq!(n.t.peers_call_count(), 6);
}

#[tokio::test(start_paused = true)]
async fn publish_duplicate_error_keeps_old_allowset() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    let mut n = Node::start(pre, ConnectConfig::default());
    assert!(n.allow.is_allowed(&x));
    let calls = n.t.peers_call_count();
    n.t.dup_error
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let res = n
        .engine
        .update_book(|b, s| add_solo_friend(b, s, vec![inv("6.6.6.6:4000")]));
    assert_eq!(res.unwrap_err(), ConnectError::Internal);
    assert!(drain(&mut n.events).await.contains(&EngineEvent::Internal));
    // разрешения прежние: новая пара не допущена, старая допущена; транспорт не менялся
    assert!(n.allow.is_allowed(&x));
    let new_pair = n.engine.read_book(|b| {
        b.friends()
            .iter()
            .map(|f| f.pair)
            .find(|p| *p != x)
            .unwrap()
    });
    assert!(!n.allow.is_allowed(&new_pair));
    assert_eq!(n.t.peers_call_count(), calls);
    // ошибка прошла: следующая публикация подхватывает книгу
    n.t.dup_error
        .store(false, std::sync::atomic::Ordering::SeqCst);
    n.engine.update_book(|_, _| Ok(())).unwrap();
    assert!(n.allow.is_allowed(&new_pair));
    assert_eq!(n.t.last_peers().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn forget_reporter_on_block_and_remove() {
    let cfg = ConnectConfig {
        manual_forward: Some(4000),
        ..ConnectConfig::default()
    };
    // блокировка
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let y = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    let n = Node::start(pre, cfg.clone());
    apply_obs(&n, x, "5.6.7.1:4000", "9.9.9.9:4000");
    apply_obs(&n, y, "5.6.7.2:4000", "9.9.9.9:4000");
    assert_eq!(n.engine.nat_view(), NatView::ManualForward);
    n.engine.update_book(|b, s| b.block(s, &x)).unwrap();
    assert_eq!(
        n.engine.nat_view(),
        NatView::ManualForward,
        "Y still reports"
    );
    n.engine.update_book(|b, s| b.block(s, &y)).unwrap();
    assert_ne!(n.engine.nat_view(), NatView::ManualForward);
    // после разблокировки старое наблюдение не возвращается
    n.engine.update_book(|b, s| b.unblock(s, &x)).unwrap();
    assert_ne!(n.engine.nat_view(), NatView::ManualForward);

    // удаление
    let mut pre = Pre::new();
    let z = pre.solo_friend(vec![inv("5.6.7.3:4000")]);
    let n = Node::start(pre, cfg);
    apply_obs(&n, z, "5.6.7.3:4000", "9.9.9.9:4000");
    assert_eq!(n.engine.nat_view(), NatView::ManualForward);
    n.engine
        .update_book(|b, s| b.remove(s, &z, BASE_UNIX).map(|_| ()))
        .unwrap();
    assert_ne!(n.engine.nat_view(), NatView::ManualForward);
}

#[tokio::test(start_paused = true)]
async fn key_problem_reported_key_not_created() {
    let mut pre = Pre::new();
    let x = pre.solo_friend(vec![inv("5.6.7.8:4000")]);
    pre.store.delete(&x).unwrap();
    assert_eq!(pre.store.pair_count(), 0);
    let mut n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let e = wait_event(&mut n.events, secs(1), |e| {
        matches!(e, EngineEvent::KeyProblem { .. })
    })
    .await
    .unwrap();
    assert_eq!(
        e,
        EngineEvent::KeyProblem {
            pair: x,
            status: KeyStatus::MissingOrChanged
        }
    );
    // ключ не создан, в набор пары его нет, на него не звонят
    assert_eq!(n.store.pair_count(), 0);
    assert!(n.t.last_peers().is_empty());
    tokio::time::sleep(secs(60)).await;
    assert!(n.t.calls_for(&x).is_empty());
    // повторная публикация то же событие не повторяет
    n.engine.update_book(|_, _| Ok(())).unwrap();
    assert!(
        !drain(&mut n.events)
            .await
            .iter()
            .any(|e| matches!(e, EngineEvent::KeyProblem { .. }))
    );
}
