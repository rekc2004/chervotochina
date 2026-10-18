//! Смена набора пар рвёт живые соединения (этап 11, решение 11): тройка
//! `(пара, наш X25519, X25519 собеседника)` должна оставаться в наборе.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::Duration;

use chervo_transport::{Transport, TransportError};

use super::kit::*;
use super::misc::alive;
use crate::{PromoteHook, QuinnConfig, QuinnConn, QuinnTransport, TransportEvent};

fn cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        knock_required: true,
        ..test_cfg()
    }
}

/// Две стороны одной пары с живым соединением A -> B.
async fn live() -> (
    Keys,
    Arc<QuinnTransport>,
    Arc<QuinnTransport>,
    QuinnConn,
    QuinnConn,
) {
    let k = Keys::new();
    let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
    let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
    let ca = a.connect(&peer_addr(k.pid, &b)).await.unwrap();
    let cb = b.accept().await.unwrap();
    (k, a, b, ca, cb)
}

async fn wait_dead(c: &QuinnConn) {
    tokio::time::timeout(Duration::from_secs(3), c.conn.closed())
        .await
        .expect("соединение не закрылось");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_removal_closes_live() {
    let (_k, a, _b, ca, cb) = live().await;
    assert!(alive(&ca) && alive(&cb));
    a.set_peers(Vec::new()).unwrap();
    wait_dead(&ca).await;
    wait_dead(&cb).await;
    assert!(!alive(&ca) && !alive(&cb));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_key_change_closes_live() {
    let (k, a, _b, ca, cb) = live().await;
    // тот же PairId, другой ключ собеседника
    let other = Keys::new();
    a.set_peers(vec![k.a.peer(other.b.kx_public)]).unwrap();
    wait_dead(&ca).await;
    wait_dead(&cb).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_unchanged_keeps_live() {
    let (k, a, b, ca, cb) = live().await;
    // свежие `KxPeer` с теми же ключами и новая сторона набора: соединение не трогают
    a.set_peers(vec![k.peer_a(), Keys::new().peer_a()]).unwrap();
    b.set_peers(vec![k.peer_b()]).unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(alive(&ca) && alive(&cb));
    assert_eq!(a.stats().removed_closed, 0);
    assert_eq!(b.stats().removed_closed, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_closed_with_refused_empty_reason() {
    let (_k, a, _b, ca, cb) = live().await;
    a.set_peers(Vec::new()).unwrap();
    // собеседник видит единый отказ: код 0 и пустая причина
    assert_eq!(wait_closed(&cb.conn, Duration::from_secs(3)).await, REFUSED);
    // сторона, закрывшая сама, видит локальное закрытие
    assert!(matches!(
        ca.conn.close_reason(),
        Some(quinn::ConnectionError::LocallyClosed)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_during_kk_refused() {
    let k = Keys::new();
    let a = Arc::new(bind(cfg(), vec![k.peer_a()]));
    let b = Arc::new(bind(cfg(), vec![k.peer_b()]));
    let mk = || PromoteHook {
        reached: Arc::new(tokio::sync::Notify::new()),
        proceed: Arc::new(tokio::sync::Notify::new()),
    };
    let (ha, hb) = (mk(), mk());
    *a.inner.promote_hook.lock().unwrap() = Some(ha.clone());
    *b.inner.promote_hook.lock().unwrap() = Some(hb.clone());
    let addr = peer_addr(k.pid, &b);
    let a2 = a.clone();
    let call = tokio::spawn(async move { a2.connect(&addr).await });
    // KK закончен с обеих сторон; обе стоят перед `promote`
    tokio::time::timeout(Duration::from_secs(5), ha.reached.notified())
        .await
        .expect("звонящий не дошёл до promote");
    tokio::time::timeout(Duration::from_secs(5), hb.reached.notified())
        .await
        .expect("вызываемый не дошёл до promote");
    a.set_peers(Vec::new()).unwrap();
    b.set_peers(Vec::new()).unwrap();
    ha.proceed.notify_one();
    hb.proceed.notify_one();
    let r = call.await.unwrap();
    assert!(
        matches!(r, Err(TransportError::PeerNotAllowed)),
        "звонящий должен получить PeerNotAllowed"
    );
    // у вызываемого соединения в accept нет
    assert!(
        tokio::time::timeout(Duration::from_millis(700), b.accept())
            .await
            .is_err(),
        "вызываемому не должно прийти соединение"
    );
    // ревью 13: прошедший KK, но не допущенный реестром, не считается в `auth_ok`
    for t in [&a, &b] {
        let st = t.stats();
        assert_eq!(st.auth_ok, 0);
        assert_eq!(st.auth_not_admitted, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_peer_cannot_reconnect() {
    let (k, a, b, ca, _cb) = live().await;
    a.set_peers(Vec::new()).unwrap();
    wait_dead(&ca).await;
    // A больше не звонит этой паре
    assert!(matches!(
        a.connect(&peer_addr(k.pid, &b)).await,
        Err(TransportError::UnknownPair)
    ));
    // и не принимает: B стучит и звонит, A молчит и не отдаёт соединение
    let quick = QuinnConfig {
        auth_deadline: Duration::from_millis(1500),
        ..cfg()
    };
    let b2 = bind(quick, vec![k.peer_b()]);
    let r = b2.connect(&peer_addr(k.pid, &a)).await;
    assert!(r.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), a.accept())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_removed_event_and_counter() {
    let (k, a, _b, ca, _cb) = live().await;
    let mut ev = a.events();
    assert_eq!(a.stats().removed_closed, 0);
    a.set_peers(Vec::new()).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(TransportEvent::PeerRemoved { pair }) = ev.recv().await {
                return pair;
            }
        }
    })
    .await
    .expect("нет PeerRemoved");
    assert_eq!(got, k.pid);
    assert_eq!(a.stats().removed_closed, 1);
    wait_dead(&ca).await;
    // повторная замена ничего не закрывает: счётчик не растёт
    a.set_peers(Vec::new()).unwrap();
    assert_eq!(a.stats().removed_closed, 1);
}

/// Ревью этапа 11, п.1: гость и друг с одним `PairId` в одном наборе. Набор отвергается
/// целиком, прежний остаётся; гостевое соединение не записывается как соединение друга и
/// закрывается при удалении гостя.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_dup_pairid_guest_misattributed() {
    let k = Keys::new();
    let g = Keys::new(); // g.b играет роль гостевого секрета
    let guest = || k.a.peer(g.b.kx_public);
    let friend = || k.a.peer(k.b.kx_public);
    let a = Arc::new(bind(cfg(), vec![guest()]));
    // повтор PairId: ошибка в обоих порядках, набор не меняется
    assert_eq!(
        a.set_peers(vec![friend(), guest()]),
        Err(crate::DuplicatePairError)
    );
    assert_eq!(
        a.set_peers(vec![guest(), friend()]),
        Err(crate::DuplicatePairError)
    );
    // держатель токена по-прежнему проходит как гость (прежний набор цел)
    let hpid = chervo_identity::PairId::generate().unwrap();
    let h = Arc::new(bind(cfg(), vec![g.b.peer_as(hpid, k.a.kx_public)]));
    let ch = h.connect(&peer_addr(hpid, &a)).await.unwrap();
    let ca = a.accept().await.unwrap();
    // гость удалён, друг остаётся: соединение держателя токена закрыто, а не живёт как друг
    a.set_peers(vec![friend()]).unwrap();
    wait_dead(&ca).await;
    wait_dead(&ch).await;
    assert!(!alive(&ca));
    assert!(!alive(&ch));
    assert_eq!(a.stats().removed_closed, 1);
}

// ---------------------------------------------------------------------------------------------
// Этап 17, B2: смена набора пар под одним замком
// ---------------------------------------------------------------------------------------------

fn pairs_of(t: &QuinnTransport) -> std::collections::HashSet<chervo_identity::PairId> {
    t.inner.peers_snapshot().iter().map(|p| p.pair()).collect()
}

fn knock_pairs_of(t: &QuinnTransport) -> std::collections::HashSet<chervo_identity::PairId> {
    t.inner.knock.key_pairs().into_iter().collect()
}

/// Верный стук друга `k` (сторона B; приёмник держит A) с адреса `from`; `true`, если это дало допуск (`knock_ok` вырос).
fn knock_admits(t: &QuinnTransport, k: &Keys, from: std::net::SocketAddr) -> bool {
    let before = t.stats().knock_ok;
    let bytes = k.peer_b().knock_keys().unwrap().make(now_window()).unwrap();
    let _ = t.inner.knock.try_knock(from, &bytes);
    t.stats().knock_ok > before
}

/// Детерминированно: первый `set_peers` стоит между ключами стука и реестром, второй (убирает
/// друга) входит в это окно. Со старым кодом (три отдельных замка) второй вызов проходит целиком,
/// потом первый возвращает в реестр удалённого друга, а ключи стука остаются от второго.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_second_call_waits_for_first() {
    use crate::SetPeersHook;
    use std::sync::mpsc;
    let (x, y) = (Keys::new(), Keys::new());
    let t = Arc::new(bind(cfg(), Vec::new()));
    let (reached_tx, reached_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    *t.inner.set_peers_hook.lock().unwrap() = Some(SetPeersHook {
        reached: reached_tx,
        proceed: go_rx,
    });
    let first = {
        let (t, set) = (t.clone(), vec![x.peer_a(), y.peer_a()]);
        std::thread::spawn(move || t.set_peers(set).unwrap())
    };
    reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("первый вызов не дошёл до паузы");
    let (done_tx, done_rx) = mpsc::channel();
    let second = {
        let (t, set) = (t.clone(), vec![y.peer_a()]);
        std::thread::spawn(move || {
            t.set_peers(set).unwrap();
            let _ = done_tx.send(());
        })
    };
    let overtook = done_rx.recv_timeout(Duration::from_millis(500)).is_ok();
    go_tx.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    assert!(
        !overtook,
        "второй set_peers прошёл целиком, пока первый стоял между структурами"
    );
    let want: std::collections::HashSet<_> = [y.pid].into_iter().collect();
    assert_eq!(pairs_of(&t), want, "реестр после двух вызовов");
    assert_eq!(knock_pairs_of(&t), want, "ключи стука после двух вызовов");
    // вернувшийся вторым вызов убрал друга `x`: ни реестра, ни допуска по стуку
    let from = "127.0.0.1:40000".parse().unwrap();
    assert!(!knock_admits(&t, &x, from), "удалённый друг прошёл стук");
    assert!(knock_admits(&t, &y, from), "оставшийся друг не прошёл стук");
}

/// 4 потока по 1000 чередований наборов A и B; в конце ключи стука и реестр описывают один и
/// тот же набор, а пара вне него не получает допуска.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_peers_concurrent_consistent() {
    let ks: Vec<Keys> = (0..4).map(|_| Keys::new()).collect();
    // A = {0,1,2}, B = {1,2,3}: пары 0 и 3 появляются и исчезают
    let set_a = |ks: &[Keys]| vec![ks[0].peer_a(), ks[1].peer_a(), ks[2].peer_a()];
    let set_b = |ks: &[Keys]| vec![ks[1].peer_a(), ks[2].peer_a(), ks[3].peer_a()];
    let t = Arc::new(bind(cfg(), Vec::new()));
    let ks = Arc::new(ks);
    let threads: Vec<_> = (0..4)
        .map(|n| {
            let (t, ks) = (t.clone(), ks.clone());
            std::thread::spawn(move || {
                for i in 0..1000 {
                    let set = if (i + n) % 2 == 0 {
                        set_a(&ks)
                    } else {
                        set_b(&ks)
                    };
                    t.set_peers(set).unwrap();
                }
            })
        })
        .collect();
    for th in threads {
        th.join().unwrap();
    }
    let reg = pairs_of(&t);
    assert_eq!(reg, knock_pairs_of(&t), "ключи стука и реестр расходятся");
    let a: std::collections::HashSet<_> = [0, 1, 2].iter().map(|i| ks[*i].pid).collect();
    let b: std::collections::HashSet<_> = [1, 2, 3].iter().map(|i| ks[*i].pid).collect();
    assert!(reg == a || reg == b, "итоговый набор не равен ни A, ни B");
    let from = "127.0.0.1:40000".parse().unwrap();
    for k in ks.iter() {
        assert_eq!(
            knock_admits(&t, k, from),
            reg.contains(&k.pid),
            "допуск по стуку не совпадает с итоговым набором"
        );
    }
}
