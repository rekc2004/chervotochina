//! Стенд X02a (этап 17, раунд 1): друг-лжец прислал подписанное обновление адресов, где рядом
//! со своим адресом перечислен адрес жертвы. Жертва в стенде получила 66 пакетов шестью
//! сериями с промежутком 15 с (обещание модели угроз: не больше одной серии в 30 с на адрес).
//!
//! Разбор причины (воспроизведён здесь поддельным транспортом на приостановленном времени):
//! 1. Пока соединение с другом живо, планировщик пару не набирает и `reknock` бьёт только по
//!    живым удалённым адресам транспорта: жертва пакетов не получает (тест `..._connected_...`).
//! 2. Пакеты уходят после обрыва соединения (в стенде `node_stop lw`): набор идёт по всем
//!    адресам книги, а неудача набора в быстром окне (запуск движка, 120 с) даёт ограничителю
//!    `fast_period` = 5 с вместо 30 с; набор длится до 10 с, итого серия раз в 15 с.
//!    Адрес из `AddressUpdate` (слова друга) не должен получать быстрое окно ни в каком режиме.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::AddrSource;
use chervo_identity::PairId;
use chervo_transport::{Connection, TransportError};
use tokio::time::Instant;

use super::kit::*;
use crate::ConnectConfig;
use crate::limiter::Limiter;

const OWN: &str = "11.0.0.50:4433";
const VICTIM: &str = "11.0.0.66:4433";

type Log = Arc<Mutex<Vec<(Instant, Vec<std::net::SocketAddr>)>>>;

/// Узел с одним другом-лжецом: его адреса из обновления, любой набор молчит 10 с и не удаётся.
fn liar_node(entries: Vec<chervo_addr::KnownAddr>) -> (Node, PairId, Log) {
    let mut pre = Pre::new();
    let pair = pre.solo_friend(entries);
    let n = Node::start(pre, ConnectConfig::default());
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    n.t.set_script(move |_, addrs| {
        l.lock().unwrap().push((Instant::now(), addrs.to_vec()));
        Action::Fail(TransportError::TimedOut, secs(10))
    });
    (n, pair, log)
}

fn victim_times(log: &Log) -> Vec<Instant> {
    let v = addr(VICTIM);
    log.lock()
        .unwrap()
        .iter()
        .filter(|(_, a)| a.contains(&v))
        .map(|(t, _)| *t)
        .collect()
}

fn min_gap(times: &[Instant]) -> Option<Duration> {
    times.windows(2).map(|w| w[1].duration_since(w[0])).min()
}

fn update_entries() -> Vec<chervo_addr::KnownAddr> {
    vec![
        known(OWN, AddrSource::AddressUpdate, false),
        known(VICTIM, AddrSource::AddressUpdate, false),
    ]
}

/// Соединение с лжецом живо с первой секунды: ни одного набора, жертва молчит.
#[tokio::test(start_paused = true)]
async fn x02a_connected_friend_is_never_dialled() {
    let (n, pair, log) = liar_node(update_entries());
    n.t.push_incoming(FakeConn::lonely(pair, addr(OWN), false));
    tokio::time::sleep(secs(300)).await;
    assert!(n.engine.connection(&pair).is_some(), "connection is live");
    assert!(log.lock().unwrap().is_empty(), "no dial at all");
    assert_eq!(n.t.reknock_count(), 0);
}

/// Лжец обрывает соединение (как в стенде): серии на жертву не чаще одной в 30 с за все 300 с,
/// включая быстрое окно запуска (в старом коде промежуток 15 с).
#[tokio::test(start_paused = true)]
async fn x02a_victim_bursts_spaced_30s_after_drop() {
    let (n, pair, log) = liar_node(update_entries());
    let conn = FakeConn::lonely(pair, addr(OWN), false);
    n.t.push_incoming(conn.clone());
    tokio::time::sleep(secs(20)).await;
    assert!(log.lock().unwrap().is_empty());
    conn.close();
    tokio::time::sleep(secs(300)).await;
    let times = victim_times(&log);
    assert!(
        times.len() >= 4,
        "the victim is dialled at all: {}",
        times.len()
    );
    let gap = min_gap(&times).unwrap();
    assert!(
        gap >= secs(30),
        "min spacing {gap:?} over {} dials",
        times.len()
    );
}

/// То же для подсказки «так вас видит друг» (X02b): быстрое окно не ускоряет набор.
#[tokio::test(start_paused = true)]
async fn x02a_hint_address_spaced_30s_in_fast_window() {
    let (_n, _pair, log) = liar_node(vec![
        known(OWN, AddrSource::AddressUpdate, false),
        known(VICTIM, AddrSource::ObservedByFriend, true),
    ]);
    tokio::time::sleep(secs(300)).await;
    let times = victim_times(&log);
    assert!(
        times.len() >= 3,
        "the victim is dialled at all: {}",
        times.len()
    );
    let gap = min_gap(&times).unwrap();
    assert!(
        gap >= secs(30),
        "min spacing {gap:?} over {} dials",
        times.len()
    );
}

/// «Соединить сейчас» каждые 3 с (наше событие) не ускоряет набор адреса из обновления.
#[tokio::test(start_paused = true)]
async fn x02a_connect_now_does_not_speed_up_update_addresses() {
    let (n, pair, log) = liar_node(update_entries());
    for _ in 0..100 {
        n.engine.connect_now(&pair).unwrap();
        tokio::time::sleep(secs(3)).await;
    }
    let times = victim_times(&log);
    assert!(
        times.len() >= 4,
        "the victim is dialled at all: {}",
        times.len()
    );
    let gap = min_gap(&times).unwrap();
    assert!(
        gap >= secs(30),
        "min spacing {gap:?} over {} dials",
        times.len()
    );
}

/// Контроль: адреса приглашения и контакта сохраняют быстрое окно (семантика этапа 13).
#[tokio::test(start_paused = true)]
async fn x02a_control_invite_addresses_keep_fast_window() {
    let (n, _pair, log) = liar_node(vec![
        known(OWN, AddrSource::Invite, false),
        known(VICTIM, AddrSource::Invite, false),
    ]);
    tokio::time::sleep(secs(110)).await;
    let times = victim_times(&log);
    let gap = min_gap(&times).unwrap();
    assert!(times.len() >= 5, "fast redials expected: {}", times.len());
    assert!(
        gap < secs(30),
        "invite addresses keep the 5 s fast period, got {gap:?}"
    );
    drop(n);
}

/// Предел устойчив к `reset_pair` (новый номер обновления друга-лжеца) и `reset_all`.
#[tokio::test(start_paused = true)]
async fn x02a_limiter_floor_survives_resets() {
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let v = addr(VICTIM);
    let t0 = Instant::now();
    assert!(l.take(v, true, t0));
    l.failed(&[v], false, true, t0 + secs(10));
    l.reset_pair(&[v], t0 + secs(11));
    l.reset_all(t0 + secs(12));
    assert!(
        !l.allow(v, true, t0 + secs(20)),
        "reset must not lift the floor"
    );
    assert!(!l.allow(v, true, t0 + secs(30)));
    assert!(l.allow(v, true, t0 + secs(33)));
    // не из слов друга: пределом не связан
    assert!(l.allow(v, false, t0 + secs(20)));
}
