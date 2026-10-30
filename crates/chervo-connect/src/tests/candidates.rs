//! Выбор пути: порядок и допустимость кандидатов.

use std::collections::HashSet;
use std::net::SocketAddr;

use chervo_addr::{AddrSource, usable_entries};
use chervo_transport::TransportError;

use super::kit::*;
use crate::ConnectConfig;
use crate::plan::{Families, families, friend_plan, guest_plan, only_unusable_v6};

fn v4_only() -> Families<'static> {
    families(&[addr("0.0.0.0:4000")], None, &ROUTE_GLOBAL)
}

/// Двойное гнездо и собственный глобальный маршрут IPv6 (выход есть).
fn dual_egress() -> Families<'static> {
    families(
        &[addr("0.0.0.0:4000"), addr("[::]:4000")],
        Some("2a00:1450::5".parse().unwrap()),
        &ROUTE_GLOBAL,
    )
}

#[test]
fn candidates_lan_first_then_book_order() {
    let stored = vec![
        known("203.0.113.9:1000", AddrSource::Contact, false),
        known("5.6.7.8:1000", AddrSource::AddressUpdate, false),
        known("192.168.1.7:1000", AddrSource::Contact, false),
        known("127.0.0.1:1000", AddrSource::Invite, false),
        known("4.4.4.4:1000", AddrSource::AddressUpdate, true),
        known("10.0.0.3:1000", AddrSource::AddressUpdate, true),
    ];
    let book_order = usable_entries(&stored, BASE_UNIX);
    let plan = friend_plan(&book_order, &v4_only());
    let got: Vec<SocketAddr> = plan.cands.iter().map(|c| c.addr).collect();
    let want: Vec<SocketAddr> = [
        "127.0.0.1:1000",
        "192.168.1.7:1000",
        "10.0.0.3:1000",
        "5.6.7.8:1000",
        "203.0.113.9:1000",
        "4.4.4.4:1000",
    ]
    .iter()
    .map(|s| addr(s))
    .collect();
    assert_eq!(got, want);
    let hints: Vec<bool> = plan.cands.iter().map(|c| c.hint).collect();
    assert_eq!(hints, [false, false, true, false, false, true]);
}

#[test]
fn candidates_skip_ipv6_on_v4_transport() {
    let mixed = vec![
        known("[2001:4860::1]:1000", AddrSource::Invite, false),
        known("5.6.7.8:1000", AddrSource::Invite, false),
        known("[::ffff:5.6.7.8]:1000", AddrSource::Contact, false),
    ];
    let plan = friend_plan(&usable_entries(&mixed, BASE_UNIX), &v4_only());
    assert_eq!(plan.cands.len(), 1);
    assert_eq!(plan.cands[0].addr, addr("5.6.7.8:1000"));
    assert!(!only_unusable_v6(&mixed, &v4_only()));

    let v6 = vec![known("[2001:4860::1]:1000", AddrSource::Invite, false)];
    assert!(friend_plan(&v6, &v4_only()).cands.is_empty());
    assert!(only_unusable_v6(&v6, &v4_only()));
    // транспорт с IPv6 те же записи принимает
    let dual = dual_egress();
    assert_eq!(friend_plan(&v6, &dual).cands.len(), 1);
    assert!(!only_unusable_v6(&v6, &dual));
    // порт 0 и неуказанный адрес не набираются
    let junk = vec![
        known("5.6.7.8:0", AddrSource::Invite, false),
        known("0.0.0.0:5", AddrSource::Invite, false),
        known("224.0.0.1:5", AddrSource::Invite, false),
    ];
    assert!(friend_plan(&junk, &v4_only()).cands.is_empty());
}

#[tokio::test(start_paused = true)]
async fn candidates_only_active() {
    let mut pre = Pre::new();
    let px = pre.solo_friend(vec![inv("5.6.7.1:4000")]);
    let py = pre.solo_friend(vec![inv("5.6.7.2:4000")]);
    pre.book.block(&*pre.store, &py).unwrap();
    assert!(pre.book.usable_known(&py, BASE_UNIX).is_empty());
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    tokio::time::sleep(secs(60)).await;
    assert!(!n.t.calls_for(&px).is_empty());
    assert!(n.t.calls_for(&py).is_empty());
    assert_eq!(n.t.last_peers(), vec![px]);
    // после разблокировки пара снова набирается
    n.engine.update_book(|b, s| b.unblock(s, &py)).unwrap();
    tokio::time::sleep(secs(60)).await;
    assert!(!n.t.calls_for(&py).is_empty());
}

#[tokio::test(start_paused = true)]
async fn candidates_guest_only_token_addrs() {
    let token = vec![addr("5.5.5.5:1111"), addr("6.6.6.6:2222")];
    let plan = guest_plan(&token, &v4_only());
    let got: Vec<SocketAddr> = plan.cands.iter().map(|c| c.addr).collect();
    assert_eq!(got, token);
    assert!(plan.cands.iter().all(|c| !c.hint));

    let mut pre = Pre::new();
    let friend = pre.solo_friend(vec![inv("9.9.9.9:4000")]);
    let n = Node::start(pre, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TransportError::TimedOut, secs(0)));
    let guest = chervo_identity::PairId::from_bytes([0x77; 16]);
    n.engine
        .add_guest(guest, token.clone(), Box::new(|| None))
        .unwrap();
    tokio::time::sleep(secs(120)).await;
    let calls = n.t.calls_for(&guest);
    assert!(!calls.is_empty());
    let allowed: HashSet<SocketAddr> = token.into_iter().collect();
    for c in calls {
        assert!(c.iter().all(|a| allowed.contains(a)));
    }
    // адреса друга гостю не достаются, адреса гостя другу тоже
    for c in n.t.calls_for(&friend) {
        assert_eq!(c, vec![addr("9.9.9.9:4000")]);
    }
}
