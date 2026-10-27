//! Ручной токен адреса (этап 16, P0): выпуск `issue_addr_update_text` и вставка
//! `apply_addr_update_text` на настоящей книге друзей и поддельном транспорте.

use std::net::SocketAddr;

use chervo_addr::{AddrClass, AddrSource, NatView, classify};
use chervo_friends::{FriendBook, FriendsError};
use chervo_identity::PairId;

use super::kit::*;
use crate::{ConnectConfig, ConnectError};

const BAD: ConnectError = ConnectError::Friends(FriendsError::BadAddrUpdate);
const STALE: ConnectError = ConnectError::Friends(FriendsError::StaleSeq);

/// Пара узлов A и B, дружащих друг с другом, и два друга-наблюдателя на стороне A.
struct Duo {
    a: Node,
    b: Node,
    pa: PairId,
    pb: PairId,
    obs: [PairId; 2],
    a_book: std::path::PathBuf,
}

fn duo(route_v4: &str, route_v6: Option<&str>, listen: Vec<SocketAddr>) -> Duo {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![], vec![]);
    let o1 = pre_a.solo_friend(vec![inv("5.6.7.8:4000")]);
    let o2 = pre_a.solo_friend(vec![inv("5.6.7.9:4000")]);
    let a_book = pre_a.dir.file();
    let t = FakeTransport::new();
    t.set_local(listen);
    let probe = FakeProbe::new(Some(route_v4));
    probe.set_v6(route_v6);
    let a = Node::start_with(pre_a, ConnectConfig::default(), t, probe);
    let b = Node::start(pre_b, ConnectConfig::default());
    Duo {
        a,
        b,
        pa,
        pb,
        obs: [o1, o2],
        a_book,
    }
}

fn v4_listen() -> Vec<SocketAddr> {
    vec![addr("0.0.0.0:4000")]
}

/// Два наблюдателя видят нас с одним и тем же адресом: вид сети `Eim` (если маршрут частный).
fn observe_same(d: &Duo) {
    apply_obs(&d.a, d.obs[0], "5.6.7.8:4000", "9.9.9.9:4000");
    apply_obs(&d.a, d.obs[1], "5.6.7.9:4000", "9.9.9.9:4000");
}

/// Два наблюдателя видят разные порты: вид сети `Symmetric`.
fn observe_diff(d: &Duo) {
    apply_obs(&d.a, d.obs[0], "5.6.7.8:4000", "9.9.9.9:4000");
    apply_obs(&d.a, d.obs[1], "5.6.7.9:4000", "9.9.9.9:4001");
}

fn seq_out(n: &Node, pair: &PairId) -> u64 {
    n.engine.read_book(|b| b.get(pair).unwrap().addr_seq_out)
}

fn seq_in(n: &Node, pair: &PairId) -> u64 {
    n.engine.read_book(|b| b.get(pair).unwrap().last_addr_seq)
}

/// Адреса друга с источником `AddressUpdate` и их флаг подсказки.
fn update_entries(n: &Node, pair: &PairId) -> Vec<(SocketAddr, bool)> {
    n.engine.read_book(|b| {
        b.get(pair)
            .unwrap()
            .known_addrs
            .iter()
            .filter(|k| k.source == AddrSource::AddressUpdate)
            .map(|k| (k.addr, k.hint))
            .collect()
    })
}

fn update_addrs(n: &Node, pair: &PairId) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = update_entries(n, pair).into_iter().map(|e| e.0).collect();
    v.sort();
    v
}

#[tokio::test(start_paused = true)]
async fn manual_token_issue_apply_roundtrip() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    assert_eq!(d.a.engine.nat_view(), NatView::Eim);
    assert_eq!(seq_out(&d.a, &d.pa), 0);

    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert!(text.starts_with("CHA1"), "token prefix");
    let s = seq_out(&d.a, &d.pa);
    assert!(s > 0, "seq persisted in the book");

    let got = d.b.engine.apply_addr_update_text(&text).unwrap();
    assert_eq!(got, d.pb);
    // ровно наш адрес со слов друзей, с флагом подсказки; чужие адреса из книги A (5.6.7.x,
    // адреса наблюдателей) в токен не попадают (U6 v6)
    assert_eq!(
        update_entries(&d.b, &d.pb),
        vec![(addr("9.9.9.9:4000"), true)]
    );
    assert_eq!(seq_in(&d.b, &d.pb), s);
    // выпуск не трогает запись ADDR_INFO
    assert!(
        d.a.engine
            .inner
            .lock()
            .friends
            .get(&d.pa)
            .is_none_or(|r| r.last_sent.is_none())
    );
}

#[tokio::test(start_paused = true)]
async fn manual_token_seq_persisted_before_return() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert!(!text.is_empty());
    let s = seq_out(&d.a, &d.pa);
    // заново открытая книга с диска уже содержит номер выпущенного токена
    let reopened = FriendBook::open_unanchored(&d.a_book, &*d.a.store).unwrap();
    assert_eq!(reopened.get(&d.pa).unwrap().addr_seq_out, s);
}

#[tokio::test(start_paused = true)]
async fn manual_token_stale_and_monotonic() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let t1 = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert_eq!(d.b.engine.apply_addr_update_text(&t1).unwrap(), d.pb);
    // тот же текст ещё раз
    assert_eq!(d.b.engine.apply_addr_update_text(&t1), Err(STALE));
    // номера растут даже в ту же секунду; новый токен принимается
    let t2 = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert_ne!(t1, t2);
    assert_eq!(d.b.engine.apply_addr_update_text(&t2).unwrap(), d.pb);
    // старый токен после нового
    assert_eq!(d.b.engine.apply_addr_update_text(&t1), Err(STALE));
    assert_eq!(d.b.engine.apply_addr_update_text(&t2), Err(STALE));
}

#[tokio::test(start_paused = true)]
async fn manual_token_foreign_pair_rejected() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    // у C единственный друг P2 с другими ключами
    let mut pre_c = Pre::new();
    let p2 = pre_c.solo_friend(vec![inv("5.6.7.8:4000")]);
    let c = Node::start(pre_c, ConnectConfig::default());
    assert_eq!(c.engine.apply_addr_update_text(&text), Err(BAD));
    assert_eq!(seq_in(&c, &p2), 0);
    assert!(update_entries(&c, &p2).is_empty());
}

#[tokio::test(start_paused = true)]
async fn manual_token_blocked_friend_rejected() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    d.b.engine.update_book(|b, s| b.block(s, &d.pb)).unwrap();
    assert_eq!(d.b.engine.apply_addr_update_text(&text), Err(BAD));
    assert_eq!(seq_in(&d.b, &d.pb), 0);
    d.b.engine.update_book(|b, s| b.unblock(s, &d.pb)).unwrap();
    assert_eq!(d.b.engine.apply_addr_update_text(&text).unwrap(), d.pb);
}

#[tokio::test(start_paused = true)]
async fn manual_token_unknown_and_not_active() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let unknown = PairId::from_bytes([0x77; 16]);
    assert_eq!(
        d.a.engine.issue_addr_update_text(&unknown, false),
        Err(ConnectError::UnknownPair)
    );
    d.a.engine.update_book(|b, s| b.block(s, &d.pa)).unwrap();
    assert_eq!(
        d.a.engine.issue_addr_update_text(&d.pa, false),
        Err(ConnectError::NotActive)
    );
    assert_eq!(seq_out(&d.a, &d.pa), 0, "no seq consumed");
    // после остановки движка оба вызова отказывают
    d.a.engine.shutdown();
    assert_eq!(
        d.a.engine.issue_addr_update_text(&d.obs[0], false),
        Err(ConnectError::Shutdown)
    );
    assert_eq!(
        d.a.engine.apply_addr_update_text("CHA1"),
        Err(ConnectError::Shutdown)
    );
}

#[tokio::test(start_paused = true)]
async fn manual_token_no_addresses_cgnat_and_symmetric() {
    // за CGNAT: маршрутный адрес 100.64/10, наблюдения друзей не публикуются
    let d = duo("100.64.0.5", None, v4_listen());
    observe_same(&d);
    assert_eq!(d.a.engine.nat_view(), NatView::BehindCgnat);
    for lan in [false, true] {
        assert_eq!(
            d.a.engine.issue_addr_update_text(&d.pa, lan),
            Err(ConnectError::NoAddresses)
        );
    }
    assert_eq!(seq_out(&d.a, &d.pa), 0, "no seq consumed (CGNAT)");

    // симметричный NAT: наблюдатели видят разные порты
    let d = duo("192.168.1.5", None, v4_listen());
    observe_diff(&d);
    assert_eq!(d.a.engine.nat_view(), NatView::Symmetric);
    assert_eq!(
        d.a.engine.issue_addr_update_text(&d.pa, false),
        Err(ConnectError::NoAddresses)
    );
    assert_eq!(seq_out(&d.a, &d.pa), 0, "no seq consumed (symmetric)");

    // без наблюдений и без глобального маршрута набор тоже пуст
    let d = duo("192.168.1.5", None, v4_listen());
    assert_eq!(
        d.a.engine.issue_addr_update_text(&d.pa, false),
        Err(ConnectError::NoAddresses)
    );
    assert_eq!(seq_out(&d.a, &d.pa), 0);
}

#[tokio::test(start_paused = true)]
async fn manual_token_include_lan_only_by_choice() {
    let both = vec![addr("0.0.0.0:4000"), addr("[::]:4000")];
    // частный IPv4 + глобальный IPv6
    let d = duo("192.168.1.5", Some("2606:4700::5"), both.clone());
    let t = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    d.b.engine.apply_addr_update_text(&t).unwrap();
    let got = update_addrs(&d.b, &d.pb);
    assert_eq!(got, vec![addr("[2606:4700::5]:4000")]);
    assert!(got.iter().all(|a| classify(a.ip()) != AddrClass::Private));
    let t = d.a.engine.issue_addr_update_text(&d.pa, true).unwrap();
    d.b.engine.apply_addr_update_text(&t).unwrap();
    let mut want = vec![addr("[2606:4700::5]:4000"), addr("192.168.1.5:4000")];
    want.sort();
    assert_eq!(update_addrs(&d.b, &d.pb), want);

    // глобальный IPv4 + ULA IPv6
    let d = duo("7.7.7.7", Some("fd12:3456::5"), both);
    let t = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    d.b.engine.apply_addr_update_text(&t).unwrap();
    let got = update_addrs(&d.b, &d.pb);
    assert_eq!(got, vec![addr("7.7.7.7:4000")]);
    assert!(got.iter().all(|a| classify(a.ip()) != AddrClass::Private));
    let t = d.a.engine.issue_addr_update_text(&d.pa, true).unwrap();
    d.b.engine.apply_addr_update_text(&t).unwrap();
    let mut want = vec![addr("7.7.7.7:4000"), addr("[fd12:3456::5]:4000")];
    want.sort();
    assert_eq!(update_addrs(&d.b, &d.pb), want);
}

#[tokio::test(start_paused = true)]
async fn manual_token_length_cap_without_decode() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert!(text.len() < 1000);
    // действительный токен, добитый пробелами до 1025 байт: отвергается по длине, хотя после
    // обрезки был бы принят (значит, разбор не начинался)
    let pad = |n: usize| format!("{text}{}", " ".repeat(n - text.len()));
    assert_eq!(pad(1025).len(), 1025);
    assert_eq!(d.b.engine.apply_addr_update_text(&pad(1025)), Err(BAD));
    assert_eq!(seq_in(&d.b, &d.pb), 0);
    assert!(update_entries(&d.b, &d.pb).is_empty());
    // мусор длиннее предела
    assert_eq!(
        d.b.engine.apply_addr_update_text(&"A".repeat(5000)),
        Err(BAD)
    );
    // ровно 1024 байта принимается; перевод строки и пробелы по краям допустимы
    assert_eq!(d.b.engine.apply_addr_update_text(&pad(1024)).unwrap(), d.pb);
    let t2 = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    assert_eq!(
        d.b.engine
            .apply_addr_update_text(&format!("\r\n {t2}\n"))
            .unwrap(),
        d.pb
    );
    // пустой текст и посторонний префикс
    assert_eq!(d.b.engine.apply_addr_update_text(""), Err(BAD));
    assert_eq!(d.b.engine.apply_addr_update_text("hello"), Err(BAD));
}

#[tokio::test(start_paused = true)]
async fn manual_token_flipped_byte_rejected() {
    let d = duo("192.168.1.5", None, v4_listen());
    observe_same(&d);
    let text = d.a.engine.issue_addr_update_text(&d.pa, false).unwrap();
    let chars: Vec<char> = text.chars().collect();
    let mut checked = 0;
    for i in (8..chars.len() - 4).step_by(5) {
        let mut v = chars.clone();
        v[i] = if v[i].eq_ignore_ascii_case(&'a') {
            'b'
        } else {
            'a'
        };
        let bad: String = v.into_iter().collect();
        assert_eq!(
            d.b.engine.apply_addr_update_text(&bad),
            Err(BAD),
            "flip at {i}"
        );
        checked += 1;
    }
    assert!(checked >= 10);
    assert_eq!(seq_in(&d.b, &d.pb), 0);
    assert!(update_entries(&d.b, &d.pb).is_empty());
    // неискажённый токен после неудач принимается
    assert_eq!(d.b.engine.apply_addr_update_text(&text).unwrap(), d.pb);
}
