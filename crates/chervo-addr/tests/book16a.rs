//! Этап 16а: срок частных записей друга (П2b) и правило L1 только для глобальных адресов.

use std::net::SocketAddr;

use chervo_addr::{
    AddrSource, Findability, INVITE_TTL_SECS, KnownAddr, PRIVATE_TTL_SECS, UpdateAddr, findability,
    merge_update, prune, usable,
};

const NOW: u64 = 10_000_000;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn known(addr: &str, source: AddrSource, last_seen: u64, hint: bool) -> KnownAddr {
    KnownAddr {
        addr: sa(addr),
        source,
        last_seen_unix: last_seen,
        short_lived: sa(addr).is_ipv6(),
        hint,
    }
}

fn upd(addr: &str, hint: bool) -> UpdateAddr {
    UpdateAddr {
        addr: sa(addr),
        short_lived: false,
        hint,
    }
}

fn addrs_of(v: &[KnownAddr]) -> Vec<SocketAddr> {
    v.iter().map(|k| k.addr).collect()
}

#[test]
fn hint_update_displaces_private_update() {
    let mut v = vec![
        known("192.168.1.9:4000", AddrSource::AddressUpdate, 1, false),
        known("8.8.4.4:4000", AddrSource::AddressUpdate, 1, false),
    ];
    merge_update(&mut v, &[upd("9.9.9.9:5000", true)], NOW);
    // частный адрес прежнего обновления ушёл, глобальный остался
    assert_eq!(addrs_of(&v), vec![sa("9.9.9.9:5000"), sa("8.8.4.4:4000")]);
}

#[test]
fn l1_keeps_global_non_hint_only() {
    let mut v = vec![
        known("8.8.4.4:4000", AddrSource::AddressUpdate, 1, false),
        known("10.1.2.3:4000", AddrSource::AddressUpdate, 1, false),
        known("[fd00::9]:4000", AddrSource::AddressUpdate, 1, false),
        known("[2606:4700::7]:4000", AddrSource::AddressUpdate, 1, false),
        known("192.168.1.9:4000", AddrSource::Contact, 3, false),
        known("8.8.8.8:4000", AddrSource::Invite, 1, false),
    ];
    merge_update(&mut v, &[upd("9.9.9.9:5000", true)], NOW);
    assert_eq!(
        addrs_of(&v),
        vec![
            sa("9.9.9.9:5000"),
            sa("8.8.4.4:4000"),
            sa("[2606:4700::7]:4000"),
            // Contact не затрагивается слиянием
            sa("192.168.1.9:4000"),
        ]
    );
}

#[test]
fn private_expires_24h_any_source() {
    let t = NOW;
    for source in [
        AddrSource::Invite,
        AddrSource::AddressUpdate,
        AddrSource::Contact,
    ] {
        let mut v = vec![known("192.168.1.9:4000", source, t, false)];
        prune(&mut v, t + PRIVATE_TTL_SECS - 1);
        assert_eq!(v.len(), 1, "{source:?}: жив до границы");
        assert_eq!(usable(&v, t + PRIVATE_TTL_SECS - 1).len(), 1);
        assert!(usable(&v, t + PRIVATE_TTL_SECS).is_empty(), "{source:?}");
        prune(&mut v, t + PRIVATE_TTL_SECS);
        assert!(v.is_empty(), "{source:?}: ушёл на границе");
    }
    assert_eq!(PRIVATE_TTL_SECS, 86_400);
    // глобальный адрес без подсказки срока не имеет
    let mut g = vec![
        known("8.8.4.4:4000", AddrSource::AddressUpdate, t, false),
        known("8.8.8.8:4000", AddrSource::Invite, t, false),
    ];
    prune(&mut g, t + PRIVATE_TTL_SECS * 10);
    assert_eq!(g.len(), 2);
    // отображённый IPv4 в частном диапазоне считается частным
    let mut m = vec![known(
        "[::ffff:10.0.0.5]:4000",
        AddrSource::Invite,
        t,
        false,
    )];
    m[0].short_lived = false;
    prune(&mut m, t + PRIVATE_TTL_SECS);
    assert!(m.is_empty());
}

#[test]
fn private_ula_expires_24h() {
    let t = NOW;
    let mut v = vec![known("[fd00::9]:4000", AddrSource::AddressUpdate, t, false)];
    // короткоживущий IPv6 и так уходит ровно через сутки; проверка границы ULA
    prune(&mut v, t + PRIVATE_TTL_SECS - 1);
    assert_eq!(v.len(), 1);
    prune(&mut v, t + PRIVATE_TTL_SECS);
    assert!(v.is_empty());
    // ULA не короткоживущий (искусственно): срок всё равно сутки
    let mut w = vec![known("[fd00::9]:4000", AddrSource::Invite, t, false)];
    w[0].short_lived = false;
    prune(&mut w, t + PRIVATE_TTL_SECS - 1);
    assert_eq!(w.len(), 1);
    prune(&mut w, t + PRIVATE_TTL_SECS);
    assert!(w.is_empty());
}

#[test]
fn private_future_last_seen_not_expired() {
    let mut v = vec![known(
        "10.0.0.5:4000",
        AddrSource::Contact,
        NOW + 500,
        false,
    )];
    prune(&mut v, NOW);
    assert_eq!(v.len(), 1);
    assert_eq!(usable(&v, NOW).len(), 1);
}

#[test]
fn findability_ignores_private_ttl() {
    // частные записи постоянным адресом друга не считаются ни до, ни после срока
    let private = vec![known("192.168.1.9:4000", AddrSource::Invite, NOW, false)];
    assert_eq!(findability(false, &private, NOW), Findability::NeedToken);
    assert_eq!(
        findability(false, &private, NOW + PRIVATE_TTL_SECS),
        Findability::NeedToken
    );
    // глобальный постоянный адрес срок частных записей не затрагивает
    let global = vec![
        known("192.168.1.9:4000", AddrSource::Invite, NOW, false),
        known("8.8.4.4:4000", AddrSource::AddressUpdate, NOW, false),
    ];
    assert_eq!(findability(false, &global, NOW), Findability::Ok);
    assert_eq!(
        findability(false, &global, NOW + PRIVATE_TTL_SECS * 3),
        Findability::Ok
    );
    // свой постоянный адрес: Ok независимо от записей
    assert_eq!(findability(true, &private, NOW), Findability::Ok);
}

// ------------------------------------------------------------------ этап 17, S2, M1

#[test]
fn invite_entry_expires_after_ttl_even_if_global_and_not_short_lived() {
    let t = NOW - INVITE_TTL_SECS;
    let mut v = vec![
        known("8.8.8.8:4000", AddrSource::Invite, t + 1, false),
        known("8.8.4.4:4000", AddrSource::Invite, t, false),
        known("9.9.9.9:4000", AddrSource::AddressUpdate, t, false),
    ];
    // чуть меньше срока: жива; ровно срок: нет (старый код хранил Invite вечно)
    assert_eq!(usable(&v, NOW).len(), 2);
    assert!(!usable(&v, NOW).contains(&sa("8.8.4.4:4000")));
    prune(&mut v, NOW);
    assert_eq!(addrs_of(&v), vec![sa("8.8.8.8:4000"), sa("9.9.9.9:4000")]);
    // постоянный адрес из устаревшего приглашения больше не делает друга находимым
    let old = vec![known("8.8.4.4:4000", AddrSource::Invite, t, false)];
    assert_eq!(findability(false, &old, NOW), Findability::NeedToken);
}

#[test]
fn confirmed_addrs_only_live_contact_without_hint() {
    use chervo_addr::{CONTACT_TTL_SECS, confirmed_addrs};
    let v = vec![
        known("8.8.8.8:4000", AddrSource::Invite, NOW, false),
        known("8.8.8.8:4000", AddrSource::Contact, NOW, false),
        known("8.8.4.4:4000", AddrSource::Contact, NOW, true),
        known(
            "9.9.9.9:4000",
            AddrSource::Contact,
            NOW - CONTACT_TTL_SECS,
            false,
        ),
        known("[::ffff:7.7.7.7]:4000", AddrSource::Contact, NOW, false),
    ];
    assert_eq!(
        confirmed_addrs(&v, NOW),
        vec![sa("8.8.8.8:4000"), sa("7.7.7.7:4000")]
    );
}
