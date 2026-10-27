//! Адреса друга: слияние, сроки, порядок набора, находимость, тексты.

use std::net::SocketAddr;

use chervo_addr::{
    AddrSource, CONTACT_REFRESH_SECS, CONTACT_TTL_SECS, Findability, HINT_TTL_SECS,
    INVITE_TTL_SECS, KnownAddr, MAX_CONTACT_ADDRS, SHORT_LIVED_TTL_SECS, UpdateAddr, findability,
    from_invite, merge_update, note_contact, prune, usable,
};

const NOW: u64 = 10_000_000;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn known(addr: &str, source: AddrSource, last_seen: u64, short: bool, hint: bool) -> KnownAddr {
    KnownAddr {
        addr: sa(addr),
        source,
        last_seen_unix: last_seen,
        short_lived: short,
        hint,
    }
}

fn upd(addr: &str, short: bool, hint: bool) -> UpdateAddr {
    UpdateAddr {
        addr: sa(addr),
        short_lived: short,
        hint,
    }
}

fn addrs_of(v: &[KnownAddr]) -> Vec<SocketAddr> {
    v.iter().map(|k| k.addr).collect()
}

#[test]
fn from_invite_marks_v6() {
    let input: Vec<SocketAddr> = (1..=10)
        .map(|i| sa(&format!("198.51.100.{i}:4000")))
        .chain([sa("[2001:db8::1]:4000")])
        .collect();
    let out = from_invite(&input, NOW);
    assert_eq!(out.len(), 8, "первые 8");
    assert!(
        out.iter()
            .all(|k| k.source == AddrSource::Invite && k.last_seen_unix == NOW && !k.hint)
    );
    assert!(out.iter().all(|k| !k.short_lived), "IPv4 не короткоживущий");
    let v6 = from_invite(&[sa("[2001:db8::1]:4000"), sa("198.51.100.1:1")], NOW);
    assert!(v6[0].short_lived && !v6[1].short_lived);
    assert!(from_invite(&[], NOW).is_empty());
}

#[test]
fn merge_update_replaces_invite_and_update_keeps_contact() {
    let mut v = vec![
        known("198.51.100.1:1", AddrSource::Invite, 1, false, false),
        known("198.51.100.2:2", AddrSource::AddressUpdate, 2, false, false),
        known("198.51.100.3:3", AddrSource::Contact, 3, false, false),
        known("198.51.100.4:4", AddrSource::Lan, 4, false, false),
        known("198.51.100.9:9", AddrSource::Contact, 5, false, false),
    ];
    merge_update(
        &mut v,
        &[
            upd("203.0.113.5:50", false, false),
            upd("[2001:db8::7]:70", true, false),
            upd("198.51.100.9:9", false, true),
            upd("203.0.113.5:50", false, false), // повтор
        ],
        NOW,
    );
    // обновление первым, Invite и старый AddressUpdate ушли, Contact и Lan остались
    let got: Vec<(SocketAddr, AddrSource, u64, bool, bool)> = v
        .iter()
        .map(|k| (k.addr, k.source, k.last_seen_unix, k.short_lived, k.hint))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                sa("203.0.113.5:50"),
                AddrSource::AddressUpdate,
                NOW,
                false,
                false
            ),
            (
                sa("[2001:db8::7]:70"),
                AddrSource::AddressUpdate,
                NOW,
                true,
                false
            ),
            (
                sa("198.51.100.9:9"),
                AddrSource::AddressUpdate,
                NOW,
                false,
                true
            ),
            (sa("198.51.100.3:3"), AddrSource::Contact, 3, false, false),
            (sa("198.51.100.4:4"), AddrSource::Lan, 4, false, false),
        ]
    );
    // пустое обновление не оставляет ни Invite, ни AddressUpdate
    merge_update(&mut v, &[], NOW + 1);
    assert_eq!(
        addrs_of(&v),
        vec![sa("198.51.100.3:3"), sa("198.51.100.4:4")]
    );
}

#[test]
fn merge_update_hint_only_keeps_previous_non_hint_updates() {
    // Адреса глобальные: класс Documentation (198.51.100/24, 203.0.113/24) не Global, L1 его не хранит.
    let base = || {
        vec![
            known("8.8.4.1:1", AddrSource::Invite, 1, false, false),
            known("8.8.4.2:2", AddrSource::AddressUpdate, 2, false, false),
            known("8.8.4.6:6", AddrSource::AddressUpdate, 2, false, true),
            known("8.8.4.3:3", AddrSource::Contact, 3, false, false),
        ]
    };
    // только подсказки: прежний AddressUpdate без подсказки остаётся после новых подсказок
    let mut v = base();
    merge_update(
        &mut v,
        &[
            upd("9.9.9.5:50", false, true),
            upd("8.8.4.2:2", false, true),
        ],
        NOW,
    );
    let got: Vec<(SocketAddr, AddrSource, u64, bool)> = v
        .iter()
        .map(|k| (k.addr, k.source, k.last_seen_unix, k.hint))
        .collect();
    assert_eq!(
        got,
        vec![
            (sa("9.9.9.5:50"), AddrSource::AddressUpdate, NOW, true),
            // тот же адрес, что и у подсказки, заменяется записью обновления
            (sa("8.8.4.2:2"), AddrSource::AddressUpdate, NOW, true),
            (sa("8.8.4.3:3"), AddrSource::Contact, 3, false),
        ]
    );
    // вторая ветвь, как раньше: есть запись без подсказки, прежние AddressUpdate уходят
    let mut v = base();
    merge_update(
        &mut v,
        &[
            upd("9.9.9.5:50", false, true),
            upd("9.9.9.6:60", false, false),
        ],
        NOW,
    );
    assert_eq!(
        addrs_of(&v),
        vec![sa("9.9.9.5:50"), sa("9.9.9.6:60"), sa("8.8.4.3:3")]
    );
    // подсказки без совпадений: прежний AddressUpdate без подсказки цел, старая подсказка ушла
    let mut v = base();
    merge_update(&mut v, &[upd("9.9.9.5:50", false, true)], NOW);
    assert_eq!(
        addrs_of(&v),
        vec![sa("9.9.9.5:50"), sa("8.8.4.2:2"), sa("8.8.4.3:3")]
    );
}

#[test]
fn merge_update_ipv6_short_lived_regardless_of_sender_flag() {
    let mut v: Vec<KnownAddr> = Vec::new();
    merge_update(
        &mut v,
        &[
            upd("[2606:4700::7]:70", false, false),
            upd("203.0.113.5:50", false, false),
        ],
        NOW,
    );
    assert!(v[0].short_lived, "IPv6 без флага всё равно короткоживущий");
    assert!(!v[1].short_lived);
    assert_eq!(usable(&v, NOW + SHORT_LIVED_TTL_SECS - 1).len(), 2);
    prune(&mut v, NOW + SHORT_LIVED_TTL_SECS);
    assert_eq!(addrs_of(&v), vec![sa("203.0.113.5:50")]);
}

#[test]
fn note_contact_refresh_and_cap() {
    let mut v: Vec<KnownAddr> = Vec::new();
    let a = sa("203.0.113.1:100");
    assert!(note_contact(&mut v, a, NOW), "новый адрес");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].source, AddrSource::Contact);
    assert!(!v[0].short_lived && !v[0].hint);
    // повтор до срока обновления: без изменений
    assert!(!note_contact(&mut v, a, NOW + 1));
    assert!(!note_contact(&mut v, a, NOW + CONTACT_REFRESH_SECS - 1));
    assert_eq!(v[0].last_seen_unix, NOW);
    // на границе обновление
    assert!(note_contact(&mut v, a, NOW + CONTACT_REFRESH_SECS));
    assert_eq!(v[0].last_seen_unix, NOW + CONTACT_REFRESH_SECS);
    assert_eq!(v.len(), 1);
    // v4-mapped нормализуется в тот же адрес
    assert!(!note_contact(
        &mut v,
        sa("[::ffff:203.0.113.1]:100"),
        NOW + CONTACT_REFRESH_SECS + 1
    ));
    assert_eq!(v.len(), 1);
    // IPv6 контакт короткоживущий
    assert!(note_contact(&mut v, sa("[2001:db8::5]:5"), NOW + 10_000));
    assert!(v.iter().any(|k| k.addr.is_ipv6() && k.short_lived));
    // не больше MAX_CONTACT_ADDRS, остаются самые новые; чужие источники не трогаются
    let mut w = vec![known("198.51.100.1:1", AddrSource::Invite, 1, false, false)];
    for i in 0..(MAX_CONTACT_ADDRS + 3) {
        let at = NOW + 100 * i as u64;
        assert!(note_contact(
            &mut w,
            sa(&format!("203.0.113.{}:7", i + 1)),
            at
        ));
    }
    let contacts: Vec<&KnownAddr> = w
        .iter()
        .filter(|k| k.source == AddrSource::Contact)
        .collect();
    assert_eq!(contacts.len(), MAX_CONTACT_ADDRS);
    let newest: Vec<SocketAddr> = (4..MAX_CONTACT_ADDRS + 3)
        .map(|i| sa(&format!("203.0.113.{}:7", i + 1)))
        .collect();
    for n in &newest {
        assert!(contacts.iter().any(|k| k.addr == *n), "новые остались");
    }
    assert!(w.iter().any(|k| k.source == AddrSource::Invite));
}

#[test]
fn prune_ttls() {
    let t = NOW;
    // короткоживущий: жив до t + TTL - 1, ушёл на t + TTL
    for (ttl, mk) in [
        (
            SHORT_LIVED_TTL_SECS,
            known("[2001:db8::1]:1", AddrSource::Invite, t, true, false),
        ),
        (
            HINT_TTL_SECS,
            known("198.51.100.1:1", AddrSource::AddressUpdate, t, false, true),
        ),
        (
            CONTACT_TTL_SECS,
            known("198.51.100.2:2", AddrSource::Contact, t, false, false),
        ),
    ] {
        let mut v = vec![mk.clone()];
        prune(&mut v, t + ttl - 1);
        assert_eq!(v.len(), 1, "жив до границы");
        prune(&mut v, t + ttl);
        assert!(v.is_empty(), "ушёл на границе");
        // будущее last_seen (часы ушли назад) не истекает
        let mut v = vec![mk];
        prune(&mut v, t - 5);
        assert_eq!(v.len(), 1);
    }
    // обновление адреса без подсказки срока не имеет; `Invite` живёт `INVITE_TTL_SECS` (S2, M1)
    let mut v = vec![
        known("198.51.100.1:1", AddrSource::Invite, 1, false, false),
        known("198.51.100.2:2", AddrSource::AddressUpdate, 1, false, false),
    ];
    prune(&mut v, INVITE_TTL_SECS);
    assert_eq!(v.len(), 2, "жив до границы");
    prune(&mut v, 1 + INVITE_TTL_SECS);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].source, AddrSource::AddressUpdate);
    prune(&mut v, u64::MAX);
    assert_eq!(v.len(), 1);
    // переполнение last_seen + ttl не паникует
    let mut v = vec![known(
        "[2001:db8::1]:1",
        AddrSource::Invite,
        u64::MAX,
        true,
        true,
    )];
    prune(&mut v, u64::MAX);
    assert!(v.is_empty());
}

#[test]
fn usable_order() {
    let v = vec![
        known("[2001:db8::c]:3", AddrSource::Contact, NOW, true, false),
        known("198.51.100.3:3", AddrSource::Contact, NOW, false, false),
        known(
            "[2001:db8::99]:9",
            AddrSource::AddressUpdate,
            NOW,
            true,
            true,
        ),
        known(
            "198.51.100.8:8",
            AddrSource::AddressUpdate,
            NOW,
            false,
            true,
        ),
        known("[2001:db8::2]:2", AddrSource::Invite, NOW, true, false),
        known("198.51.100.2:2", AddrSource::Invite, NOW, false, false),
        known(
            "[2001:db8::1]:1",
            AddrSource::AddressUpdate,
            NOW,
            true,
            false,
        ),
        known(
            "198.51.100.1:1",
            AddrSource::AddressUpdate,
            NOW,
            false,
            false,
        ),
        known("198.51.100.1:1", AddrSource::Invite, NOW, false, false), // повтор адреса
        known("198.51.100.5:5", AddrSource::Lan, NOW, false, false),
        // просрочено
        known("[2001:db8::dead]:1", AddrSource::Invite, 1, true, false),
    ];
    let got = usable(&v, NOW);
    let want: Vec<SocketAddr> = [
        "198.51.100.1:1",
        "[2001:db8::1]:1",
        "198.51.100.2:2",
        "[2001:db8::2]:2",
        "198.51.100.3:3",
        "[2001:db8::c]:3",
        "198.51.100.8:8",
        "[2001:db8::99]:9",
        "198.51.100.5:5",
    ]
    .iter()
    .map(|s| sa(s))
    .collect();
    assert_eq!(got, want);
    assert!(usable(&[], NOW).is_empty());
}

#[test]
fn findability_rules() {
    let stable = known("203.0.114.1:1", AddrSource::Invite, NOW, false, false);
    // свой постоянный адрес: всегда Ok
    assert_eq!(findability(true, &[], NOW), Findability::Ok);
    assert_eq!(findability(false, &[], NOW), Findability::NeedToken);
    assert_eq!(
        findability(false, std::slice::from_ref(&stable), NOW),
        Findability::Ok
    );
    let upd_stable = known("8.8.4.4:5", AddrSource::AddressUpdate, NOW, false, false);
    assert_eq!(findability(false, &[upd_stable], NOW), Findability::Ok);
    // не считаются: короткоживущий, подсказка, частный, не тот источник, просроченный контакт
    let mut weak = vec![
        known("[2001:4860::1]:1", AddrSource::Invite, NOW, true, false),
        known("8.8.8.8:1", AddrSource::AddressUpdate, NOW, false, true),
        known("192.168.1.5:1", AddrSource::Invite, NOW, false, false),
        known("100.64.0.1:1", AddrSource::AddressUpdate, NOW, false, false),
        known("8.8.8.8:2", AddrSource::Contact, NOW, false, false),
        known("8.8.8.8:3", AddrSource::ObservedByFriend, NOW, false, false),
    ];
    assert_eq!(findability(false, &weak, NOW), Findability::NeedToken);
    assert_eq!(findability(true, &weak, NOW), Findability::Ok);
    // постоянный адрес, но короткоживущий-срок: Global IPv6 без флага тоже подходит
    weak.push(known(
        "[2001:4860::2]:1",
        AddrSource::Invite,
        NOW,
        false,
        false,
    ));
    assert_eq!(findability(false, &weak, NOW), Findability::Ok);
    // IPv6 short_lived просрочен и без флага не имеет срока; v4-mapped нормализуется
    let mapped = known("[::ffff:8.8.8.8]:1", AddrSource::Invite, NOW, false, false);
    assert_eq!(findability(false, &[mapped], NOW), Findability::Ok);
}

#[test]
fn usable_entries_matches_usable() {
    use chervo_addr::usable_entries;
    let addrs = vec![
        known("203.0.113.5:4000", AddrSource::Contact, NOW, false, false),
        known(
            "[2001:db8::1]:4000",
            AddrSource::AddressUpdate,
            NOW,
            true,
            false,
        ),
        known(
            "198.51.100.9:4000",
            AddrSource::AddressUpdate,
            NOW,
            false,
            true,
        ),
        known(
            "198.51.100.1:4000",
            AddrSource::AddressUpdate,
            NOW,
            false,
            false,
        ),
        known("192.0.2.77:4000", AddrSource::Invite, NOW, false, false),
        // повтор адреса: остаётся первая запись в порядке набора
        known("203.0.113.5:4000", AddrSource::Contact, NOW, false, false),
        // просроченная подсказка и просроченный короткоживущий
        known(
            "198.51.100.200:4000",
            AddrSource::AddressUpdate,
            1,
            false,
            true,
        ),
        known(
            "[2001:db8::2]:4000",
            AddrSource::AddressUpdate,
            1,
            true,
            false,
        ),
    ];
    for now in [
        NOW,
        NOW + 1,
        NOW + HINT_TTL_SECS + 1,
        NOW + CONTACT_TTL_SECS + 1,
    ] {
        let plain = usable(&addrs, now);
        let rich = usable_entries(&addrs, now);
        assert_eq!(addrs_of(&rich), plain, "now = {now}");
    }
    // флаги сохранены
    let rich = usable_entries(&addrs, NOW);
    let hint = rich
        .iter()
        .find(|k| k.addr == sa("198.51.100.9:4000"))
        .unwrap();
    assert!(hint.hint && hint.source == AddrSource::AddressUpdate);
    let v6 = rich
        .iter()
        .find(|k| k.addr == sa("[2001:db8::1]:4000"))
        .unwrap();
    assert!(v6.short_lived);
    assert!(usable_entries(&[], NOW).is_empty());
}
