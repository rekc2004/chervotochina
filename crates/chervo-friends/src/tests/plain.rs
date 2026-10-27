use chervo_addr::{AddrSource, KnownAddr};
use chervo_identity::PairId;
use chervo_token::RevocationReason;

use super::kit::*;
use crate::plain::{decode, encode};
use crate::{
    AutoAcceptLimits, BookData, FriendsError, MAX_ADDRS_PER_FRIEND, MAX_FRIENDS, MAX_NAME_BYTES,
    MAX_PENDING, PendingRole, Permission,
};

fn bytes_of(d: &BookData) -> Vec<u8> {
    encode(d).unwrap().to_vec()
}

/// Версия, epoch, число друзей.
const HEADER: usize = 1 + 8 + 2;

/// Смещения полей первого друга в открытом тексте.
struct Off {
    name_len: usize,
    friend_ed: usize,
    friend_x: usize,
    our_ed: usize,
    state: usize,
    perm: usize,
}

fn off(name_len: usize) -> Off {
    let name_len_at = HEADER + 16;
    let friend_ed = name_len_at + 1 + name_len;
    Off {
        name_len: name_len_at,
        friend_ed,
        friend_x: friend_ed + 32,
        our_ed: friend_ed + 64,
        state: friend_ed + 96,
        perm: friend_ed + 97,
    }
}

fn one_friend() -> (BookData, Vec<u8>, Off) {
    let mut d = BookData {
        epoch: 0,
        friends: vec![friend(1)],
        pending: vec![],
    };
    d.friends[0].name = "abc".into();
    let b = bytes_of(&d);
    (d, b, off(3))
}

#[test]
fn plain_roundtrip_and_layout() {
    let d = sample();
    let b = bytes_of(&d);
    assert_eq!(b[0], 3);
    assert_eq!(u64::from_be_bytes(b[1..9].try_into().unwrap()), 77);
    assert_eq!(u16::from_be_bytes([b[9], b[10]]), 3);
    let back = decode(&b).unwrap();
    assert_eq!(back.epoch, 77);
    assert!(same(&d, &back));
    assert_eq!(bytes_of(&back), b, "кодирование каноническое");
}

/// Ёмкость выбрана по точному размеру: буфер не перевыделялся (иначе остались бы копии
/// открытого текста в освобождённой памяти).
#[test]
fn plain_encode_exact_capacity() {
    let full = encode(&sample()).unwrap();
    assert_eq!(full.capacity(), full.len());
    let empty = encode(&BookData::default()).unwrap();
    assert_eq!(empty.capacity(), empty.len());
    let many = BookData {
        epoch: 0,
        friends: (0..200u8).map(friend).collect(),
        pending: vec![pending(1, PendingRole::Inviter)],
    };
    let b = encode(&many).unwrap();
    assert_eq!(b.capacity(), b.len());
}

#[test]
fn plain_limits() {
    // 1025 друзей: запись отказывает, разбор отказывает
    let f = friend(1);
    let many = BookData {
        epoch: 0,
        friends: (0..=MAX_FRIENDS)
            .map(|i| {
                let mut g = f.clone();
                g.pair = PairId::from_bytes([
                    i as u8,
                    (i >> 8) as u8,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
                g
            })
            .collect(),
        pending: vec![],
    };
    assert_eq!(encode(&many).err(), Some(FriendsError::LimitExceeded));
    // ровно 1024: запись и разбор проходят
    let max = BookData {
        epoch: 0,
        friends: many.friends[..MAX_FRIENDS].to_vec(),
        pending: vec![],
    };
    let b = bytes_of(&max);
    assert_eq!(decode(&b).unwrap().friends.len(), MAX_FRIENDS);
    // счётчик 1025 в заголовке
    let mut bad = b.clone();
    bad[9..11].copy_from_slice(&1025u16.to_be_bytes());
    assert_eq!(decode(&bad).err(), Some(FriendsError::Corrupt));

    // 65 pending
    let pend = |n: usize| BookData {
        epoch: 0,
        friends: vec![],
        pending: (0..n)
            .map(|i| crate::PendingEntry {
                pair: PairId::from_bytes([i as u8 + 1; 16]),
                role: PendingRole::Inviter,
                expires_at_unix: 1,
            })
            .collect(),
    };
    assert_eq!(
        encode(&pend(MAX_PENDING + 1)).err(),
        Some(FriendsError::LimitExceeded)
    );
    let b = bytes_of(&pend(MAX_PENDING));
    assert_eq!(decode(&b).unwrap().pending.len(), MAX_PENDING);
    let mut bad = pend(MAX_PENDING + 1).pending;
    // руками: 65 записей в разборе
    let mut raw = vec![2u8, 0, 0];
    raw.extend_from_slice(&65u16.to_be_bytes());
    for e in bad.drain(..) {
        raw.extend_from_slice(e.pair.as_bytes());
        raw.push(0);
        raw.extend_from_slice(&1u64.to_be_bytes());
    }
    assert_eq!(decode(&raw).err(), Some(FriendsError::Corrupt));

    // имя: 64 байта можно, 65 нельзя, пустое нельзя, управляющий символ нельзя
    let named = |name: &str| BookData {
        epoch: 0,
        friends: vec![{
            let mut g = friend(1);
            g.name = name.to_owned();
            g
        }],
        pending: vec![],
    };
    assert!(encode(&named(&"a".repeat(MAX_NAME_BYTES))).is_ok());
    for bad in [
        "a".repeat(MAX_NAME_BYTES + 1),
        String::new(),
        "a\u{0}b".into(),
        "a\nb".into(),
        "\u{7f}".into(),
        "x\u{85}".into(),
    ] {
        assert_eq!(
            encode(&named(&bad)).err(),
            Some(FriendsError::InvalidName),
            "{bad:?}"
        );
    }
    // разбор: те же имена в готовом тексте
    let (_d, b, o) = one_friend();
    for bad in [&b"ab\n"[..], b"\x00bc", b"\xC2\x85b"] {
        let mut x = b.clone();
        x.splice(o.name_len + 1..o.name_len + 4, bad.iter().copied());
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt), "{bad:?}");
    }
    // не UTF-8
    let mut x = b.clone();
    x[o.name_len + 1] = 0xFF;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    // пустое имя
    let mut x = b.clone();
    x[o.name_len] = 0;
    x.drain(o.name_len + 1..o.name_len + 4);
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    // длина имени 65 при коротком остатке
    let mut x = b.clone();
    x[o.name_len] = 65;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));

    // 17 адресов
    let mut g = friend(1);
    g.name = "abc".into();
    g.known_addrs = (0..=MAX_ADDRS_PER_FRIEND)
        .map(|i| KnownAddr {
            addr: addr(&format!("203.0.113.{}:1000", i + 1)),
            source: AddrSource::Lan,
            last_seen_unix: 1,
            short_lived: false,
            hint: false,
        })
        .collect();
    let seventeen = BookData {
        epoch: 0,
        friends: vec![g.clone()],
        pending: vec![],
    };
    assert_eq!(encode(&seventeen).err(), Some(FriendsError::LimitExceeded));
    g.known_addrs.truncate(MAX_ADDRS_PER_FRIEND);
    let sixteen = BookData {
        epoch: 0,
        friends: vec![g.clone()],
        pending: vec![],
    };
    let mut b16 = bytes_of(&sixteen);
    assert_eq!(decode(&b16).unwrap().friends[0].known_addrs.len(), 16);
    // 17-й адрес руками: счётчик 17 и лишняя запись (17 байт для IPv4)
    let n_addrs_at = off(3).perm + 1 + 8 + 8 + 8;
    assert_eq!(b16[n_addrs_at], 16);
    b16[n_addrs_at] = 17;
    let insert_at = b16.len() - 2; // перед `n_pending u16`
    let rec: Vec<u8> = b16[insert_at - 17..insert_at].to_vec();
    b16.splice(insert_at..insert_at, rec);
    assert_eq!(decode(&b16).err(), Some(FriendsError::Corrupt));
}

#[test]
fn plain_rejects_duplicates() {
    let mut f2 = friend(2);
    f2.pair = friend(1).pair;
    let dup = BookData {
        epoch: 0,
        friends: vec![friend(1), f2],
        pending: vec![],
    };
    assert_eq!(encode(&dup).err(), Some(FriendsError::AlreadyExists));
    // руками: два разных друга, затем второй pair := первый
    let d = BookData {
        epoch: 0,
        friends: vec![friend(1), friend(2)],
        pending: vec![],
    };
    let mut b = bytes_of(&d);
    let first_len = {
        // длина записи первого друга = позиция второго `pair` - 3
        let p2 = [2u8; 16];
        b.windows(16).position(|w| w == p2).unwrap() - HEADER
    };
    let second_pair_at = HEADER + first_len;
    let first_pair: Vec<u8> = b[HEADER..HEADER + 16].to_vec();
    b[second_pair_at..second_pair_at + 16].copy_from_slice(&first_pair);
    assert_eq!(decode(&b).err(), Some(FriendsError::Corrupt));

    // pending
    let p = pending(1, PendingRole::Inviter);
    let dup = BookData {
        epoch: 0,
        friends: vec![],
        pending: vec![p, p],
    };
    assert_eq!(encode(&dup).err(), Some(FriendsError::AlreadyExists));
    let mut raw = vec![2u8, 0, 0, 0, 2];
    for _ in 0..2 {
        raw.extend_from_slice(p.pair.as_bytes());
        raw.push(0);
        raw.extend_from_slice(&1u64.to_be_bytes());
    }
    assert_eq!(decode(&raw).err(), Some(FriendsError::Corrupt));
    // пара и друг, и pending
    let mixed = BookData {
        epoch: 0,
        friends: vec![friend(1)],
        pending: vec![crate::PendingEntry {
            pair: friend(1).pair,
            role: PendingRole::Invitee,
            expires_at_unix: 1,
        }],
    };
    assert_eq!(encode(&mixed).err(), Some(FriendsError::AlreadyExists));
}

#[test]
fn plain_rejects_bad_keys() {
    let (_d, b, o) = one_friend();
    assert!(decode(&b).is_ok());
    let mut weak = [0u8; 32];
    weak[0] = 1; // единичная точка Ed: слабая
    let mut small_x = [0u8; 32];
    small_x[0] = 1; // малый порядок X
    let cases: Vec<(&str, usize, Vec<u8>)> = vec![
        ("friend_ed слабый", o.friend_ed, weak.to_vec()),
        ("friend_ed не точка", o.friend_ed, vec![0xFF; 32]),
        ("friend_x ноль", o.friend_x, vec![0; 32]),
        ("friend_x малый порядок", o.friend_x, small_x.to_vec()),
        ("friend_x не канонический", o.friend_x, vec![0xFF; 32]),
        ("our_ed слабый", o.our_ed, weak.to_vec()),
        ("our_ed не точка", o.our_ed, vec![0xFF; 32]),
    ];
    for (name, at, val) in cases {
        let mut x = b.clone();
        x[at..at + 32].copy_from_slice(&val);
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt), "{name}");
    }
}

#[test]
fn plain_rejects_unknown_enums() {
    let (_d, b, o) = one_friend();
    // состояние 4, разрешение 2 (3 это `Retired`: без записи об отзыве отклоняется ниже)
    for v in [3u8, 4, 5, 0xFF] {
        let mut x = b.clone();
        x[o.state] = v;
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt), "state {v}");
    }
    for v in [2u8, 3, 0xFF] {
        let mut x = b.clone();
        x[o.perm] = v;
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt), "perm {v}");
    }
    // адрес: семейство, источник, short_lived
    let addr0 = o.perm + 1 + 8 + 8 + 8 + 1; // первый адрес (IPv4)
    let mut x = b.clone();
    x[addr0] = 5;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    let mut x = b.clone();
    x[addr0 + 1 + 4 + 2] = 7;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    let mut x = b.clone();
    x[addr0 + 1 + 4 + 2 + 1 + 8] = 4;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    // положительный контроль на всех допустимых значениях
    for s in 0..=2u8 {
        let mut x = b.clone();
        x[o.state] = s;
        assert!(decode(&x).is_ok());
    }
    for s in 0..=6u8 {
        let mut x = b.clone();
        x[addr0 + 1 + 4 + 2] = s;
        assert!(decode(&x).is_ok());
    }
    // роль pending
    let mut raw = vec![2u8, 0, 0, 0, 1];
    raw.extend_from_slice(&[9u8; 16]);
    raw.push(2);
    raw.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(decode(&raw).err(), Some(FriendsError::Corrupt));
    let at = raw.len() - 9;
    raw[at] = 1;
    assert!(decode(&raw).is_ok());
    // версия открытого текста
    let mut x = b.clone();
    x[0] = 4;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    // автоприём с нулевыми лимитами: запись отказывает, разбор отказывает
    let mut d = BookData {
        epoch: 0,
        friends: vec![friend(1)],
        pending: vec![],
    };
    d.friends[0].permission = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 0,
        max_files: 5,
    });
    assert_eq!(encode(&d).err(), Some(FriendsError::InvalidLimits));
    d.friends[0].permission = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 5,
        max_files: 0,
    });
    assert_eq!(encode(&d).err(), Some(FriendsError::InvalidLimits));
    d.friends[0].permission = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 5,
        max_files: 5,
    });
    let mut x = bytes_of(&d);
    let o = off(d.friends[0].name.len());
    assert_eq!(x[o.perm], 1);
    x[o.perm + 1..o.perm + 9].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
}

#[test]
fn plain_rejects_trailing() {
    let b = bytes_of(&sample());
    for extra in 1..=8usize {
        let mut x = b.clone();
        x.extend(std::iter::repeat_n(0u8, extra));
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    }
    // любая обрезка: ошибка
    for n in 0..b.len() {
        assert!(decode(&b[..n]).is_err(), "обрезка до {n}");
    }
    assert_eq!(decode(&[]).err(), Some(FriendsError::Corrupt));
}

/// Открытый текст v1, собранный руками: старая раскладка (без `addr_seq_out`, байт
/// short_lived 0|1 после `last_seen`).
pub(super) fn v1_blob(f: &crate::Friend) -> Vec<u8> {
    let mut b = vec![1u8, 0, 1];
    b.extend_from_slice(f.pair.as_bytes());
    b.push(f.name.len() as u8);
    b.extend_from_slice(f.name.as_bytes());
    b.extend_from_slice(&f.friend_ed.to_bytes());
    b.extend_from_slice(&f.friend_x.to_bytes());
    b.extend_from_slice(&f.our_ed.to_bytes());
    b.push(0); // Active
    b.push(0); // Ask
    b.extend_from_slice(&f.last_addr_seq.to_be_bytes());
    b.extend_from_slice(&f.added_at_unix.to_be_bytes());
    b.push(f.known_addrs.len() as u8);
    for a in &f.known_addrs {
        match a.addr {
            std::net::SocketAddr::V4(v) => {
                b.push(4);
                b.extend_from_slice(&v.ip().octets());
            }
            std::net::SocketAddr::V6(v) => {
                b.push(6);
                b.extend_from_slice(&v.ip().octets());
            }
        }
        b.extend_from_slice(&a.addr.port().to_be_bytes());
        b.push(match a.source {
            AddrSource::Invite => 3,
            AddrSource::ObservedByFriend => 5,
            _ => 0,
        });
        b.extend_from_slice(&a.last_seen_unix.to_be_bytes());
        b.push(u8::from(a.short_lived));
    }
    b.extend_from_slice(&[0, 0]); // n_pending
    b
}

#[test]
fn plain_v1_migrates() {
    let mut f = friend(1);
    f.name = "abc".into();
    let v1 = v1_blob(&f);
    let d = decode(&v1).unwrap();
    assert_eq!(d.friends.len(), 1);
    let g = &d.friends[0];
    assert_eq!(g.last_addr_seq, 7);
    assert_eq!(g.addr_seq_out, 0, "v1 не знает addr_seq_out");
    assert_eq!(g.known_addrs.len(), 2);
    assert!(g.known_addrs.iter().all(|a| !a.hint));
    assert!(!g.known_addrs[0].short_lived && g.known_addrs[1].short_lived);
    assert_eq!(g.known_addrs[0].source, AddrSource::Invite);
    assert_eq!(g.known_addrs[1].source, AddrSource::ObservedByFriend);
    // запись всегда v3; повторное чтение даёт те же данные
    let again = bytes_of(&d);
    assert_eq!(again[0], 3);
    assert_eq!(d.epoch, 0);
    assert_eq!(
        again.len(),
        v1.len() + 8 + 8,
        "добавлены только addr_seq_out и epoch"
    );
    assert!(same(&decode(&again).unwrap(), &d));
    assert_eq!(bytes_of(&decode(&again).unwrap()), again);
    // v1 строже: источник 6, байт short_lived 2 и обрезки отклоняются
    let at_src = v1.len() - 2 - 1 - 8 - 1; // источник последнего адреса
    assert_eq!(v1[at_src], 5);
    let mut x = v1.clone();
    x[at_src] = 6;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    let mut x = v1.clone();
    let last_flag = v1.len() - 3;
    assert_eq!(v1[last_flag], 1);
    x[last_flag] = 2;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    for n in 0..v1.len() {
        assert!(decode(&v1[..n]).is_err(), "обрезка v1 до {n}");
    }
    let mut x = v1.clone();
    x.push(0);
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
}

#[test]
fn plain_v2_roundtrip_new_fields() {
    let mut d = BookData {
        epoch: 0,
        friends: vec![friend(1)],
        pending: vec![],
    };
    d.friends[0].name = "abc".into();
    d.friends[0].addr_seq_out = u64::MAX - 3;
    d.friends[0].known_addrs = vec![
        KnownAddr {
            addr: addr("203.0.113.7:1"),
            source: AddrSource::Contact,
            last_seen_unix: 5,
            short_lived: false,
            hint: true,
        },
        KnownAddr {
            addr: addr("[2001:db8::2]:2"),
            source: AddrSource::AddressUpdate,
            last_seen_unix: 6,
            short_lived: true,
            hint: true,
        },
        KnownAddr {
            addr: addr("198.51.100.1:3"),
            source: AddrSource::Contact,
            last_seen_unix: 7,
            short_lived: true,
            hint: false,
        },
    ];
    let b = bytes_of(&d);
    assert_eq!(b[0], 3);
    let back = decode(&b).unwrap();
    assert!(same(&d, &back));
    assert_eq!(back.friends[0].addr_seq_out, u64::MAX - 3);
    assert_eq!(bytes_of(&back), b);
    // флаги: bit0 = short_lived, bit1 = hint
    let o = off(3);
    let addr0 = o.perm + 1 + 8 + 8 + 8 + 1;
    let flags_at = |i: usize| match i {
        0 => addr0 + 1 + 4 + 2 + 1 + 8,
        1 => addr0 + 17 + 1 + 16 + 2 + 1 + 8,
        _ => addr0 + 17 + 29 + 1 + 4 + 2 + 1 + 8,
    };
    assert_eq!(b[flags_at(0)], 2);
    assert_eq!(b[flags_at(1)], 3);
    assert_eq!(b[flags_at(2)], 1);
}

#[test]
fn plain_v2_rejects_bad_flags() {
    let (_d, b, o) = one_friend();
    let flags0 = o.perm + 1 + 8 + 8 + 8 + 1 + 1 + 4 + 2 + 1 + 8;
    assert_eq!(b[flags0], 0);
    for v in 0..=3u8 {
        let mut x = b.clone();
        x[flags0] = v;
        assert!(decode(&x).is_ok(), "флаги {v}");
    }
    for bit in 2..8u8 {
        for extra in [0u8, 1, 2, 3] {
            let mut x = b.clone();
            x[flags0] = (1 << bit) | extra;
            assert_eq!(
                decode(&x).err(),
                Some(FriendsError::Corrupt),
                "бит {bit} + {extra}"
            );
        }
    }
}

#[test]
fn plain_v2_rejects_source_7() {
    let (_d, b, o) = one_friend();
    let src0 = o.perm + 1 + 8 + 8 + 8 + 1 + 1 + 4 + 2;
    for s in 0..=6u8 {
        let mut x = b.clone();
        x[src0] = s;
        assert!(decode(&x).is_ok(), "источник {s}");
    }
    for s in [7u8, 8, 0x7F, 0xFF] {
        let mut x = b.clone();
        x[src0] = s;
        assert_eq!(
            decode(&x).err(),
            Some(FriendsError::Corrupt),
            "источник {s}"
        );
    }
}

/// v2 из v3-кодировки данных без `Retired` и с `epoch = 0`: версия 2, без поля `epoch`.
fn v2_of(d: &BookData) -> Vec<u8> {
    assert_eq!(d.epoch, 0);
    assert!(d.friends.iter().all(|f| f.retired.is_none()));
    let v3 = bytes_of(d);
    let mut v = vec![2u8];
    v.extend_from_slice(&v3[9..]);
    v
}

#[test]
fn plain_v2_upgrades_to_v3() {
    let mut d = sample();
    d.epoch = 0;
    d.friends.retain(|f| f.retired.is_none());
    let v3 = bytes_of(&d);
    let v2 = v2_of(&d);
    assert_eq!(v2[0], 2);
    assert_eq!(v2.len() + 8, v3.len(), "в v3 добавлен только epoch");
    let back = decode(&v2).unwrap();
    assert!(same(&d, &back));
    assert_eq!(back.epoch, 0, "v2 не знает epoch");
    assert!(back.friends.iter().all(|f| f.retired.is_none()));
    // запись даёт канонический v3, он читается и пишется байт в байт
    assert_eq!(bytes_of(&back), v3);
    assert_eq!(bytes_of(&decode(&v3).unwrap()), v3);
    // v2 строгий: состояния 3 (`Retired`) в нём нет
    let (d1, _b, o) = one_friend();
    let x2 = v2_of(&d1);
    assert!(decode(&x2).is_ok());
    let mut x = x2.clone();
    x[o.state - 8] = 3;
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    for n in 0..v2.len() {
        assert!(decode(&v2[..n]).is_err(), "обрезка v2 до {n}");
    }
}

#[test]
fn plain_v3_retired_roundtrip_and_strict() {
    let f = retired_friend(5, RevocationReason::Removed);
    let d = BookData {
        epoch: 9,
        friends: vec![f.clone(), friend(6)],
        pending: vec![],
    };
    let b = bytes_of(&d);
    assert_eq!(b[0], 3);
    let back = decode(&b).unwrap();
    assert!(same(&d, &back));
    assert_eq!(back.epoch, 9);
    assert_eq!(bytes_of(&back), b, "v3 байт в байт");
    for n in 0..b.len() {
        assert!(decode(&b[..n]).is_err(), "обрезка до {n}");
    }
    // запись: состояние и запись об отзыве согласованы, текст разбирается как отзыв нашего ключа
    let enc = |g: &crate::Friend| {
        encode(&BookData {
            epoch: 0,
            friends: vec![g.clone()],
            pending: vec![],
        })
        .err()
    };
    let mut g = f.clone();
    g.retired = None;
    assert_eq!(enc(&g), Some(FriendsError::Corrupt));
    let mut g = friend(7);
    g.retired = f.retired.clone();
    assert_eq!(enc(&g), Some(FriendsError::Corrupt));
    let mut g = f.clone();
    g.retired.as_mut().unwrap().reason = RevocationReason::Rekey;
    assert_eq!(enc(&g), Some(FriendsError::BadRevocation));
    let mut g = f.clone();
    g.our_ed = friend(8).our_ed;
    assert_eq!(enc(&g), Some(FriendsError::BadRevocation));
    let mut g = f.clone();
    g.retired.as_mut().unwrap().revocation = "CHR1AAAA".into();
    assert_eq!(enc(&g), Some(FriendsError::BadRevocation));
    let mut g = f.clone();
    g.retired.as_mut().unwrap().revocation = "A".repeat(3000);
    assert_eq!(enc(&g), Some(FriendsError::BadRevocation));
    // разбор: причина, длина и каждый символ текста
    let o = off(f.name.len());
    let text_len = f.retired.as_ref().unwrap().revocation.len();
    assert_eq!(b[o.state], 3);
    assert_eq!(
        usize::from(u16::from_be_bytes([b[o.state + 2], b[o.state + 3]])),
        text_len
    );
    for v in [0u8, 3, 0xFF] {
        let mut x = b.clone();
        x[o.state + 1] = v;
        assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt), "причина {v}");
    }
    let mut x = b.clone();
    x[o.state + 1] = 1; // Rekey вместо Removed: не совпадает с подписанным текстом
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
    for i in 0..text_len {
        let mut x = b.clone();
        x[o.state + 4 + i] ^= 0x01;
        assert!(decode(&x).is_err(), "символ {i}");
    }
    // чужой our_ed
    let mut x = b.clone();
    let other = friend(9).our_ed.to_bytes();
    x[o.our_ed..o.our_ed + 32].copy_from_slice(&other);
    assert_eq!(decode(&x).err(), Some(FriendsError::Corrupt));
}
