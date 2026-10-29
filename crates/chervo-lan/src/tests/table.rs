//! Тесты таблицы меток (`table.rs`).

use chervo_identity::{LAN_ID_LEN, LAN_NONCE_LEN};

use super::{PORT, SRC, W, fixture};
use crate::table::IdTable;

#[test]
fn table_collision_fail_closed() {
    let mut fx = fixture(3);
    let recv = std::mem::take(&mut fx.receiver);
    // пары 0 и 1 получают одинаковые метки во всех окнах; пара 2 свои
    let same = |i: usize, w: u64| -> [u8; LAN_ID_LEN] {
        let mut id = [0u8; LAN_ID_LEN];
        id[0] = if i == 2 { 2 } else { 1 };
        id[1..].copy_from_slice(&w.to_be_bytes()[1..]);
        id
    };
    let t = IdTable::from_peers_with(recv, W, &same);
    assert_eq!(t.collisions(), 3, "по метке на каждое из трёх окон");
    assert_eq!(t.id_count(), 3, "остались только метки третьей пары");
    for w in [W - 1, W, W + 1] {
        assert!(!t.contains_id(&same(0, w)));
        assert!(t.contains_id(&same(2, w)));
    }
}

#[test]
fn table_rebuild_on_window() {
    let mut fx = fixture(2);
    let mut t = fx.table(W);
    assert_eq!(t.window(), W);
    assert_eq!(t.peer_count(), 2);
    assert_eq!(t.id_count(), 6, "2 пары * 3 окна");
    let hit = |t: &IdTable, w: u64| -> usize {
        fx.sender
            .iter()
            .filter(|(_, k)| t.contains_id(&k.send_id(w)))
            .count()
    };
    for w in [W - 1, W, W + 1] {
        assert_eq!(hit(&t, w), 2, "окно {w}");
    }
    assert_eq!(hit(&t, W - 2), 0);
    assert_eq!(hit(&t, W + 2), 0);
    t.rebuild(W + 1);
    assert_eq!(t.window(), W + 1);
    assert_eq!(hit(&t, W - 1), 0, "старое окно ушло");
    assert_eq!(hit(&t, W + 2), 2, "новое окно пришло");
    // край диапазона не ломает таблицу
    t.rebuild(0);
    assert_eq!(t.id_count(), 4, "окна 0 и 1: 2 пары * 2");
    t.rebuild(u64::MAX);
    assert_eq!(t.id_count(), 4);
}

#[test]
fn table_set_peers_limits_and_dedup() {
    let fx = fixture(2);
    let extra = fixture(1);
    let first = fx.receiver[0].0;
    let mut list = fx.receiver;
    let (_, k) = extra.receiver.into_iter().next().unwrap();
    list.push((first, k));
    let mut t = IdTable::empty();
    t.set_peers(list, W);
    assert_eq!(t.peer_count(), 2, "повтор пары отброшен");
    assert_eq!(t.id_count(), 6);
}

#[test]
fn table_open_slot_only_on_hit() {
    let mut fx = fixture(1);
    let slot = fx.sender[0]
        .1
        .seal(W, &[3; LAN_NONCE_LEN], SRC, PORT)
        .unwrap();
    let t = fx.table(W);
    assert_eq!(t.opens(), 0);
    assert!(t.open_slot(&[3; LAN_NONCE_LEN], SRC, &slot).is_some());
    assert_eq!(t.opens(), 1);
    let mut rnd = slot;
    rnd[0] ^= 0xFF;
    assert!(t.open_slot(&[3; LAN_NONCE_LEN], SRC, &rnd).is_none());
    assert_eq!(t.opens(), 1, "нет метки: нет вызова AEAD");
}
