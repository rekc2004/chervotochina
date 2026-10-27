//! Вшитые ключи владельца. Тест под `#[ignore]`: пока файлы `keys/primary.pub` и
//! `keys/backup.pub` пусты, он падает. Release-workflow (19б) запускает его с
//! `--include-ignored`, поэтому выпуск без ключей владельца невозможен.

use chervo_update::{KeyRole, KeySet};

#[test]
#[ignore = "ключи владельца ещё не вшиты; release-workflow запускает с --include-ignored"]
fn embedded_keys_ready() {
    let keys = KeySet::embedded().expect("вшитые ключи разбираются");
    let list = keys.list();
    assert_eq!(list.len(), 2, "нужны оба ключа: основной и запасной");
    assert!(list.iter().any(|(r, _, _)| *r == KeyRole::Primary));
    assert!(list.iter().any(|(r, _, _)| *r == KeyRole::Backup));
    assert_ne!(list[0].1, list[1].1, "key_id должны различаться");
    assert_ne!(list[0].2, list[1].2, "ключи должны различаться");
}
