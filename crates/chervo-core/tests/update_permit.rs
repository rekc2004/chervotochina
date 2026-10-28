#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Разрешение на проверку новых версий (этап 19г-1, Р19г-5 и Р19г-6): без согласия его нет,
//! время пишется до запроса, часы назад не дают запроса. Сети тут нет: разрешение только
//! выдаётся, `check_latest` не вызывается.

#[path = "support/harness.rs"]
mod harness;

use std::path::PathBuf;
use std::time::Duration;

use chervo_core::update::{MANUAL_CHECK_FLOOR_SECS, UPDATE_CHECK_INTERVAL_SECS, UpdateConsent};
use chervo_core::{Node, NodeError};
use harness::Rig;

const DAY: u64 = UPDATE_CHECK_INTERVAL_SECS;
const T0: u64 = 1_700_000_000;

fn settings_bytes(rig: &Rig) -> Vec<u8> {
    std::fs::read(rig.data.join("settings.v1")).unwrap()
}

fn recorded_time(rig: &Rig) -> String {
    String::from_utf8(settings_bytes(rig))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("update_checked_at=").map(str::to_owned))
        .expect("в файле нет update_checked_at")
}

fn stop(node: Node) {
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn update_consent_defaults_to_not_asked_and_persists() {
    let rig = Rig::new("upd-consent");
    let (node, _ev) = rig.start();
    assert_eq!(node.settings().update_consent, UpdateConsent::NotAsked);
    assert!(
        !String::from_utf8(settings_bytes(&rig))
            .unwrap()
            .contains("update_check="),
        "до ответа строки согласия нет"
    );
    node.set_update_consent(true).unwrap();
    assert_eq!(node.settings().update_consent, UpdateConsent::Enabled);
    node.set_update_consent(false).unwrap();
    assert_eq!(node.settings().update_consent, UpdateConsent::Disabled);
    stop(node);
    // после перезапуска ответ на месте
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().update_consent, UpdateConsent::Disabled);
    node.set_update_consent(true).unwrap();
    stop(node);
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().update_consent, UpdateConsent::Enabled);
    stop(node);
}

#[test]
fn update_permit_requires_consent() {
    let rig = Rig::new("upd-noconsent");
    let (node, _ev) = rig.start();
    let nows = [0, 1, T0, T0 + DAY * 400, u64::MAX];
    // NotAsked
    let before = settings_bytes(&rig);
    for manual in [false, true] {
        for now in nows {
            assert!(
                node.update_check_permit(now, manual).unwrap().is_none(),
                "NotAsked: разрешение выдано (manual={manual}, now={now})"
            );
        }
    }
    assert_eq!(settings_bytes(&rig), before, "NotAsked: файл изменился");
    // Disabled
    node.set_update_consent(false).unwrap();
    let before = settings_bytes(&rig);
    for manual in [false, true] {
        for now in nows {
            assert!(
                node.update_check_permit(now, manual).unwrap().is_none(),
                "Disabled: разрешение выдано (manual={manual}, now={now})"
            );
        }
    }
    assert_eq!(settings_bytes(&rig), before, "Disabled: файл изменился");
    stop(node);
}

#[test]
fn update_permit_records_time_before_request() {
    let rig = Rig::new("upd-record");
    let (node, _ev) = rig.start();
    node.set_update_consent(true).unwrap();
    assert_eq!(recorded_time(&rig), "0");
    // первое разрешение: время уже в файле, хотя запроса не было и нет
    let p = node.update_check_permit(T0, false).unwrap();
    assert!(p.is_some());
    assert_eq!(recorded_time(&rig), T0.to_string());
    let _lost = p; // запрос не выполнен, потерянное разрешение повтора не вызывает
    let after = settings_bytes(&rig);
    // фон: до суток отказ, файл не меняется
    for now in [T0, T0 + 3600, T0 + DAY - 1] {
        assert!(node.update_check_permit(now, false).unwrap().is_none());
    }
    assert_eq!(settings_bytes(&rig), after);
    // кнопка: меньше минуты отказ, минута проходит
    assert!(
        node.update_check_permit(T0 + MANUAL_CHECK_FLOOR_SECS - 1, true)
            .unwrap()
            .is_none()
    );
    assert_eq!(settings_bytes(&rig), after);
    assert!(
        node.update_check_permit(T0 + MANUAL_CHECK_FLOOR_SECS, true)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        recorded_time(&rig),
        (T0 + MANUAL_CHECK_FLOOR_SECS).to_string()
    );
    // ровно сутки после последней записи: фон проходит
    let last = T0 + MANUAL_CHECK_FLOOR_SECS;
    assert!(
        node.update_check_permit(last + DAY - 1, false)
            .unwrap()
            .is_none()
    );
    assert!(
        node.update_check_permit(last + DAY, false)
            .unwrap()
            .is_some()
    );
    assert_eq!(recorded_time(&rig), (last + DAY).to_string());
    stop(node);
    // время переживает перезапуск: сразу после открытия фон не проходит
    let (node, _ev) = rig.open().unwrap();
    assert!(
        node.update_check_permit(last + DAY + 10, false)
            .unwrap()
            .is_none()
    );
    stop(node);
}

#[test]
fn update_permit_clock_back_records_only() {
    let rig = Rig::new("upd-clockback");
    let (node, _ev) = rig.start();
    node.set_update_consent(true).unwrap();
    assert!(node.update_check_permit(T0, false).unwrap().is_some());
    // часы ушли назад: запроса нет, но новое время записано, срок считается от него
    let back = T0 - 5 * DAY;
    assert!(node.update_check_permit(back, false).unwrap().is_none());
    assert_eq!(recorded_time(&rig), back.to_string());
    assert!(
        node.update_check_permit(back + DAY - 1, false)
            .unwrap()
            .is_none()
    );
    assert!(
        node.update_check_permit(back + DAY, false)
            .unwrap()
            .is_some()
    );
    // кнопка при ушедших назад часах проходит и тоже записывает время
    assert!(
        node.update_check_permit(back - 100, true)
            .unwrap()
            .is_some()
    );
    assert_eq!(recorded_time(&rig), (back - 100).to_string());
    stop(node);
}

#[test]
fn update_permit_write_error_means_no_permit() {
    let rig = Rig::new("upd-writeerr");
    let (node, _ev) = rig.start();
    node.set_update_consent(true).unwrap();
    // каталог на месте временного файла: запись настроек невозможна
    let blocker: PathBuf = rig.data.join("settings.v1.tmp");
    std::fs::create_dir(&blocker).unwrap();
    let before = settings_bytes(&rig);
    let r = node.update_check_permit(T0, false);
    assert_eq!(r.err(), Some(NodeError::Io), "ошибка записи это Err");
    assert_eq!(settings_bytes(&rig), before);
    // состояние в памяти тоже не продвинулось: после снятия помехи разрешение выдаётся
    std::fs::remove_dir(&blocker).unwrap();
    assert!(node.update_check_permit(T0, false).unwrap().is_some());
    assert_eq!(recorded_time(&rig), T0.to_string());
    stop(node);
}
