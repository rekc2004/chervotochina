#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Узел без сети между двумя узлами (этап 18а, критерии A1-A3): первый запуск, замок
//! единственного экземпляра, сопоставление ошибок открытия, явное «принять старый список»,
//! предел вставляемого текста, сверка часов, предупреждение о якоре.

#[path = "support/harness.rs"]
mod harness;

use std::sync::atomic::Ordering;
use std::time::Duration;

use chervo_core::{
    ClockSync, FriendStatus, Node, NodeError, NodeEvent, NodeWarning, SyncError, TestOpen,
    TrustConfirmation,
};
use chervo_timesync::ClockOffset;
use harness::{Rig, hardened, seed_one_friend, wait_event};

const SHORT: Duration = Duration::from_millis(1500);

fn offset(ms: i64) -> ClockOffset {
    ClockOffset {
        offset_ms: ms,
        valid: 3,
        queried: 4,
    }
}

#[test]
fn first_run_needs_setup_then_opens() {
    let rig = Rig::new("firstrun");
    assert_eq!(rig.open().err(), Some(NodeError::FirstRun));
    rig.setup();
    let (node, _ev) = rig.open().unwrap();
    let s = node.settings();
    assert_eq!(s.port, rig.port);
    assert!(!s.restart_needed);
    assert_eq!(s.min_free_percent, 10);
    assert_eq!(s.invite_ttl_secs, 900);
    assert!(s.routers.is_empty());
    assert!(node.friends().is_empty());
    assert!(node.transfers().is_empty());
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn first_run_creates_no_keys() {
    let rig = Rig::new("nokeys");
    rig.setup();
    assert_eq!(
        rig.store.write_count(),
        0,
        "first_run_setup пишет в хранилище"
    );
    let (node, ev) = rig.open().unwrap();
    // снимки и диагностика ключей не создают
    let _ = node.friends();
    let _ = node.transfers();
    let _ = node.settings();
    let _ = node.nat_view();
    let _ = node.mapping_status();
    node.refresh_mapping();
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(rig.store.write_count(), 0, "узел записал ключ без действия");
    assert_eq!(rig.store.pair_count(), 0);
    assert!(!rig.store.has_list_key());
    assert_eq!(rig.store.epoch_value(), None);
    assert!(!rig.data.join("friends.chfl").exists());
    drop(ev);
    node.shutdown(Duration::from_secs(5));
    assert_eq!(rig.store.write_count(), 0);
}

#[test]
fn instance_lock_second_open_refused() {
    let rig = Rig::new("lock");
    let (node, _ev) = rig.start();
    assert_eq!(rig.open().err(), Some(NodeError::AlreadyRunning));
    let cfg = rig.cfg();
    assert_eq!(
        Node::first_run_setup(&cfg, &hardened(), &rig.recv, false).err(),
        Some(NodeError::AlreadyRunning)
    );
    assert_eq!(
        Node::reset_settings(&cfg, &hardened()).err(),
        Some(NodeError::AlreadyRunning)
    );
    node.shutdown(Duration::from_secs(5));
    // замок снят: можно открыть снова
    let (again, _ev) = rig.open().unwrap();
    again.shutdown(Duration::from_secs(5));
}

#[test]
fn drop_without_shutdown_releases_everything() {
    let rig = Rig::new("drop");
    let (node, _ev) = rig.start();
    drop(node);
    let (again, _ev) = rig.open().unwrap();
    again.shutdown(Duration::from_secs(5));
}

#[test]
fn settings_corrupt_is_kept_and_reset_keeps_a_copy() {
    let rig = Rig::new("corrupt");
    rig.setup();
    let file = rig.data.join("settings.v1");
    let mut bytes = std::fs::read(&file).unwrap();
    bytes.extend_from_slice(b"surprise=1\n");
    std::fs::write(&file, &bytes).unwrap();
    assert_eq!(rig.open().err(), Some(NodeError::SettingsCorrupt));
    assert_eq!(std::fs::read(&file).unwrap(), bytes, "файл переписан молча");
    Node::reset_settings(&rig.cfg(), &hardened()).unwrap();
    assert!(!file.exists());
    let kept: Vec<_> = std::fs::read_dir(&rig.data)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("settings.v1.bad-")
        })
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::read(kept[0].path()).unwrap(), bytes);
    assert_eq!(rig.open().err(), Some(NodeError::FirstRun));
}

#[test]
fn open_maps_key_store_locked() {
    let rig = Rig::new("locked");
    rig.setup();
    rig.store.locked.store(true, Ordering::SeqCst);
    // файла списка нет, но чтение ключа списка уже упирается в закрытое хранилище
    assert_eq!(rig.open().err(), Some(NodeError::KeyStoreLocked));
    rig.store.locked.store(false, Ordering::SeqCst);
    let (node, _ev) = rig.open().unwrap();
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn open_maps_rolled_back() {
    let rig = Rig::new("rolled");
    rig.setup();
    seed_one_friend(&rig, "Анна");
    rig.store.set_epoch(Some(5));
    assert_eq!(rig.open().err(), Some(NodeError::RolledBack));
    // обычное открытие якорь не понижает
    assert_eq!(rig.store.epoch_value(), Some(5));
}

#[test]
fn open_maps_list_key_missing_to_keys_lost() {
    let rig = Rig::new("keyslost");
    rig.setup();
    seed_one_friend(&rig, "Анна");
    rig.store.drop_list_key();
    assert_eq!(rig.open().err(), Some(NodeError::KeysLost));
    // само по себе ничего не создаётся и не удаляется
    assert!(rig.data.join("friends.chfl").exists());
    assert!(!rig.store.has_list_key());
    // явный выбор: начать заново, старый файл остаётся рядом
    let (node, _ev) = Node::open_with_store_for_tests_mode(
        rig.cfg(),
        &hardened(),
        rig.store.backend(),
        TestOpen::StartOver,
    )
    .unwrap();
    assert!(node.friends().is_empty());
    node.shutdown(Duration::from_secs(5));
    let kept = std::fs::read_dir(&rig.data)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("friends.chfl.unreadable-")
        });
    assert!(kept, "старый список не сохранён");
}

#[test]
fn accept_older_only_explicit() {
    let rig = Rig::new("older");
    rig.setup();
    seed_one_friend(&rig, "Анна");
    rig.store.set_epoch(Some(5));
    assert_eq!(rig.open().err(), Some(NodeError::RolledBack));
    assert_eq!(rig.store.epoch_value(), Some(5));
    let (node, _ev) = Node::open_with_store_for_tests_mode(
        rig.cfg(),
        &hardened(),
        rig.store.backend(),
        TestOpen::AcceptOlder,
    )
    .unwrap();
    assert_eq!(node.friends().len(), 1);
    node.shutdown(Duration::from_secs(5));
    // якорь теперь равен счётчику файла, обычное открытие проходит
    assert_eq!(rig.store.epoch_value(), Some(1));
    let (node, _ev) = rig.open().unwrap();
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn token_input_caps() {
    let rig = Rig::new("caps");
    let (node, _ev) = rig.start();
    let long = "a".repeat(4097);
    let exact = "a".repeat(4096);
    assert_eq!(
        node.accept_invite(&long).err(),
        Some(NodeError::InputTooLong)
    );
    assert_eq!(
        node.apply_addr_update_text(&long).err(),
        Some(NodeError::InputTooLong)
    );
    assert_eq!(
        node.apply_revocation_text(&long).err(),
        Some(NodeError::InputTooLong)
    );
    // ровно 4096 байт доходят до разбора и отвергаются им, а не пределом
    let e = node.accept_invite(&exact).err().unwrap();
    assert_ne!(e, NodeError::InputTooLong);
    assert!(matches!(e, NodeError::Connect(_)), "{e:?}");
    let e = node.apply_revocation_text(&exact).err().unwrap();
    assert!(matches!(e, NodeError::Friends(_)), "{e:?}");
    // пробелы по краям не считаются
    let padded = format!("{}x{}", " ".repeat(5000), " ".repeat(5000));
    assert_ne!(
        node.accept_invite(&padded).err(),
        Some(NodeError::InputTooLong)
    );
    // ошибка не повторяет ввод
    let shown = format!("{} {:?}", e, e);
    assert!(!shown.contains("aaaa"));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn clock_over_5_min_needs_confirm() {
    let rig = Rig::new("clock");
    let (node, _ev) = rig.start();
    // до 5 минут: применяется и сохраняется
    let r = node.clock_result_for_tests(Ok(offset(299_999))).unwrap();
    assert_eq!(r, ClockSync::Applied { offset_ms: 299_999 });
    assert_eq!(node.settings().clock_offset_ms, 299_999);
    assert!(node.settings().clock_offset_at > 0);
    // больше 5 минут: ничего не применено, пока человек не подтвердит
    let ClockSync::NeedsConfirm(p) = node.clock_result_for_tests(Ok(offset(-360_000))).unwrap()
    else {
        panic!("поправка больше 5 минут применена без подтверждения");
    };
    assert_eq!(p.offset_ms(), -360_000);
    assert_eq!(node.settings().clock_offset_ms, 299_999);
    node.confirm_clock(p).unwrap();
    assert_eq!(node.settings().clock_offset_ms, -360_000);
    // ошибка сверки проходит как есть
    assert_eq!(
        node.clock_result_for_tests(Err(SyncError::TooFewValid))
            .err(),
        Some(NodeError::Clock(SyncError::TooFewValid))
    );
    // за пределом в 7 суток подтверждение не помогает
    let ClockSync::NeedsConfirm(huge) = node
        .clock_result_for_tests(Ok(offset(8 * 24 * 3600 * 1000)))
        .unwrap()
    else {
        panic!("огромная поправка применена");
    };
    assert_eq!(
        node.confirm_clock(huge).err(),
        Some(NodeError::Clock(SyncError::TooLarge))
    );
    assert_eq!(node.settings().clock_offset_ms, -360_000);
    node.shutdown(Duration::from_secs(5));
    // поправка пережила перезапуск
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().clock_offset_ms, -360_000);
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn clock_reset() {
    let rig = Rig::new("clockreset");
    let (node, _ev) = rig.start();
    let ClockSync::NeedsConfirm(p) = node.clock_result_for_tests(Ok(offset(600_000))).unwrap()
    else {
        panic!("нужно подтверждение");
    };
    node.confirm_clock(p).unwrap();
    assert_eq!(node.settings().clock_offset_ms, 600_000);
    node.reset_clock().unwrap();
    let s = node.settings();
    assert_eq!((s.clock_offset_ms, s.clock_offset_at), (0, 0));
    node.shutdown(Duration::from_secs(5));
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().clock_offset_ms, 0);
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn settings_setters_persist_and_flag_restart() {
    let rig = Rig::new("setters");
    let (node, _ev) = rig.start();
    assert_eq!(node.set_port(80).err(), Some(NodeError::InvalidValue));
    assert_eq!(
        node.set_min_free_percent(101).err(),
        Some(NodeError::InvalidValue)
    );
    assert_eq!(
        node.set_manual_forward(Some(0)).err(),
        Some(NodeError::InvalidValue)
    );
    node.set_min_free_percent(25).unwrap();
    node.set_manual_forward(Some(50123)).unwrap();
    let new_port = harness::free_port();
    node.set_port(new_port).unwrap();
    let s = node.settings();
    assert!(s.restart_needed);
    assert_eq!(
        (s.min_free_percent, s.manual_forward, s.port),
        (25, Some(50123), new_port)
    );
    node.shutdown(Duration::from_secs(5));
    // после перезапуска значения на месте (порт из настроек, без переопределения)
    let mut cfg = rig.cfg();
    cfg.port_override = None;
    let (node, _ev) =
        Node::open_with_store_for_tests(cfg, &hardened(), rig.store.backend()).unwrap();
    let s = node.settings();
    assert!(!s.restart_needed);
    assert_eq!(
        (s.min_free_percent, s.manual_forward, s.port),
        (25, Some(50123), new_port)
    );
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn set_receive_root_keeps_the_old_one_as_extra() {
    let rig = Rig::new("roots");
    let (node, _ev) = rig.start();
    let second = rig.dir.join("recv2");
    std::fs::create_dir_all(&second).unwrap();
    node.set_receive_root(&second, false).unwrap();
    let s = node.settings();
    assert!(s.restart_needed);
    assert_eq!(s.extra_roots.len(), 1);
    // не папка: ошибка, настройки не тронуты
    let missing = rig.dir.join("no-such-folder");
    assert!(matches!(
        node.set_receive_root(&missing, false).err(),
        Some(NodeError::ReceiveRoot(_))
    ));
    node.shutdown(Duration::from_secs(5));
    // запуск с новой основной и прежней дополнительной
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().extra_roots.len(), 1);
    node.shutdown(Duration::from_secs(5));
    // исчезнувшая дополнительная папка: предупреждение, узел работает
    std::fs::remove_dir_all(&rig.recv).unwrap();
    let (node, ev) = rig.open().unwrap();
    let w = wait_event(&ev, SHORT, |e| match e {
        NodeEvent::Warning(w) => Some(*w),
        _ => None,
    });
    assert_eq!(w, Some(NodeWarning::RootUnavailable));
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn anchor_write_failure_is_a_warning_not_an_error() {
    let rig = Rig::new("anchor");
    rig.setup();
    let pair_seed = seed_one_friend(&rig, "Анна");
    let _ = pair_seed;
    let (node, ev) = rig.open().unwrap();
    let f = node.friends();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].state, FriendStatus::Active);
    let friend = f[0].friend;

    // блокировка при сломанной записи якоря: действие выполнено, предупреждение, не ошибка
    rig.store.fail_epoch_write.store(true, Ordering::SeqCst);
    node.block(friend).unwrap();
    assert_eq!(node.friends()[0].state, FriendStatus::Blocked);
    let w = wait_event(&ev, SHORT, |e| match e {
        NodeEvent::Warning(w) => Some(*w),
        _ => None,
    });
    assert_eq!(w, Some(NodeWarning::AnchorNotUpdated));
    assert_eq!(
        rig.store.epoch_value(),
        Some(1),
        "якорь не должен был обновиться"
    );

    // исправная запись: без предупреждения, якорь догнал файл
    rig.store.fail_epoch_write.store(false, Ordering::SeqCst);
    node.unblock(friend).unwrap();
    assert_eq!(node.friends()[0].state, FriendStatus::Active);
    assert!(
        wait_event(&ev, Duration::from_millis(400), |e| match e {
            NodeEvent::Warning(w) => Some(*w),
            _ => None,
        })
        .is_none()
    );
    assert_eq!(rig.store.epoch_value(), Some(3));

    // удаление при сломанной записи якоря: текст отзыва выдан, ключ пары убран
    rig.store.fail_epoch_write.store(true, Ordering::SeqCst);
    assert_eq!(rig.store.pair_count(), 1);
    let text = node.remove(friend).unwrap().expect("текст отзыва");
    assert!(!text.as_str().is_empty());
    assert_eq!(rig.store.pair_count(), 0, "ключ пары не удалён");
    let w = wait_event(&ev, SHORT, |e| match e {
        NodeEvent::Warning(w) => Some(*w),
        _ => None,
    });
    assert_eq!(w, Some(NodeWarning::AnchorNotUpdated));
    assert_eq!(node.retired().len(), 1);
    assert_eq!(node.friends()[0].state, FriendStatus::Retired);
    node.forget_retired(friend).unwrap();
    assert!(node.retired().is_empty());
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn auto_accept_needs_the_confirmation_value_and_persists() {
    let rig = Rig::new("auto");
    rig.setup();
    seed_one_friend(&rig, "Анна");
    let (node, _ev) = rig.open().unwrap();
    let friend = node.friends()[0].friend;
    assert!(!node.friends()[0].auto_accept);
    node.enable_auto_accept(friend, TrustConfirmation::user_confirmed_trust())
        .unwrap();
    assert!(node.friends()[0].auto_accept);
    node.disable_auto_accept(friend).unwrap();
    assert!(!node.friends()[0].auto_accept);
    node.shutdown(Duration::from_secs(5));
}

// ---------------------------------------------------------------- этап 13в: поиск в локальной сети

#[test]
fn lan_default_is_listen_and_mode_persists() {
    use chervo_core::LanMode;
    let rig = Rig::new("lan_mode");
    let (node, _ev) = rig.start();
    // решение В1: по умолчанию «только слушать», служба создана
    assert_eq!(node.settings().lan_mode, LanMode::Listen);
    assert!(node.lan_status().is_some());
    // выключили: настройка записана, служба остановлена, адресов нет
    node.set_lan_mode(LanMode::Off).unwrap();
    assert_eq!(node.settings().lan_mode, LanMode::Off);
    // состояние обновляет поток службы: в пределах нескольких сотен миллисекунд
    let end = std::time::Instant::now() + Duration::from_secs(3);
    while node.lan_status() != Some(chervo_core::LanStatus::Off) && std::time::Instant::now() < end
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(node.lan_status(), Some(chervo_core::LanStatus::Off));
    assert!(node.lan_addrs().is_empty());
    node.shutdown(Duration::from_secs(5));
    // и после перезапуска остаётся выключенным: службы нет вовсе (ни потока, ни сокетов)
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().lan_mode, LanMode::Off);
    assert_eq!(node.lan_status(), None);
    assert!(node.lan_addrs().is_empty());
    // включили снова: служба создаётся и подключается к движку
    node.set_lan_mode(LanMode::Listen).unwrap();
    assert_eq!(node.settings().lan_mode, LanMode::Listen);
    assert!(node.lan_status().is_some());
    node.shutdown(Duration::from_secs(5));
    let (node, _ev) = rig.open().unwrap();
    assert_eq!(node.settings().lan_mode, LanMode::Listen);
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn lan_off_no_socket() {
    use chervo_core::LanMode;
    let rig = Rig::new("lan_off");
    let (node, _ev) = rig.start();
    node.set_lan_mode(LanMode::Off).unwrap();
    node.shutdown(Duration::from_secs(5));
    let (node, _ev) = rig.open().unwrap();
    // режим «выключено» с самого запуска: служба не создана, значит нет ни потока, ни сокета
    assert_eq!(node.lan_status(), None);
    assert!(node.lan_addrs().is_empty());
    node.shutdown(Duration::from_secs(5));
}

#[test]
fn set_port_rejects_lan_port() {
    let rig = Rig::new("lan_port");
    let (node, _ev) = rig.start();
    let before = node.settings().port;
    assert_eq!(
        node.set_port(chervo_lan::LAN_PORT),
        Err(NodeError::PortInUse)
    );
    assert_eq!(node.settings().port, before, "порт не изменился");
    node.shutdown(Duration::from_secs(5));
}
