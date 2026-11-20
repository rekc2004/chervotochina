//! Привязка сокета узла к петле (этап 18е, п.1). Только для тестов: файл подключается за
//! `cfg(any(test, feature = "test-net"))`, в продуктовой сборке (GUI, CLI, релиз) его нет вовсе
//! и узел всегда слушает `0.0.0.0`. Причина: тестовый бинарь, открывший UDP на `0.0.0.0`,
//! заставляет Windows показывать окно «Разрешить доступ» при каждой пересборке.
//!
//! Переключатель общий на процесс: в тестовом процессе все узлы тестовые. Включают его
//! тестовые точки открытия узла из `testing.rs` и `bind_loopback_only` (для `first_run_setup`, который
//! выбирает порт до открытия узла).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

static LOOPBACK: AtomicBool = AtomicBool::new(false);

/// Дальше узлы этого процесса слушают только `127.0.0.1`, а `pick_port` проверяет порт там же.
pub fn bind_loopback_only() {
    LOOPBACK.store(true, Ordering::SeqCst);
}

pub(super) fn is_on() -> bool {
    LOOPBACK.load(Ordering::SeqCst)
}

/// Адрес привязки сокета узла в тестовой сборке.
pub(super) fn listen_ip() -> Ipv4Addr {
    if is_on() {
        Ipv4Addr::LOCALHOST
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}
