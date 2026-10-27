//! `chervo doctor`: только чтение. Открывает хранилище ключей ОС и читает счётчик (`read_epoch`).
//! Окно пароля не показывает, ничего не пишет, программ не запускает (решение владельца Q2:
//! разблокировка только по кнопке).

use chervo_core::chervo_identity::{EpochStore, IdentityError, OsKeyStore};
use std::io::Write;

const AVAILABLE: &str = "хранилище ключей доступно";
const LOCKED: &str = "хранилище заблокировано: разблокируйте (инструкция: docs/INSTALL.md)";

#[cfg(target_os = "linux")]
const UNAVAILABLE: &str = "хранилище ключей недоступно: установите и запустите Secret Service, \
например: sudo apt install gnome-keyring dbus-user-session (инструкция: docs/HEADLESS_LINUX.md)";
#[cfg(target_os = "macos")]
const UNAVAILABLE: &str = "хранилище ключей недоступно: проверьте связку ключей (Keychain Access), устанавливать ничего не нужно";
#[cfg(target_os = "windows")]
const UNAVAILABLE: &str = "хранилище ключей недоступно: проверьте Диспетчер учётных данных Windows, устанавливать ничего не нужно";
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const UNAVAILABLE: &str = "хранилище ключей недоступно на этой ОС";

/// Строка итога и код возврата по результату чтения.
fn classify<T>(result: &Result<T, IdentityError>) -> (&'static str, u8) {
    match result {
        Ok(_) => (AVAILABLE, 0),
        Err(IdentityError::StorageLocked) => (LOCKED, 1),
        Err(_) => (UNAVAILABLE, 1),
    }
}

pub fn doctor(args: &[std::ffi::OsString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if !args.is_empty() {
        let _ = writeln!(err, "использование: chervo doctor");
        return 2;
    }
    let result = OsKeyStore::open().and_then(|store| store.read_epoch());
    let (line, code) = classify(&result);
    let _ = writeln!(out, "{line}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_errors() {
        assert_eq!(
            classify(&Ok::<_, IdentityError>(None::<u64>)),
            (AVAILABLE, 0)
        );
        assert_eq!(
            classify::<()>(&Err(IdentityError::StorageLocked)),
            (LOCKED, 1)
        );
        assert_eq!(
            classify::<()>(&Err(IdentityError::StorageUnavailable)),
            (UNAVAILABLE, 1)
        );
        assert_eq!(
            classify::<()>(&Err(IdentityError::StorageInconsistent)),
            (UNAVAILABLE, 1)
        );
    }

    #[test]
    fn extra_args_is_usage_error() {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let args = [std::ffi::OsString::from("x")];
        assert_eq!(doctor(&args, &mut o, &mut e), 2);
        assert!(o.is_empty());
    }
}
