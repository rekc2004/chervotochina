//! `chervo check-update`: однократная явная проверка, вышла ли новая версия (этап 19д).
//!
//! Сам вызов команды согласие на один запрос к github.com. Ничего не сохраняется, браузер не
//! открывается, процессы не запускаются. Из ответа сети печатается только номер версии; адрес
//! страницы вшит в код (`RELEASES_PAGE`). Проверка передаётся функцией, чтобы тесты не ходили в сеть.

use std::ffi::OsString;
use std::io::Write;
use std::str::FromStr;

use chervo_update::{KeySet, Version};
use chervo_update_check::{CheckError, RELEASES_PAGE, UpdateStatus};

const USAGE: &str = "использование: chervo check-update";

/// Коды: 0 проверка выполнена (новая версия есть или её нет); 1 проверка невозможна или не
/// прошла; 2 ошибка использования.
///
/// `keys_embedded`: вшиты ли ключи владельца. Если нет, ничего не печатается о запросе и сети нет.
pub(crate) fn check_update(
    args: &[OsString],
    keys_embedded: bool,
    running: &str,
    check: impl FnOnce(Version) -> Result<UpdateStatus, CheckError>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if !args.is_empty() {
        let _ = writeln!(err, "chervo: лишние аргументы\n{USAGE}");
        return 2;
    }
    let Ok(running) = Version::from_str(running) else {
        let _ = writeln!(
            err,
            "Версия этой программы не разобрана: проверка невозможна."
        );
        return 1;
    };
    if !keys_embedded {
        let _ = writeln!(err, "Ключи владельца не вшиты: проверка невозможна.");
        return 1;
    }
    let _ = writeln!(
        out,
        "Проверка обновлений: запрос к github.com (GitHub увидит ваш IP-адрес)."
    );
    let _ = out.flush();
    match check(running) {
        Ok(UpdateStatus::Newer(v)) => {
            let _ = writeln!(
                out,
                "Вышла версия {v} (у вас {running}). Страница загрузки: {RELEASES_PAGE}. \
                 Скачанный файл проверьте: chervo verify-release <манифест> <подпись> <файл>."
            );
            0
        }
        Ok(UpdateStatus::UpToDate) => {
            let _ = writeln!(out, "Установлена последняя версия ({running}).");
            0
        }
        Err(CheckError::NoTrustedKeys) => {
            let _ = writeln!(err, "Ключи владельца не вшиты: проверка невозможна.");
            1
        }
        Err(CheckError::Network | CheckError::Timeout) => {
            let _ = writeln!(err, "Нет связи с GitHub.");
            1
        }
        // BadResponse, BadSignature и любые будущие варианты: ответ не принимаем
        Err(_) => {
            let _ = writeln!(err, "Ответ не прошёл проверку.");
            1
        }
    }
}

/// Вызов из `main`: вшитые ключи и настоящая сеть.
pub(crate) fn run(args: &[OsString]) -> u8 {
    check_update(
        args,
        KeySet::embedded().is_ok(),
        env!("CARGO_PKG_VERSION"),
        chervo_update_check::check_latest,
        &mut chervo_cli::out::main_sink(),
        &mut chervo_cli::out::err_sink(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    fn run_with(
        args: &[&str],
        keys: bool,
        result: Result<UpdateStatus, CheckError>,
    ) -> (u8, String, String, bool) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut called = false;
        let code = check_update(
            &args,
            keys,
            "1.2.3",
            |running| {
                called = true;
                assert_eq!(running, v(1, 2, 3));
                result
            },
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
            called,
        )
    }

    #[test]
    fn newer_prints_only_version_and_fixed_page() {
        let (code, out, err, called) = run_with(&[], true, Ok(UpdateStatus::Newer(v(1, 3, 0))));
        assert_eq!((code, called), (0, true));
        assert!(err.is_empty());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "Проверка обновлений: запрос к github.com (GitHub увидит ваш IP-адрес)."
        );
        assert!(lines[1].starts_with("Вышла версия 1.3.0 (у вас 1.2.3). Страница загрузки: https://github.com/rekc2004/chervotochina/releases."));
    }

    #[test]
    fn up_to_date_exit0() {
        let (code, out, _, _) = run_with(&[], true, Ok(UpdateStatus::UpToDate));
        assert_eq!(code, 0);
        assert!(out.contains("Установлена последняя версия (1.2.3)."));
    }

    #[test]
    fn errors_exit1_with_fixed_lines() {
        for (e, text) in [
            (CheckError::Network, "Нет связи с GitHub."),
            (CheckError::Timeout, "Нет связи с GitHub."),
            (CheckError::BadResponse, "Ответ не прошёл проверку."),
            (CheckError::BadSignature, "Ответ не прошёл проверку."),
            (
                CheckError::NoTrustedKeys,
                "Ключи владельца не вшиты: проверка невозможна.",
            ),
        ] {
            let (code, _, err, _) = run_with(&[], true, Err(e));
            assert_eq!(code, 1);
            assert_eq!(err.trim_end(), text);
        }
    }

    #[test]
    fn no_keys_means_no_check_call_and_no_request_line() {
        let (code, out, err, called) = run_with(&[], false, Ok(UpdateStatus::UpToDate));
        assert_eq!(code, 1);
        assert!(!called, "проверка без ключей не должна вызываться");
        assert!(out.is_empty(), "о запросе не сообщаем, его нет");
        assert!(err.contains("не вшиты"));
    }

    #[test]
    fn extra_args_exit2_without_check() {
        let (code, out, _, called) = run_with(&["x"], true, Ok(UpdateStatus::UpToDate));
        assert_eq!(code, 2);
        assert!(out.is_empty() && !called);
    }
}
