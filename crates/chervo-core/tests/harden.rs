//! Укрепление процесса (этап 17, C07). Проверки по платформам: на каждой ОС выполняется своя.
//! Windows: мер нет (принятый остаток T10, решение Q4), и тест это фиксирует, чтобы остаток
//! не исчез из виду.

use chervo_core::harden_process;

#[cfg(target_os = "linux")]
#[test]
fn harden_linux_not_dumpable_and_core_zero() {
    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};

    let report = harden_process();
    assert!(
        report.not_dumpable,
        "PR_SET_DUMPABLE не применён: {report:?}"
    );
    assert!(report.core_limit_zero, "RLIMIT_CORE не 0: {report:?}");
    assert!(report.any_applied());

    // чтение обратно напрямую, не через отчёт
    assert_eq!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable));
    let lim = getrlimit(Resource::Core);
    assert_eq!(lim.current, Some(0));
    assert_eq!(lim.maximum, Some(0));

    // и независимо от rustix: строка `Max core file size  0  0  bytes` в /proc/self/limits
    let text = std::fs::read_to_string("/proc/self/limits").expect("read /proc/self/limits");
    let row = text
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .expect("row Max core file size");
    let cols: Vec<&str> = row["Max core file size".len()..]
        .split_whitespace()
        .collect();
    assert_eq!(cols.first(), Some(&"0"), "{row}");
    assert_eq!(cols.get(1), Some(&"0"), "{row}");

    // повторный вызов безопасен и даёт тот же итог
    assert_eq!(harden_process(), report);
}

#[cfg(target_os = "macos")]
#[test]
fn harden_macos_core_zero() {
    use rustix::process::{Resource, getrlimit};

    let report = harden_process();
    assert!(report.core_limit_zero, "RLIMIT_CORE не 0: {report:?}");
    assert!(
        !report.not_dumpable,
        "на macOS PR_SET_DUMPABLE нет: {report:?}"
    );
    let lim = getrlimit(Resource::Core);
    assert_eq!(lim.current, Some(0));
    assert_eq!(lim.maximum, Some(0));
    assert_eq!(harden_process(), report);
}

/// Windows: меры не применяются (WER и отладчик того же пользователя: принятый остаток).
#[cfg(windows)]
#[test]
fn harden_windows_applies_nothing() {
    let report = harden_process();
    assert_eq!(report, chervo_core::HardenReport::default());
    assert!(!report.any_applied());
}

/// На любой ОС вызов не паникует и повторяем.
#[test]
fn harden_is_idempotent() {
    let a = harden_process();
    let b = harden_process();
    assert_eq!(a, b);
}
