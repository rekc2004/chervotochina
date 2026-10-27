use std::process::Command;

#[test]
fn doctor_usage_exit2() {
    let out = Command::new(env!("CARGO_BIN_EXE_chervo"))
        .args(["doctor", "extra"])
        .output()
        .expect("run chervo doctor extra");
    assert_eq!(out.status.code(), Some(2));
}

/// Страж исходника: `doctor` не разблокирует хранилище, ничего не пишет и не запускает программы.
#[test]
fn doctor_never_unlocks() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/doctor.rs");
    let text = std::fs::read_to_string(path).expect("read doctor.rs");
    // только код до модуля тестов, без строк-комментариев
    let head = text.split("#[cfg(test)]").next().expect("head");
    let code: String = head
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for bad in [
        "request_unlock",
        "process::Command",
        "Command::new",
        "write_epoch",
        "write_list_key",
        "delete_list_key",
    ] {
        assert!(!code.contains(bad), "doctor.rs содержит запрещённое: {bad}");
    }
}
