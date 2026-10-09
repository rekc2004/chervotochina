use std::process::Command;

#[test]
fn version_prints_and_succeeds() {
    let out = Command::new(env!("CARGO_BIN_EXE_chervo"))
        .arg("--version")
        .output()
        .expect("run chervo --version");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("chervo 0.0.0"), "stdout was: {stdout}");
}

#[test]
fn no_args_fails() {
    let out = Command::new(env!("CARGO_BIN_EXE_chervo"))
        .output()
        .expect("run chervo");
    assert!(!out.status.success());
}
