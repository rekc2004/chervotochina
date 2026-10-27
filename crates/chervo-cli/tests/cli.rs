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

/// Окружение с профилем в каталоге `home`: бинарный файл ищет данные только там.
fn chervo_in(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_chervo"));
    c.env("LOCALAPPDATA", home)
        .env("XDG_DATA_HOME", home)
        .env("HOME", home);
    c
}

fn temp_home(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("chervo-cli-{tag}-{}-{nanos:x}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn find_settings(dir: &std::path::Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            find_settings(&p)
        } else {
            p.file_name().is_some_and(|n| n == "settings.v1")
        }
    })
}

#[test]
fn init_writes_settings_and_run_before_init_says_first_run() {
    let home = temp_home("init");
    let recv = home.join("recv");
    std::fs::create_dir_all(&recv).unwrap();

    // до init: запуск отказывает, не трогая хранилище ключей
    let out = chervo_in(&home).arg("run").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("chervo init"), "stderr: {err}");

    let out = chervo_in(&home)
        .args(["init", "--receive"])
        .arg(&recv)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(find_settings(&home), "settings.v1 не создан");

    // нет флага папки приёма: ошибка использования
    let out = chervo_in(&home).arg("init").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn unknown_flags_are_refused() {
    // обхода хранилища ключей и прочих скрытых режимов нет: незнакомый аргумент это ошибка
    for args in [
        vec!["run", "--file-store"],
        vec!["run", "--data-dir", "x"],
        vec!["--daemon"],
        vec!["bogus"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_chervo"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}
