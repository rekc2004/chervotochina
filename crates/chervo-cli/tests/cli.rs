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

fn settings_files(dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            settings_files(&p, out);
        } else if let Some(n) = p.file_name().and_then(|n| n.to_str())
            && n.starts_with("settings.v1")
        {
            out.push(n.to_owned());
        }
    }
}

fn run_with_stdin(mut c: Command, input: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = c
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn reset_settings_needs_confirmation_and_works_with_yes() {
    let home = temp_home("reset");
    let recv = home.join("recv");
    std::fs::create_dir_all(&recv).unwrap();
    let init = chervo_in(&home)
        .args(["init", "--receive"])
        .arg(&recv)
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));

    // стандартный ввод не терминал: слово ДА не принимается, настройки целы
    for input in ["", "ДА\n"] {
        let mut c = chervo_in(&home);
        c.arg("reset-settings");
        let out = run_with_stdin(c, input);
        assert_eq!(out.status.code(), Some(2));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("--yes"), "stderr: {err}");
        let mut files = Vec::new();
        settings_files(&home, &mut files);
        assert_eq!(files, ["settings.v1"]);
    }
    // неверные аргументы
    let out = chervo_in(&home)
        .args(["reset-settings", "--force"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    // с --yes: объяснение, настройки убраны в сторону, дальше первый запуск
    let out = chervo_in(&home)
        .args(["reset-settings", "--yes"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Сбросить настройки."));
    let mut files = Vec::new();
    settings_files(&home, &mut files);
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].starts_with("settings.v1.bad-"), "{files:?}");
    let run = chervo_in(&home).arg("run").output().unwrap();
    assert_eq!(run.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&run.stderr).contains("chervo init"));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn recover_refuses_without_confirmation_before_opening_anything() {
    let home = temp_home("recover");
    for kind in ["accept-older", "start-over"] {
        let mut c = chervo_in(&home);
        c.args(["recover", kind]);
        let out = run_with_stdin(c, "ДА\n");
        assert_eq!(out.status.code(), Some(2), "{kind}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(all.contains("--yes"), "{kind}: {all}");
    }
    for args in [
        vec!["recover"],
        vec!["recover", "bogus"],
        vec!["recover", "start-over", "-y"],
    ] {
        let out = chervo_in(&home).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    // ничего не создано: ни настроек, ни ключей
    let mut files = Vec::new();
    settings_files(&home, &mut files);
    assert!(files.is_empty());
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
