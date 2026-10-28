//! Охрана обновлений (этап 19г-2, SPEC 19г разд. 4 п. 7). Сеть и чтение файлов выпуска живут
//! в одном месте и только в потоке обновлений; разрешение на запрос видят только поток узла и
//! поток обновлений; в `src/` нет запуска процессов и открытия ссылок; экран не превращает пути
//! в строки сам. У каждого правила есть самопроверка на подложенном нарушении.

mod common;

type Files = Vec<(String, String)>;

/// Строки кода (без комментариев) с `needle`: `(файл, номер строки в коде файла)`.
fn places(files: &Files, needle: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (name, text) in files {
        for (i, line) in common::code(text).lines().enumerate() {
            if line.contains(needle) {
                out.push((name.clone(), i));
            }
        }
    }
    out
}

fn code_of(files: &Files, name: &str) -> Vec<String> {
    files
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, t)| common::code(t).lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Ближайшая сверху строка с `UpdateJob::` (заголовок ветки, в том числе из нескольких строк).
fn job_header(lines: &[String], idx: usize) -> Option<&str> {
    lines[..idx]
        .iter()
        .rev()
        .find(|l| l.contains("UpdateJob::"))
        .map(String::as_str)
}

/// Вызов `needle` ровно один раз в `file`, внутри ветки `UpdateJob::<variant>`.
fn single_call_in_arm(files: &Files, needle: &str, file: &str, variant: &str) -> Vec<String> {
    let at = places(files, needle);
    if at.len() != 1 {
        return vec![format!("{needle}: мест {}, нужно ровно одно", at.len())];
    }
    if at[0].0 != file {
        return vec![format!("{needle}: в {}, нужно в {file}", at[0].0)];
    }
    let lines = code_of(files, file);
    match job_header(&lines, at[0].1) {
        Some(h) if h.contains(&format!("UpdateJob::{variant}")) => Vec::new(),
        other => vec![format!(
            "{needle}: не в ветке UpdateJob::{variant}, а в {other:?}"
        )],
    }
}

const FORBIDDEN: [&str; 6] = [
    "process::Command",
    "std::process::Stdio",
    "open_url",
    "OpenUrl",
    "webbrowser",
    "trusted_comment",
];

fn violations(files: &Files) -> Vec<String> {
    let mut bad = Vec::new();
    bad.extend(single_call_in_arm(
        files,
        "check_latest(",
        "src/update_worker.rs",
        "Check",
    ));
    bad.extend(single_call_in_arm(
        files,
        "verify_release_files(",
        "src/update_worker.rs",
        "Verify",
    ));
    let permit = places(files, "update_check_permit(");
    if permit.len() != 1 || permit[0].0 != "src/worker_ops.rs" {
        bad.push(format!("update_check_permit(: {permit:?}"));
    }
    for (name, _) in places(files, "UpdateCheckPermit") {
        if name != "src/update_worker.rs" && name != "src/worker_ops.rs" {
            bad.push(format!("UpdateCheckPermit в {name}"));
        }
    }
    for (name, _) in places(files, "UpdateJob::") {
        if name.starts_with("src/screens/") || name == "src/app.rs" {
            bad.push(format!("UpdateJob:: в {name}"));
        }
    }
    for needle in FORBIDDEN {
        for (name, line) in places(files, needle) {
            bad.push(format!("{needle} в {name}:{line}"));
        }
    }
    // `std::process` допустим только как `ExitCode` в main.rs
    for (name, text) in files {
        for l in common::code(text).lines() {
            if l.contains("std::process") && l.trim() != "use std::process::ExitCode;" {
                bad.push(format!("std::process в {name}: {}", l.trim()));
            }
        }
    }
    // экран не превращает пути в строки: имена приходят готовыми из модели
    let screen = "src/screens/update.rs";
    for needle in [".display()", "to_string_lossy"] {
        for (name, _) in places(files, needle) {
            if name == screen {
                bad.push(format!("{needle} в {name}"));
            }
        }
    }
    // сама охрана не пуста
    if !files.iter().any(|(n, _)| n == screen) {
        bad.push(format!("нет файла {screen}"));
    }
    bad
}

/// Команда «Проверить сейчас» создаётся только в ветке `U::CheckNow` модели обновлений
/// (форма охраны `gated_node_actions` для неё не подходит: вызов узла идёт из двух мест).
fn check_now_violations(files: &Files) -> Vec<String> {
    let mut bad = Vec::new();
    let at = places(files, "Command::CheckUpdateNow");
    let creators: Vec<_> = at
        .iter()
        .filter(|(n, _)| n == "src/update_model.rs")
        .collect();
    // тесты модели тоже сравнивают команду; создаёт её первое вхождение до тестов
    let Some((_, line)) = creators.first() else {
        return vec!["Command::CheckUpdateNow не создаётся в update_model.rs".to_owned()];
    };
    let lines = code_of(files, "src/update_model.rs");
    match common::enclosing_arm(&lines.iter().map(String::as_str).collect::<Vec<_>>(), *line) {
        Some(arm) if arm.contains("U::CheckNow") => {}
        other => bad.push(format!(
            "Command::CheckUpdateNow не в U::CheckNow, а в {other:?}"
        )),
    }
    for (name, _) in &at {
        if !matches!(
            name.as_str(),
            "src/update_model.rs" | "src/worker.rs" | "src/model.rs"
        ) {
            bad.push(format!("Command::CheckUpdateNow в {name}"));
        }
    }
    bad
}

#[test]
fn update_gates() {
    let files = common::src_files();
    let bad = violations(&files);
    assert!(bad.is_empty(), "{bad:#?}");
    let bad = check_now_violations(&files);
    assert!(bad.is_empty(), "{bad:#?}");
}

fn good() -> Files {
    let f = |n: &str, t: &str| (n.to_owned(), t.to_owned());
    vec![
        f(
            "src/update_worker.rs",
            "fn run(job: UpdateJob) {
    match job {
        UpdateJob::Check {
            permit,
            running,
        } => {
            let r = update::check_latest(permit, running);
        }
        UpdateJob::Verify {
            manifest,
        } => {
            let r = update::verify_release_files(&manifest);
        }
    }
}
",
        ),
        f(
            "src/worker_ops.rs",
            "fn tick(p: UpdateCheckPermit) { node.update_check_permit(m); UpdateJob::Check { p }; }\n",
        ),
        f("src/main.rs", "use std::process::ExitCode;\n"),
        f("src/screens/update.rs", "fn show() { ui.label(label); }\n"),
        f("src/app.rs", "fn x() {}\n"),
        f(
            "src/update_model.rs",
            "match intent {
    U::CheckNow => {
        vec![Command::CheckUpdateNow]
    }
}
",
        ),
        f("src/worker.rs", "Command::CheckUpdateNow => {}\n"),
    ]
}

fn with(files: &Files, name: &str, extra: &str) -> Files {
    let mut out = files.clone();
    match out.iter_mut().find(|(n, _)| n == name) {
        Some((_, t)) => {
            t.push_str(extra);
            t.push('\n');
        }
        None => out.push((name.to_owned(), extra.to_owned())),
    }
    out
}

#[test]
fn control_update_guard_can_fail() {
    assert!(violations(&good()).is_empty(), "{:#?}", violations(&good()));
    assert!(check_now_violations(&good()).is_empty());
    // второй вызов сети
    let twice = with(
        &good(),
        "src/update_worker.rs",
        "fn y() { check_latest(p, r); }",
    );
    assert!(!violations(&twice).is_empty());
    // сеть вне ветки Check
    let wrong_arm = good()
        .into_iter()
        .map(|(n, t)| {
            if n == "src/update_worker.rs" {
                (n, t.replace("UpdateJob::Check {", "UpdateJob::Verify {"))
            } else {
                (n, t)
            }
        })
        .collect();
    assert!(!violations(&wrong_arm).is_empty());
    // сеть в другом файле
    let elsewhere = with(&good(), "src/worker.rs", "fn z() { check_latest(p, r); }");
    assert!(!violations(&elsewhere).is_empty());
    // сверка файлов вне потока обновлений
    let verify = with(
        &good(),
        "src/worker_ops.rs",
        "fn v() { verify_release_files(a); }",
    );
    assert!(!violations(&verify).is_empty());
    // второе место выдачи разрешения
    let permit = with(
        &good(),
        "src/worker.rs",
        "fn p() { n.update_check_permit(m); }",
    );
    assert!(!violations(&permit).is_empty());
    // разрешение в экране или модели
    let leak = with(
        &good(),
        "src/update_model.rs",
        "fn p(x: UpdateCheckPermit) {}",
    );
    assert!(!violations(&leak).is_empty());
    // задания потока обновлений создают экран и app.rs
    let job = with(
        &good(),
        "src/screens/update.rs",
        "fn j() { UpdateJob::Verify {}; }",
    );
    assert!(!violations(&job).is_empty());
    let job = with(&good(), "src/app.rs", "fn j() { UpdateJob::Verify {}; }");
    assert!(!violations(&job).is_empty());
    // процессы и ссылки
    for bad in [
        "use std::process::Command;",
        "let c = process::Command::new(x);",
        "ctx.open_url(u);",
        "OpenUrl::new_tab(u)",
        "webbrowser::open(u)",
        "let c = r.trusted_comment;",
        "let s = std::process::exit(1);",
    ] {
        assert!(
            !violations(&with(&good(), "src/app.rs", bad)).is_empty(),
            "{bad}"
        );
    }
    // имена в экране только готовые
    for bad in ["let s = p.display();", "let s = n.to_string_lossy();"] {
        assert!(
            !violations(&with(&good(), "src/screens/update.rs", bad)).is_empty(),
            "{bad}"
        );
    }
    // комментарий нарушением не считается
    let comment = with(&good(), "src/app.rs", "// webbrowser::open(u)");
    assert!(violations(&comment).is_empty());
    // «Проверить сейчас» вне своей ветки или в чужом файле
    let other_arm = good()
        .into_iter()
        .map(|(n, t)| {
            if n == "src/update_model.rs" {
                (n, t.replace("U::CheckNow", "U::Verify"))
            } else {
                (n, t)
            }
        })
        .collect();
    assert!(!check_now_violations(&other_arm).is_empty());
    let screen = with(
        &good(),
        "src/screens/update.rs",
        "out.push(Command::CheckUpdateNow);",
    );
    assert!(!check_now_violations(&screen).is_empty());
}
