//! Охрана «действия узла с условием доступны только из своих обработчиков» (этап 18б, SPEC 4.4):
//! - экраны и `app.rs` не создают команд (`Command::`), только намерения пользователя;
//! - `Command::ConnectNow` рождается ровно в одном месте модели, в ветке `I::ConnectNow` (кнопка
//!   «Соединить»), а `Command::EnableAutoAccept` только в ветке `I::TrustYes` (ответ «да» на
//!   вопрос о доверии);
//! - `connect_now`, `enable_auto_accept` и `TrustConfirmation` встречаются только в `worker_ops.rs`.

mod common;

/// (команда, ветка намерения, в которой она одна может появиться)
const GATED: [(&str, &str); 4] = [
    ("Command::ConnectNow", "I::ConnectNow("),
    ("Command::EnableAutoAccept", "I::TrustYes"),
    ("Command::UpnpIdentify", "S::UpnpFind"),
    ("Command::SyncClock", "S::ClockSync"),
];
/// Окно строк после заголовка ветки, в которое должна попасть команда.
const ARM_WINDOW: usize = 14;

/// Нарушения для текста модели (без модуля тестов).
fn model_violations(text: &str) -> Vec<String> {
    let product = match text.find("\n#[cfg(test)]") {
        Some(i) => &text[..i],
        None => text,
    };
    let code = common::code(product);
    let lines: Vec<&str> = code.lines().collect();
    let mut bad = Vec::new();
    for (command, arm) in GATED {
        let at: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(command))
            .map(|(i, _)| i)
            .collect();
        if at.len() != 1 {
            bad.push(format!(
                "{command}: мест создания {}, нужно ровно одно",
                at.len()
            ));
            continue;
        }
        let i = at[0];
        let from = i.saturating_sub(ARM_WINDOW);
        if !lines[from..=i].iter().any(|l| l.contains(arm)) {
            bad.push(format!("{command}: не в ветке {arm}"));
        }
    }
    bad
}

fn files_containing(files: &[(String, String)], needle: &str) -> Vec<String> {
    files
        .iter()
        .filter(|(_, t)| common::code(t).contains(needle))
        .map(|(n, _)| n.clone())
        .collect()
}

#[test]
fn gated_commands_are_built_only_in_their_handlers() {
    let files = common::src_files();
    // модели с обработчиками намерений
    let handlers: Vec<&str> = ["src/main_model.rs", "src/settings_model.rs"]
        .iter()
        .map(|want| {
            files
                .iter()
                .find(|(n, _)| n == want)
                .map(|(_, t)| t.as_str())
                .expect("model file")
        })
        .map(|t| t.split("\n#[cfg(test)]").next().unwrap_or(t))
        .collect();
    let bad = model_violations(&handlers.join("\n"));
    assert!(bad.is_empty(), "{bad:#?}");
    // и нигде больше в src/ эти команды не создаются
    for (command, _) in GATED {
        let places = files_containing(&files, command);
        // main_model.rs создаёт, worker_ops.rs разбирает команду
        for p in &places {
            assert!(
                matches!(
                    p.as_str(),
                    "src/main_model.rs"
                        | "src/settings_model.rs"
                        | "src/worker_ops.rs"
                        | "src/model.rs"
                ),
                "{command} в {p}"
            );
        }
    }
}

#[test]
fn ui_files_do_not_build_commands() {
    let files: Vec<_> = common::src_files()
        .into_iter()
        .filter(|(n, _)| n.starts_with("src/screens/") || n == "src/app.rs")
        .collect();
    assert!(!files.is_empty());
    // `ViewportCommand::` (команды окна egui) не наш `Command::`
    let hits: Vec<String> = common::hits(&files, &["Command::"])
        .into_iter()
        .filter(|h| h.replace("ViewportCommand::", "").contains("Command::"))
        .collect();
    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn node_calls_for_gated_actions_live_in_worker_ops_only() {
    let files = common::src_files();
    for needle in [
        ".connect_now(",
        ".enable_auto_accept(",
        ".upnp_identify(",
        ".sync_clock(",
        "user_confirmed_trust",
        "TrustConfirmation",
    ] {
        let places = files_containing(&files, needle);
        assert_eq!(places, vec!["src/worker_ops.rs".to_owned()], "{needle}");
    }
}

#[test]
fn control_guard_can_fail() {
    let good = "match i {\n    I::ConnectNow(id) => {\n        vec![Command::ConnectNow(id)]\n    }\n    I::TrustYes => {\n        vec![Command::EnableAutoAccept(id)]\n    }\n    S::UpnpFind => {\n        vec![Command::UpnpIdentify]\n    }\n    S::ClockSync => {\n        vec![Command::SyncClock]\n    }\n}\n";
    assert!(model_violations(good).is_empty());
    // команда в чужой ветке
    let wrong = "match i {\n    I::Block(id) => {\n        vec![Command::ConnectNow(id)]\n    }\n    I::TrustYes => {\n        vec![Command::EnableAutoAccept(id)]\n    }\n    S::UpnpFind => {\n        vec![Command::UpnpIdentify]\n    }\n    S::ClockSync => {\n        vec![Command::SyncClock]\n    }\n}\n";
    assert!(!model_violations(wrong).is_empty());
    // сверка часов в чужой ветке
    let clock_wrong = good.replace("S::ClockSync", "S::ClockReset");
    assert!(!model_violations(&clock_wrong).is_empty());
    let upnp_wrong = good.replace("S::UpnpFind", "S::UpnpDecline");
    assert!(!model_violations(&upnp_wrong).is_empty());
    // второе место создания
    let twice = format!("{good}fn other() {{ Command::EnableAutoAccept(x); }}\n");
    assert!(!model_violations(&twice).is_empty());
    // команды нет совсем: охрана не должна быть пустой
    assert!(!model_violations("fn x() {}\n").is_empty());
    // комментарий не считается созданием
    let commented = format!("{good}// Command::ConnectNow(id)\n");
    assert!(model_violations(&commented).is_empty());
}
