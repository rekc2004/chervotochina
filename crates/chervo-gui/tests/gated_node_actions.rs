//! Охрана «действия узла с условием доступны только из своих обработчиков» (этап 18б, SPEC 4.4):
//! - экраны и `app.rs` не создают команд (`Command::`), только намерения пользователя;
//! - каждая команда из `GATED` создаётся ровно в одном месте моделей и именно внутри ветки
//!   своего намерения (кнопка «Соединить», ответ «да» на вопрос о доверии, «Найти роутер»,
//!   «Сверить часы»); границы ветки берутся по отступам (`common::enclosing_arm`);
//! - вызов узла для такой команды (`connect_now`, `enable_auto_accept`, `upnp_identify`,
//!   `sync_clock`) стоит только в `worker_ops.rs` и именно внутри ветки своей команды;
//! - `TrustConfirmation` создаётся только в ветке `EnableAutoAccept`.

mod common;

struct Gate {
    /// Команда, которую создаёт модель.
    command: &'static str,
    /// Ветка намерения в модели, в которой она одна может появиться.
    intent_arm: &'static str,
    /// Вызов узла в `worker_ops.rs`.
    node_call: &'static str,
}

const GATED: [Gate; 4] = [
    Gate {
        command: "Command::ConnectNow",
        intent_arm: "I::ConnectNow(",
        node_call: "connect_now(",
    },
    Gate {
        command: "Command::EnableAutoAccept",
        intent_arm: "I::TrustYes",
        node_call: "enable_auto_accept(",
    },
    Gate {
        command: "Command::UpnpIdentify",
        intent_arm: "S::UpnpFind",
        node_call: "upnp_identify(",
    },
    Gate {
        command: "Command::SyncClock",
        intent_arm: "S::ClockSync",
        node_call: "sync_clock(",
    },
];

/// Нарушения для текста моделей (без модулей тестов): место создания команды ровно одно и оно в
/// ветке своего намерения.
fn model_violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut bad = Vec::new();
    for g in &GATED {
        let at: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(g.command))
            .map(|(i, _)| i)
            .collect();
        if at.len() != 1 {
            bad.push(format!(
                "{}: мест создания {}, нужно ровно одно",
                g.command,
                at.len()
            ));
            continue;
        }
        match common::enclosing_arm(&lines, at[0]) {
            Some(arm) if arm.contains(g.intent_arm) => {}
            other => bad.push(format!(
                "{}: не в ветке {}, а в {:?}",
                g.command, g.intent_arm, other
            )),
        }
    }
    bad
}

/// Нарушения для `worker_ops.rs`: вызов узла один и внутри ветки своей команды.
fn worker_violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut bad = Vec::new();
    let mut check = |needle: &str, command: &str| {
        let at: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, _)| i)
            .collect();
        if at.len() != 1 {
            bad.push(format!("{needle}: мест {}, нужно ровно одно", at.len()));
            return;
        }
        match common::enclosing_arm(&lines, at[0]) {
            Some(arm) if arm.contains(command) => {}
            other => bad.push(format!("{needle}: не в ветке {command}, а в {other:?}")),
        }
    };
    for g in &GATED {
        check(g.node_call, g.command);
    }
    check("user_confirmed_trust", "Command::EnableAutoAccept");
    bad
}

fn product_part(text: &str) -> &str {
    text.split("\n#[cfg(test)]").next().unwrap_or(text)
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
                .map(|(_, t)| product_part(t))
                .expect("model file")
        })
        .collect();
    let bad = model_violations(&handlers.join("\n"));
    assert!(bad.is_empty(), "{bad:#?}");
    // и нигде больше в src/ эти команды не создаются
    for g in &GATED {
        for p in files_containing(&files, g.command) {
            assert!(
                matches!(
                    p.as_str(),
                    "src/main_model.rs"
                        | "src/settings_model.rs"
                        | "src/worker_ops.rs"
                        | "src/model.rs"
                ),
                "{} в {p}",
                g.command
            );
        }
    }
}

#[test]
fn node_calls_for_gated_actions_are_in_their_worker_arms() {
    let files = common::src_files();
    let worker = files
        .iter()
        .find(|(n, _)| n == "src/worker_ops.rs")
        .expect("worker_ops.rs");
    let bad = worker_violations(&worker.1);
    assert!(bad.is_empty(), "{bad:#?}");
    // эти вызовы и тип доверия нигде больше не встречаются
    for needle in [
        "connect_now(",
        "enable_auto_accept(",
        "upnp_identify(",
        "sync_clock(",
        "user_confirmed_trust",
        "TrustConfirmation",
    ] {
        let places = files_containing(&files, needle);
        assert_eq!(places, vec!["src/worker_ops.rs".to_owned()], "{needle}");
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
    // положительный пример: наша команда была бы поймана
    let sample = vec![(
        "src/screens/x.rs".to_owned(),
        "out.push(Command::ConnectNow(id));".to_owned(),
    )];
    assert!(!common::hits(&sample, &["Command::"]).is_empty());
}

const GOOD_MODEL: &str = "match i {
    I::ConnectNow(id) => {
        if ok {
            vec![Command::ConnectNow(id)]
        } else {
            Vec::new()
        }
    }
    I::TrustYes => {
        vec![Command::EnableAutoAccept(id)]
    }
    S::UpnpFind => {
        a();
        b();
        c();
        d();
        e();
        f();
        g();
        h();
        i();
        j();
        vec![Command::UpnpIdentify]
    }
    S::ClockSync => {
        vec![Command::SyncClock]
    }
}
";

const GOOD_WORKER: &str = "match cmd {
        Command::ConnectNow(id) => done(match x {
            Some(f) => node.connect_now(f),
        }),
        Command::EnableAutoAccept(id) => done(match x {
            Some(f) => node.enable_auto_accept(f, TrustConfirmation::user_confirmed_trust()),
        }),
        Command::UpnpIdentify => {
            let r = node.upnp_identify().map(|c| c);
        }
        Command::SyncClock => {
            let r = node.sync_clock();
        }
}
";

#[test]
fn control_model_guard_can_fail() {
    assert!(model_violations(GOOD_MODEL).is_empty());
    // команда в чужой ветке
    let wrong = GOOD_MODEL.replace("I::ConnectNow(id) => {", "I::Block(id) => {");
    assert!(!model_violations(&wrong).is_empty());
    let clock_wrong = GOOD_MODEL.replace("S::ClockSync", "S::ClockReset");
    assert!(!model_violations(&clock_wrong).is_empty());
    // команда далеко от заголовка ветки (больше 10 строк) всё равно в своей ветке: допустимо,
    // а в чужой ветке даже рядом с заголовком своей: нет
    let hijack = GOOD_MODEL.replace(
        "    I::TrustYes => {\n        vec![Command::EnableAutoAccept(id)]\n    }\n",
        "    I::TrustYes => {\n    }\n    I::Other => {\n        vec![Command::EnableAutoAccept(id)]\n    }\n",
    );
    assert!(!model_violations(&hijack).is_empty());
    // второе место создания
    let twice = format!("{GOOD_MODEL}fn other() {{\n    Command::EnableAutoAccept(x);\n}}\n");
    assert!(!model_violations(&twice).is_empty());
    // команды нет совсем: охрана не должна быть пустой
    assert!(!model_violations("fn x() {}\n").is_empty());
    // комментарий не считается созданием
    let commented = format!("{GOOD_MODEL}// Command::ConnectNow(id)\n");
    assert!(model_violations(&commented).is_empty());
}

#[test]
fn control_worker_guard_can_fail() {
    assert!(worker_violations(GOOD_WORKER).is_empty());
    // вызов узла в чужой ветке
    let wrong = GOOD_WORKER.replace(
        "Command::SyncClock => {\n            let r = node.sync_clock();",
        "Command::ResetClock => {\n            let r = node.sync_clock();",
    );
    assert!(!worker_violations(&wrong).is_empty());
    // второй вызов
    let twice = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.upnp_identify();",
    );
    assert!(!worker_violations(&twice).is_empty());
    // вызов в форме `Node::метод(&node, ..)` (UFCS) в чужой ветке тоже ловится
    let ufcs = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            Node::connect_now(&node, f);",
    );
    assert!(!worker_violations(&ufcs).is_empty());
    let ufcs_clock = GOOD_WORKER.replace(
        "let r = node.sync_clock();",
        "let r = Node::sync_clock(node);",
    );
    assert!(worker_violations(&ufcs_clock).is_empty());
    let ufcs_elsewhere = GOOD_WORKER.replace(
        "Command::UpnpIdentify => {",
        "Command::UpnpIdentify => {\n            let c = Node::sync_clock(node);",
    );
    assert!(!worker_violations(&ufcs_elsewhere).is_empty());
    // и во всех остальных файлах src/ такие имена не встречаются
    let other = vec![(
        "src/screens/x.rs".to_owned(),
        "let r = Node::upnp_identify(n);".to_owned(),
    )];
    assert_eq!(
        files_containing(&other, "upnp_identify("),
        vec!["src/screens/x.rs"]
    );
    // доверие создаётся вне ветки автоприёма
    let trust = GOOD_WORKER.replace(
        "Some(f) => node.connect_now(f),",
        "Some(f) => node.connect_now(f, TrustConfirmation::user_confirmed_trust()),",
    );
    assert!(!worker_violations(&trust).is_empty());
}
