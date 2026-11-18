//! Охрана «действия узла с условием доступны только из своих обработчиков» (этап 18б, SPEC 4.4;
//! форма Р11 этапа 13д):
//! - экраны и `app.rs` не создают команд (`Command::`), только намерения пользователя;
//! - каждая команда из `GATED` создаётся ровно один раз внутри каждой ветки из `intent_arms` и
//!   нигде больше (кнопка «Соединить», ответ «да» на вопрос о доверии, «Найти роутер» и
//!   «Попробовать автоматически», «Сверить часы», «Создать приглашение», «Получить свой IP»,
//!   «Проверить», «Правило создано»); границы ветки берутся по отступам (`common::arm_block`);
//! - вызов узла для такой команды (`connect_now`, `enable_auto_accept`, `upnp_identify`,
//!   `sync_clock`, `set_lan_mode`, `echo_probe`, ...) стоит только в `worker_ops.rs`, ровно один
//!   раз в каждой ветке из `command_arms` и больше нигде;
//! - внутри ветки `Command::CreateInvite` вызов `echo_probe(` стоит только под
//!   `ExternalMode::Probe`;
//! - `TrustConfirmation` создаётся только в ветке `EnableAutoAccept`.

mod common;

struct Gate {
    /// Команда (или режим), которую создаёт модель.
    command: &'static str,
    /// Ветки намерений в моделях: в каждой команда появляется ровно один раз, больше нигде.
    intent_arms: &'static [&'static str],
    /// Вызов узла в `worker_ops.rs`.
    node_call: &'static str,
    /// Ветки команд в `worker_ops.rs`: в каждой вызов один раз, больше нигде.
    command_arms: &'static [&'static str],
}

/// Ветки, в которых узнаётся адрес у сервера: кнопка «Получить свой IP» и создание приглашения.
const PROBE_ARMS: &[&str] = &["Command::EchoProbe", "Command::CreateInvite"];
/// Ветка, где приглашение создаётся с адресами `extra`.
const INVITE_ARM: &[&str] = &["Command::CreateInvite"];

const GATED: [Gate; 16] = [
    Gate {
        command: "Command::ConnectNow",
        intent_arms: &["I::ConnectNow("],
        node_call: "connect_now(",
        command_arms: &["Command::ConnectNow"],
    },
    Gate {
        command: "Command::EnableAutoAccept",
        intent_arms: &["I::TrustYes"],
        node_call: "enable_auto_accept(",
        command_arms: &["Command::EnableAutoAccept"],
    },
    // «Найти роутер» в настройках и «Попробовать автоматически» в помощнике (13д)
    Gate {
        command: "Command::UpnpIdentify",
        intent_arms: &["S::UpnpFind", "A::AccessAuto"],
        node_call: "upnp_identify(",
        command_arms: &["Command::UpnpIdentify"],
    },
    Gate {
        command: "Command::SyncClock",
        intent_arms: &["S::ClockSync"],
        node_call: "sync_clock(",
        command_arms: &["Command::SyncClock"],
    },
    // 13в: выбор режима поиска в локальной сети. «Сообщать о себе» рассылает маяк в сеть, поэтому
    // команда появляется только из ветки выбора человека (не из открытия экрана или события).
    Gate {
        command: "Command::SetLanMode",
        intent_arms: &["S::LanChoose"],
        node_call: "set_lan_mode(",
        command_arms: &["Command::SetLanMode"],
    },
    // 19г-2: ответ на вопрос о проверке новых версий (карточка и переключатель: одна ветка).
    // «Проверить сейчас» (`Command::CheckUpdateNow`, `U::CheckNow`) здесь не записана: вызов узла
    // идёт из `update_tick` из двух мест (такт и кнопка), охраняет её `update_gates.rs`.
    Gate {
        command: "Command::SetUpdateConsent",
        intent_arms: &["U::SetConsent"],
        node_call: "set_update_consent(",
        command_arms: &["Command::SetUpdateConsent"],
    },
    // 18б: любой текст от друга (приглашение, новый адрес, уведомление об удалении) уходит узлу
    // только из ветки кнопки «Применить» окна «Друг прислал мне текст»; вид текста решает узел
    Gate {
        command: "Command::ApplyFriendText",
        intent_arms: &["I::FriendTextSubmit"],
        node_call: "apply_friend_text(",
        command_arms: &["Command::ApplyFriendText"],
    },
    // 18б, Н7: запуск проводника для папки приёма только из ветки кнопки «Открыть папку»
    Gate {
        command: "Command::OpenReceiveFolder",
        intent_arms: &["I::OpenReceiveFolder"],
        node_call: "open_receive_folder(",
        command_arms: &["Command::OpenReceiveFolder"],
    },
    // 13д: запрос к серверу за адресом в интернете только из кнопки «Получить свой IP» и из
    // «Создать приглашение» (и в ней только под `ExternalMode::Probe`)
    Gate {
        command: "Command::EchoProbe",
        intent_arms: &["I::GetIp"],
        node_call: "echo_probe(",
        command_arms: PROBE_ARMS,
    },
    Gate {
        command: "ExternalMode::Probe",
        intent_arms: &["I::AddCreate"],
        node_call: "echo_probe(",
        command_arms: PROBE_ARMS,
    },
    // адрес вписывается после VPN только по явному ответу человека
    Gate {
        command: "ExternalMode::Use",
        intent_arms: &["I::AddVpnWithAddr"],
        node_call: "create_invite_ext(",
        command_arms: INVITE_ARM,
    },
    Gate {
        command: "ExternalMode::Without",
        intent_arms: &["I::AddVpnWithout"],
        node_call: "create_invite_ext(",
        command_arms: INVITE_ARM,
    },
    // 13д: проверка доступа (сервер шлёт ответ со второго порта) только по кнопке «Проверить»
    Gate {
        command: "Command::ReachCheck",
        intent_arms: &["A::AccessCheck"],
        node_call: "reach_check(",
        command_arms: &["Command::ReachCheck"],
    },
    // 13д: ручной проброс запоминается только по кнопке «Правило создано»
    Gate {
        command: "Command::ConfirmForward",
        intent_arms: &["A::AccessDone"],
        node_call: "confirm_manual_forward(",
        command_arms: &["Command::ConfirmForward"],
    },
    // 13д: ответ на вопрос о роутере; в помощнике «Разрешить» это `AccessAllow`
    Gate {
        command: "Command::UpnpAllow",
        intent_arms: &["S::UpnpAllowYes", "S::UpnpPermanentYes", "A::AccessAllow"],
        node_call: "upnp_allow(",
        command_arms: &["Command::UpnpAllow"],
    },
    // 13д: запись адреса сервера (сети не трогает) из двух кнопок: «Сохранить» и «Очистить»
    Gate {
        command: "Command::SetEchoServer",
        intent_arms: &["S::EchoSave", "S::EchoClear"],
        node_call: "set_echo_server(",
        command_arms: &["Command::SetEchoServer"],
    },
];

/// Нарушения для текста моделей (без модулей тестов): команда создаётся ровно один раз в каждой
/// ветке своего намерения и больше нигде.
fn model_violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut bad = Vec::new();
    for g in &GATED {
        let total = common::count_in(&lines, g.command);
        if total != g.intent_arms.len() {
            bad.push(format!(
                "{}: мест создания {total}, нужно {}",
                g.command,
                g.intent_arms.len()
            ));
        }
        for arm in g.intent_arms {
            match common::arm_block(&lines, arm) {
                Some(block) if common::count_in(&block, g.command) == 1 => {}
                Some(_) => bad.push(format!("{}: не ровно одно место в ветке {arm}", g.command)),
                None => bad.push(format!("{}: ветки {arm} нет", g.command)),
            }
        }
    }
    bad
}

/// Нарушения для `worker_ops.rs`: вызов узла один раз в каждой ветке своей команды и больше нигде.
fn worker_violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut bad = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    let mut check = |needle: &str, arms: &[&str]| {
        let total = common::count_in(&lines, needle);
        if total != arms.len() {
            bad.push(format!("{needle}: мест {total}, нужно {}", arms.len()));
        }
        for arm in arms {
            match common::arm_block(&lines, arm) {
                Some(block) if common::count_in(&block, needle) == 1 => {}
                Some(_) => bad.push(format!("{needle}: не ровно один вызов в ветке {arm}")),
                None => bad.push(format!("{needle}: ветки {arm} нет")),
            }
        }
    };
    for g in &GATED {
        // один вызов может обслуживать несколько записей: проверяется один раз
        if seen.contains(&g.node_call) {
            continue;
        }
        seen.push(g.node_call);
        check(g.node_call, g.command_arms);
    }
    check("user_confirmed_trust", &["Command::EnableAutoAccept"]);
    // внутри `Command::CreateInvite` проба адреса только под `ExternalMode::Probe`
    if let Some(block) = common::arm_block(&lines, "Command::CreateInvite") {
        for (i, l) in block.iter().enumerate() {
            if l.contains("echo_probe(") {
                match common::enclosing_arm(&block, i) {
                    Some(arm) if arm.contains("ExternalMode::Probe") => {}
                    other => bad.push(format!("echo_probe( не под ExternalMode::Probe: {other:?}")),
                }
            }
        }
    }
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
    let handlers: Vec<&str> = [
        "src/main_model.rs",
        "src/settings_model.rs",
        "src/update_model.rs",
        "src/access_model.rs",
    ]
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
                        | "src/update_model.rs"
                        | "src/access_model.rs"
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
        "set_lan_mode(",
        "set_update_consent(",
        "apply_friend_text(",
        "open_receive_folder(",
        "echo_probe(",
        "reach_check(",
        "confirm_manual_forward(",
        "create_invite_ext(",
        "set_echo_server(",
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
    A::AccessAuto => {
        vec![Command::UpnpIdentify]
    }
    S::ClockSync => {
        vec![Command::SyncClock]
    }
    S::LanChoose(mode) => {
        vec![Command::SetLanMode(mode)]
    }
    U::SetConsent(on) => {
        vec![Command::SetUpdateConsent(on)]
    }
    I::FriendTextSubmit => {
        if let Dialog::FriendText(d) = &mut self.dialog {
            return vec![Command::ApplyFriendText(text)];
        }
    }
    I::OpenReceiveFolder => {
        vec![Command::OpenReceiveFolder]
    }
    I::GetIp => {
        vec![Command::EchoProbe]
    }
    I::AddCreate => {
        vec![Command::CreateInvite {
            same_network: s,
            external: ExternalMode::Probe,
        }]
    }
    I::AddVpnWithAddr => {
        vec![Command::CreateInvite {
            same_network: s,
            external: ExternalMode::Use(addrs),
        }]
    }
    I::AddVpnWithout => {
        vec![Command::CreateInvite {
            same_network: s,
            external: ExternalMode::Without,
        }]
    }
    A::AccessCheck => {
        vec![Command::ReachCheck]
    }
    A::AccessDone => {
        vec![Command::ConfirmForward]
    }
    S::UpnpAllowYes => {
        vec![Command::UpnpAllow { router: None }]
    }
    S::UpnpPermanentYes(id) => {
        vec![Command::UpnpAllow { router: Some(id) }]
    }
    A::AccessAllow => {
        vec![Command::UpnpAllow { router: None }]
    }
    S::EchoSave => {
        vec![Command::SetEchoServer(Some(t))]
    }
    S::EchoClear => {
        vec![Command::SetEchoServer(None)]
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
        Command::SetLanMode(mode) => {
            let r = node.set_lan_mode(mode);
            done(r)
        }
        Command::SetUpdateConsent(on) => Some(Outcome::UpdateConsentSet {
            result: node.set_update_consent(on),
        }),
        Command::ApplyFriendText(text) => {
            let r = node.apply_friend_text(&text);
            Some(Outcome::FriendText(r))
        }
        Command::OpenReceiveFolder => {
            let r = node.open_receive_folder();
            Some(Outcome::FolderOpened(r))
        }
        Command::CreateInvite {
            same_network,
            external,
        } => {
            let (extra, ext) = match external {
                ExternalMode::Without => (Vec::new(), Plain),
                ExternalMode::Use(addrs) => (addrs, ext),
                ExternalMode::Probe => {
                    let probed = node.echo_probe();
                    (Vec::new(), NotSet)
                }
            };
            let r = node.create_invite_ext(same_network, &extra);
            Some(Outcome::InviteCreated(r))
        }
        Command::EchoProbe => {
            let r = match node.echo_probe() {
                Ok(report) => report,
            };
            Some(Outcome::GetIp(r))
        }
        Command::ReachCheck => Some(Outcome::Reach(node.reach_check())),
        Command::ConfirmForward => Some(Outcome::ForwardConfirmed(node.confirm_manual_forward())),
        Command::UpnpAllow { router } => {
            let r = node.upnp_allow(&c, false);
            done(r)
        }
        Command::SetEchoServer(server) => {
            let result = node.set_echo_server(server.as_deref());
            Some(Outcome::EchoServerSet { result })
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
    // 13в: выбор режима поиска в сети только из ветки выбора, не из соседней
    let lan_wrong = GOOD_MODEL.replace("S::LanChoose(mode)", "S::MappingRefresh");
    assert!(!model_violations(&lan_wrong).is_empty());
    let lan_twice = format!("{GOOD_MODEL}fn other() {{\n    Command::SetLanMode(m);\n}}\n");
    assert!(!model_violations(&lan_twice).is_empty());
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
    // 18б: текст от друга и «Открыть папку» только из своих веток
    let text_wrong = GOOD_MODEL.replace("I::FriendTextSubmit => {", "I::FriendTextEdited(t) => {");
    assert!(!model_violations(&text_wrong).is_empty());
    let folder_wrong = GOOD_MODEL.replace("I::OpenReceiveFolder => {", "I::Block(id) => {");
    assert!(!model_violations(&folder_wrong).is_empty());
    let text_twice = format!("{GOOD_MODEL}fn other() {{\n    Command::ApplyFriendText(x);\n}}\n");
    assert!(!model_violations(&text_twice).is_empty());
    // 13д: поиск роутера из помощника: обе ветки обязательны, третьей нет
    let acc_missing = GOOD_MODEL.replace("A::AccessAuto => {", "A::AccessOther => {");
    assert!(!model_violations(&acc_missing).is_empty());
    let identify_third = format!("{GOOD_MODEL}fn other() {{\n    Command::UpnpIdentify;\n}}\n");
    assert!(!model_violations(&identify_third).is_empty());
    // 13д: `Command::EchoProbe` вне `I::GetIp` ловится
    let echo_wrong = GOOD_MODEL.replace("I::GetIp => {", "I::AddCancel => {");
    assert!(!model_violations(&echo_wrong).is_empty());
    let echo_twice = format!("{GOOD_MODEL}fn other() {{\n    Command::EchoProbe;\n}}\n");
    assert!(!model_violations(&echo_twice).is_empty());
    // проба в «Создать приглашение» только из ветки `I::AddCreate`; в ответе о VPN её быть не может
    let probe_in_vpn = GOOD_MODEL.replace(
        "external: ExternalMode::Without,",
        "external: ExternalMode::Probe,",
    );
    assert!(!model_violations(&probe_in_vpn).is_empty());
    let use_wrong = GOOD_MODEL.replace("I::AddVpnWithAddr => {", "I::AddCancel => {");
    assert!(!model_violations(&use_wrong).is_empty());
    // проверка и «Правило создано» только из своих веток
    let check_wrong = GOOD_MODEL.replace("A::AccessCheck => {", "A::AccessOther => {");
    assert!(!model_violations(&check_wrong).is_empty());
    let done_twice = format!("{GOOD_MODEL}fn other() {{\n    Command::ConfirmForward;\n}}\n");
    assert!(!model_violations(&done_twice).is_empty());
    // «Разрешить» роутеру из помощника: только из своей ветки
    let allow_wrong = GOOD_MODEL.replace("A::AccessAllow => {", "A::AccessOther => {");
    assert!(!model_violations(&allow_wrong).is_empty());
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
    // 13в: вызов смены режима поиска в сети в чужой ветке или второй раз
    let lan_wrong =
        GOOD_WORKER.replace("Command::SetLanMode(mode) => {", "Command::ResetClock => {");
    assert!(!worker_violations(&lan_wrong).is_empty());
    let lan_twice = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.set_lan_mode(m);",
    );
    assert!(!worker_violations(&lan_twice).is_empty());
    // 18б: вызов узла для текста от друга и для папки приёма в чужой ветке или второй раз
    let text_wrong = GOOD_WORKER.replace(
        "Command::ApplyFriendText(text) => {",
        "Command::ResetClock => {",
    );
    assert!(!worker_violations(&text_wrong).is_empty());
    let folder_twice = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.open_receive_folder();",
    );
    assert!(!worker_violations(&folder_twice).is_empty());
    // доверие создаётся вне ветки автоприёма
    let trust = GOOD_WORKER.replace(
        "Some(f) => node.connect_now(f),",
        "Some(f) => node.connect_now(f, TrustConfirmation::user_confirmed_trust()),",
    );
    assert!(!worker_violations(&trust).is_empty());
    // 13д: лишний `echo_probe(` в третьей ветке ловится
    let probe_third = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.echo_probe();",
    );
    assert!(!worker_violations(&probe_third).is_empty());
    // `echo_probe(` внутри `CreateInvite` не под `ExternalMode::Probe`
    let probe_not_under = GOOD_WORKER.replace(
        "ExternalMode::Without => (Vec::new(), Plain),",
        "ExternalMode::Without => {\n                    let p = node.echo_probe();\n                    (Vec::new(), Plain)\n                }",
    );
    assert!(!worker_violations(&probe_not_under).is_empty());
    // пробы нет в `EchoProbe` совсем: охрана не должна быть пустой
    let probe_missing = GOOD_WORKER.replace("match node.echo_probe() {", "match other() {");
    assert!(!worker_violations(&probe_missing).is_empty());
    // проверка доступа и «Правило создано» в чужой ветке или второй раз
    let reach_wrong = GOOD_WORKER.replace("Command::ReachCheck =>", "Command::ResetClock =>");
    assert!(!worker_violations(&reach_wrong).is_empty());
    let confirm_twice = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.confirm_manual_forward();",
    );
    assert!(!worker_violations(&confirm_twice).is_empty());
    // приглашение: второй вызов `create_invite_ext(`
    let invite_twice = GOOD_WORKER.replace(
        "Command::SyncClock => {",
        "Command::SyncClock => {\n            node.create_invite_ext(a, &b);",
    );
    assert!(!worker_violations(&invite_twice).is_empty());
}
