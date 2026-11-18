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
//! - `TrustConfirmation` создаётся только в ветке `EnableAutoAccept`;
//! - команды из `GATED` не встречаются нигде в `src/`, кроме четырёх моделей и `worker_ops.rs`
//!   (`model.rs` не в списке);
//! - намерения `GetIp`, `AddCreate`, `AccessAuto/Allow/Check/Done`, `EchoSave/Clear` создаются только
//!   в `src/screens/`; единственное исключение: `access_progress` запускает `AccessCheck` в стадии
//!   `Waiting`;
//! - у типов `Command`, `ExternalMode` и намерений нет псевдонимов `as`, импортов вариантов
//!   (`Command::*`) и `type`-псевдонимов (кроме записанных `A`, `I`, `S`, `U`); методы узла из
//!   списка встречаются только как вызов `имя(`.
//!
//! Не закрыто (остаточный риск, T22): заголовок ветки с «или» (`Probe | Without =>`), `Self::`
//! внутри `impl` этих типов, глобальный импорт модуля (`use crate::model::*`), макросы, строки
//! и блочные комментарии в разборе кода, `#[cfg(test)]` перед не-тестовым кодом в середине файла.

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

/// Код без модуля тестов в конце файла (`#[cfg(test)]` с `mod` на следующей строке). Отдельные
/// пометки `#[cfg(test)]` на других вещах (`screens/mod.rs`) часть файла не отрезают.
fn product_part(text: &str) -> &str {
    text.split("\n#[cfg(test)]\nmod ").next().unwrap_or(text)
}

fn files_containing(files: &[(String, String)], needle: &str) -> Vec<String> {
    files
        .iter()
        .filter(|(_, t)| common::code(t).contains(needle))
        .map(|(n, _)| n.clone())
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Позиции `word` в строке как отдельного слова (не часть более длинного имени).
fn word_positions(line: &str, word: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, _) in line.match_indices(word) {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            out.push(i);
        }
    }
    out
}

/// Файлы, где `word` встречается в коде как отдельное слово (с вызовом или без него).
fn files_with_word(files: &[(String, String)], word: &str) -> Vec<String> {
    files
        .iter()
        .filter(|(_, t)| {
            common::code(t)
                .lines()
                .any(|l| !word_positions(l, word).is_empty())
        })
        .map(|(n, _)| n.clone())
        .collect()
}

/// Места, где команда из `GATED` встречается вне разрешённых файлов. Файл `model.rs` (тип
/// `Command` и снимок) не разрешён: команды там не создаются, а его текст модельная проверка
/// не читает.
fn placement_violations(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for g in &GATED {
        for p in files_containing(files, g.command) {
            if !matches!(
                p.as_str(),
                "src/main_model.rs"
                    | "src/settings_model.rs"
                    | "src/update_model.rs"
                    | "src/access_model.rs"
                    | "src/worker_ops.rs"
            ) {
                bad.push(format!("{} в {p}", g.command));
            }
        }
    }
    bad
}

// --- намерения пользователя создаются только на экранах (Р10, Р11) ---

/// Имена типов намерений и их псевдонимы в моделях (`use X as A;`).
const INTENT_PREFIXES: [&str; 6] = [
    "MainIntent",
    "AccessIntent",
    "SettingsIntent",
    "I",
    "A",
    "S",
];
/// Намерения, за которыми стоит запрос в сеть, запись адреса сервера или запоминание проброса.
const GUARDED_INTENTS: [&str; 8] = [
    "GetIp",
    "AddCreate",
    "AccessAuto",
    "AccessAllow",
    "AccessCheck",
    "AccessDone",
    "EchoSave",
    "EchoClear",
];

/// Единственное записанное исключение: `access_progress` запускает проверку сам, но только в
/// стадии `Waiting` (после «Попробовать автоматически» или «Разрешить», Р10.1): строка стоит
/// внутри `fn access_progress` после `let AccessStage::Waiting {`.
fn is_access_progress_exception(file: &str, lines: &[&str], idx: usize, token: &str) -> bool {
    if file != "src/access_model.rs" || token != "AccessIntent::AccessCheck" {
        return false;
    }
    let is_fn = |l: &&str| {
        let t = l.trim_start();
        t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ")
    };
    let Some(head) = lines[..=idx].iter().rposition(is_fn) else {
        return false;
    };
    lines[head].contains("fn access_progress(")
        && lines[head..idx]
            .iter()
            .any(|l| l.contains("let AccessStage::Waiting {"))
}

/// Нарушения: намерение из `GUARDED_INTENTS` создано не в `src/screens/`. Заголовок ветки
/// `match` (`A::AccessAuto => {`) созданием не считается.
fn intent_violations(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    let mut exceptions = 0;
    for (file, text) in files {
        if file.starts_with("src/screens/") {
            continue;
        }
        let code = common::code(product_part(text));
        let lines: Vec<&str> = code.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            for prefix in INTENT_PREFIXES {
                for name in GUARDED_INTENTS {
                    let token = format!("{prefix}::{name}");
                    for pos in word_positions(line, &token) {
                        let arm_head = line[..pos].trim().is_empty() && line.contains("=>");
                        if arm_head {
                            continue;
                        }
                        if is_access_progress_exception(file, &lines, i, &token) {
                            exceptions += 1;
                            if exceptions > 1 {
                                bad.push(format!("{file}:{}: второе исключение {token}", i + 1));
                            }
                            continue;
                        }
                        bad.push(format!("{file}:{}: {token} вне screens/", i + 1));
                    }
                }
            }
        }
    }
    bad
}

// --- обходы текстовой проверки: псевдонимы, импорты вариантов, методы без скобок ---

/// Типы, чьи имена ищет текстовая проверка: `Command::`, `ExternalMode::`, `I::GetIp` и так далее.
const WATCHED_TYPES: [&str; 7] = [
    "Command",
    "ExternalMode",
    "Intent",
    "MainIntent",
    "AccessIntent",
    "SettingsIntent",
    "UpdateIntent",
];

/// Записанные псевдонимы типов намерений: (файл, тип, псевдоним). Остальные запрещены: под другим
/// именем тип не нашёл бы ни одна проверка.
const ALLOWED_ALIASES: [(&str, &str, &str); 6] = [
    ("src/access_model.rs", "AccessIntent", "A"),
    ("src/main_model.rs", "MainIntent", "I"),
    ("src/settings_model.rs", "SettingsIntent", "S"),
    ("src/update_model.rs", "UpdateIntent", "U"),
    ("src/screens/settings.rs", "SettingsIntent", "S"),
    ("src/screens/update.rs", "UpdateIntent", "U"),
];

fn idents(s: &str) -> Vec<&str> {
    s.split(|c: char| !is_ident(c))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Операторы `use` из кода (в том числе многострочные), каждый одной строкой.
fn use_statements(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in code.lines() {
        let t = line.trim();
        if cur.is_none() {
            let rest = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            if rest.starts_with("use ") {
                cur = Some(String::new());
            }
        }
        if let Some(s) = cur.as_mut() {
            s.push(' ');
            s.push_str(t);
            if t.contains(';') {
                out.push(cur.take().unwrap_or_default());
            }
        }
    }
    out
}

/// Нарушения: псевдоним `as` у отслеживаемого типа (кроме записанных), импорт его вариантов
/// (`Command::*`, `ExternalMode::{Probe}`), `type X = Command;`.
fn alias_violations(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (file, text) in files {
        let code = common::code(text);
        for stmt in use_statements(&code) {
            let toks = idents(&stmt);
            for i in 0..toks.len().saturating_sub(2) {
                if toks[i + 1] == "as"
                    && WATCHED_TYPES.contains(&toks[i])
                    && !ALLOWED_ALIASES.contains(&(file.as_str(), toks[i], toks[i + 2]))
                {
                    bad.push(format!("{file}: псевдоним {} as {}", toks[i], toks[i + 2]));
                }
            }
            for w in WATCHED_TYPES {
                if stmt
                    .match_indices(&format!("{w}::"))
                    .any(|(i, _)| !stmt[..i].chars().next_back().is_some_and(is_ident))
                {
                    bad.push(format!("{file}: импорт вариантов {w}::"));
                }
            }
        }
        for line in code.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            if t.starts_with("type ") && idents(t).iter().any(|w| WATCHED_TYPES.contains(w)) {
                bad.push(format!("{file}: type-псевдоним: {}", line.trim()));
            }
        }
    }
    bad
}

/// Методы узла, которые охрана ищет по тексту `имя(`: ссылка на метод без скобок
/// (`.map(Node::echo_probe)`, `let f = node.reach_check;`) и вызов `имя (` с пробелом обходят
/// подсчёт, поэтому после имени сразу `(`.
const NODE_METHODS: [&str; 15] = [
    "connect_now",
    "enable_auto_accept",
    "upnp_identify",
    "sync_clock",
    "set_lan_mode",
    "set_update_consent",
    "apply_friend_text",
    "open_receive_folder",
    "echo_probe",
    "reach_check",
    "confirm_manual_forward",
    "create_invite_ext",
    "set_echo_server",
    "upnp_allow",
    "user_confirmed_trust",
];

fn bare_method_violations(files: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (file, text) in files {
        for (n, line) in common::code(text).lines().enumerate() {
            for m in NODE_METHODS {
                for pos in word_positions(line, m) {
                    if !line[pos + m.len()..].starts_with('(') {
                        bad.push(format!("{file}:{}: {m} не вызов: {}", n + 1, line.trim()));
                    }
                }
            }
        }
    }
    bad
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
    // и нигде больше в src/ эти команды не создаются (в том числе в `model.rs`)
    let bad = placement_violations(&files);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn user_intents_are_built_only_on_screens() {
    let files = common::src_files();
    let bad = intent_violations(&files);
    assert!(bad.is_empty(), "{bad:#?}");
    // охрана не пустая: на экранах эти намерения действительно создаются
    for name in GUARDED_INTENTS {
        let on_screens = files
            .iter()
            .filter(|(n, _)| n.starts_with("src/screens/"))
            .any(|(_, t)| {
                common::code(t).contains(&format!("Intent::{name}"))
                    || common::code(t).contains(&format!("S::{name}"))
            });
        assert!(on_screens, "{name}: на экранах не найдено");
    }
}

#[test]
fn watched_types_have_no_aliases_or_variant_imports() {
    let bad = alias_violations(&common::src_files());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn node_methods_are_never_taken_without_a_call() {
    let bad = bare_method_violations(&common::src_files());
    assert!(bad.is_empty(), "{bad:#?}");
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
        // имя как слово, с вызовом или без него (`.map(Node::echo_probe)` тоже место)
        let places = files_with_word(&files, needle.trim_end_matches('('));
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

fn src(name: &str, text: &str) -> (String, String) {
    (name.to_owned(), text.to_owned())
}

#[test]
fn control_model_rs_is_not_exempt() {
    // `Command::EchoProbe` или `ExternalMode::Probe` в `model.rs` (в ветке `Outcome::Snapshot`)
    // ловится: файл не в списке разрешённых
    let clean = vec![src("src/model.rs", "fn f() { vec![Command::Shutdown]; }\n")];
    assert!(placement_violations(&clean).is_empty());
    for cmd in [
        "Command::EchoProbe",
        "Command::ReachCheck",
        "ExternalMode::Probe",
    ] {
        let text = format!("Outcome::Snapshot(s) => {{\n    out.push({cmd});\n}}\n");
        assert!(
            !placement_violations(&[src("src/model.rs", &text)]).is_empty(),
            "{cmd}"
        );
    }
    // записанные места по-прежнему разрешены
    let ok = vec![src("src/worker_ops.rs", "Command::EchoProbe => {}\n")];
    assert!(placement_violations(&ok).is_empty());
}

const GOOD_ACCESS: &str = "impl Model {
    pub fn update_access(&mut self, intent: AccessIntent) -> Vec<Command> {
        use AccessIntent as A;
        match intent {
            A::AccessCheck => {
                vec![Command::ReachCheck]
            }
            A::AccessAuto => {
                vec![Command::UpnpIdentify]
            }
        }
    }

    pub fn access_progress(&mut self) -> Vec<Command> {
        let AccessStage::Waiting { deadline } = self.access.stage else {
            return Vec::new();
        };
        cmds.extend(self.update_access(AccessIntent::AccessCheck));
        cmds
    }
}

#[cfg(test)]
mod tests {
    fn t() {
        acc(&mut m, AccessIntent::AccessAuto);
    }
}
";

fn intent_files(access: &str) -> Vec<(String, String)> {
    vec![
        src("src/access_model.rs", access),
        src(
            "src/screens/access.rs",
            "out.push(acc(AccessIntent::AccessAuto));\nout.push(main(MainIntent::GetIp));\n",
        ),
        src(
            "src/main_model.rs",
            "I::GetIp => {\n    vec![]\n}\nOutcome::GetIp(r) => {}\n",
        ),
    ]
}

#[test]
fn control_intents_only_on_screens() {
    assert!(intent_violations(&intent_files(GOOD_ACCESS)).is_empty());
    // чужие файлы создают намерение: модель, app.rs, псевдоним в модели
    for (file, line) in [
        ("src/model.rs", "out.push(MainIntent::GetIp);"),
        (
            "src/app.rs",
            "out.push(Intent::Main(MainIntent::AddCreate));",
        ),
        ("src/main_model.rs", "out.push(I::GetIp);"),
        ("src/settings_model.rs", "self.update(S::EchoSave);"),
        ("src/settings_model.rs", "let x = S::EchoClear;"),
        ("src/update_model.rs", "acc(AccessIntent::AccessAllow);"),
        ("src/update_model.rs", "acc(AccessIntent::AccessDone);"),
        ("src/fixtures.rs", "acc(A::AccessCheck);"),
    ] {
        let mut files = intent_files(GOOD_ACCESS);
        files.push(src(file, &format!("{line}\n")));
        assert!(!intent_violations(&files).is_empty(), "{file}: {line}");
    }
    // исключение только для `AccessCheck` в `access_progress` после `Waiting`
    let other_intent = GOOD_ACCESS.replace(
        "self.update_access(AccessIntent::AccessCheck)",
        "self.update_access(AccessIntent::AccessAllow)",
    );
    assert!(!intent_violations(&intent_files(&other_intent)).is_empty());
    let before_waiting = GOOD_ACCESS.replace(
        "let AccessStage::Waiting { deadline } = self.access.stage else {",
        "cmds.extend(self.update_access(AccessIntent::AccessCheck));\n        let AccessStage::Waiting { deadline } = self.access.stage else {",
    );
    assert!(!intent_violations(&intent_files(&before_waiting)).is_empty());
    let other_fn = GOOD_ACCESS.replace("pub fn access_progress(", "pub fn access_other(");
    assert!(!intent_violations(&intent_files(&other_fn)).is_empty());
    let second = GOOD_ACCESS.replace(
        "        cmds\n",
        "        cmds.extend(self.update_access(AccessIntent::AccessCheck));\n        cmds\n",
    );
    assert!(!intent_violations(&intent_files(&second)).is_empty());
    let elsewhere = vec![src(
        "src/settings_model.rs",
        "pub fn access_progress(&mut self) {\n    let AccessStage::Waiting { deadline } = x else { return };\n    self.update_access(AccessIntent::AccessCheck);\n}\n",
    )];
    assert!(!intent_violations(&elsewhere).is_empty());
    // комментарий созданием не считается
    let commented = vec![src("src/model.rs", "// MainIntent::GetIp\n")];
    assert!(intent_violations(&commented).is_empty());
}

#[test]
fn control_aliases_and_variant_imports() {
    let ok = |file: &str, text: &str| alias_violations(&[src(file, text)]).is_empty();
    assert!(ok("src/model.rs", "use crate::model::{Command, Model};\n"));
    assert!(ok("src/main_model.rs", "use MainIntent as I;\n"));
    assert!(ok(
        "src/screens/settings.rs",
        "use crate::settings_model::{\n    ClockUi,\n    SettingsIntent as S,\n};\n"
    ));
    assert!(ok("src/worker_ops.rs", "let n = x as u64;\n"));
    for (file, text) in [
        ("src/worker_ops.rs", "use crate::model::Command as C;\n"),
        (
            "src/worker_ops.rs",
            "use crate::model::{Model, Command as C};\n",
        ),
        (
            "src/worker_ops.rs",
            "use crate::model::{\n    Model,\n    Command as Cmd,\n};\n",
        ),
        (
            "src/worker_ops.rs",
            "use crate::access_model::ExternalMode as E;\n",
        ),
        (
            "src/worker_ops.rs",
            "use crate::access_model::ExternalMode::*;\n",
        ),
        (
            "src/worker_ops.rs",
            "use crate::access_model::ExternalMode::{Probe, Use};\n",
        ),
        ("src/worker_ops.rs", "use Command::*;\n"),
        (
            "src/worker_ops.rs",
            "use crate::model::Command::{EchoProbe};\n",
        ),
        (
            "src/worker_ops.rs",
            "pub(crate) use crate::model::Command as C;\n",
        ),
        ("src/worker_ops.rs", "type C = Command;\n"),
        (
            "src/worker_ops.rs",
            "pub type E = crate::access_model::ExternalMode;\n",
        ),
        (
            "src/screens/access.rs",
            "use crate::access_model::AccessIntent as X;\n",
        ),
        (
            "src/screens/access.rs",
            "use crate::access_model::AccessIntent::*;\n",
        ),
        (
            "src/screens/add_friend.rs",
            "use crate::main_model::MainIntent as I;\n",
        ),
        ("src/access_model.rs", "use MainIntent as A;\n"),
        ("src/access_model.rs", "use crate::model::Intent as I;\n"),
        ("src/update_model.rs", "use SettingsIntent as S;\n"),
    ] {
        assert!(!ok(file, text), "{file}: {text}");
    }
}

#[test]
fn control_methods_without_a_call() {
    let ok = |text: &str| bare_method_violations(&[src("src/worker_ops.rs", text)]).is_empty();
    assert!(ok(
        "let r = node.echo_probe();\nlet s = Node::reach_check(node);\n"
    ));
    assert!(ok("let echo_probe_count = 1;\n"));
    for text in [
        "let f = Node::echo_probe;\n",
        "let r = jobs.map(Node::reach_check);\n",
        "let f = node.echo_probe;\n",
        "let r = node.reach_check ();\n",
        "let f: fn(&Node) = Node::upnp_identify;\n",
        "let f = Node::confirm_manual_forward;\n",
    ] {
        assert!(!ok(text), "{text}");
    }
    // имя без вызова в другом файле тоже место (проверка «только `worker_ops.rs`»)
    let other = vec![src("src/screens/x.rs", "let f = Node::echo_probe;\n")];
    assert_eq!(
        files_with_word(&other, "echo_probe"),
        vec!["src/screens/x.rs"]
    );
}
