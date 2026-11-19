//! Охрана «у каждого пункта есть значок «?»» (этап 18г). Простая эвристика по тексту экранов
//! `src/screens/*.rs` (без тестовых модулей): в файле вызовов `help_mark(`, `label_with_help(` и
//! `*_with_help(` не меньше, чем нажимаемых и вводимых пунктов (`ui.button(`, `ui.small_button(`,
//! `ui.checkbox(`, `ui.radio(`, `ui.radio_value(`, `ui.selectable_label(`, `Button::new(`,
//! `Checkbox::new(`, `TextEdit::`, `text_edit_singleline(`) за вычетом строк с пометкой
//! `// без ?:` (очевидные: «Отмена», «Закрыть», вкладки). Очевидные кнопки в остальном идут через
//! `plain_button` и не считаются пунктами. Не проверяет, что «?» стоит рядом именно с этим пунктом:
//! это охрана от забытых пунктов, а не от неверного места.
//! Не смотрятся: `common.rs` (там сами помощники), `mod.rs`, `close.rs` (окно закрытия по
//! решению владельца без «?»).

mod common;

const WIDGETS: [&str; 10] = [
    "ui.button(",
    "ui.small_button(",
    "ui.checkbox(",
    "ui.radio(",
    "ui.radio_value(",
    "ui.selectable_label(",
    "Button::new(",
    "Checkbox::new(",
    "TextEdit::",
    "text_edit_singleline(",
];

const SKIPPED: [&str; 3] = [
    "src/screens/common.rs",
    "src/screens/mod.rs",
    "src/screens/close.rs",
];

const EXEMPT: &str = "// без ?:";

fn count(line: &str, needle: &str) -> usize {
    line.matches(needle).count()
}

/// (пунктов, значков) в тексте экрана без тестового модуля.
fn tally(text: &str) -> (usize, usize) {
    let product = text.split("\n#[cfg(test)]").next().unwrap_or(text);
    let (mut widgets, mut helps) = (0, 0);
    for line in product.lines() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        if line.contains(EXEMPT) {
            continue;
        }
        // код до хвостового комментария
        let code = line.split("//").next().unwrap_or(line);
        widgets += WIDGETS.iter().map(|w| count(code, w)).sum::<usize>();
        if !code.contains("fn ") {
            helps += count(code, "help_mark(") + count(code, "_with_help(");
        }
    }
    (widgets, helps)
}

fn screens() -> Vec<(String, String)> {
    common::src_files()
        .into_iter()
        .filter(|(n, _)| n.starts_with("src/screens/") && !SKIPPED.contains(&n.as_str()))
        .collect()
}

#[test]
fn every_screen_item_has_a_help_mark() {
    let files = screens();
    // охрана видит все экраны вкладок, помощника и запуска
    for need in [
        "src/screens/friends.rs",
        "src/screens/add_friend.rs",
        "src/screens/send.rs",
        "src/screens/offers.rs",
        "src/screens/transfers.rs",
        "src/screens/diagnosis.rs",
        "src/screens/settings.rs",
        "src/screens/update.rs",
        "src/screens/access.rs",
        "src/screens/start.rs",
    ] {
        assert!(files.iter().any(|(n, _)| n == need), "нет файла {need}");
    }
    let mut bad = Vec::new();
    for (name, text) in &files {
        let (widgets, helps) = tally(text);
        if helps < widgets {
            bad.push(format!("{name}: пунктов {widgets}, значков «?» {helps}"));
        }
    }
    assert!(bad.is_empty(), "забыт значок «?»:\n{}", bad.join("\n"));
}

#[test]
fn control_guard_can_fail() {
    // кнопка без значка: охрана ловит
    assert_eq!(tally("if ui.button(x).clicked() {}\n"), (1, 0));
    // с помощником значок есть
    assert_eq!(
        tally("if button_with_help(ui, a, b).clicked() {}\n"),
        (0, 1)
    );
    // пометка очевидной снимает пункт; определение помощника не считается значком
    assert_eq!(
        tally("let t = ui.selectable_label(a, b); // без ?: очевидная\n"),
        (0, 0)
    );
    assert_eq!(tally("pub fn x_with_help(ui: &mut Ui) {}\n"), (0, 0));
    // тестовый модуль не считается
    assert_eq!(
        tally("fn a() {}\n#[cfg(test)]\nmod t { ui.button(x); }\n"),
        (0, 0)
    );
    // поле ввода тоже пункт
    assert_eq!(
        tally("let e = egui::TextEdit::singleline(&mut t);\n"),
        (1, 0)
    );
}
