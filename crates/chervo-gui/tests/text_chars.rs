//! Охрана Ж1 (этап 18в): пользовательские тексты состоят только из знаков, которые есть в шрифте
//! окна. Стрелка «→» показывалась квадратиком. Читает константы `&str` из файлов `texts.rs` всех
//! крейтов, чьи тексты показывает окно; при нарушении называет константу и знак.

use std::fs;
use std::path::PathBuf;

/// Файлы с пользовательскими текстами (от корня `crates/`).
const TEXT_FILES: [&str; 7] = [
    "chervo-gui/src/texts.rs",
    "chervo-connect/src/texts.rs",
    "chervo-core/src/node/texts.rs",
    "chervo-lan/src/texts.rs",
    "chervo-upnp/src/texts.rs",
    "chervo-receive/src/texts.rs",
    "chervo-addr/src/book.rs",
];

const EXTRA_ALLOWED: &str = ".,:;!?()«»\"'-–—…%/№+=_\n";

fn allowed(c: char) -> bool {
    matches!(c, 'а'..='я' | 'А'..='Я' | 'ё' | 'Ё' | 'a'..='z' | 'A'..='Z' | '0'..='9' | ' ')
        || EXTRA_ALLOWED.contains(c)
        // подстановка `{ver}` в тексте о лицензиях заменяется номером версии
        || c == '{'
        || c == '}'
}

/// Первый запрещённый знак текста.
fn first_bad(text: &str) -> Option<char> {
    text.chars().find(|c| !allowed(*c))
}

/// Разбор одного строкового литерала с начала `rest` (после открывающей кавычки).
fn literal(rest: &str) -> String {
    let mut out = String::new();
    let mut it = rest.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '"' => break,
            '\\' => match it.next() {
                Some('n') => out.push('\n'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('\n') | Some('\r') => {
                    while it.peek().is_some_and(|c| c.is_whitespace()) {
                        it.next();
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => break,
            },
            c => out.push(c),
        }
    }
    out
}

/// (имя константы, текст) для каждой `const NAME: &str = "...";` файла.
fn consts(src: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find("const ") {
        let after = &rest[pos + 6..];
        rest = after;
        let Some(colon) = after.find(':') else { break };
        let name = after[..colon].trim().to_owned();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        let tail = &after[colon..];
        let Some(eq) = tail.find('=') else { break };
        let decl = &tail[..eq];
        if !decl.contains("&str") || decl.contains('[') {
            continue;
        }
        let value = tail[eq + 1..].trim_start();
        if let Some(body) = value.strip_prefix('"') {
            found.push((name, literal(body)));
        }
    }
    found
}

#[test]
fn control_arrow_is_rejected() {
    // контрольный случай: знак, из-за которого появилась охрана, должен падать
    assert_eq!(first_bad("«Друзья» → «Отправить»"), Some('→'));
    assert_eq!(first_bad("«Друзья», затем «Отправить»"), None);
    let found = consts("pub const X: &str = \"а → б\";");
    assert_eq!(found, vec![("X".to_owned(), "а → б".to_owned())]);
}

#[test]
fn user_texts_use_only_allowed_symbols() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut total = 0usize;
    let mut bad = Vec::new();
    for file in TEXT_FILES {
        let path = root.join(file);
        let Ok(src) = fs::read_to_string(&path) else {
            // крейт без файла текстов: проверять нечего
            continue;
        };
        let src = src.replace("\r\n", "\n");
        for (name, text) in consts(&src) {
            total += 1;
            if let Some(c) = first_bad(&text) {
                bad.push(format!("{file}: {name}: знак {c:?} (U+{:04X})", c as u32));
            }
        }
    }
    assert!(total > 100, "прочитано слишком мало констант: {total}");
    assert!(
        bad.is_empty(),
        "запрещённые знаки в текстах:\n{}",
        bad.join("\n")
    );
}
