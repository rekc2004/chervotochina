//! Охрана «GUI ходит только через публичный API узла» (этап 18б, SPEC 4.2/4.5): в `src/` нет
//! обращений к нижним слоям через ядро (`chervo_core::chervo_*`, в том числе в скобках
//! `use chervo_core::{chervo_x, ..}`) и нет `use chervo_core::*` (звёздочка тянет те же слои).
//! Тексты нижних слоёв берутся из `chervo_core::texts`.

mod common;

/// Нарушения в одном файле.
fn violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    let mut bad = Vec::new();
    for line in code.lines() {
        if line.contains("chervo_core::chervo_") || line.contains("chervo_core::*") {
            bad.push(line.trim().to_owned());
        }
    }
    // группы `use chervo_core::{ ... };` на нескольких строках
    let mut rest = code.as_str();
    while let Some(i) = rest.find("chervo_core::{") {
        let tail = &rest[i + "chervo_core::{".len()..];
        let end = tail.find("};").unwrap_or(tail.len());
        let group = &tail[..end];
        for item in group.split(',') {
            let item = item.trim();
            if item.starts_with("chervo_") || item == "*" {
                bad.push(format!("chervo_core::{{{item}}}"));
            }
        }
        rest = tail;
    }
    bad
}

#[test]
fn gui_src_does_not_reach_into_lower_layers() {
    let mut bad = Vec::new();
    for (name, text) in common::src_files() {
        for v in violations(&text) {
            bad.push(format!("{name}: {v}"));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn control_guard_can_fail() {
    assert!(violations("use chervo_core::{Node, NodeConfig};\n").is_empty());
    assert!(violations("use chervo_core::texts::FIRST_RUN_TEXT;\n").is_empty());
    assert!(!violations("use chervo_core::chervo_friends::FriendBook;\n").is_empty());
    assert!(!violations("let b = chervo_core::chervo_addr::X;\n").is_empty());
    assert!(!violations("use chervo_core::{\n    Node,\n    chervo_transfer,\n};\n").is_empty());
    assert!(!violations("use chervo_core::*;\n").is_empty());
    // комментарий не считается
    assert!(violations("// use chervo_core::chervo_friends::X;\n").is_empty());
}
