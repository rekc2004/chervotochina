//! Охрана «поток окна не вызывает узел» (этап 18б, SPEC 4.1): методы узла синхронные и могут
//! блокироваться (до ~12 с), поэтому в `screens/` и `app.rs` нет ни `node.`, ни `Node::`, ни
//! самого типа `Node`. Узел живёт только в `worker.rs`.

mod common;

/// Слово `Node` как отдельный идентификатор (не `NodeError`, не `node_open`).
fn has_node_type(code: &str) -> bool {
    let b = code.as_bytes();
    let mut from = 0;
    while let Some(i) = code[from..].find("Node") {
        let s = from + i;
        let e = s + 4;
        let before_ok = s == 0 || !(b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_');
        let after_ok = e >= b.len() || !(b[e].is_ascii_alphanumeric() || b[e] == b'_');
        if before_ok && after_ok {
            return true;
        }
        from = e;
    }
    false
}

fn violations(text: &str) -> Vec<String> {
    let code = common::code(text);
    code.lines()
        .filter(|l| l.contains("node.") || l.contains("Node::") || has_node_type(l))
        .map(|l| l.trim().to_owned())
        .collect()
}

fn ui_files() -> Vec<(String, String)> {
    common::src_files()
        .into_iter()
        .filter(|(n, _)| n.starts_with("src/screens/") || n == "src/app.rs")
        .collect()
}

#[test]
fn ui_files_do_not_call_the_node() {
    let files = ui_files();
    // охрана видит экраны и app.rs (иначе она пуста)
    assert!(files.iter().any(|(n, _)| n == "src/app.rs"));
    assert!(files.iter().any(|(n, _)| n == "src/screens/start.rs"));
    let mut bad = Vec::new();
    for (name, text) in &files {
        for v in violations(text) {
            bad.push(format!("{name}: {v}"));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn control_guard_can_fail() {
    assert!(!violations("self.node.friends();\n").is_empty());
    assert!(!violations("let n = Node::open(cfg, &h);\n").is_empty());
    assert!(!violations("fn show(n: &Node) {}\n").is_empty());
    assert!(!violations("use chervo_core::{Node, NodeError};\n").is_empty());
    // не нарушения
    assert!(violations("use chervo_core::NodeError;\n").is_empty());
    assert!(violations("if model.node_open { }\n").is_empty());
    assert!(violations("// node.friends() в комментарии\n").is_empty());
    assert!(violations("let e: NodeEvent = x;\n").is_empty());
}
