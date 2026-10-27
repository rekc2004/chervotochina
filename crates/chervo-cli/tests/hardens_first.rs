//! Охрана по тексту (этап 17, C07): `main` вызывает `harden_process` первым делом, до чтения
//! аргументов и любого другого действия. Оболочка GUI (этап 18) обязана делать то же до
//! загрузки любого ключа; для неё этот тест нужно скопировать.

use std::path::Path;

#[test]
fn cli_main_hardens_first() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let text = std::fs::read_to_string(path)
        .expect("read main.rs")
        .replace("\r\n", "\n");
    // без строк-комментариев: упоминание в комментарии не считается вызовом
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        code.matches("harden_process()").count(),
        1,
        "ровно один вызов harden_process()"
    );
    let main_at = code.find("fn main(").expect("fn main");
    let body = &code[main_at..];
    let open = body.find('{').expect("тело main");
    let first_stmt = body[open + 1..].trim_start();
    assert!(
        first_stmt.starts_with("let _hardening = chervo_core::harden_process();"),
        "первая инструкция main не harden_process: {}",
        first_stmt.lines().next().unwrap_or("")
    );
}
