//! Охрана по тексту (этап 17, C07; копия `chervo-cli/tests/hardens_first.rs`): `main` вызывает
//! `harden_process` первым делом, до чтения аргументов, до окна и до загрузки любого ключа.

mod common;

/// `Ok`, если в `main_rs` ровно один вызов и это первая инструкция `main`.
fn check(main_rs: &str) -> Result<(), String> {
    let text = main_rs.replace("\r\n", "\n");
    // без строк-комментариев: упоминание в комментарии не считается вызовом
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let calls = code.matches("harden_process()").count();
    if calls != 1 {
        return Err(format!(
            "вызовов harden_process(): {calls}, нужен ровно один"
        ));
    }
    let main_at = code.find("fn main(").ok_or("нет fn main")?;
    let body = &code[main_at..];
    let open = body.find('{').ok_or("нет тела main")?;
    let first_stmt = body[open + 1..].trim_start();
    if first_stmt.starts_with("let _hardening = chervo_core::harden_process();") {
        Ok(())
    } else {
        Err(format!(
            "первая инструкция main не harden_process: {}",
            first_stmt.lines().next().unwrap_or("")
        ))
    }
}

#[test]
fn gui_main_hardens_first() {
    let path = common::crate_dir().join("src/main.rs");
    let text = std::fs::read_to_string(path).expect("read main.rs");
    if let Err(e) = check(&text) {
        panic!("{e}");
    }
}

#[test]
fn windows_subsystem_attribute_is_present() {
    let path = common::crate_dir().join("src/main.rs");
    let text = std::fs::read_to_string(path).expect("read main.rs");
    assert!(
        common::code(&text).contains("#![windows_subsystem = \"windows\"]"),
        "без этого атрибута на Windows открывается консольное окно"
    );
}

#[test]
fn control_guard_can_fail() {
    let good = "fn main() -> ExitCode {\n    let _hardening = chervo_core::harden_process();\n    run()\n}\n";
    assert!(check(good).is_ok());
    // другая инструкция раньше
    let late =
        "fn main() {\n    let a = 1;\n    let _hardening = chervo_core::harden_process();\n}\n";
    assert!(check(late).is_err());
    // вызова нет
    assert!(check("fn main() {\n    run();\n}\n").is_err());
    // вызов только в комментарии
    assert!(check("fn main() {\n    // harden_process()\n    run();\n}\n").is_err());
    // два вызова
    let twice = "fn main() {\n    let _hardening = chervo_core::harden_process();\n    let _h2 = chervo_core::harden_process();\n}\n";
    assert!(check(twice).is_err());
    // результат не сохранён под именем
    let dropped = "fn main() {\n    chervo_core::harden_process();\n}\n";
    assert!(check(dropped).is_err());
}
