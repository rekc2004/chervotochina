//! Проверка общего разборщика кода для охранных тестов (`common::code`, `common::enclosing_arm`):
//! комментарии не считаются кодом, а `//` внутри строки (адрес, путь) не обрезает строку.

mod common;

#[test]
fn comment_markers_inside_strings_do_not_cut_the_line() {
    let c = common::code("let u = \"https://example\"; let x = fs::write(p, b);\n");
    assert!(c.contains("fs::write"), "{c}");
    assert!(c.contains("https://example"));
    // многострочная строка: вторая строка начинается с `//`, но это текст
    let c = common::code("let s = \"a\n// File::create(p)\nb\";\nlet y = 1;\n");
    assert!(c.contains("File::create"), "{c}");
    // символьный литерал с кавычкой не открывает строку
    let c = common::code("let q = '\"'; let z = File::create(p); // хвост\n");
    assert!(c.contains("File::create") && !c.contains("хвост"), "{c}");
    // экранированная кавычка внутри строки
    let c = common::code("let s = \"a\\\"//b\"; File::create(p);\n");
    assert!(c.contains("File::create"), "{c}");
}

#[test]
fn real_comments_are_removed() {
    let c =
        common::code("// std::fs::write(p, b)\nlet a = 1; // File::create(p)\n/// doc fs::write\n");
    assert!(
        !c.contains("fs::write") && !c.contains("File::create"),
        "{c}"
    );
    assert!(c.contains("let a = 1;"));
}

#[test]
fn enclosing_arm_finds_the_match_arm() {
    let src = "match c {\n    A::One => {\n        if x {\n            call();\n        }\n    }\n    A::Two => call2(),\n}\n";
    let lines: Vec<&str> = src.lines().collect();
    assert_eq!(common::enclosing_arm(&lines, 3), Some("    A::One => {"));
    // сама строка-ветка лежит в `match`, у которого заголовка с `=>` нет
    assert_eq!(common::enclosing_arm(&lines, 6), None);
    assert_eq!(common::enclosing_arm(&lines, 0), None);
}
