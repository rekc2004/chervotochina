//! Охрана «тестовые узлы слушают только петлю» (этап 18е, п.1). Причина: тестовый бинарь,
//! открывший UDP на `0.0.0.0`, вызывает окно брандмауэра Windows (на каждую пересборку, имя с
//! хешем). Текстовая проверка исходников без `cargo`, эвристика такая:
//!
//! 1. В тестовых помощниках узла (`chervo-core/tests`, `chervo-cli/tests`, а также
//!    `chervo-core/src/node/testing.rs`; `loopback.rs` не проверяется: у него по умолчанию
//!    `UNSPECIFIED`) нет привязки на «любой адрес»:
//!    `UNSPECIFIED`, `0.0.0.0`, `[::]`, `[0, 0, 0, 0]`, `(0, 0, 0, 0)`. Строки-комментарии
//!    пропускаются. Файл этого стража исключён (в нём эти слова названы).
//! 2. Файл тестов, который зовёт `first_run_setup` или `Node::open(`, должен либо
//!    быть общим помощником (`support/harness.rs`, где `cfg_in` включает петлю), либо сам звать
//!    `bind_loopback_only` (до выбора порта) или брать конфигурацию у помощника (`cfg_in`,
//!    `Rig`).
//! 3. В продуктовых исходниках (`crates/*/src`, кроме четырёх файлов ядра) имя `bind_loopback_only`
//!    и `loopback::` не встречаются; в `node/mod.rs` строка `mod loopback;` и `pub use` его
//!    стоят сразу под `#[cfg(any(test, feature = "test-net"))]`, а `listen_ip` без этого условия
//!    возвращает `Ipv4Addr::UNSPECIFIED` (продукт слушает `0.0.0.0`).
//!
//! Ограничение: проверка текстовая; сокет, открытый в тесте напрямую (`UdpSocket::bind`), она не
//! видит, но слово «любой адрес» в тестовых помощниках ловит.

use std::fs;
use std::path::{Path, PathBuf};

const WILDCARDS: [&str; 6] = [
    "UNSPECIFIED",
    "0.0.0.0",
    "[::]",
    "[0, 0, 0, 0]",
    "(0, 0, 0, 0)",
    "Ipv4Addr::new(0,",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Строки с «любым адресом» вне комментариев.
fn wildcard_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !is_comment(l) && WILDCARDS.iter().any(|w| l.contains(w)))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// Нарушения пункта 2 для одного файла тестов (`rel`: путь с косой чертой от `crates/`).
fn config_violation(rel: &str, text: &str) -> bool {
    let creates = text.contains("first_run_setup(") || text.contains("Node::open(");
    if !creates || rel.ends_with("support/harness.rs") {
        return false;
    }
    !(text.contains("bind_loopback_only") || text.contains("cfg_in(") || text.contains("Rig"))
}

#[test]
fn guard_sees_wildcards_and_missing_loopback() {
    assert!(!wildcard_lines("let a = Ipv4Addr::UNSPECIFIED;").is_empty());
    assert!(!wildcard_lines("bind(\"0.0.0.0:0\")").is_empty());
    assert!(!wildcard_lines("bind(\"[::]:0\")").is_empty());
    assert!(!wildcard_lines("let a = ([0, 0, 0, 0], 0);").is_empty());
    assert!(wildcard_lines("// слушает 0.0.0.0 в продукте").is_empty());
    assert!(wildcard_lines("let a = \"127.0.0.1:0\";").is_empty());
    assert!(config_violation(
        "chervo-core/tests/x.rs",
        "Node::open(cfg, &h)"
    ));
    assert!(config_violation(
        "chervo-core/tests/x.rs",
        "Node::first_run_setup(&c, &h, &r, false)"
    ));
    assert!(!config_violation(
        "chervo-core/tests/x.rs",
        "chervo_core::bind_loopback_only(); Node::first_run_setup(&c)"
    ));
    assert!(!config_violation(
        "chervo-core/tests/x.rs",
        "let c = rig.cfg();"
    ));
}

#[test]
fn test_node_helpers_never_bind_wildcard() {
    let mut files = Vec::new();
    for dir in ["chervo-core/tests", "chervo-cli/tests"] {
        walk(&root().join("crates").join(dir), &mut files);
    }
    // `loopback.rs` не проверяется: там по умолчанию (переключатель выключен) `UNSPECIFIED`
    files.push(root().join("crates/chervo-core/src/node/testing.rs"));
    assert!(files.len() >= 20, "найдено файлов: {}", files.len());
    for f in &files {
        if f.file_name().is_some_and(|n| n == "loopback_guard.rs") {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        let bad = wildcard_lines(&text);
        assert!(bad.is_empty(), "{}: {bad:?}", f.display());
        let rel = f
            .strip_prefix(root().join("crates"))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        assert!(
            !config_violation(&rel, &text),
            "{rel}: узел создаётся без петли (вызовите bind_loopback_only или возьмите cfg_in)"
        );
    }
}

#[test]
fn product_never_names_loopback_switch() {
    let allowed = [
        "chervo-core/src/node/mod.rs",
        "chervo-core/src/node/loopback.rs",
        "chervo-core/src/node/testing.rs",
        "chervo-core/src/node/network.rs",
    ];
    let mut files = Vec::new();
    for e in fs::read_dir(root().join("crates")).unwrap() {
        walk(&e.unwrap().path().join("src"), &mut files);
    }
    assert!(files.len() > 100, "найдено файлов: {}", files.len());
    for f in &files {
        let rel = f
            .strip_prefix(root().join("crates"))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if allowed.contains(&rel.as_str()) {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        assert!(
            !text.contains("bind_loopback_only") && !text.contains("loopback::"),
            "{rel}: переключатель петли вне ядра"
        );
    }
    // в `mod.rs`: каждое упоминание модуля стоит под условием, продуктовый `listen_ip` слушает всё
    let m = fs::read_to_string(root().join("crates/chervo-core/src/node/mod.rs")).unwrap();
    let lines: Vec<&str> = m.lines().collect();
    let cfg = "#[cfg(any(test, feature = \"test-net\"))]";
    let mut seen = 0;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t == "mod loopback;" || t == "pub use self::loopback::bind_loopback_only;" {
            seen += 1;
            let above: Vec<&str> = lines[..i]
                .iter()
                .rev()
                .map(|x| x.trim())
                .take_while(|x| x.starts_with("#["))
                .collect();
            assert!(
                above.contains(&cfg),
                "строка {} без условия test-net",
                i + 1
            );
        }
    }
    assert_eq!(seen, 2, "ожидались `mod loopback;` и `pub use`");
    let product = "#[cfg(not(any(test, feature = \"test-net\")))]\nfn listen_ip() -> Ipv4Addr {\n    Ipv4Addr::UNSPECIFIED\n}";
    assert!(
        m.replace("\r\n", "\n").contains(product),
        "продуктовый listen_ip должен возвращать Ipv4Addr::UNSPECIFIED"
    );
}
