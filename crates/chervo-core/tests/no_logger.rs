//! Охрана «в продукте нет журнала» (этап 17, B3, решение 1a, C21): в продуктовых крейтах нет
//! ни крейта `log`/`tracing`, ни реализации журнала, ни макросов журнала, ни печати в `src/`
//! (кроме модуля вывода CLI `chervo-cli/src/out.rs`, этап 18в). Журнал в оболочке этапа 18 можно добавить только осознанно, правкой
//! этого теста и новым ревью.
//!
//! Без запуска `cargo`: текстовый разбор манифестов и `Cargo.lock` (работает офлайн). Граф из
//! `Cargo.lock` содержит и dev-зависимости, и платформенные, то есть берётся с запасом: тест
//! строже, чем нормальное дерево.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// Реализации журнала: недопустимы нигде в графе продуктовых крейтов.
const LOGGER_IMPLS: [&str; 22] = [
    "env_logger",
    "pretty_env_logger",
    "tracing-subscriber",
    "tracing-appender",
    "tracing-journald",
    "tracing-oslog",
    "tracing-android",
    "console_subscriber",
    "simplelog",
    "fern",
    "log4rs",
    "flexi_logger",
    "fast_log",
    "femme",
    "stderrlog",
    "slog-term",
    "slog-async",
    "slog-json",
    "android_logger",
    "syslog",
    "systemd-journal-logger",
    "win_etw_logger",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(p: &Path) -> String {
    fs::read_to_string(p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        .replace("\r\n", "\n")
}

fn product_manifests() -> Vec<PathBuf> {
    let mut out = vec![root().join("Cargo.toml")];
    for e in fs::read_dir(root().join("crates")).unwrap() {
        let m = e.unwrap().path().join("Cargo.toml");
        if m.is_file() {
            out.push(m);
        }
    }
    out
}

/// Имена зависимостей из текста манифеста (все таблицы `*dependencies*`, включая
/// `[target.*.dependencies]`, `[dependencies.имя]` и переименование `package = "имя"`).
fn dependency_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            section = t.trim_matches(|c| c == '[' || c == ']').to_owned();
            if let Some((_, tail)) = section.split_once("dependencies.") {
                names.push(tail.trim_matches('"').to_owned());
            }
            continue;
        }
        if !section.contains("dependencies") || section.contains("dependencies.") {
            if section.contains("dependencies.")
                && let Some((_, rest)) = t.split_once("package")
                && let Some(name) = rest.split('"').nth(1)
            {
                names.push(name.to_owned());
            }
            continue;
        }
        let Some((key, value)) = t.split_once('=') else {
            continue;
        };
        let key = key.trim().split('.').next().unwrap_or("").trim_matches('"');
        names.push(key.to_owned());
        if let Some((_, rest)) = value.split_once("package")
            && let Some(name) = rest.split('"').nth(1)
        {
            names.push(name.to_owned());
        }
    }
    names
}

fn is_logger_crate(name: &str) -> bool {
    name == "log"
        || name.starts_with("tracing")
        || name.starts_with("slog")
        || LOGGER_IMPLS.contains(&name)
}

/// Граф `Cargo.lock`: имя пакета -> имена зависимостей (версии не различаются: с запасом).
fn lock_graph(lock: &str) -> (HashMap<String, BTreeSet<String>>, BTreeSet<String>) {
    let mut graph: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut local = BTreeSet::new();
    let (mut name, mut has_source, mut in_deps) = (None::<String>, false, false);
    let mut flush = |name: &mut Option<String>, has_source: &mut bool| {
        if let Some(n) = name.take()
            && !*has_source
        {
            local.insert(n);
        }
        *has_source = false;
    };
    for line in lock.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut name, &mut has_source);
            in_deps = false;
        } else if let Some(v) = t.strip_prefix("name = ") {
            let n = v.trim_matches('"').to_owned();
            graph.entry(n.clone()).or_default();
            name = Some(n);
        } else if t.starts_with("source = ") {
            has_source = true;
        } else if t.starts_with("dependencies = [") {
            in_deps = !t.ends_with(']') || t == "dependencies = [";
        } else if in_deps {
            if t == "]" {
                in_deps = false;
            } else if let (Some(n), Some(first)) = (
                &name,
                t.trim_matches(|c| c == '"' || c == ',').split(' ').next(),
            ) {
                graph.entry(n.clone()).or_default().insert(first.to_owned());
            }
        }
    }
    flush(&mut name, &mut has_source);
    (graph, local)
}

fn reachable(
    graph: &HashMap<String, BTreeSet<String>>,
    roots: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = roots.iter().cloned().collect();
    while let Some(n) = stack.pop() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(next) = graph.get(&n) {
            stack.extend(next.iter().cloned());
        }
    }
    seen
}

#[test]
fn no_logger_in_manifests() {
    // охрана видит нарушения
    let sample = "[dependencies]\nfoo.workspace = true\nlog = \"0.4\"\n[dev-dependencies.tracing]\nversion = \"1\"\n\
                  [target.'cfg(unix)'.dependencies]\nx = { package = \"env_logger\", version = \"1\" }\n";
    let names = dependency_names(sample);
    assert!(
        names.iter().filter(|n| is_logger_crate(n)).count() >= 3,
        "{names:?}"
    );

    let manifests = product_manifests();
    assert!(
        manifests.len() >= 14,
        "найдено манифестов: {}",
        manifests.len()
    );
    let mut all = 0;
    for m in manifests {
        let names = dependency_names(&read(&m));
        all += names.len();
        for n in &names {
            assert!(
                !is_logger_crate(n),
                "{}: зависимость от журнала `{n}`",
                m.display()
            );
        }
    }
    assert!(all > 30, "разбор манифестов ничего не нашёл ({all})");
}

#[test]
fn no_logger_impl_reachable_from_product_crates() {
    // синтетический граф: цепочка до реализации журнала находится
    let lock = "[[package]]\nname = \"chervo-x\"\nversion = \"0.0.0\"\ndependencies = [\n \"a\",\n]\n\n\
                [[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\ndependencies = [\n \"b 1.0.0\",\n]\n\n\
                [[package]]\nname = \"b\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\ndependencies = [\n \"env_logger 0.11.0 (registry+x)\",\n]\n\n\
                [[package]]\nname = \"env_logger\"\nversion = \"0.11.0\"\nsource = \"registry+x\"\n";
    let (g, local) = lock_graph(lock);
    assert_eq!(
        local.iter().map(String::as_str).collect::<Vec<_>>(),
        ["chervo-x"]
    );
    assert!(reachable(&g, &local).contains("env_logger"));

    let text = read(&root().join("Cargo.lock"));
    let (graph, local) = lock_graph(&text);
    let roots: BTreeSet<String> = local
        .into_iter()
        .filter(|n| n.starts_with("chervo-"))
        .collect();
    assert!(
        roots.len() >= 13,
        "продуктовых крейтов в Cargo.lock: {}",
        roots.len()
    );
    let seen = reachable(&graph, &roots);
    // обход действительно идёт вглубь
    for must in ["ring", "snow", "quinn"] {
        assert!(seen.contains(must), "обход графа не дошёл до {must}");
    }
    let bad: Vec<&String> = seen
        .iter()
        .filter(|n| LOGGER_IMPLS.contains(&n.as_str()))
        .collect();
    assert!(
        bad.is_empty(),
        "реализация журнала в графе продуктовых крейтов: {bad:?}"
    );
}

/// Файлы `src/` продуктовых крейтов без тестовых модулей.
fn product_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let name = p.file_name().unwrap().to_string_lossy();
                if name != "tests.rs" && name != "fuzz_tests.rs" {
                    out.push(p);
                }
            }
        }
    }
    let mut files = Vec::new();
    for e in fs::read_dir(root().join("crates")).unwrap() {
        let src = e.unwrap().path().join("src");
        if src.is_dir() {
            walk(&src, &mut files);
        }
    }
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root().join("crates"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            // строки-комментарии не считаются: упоминание в тексте не вызов
            let code = read(&p)
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            (rel, code)
        })
        .collect()
}

/// Вхождения `word` не внутри более длинного идентификатора.
fn has_word(code: &str, word: &str) -> bool {
    code.match_indices(word).any(|(i, _)| {
        !code[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

#[test]
fn no_logger_macros_in_product_src() {
    // охрана видит нарушения
    assert!(has_word("    info!(\"x\");", "info!("));
    assert!(!has_word("fn my_info!(", "info!("));

    let srcs = product_sources();
    assert!(srcs.len() >= 100, "просканировано файлов: {}", srcs.len());
    for (rel, code) in &srcs {
        for w in [
            "log::",
            "tracing::",
            "extern crate log",
            "extern crate tracing",
            "use log;",
            "use tracing;",
            "trace!(",
            "debug!(",
            "info!(",
            "warn!(",
            "error!(",
        ] {
            assert!(!has_word(code, w), "{rel}: `{w}` в продуктовом коде");
        }
    }
}

#[test]
fn no_print_in_product_src_except_cli_out() {
    // Этап 18в: охрана расширена с `chervo-cli/src/main.rs` на весь `chervo-cli/src/`. Печать
    // макросами запрещена везде; единственное место, где продукт открывает стандартный вывод
    // или вывод ошибок, это `chervo-cli/src/out.rs` (вывод CLI намеренный: это его интерфейс).
    assert!(has_word("    println!(\"x\");", "println!("));
    assert!(has_word("let o = std::io::stdout();", "stdout"));
    assert!(!has_word("fn my_stdout(", "stdout"));

    let srcs = product_sources();
    let mut sink_hits = 0;
    for (rel, code) in &srcs {
        for w in ["println!(", "eprintln!(", "print!(", "eprint!(", "dbg!("] {
            assert!(!has_word(code, w), "{rel}: `{w}` в продуктовом коде");
        }
        for w in ["stdout", "stderr"] {
            if has_word(code, w) {
                assert_eq!(
                    rel, "chervo-cli/src/out.rs",
                    "{rel}: `{w}` вне модуля вывода CLI"
                );
                sink_hits += 1;
            }
        }
    }
    // положительный контроль: модуль вывода CLI открывает оба потока
    assert!(
        sink_hits >= 2,
        "ожидались stdout и stderr в chervo-cli/src/out.rs, найдено {sink_hits}"
    );
}
