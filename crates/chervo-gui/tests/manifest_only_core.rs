//! Охрана состава GUI (этап 18б, SPEC 4.3/4.5, DECISION 2.9): путевая зависимость только
//! `chervo-core`; внешние ровно `eframe`, `rfd`, `qrcode` с точными версиями `=x.y.z` и
//! `default-features = false`; ни `[build-dependencies]`, ни `[dev-dependencies]`, ни `build.rs`;
//! `accesskit` только для не-Linux (иначе на Linux придёт zbus 5, запрещённый в `deny.toml`).

mod common;

use std::collections::BTreeSet;
use std::fs;

const PATH_DEPS: [&str; 1] = ["chervo-core"];
const EXTERNAL: [&str; 3] = ["eframe", "qrcode", "rfd"];
/// Точный набор возможностей eframe в корне (DECISION 2.9): без `persistence` и прочего.
const EFRAME_FEATURES: [&str; 6] = [
    "clipboard",
    "default_fonts",
    "glow",
    "wayland",
    "wgpu",
    "x11",
];
const NOT_LINUX: &str = "target.'cfg(not(target_os = \"linux\"))'.dependencies";

/// Таблица манифеста: заголовок без скобок и пары `ключ = значение` (значение как в тексте).
fn tables(manifest: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in manifest.replace("\r\n", "\n").lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let name = t.trim_matches(|c| c == '[' || c == ']').trim().to_owned();
            out.push((name, Vec::new()));
        } else if let (Some((_, rows)), Some((k, v))) = (out.last_mut(), t.split_once('=')) {
            rows.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    out
}

/// Возможности из строки вида `{ ..., features = ["a", "b"] }`, по алфавиту.
fn features_of(row: &str) -> Vec<String> {
    let Some(at) = row.find("features = [") else {
        return Vec::new();
    };
    let rest = &row[at + "features = [".len()..];
    let list = rest.split(']').next().unwrap_or("");
    let mut v: Vec<String> = list
        .split(',')
        .map(|x| x.trim().trim_matches('"').to_owned())
        .filter(|x| !x.is_empty())
        .collect();
    v.sort();
    v
}

/// Нарушения для манифеста крейта и корневого манифеста рабочего пространства.
fn violations(manifest: &str, root: &str, has_build_rs: bool) -> Vec<String> {
    let mut bad = Vec::new();
    if has_build_rs {
        bad.push("есть build.rs".to_owned());
    }
    let mut names = BTreeSet::new();
    for (table, rows) in tables(manifest) {
        let is_deps = table.ends_with("dependencies");
        if table.contains("build-dependencies") || table.contains("dev-dependencies") {
            bad.push(format!("запрещена таблица [{table}]"));
        }
        if table.starts_with("dependencies.") || table.contains(".dependencies.") {
            bad.push(format!("зависимости в виде отдельной таблицы [{table}]"));
        }
        if is_deps {
            for (k, v) in &rows {
                let key = k
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_owned();
                // свои возможности в крейте: eframe только `accesskit` (не Linux), rfd только
                // `xdg-portal` (Linux); всё остальное задано в корне
                let own = features_of(v);
                if key == "eframe" && !own.is_empty() && own != ["accesskit"] {
                    bad.push(format!("eframe: лишние возможности {own:?} в [{table}]"));
                }
                if key == "rfd" && !own.is_empty() && own != ["xdg-portal"] {
                    bad.push(format!("rfd: лишние возможности {own:?} в [{table}]"));
                }
                if key != "eframe" && key != "rfd" && !own.is_empty() {
                    bad.push(format!("{key}: возможности {own:?} не предусмотрены"));
                }
                if v.contains("package") {
                    bad.push(format!("переименование пакета: {key}"));
                }
                // `accesskit` только в таблице не-Linux
                if v.contains("accesskit") && table != NOT_LINUX {
                    bad.push(format!("accesskit вне таблицы не-Linux: [{table}] {key}"));
                }
                names.insert(key);
            }
        }
    }
    let allowed: BTreeSet<String> = PATH_DEPS
        .iter()
        .chain(EXTERNAL.iter())
        .map(|s| (*s).to_owned())
        .collect();
    for n in names.difference(&allowed) {
        bad.push(format!("лишняя зависимость: {n}"));
    }
    for n in allowed.difference(&names) {
        bad.push(format!("нет зависимости: {n}"));
    }
    // версии и свойства берутся из корня: точные и без свойств по умолчанию
    let root_rows: Vec<(String, String)> = tables(root)
        .into_iter()
        .filter(|(t, _)| t == "workspace.dependencies")
        .flat_map(|(_, rows)| rows)
        .collect();
    for n in EXTERNAL {
        match root_rows.iter().find(|(k, _)| k == n) {
            None => bad.push(format!("{n} не объявлен в [workspace.dependencies]")),
            Some((_, v)) => {
                if !v.contains("version = \"=") {
                    bad.push(format!("{n}: версия не закреплена знаком ="));
                }
                if !v.contains("default-features = false") {
                    bad.push(format!("{n}: нет default-features = false"));
                }
                if n == "eframe" && features_of(v) != EFRAME_FEATURES {
                    bad.push(format!(
                        "eframe: набор возможностей {:?}, нужен {EFRAME_FEATURES:?}",
                        features_of(v)
                    ));
                }
                if n != "eframe" && !features_of(v).is_empty() {
                    bad.push(format!("{n}: возможности в корне не предусмотрены"));
                }
            }
        }
    }
    for n in PATH_DEPS {
        match root_rows.iter().find(|(k, _)| k == n) {
            Some((_, v)) if v.contains("path = \"crates/") => {}
            _ => bad.push(format!("{n}: нет путевой зависимости в корне")),
        }
    }
    bad
}

#[test]
fn gui_manifest_has_only_core_and_framework_crates() {
    let dir = common::crate_dir();
    let manifest = fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    let root = fs::read_to_string(dir.join("../../Cargo.toml")).expect("read root Cargo.toml");
    let build_rs = dir.join("build.rs").exists();
    let bad = violations(&manifest, &root, build_rs);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn control_guard_can_fail() {
    let root = "[workspace.dependencies]\nchervo-core = { path = \"crates/chervo-core\", version = \"0.0.0\" }\n\
                eframe = { version = \"=0.37.0\", default-features = false, features = [\"clipboard\", \"default_fonts\", \"wgpu\", \"glow\", \"wayland\", \"x11\"] }\n\
                rfd = { version = \"=0.17.2\", default-features = false }\n\
                qrcode = { version = \"=0.14.1\", default-features = false }\n";
    let good = "[dependencies]\nchervo-core.workspace = true\neframe.workspace = true\nrfd.workspace = true\nqrcode.workspace = true\n\
                [target.'cfg(not(target_os = \"linux\"))'.dependencies]\neframe = { workspace = true, features = [\"accesskit\"] }\n";
    assert_eq!(violations(good, root, false), Vec::<String>::new());

    // лишний внешний пакет
    let extra = format!("{good}[target.'cfg(unix)'.dependencies]\nreqwest = \"1\"\n");
    assert!(
        violations(&extra, root, false)
            .iter()
            .any(|v| v.contains("reqwest"))
    );
    // лишняя путевая зависимость на нижний слой
    let lower = format!("{good}[dependencies.chervo-addr]\npath = \"../chervo-addr\"\n");
    assert!(!violations(&lower, root, false).is_empty());
    // build-зависимости, dev-зависимости, build.rs
    assert!(
        !violations(
            &format!("{good}[build-dependencies]\ncc = \"1\"\n"),
            root,
            false
        )
        .is_empty()
    );
    assert!(
        !violations(
            &format!("{good}[dev-dependencies]\ntempfile = \"3\"\n"),
            root,
            false
        )
        .is_empty()
    );
    assert!(!violations(good, root, true).is_empty());
    // accesskit на Linux
    let linux_ak = format!(
        "{good}[target.'cfg(target_os = \"linux\")'.dependencies]\nrfd = {{ workspace = true, features = [\"accesskit\"] }}\n"
    );
    assert!(
        violations(&linux_ak, root, false)
            .iter()
            .any(|v| v.contains("accesskit"))
    );
    // eframe с хранением состояния
    let persist = root.replace("\"x11\"", "\"x11\", \"persistence\"");
    assert!(
        violations(good, &persist, false)
            .iter()
            .any(|v| v.contains("набор возможностей"))
    );
    // лишняя возможность eframe в манифесте крейта
    let extra = good.replace("[\"accesskit\"]", "[\"accesskit\", \"persistence\"]");
    assert!(
        violations(&extra, root, false)
            .iter()
            .any(|v| v.contains("лишние"))
    );
    // у rfd чужая возможность
    let rfd_extra = format!(
        "{good}[target.'cfg(target_os = \"linux\")'.dependencies]\nrfd = {{ workspace = true, features = [\"tokio\"] }}\n"
    );
    assert!(
        violations(&rfd_extra, root, false)
            .iter()
            .any(|v| v.contains("rfd"))
    );
    // пропавшая зависимость
    let missing = "[dependencies]\nchervo-core.workspace = true\n";
    assert!(!violations(missing, root, false).is_empty());
    // версия без точного закрепления
    let loose = root.replace("=0.37.0", "0.37.0");
    assert!(
        violations(good, &loose, false)
            .iter()
            .any(|v| v.contains("eframe"))
    );
    // свойства по умолчанию включены
    let defaults = root.replace(
        "qrcode = { version = \"=0.14.1\", default-features = false }",
        "qrcode = { version = \"=0.14.1\" }",
    );
    assert!(
        violations(good, &defaults, false)
            .iter()
            .any(|v| v.contains("qrcode"))
    );
}
