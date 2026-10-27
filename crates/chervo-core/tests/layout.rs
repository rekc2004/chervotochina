//! Охрана состава ядра (этап 18а, решение D1). Раньше это был поиск подстрок: ядру нельзя было
//! даже называть `quinn` или `tokio`. Теперь ядру разрешены наш транспорт `chervo-transport-quinn`
//! и `tokio` (рабочие возможности без `rt-multi-thread`), поэтому проверка точная, по ИМЕНАМ
//! прямых зависимостей: запрещены сами крейты `quinn`, `rustls`, `snow`, `ring`, `iroh`, оболочки
//! (`chervo-cli`, `chervo-gui`) и любые крейты GUI.

use std::fs;
use std::path::Path;

/// Запрещённые прямые зависимости ядра (точные имена).
const FORBIDDEN: [&str; 14] = [
    "chervo-cli",
    "chervo-gui",
    "iroh",
    "quinn",
    "rustls",
    "snow",
    "ring",
    "eframe",
    "egui",
    "winit",
    "wgpu",
    "glow",
    "accesskit",
    "tauri",
];

/// Имена зависимостей из таблиц `[dependencies]` и `[target.*.dependencies]` (не dev, не build).
fn direct_dependency_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let section = t.trim_matches(|c| c == '[' || c == ']');
            let table = section == "dependencies"
                || (section.starts_with("target.") && section.ends_with(".dependencies"));
            // `[dependencies.имя]`: имя в заголовке
            if let Some(name) = section.strip_prefix("dependencies.") {
                names.push(name.trim_matches('"').to_owned());
            }
            in_deps = table;
            continue;
        }
        if !in_deps {
            continue;
        }
        let Some((key, value)) = t.split_once('=') else {
            continue;
        };
        let key = key.trim().split('.').next().unwrap_or("").trim_matches('"');
        names.push(key.to_owned());
        // переименование: `x = { package = "quinn", ... }`
        if let Some((_, rest)) = value.split_once("package")
            && let Some(real) = rest.split('"').nth(1)
        {
            names.push(real.to_owned());
        }
    }
    names
}

#[test]
fn guard_matches_names_not_substrings() {
    let sample = "[dependencies]\nchervo-transport-quinn.workspace = true\ntokio.workspace = true\n\
                  [target.'cfg(unix)'.dependencies]\nrustix = { version = \"1\" }\n\
                  [dev-dependencies]\nring = \"0.17\"\n";
    let names = direct_dependency_names(sample);
    assert_eq!(
        names,
        ["chervo-transport-quinn", "tokio", "rustix"],
        "dev-зависимости не считаются, подстрока `quinn` не нарушение"
    );
    let bad = "[dependencies]\nquinn = \"0.11\"\nx = { package = \"rustls\", version = \"1\" }\n\
               [dependencies.snow]\nversion = \"1\"\n";
    let names = direct_dependency_names(bad);
    let hits: Vec<_> = names
        .iter()
        .filter(|n| FORBIDDEN.contains(&n.as_str()))
        .collect();
    assert_eq!(hits.len(), 3, "{names:?}");
}

#[test]
fn workspace_layout() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_manifest = fs::read_to_string(manifest_dir.join("../../Cargo.toml"))
        .expect("read workspace Cargo.toml");
    let crates = [
        "chervo-identity",
        "chervo-addr",
        "chervo-transport",
        "chervo-transport-quinn",
        "chervo-timesync",
        "chervo-token",
        "chervo-friends",
        "chervo-connect",
        "chervo-upnp",
        "chervo-transfer",
        "chervo-receive",
        "chervo-core",
        "chervo-cli",
    ];
    for name in crates {
        let rel = format!("crates/{name}");
        assert!(root_manifest.contains(&rel), "workspace must list {rel}");
        assert!(
            manifest_dir
                .join("../..")
                .join(&rel)
                .join("Cargo.toml")
                .is_file(),
            "missing {rel}/Cargo.toml"
        );
    }
}

#[test]
fn core_direct_dependencies_by_exact_name() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let own = fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read core Cargo.toml");
    let names = direct_dependency_names(&own);
    // разбор что-то нашёл (иначе охрана пуста)
    for must in [
        "tokio",
        "chervo-transport-quinn",
        "chervo-upnp",
        "chervo-timesync",
    ] {
        assert!(names.iter().any(|n| n == must), "нет {must} в {names:?}");
    }
    for n in &names {
        assert!(
            !FORBIDDEN.contains(&n.as_str()),
            "core must not depend on {n}"
        );
    }
    // tokio только с рабочими возможностями (rt, net, time, sync, macros): без многопоточной среды
    assert!(
        !own.contains("rt-multi-thread"),
        "ядру не нужна многопоточная среда tokio"
    );
}
