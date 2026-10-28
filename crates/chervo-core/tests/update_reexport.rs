//! Охрана реэкспорта проверки выпусков (этап 19г-1, Р19г-4 и Р19г-5). Сеть для оболочек идёт
//! только через `chervo_core::update::check_latest(permit, ..)`, а разрешение выдаёт узел при
//! записанном согласии. Поэтому ядро не должно отдавать наружу ни крейты `chervo_update` и
//! `chervo_update_check` целиком, ни сырую `chervo_update_check::check_latest`, ни глоб-реэкспорт
//! этих крейтов; а зависимости ядра на них идут без `features` (там `fuzzing`).
//!
//! Текстовый разбор без `cargo`, как у остальных охран ядра.

use std::fs;
use std::path::{Path, PathBuf};

/// Предложения `pub use ...;` и `pub extern crate ...;` без комментариев, пробелы схлопнуты.
fn pub_statements(src: &str) -> Vec<String> {
    let code: String = src
        .replace("\r\n", "\n")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ");
    code.split(';')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| {
            // начало предложения может прятаться за предыдущим текстом (`... } pub use ...`)
            s.contains("pub use ") || s.contains("pub extern crate ")
        })
        .collect()
}

fn mentions_word(s: &str, word: &str) -> bool {
    s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == word)
}

/// Реэкспорты, которых в ядре быть не должно.
fn reexport_violations(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for st in pub_statements(src) {
        let Some(at) = st.find("chervo_update") else {
            continue;
        };
        let rest = &st[at..];
        // путь до первого `::`, ` as ` или конца предложения
        let path_end = rest
            .find("::")
            .or_else(|| rest.find(" as "))
            .unwrap_or(rest.len());
        let krate = rest[..path_end].trim();
        let whole_crate = !rest.contains("::");
        let is_update = krate == "chervo_update" || krate == "chervo_update_check";
        if !is_update {
            continue;
        }
        if whole_crate
            || rest.contains('*')
            || mentions_word(rest, "self")
            || (krate == "chervo_update_check" && mentions_word(rest, "check_latest"))
        {
            out.push(st.clone());
        }
    }
    out
}

/// Строки `Cargo.toml`, нарушающие правило «зависимости `chervo-update*` без `features`».
fn manifest_violations(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in manifest.replace("\r\n", "\n").lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        // табличная форма `[dependencies.chervo-update]` позволяет задать features ниже
        if t.starts_with('[') && t.contains("chervo-update") {
            out.push(t.to_owned());
            continue;
        }
        if t.starts_with("chervo-update")
            && (t.contains("features") || t.contains("fuzzing") || t.contains("default-features"))
        {
            out.push(t.to_owned());
        }
    }
    out
}

fn core_src_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

#[test]
fn reexport_guard_self_check() {
    let bad = [
        "pub use chervo_update_check;",
        "pub use chervo_update;",
        "pub use chervo_update_check as x;",
        "pub use chervo_update_check::check_latest;",
        "pub use chervo_update_check::{CheckError, check_latest};",
        "pub use chervo_update_check::{\n    CheckError,\n    check_latest as raw,\n};",
        "pub use chervo_update_check::*;",
        "pub use chervo_update::*;",
        "pub use chervo_update::{self, Version};",
        "pub use chervo_update_check::{self};",
        "pub extern crate chervo_update;",
        "pub use  chervo_update_check ;",
        "mod a {} pub use chervo_update_check::check_latest;",
        "pub use chervo_update_check::{CheckError};\r\npub use chervo_update::*;\r\n",
    ];
    for (i, s) in bad.iter().enumerate() {
        assert!(
            !reexport_violations(s).is_empty(),
            "обход {i} не пойман: {s:?}"
        );
    }
    let good = [
        "pub use chervo_update::{Freshness, KeyId, Version};",
        "pub use chervo_update_check::{CheckError, RELEASES_PAGE, UpdateStatus};",
        "use chervo_update_check::check_latest;",
        "// pub use chervo_update_check::check_latest;\npub use chervo_update::Version;",
        "//! pub use chervo_update::*;\n",
        "pub use chervo_addr;\npub use chervo_connect;",
        "pub fn check_latest(permit: P) { chervo_update_check::check_latest(v) }",
    ];
    for (i, s) in good.iter().enumerate() {
        assert!(
            reexport_violations(s).is_empty(),
            "ложное срабатывание {i}: {s:?}: {:?}",
            reexport_violations(s)
        );
    }
}

#[test]
fn manifest_guard_self_check() {
    let bad = [
        "[dependencies]\nchervo-update-check = { workspace = true, features = [\"fuzzing\"] }\n",
        "[dependencies]\nchervo-update = { workspace = true, features = [\"x\"] }\n",
        "[dependencies]\nchervo-update-check = { workspace = true, default-features = false }\n",
        "[dependencies.chervo-update-check]\nworkspace = true\nfeatures = [\"fuzzing\"]\n",
        "[dependencies]\nchervo-update-check.features = [\"fuzzing\"]\n",
    ];
    for (i, s) in bad.iter().enumerate() {
        assert!(
            !manifest_violations(s).is_empty(),
            "обход {i} не пойман: {s:?}"
        );
    }
    let good = "[dependencies]\n# features = fuzzing в комментарии\nchervo-update.workspace = true\n\
                chervo-update-check.workspace = true\n";
    assert!(manifest_violations(good).is_empty());
}

#[test]
fn core_has_no_bypass_reexport() {
    let files = core_src_files();
    assert!(files.len() >= 15, "найдено файлов: {}", files.len());
    for f in &files {
        let src = fs::read_to_string(f).unwrap();
        let bad = reexport_violations(&src);
        assert!(bad.is_empty(), "{}: {bad:?}", f.display());
    }
    // положительный контроль: поимённый реэкспорт на месте, а разбор его не пропускает
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    assert!(lib.contains("pub mod update;"));
    let upd =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/update.rs")).unwrap();
    assert!(
        pub_statements(&upd).len() >= 2,
        "реэкспорт update.rs не виден охране"
    );
}

#[test]
fn core_update_dependencies_have_no_features() {
    let own = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(
        manifest_violations(&own).is_empty(),
        "{:?}",
        manifest_violations(&own)
    );
    // положительный контроль: обе зависимости объявлены
    for name in [
        "chervo-update.workspace = true",
        "chervo-update-check.workspace = true",
    ] {
        assert!(
            own.lines().any(|l| l.trim() == name),
            "в Cargo.toml ядра нет строки `{name}`"
        );
    }
}
