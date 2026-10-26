//! Охрана «тестовые возможности не попадают в продукт» (этап 18а, исправление M1): свойства
//! `test-store` и `fuzzing` крейта `chervo-core` (и `fuzzing` других крейтов) включаются только
//! через dev-зависимость на самих себя. Ни одна запись `[dependencies]`,
//! `[target.*.dependencies]`, `[workspace.dependencies]` или `default` в `[features]` ни одного
//! продуктового манифеста их не включает.
//!
//! Текстовый разбор без `cargo`.

use std::fs;
use std::path::{Path, PathBuf};

const TEST_FEATURES: [&str; 2] = ["\"test-store\"", "\"fuzzing\""];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Строки манифеста, где в продуктовой таблице включено тестовое свойство.
fn violations(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut product = false;
    let mut in_features = false;
    for line in manifest.replace("\r\n", "\n").lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let s = t.trim_matches(|c| c == '[' || c == ']');
            product = s == "dependencies"
                || s == "workspace.dependencies"
                || s.starts_with("dependencies.")
                || (s.starts_with("target.") && s.contains("dependencies") && !s.contains("dev-"));
            in_features = s == "features";
            continue;
        }
        let hit = TEST_FEATURES.iter().any(|f| t.contains(f));
        if hit && (product || (in_features && t.starts_with("default"))) {
            out.push(t.to_owned());
        }
    }
    out
}

#[test]
fn guard_sees_violations() {
    let bad = "[dependencies]\nchervo-core = { workspace = true, features = [\"test-store\"] }\n";
    assert_eq!(violations(bad).len(), 1);
    let bad =
        "[target.'cfg(unix)'.dependencies]\nx = { path = \"..\", features = [\"fuzzing\"] }\n";
    assert_eq!(violations(bad).len(), 1);
    let bad = "[dependencies.x]\nfeatures = [\"fuzzing\"]\n";
    assert_eq!(violations(bad).len(), 1);
    let bad = "[features]\ndefault = [\"test-store\"]\n";
    assert_eq!(violations(bad).len(), 1);
    // dev-зависимость и сами определения свойств не нарушение
    let ok = "[dev-dependencies]\nx = { path = \".\", features = [\"fuzzing\", \"test-store\"] }\n\
              [features]\nfuzzing = []\ntest-store = []\n";
    assert!(violations(ok).is_empty());
}

#[test]
fn no_product_manifest_enables_test_features() {
    let mut manifests = vec![root().join("Cargo.toml")];
    for e in fs::read_dir(root().join("crates")).unwrap() {
        let m = e.unwrap().path().join("Cargo.toml");
        if m.is_file() {
            manifests.push(m);
        }
    }
    assert!(
        manifests.len() >= 14,
        "найдено манифестов: {}",
        manifests.len()
    );
    for m in &manifests {
        let bad = violations(&fs::read_to_string(m).unwrap());
        assert!(bad.is_empty(), "{}: {bad:?}", m.display());
    }
    // положительный контроль: свой манифест определяет оба свойства и включает их только в dev
    let own = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(own.contains("test-store = []") && own.contains("fuzzing = []"));
    assert!(own.contains("features = [\"fuzzing\", \"test-store\"]"));
}
