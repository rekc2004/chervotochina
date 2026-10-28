//! Охрана «тестовые возможности не попадают в продукт» (этап 18а, исправления M1 и круга 2):
//! свойства `test-store` и `fuzzing` включаются только через dev-зависимости. В каждом
//! продуктовом манифесте (корневом и `crates/*/Cargo.toml`) подстроки `test-store` и `fuzzing`
//! (в любых кавычках, в любой строке, в том числе пересылка вида `chervo-core/test-store` или
//! `dep:`) запрещены везде, кроме:
//! * таблиц `[dev-dependencies]` (и `[target.*.dev-dependencies]`, `[dev-dependencies.имя]`);
//! * строк-определений свойства с пустым списком (`fuzzing = []`, `test-store = []`) в `[features]`:
//!   пустое определение ничего не включает;
//! * строк-комментариев.
//!
//! Текстовый разбор без `cargo`.

use std::fs;
use std::path::{Path, PathBuf};

const TEST_FEATURES: [&str; 3] = ["test-store", "fuzzing", "test-net"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Строка вида `fuzzing = []` (с любыми пробелами): определение свойства без включений.
fn is_empty_definition(t: &str) -> bool {
    let Some((name, value)) = t.split_once('=') else {
        return false;
    };
    let name = name.trim().trim_matches(|c| c == '"' || c == '\'');
    let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    TEST_FEATURES.contains(&name) && value == "[]"
}

/// Строки манифеста, где тестовое свойство упомянуто вне разрешённых мест.
fn violations(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut dev = false;
    let mut features = false;
    for line in manifest.replace("\r\n", "\n").lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            let s = t.trim_matches(|c| c == '[' || c == ']');
            dev = s.contains("dev-dependencies");
            features = s == "features";
            // имя свойства или зависимости прямо в заголовке таблицы
            if !dev && TEST_FEATURES.iter().any(|f| s.contains(f)) {
                out.push(t.to_owned());
            }
            continue;
        }
        if dev || !TEST_FEATURES.iter().any(|f| t.contains(f)) {
            continue;
        }
        if features && is_empty_definition(t) {
            continue;
        }
        out.push(t.to_owned());
    }
    out
}

#[test]
fn guard_sees_every_bypass_form() {
    let bad = [
        // двойные кавычки в [dependencies]
        "[dependencies]\nchervo-core = { workspace = true, features = [\"test-store\"] }\n",
        // одинарные кавычки
        "[dependencies]\nchervo-core = { workspace = true, features = ['test-store'] }\n",
        // без кавычек (разобрать как строку нельзя, но подстрока видна)
        "[dependencies]\nchervo-core = { features = [test-store] }\n",
        // многострочный список
        "[dependencies]\nchervo-core = { workspace = true, features = [\n  \"x\",\n  'fuzzing',\n] }\n",
        // целевая таблица
        "[target.'cfg(unix)'.dependencies]\nx = { path = \"..\", features = [\"fuzzing\"] }\n",
        // таблица зависимости
        "[dependencies.x]\nfeatures = [\"fuzzing\"]\n",
        "[dependencies.x]\nfeatures = ['fuzzing']\n",
        // зависимость, названная тестовым свойством в заголовке
        "[dependencies.fuzzing]\nversion = \"1\"\n",
        // сборочные зависимости и рабочее пространство
        "[build-dependencies]\nx = { path = \"..\", features = [\"fuzzing\"] }\n",
        "[workspace.dependencies]\nx = { path = \"..\", features = [\"test-store\"] }\n",
        // свойство, пересылающее тестовое свойство (любое имя, не только `default`)
        "[features]\ndefault = [\"test-store\"]\n",
        "[features]\nconvenient = [\"chervo-core/test-store\"]\n",
        "[features]\nconvenient = ['chervo-core/fuzzing']\n",
        "[features]\nconvenient = [\"dep:fuzzing\"]\n",
        "[features]\ndefault = [\n  \"x\",\n  \"fuzzing\",\n]\n",
        // определение, которое что-то включает
        "[features]\nfuzzing = [\"chervo-token/fuzzing\"]\n",
        "[features]\ntest-store = [ \"x\" ]\n",
        // пересылка в обычной зависимости
        "[dependencies]\nx = { path = \"..\", features = [\"chervo-core/test-store\"] }\n",
        // CRLF
        "[dependencies]\r\nx = { features = ['fuzzing'] }\r\n",
        // 13в: `test-net` (юникаст на петле вместо группы) тоже только для dev-зависимостей
        "[dependencies]\nchervo-lan = { workspace = true, features = [\"test-net\"] }\n",
        "[dependencies.chervo-lan]\nfeatures = ['test-net']\n",
        "[features]\nconvenient = [\"chervo-lan/test-net\"]\n",
        "[features]\ntest-net = [\"x\"]\n",
        "[target.'cfg(unix)'.dependencies]\nx = { path = \"..\", features = [\"test-net\"] }\n",
    ];
    for (i, m) in bad.iter().enumerate() {
        assert!(!violations(m).is_empty(), "обход {i} не пойман: {m:?}");
    }
    // разрешённое: dev-таблицы в любом виде, пустые определения, комментарии
    let ok = [
        "[dev-dependencies]\nx = { path = \".\", features = [\"fuzzing\", \"test-store\"] }\n",
        "[dev-dependencies]\nchervo-lan = { workspace = true, features = [\"test-net\"] }\n",
        "[features]\ntest-net = []\n",
        "[target.'cfg(unix)'.dev-dependencies]\nx = { path = \".\", features = ['fuzzing'] }\n",
        "[dev-dependencies.x]\nfeatures = [\"test-store\"]\n",
        "[dev-dependencies]\nx = { features = [\n  \"fuzzing\",\n] }\n",
        "[features]\nfuzzing = []\ntest-store = []\n",
        "[features]\nfuzzing = [ ]\n",
        "# test-store и fuzzing в комментарии\n[dependencies]\nx = \"1\"\n",
    ];
    for (i, m) in ok.iter().enumerate() {
        assert!(violations(m).is_empty(), "ложное срабатывание {i}: {m:?}");
    }
    // после dev-таблицы следующая продуктовая снова проверяется
    let mixed = "[dev-dependencies]\nx = { features = [\"fuzzing\"] }\n[dependencies]\ny = { features = [\"fuzzing\"] }\n";
    assert_eq!(violations(mixed).len(), 1);
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
