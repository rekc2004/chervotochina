//! Совместимость с настоящей программой minisign.
//!
//! Фикстуры должен создать владелец штатной программой minisign (одноразовый тестовый ключ,
//! НЕ ключ релизов) или взять из тестов репозитория minisign с указанием источника и версии.
//! Файлы в `tests/fixtures/`:
//!   `test.pub`                 публичный ключ (`minisign -G -p test.pub -s test.key`)
//!   `chervo-release.txt`       манифест выпуска в каноничном виде (его создаёт `chervo-make-manifest`)
//!   `chervo-release.txt.minisig`  `minisign -Sm chervo-release.txt -s test.key`
//!   `artifact.bin`             файл, чей SHA-256 и размер записаны в манифесте как `any`
//! Пока файлов нет, тест `#[ignore]` и критерий «совместимость с настоящим minisign»
//! считается НЕ ПРОВЕРЕННЫМ. Подписью из нашего кода фикстуру подменять нельзя.

use std::path::PathBuf;

use chervo_update::{KeyRole, KeySet, Target, Version, check_artifact_path, verify_manifest};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
#[ignore = "нет фикстур настоящего minisign (tests/fixtures/); см. описание в начале файла"]
fn real_minisign_fixture() {
    let read =
        |n: &str| std::fs::read(fixture(n)).unwrap_or_else(|e| panic!("нет фикстуры {n}: {e}"));
    let pubkey = read("test.pub");
    let manifest = read("chervo-release.txt");
    let sig = read("chervo-release.txt.minisig");
    let keys = KeySet::from_pubkey_files(&[(KeyRole::Primary, &pubkey)]).expect("test.pub");
    let vm = verify_manifest(&keys, &manifest, &sig).expect("подпись настоящего minisign");
    // флип одного бита манифеста ломает подпись
    let mut bad = manifest.clone();
    bad[0] ^= 1;
    assert!(verify_manifest(&keys, &bad, &sig).is_err());
    let running = Version {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let checked = check_artifact_path(
        &vm,
        &fixture("artifact.bin"),
        running,
        Some(Target::Any),
        true,
    )
    .expect("artifact.bin совпадает с манифестом");
    assert_eq!(checked.artifact.target, Target::Any);
}
