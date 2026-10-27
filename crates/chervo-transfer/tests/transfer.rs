/// Проверка файла с диска перед размещением нельзя отключить в рабочей сборке (флаг
/// допускается только в тестах самого крейта, где `cfg(test)`).
#[test]
fn verify_after_write_false_rejected_outside_crate_tests() {
    let dir = std::env::temp_dir();
    let mut cfg = chervo_transfer::TransferConfig::new(dir);
    assert!(cfg.validate().is_ok());
    cfg.verify_after_write = false;
    assert!(cfg.validate().is_err());
}
