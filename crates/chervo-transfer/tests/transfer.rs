use chervo_transfer::{MAX_MESSAGE_LEN, ProtocolError, decode_message};

#[test]
fn decode_message_bounds() {
    let too_big = vec![0u8; MAX_MESSAGE_LEN + 1];
    assert!(matches!(
        decode_message(&too_big),
        Err(ProtocolError::TooLong)
    ));
    // Пустое тело: нет даже байта типа.
    assert!(matches!(decode_message(&[]), Err(ProtocolError::Malformed)));
    // Известный тип с неверной длиной.
    assert!(matches!(
        decode_message(&[1, 2, 3]),
        Err(ProtocolError::Malformed)
    ));
    // Неизвестный тип.
    assert!(matches!(
        decode_message(&[0xEE, 1, 2, 3]),
        Err(ProtocolError::UnknownType)
    ));
}

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
