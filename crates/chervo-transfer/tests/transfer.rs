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
