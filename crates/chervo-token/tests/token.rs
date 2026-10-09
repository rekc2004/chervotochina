use chervo_token::{MAX_TOKEN_TEXT_LEN, TokenError, decode};

#[test]
fn oversize_rejected() {
    let text = "A".repeat(MAX_TOKEN_TEXT_LEN + 1);
    assert!(matches!(decode(&text), Err(TokenError::TooLong)));
}

#[test]
fn never_ok() {
    let samples = [
        String::new(),
        "garbage".to_string(),
        "\0\0".to_string(),
        "чвч://x".to_string(),
        "A".repeat(MAX_TOKEN_TEXT_LEN),
    ];
    for text in &samples {
        assert!(decode(text).is_err(), "decode must not return Ok");
    }
}
