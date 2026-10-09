use chervo_identity::{DeviceId, IdentityError, SecretKeyStore, UnavailableKeyStore};

#[test]
fn device_id_roundtrip() {
    assert_eq!(DeviceId::from_bytes([7; 32]).as_bytes(), &[7; 32]);
}

#[test]
fn debug_does_not_leak_key() {
    assert_eq!(
        format!("{:?}", DeviceId::from_bytes([0xAB; 32])),
        "DeviceId(..)"
    );
    assert!(matches!(
        UnavailableKeyStore.load_or_create(),
        Err(IdentityError::NotImplemented)
    ));
}
