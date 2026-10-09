use std::path::Path;

use chervo_receive::{PathError, ReceiveLimits, sanitize_relative_path};

#[test]
fn evil_paths_never_ok() {
    let limits = ReceiveLimits::default();
    let root = Path::new("recv");
    for evil in [
        "../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\x",
        "\\\\server\\share",
        "CON",
        "a/../../b",
        "ok.txt",
    ] {
        assert!(
            sanitize_relative_path(root, evil, &limits).is_err(),
            "must not return Ok for {evil:?}"
        );
    }
    assert!(matches!(
        sanitize_relative_path(root, "", &limits),
        Err(PathError::Empty)
    ));
    let long = "a".repeat(usize::from(limits.max_path_bytes) + 1);
    assert!(matches!(
        sanitize_relative_path(root, &long, &limits),
        Err(PathError::TooLong)
    ));
}

#[test]
fn default_limits_nonzero() {
    let d = ReceiveLimits::default();
    assert!(d.max_files > 0);
    assert!(d.max_depth > 0);
    assert!(d.max_name_bytes > 0);
    assert!(d.max_path_bytes > 0);
    assert!(d.max_total_bytes > 0);
    assert!(d.max_total_bytes < u64::MAX);
}
