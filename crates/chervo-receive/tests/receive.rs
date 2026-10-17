use std::path::{Component, Path};

use chervo_receive::{PathError, ReceiveLimits, sanitize_relative_path};

#[test]
fn evil_paths_never_escape_root() {
    let limits = ReceiveLimits::default();
    let root = Path::new("recv");
    for evil in [
        "../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\x",
        "\\\\server\\share",
        "a/../../b",
        "a/./b",
        "c:x",
        "//server/share",
    ] {
        assert!(
            sanitize_relative_path(root, evil, &limits).is_err(),
            "must not return Ok for {evil:?}"
        );
    }
    // Имена, которые честные люди присылают с других ОС, переписываются и остаются внутри.
    for (input, depth) in [("ok.txt", 1usize), ("CON", 1), ("a/b/.hidden", 3)] {
        let p = sanitize_relative_path(root, input, &limits).expect("rewritable name");
        let rest = p.strip_prefix(root).expect("starts with root");
        assert_eq!(rest.components().count(), depth);
        assert!(rest.components().all(|c| matches!(c, Component::Normal(_))));
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
fn default_limits_valid() {
    let d = ReceiveLimits::default();
    assert_eq!(d.validate(), Ok(()));
    assert_eq!(d.max_files, 10_000);
    assert_eq!(d.max_depth, 16);
    assert_eq!(d.max_name_bytes, 255);
    assert_eq!(d.max_path_bytes, 1024);
    assert_eq!(d.max_total_bytes, 2 * 1024 * 1024 * 1024 * 1024);
}

#[test]
fn validate_rejects_bad_limits() {
    let d = ReceiveLimits::default();
    for bad in [
        ReceiveLimits { max_files: 0, ..d },
        ReceiveLimits {
            max_files: 10_001,
            ..d
        },
        ReceiveLimits { max_depth: 0, ..d },
        ReceiveLimits {
            max_name_bytes: 0,
            ..d
        },
        ReceiveLimits {
            max_name_bytes: 256,
            ..d
        },
        ReceiveLimits {
            max_path_bytes: 0,
            ..d
        },
        ReceiveLimits {
            max_path_bytes: 1025,
            ..d
        },
        ReceiveLimits {
            max_total_bytes: 0,
            ..d
        },
    ] {
        assert_eq!(bad.validate(), Err(PathError::BadLimits));
        assert_eq!(
            sanitize_relative_path(Path::new("r"), "a", &bad),
            Err(PathError::BadLimits)
        );
    }
}
