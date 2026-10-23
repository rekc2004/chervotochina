//! T23, stage 17a: source guard for `src/secret_service/`. An integration test (not a unit test in
//! `src/`), because the older guard `src_has_no_io_or_default_store` scans all of `src/` for `std::fs`
//! and the like. It reads the files on any OS, so it also runs on Windows and macOS CI.

use std::path::Path;

#[test]
fn ss_src_guard() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/secret_service");
    let forbidden = [
        "std::fs",
        "File::",
        "OpenOptions",
        "zbus::block_on",
        "derive(Debug",
        "tracing::",
        "println!",
        "eprintln!",
        "dbg!",
    ];
    // Member strings of the prompt and unlock calls live only in the unlock file (stage B2).
    let unlock_only = ["\"Prompt\"", "\"Unlock\""];
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // The unit tests of the fake service name every member they count.
        if !name.ends_with(".rs") || name == "tests.rs" {
            continue;
        }
        seen += 1;
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        for needle in forbidden {
            assert!(!text.contains(needle), "{name} contains {needle}");
        }
        // The worker drives its own runtime with exactly one `block_on`; nowhere else may call
        // it (a caller's thread may be a Tokio worker).
        let allowed = usize::from(name == "worker.rs");
        assert_eq!(text.matches("block_on(").count(), allowed, "{name}");
        if name != "unlock.rs" {
            for needle in unlock_only {
                assert!(!text.contains(needle), "{name} contains {needle}");
            }
        }
    }
    assert!(seen >= 5, "only {seen} source files scanned");
}
