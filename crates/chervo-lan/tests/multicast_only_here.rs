//! Workspace-wide guard: multicast sockets exist in exactly two product files (UPnP's SSDP
//! and this crate's beacon), and no product file anywhere turns on `allow_loopback`.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under `crates/*/src`, except test code (`src/tests/`, `tests.rs`).
fn product_files() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    let mut out = Vec::new();
    for entry in fs::read_dir(&crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            walk(&src, &mut out);
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                walk(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

fn rel(path: &Path) -> String {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    path.strip_prefix(crates)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn multicast_only_here() {
    let files = product_files();
    assert!(files.len() > 50, "only {} product files found", files.len());
    let mut with_multicast: Vec<String> = Vec::new();
    for p in &files {
        let text = fs::read_to_string(p).unwrap();
        if text.contains("join_multicast") || text.contains("set_multicast_") {
            with_multicast.push(rel(p));
        }
    }
    with_multicast.sort();
    // both expected files found: the positive control of the walk
    assert_eq!(
        with_multicast,
        ["chervo-lan/src/net.rs", "chervo-upnp/src/net.rs"]
    );
}

#[test]
fn allow_loopback_true_in_no_product_file() {
    let files = product_files();
    // positive control: the field itself is spelled in product code (as `false`)
    let mut declared = 0;
    for p in &files {
        let text = fs::read_to_string(p).unwrap();
        let squeezed: String = text.split_whitespace().collect();
        assert!(
            !squeezed.contains("allow_loopback:true"),
            "allow_loopback: true in {}",
            rel(p)
        );
        if text.contains("allow_loopback") {
            declared += 1;
        }
    }
    assert!(declared >= 2, "the walk does not see allow_loopback at all");
}
