use std::fs;
use std::path::Path;

#[test]
fn workspace_layout() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_manifest = fs::read_to_string(manifest_dir.join("../../Cargo.toml"))
        .expect("read workspace Cargo.toml");
    let crates = [
        "chervo-identity",
        "chervo-addr",
        "chervo-transport",
        "chervo-token",
        "chervo-friends",
        "chervo-connect",
        "chervo-transfer",
        "chervo-receive",
        "chervo-core",
        "chervo-cli",
    ];
    for name in crates {
        let rel = format!("crates/{name}");
        assert!(root_manifest.contains(&rel), "workspace must list {rel}");
        assert!(
            manifest_dir
                .join("../..")
                .join(&rel)
                .join("Cargo.toml")
                .is_file(),
            "missing {rel}/Cargo.toml"
        );
    }

    let own = fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read core Cargo.toml");
    for forbidden in ["chervo-cli", "iroh", "quinn", "rustls", "tokio"] {
        assert!(
            !own.contains(forbidden),
            "core must not depend on {forbidden}"
        );
    }
}
