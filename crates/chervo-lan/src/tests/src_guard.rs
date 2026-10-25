//! Source guard: sockets and multicast options only in `net.rs`; nothing that could widen the
//! reach (IPv6, broadcast, TCP, DNS, processes, printing); the group literal only in
//! `limits.rs`; `allow_loopback: true` only under `src/tests/`; the manifest stays small.

use std::fs;
use std::path::Path;

/// Product sources: the `.rs` files directly in `src/` (not `src/tests/`).
fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        out.push((name, text));
    }
    out.sort();
    out
}

fn files_with(src: &[(String, String)], needle: &str) -> Vec<String> {
    src.iter()
        .filter(|(_, t)| t.contains(needle))
        .map(|(n, _)| n.clone())
        .collect()
}

fn squeeze(src: &[(String, String)]) -> Vec<(String, String)> {
    src.iter()
        .map(|(n, t)| (n.clone(), t.split_whitespace().collect::<String>()))
        .collect()
}

#[test]
fn src_guard() {
    let src = sources();
    assert!(src.len() >= 7, "sources not found: {}", src.len());
    assert!(src.iter().any(|(n, _)| n == "net.rs"));

    // sockets, binding, joining, multicast options, sending: net.rs only
    for needle in [
        "UdpSocket",
        "Socket::new",
        "send_to(",
        "recv_from(",
        "bind(",
        "join_multicast_v4",
        "set_multicast_",
        "set_reuse_address",
    ] {
        let files = files_with(&src, needle);
        assert!(
            files.iter().all(|f| f == "net.rs"),
            "{needle} outside net.rs: {files:?}"
        );
        assert!(
            !files.is_empty(),
            "{needle} not found at all: the guard is empty"
        );
    }
    let net = &src.iter().find(|(n, _)| n == "net.rs").unwrap().1;
    for needle in [
        "set_multicast_ttl_v4(1)",
        "set_multicast_loop_v4(false)",
        "set_multicast_if_v4(",
        "join_multicast_v4(&LAN_GROUP_V4",
    ] {
        assert!(net.contains(needle), "net.rs lacks {needle}");
    }
    // one send call, to the fixed list of destinations; in production that list is the group
    assert_eq!(net.matches("send_to(").count(), 1);
    assert!(net.contains("send_to(beacon, *t)"));
    assert!(
        net.contains("targets: vec![SocketAddr::V4(SocketAddrV4::new(LAN_GROUP_V4, LAN_PORT))]")
    );

    // absent everywhere
    for needle in [
        "Domain::IPV6",
        "set_broadcast",
        "TcpStream",
        "TcpListener",
        "lookup_host",
        "to_socket_addrs",
        "ToSocketAddrs",
        "tokio",
        "Command::new",
        "std::process",
        "println!",
        "eprintln!",
        "dbg!",
        "unsafe",
        "mdns",
    ] {
        let files = files_with(&src, needle);
        assert!(files.is_empty(), "{needle} found in {files:?}");
    }

    // the group literal (both forms) only in limits.rs; others use the constant
    let files = files_with(&src, "239.255.112.47");
    assert!(files.iter().all(|f| f == "limits.rs"), "{files:?}");
    let files = files_with(&squeeze(&src), "239,255,112,47");
    assert_eq!(
        files,
        vec!["limits.rs".to_owned()],
        "group literal outside limits.rs"
    );
    assert!(
        files_with(&src, "LAN_GROUP_V4").contains(&"net.rs".to_owned()),
        "net.rs does not use LAN_GROUP_V4"
    );

    // production never enables the loopback switch
    let files = files_with(&src, "allow_loopback: true");
    assert!(files.is_empty(), "allow_loopback: true in {files:?}");
    let files = files_with(&squeeze(&src), "allow_loopback:true");
    assert!(files.is_empty(), "allow_loopback:true in {files:?}");
}

#[test]
fn allow_loopback_true_only_in_tests() {
    // the positive control: the test directory does use it
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests");
    let mut in_tests = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let text = fs::read_to_string(entry.unwrap().path()).unwrap();
        in_tests += text.matches("allow_loopback: true").count()
            + text.matches("allow_loopback:\n").count();
    }
    assert!(in_tests > 0);
}

#[test]
fn manifest_dependencies_exact() {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    let mut section = String::new();
    let mut plain = Vec::new();
    let mut optional = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_owned();
            continue;
        }
        if section != "[dependencies]" || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split('=').next().unwrap().trim().to_owned();
        let name = name.split('.').next().unwrap().to_owned();
        if line.contains("optional = true") {
            optional.push(name);
        } else {
            plain.push(name);
        }
    }
    plain.sort();
    assert_eq!(
        plain,
        ["chervo-addr", "chervo-identity", "getrandom", "socket2"]
    );
    // only the in-memory key store of the fuzz entry is optional
    assert_eq!(optional, ["zeroize"]);
    assert!(text.contains("fuzzing = [\"dep:zeroize\"]"));
}
