//! Проверки папки приёма: абсолютность, ссылки, права владельца (Unix).

mod common;

use std::fs;
use std::path::PathBuf;

use chervo_receive::{ReceiveConfig, ReceiveRoot, RootError};
use common::{Tmp, link_dir_or_skip};

fn cfg_in(tmp: &Tmp, name: &str) -> (ReceiveConfig, PathBuf) {
    let dir = tmp.path().join(name);
    fs::create_dir(&dir).expect("create");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    (ReceiveConfig::new(dir.clone()), dir)
}

#[test]
fn root_creates_service_dirs_and_hides_paths() {
    let tmp = Tmp::new("rootc");
    let (cfg, dir) = cfg_in(&tmp, "recv");
    let root = ReceiveRoot::open(&cfg).expect("open");
    assert_eq!(root.root(), fs::canonicalize(&dir).expect("canon"));
    assert_eq!(root.partial_dir(), root.root().join(".chervo-partial"));
    assert!(root.partial_dir().is_dir());
    assert!(root.partial_dir().join("receive").is_dir());
    println!(
        "root_creates_service_dirs: os={} root={:?}",
        std::env::consts::OS,
        root.root()
    );
    // повторное открытие допустимо
    ReceiveRoot::open(&cfg).expect("reopen");
    // Debug и Display не содержат путей
    let shown = format!("{root:?} {cfg:?}");
    assert!(!shown.contains("chervo-rcv"), "{shown}");
    for e in [
        RootError::NotAbsolute,
        RootError::NotDir,
        RootError::Shared,
        RootError::PartialNotPrivate,
        RootError::Io(std::io::ErrorKind::NotFound),
    ] {
        let s = format!("{e} {e:?}");
        assert!(
            !s.contains("chervo") && !s.contains('\\') && !s.contains(':'),
            "{s}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: &std::path::Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(root.partial_dir()), 0o700);
        assert_eq!(mode(&root.partial_dir().join("receive")), 0o700);
    }
    #[cfg(windows)]
    assert!(
        root.root().to_string_lossy().starts_with(r"\\?\"),
        "canonical root is a verbatim path on Windows"
    );
}

#[test]
fn root_must_be_absolute_existing_dir() {
    let cfg = ReceiveConfig::new(PathBuf::from("relative/dir"));
    assert_eq!(ReceiveRoot::open(&cfg).unwrap_err(), RootError::NotAbsolute);

    let tmp = Tmp::new("rootd");
    let file = tmp.path().join("file.txt");
    fs::write(&file, b"x").expect("write");
    let cfg = ReceiveConfig::new(file);
    assert_eq!(ReceiveRoot::open(&cfg).unwrap_err(), RootError::NotDir);

    let cfg = ReceiveConfig::new(tmp.path().join("missing"));
    assert_eq!(
        ReceiveRoot::open(&cfg).unwrap_err(),
        RootError::Io(std::io::ErrorKind::NotFound)
    );
}

#[test]
fn root_symlink_canonicalized() {
    let tmp = Tmp::new("roots");
    let (_cfg, real) = cfg_in(&tmp, "real");
    let link = tmp.path().join("link");
    let Some(_) = link_dir_or_skip("root_symlink_canonicalized", &real, &link) else {
        return;
    };
    let root = ReceiveRoot::open(&ReceiveConfig::new(link)).expect("open via link");
    assert_eq!(root.root(), fs::canonicalize(&real).expect("canon"));
    assert!(root.partial_dir().starts_with(root.root()));
    // служебные каталоги созданы в настоящей папке
    assert!(real.join(".chervo-partial").join("receive").is_dir());
}

#[test]
fn partial_dir_that_is_a_link_refused() {
    let tmp = Tmp::new("rootl");
    let (cfg, dir) = cfg_in(&tmp, "recv");
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).expect("outside");
    let Some(_) = link_dir_or_skip(
        "partial_dir_that_is_a_link_refused",
        &outside,
        &dir.join(".chervo-partial"),
    ) else {
        return;
    };
    assert_eq!(ReceiveRoot::open(&cfg).unwrap_err(), RootError::NotDir);
    assert!(
        fs::read_dir(&outside).expect("read").next().is_none(),
        "nothing created through the link"
    );
}

#[cfg(unix)]
#[test]
fn root_shared_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = Tmp::new("roots2");
    let (mut cfg, dir) = cfg_in(&tmp, "recv");
    for mode in [0o777, 0o775, 0o757] {
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).expect("chmod");
        assert_eq!(
            ReceiveRoot::open(&cfg).unwrap_err(),
            RootError::Shared,
            "mode {mode:o}"
        );
    }
    cfg.allow_shared_root = true;
    ReceiveRoot::open(&cfg).expect("allowed when asked for");
    cfg.allow_shared_root = false;
    // чтение для других допустимо (запись нет)
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    ReceiveRoot::open(&cfg).expect("755 is fine");
}

#[cfg(unix)]
#[test]
fn partial_not_private_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = Tmp::new("rootp");
    let (mut cfg, dir) = cfg_in(&tmp, "recv");
    let partial = dir.join(".chervo-partial");
    fs::create_dir(&partial).expect("partial");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(
        ReceiveRoot::open(&cfg).unwrap_err(),
        RootError::PartialNotPrivate
    );
    cfg.allow_shared_root = true;
    ReceiveRoot::open(&cfg).expect("allowed when asked for");
    cfg.allow_shared_root = false;
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o700)).expect("chmod");
    ReceiveRoot::open(&cfg).expect("private is fine");
}
