#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Тесты внутренностей узла (этап 18а): разбор файла настроек, каталог данных, замок, раскрытие
//! папок, вид предложения, очередь событий, `Debug` ссылок и событий. Тесты с настоящим узлом
//! лежат в `tests/`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chervo_identity::PairId;
use chervo_receive::{ReceiveLimits, plan_offer_in};
use chervo_transfer::{OfferedFile, TransferId, TransferKey, UntrustedName};

use super::error::NodeError;
use super::events::{EventSink, NodeEvent};
use super::folder;
use super::profile::{self, InstanceLock, Os};
use super::settings::{self, HEADER, MAX_FILE_BYTES, Settings, parse, serialize};
use super::transfers::offer_files;
use super::views::{FriendRef, InviteRef, NodeWarning, TransferRef, TransferResult};

#[path = "../../tests/support/redact_kit.rs"]
mod redact_kit;

// ------------------------------------------------------------------------------ помощники

/// Абсолютный путь для текущей ОС из компонентов.
fn abs(parts: &[&str]) -> PathBuf {
    let mut p = if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        PathBuf::from("/")
    };
    for c in parts {
        p.push(c);
    }
    p
}

fn abs_text(parts: &[&str]) -> String {
    abs(parts).to_str().unwrap().to_owned()
}

fn base() -> String {
    format!(
        "{HEADER}\nport=50000\nreceive_root={}\n",
        abs_text(&["recv"])
    )
}

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let rnd = u128::from_be_bytes(*PairId::generate().unwrap().as_bytes());
        let p = std::env::temp_dir().join(format!(
            "chervo-core-unit-{tag}-{}-{n}-{:08x}",
            std::process::id(),
            rnd as u32
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn udn(n: u8) -> String {
    format!("uuid:6f1c0a2e-0000-4000-8000-0000000000{n:02}")
}

fn full_sample() -> Settings {
    let mut s = Settings::new(51000, abs(&["data", "recv"]), true);
    s.extra_roots = vec![abs(&["data", "other"]), abs(&["mnt", "disk"])];
    s.min_free_percent = 25;
    s.invite_ttl_secs = 3600;
    s.manual_forward = Some(51000);
    s.routers = vec![
        chervo_upnp::AllowedRouter {
            id: chervo_upnp::RouterId::from_setting(&udn(1)).unwrap(),
            permanent_ok: true,
        },
        chervo_upnp::AllowedRouter {
            id: chervo_upnp::RouterId::from_setting(&udn(2)).unwrap(),
            permanent_ok: false,
        },
    ];
    s.clock_offset_ms = -123_456;
    s.clock_offset_at = 1_700_000_000;
    s.ntp_servers = vec!["ntp.example.org".to_owned(), "10.0.0.1".to_owned()];
    s
}

// ------------------------------------------------------------------------------ настройки

#[test]
fn settings_roundtrip() {
    // минимальные настройки первого запуска
    let s = Settings::new(49152, abs(&["recv"]), false);
    let text = serialize(&s).unwrap();
    assert!(text.starts_with("chervo-settings 1\n"));
    assert_eq!(parse(text.as_bytes()).unwrap(), s);
    assert_eq!(serialize(&parse(text.as_bytes()).unwrap()).unwrap(), text);
    // все поля
    let f = full_sample();
    let text = serialize(&f).unwrap();
    let back = parse(text.as_bytes()).unwrap();
    assert_eq!(back, f);
    assert_eq!(serialize(&back).unwrap(), text);
    // значения по умолчанию, когда необязательных строк нет
    let d = parse(base().as_bytes()).unwrap();
    assert_eq!((d.min_free_percent, d.invite_ttl_secs), (10, 900));
    assert!(d.routers.is_empty() && d.ntp_servers.is_empty() && !d.shared_root_confirmed);
    // граница: строка ровно 4096 байт проходит
    let prefix = format!("receive_root={}", abs_text(&["a"]));
    let pad = 4096 - prefix.len();
    let long_root = format!("{}{}", abs_text(&["a"]), "b".repeat(pad));
    let text = format!("{HEADER}\nport=50000\nreceive_root={long_root}\n");
    assert_eq!(
        text.lines().nth(2).unwrap().len(),
        4096,
        "проверка границы построена неверно"
    );
    assert!(parse(text.as_bytes()).is_ok());
    // и крайние допустимые значения
    let edge = format!(
        "{}invite_ttl_secs=60\nmin_free_percent=0\nmanual_forward=65535\nclock_offset_ms=604800000\n",
        base()
    );
    assert!(parse(edge.as_bytes()).is_ok());
    let edge = format!(
        "{}invite_ttl_secs=86400\nmin_free_percent=100\nmanual_forward=1\nclock_offset_ms=-604800000\n",
        base()
    );
    assert!(parse(edge.as_bytes()).is_ok());
}

#[test]
fn settings_hostile_table() {
    let ok = base();
    let recv = abs_text(&["recv"]);
    let mut rows: Vec<(&str, Vec<u8>)> = vec![
        ("empty file", Vec::new()),
        ("header only", format!("{HEADER}\n").into_bytes()),
        ("BOM", format!("\u{FEFF}{ok}").into_bytes()),
        ("CRLF", ok.replace('\n', "\r\n").into_bytes()),
        (
            "lone CR",
            ok.replace("port=50000\n", "port=50000\r").into_bytes(),
        ),
        (
            "no header",
            ok.replacen(&format!("{HEADER}\n"), "", 1).into_bytes(),
        ),
        (
            "header v2",
            ok.replace("settings 1", "settings 2").into_bytes(),
        ),
        (
            "header trailing space",
            ok.replace("settings 1", "settings 1 ").into_bytes(),
        ),
        (
            "no final newline",
            ok.trim_end_matches('\n').to_owned().into_bytes(),
        ),
        ("blank line", format!("{ok}\n").into_bytes()),
        (
            "blank line in the middle",
            ok.replace("port", "\nport").into_bytes(),
        ),
        ("duplicate port", format!("{ok}port=50001\n").into_bytes()),
        (
            "duplicate receive_root",
            format!("{ok}receive_root={recv}\n").into_bytes(),
        ),
        (
            "duplicate scalar ttl",
            format!("{ok}invite_ttl_secs=100\ninvite_ttl_secs=100\n").into_bytes(),
        ),
        ("unknown key", format!("{ok}color=red\n").into_bytes()),
        ("key without =", format!("{ok}port\n").into_bytes()),
        ("empty key", format!("{ok}=1\n").into_bytes()),
        ("key case", format!("{ok}Min_Free_Percent=5\n").into_bytes()),
        ("port=0", ok.replace("port=50000", "port=0").into_bytes()),
        (
            "port=70000",
            ok.replace("port=50000", "port=70000").into_bytes(),
        ),
        (
            "port=65536",
            ok.replace("port=50000", "port=65536").into_bytes(),
        ),
        (
            "port negative",
            ok.replace("port=50000", "port=-1").into_bytes(),
        ),
        (
            "port plus",
            ok.replace("port=50000", "port=+5").into_bytes(),
        ),
        (
            "port leading zero",
            ok.replace("port=50000", "port=050000").into_bytes(),
        ),
        ("port empty", ok.replace("port=50000", "port=").into_bytes()),
        (
            "port hex",
            ok.replace("port=50000", "port=0xc350").into_bytes(),
        ),
        (
            "port space",
            ok.replace("port=50000", "port= 50000").into_bytes(),
        ),
        ("port missing", ok.replace("port=50000\n", "").into_bytes()),
        (
            "receive_root missing",
            ok.replace(&format!("receive_root={recv}\n"), "")
                .into_bytes(),
        ),
        (
            "relative root",
            ok.replace(&recv, "relative/dir").into_bytes(),
        ),
        (
            "empty root",
            ok.replace(&format!("receive_root={recv}"), "receive_root=")
                .into_bytes(),
        ),
        ("dot root", ok.replace(&recv, ".").into_bytes()),
        (
            "relative extra root",
            format!("{ok}extra_root=rel\n").into_bytes(),
        ),
        (
            "extra root equals root",
            format!("{ok}extra_root={recv}\n").into_bytes(),
        ),
        (
            "extra root twice",
            format!(
                "{ok}extra_root={}\nextra_root={}\n",
                abs_text(&["x"]),
                abs_text(&["x"])
            )
            .into_bytes(),
        ),
        ("NUL in value", ok.replace("recv", "re\0cv").into_bytes()),
        ("tab in value", ok.replace("recv", "re\tcv").into_bytes()),
        (
            "control in value",
            ok.replace("recv", "re\u{7}cv").into_bytes(),
        ),
        ("non-UTF-8", vec![0xff, 0xfe, 0x00, 0x81]),
        ("non-UTF-8 inside", {
            let mut b = ok.clone().into_bytes();
            b.extend_from_slice(b"extra_root=\xff\xfe\n");
            b
        }),
        ("ttl 59", format!("{ok}invite_ttl_secs=59\n").into_bytes()),
        (
            "ttl 86401",
            format!("{ok}invite_ttl_secs=86401\n").into_bytes(),
        ),
        (
            "min free 101",
            format!("{ok}min_free_percent=101\n").into_bytes(),
        ),
        (
            "min free negative",
            format!("{ok}min_free_percent=-1\n").into_bytes(),
        ),
        (
            "shared flag 2",
            format!("{ok}shared_root_confirmed=2\n").into_bytes(),
        ),
        (
            "shared flag word",
            format!("{ok}shared_root_confirmed=true\n").into_bytes(),
        ),
        ("forward 0", format!("{ok}manual_forward=0\n").into_bytes()),
        (
            "forward 70000",
            format!("{ok}manual_forward=70000\n").into_bytes(),
        ),
        (
            "offset beyond 7 days",
            format!("{ok}clock_offset_ms=604800001\n").into_bytes(),
        ),
        (
            "offset negative beyond",
            format!("{ok}clock_offset_ms=-604800001\n").into_bytes(),
        ),
        (
            "offset minus zero",
            format!("{ok}clock_offset_ms=-0\n").into_bytes(),
        ),
        (
            "offset huge",
            format!("{ok}clock_offset_ms=99999999999999999999999\n").into_bytes(),
        ),
        (
            "offset_at negative",
            format!("{ok}clock_offset_at=-5\n").into_bytes(),
        ),
        (
            "router bad udn",
            format!("{ok}upnp_router=notauuid;1\n").into_bytes(),
        ),
        (
            "router no flag",
            format!("{ok}upnp_router={}\n", udn(1)).into_bytes(),
        ),
        (
            "router bad flag",
            format!("{ok}upnp_router={};2\n", udn(1)).into_bytes(),
        ),
        (
            "router duplicate",
            format!("{ok}upnp_router={0};1\nupnp_router={0};0\n", udn(1)).into_bytes(),
        ),
        (
            "ntp with space",
            format!("{ok}ntp_server=a b\n").into_bytes(),
        ),
        ("ntp empty", format!("{ok}ntp_server=\n").into_bytes()),
        (
            "ntp with port",
            format!("{ok}ntp_server=host:123\n").into_bytes(),
        ),
        (
            "ntp non-ascii",
            format!("{ok}ntp_server=хост.рф\n").into_bytes(),
        ),
        (
            "ntp duplicate",
            format!("{ok}ntp_server=a.b\nntp_server=a.b\n").into_bytes(),
        ),
        (
            "ntp too long",
            format!("{ok}ntp_server={}\n", "a".repeat(254)).into_bytes(),
        ),
    ];
    // 17 папок приёма (основная и 16 дополнительных)
    let mut seventeen = ok.clone();
    for i in 0..16 {
        seventeen.push_str(&format!(
            "extra_root={}\n",
            abs_text(&["extra", &i.to_string()])
        ));
    }
    rows.push(("17 roots", seventeen.into_bytes()));
    let mut routers = ok.clone();
    for i in 0..17u8 {
        routers.push_str(&format!("upnp_router={};0\n", udn(i)));
    }
    rows.push(("17 routers", routers.into_bytes()));
    let mut ntp = ok.clone();
    for i in 0..17 {
        ntp.push_str(&format!("ntp_server=n{i}.example.org\n"));
    }
    rows.push(("17 ntp servers", ntp.into_bytes()));
    // длинная строка (4097 байт)
    let too_long = format!("{ok}extra_root={}\n", abs_text(&["a"]) + &"b".repeat(4085));
    assert!(too_long.lines().last().unwrap().len() > 4096);
    rows.push(("line over 4 KiB", too_long.into_bytes()));
    // размер 64 КиБ + 1
    let mut big = ok.clone().into_bytes();
    big.resize(MAX_FILE_BYTES + 1, b'x');
    rows.push(("64 KiB + 1", big));
    let mut big = ok.clone();
    while big.len() <= MAX_FILE_BYTES {
        big.push_str("ntp_server=a.b\n");
    }
    rows.push(("64 KiB of lines", big.into_bytes()));

    assert!(rows.len() >= 25, "в таблице {} строк", rows.len());
    for (name, bytes) in &rows {
        assert_eq!(
            parse(bytes).err(),
            Some(NodeError::SettingsCorrupt),
            "строка «{name}» принята"
        );
    }
    // положительный контроль: исходный текст принимается
    assert!(parse(ok.as_bytes()).is_ok());
}

#[test]
fn settings_file_io_is_atomic_and_strict() {
    let dir = Tmp::new("settingsio");
    assert_eq!(settings::load(&dir.0).unwrap(), None);
    let s = full_sample();
    settings::save(&dir.0, &s).unwrap();
    assert_eq!(settings::load(&dir.0).unwrap(), Some(s.clone()));
    assert!(
        !dir.0.join("settings.v1.tmp").exists(),
        "временный файл остался"
    );
    // повторная запись заменяет файл
    let mut s2 = s.clone();
    s2.min_free_percent = 30;
    settings::save(&dir.0, &s2).unwrap();
    assert_eq!(settings::load(&dir.0).unwrap(), Some(s2));
    // файл, который не обычный (каталог): повреждён
    std::fs::remove_file(dir.0.join("settings.v1")).unwrap();
    std::fs::create_dir(dir.0.join("settings.v1")).unwrap();
    assert_eq!(
        settings::load(&dir.0).err(),
        Some(NodeError::SettingsCorrupt)
    );
    // слишком большой файл не читается целиком
    std::fs::remove_dir(dir.0.join("settings.v1")).unwrap();
    std::fs::write(dir.0.join("settings.v1"), vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
    assert_eq!(
        settings::load(&dir.0).err(),
        Some(NodeError::SettingsCorrupt)
    );
    // копия в сторону
    settings::set_aside(&dir.0, 42).unwrap();
    assert!(dir.0.join("settings.v1.bad-42").exists());
    assert!(!dir.0.join("settings.v1").exists());
    // нечего откладывать: не ошибка
    settings::set_aside(&dir.0, 43).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        settings::save(&dir.0, &full_sample()).unwrap();
        let mode = std::fs::metadata(dir.0.join("settings.v1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "настройки доступны другим: {mode:o}");
    }
}

#[test]
fn unwritable_values_are_refused_not_corrupted() {
    let mut s = full_sample();
    s.receive_root = PathBuf::from("relative");
    assert_eq!(serialize(&s).err(), Some(NodeError::SettingsCorrupt));
    let mut s = full_sample();
    s.extra_roots = vec![abs(&["with\nnewline"])];
    // на Windows перевод строки в имени запрещён сам, на Unix допустим: запись всё равно отказ
    assert_eq!(serialize(&s).err(), Some(NodeError::SettingsCorrupt));
    let mut s = full_sample();
    s.invite_ttl_secs = 5;
    assert_eq!(serialize(&s).err(), Some(NodeError::SettingsCorrupt));
}

#[test]
fn fuzz_entry_accepts_and_rejects_without_panic() {
    for seed in 0u32..2000 {
        // быстрый детерминированный шум вокруг рабочего файла
        let mut b = full_sample_text().into_bytes();
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        for _ in 0..(seed % 5) {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let at = (x as usize) % b.len();
            b[at] = (x >> 24) as u8;
        }
        settings::fuzz_settings(&b);
    }
}

fn full_sample_text() -> String {
    serialize(&full_sample()).unwrap()
}

// ------------------------------------------------------------------------------ каталог данных

fn env_of<'a>(pairs: &'a [(&'a str, OsString)]) -> impl Fn(&str) -> Option<OsString> + 'a {
    move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
}

#[test]
fn data_dir_per_os() {
    let home = abs(&["home", "anna"]);
    let local = abs(&["home", "anna", "AppData", "Local"]);
    let xdg = abs(&["xdg"]);
    let env = [
        ("HOME", home.clone().into_os_string()),
        ("LOCALAPPDATA", local.clone().into_os_string()),
    ];
    let get = env_of(&env);
    assert_eq!(
        profile::default_data_dir(Os::Windows, &get).unwrap(),
        local.join("Chervotochina")
    );
    assert_eq!(
        profile::default_data_dir(Os::Mac, &get).unwrap(),
        home.join("Library")
            .join("Application Support")
            .join("Chervotochina")
    );
    assert_eq!(
        profile::default_data_dir(Os::Linux, &get).unwrap(),
        home.join(".local").join("share").join("chervotochina")
    );
    // XDG_DATA_HOME главнее HOME
    let env2 = [
        ("HOME", home.clone().into_os_string()),
        ("XDG_DATA_HOME", xdg.clone().into_os_string()),
    ];
    assert_eq!(
        profile::default_data_dir(Os::Linux, &env_of(&env2)).unwrap(),
        xdg.join("chervotochina")
    );
    // пустое значение это «не задано»
    let env3 = [
        ("HOME", home.clone().into_os_string()),
        ("XDG_DATA_HOME", OsString::new()),
    ];
    assert_eq!(
        profile::default_data_dir(Os::Linux, &env_of(&env3)).unwrap(),
        home.join(".local").join("share").join("chervotochina")
    );
    // не абсолютное значение: ошибка, а не подмена
    for (os, var) in [
        (Os::Windows, "LOCALAPPDATA"),
        (Os::Mac, "HOME"),
        (Os::Linux, "HOME"),
        (Os::Linux, "XDG_DATA_HOME"),
    ] {
        let mut env = vec![(var, OsString::from("relative/dir"))];
        if var != "HOME" {
            env.push(("HOME", home.clone().into_os_string()));
        }
        assert_eq!(
            profile::default_data_dir(os, &env_of(&env)).err(),
            Some(NodeError::DataDir),
            "{os:?} {var}"
        );
    }
    // ничего не задано
    assert_eq!(
        profile::default_data_dir(Os::Linux, &env_of(&[])).err(),
        Some(NodeError::DataDir)
    );
    assert_eq!(
        profile::default_data_dir(Os::Windows, &env_of(&[])).err(),
        Some(NodeError::DataDir)
    );
}

#[test]
fn explicit_data_dir_must_be_absolute() {
    assert_eq!(
        profile::resolve_data_dir(Some(Path::new("relative"))).err(),
        Some(NodeError::DataDir)
    );
    let t = Tmp::new("datadir");
    let nested = t.0.join("a").join("b");
    assert_eq!(profile::resolve_data_dir(Some(&nested)).unwrap(), nested);
    assert!(nested.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let fresh = t.0.join("private");
        profile::resolve_data_dir(Some(&fresh)).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "каталог данных открыт другим: {mode:o}");
    }
    // файл вместо каталога
    let f = t.0.join("file");
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(
        profile::resolve_data_dir(Some(&f)).err(),
        Some(NodeError::DataDir)
    );
}

#[test]
fn instance_lock_is_exclusive_and_released_on_drop() {
    let t = Tmp::new("lock");
    let first = InstanceLock::acquire(&t.0).unwrap();
    assert_eq!(
        InstanceLock::acquire(&t.0).err(),
        Some(NodeError::AlreadyRunning)
    );
    drop(first);
    let again = InstanceLock::acquire(&t.0).unwrap();
    drop(again);
    // другой каталог данных: свой замок
    let other = Tmp::new("lock2");
    let a = InstanceLock::acquire(&t.0).unwrap();
    let b = InstanceLock::acquire(&other.0).unwrap();
    drop((a, b));
}

// ------------------------------------------------------------------------------ папки

fn touch(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

#[test]
fn folders_expand_to_relative_slash_names() {
    let t = Tmp::new("expand");
    let top = t.0.join("top");
    touch(&top.join("a.txt"), b"a");
    touch(&top.join("sub").join("b.bin"), b"b");
    touch(&top.join("sub").join("deep").join("c.exe"), b"c");
    let single = t.0.join("single.txt");
    touch(&single, b"s");
    let files = folder::expand(&[top.clone(), single.clone()], 16).unwrap();
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "top/a.txt",
            "top/sub/b.bin",
            "top/sub/deep/c.exe",
            "single.txt"
        ]
    );
    assert!(files.iter().all(|f| f.path.is_file()));
    // глубина: путь из четырёх компонентов не проходит предел 2
    assert_eq!(
        folder::expand(std::slice::from_ref(&top), 2).err(),
        Some(NodeError::Transfer(chervo_transfer::TransferError::BadName))
    );
    // предел числа файлов
    assert_eq!(
        folder::expand_with(std::slice::from_ref(&top), 16, 2).err(),
        Some(NodeError::Transfer(
            chervo_transfer::TransferError::TooManyFiles
        ))
    );
    assert!(folder::expand_with(std::slice::from_ref(&top), 16, 3).is_ok());
    // пусто и нет такого пути
    assert!(folder::expand(&[], 16).is_err());
    assert!(folder::expand(&[t.0.join("missing")], 16).is_err());
    let empty = t.0.join("empty");
    std::fs::create_dir(&empty).unwrap();
    assert!(folder::expand(&[empty], 16).is_err());
}

#[cfg(unix)]
#[test]
fn folders_do_not_follow_symlinks() {
    use std::os::unix::ffi::OsStrExt;
    let t = Tmp::new("symlink");
    let secret = t.0.join("secret.txt");
    touch(&secret, b"top secret");
    let top = t.0.join("top");
    touch(&top.join("ok.txt"), b"ok");
    std::os::unix::fs::symlink(&secret, top.join("link.txt")).unwrap();
    std::os::unix::fs::symlink(t.0.join("top"), top.join("loop")).unwrap();
    let files = folder::expand(std::slice::from_ref(&top), 16).unwrap();
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["top/ok.txt"], "ссылка попала в предложение");
    // ссылка на верхнем уровне: отказ
    assert!(folder::expand(&[top.join("link.txt")], 16).is_err());
    // имя не UTF-8: число таких имён
    let bad = top.join(std::ffi::OsStr::from_bytes(b"bad\xff.txt"));
    if std::fs::write(&bad, b"x").is_ok() {
        assert_eq!(
            folder::expand(&[top], 16).err(),
            Some(NodeError::BadName(1))
        );
    }
}

// ------------------------------------------------------------------------------ вид предложения

fn offered(name: &str) -> OfferedFile {
    OfferedFile {
        name: UntrustedName::new(name).unwrap(),
        size: 10,
    }
}

const BAD_CHARS: [char; 24] = [
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}', '\u{2028}',
    '\u{2029}', '\u{061C}', '\u{00AD}', '\u{2060}', '\u{180E}', '\u{0000}', '\u{007F}', '\u{0085}',
];

const RESERVED: [&str; 10] = [
    "con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9", "conin$", "conout$",
];

fn assert_clean_name(shown: &str) {
    assert!(!shown.is_empty());
    assert!(
        !shown.chars().any(|c| BAD_CHARS.contains(&c)),
        "скрытый символ в «{shown:?}»"
    );
    assert!(
        !shown.chars().any(char::is_control),
        "управляющий символ в «{shown:?}»"
    );
    assert!(!shown.contains('\\') && !shown.contains(':'), "{shown:?}");
    assert!(!shown.starts_with('/'), "{shown:?}");
    for comp in shown.split('/') {
        assert!(!comp.is_empty() && comp != "." && comp != "..", "{shown:?}");
        let stem = comp.split('.').next().unwrap_or("").to_lowercase();
        assert!(
            !RESERVED.contains(&stem.as_str()),
            "зарезервированное имя в {shown:?}"
        );
        assert!(!comp.ends_with(' ') && !comp.ends_with('.'), "{shown:?}");
    }
}

#[test]
fn offer_view_only_sanitized_names() {
    let t = Tmp::new("offer");
    let hostile: Vec<String> = vec![
        "photo\u{202E}gpj.exe".to_owned(),
        "invoice\u{200B}\u{200D}.pdf.exe".to_owned(),
        "\u{FEFF}bom.txt".to_owned(),
        "../../etc/passwd".to_owned(),
        "a/../../b.txt".to_owned(),
        "..".to_owned(),
        ".".to_owned(),
        "CON".to_owned(),
        "nul.txt".to_owned(),
        "COM1.log".to_owned(),
        "dir/\u{202E}evil.exe".to_owned(),
        "dir/./x.txt".to_owned(),
        "C:\\Windows\\evil.exe".to_owned(),
        "/abs/path.txt".to_owned(),
        "back\\slash.txt".to_owned(),
        "trail. ".to_owned(),
        "a//b.txt".to_owned(),
        "bell\u{7}.txt".to_owned(),
        "x".repeat(1000),
        format!("{}/{}", "d".repeat(300), "f".repeat(300)),
        "\u{202E}\u{202E}\u{202E}".to_owned(),
        "ok.txt".to_owned(),
        "фото.jpg".to_owned(),
    ];
    let limits = ReceiveLimits::default();
    let mut shown_total = 0;
    for name in &hostile {
        // по одному имени: отказ плана допустим (предложение отклоняется целиком и вида нет)
        let one = [offered(name)];
        let Ok(plan) = plan_offer_in(&one, &limits, &t.0) else {
            continue;
        };
        for f in offer_files(&plan) {
            assert_clean_name(&f.name);
            shown_total += 1;
        }
    }
    // все имена вместе (общий план)
    let all: Vec<OfferedFile> = hostile.iter().map(|n| offered(n)).collect();
    if let Ok(plan) = plan_offer_in(&all, &limits, &t.0) {
        for f in offer_files(&plan) {
            assert_clean_name(&f.name);
            shown_total += 1;
        }
    }
    assert!(
        shown_total >= 3,
        "таблица ничего не показала ({shown_total})"
    );
    // тип и вопрос: .exe требует вопроса, .jpg нет
    let plan = plan_offer_in(&[offered("pics/a.jpg"), offered("tool.exe")], &limits, &t.0).unwrap();
    let files = offer_files(&plan);
    let jpg = files.iter().find(|f| f.name.ends_with("a.jpg")).unwrap();
    let exe = files.iter().find(|f| f.name.ends_with("tool.exe")).unwrap();
    assert_eq!(
        (jpg.kind, jpg.needs_question),
        (super::views::FileKind::Safe, false)
    );
    assert_eq!(
        (exe.kind, exe.needs_question),
        (super::views::FileKind::ExecutableLike, true)
    );
}

// ------------------------------------------------------------------------------ события

#[test]
fn event_queue_is_bounded_and_reports_lag_once() {
    let (sink, events) = EventSink::with_capacity(2);
    let woke = Arc::new(AtomicUsize::new(0));
    let w = woke.clone();
    sink.set_waker(Box::new(move || {
        w.fetch_add(1, Ordering::SeqCst);
    }));
    for _ in 0..5 {
        sink.emit(NodeEvent::Internal);
    }
    assert_eq!(
        woke.load(Ordering::SeqCst),
        2,
        "будильник на каждую отправку"
    );
    assert_eq!(events.try_recv().unwrap(), NodeEvent::Internal);
    assert_eq!(events.try_recv().unwrap(), NodeEvent::Internal);
    assert!(events.try_recv().is_err(), "лишние события не копятся");
    // место появилось: Lagged один раз
    sink.flush_lagged();
    assert_eq!(events.try_recv().unwrap(), NodeEvent::Lagged);
    sink.flush_lagged();
    assert!(events.try_recv().is_err());
    // дальше работает как раньше
    sink.emit(NodeEvent::Stopped);
    assert_eq!(events.try_recv().unwrap(), NodeEvent::Stopped);
    // получатель отпущен: отправка не падает
    drop(events);
    sink.emit(NodeEvent::Internal);
}

#[test]
fn replace_root_keeps_the_old_one_and_reports_a_full_list() {
    let mut s = Settings::new(50000, abs(&["a"]), false);
    settings::replace_root(&mut s, &abs(&["b"]), true).unwrap();
    assert_eq!(
        (s.receive_root.clone(), s.extra_roots.clone()),
        (abs(&["b"]), vec![abs(&["a"])])
    );
    assert!(s.shared_root_confirmed);
    // возврат на прежнюю папку: она уходит из дополнительных, новая дополнительная это бывшая основная
    settings::replace_root(&mut s, &abs(&["a"]), false).unwrap();
    assert_eq!(
        (s.receive_root.clone(), s.extra_roots.clone()),
        (abs(&["a"]), vec![abs(&["b"])])
    );
    assert!(s.shared_root_confirmed, "подтверждение не снимается");
    // список полон (основная и 15 дополнительных): LimitReached, настройки не тронуты
    let mut full = Settings::new(50000, abs(&["main"]), false);
    full.extra_roots = (0..15).map(|i| abs(&["x", &i.to_string()])).collect();
    assert!(serialize(&full).is_ok());
    let before = full.clone();
    assert_eq!(
        settings::replace_root(&mut full, &abs(&["new"]), false).err(),
        Some(NodeError::LimitReached)
    );
    assert!(full == before);
    // но выбрать одну из уже известных можно
    settings::replace_root(&mut full, &abs(&["x", "3"]), false).unwrap();
    assert_eq!(full.extra_roots.len(), 15);
}

#[test]
fn run_timeout_gives_up_but_does_not_hang() {
    let rt = super::runtime::RtThread::start().unwrap();
    let slow = super::runtime::run_timeout(
        &rt.handle,
        async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            1
        },
        std::time::Duration::from_millis(200),
    );
    assert_eq!(slow, None);
    let fast =
        super::runtime::run_timeout(&rt.handle, async { 7 }, std::time::Duration::from_secs(5));
    assert_eq!(fast, Some(7));
    let mut rt = rt;
    rt.stop();
    // среда остановлена: ожидание не зависает
    assert_eq!(
        super::runtime::run_timeout(&rt.handle, async { 1 }, std::time::Duration::from_secs(5)),
        None
    );
}

#[cfg(unix)]
#[test]
fn data_dir_must_be_ours_and_private_unix() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new("owner");
    let open = t.0.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        profile::resolve_data_dir(Some(&open)).err(),
        Some(NodeError::DataDir)
    );
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(profile::resolve_data_dir(Some(&open)).unwrap(), open);
    let group = t.0.join("group");
    std::fs::create_dir(&group).unwrap();
    std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        profile::resolve_data_dir(Some(&group)).err(),
        Some(NodeError::DataDir)
    );
    // ссылка на хороший каталог: отказ
    let link = t.0.join("link");
    std::os::unix::fs::symlink(&open, &link).unwrap();
    assert_eq!(
        profile::resolve_data_dir(Some(&link)).err(),
        Some(NodeError::DataDir)
    );
}

#[cfg(unix)]
#[test]
fn settings_symlink_is_not_followed_unix() {
    let t = Tmp::new("setlink");
    let real = t.0.join("real");
    settings::save(&t.0, &full_sample()).unwrap();
    std::fs::rename(t.0.join("settings.v1"), &real).unwrap();
    std::os::unix::fs::symlink(&real, t.0.join("settings.v1")).unwrap();
    assert_eq!(settings::load(&t.0).err(), Some(NodeError::SettingsCorrupt));
    // сам O_NOFOLLOW (гонка между проверкой и открытием): открытие ссылки обрывается
    assert!(super::settings::open_nofollow(&t.0.join("settings.v1")).is_err());
    assert!(super::settings::open_nofollow(&real).is_ok());
}

#[test]
fn node_and_events_are_thread_safe() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>() {}
    send_sync::<super::Node>();
    send::<super::NodeEvents>();
    send_sync::<FriendRef>();
    send_sync::<TransferRef>();
    send_sync::<super::views::SettingsView>();
}

#[test]
fn events_debug_redacted() {
    use redact_kit::{Needles, Out, check};
    let pair = PairId::from_bytes([0xAB; 16]);
    let key = TransferKey {
        pair,
        id: TransferId([0xCD; 16]),
    };
    let friend = FriendRef::new(pair);
    let transfer = TransferRef::new(key);
    let invite = InviteRef::new(pair);
    let mut out = Out::new();
    for e in [
        NodeEvent::FriendOnline {
            friend,
            path: chervo_connect::PathKind::Lan,
        },
        NodeEvent::FriendOffline { friend },
        NodeEvent::InviteFinished {
            invite,
            outcome: chervo_connect::InviteOutcome::Added,
        },
        NodeEvent::FriendKeyProblem { friend },
        NodeEvent::ClockSkewSuspected { friend },
        NodeEvent::OfferIncoming { transfer },
        NodeEvent::OfferAutoAccepted { transfer },
        NodeEvent::TransferChanged { transfer },
        NodeEvent::TransferFinished {
            transfer,
            result: TransferResult::Completed,
        },
        NodeEvent::Warning(NodeWarning::AnchorNotUpdated),
        NodeEvent::OwnAddressChanged,
        NodeEvent::Internal,
        NodeEvent::Lagged,
        NodeEvent::Stopped,
    ] {
        let s = format!("{e:?}");
        assert!(s.chars().all(|c| c.is_ascii_alphabetic()), "{s}");
        out.dbg("event", &e);
    }
    out.dbg("friend", &friend);
    out.dbg("transfer", &transfer);
    out.dbg("invite", &invite);
    let mut n = Needles::new();
    n.bytes("pair", &[0xAB; 16]);
    n.bytes("transfer id", &[0xCD; 16]);
    n.add("raw hex", "abababab");
    check(&out, &n);
    // ссылки не раскрывают содержимое, но сравнимы
    assert_eq!(friend, FriendRef::new(pair));
    assert_eq!(FriendRef::from_invite(invite), friend);
}
