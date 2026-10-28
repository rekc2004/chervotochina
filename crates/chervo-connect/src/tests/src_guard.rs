//! Охрана исходников: в крейте нет сокетов, DNS и сторонних служб, а чувствительные вызовы
//! стоят строго в своих модулях. Тестовый код (`src/tests/`) проверяется только на запретные
//! слова: его вызовы не часть движка.

use std::path::{Path, PathBuf};

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

struct Src {
    rel: String,
    text: String,
    is_test: bool,
}

fn load() -> Vec<Src> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            // переводы строк Windows приводятся к LF
            let text = std::fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
            let is_test = rel.starts_with("tests/");
            Src { rel, text, is_test }
        })
        .filter(|s| s.rel != "tests/src_guard.rs")
        .collect()
}

#[test]
fn src_guard() {
    let srcs = load();
    assert!(srcs.len() >= 12, "scan found only {} files", srcs.len());

    // сокеты, DNS и сторонние службы
    for s in &srcs {
        for w in [
            "UdpSocket",
            "TcpStream",
            "TcpListener",
            "send_to",
            "lookup_host",
            "to_socket_addrs",
        ] {
            assert!(!s.text.contains(w), "{} contains {w}", s.rel);
        }
        // имя поля диагноза `rendezvous_could_help` обязательно по спецификации, но допустимо
        // только в `diag.rs` и `engine.rs` (и тестах диагноза); любое другое упоминание
        // посредника, STUN, UPnP, mDNS запрещено
        let flag_ok = matches!(
            s.rel.as_str(),
            "diag.rs" | "engine.rs" | "tests/diag.rs" | "tests/engine.rs"
        );
        let mut lower = s.text.to_lowercase();
        if flag_ok {
            lower = lower.replace("rendezvous_could_help", "");
        }
        for w in ["rendezvous", "stun", "igd", "upnp", "mdns"] {
            assert!(!lower.contains(w), "{} contains {w}", s.rel);
        }
        // производственный код не запускает процессы и не открывает сокеты tokio
        if !s.is_test {
            for w in ["Command::new", "std::process", "tokio::net"] {
                assert!(!s.text.contains(w), "{} contains {w}", s.rel);
            }
        }
    }

    let engine: Vec<&Src> = srcs.iter().filter(|s| !s.is_test).collect();
    // вхождения шаблона; `-> Имя {` (сигнатура функции) не литерал структуры и не считается
    let occurrences = |text: &str, pat: &str| -> usize {
        text.match_indices(pat)
            .filter(|(i, _)| !text[..*i].ends_with("-> "))
            .count()
    };
    let count = |pat: &str, only: &str| -> usize {
        let mut n = 0;
        for s in &engine {
            let c = occurrences(&s.text, pat);
            if s.rel != only {
                assert_eq!(c, 0, "`{pat}` outside {only}: {}", s.rel);
            }
            n += c;
        }
        n
    };
    // снимок собственных адресов строится ровно в одном месте
    assert_eq!(count("LocalSnapshot {", "watch.rs"), 1);
    // маршрут берётся только из пробы
    assert_eq!(count("RouteSources {", "none"), 0);
    // шлюз задаётся ровно в одном месте, в задаче проброса; блокирующие вызовы тоже только там
    assert_eq!(count("set_gateway(", "gateway.rs"), 1);
    assert!(count("spawn_blocking", "gateway.rs") >= 1);
    assert!(count("PortMapper", "gateway.rs") >= 1);
    // наблюдения и выпуск токенов обновления только в жизненном цикле ADDR_INFO
    assert!(count(".observe(", "addrinfo.rs") >= 1);
    assert!(count("issue_addr_update(", "addrinfo.rs") >= 1);
    // отметки «друг на связи» (F1) ставятся и снимаются только по событиям соединения в движке
    assert!(count("reporter_up(", "engine.rs") >= 1);
    assert!(count("reporter_down(", "engine.rs") >= 1);
    // проба маршрута к цели (сокетный код) вызывается только из `clock.rs`
    assert!(count("route_source_for(", "clock.rs") >= 1);
    // служба поиска в локальной сети (13в): интерфейс и забор находок только в lan.rs
    assert!(count("LanDiscovery", "lan.rs") >= 1);
    assert!(count("take_sightings(", "lan.rs") >= 1);
    // положительный контроль: охрана видит нужные файлы
    assert!(engine.iter().any(|s| s.rel == "lan.rs"));
    assert!(engine.iter().any(|s| s.rel == "watch.rs"));
    assert!(engine.iter().any(|s| s.rel == "addrinfo.rs"));
    assert!(engine.iter().any(|s| s.rel == "gateway.rs"));

    // манифест: ни зависимости от крейта проброса, ни сокетной библиотеки
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap()
            .to_lowercase();
    for w in ["upnp", "igd", "socket2", "mio", "hyper"] {
        assert!(!manifest.contains(w), "Cargo.toml contains {w}");
    }
    // 13в: крейта маяка нет в обычных зависимостях (в dev-зависимостях для сквозного теста можно)
    let (normal, dev) = manifest
        .split_once("[dev-dependencies]")
        .expect("в манифесте есть [dev-dependencies]");
    assert!(
        !normal.contains("chervo-lan"),
        "chervo-lan в [dependencies]"
    );
    assert!(
        dev.contains("chervo-lan"),
        "сквозной тест подключает chervo-lan как dev"
    );
}

// ----------------------------------------------------------------------------------------
// Этап 17, C15 (SEC-13 L4, 12 L5): `tests/` и `examples/` крейта тоже под охраной
// «конечных точек и процессов». Структурные правила выше остаются только для `src/`.
// ----------------------------------------------------------------------------------------

/// Слова, которым нечего делать в тестах и примерах: запуск процессов, сокеты tokio, TCP, DNS.
const OUTSIDE_SRC_FORBIDDEN: [&str; 8] = [
    "Command::new",
    "process::Command",
    "tokio::net",
    "TcpStream",
    "TcpListener",
    "lookup_host",
    "to_socket_addrs",
    "ToSocketAddrs",
];

fn forbidden_outside_src(text: &str) -> Vec<&'static str> {
    OUTSIDE_SRC_FORBIDDEN
        .into_iter()
        .filter(|w| text.contains(w))
        .collect()
}

fn guard_walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            guard_walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn src_guard_tests_and_examples() {
    // охрана сама видит нарушения (иначе пустой список слов прошёл бы молча)
    assert_eq!(
        forbidden_outside_src("let c = std::process::Command::new(\"x\");"),
        ["Command::new", "process::Command"]
    );
    assert_eq!(
        forbidden_outside_src("use tokio::net::TcpStream;"),
        ["tokio::net", "TcpStream"]
    );
    assert!(forbidden_outside_src("let n = std::process::id();").is_empty());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for d in ["tests", "examples"] {
        guard_walk(&root.join(d), &mut files);
    }
    // сам файл охраны называет запретные слова в своих списках
    files.retain(|p| p.file_name().is_some_and(|n| n != "src_guard.rs"));
    assert!(
        files.len() >= MIN_OUTSIDE_FILES,
        "охрана tests/ и examples/ нашла только {} файлов",
        files.len()
    );
    assert!(
        files
            .iter()
            .any(|p| p.components().any(|c| c.as_os_str() == "examples")),
        "examples/ не просканирован"
    );
    for p in &files {
        // переводы строк Windows приводятся к LF
        let text = std::fs::read_to_string(p).unwrap().replace("\r\n", "\n");
        let bad = forbidden_outside_src(&text);
        assert!(bad.is_empty(), "{} содержит {bad:?}", p.display());
    }
}

const MIN_OUTSIDE_FILES: usize = 3;
