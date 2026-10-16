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
        // имя поля диагноза `rendezvous_could_help` обязательно по спецификации и допустимо;
        // любое другое упоминание посредника, STUN, UPnP, mDNS запрещено
        let lower = s.text.to_lowercase().replace("rendezvous_could_help", "");
        for w in ["rendezvous", "stun", "igd", "upnp", "mdns"] {
            assert!(!lower.contains(w), "{} contains {w}", s.rel);
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
    // маршрут берётся только из пробы, шлюз не задаётся
    assert_eq!(count("RouteSources {", "none"), 0);
    assert_eq!(count("set_gateway(", "none"), 0);
    // наблюдения и выпуск токенов обновления только в жизненном цикле ADDR_INFO
    assert!(count(".observe(", "addrinfo.rs") >= 1);
    assert!(count("issue_addr_update(", "addrinfo.rs") >= 1);
    // положительный контроль: охрана видит нужные файлы
    assert!(engine.iter().any(|s| s.rel == "watch.rs"));
    assert!(engine.iter().any(|s| s.rel == "addrinfo.rs"));
}
