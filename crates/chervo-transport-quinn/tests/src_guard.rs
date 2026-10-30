//! Статический страж по исходникам `src/` (кроме `src/tests/`, который собирается только в `cfg(test)`).

use std::fs;
use std::path::{Path, PathBuf};

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(files.len() >= 7, "ожидаются модули крейта");
    files
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            // Git на Windows может выдать CRLF: приводим к LF, иначе многострочные иглы не находятся.
            (name, fs::read_to_string(p).unwrap().replace("\r\n", "\n"))
        })
        .collect()
}

fn count(srcs: &[(String, String)], needle: &str) -> usize {
    srcs.iter().map(|(_, s)| s.matches(needle).count()).sum()
}

#[test]
fn src_guard() {
    let srcs = sources();

    // модульные тесты подключены только под cfg(test)
    let lib = &srcs.iter().find(|(n, _)| n == "lib.rs").unwrap().1;
    assert!(
        lib.contains("#[cfg(test)]\nmod tests;"),
        "src/tests должен подключаться только под cfg(test)"
    );

    // запрещённые вхождения
    for bad in [
        "tracing",
        "log::",
        "println!",
        "eprintln!",
        "print!",
        "dbg!",
        concat!("Device", "Id"),
        "QuicServerConfig::new",
        ".refuse(",
        "into_0rtt",
        "send_datagram",
        "IdentityError::",
        // стук: только свои гнёзда, нет прямого `Endpoint::new` и `.rebind(`; тайм-синхронизация
        // не вызывается из транспорта; обязательность стука не отключается в коде крейта
        "Endpoint::new(",
        ".rebind(",
        "chervo_timesync",
        "knock_required: false",
    ] {
        assert_eq!(count(&srcs, bad), 0, "запрещено в src/: {bad}");
    }

    // ровно по одному вхождению
    for once in [
        "accept_with(",
        "kk_respond(",
        "spawn_blocking(",
        "export_keying_material(",
        "ChannelBinding::from_bytes(",
    ] {
        assert_eq!(
            count(&srcs, once),
            1,
            "должно быть ровно одно вхождение: {once}"
        );
    }
    // kk_respond и spawn_blocking только в limits.rs
    for (name, s) in &srcs {
        if name != "limits.rs" {
            assert!(
                !s.contains("kk_respond("),
                "kk_respond( вне limits.rs: {name}"
            );
            assert!(
                !s.contains("spawn_blocking("),
                "spawn_blocking( вне limits.rs: {name}"
            );
        }
        if name != "conn.rs" {
            assert!(
                !s.contains("export_keying_material(")
                    && !s.contains("ChannelBinding::from_bytes("),
                "источник ChannelBinding вне conn.rs: {name}"
            );
        }
        // отправка стука и любая прямая отправка в гнездо только в knock.rs
        if name != "knock.rs" {
            assert!(!s.contains("try_send("), "try_send( вне knock.rs: {name}");
        }
        if name != "tls.rs" {
            assert!(!s.contains("dangerous()"), "dangerous() вне tls.rs: {name}");
        }
    }

    assert!(
        count(&srcs, "try_send(") >= 1,
        "try_send( должен быть в knock.rs"
    );

    // этап 13г: `socket2` только в bind.rs; `IPV6_V6ONLY` снимается ровно в одном месте
    for (name, s) in &srcs {
        if name != "bind.rs" {
            assert!(!s.contains("socket2"), "socket2 вне bind.rs: {name}");
        }
    }
    assert!(
        srcs.iter()
            .any(|(n, s)| n == "bind.rs" && s.contains("socket2::")),
        "socket2 должен использоваться в bind.rs"
    );
    assert_eq!(count(&srcs, "set_only_v6("), 1, "set_only_v6( ровно одно");

    // CLOSE_REFUSED: ровно два использования (не объявление и не комментарий), оба в conn.rs:
    // внутри fn refuse и внутри fn close_endpoint (закрытие гнезда при shutdown)
    let mut uses = Vec::new();
    for (name, s) in &srcs {
        for (i, line) in s.lines().enumerate() {
            let t = line.trim_start();
            if line.contains("CLOSE_REFUSED")
                && !t.starts_with("//")
                && !t.starts_with("pub const CLOSE_REFUSED")
            {
                uses.push((name.clone(), i, s.clone()));
            }
        }
    }
    assert_eq!(
        uses.len(),
        2,
        "CLOSE_REFUSED используется не только в refuse и close_endpoint"
    );
    let mut covered = Vec::new();
    for (name, line_no, text) in &uses {
        assert_eq!(name, "conn.rs");
        let line_start: usize = text.lines().take(*line_no).map(|l| l.len() + 1).sum();
        let fn_name = ["fn refuse(", "fn close_endpoint("]
            .into_iter()
            .find(|f| {
                let start = text.find(f).expect("функция есть");
                let end = start + text[start..].find("\n}\n").expect("конец функции");
                line_start > start && line_start < end
            })
            .expect("CLOSE_REFUSED вне тел refuse и close_endpoint");
        covered.push(fn_name);
    }
    covered.sort_unstable();
    assert_eq!(
        covered,
        ["fn close_endpoint(", "fn refuse("],
        "по одному использованию в каждой из двух функций"
    );

    // accept() только как endpoint.accept()
    for (name, s) in &srcs {
        let mut from = 0;
        while let Some(i) = s[from..].find(".accept()") {
            let at = from + i;
            assert!(
                s[..at].ends_with("endpoint"),
                "посторонний .accept() в {name}"
            );
            from = at + 1;
        }
    }
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

const MIN_OUTSIDE_FILES: usize = 5;
