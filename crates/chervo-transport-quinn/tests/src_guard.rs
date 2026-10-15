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
            (name, fs::read_to_string(p).unwrap())
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
        if name != "tls.rs" {
            assert!(!s.contains("dangerous()"), "dangerous() вне tls.rs: {name}");
        }
    }

    // CLOSE_REFUSED: единственное использование (не объявление и не комментарий) внутри fn refuse
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
        1,
        "CLOSE_REFUSED используется не только в refuse"
    );
    let (name, line_no, text) = &uses[0];
    assert_eq!(name, "conn.rs");
    let start = text.find("fn refuse(").expect("fn refuse");
    let end = start + text[start..].find("\n}\n").expect("конец refuse");
    let line_start: usize = text.lines().take(*line_no).map(|l| l.len() + 1).sum();
    assert!(
        line_start > start && line_start < end,
        "CLOSE_REFUSED вне тела refuse"
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
