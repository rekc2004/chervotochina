//! Охрана исходников границы этапов 14 и 15: недоверенное имя не превращается в путь, пути
//! строятся только в трёх модулях, а запрещённых вызовов (права, процессы, сокеты, рекурсивное
//! удаление) в крейте нет. Тестовый код (`src/tests/`) не сканируется.

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
            Src { rel, text }
        })
        .filter(|s| !s.rel.starts_with("tests/"))
        .collect()
}

/// Слово встречается только в перечисленных файлах (и в них хотя бы раз, если `must`).
fn only_in(srcs: &[Src], word: &str, allowed: &[&str]) {
    for s in srcs {
        let has = s.text.contains(word);
        let ok = allowed.contains(&s.rel.as_str());
        assert!(!has || ok, "`{word}` found in {}", s.rel);
    }
}

#[test]
fn src_guard() {
    let srcs = load();
    assert!(srcs.len() >= 20, "scan found only {} files", srcs.len());

    // значение недоверенного имени читают только кодек, файл состояния и сам тип
    only_in(
        &srcs,
        "untrusted_str(",
        &["names.rs", "codec.rs", "state.rs"],
    );
    // пути строятся только здесь
    for w in ["Path::new(", "PathBuf::from(", ".join("] {
        only_in(&srcs, w, &["paths.rs", "placement.rs", "config.rs"]);
    }
    // права, исполнение, сокеты и рекурсивное удаление
    for w in [
        "set_permissions",
        "PermissionsExt",
        "std::process",
        "Command::new",
        "tokio::net",
        "UdpSocket",
        "TcpStream",
        "remove_dir_all",
    ] {
        only_in(&srcs, w, &[]);
    }
}
