mod common;

use std::path::{Path, PathBuf};

use chervo_identity::{create, load, rekey, PairId, SignDomain};
use common::MemStore;

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        let keep = chunk.len() + 1;
        for (i, ix) in idx.iter().enumerate() {
            if i < keep {
                out.push(alphabet[*ix as usize]);
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

fn hex(data: &[u8], upper: bool) -> Vec<u8> {
    data.iter()
        .flat_map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
            .into_bytes()
        })
        .collect()
}

/// Все формы записи секрета: сырая, hex (оба регистра), base64 (оба алфавита, с паддингом и без).
fn forms(secret: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("raw", secret.to_vec()),
        ("hex-lower", hex(secret, false)),
        ("hex-upper", hex(secret, true)),
        ("b64-std-pad", b64(secret, STD, true)),
        ("b64-std-nopad", b64(secret, STD, false)),
        ("b64-url-pad", b64(secret, URL, true)),
        ("b64-url-nopad", b64(secret, URL, false)),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Возвращает найденные (файл, форма).
fn scan(dir: &Path, secrets: &[Vec<u8>]) -> Vec<(PathBuf, &'static str)> {
    let mut files = Vec::new();
    all_files(dir, &mut files);
    let mut found = Vec::new();
    for f in files {
        let data = std::fs::read(&f).unwrap();
        for s in secrets {
            for (name, needle) in forms(s) {
                if contains(&data, &needle) {
                    found.push((f.clone(), name));
                }
            }
        }
    }
    found
}

fn unique_dir(tag: &str) -> PathBuf {
    let id = PairId::generate().unwrap().account_name();
    let d = std::env::temp_dir().join(format!("chervo-nodisk-{tag}-{id}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn key_bytes_not_written_to_data_dir() {
    let d = unique_dir("main");
    let old = std::env::current_dir().unwrap();
    std::env::set_current_dir(&d).unwrap();

    let store = MemStore::new();
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    for _ in 0..5 {
        let p = PairId::generate().unwrap();
        let key = create(&store, &p).unwrap();
        let expected = key.public_key();
        let loaded = load(&store, &p, &expected).unwrap();
        let sig = loaded.sign(SignDomain::Invite, b"msg").unwrap();
        expected.verify(SignDomain::Invite, b"msg", &sig).unwrap();
        let blob = store.raw(&p).unwrap();
        secrets.push(blob[1..33].to_vec());
        secrets.push(blob);
        drop(key);
        drop(loaded);

        let new = rekey(&store, &p).unwrap();
        let blob = store.raw(&p).unwrap();
        secrets.push(blob[1..33].to_vec());
        secrets.push(blob);
        drop(new);
    }
    assert_eq!(secrets.len(), 20);

    std::env::set_current_dir(&old).unwrap();
    let found = scan(&d, &secrets);
    std::fs::remove_dir_all(&d).unwrap();
    assert!(found.is_empty(), "найдены секреты на диске: {found:?}");
}

#[test]
fn scan_detects_planted_key() {
    let d2 = unique_dir("plant");
    let store = MemStore::new();
    let p = PairId::generate().unwrap();
    create(&store, &p).unwrap();
    let blob = store.raw(&p).unwrap();
    let seed = blob[1..33].to_vec();

    for secret in [&seed, &blob] {
        for (name, bytes) in forms(secret) {
            let dir = d2.join(format!("{}-{name}", secret.len()));
            std::fs::create_dir_all(&dir).unwrap();
            let mut data = b"prefix-".to_vec();
            data.extend_from_slice(&bytes);
            std::fs::write(dir.join("planted.bin"), data).unwrap();
            let found = scan(&dir, std::slice::from_ref(secret));
            assert!(
                found.iter().any(|(_, n)| *n == name),
                "сканер не нашёл форму {name} для длины {}",
                secret.len()
            );
        }
    }
    std::fs::remove_dir_all(&d2).unwrap();
}
