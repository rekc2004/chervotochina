//! Тесты проверки выпусков. Ключи ТЕСТОВЫЕ (зерно в коде), подписи собраны здесь же в формате
//! minisign. Совместимость с настоящей программой minisign: `real_minisign.rs`.

mod common;

use std::io::Read;

use chervo_update::{
    Freshness, KeyId, KeyRole, KeySet, MAX_ARTIFACTS, MAX_MANIFEST_LEN, MAX_MINISIG_LEN,
    MAX_PUBKEY_LEN, Manifest, Target, UpdateError, Version, check_artifact, check_artifact_path,
    pubkey_line, verify_manifest,
};
use common::*;

const TRUSTED: &str = "chervo-release 1.2.3";

fn keyset(seed: u8, n: u8) -> KeySet {
    let sk = test_key(seed);
    KeySet::from_pubkey_files(&[(KeyRole::Primary, &pubkey_file(&sk, key_id(n)))]).unwrap()
}

/// Подписанный образец: (набор ключей, манифест, подпись).
fn signed() -> (KeySet, Vec<u8>, Vec<u8>) {
    let m = sample_manifest_bytes();
    let sig = sign(&test_key(1), key_id(1), &m, TRUSTED);
    (keyset(1, 1), m, sig)
}

/// Заменяет первую подстроку в тексте файла подписи.
fn replace_in(sig: &[u8], from: &str, to: &str) -> Vec<u8> {
    let s = String::from_utf8(sig.to_vec()).unwrap();
    assert!(s.contains(from), "нет {from:?}");
    s.replacen(from, to, 1).into_bytes()
}

fn sig_lines(sig: &[u8]) -> Vec<String> {
    String::from_utf8(sig.to_vec())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn join_lines(l: &[String]) -> Vec<u8> {
    let mut s = l.join("\n");
    s.push('\n');
    s.into_bytes()
}

#[test]
fn pubkey_ok() {
    let sk = test_key(7);
    let file = pubkey_file(&sk, key_id(7));
    let ks = KeySet::from_pubkey_files(&[(KeyRole::Backup, &file)]).unwrap();
    let list = ks.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, KeyRole::Backup);
    assert_eq!(list[0].1, KeyId(key_id(7)));
    assert_eq!(list[0].2, sk.verifying_key().to_bytes());
    // строка для сверки с README совпадает со строкой файла и начинается с `RW`
    let line = pubkey_line(list[0].1, &list[0].2);
    assert_eq!(line.len(), 56);
    assert!(line.starts_with("RW"));
    assert!(String::from_utf8(file.clone()).unwrap().contains(&line));
    // `\r\n`, отсутствие конечного перевода строки и комментарий до 1024 байт допустимы
    let crlf = String::from_utf8(file.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert!(KeySet::from_pubkey_files(&[(KeyRole::Primary, &crlf)]).is_ok());
    let no_nl = &file[..file.len() - 1];
    assert!(KeySet::from_pubkey_files(&[(KeyRole::Primary, no_nl)]).is_ok());
    // как в комментарии minisign: u64 little-endian, заглавные цифры
    assert_eq!(
        KeyId([1, 2, 3, 4, 5, 6, 7, 8]).to_string(),
        "0807060504030201"
    );
}

#[test]
fn sig_ok_test_key() {
    let (ks, m, sig) = signed();
    let vm = verify_manifest(&ks, &m, &sig).unwrap();
    assert_eq!(vm.signer(), (KeyRole::Primary, KeyId(key_id(1))));
    assert_eq!(vm.trusted_comment(), TRUSTED);
    assert_eq!(vm.manifest().version, v(1, 2, 3));
    assert_eq!(vm.manifest().artifacts.len(), 3);
    // `\r\n` в файле подписи допустим
    let crlf = String::from_utf8(sig.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert!(verify_manifest(&ks, &m, &crlf).is_ok());
    // табуляция в доверенном комментарии (минисайн по умолчанию пишет `timestamp:..\tfile:..`)
    let tab = "timestamp:1\tfile:x\thashed";
    let sig2 = sign(&test_key(1), key_id(1), &m, tab);
    assert_eq!(
        verify_manifest(&ks, &m, &sig2).unwrap().trusted_comment(),
        tab
    );
}

#[test]
fn rejects_legacy_ed_alg() {
    let (ks, m, _) = signed();
    let sig = sign_alg(&test_key(1), key_id(1), b"Ed", &m, TRUSTED);
    assert_eq!(
        verify_manifest(&ks, &m, &sig).err(),
        Some(UpdateError::UnsupportedAlgorithm)
    );
    let sig = sign_alg(&test_key(1), key_id(1), b"XY", &m, TRUSTED);
    assert_eq!(
        verify_manifest(&ks, &m, &sig).err(),
        Some(UpdateError::UnsupportedAlgorithm)
    );
    // публичный ключ с иным алгоритмом
    let mut raw = b"ED".to_vec();
    raw.extend_from_slice(&key_id(1));
    raw.extend_from_slice(&test_key(1).verifying_key().to_bytes());
    let f = format!("untrusted comment: x\n{}\n", b64(&raw)).into_bytes();
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &f)]).err(),
        Some(UpdateError::UnsupportedAlgorithm)
    );
}

#[test]
fn rejects_unknown_key_id() {
    let (ks, m, _) = signed();
    let sig = sign(&test_key(1), key_id(2), &m, TRUSTED);
    assert_eq!(
        verify_manifest(&ks, &m, &sig).err(),
        Some(UpdateError::UnknownKey)
    );
}

#[test]
fn rejects_flipped_bit_manifest() {
    let (ks, m, sig) = signed();
    for byte in 0..m.len() {
        for bit in [0u8, 3, 7] {
            let mut bad = m.clone();
            bad[byte] ^= 1 << bit;
            assert_eq!(
                verify_manifest(&ks, &bad, &sig).err(),
                Some(UpdateError::BadSignature),
                "byte {byte} bit {bit}"
            );
        }
    }
}

/// Сырые 74 байта строки подписи: перекодируем с перевёрнутым битом.
fn flip_raw_sig_bit(sig: &[u8], raw_byte: usize, bit: u8) -> Vec<u8> {
    let mut lines = sig_lines(sig);
    let mut raw = decode_std(&lines[1]);
    raw[raw_byte] ^= 1 << bit;
    lines[1] = b64(&raw);
    join_lines(&lines)
}

fn decode_std(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    };
    let b = s.as_bytes();
    let pad = b.iter().filter(|&&c| c == b'=').count();
    let mut out = Vec::new();
    for ch in b.chunks(4) {
        let n = (val(ch[0]) << 18) | (val(ch[1]) << 12) | (val(ch[2]) << 6) | val(ch[3]);
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.truncate(out.len() - pad);
    out
}

#[test]
fn rejects_flipped_bit_sig() {
    let (ks, m, sig) = signed();
    // байты 10..74 строки подписи это сама подпись
    for raw_byte in 10..74 {
        for bit in 0..8 {
            let bad = flip_raw_sig_bit(&sig, raw_byte, bit);
            assert_eq!(
                verify_manifest(&ks, &m, &bad).err(),
                Some(UpdateError::BadSignature),
                "byte {raw_byte} bit {bit}"
            );
        }
    }
    // перевёрнутый бит key_id: ключ неизвестен
    let bad = flip_raw_sig_bit(&sig, 2, 0);
    assert_eq!(
        verify_manifest(&ks, &m, &bad).err(),
        Some(UpdateError::UnknownKey)
    );
}

#[test]
fn rejects_bad_global_sig() {
    let (ks, m, sig) = signed();
    let mut lines = sig_lines(&sig);
    let mut raw = decode_std(&lines[3]);
    for byte in [0usize, 31, 32, 63] {
        raw[byte] ^= 0x01;
        lines[3] = b64(&raw);
        assert_eq!(
            verify_manifest(&ks, &m, &join_lines(&lines)).err(),
            Some(UpdateError::BadGlobalSignature),
            "byte {byte}"
        );
        raw[byte] ^= 0x01;
    }
    // подпись манифеста от другой подписи: глобальная не от этой пары
    let other = sign(&test_key(1), key_id(1), b"other manifest", TRUSTED);
    let mut l2 = sig_lines(&sig);
    l2[3] = sig_lines(&other)[3].clone();
    assert_eq!(
        verify_manifest(&ks, &m, &join_lines(&l2)).err(),
        Some(UpdateError::BadGlobalSignature)
    );
}

#[test]
fn rejects_changed_trusted_comment() {
    let (ks, m, sig) = signed();
    for new in ["chervo-release 1.2.4", "", "chervo-release 1.2.3 ", "x"] {
        let bad = replace_in(&sig, TRUSTED, new);
        assert_eq!(
            verify_manifest(&ks, &m, &bad).err(),
            Some(UpdateError::BadGlobalSignature),
            "{new:?}"
        );
    }
    // управляющие символы в доверенном комментарии: формат неверен
    for ctl in ["a\u{1}b", "a\u{7f}b", "a\u{85}b"] {
        let bad = replace_in(&sig, TRUSTED, ctl);
        assert_eq!(
            verify_manifest(&ks, &m, &bad).err(),
            Some(UpdateError::MalformedSignature),
            "{ctl:?}"
        );
    }
    // не UTF-8
    let mut bad = sig.clone();
    let at = String::from_utf8(sig.clone())
        .unwrap()
        .find(TRUSTED)
        .unwrap();
    bad[at] = 0xFF;
    assert_eq!(
        verify_manifest(&ks, &m, &bad).err(),
        Some(UpdateError::MalformedSignature)
    );
}

#[test]
fn rejects_noncanonical_base64() {
    let (ks, m, sig) = signed();
    let lines = sig_lines(&sig);
    // строка подписи (100 символов, набивка `=`): третий знак последней четвёрки несёт
    // хвостовые биты (у настоящей подписи нулевые); 'B' делает их ненулевыми
    let mut l = lines.clone();
    let mut chars: Vec<char> = l[1].chars().collect();
    assert_eq!(chars[99], '=');
    chars[98] = 'B';
    l[1] = chars.iter().collect();
    assert_eq!(
        verify_manifest(&ks, &m, &join_lines(&l)).err(),
        Some(UpdateError::MalformedSignature)
    );
    // глобальная подпись (88 символов, `==`): второй знак последней четвёрки
    let mut l = lines.clone();
    let mut chars: Vec<char> = l[3].chars().collect();
    assert_eq!(&chars[86..], &['=', '=']);
    chars[85] = 'B';
    l[3] = chars.iter().collect();
    assert_eq!(
        verify_manifest(&ks, &m, &join_lines(&l)).err(),
        Some(UpdateError::MalformedSignature)
    );
    // без набивки, с пробелом, URL-safe, перевод строки внутри
    for bad_line in [
        lines[1].trim_end_matches('=').to_owned(),
        format!("{} ", lines[1]),
        format!(" {}", lines[1]),
        lines[1].replace('+', "-").replace('/', "_") + "A",
        lines[1].replacen('A', "\t", 1),
    ] {
        let mut l = lines.clone();
        if bad_line == l[1] {
            continue;
        }
        l[1] = bad_line;
        assert_eq!(
            verify_manifest(&ks, &m, &join_lines(&l)).err(),
            Some(UpdateError::MalformedSignature)
        );
    }
    // публичный ключ: пробел, набивка, замена на URL-safe
    let pk = pubkey_file(&test_key(1), key_id(1));
    let text = String::from_utf8(pk).unwrap();
    let key_line = text.lines().nth(1).unwrap().to_owned();
    for bad_line in [
        format!("{key_line} "),
        format!("{key_line}="),
        key_line[..55].to_owned(),
        key_line.replace('+', "-"),
    ] {
        if bad_line == key_line {
            continue;
        }
        let f = format!("untrusted comment: x\n{bad_line}\n").into_bytes();
        assert_eq!(
            KeySet::from_pubkey_files(&[(KeyRole::Primary, &f)]).err(),
            Some(UpdateError::MalformedPubkey),
            "{bad_line:?}"
        );
    }
}

#[test]
fn rejects_wrong_lengths() {
    let (ks, m, sig) = signed();
    let lines = sig_lines(&sig);
    // подпись и глобальная подпись неверной длины (корректный base64, но не те байты)
    for (idx, n) in [(1usize, 73usize), (1, 75), (1, 0), (3, 63), (3, 65), (3, 0)] {
        let mut l = lines.clone();
        l[idx] = b64(&vec![0x11; n]);
        assert_eq!(
            verify_manifest(&ks, &m, &join_lines(&l)).err(),
            Some(UpdateError::MalformedSignature),
            "line {idx} len {n}"
        );
    }
    // число строк
    for l in [
        lines[..3].to_vec(),
        lines[..2].to_vec(),
        lines[..1].to_vec(),
        vec![],
        [lines.clone(), vec![String::new()]].concat(),
        [lines.clone(), vec!["x".to_owned()]].concat(),
    ] {
        assert_eq!(
            verify_manifest(&ks, &m, &join_lines(&l)).err(),
            Some(UpdateError::MalformedSignature)
        );
    }
    assert_eq!(
        verify_manifest(&ks, &m, b"").err(),
        Some(UpdateError::MalformedSignature)
    );
    // нет префиксов
    for (from, to) in [
        ("untrusted comment: ", "comment: "),
        ("trusted comment: ", "untrusted comment: "),
        ("trusted comment: ", "trusted_comment: "),
    ] {
        let bad = replace_in(&sig, from, to);
        assert_eq!(
            verify_manifest(&ks, &m, &bad).err(),
            Some(UpdateError::MalformedSignature),
            "{from:?}"
        );
    }
    // публичный ключ: длина raw 41 и 43, число строк, нет префикса
    for n in [41usize, 43, 0, 74] {
        let f = format!("untrusted comment: x\n{}\n", b64(&vec![0x22; n])).into_bytes();
        assert_eq!(
            KeySet::from_pubkey_files(&[(KeyRole::Primary, &f)]).err(),
            Some(UpdateError::MalformedPubkey),
            "len {n}"
        );
    }
    let good = String::from_utf8(pubkey_file(&test_key(1), key_id(1))).unwrap();
    let key_line = good.lines().nth(1).unwrap();
    for f in [
        key_line.to_owned() + "\n",
        format!("untrusted comment: x\n{key_line}\nextra\n"),
        format!("untrusted comment: x\n{key_line}\n\n"),
        format!("comment: x\n{key_line}\n"),
        String::new(),
    ] {
        assert_eq!(
            KeySet::from_pubkey_files(&[(KeyRole::Primary, f.as_bytes())]).err(),
            Some(UpdateError::MalformedPubkey)
        );
    }
}

#[test]
fn rejects_oversize_inputs() {
    let (ks, m, sig) = signed();
    // длина проверяется до разбора: мусор той же длины даёт TooLarge, а не ошибку формата
    let huge_manifest = vec![b'x'; MAX_MANIFEST_LEN + 1];
    assert_eq!(
        verify_manifest(&ks, &huge_manifest, &sig).err(),
        Some(UpdateError::TooLarge)
    );
    assert_eq!(
        Manifest::parse(&huge_manifest).err(),
        Some(UpdateError::TooLarge)
    );
    let huge_sig = vec![b'x'; MAX_MINISIG_LEN + 1];
    assert_eq!(
        verify_manifest(&ks, &m, &huge_sig).err(),
        Some(UpdateError::TooLarge)
    );
    let huge_key = vec![b'x'; MAX_PUBKEY_LEN + 1];
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &huge_key)]).err(),
        Some(UpdateError::TooLarge)
    );
    // ровно на пределе длина допустима (дальше ошибка формата)
    let at_limit = vec![b'x'; MAX_MANIFEST_LEN];
    assert_ne!(
        verify_manifest(&ks, &at_limit, &sig).err(),
        Some(UpdateError::TooLarge)
    );
    // слишком длинный комментарий в пределах файла
    let long_comment = format!("untrusted comment: {}", "a".repeat(1100));
    let mut l = sig_lines(&sig);
    l[0] = long_comment;
    assert_eq!(
        verify_manifest(&ks, &m, &join_lines(&l)).err(),
        Some(UpdateError::MalformedSignature)
    );
}

#[test]
fn rejects_weak_pubkey() {
    // нейтральный элемент (y = 1), точка порядка 2 (y = -1), нулевой ключ (порядок 4)
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut order2 = [0xffu8; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    let zero = [0u8; 32];
    for pk in [identity, order2, zero] {
        let f = pubkey_file_raw(pk, key_id(9));
        assert_eq!(
            KeySet::from_pubkey_files(&[(KeyRole::Primary, &f)]).err(),
            Some(UpdateError::MalformedPubkey),
            "{pk:?}"
        );
    }
    // не точка кривой / неканоническая кодировка (y >= p)
    let noncanon = [0xffu8; 32];
    let f = pubkey_file_raw(noncanon, key_id(9));
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &f)]).err(),
        Some(UpdateError::MalformedPubkey)
    );
}

#[test]
fn rejects_sig_other_key_same_id() {
    // набор знает ключ A под key_id X; подпись ключом B с тем же key_id X не проходит
    let m = sample_manifest_bytes();
    let ks = keyset(1, 5);
    let sig = sign(&test_key(2), key_id(5), &m, TRUSTED);
    assert_eq!(
        verify_manifest(&ks, &m, &sig).err(),
        Some(UpdateError::BadSignature)
    );
}

#[test]
fn keyset_duplicate_ids_rejected() {
    let a = pubkey_file(&test_key(1), key_id(4));
    let b = pubkey_file(&test_key(2), key_id(4));
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &a), (KeyRole::Backup, &b)]).err(),
        Some(UpdateError::KeysetInvalid)
    );
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &a), (KeyRole::Backup, &a)]).err(),
        Some(UpdateError::KeysetInvalid)
    );
    let c = pubkey_file(&test_key(2), key_id(5));
    let ks = KeySet::from_pubkey_files(&[(KeyRole::Primary, &a), (KeyRole::Backup, &c)]).unwrap();
    assert_eq!(ks.list().len(), 2);
    // ошибка любого файла отвергает весь набор
    assert_eq!(
        KeySet::from_pubkey_files(&[(KeyRole::Primary, &a), (KeyRole::Backup, b"junk")]).err(),
        Some(UpdateError::MalformedPubkey)
    );
}

#[test]
fn keyset_empty_is_no_trusted_keys() {
    assert_eq!(
        KeySet::from_pubkey_files(&[]).err(),
        Some(UpdateError::NoTrustedKeys)
    );
    // пока владелец не вшил ключи, вшитый набор пуст; после вшивания тест ничего не утверждает
    if let Err(e) = KeySet::embedded() {
        assert_eq!(e, UpdateError::NoTrustedKeys);
    }
}

fn manifest_text(extra_lines: &[&str]) -> String {
    let mut s = String::from("chervo-release-manifest 1\nversion 1.2.3\ncommit ");
    s.push_str(&"ab".repeat(20));
    s.push('\n');
    for l in extra_lines {
        s.push_str(l);
        s.push('\n');
    }
    s
}

fn hx(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn art(n: u8) -> String {
    format!("artifact linux-x86_64 {} 10 f{n}", hx(n))
}

#[test]
fn manifest_grammar_table() {
    let good_commit = "ab".repeat(20);
    // (текст, ожидаемая ошибка)
    let mut cases: Vec<(String, UpdateError)> = Vec::new();
    let bad = |line: u32| UpdateError::MalformedManifest { line };

    let base = manifest_text(&[&art(1)]);
    assert!(Manifest::parse(base.as_bytes()).is_ok());

    cases.push((base.replace('\n', "\r\n"), bad(1)));
    cases.push((base.replace("f1\n", "f1 \n"), bad(4)));
    cases.push((base.trim_end_matches('\n').to_owned(), bad(4)));
    cases.push((manifest_text(&[&art(1), &art(1)]), bad(5)));
    // повтор имени с другим хэшем
    cases.push((
        manifest_text(&[&art(1), &format!("artifact linux-x86_64 {} 10 f1", hx(2))]),
        bad(5),
    ));
    // повтор хэша с другим именем
    cases.push((
        manifest_text(&[
            &art(1),
            &format!("artifact linux-x86_64 {} 10 other", hx(1)),
        ]),
        bad(5),
    ));
    cases.push((base.replace("version 1.2.3", "version 01.2.3"), bad(2)));
    cases.push((base.replace("version 1.2.3", "version 1.2.3.4"), bad(2)));
    cases.push((base.replace("version 1.2.3", "version 1.2"), bad(2)));
    cases.push((base.replace("version 1.2.3", "version +1.2.3"), bad(2)));
    cases.push((
        base.replace("version 1.2.3", "version 4294967296.0.0"),
        bad(2),
    ));
    cases.push((base.replace(" 10 f1", " 010 f1"), bad(4)));
    cases.push((base.replace(" 10 f1", " -1 f1"), bad(4)));
    cases.push((base.replace(" 10 f1", " 18446744073709551616 f1"), bad(4)));
    cases.push((
        manifest_text(&[&format!(
            "artifact linux-x86_64 {} 10 f1",
            "ab".repeat(32).to_uppercase()
        )]),
        bad(4),
    ));
    cases.push((base.replace(&hx(1), &hx(1)[..63]), bad(4)));
    cases.push((base.replace(&hx(1), &(hx(1) + "0")), bad(4)));
    cases.push((base.replace("linux-x86_64", "linux-aarch64"), bad(4)));
    cases.push((base.replace("linux-x86_64", "Linux-x86_64"), bad(4)));
    cases.push((base.replace("artifact ", "artefact "), bad(4)));
    cases.push((base.replace("artifact ", "artifact  "), bad(4)));
    cases.push((base.replace("artifact ", "artifact\t"), bad(4)));
    cases.push((base.replace(" f1", " "), bad(4)));
    cases.push((base.replace(" f1", " a/b"), bad(4)));
    cases.push((base.replace(" f1", " a\\b"), bad(4)));
    cases.push((base.replace(" f1", " .."), bad(4)));
    cases.push((base.replace(" f1", " .hidden"), bad(4)));
    cases.push((base.replace(" f1", " a b"), bad(4)));
    cases.push((
        base.replace(" f1", &format!(" {}", "n".repeat(129))),
        bad(4),
    ));
    cases.push((base.replace(" f1", " \u{444}"), bad(4)));
    cases.push((base.replace(&good_commit, &good_commit[..39]), bad(3)));
    cases.push((
        base.replace(&good_commit, &good_commit.to_uppercase()),
        bad(3),
    ));
    cases.push((base.replace("commit ", "commit  "), bad(3)));
    cases.push((base.replace("version 1.2.3\ncommit", "commit"), bad(2)));
    // другой порядок: commit раньше version
    cases.push((
        format!(
            "chervo-release-manifest 1\ncommit {good_commit}\nversion 1.2.3\n{}\n",
            art(1)
        ),
        bad(2),
    ));
    cases.push((manifest_text(&["", &art(1)]), bad(4)));
    cases.push((manifest_text(&[&art(1), ""]), bad(5)));
    cases.push((manifest_text(&[&art(1), "extra 1"]), bad(5)));
    cases.push((manifest_text(&[]), bad(4)));
    cases.push((String::new(), bad(1)));
    cases.push(("\n".to_owned(), bad(1)));
    cases.push(("chervo-release-manifest 1\n".to_owned(), bad(2)));
    cases.push((format!("\u{feff}{base}"), bad(1)));
    cases.push((base.replace("manifest 1", "manifest  1"), bad(1)));
    cases.push((base.replace("manifest 1", "Manifest 1"), bad(1)));
    // 33 артефакта
    let many: Vec<String> = (0..=u8::try_from(MAX_ARTIFACTS).unwrap())
        .map(art)
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(refs.len(), MAX_ARTIFACTS + 1);
    cases.push((
        manifest_text(&refs),
        bad(u32::try_from(4 + MAX_ARTIFACTS).unwrap()),
    ));
    // другая версия формата
    cases.push((
        base.replace("manifest 1", "manifest 2"),
        UpdateError::UnsupportedManifestVersion,
    ));
    cases.push((
        base.replace("manifest 1", "manifest 99"),
        UpdateError::UnsupportedManifestVersion,
    ));

    assert!(cases.len() >= 25, "злых строк {}", cases.len());
    for (text, expected) in cases {
        assert_eq!(
            Manifest::parse(text.as_bytes()).err(),
            Some(expected),
            "{text:?}"
        );
    }
    // 32 артефакта допустимы; нулевой размер и версия 0.0.0 допустимы
    let ok32: Vec<String> = (0..u8::try_from(MAX_ARTIFACTS).unwrap()).map(art).collect();
    let refs: Vec<&str> = ok32.iter().map(String::as_str).collect();
    assert_eq!(
        Manifest::parse(manifest_text(&refs).as_bytes())
            .unwrap()
            .artifacts
            .len(),
        32
    );
    let zero = base
        .replace(" 10 f1", " 0 f1")
        .replace("version 1.2.3", "version 0.0.0");
    assert!(Manifest::parse(zero.as_bytes()).is_ok());
    // версия максимальная
    let max = base.replace("version 1.2.3", "version 4294967295.4294967295.4294967295");
    assert!(Manifest::parse(max.as_bytes()).is_ok());
}

#[test]
fn manifest_canonical_roundtrip() {
    let bytes = sample_manifest_bytes();
    let m = Manifest::parse(&bytes).unwrap();
    assert_eq!(m.to_canonical_bytes(), bytes);
    assert_eq!(m.commit, [0xab; 20]);
    assert_eq!(m.artifacts[0].target, Target::LinuxX86_64);
    assert_eq!(m.artifacts[2].target, Target::Any);
    let again = Manifest::parse(&m.to_canonical_bytes()).unwrap();
    assert_eq!(again, m);
    // каждое значение цели записывается и читается обратно
    for t in [
        Target::LinuxX86_64,
        Target::MacosAarch64,
        Target::MacosX86_64,
        Target::WindowsX86_64,
        Target::Any,
    ] {
        assert_eq!(t.to_string().parse::<Target>().unwrap(), t);
    }
    assert_eq!(v(1, 2, 3).to_string(), "1.2.3");
    assert!(v(1, 2, 3) < v(1, 10, 0));
    assert!(v(2, 0, 0) > v(1, 99, 99));
}

/// Образец для проверки артефактов: версия манифеста и подписанный набор.
fn signed_with(version: Version) -> chervo_update::VerifiedManifest {
    let m = manifest(
        version,
        vec![
            artifact(Target::LinuxX86_64, "chervo-linux", b"linux-bin"),
            artifact(Target::WindowsX86_64, "chervo-windows.exe", b"win-bin"),
            artifact(Target::Any, "sbom.json", b"{}"),
        ],
    )
    .to_canonical_bytes();
    let sig = sign(&test_key(1), key_id(1), &m, TRUSTED);
    verify_manifest(&keyset(1, 1), &m, &sig).unwrap()
}

#[test]
fn artifact_ok_newer() {
    let vm = signed_with(v(1, 2, 3));
    let r = check_artifact(
        &vm,
        &b"linux-bin"[..],
        v(1, 0, 0),
        Some(Target::LinuxX86_64),
        false,
    )
    .unwrap();
    assert_eq!(r.freshness, Freshness::Newer);
    assert_eq!(r.version, v(1, 2, 3));
    assert_eq!(r.artifact.name, "chervo-linux");
    assert_eq!(r.artifact.size, 9);
    // файл «для всех» подходит любой цели, в том числе неизвестной
    let r = check_artifact(&vm, &b"{}"[..], v(1, 0, 0), None, false).unwrap();
    assert_eq!(r.artifact.target, Target::Any);
}

#[test]
fn artifact_same_version() {
    let vm = signed_with(v(1, 2, 3));
    let r = check_artifact(
        &vm,
        &b"win-bin"[..],
        v(1, 2, 3),
        Some(Target::WindowsX86_64),
        false,
    )
    .unwrap();
    assert_eq!(r.freshness, Freshness::Same);
}

#[test]
fn artifact_wrong_target() {
    let vm = signed_with(v(1, 2, 3));
    assert_eq!(
        check_artifact(
            &vm,
            &b"win-bin"[..],
            v(1, 0, 0),
            Some(Target::LinuxX86_64),
            false
        )
        .err(),
        Some(UpdateError::WrongTarget {
            expected: Some(Target::LinuxX86_64),
            found: Target::WindowsX86_64
        })
    );
    assert_eq!(
        check_artifact(&vm, &b"linux-bin"[..], v(1, 0, 0), None, false).err(),
        Some(UpdateError::WrongTarget {
            expected: None,
            found: Target::LinuxX86_64
        })
    );
}

#[test]
fn artifact_not_in_manifest() {
    let vm = signed_with(v(1, 2, 3));
    for data in [
        &b"linux-bio"[..],
        &b""[..],
        &b"linux-bin "[..],
        &b"linux-bi"[..],
    ] {
        assert_eq!(
            check_artifact(&vm, data, v(1, 0, 0), Some(Target::LinuxX86_64), false).err(),
            Some(UpdateError::NotInManifest)
        );
    }
}

/// Читатель без конца; считает отданные байты.
struct Endless {
    given: u64,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(0xAA);
        self.given += buf.len() as u64;
        Ok(buf.len())
    }
}

#[test]
fn artifact_stops_reading_after_max_size() {
    let vm = signed_with(v(1, 2, 3));
    // наибольший size манифеста 9 байт; один блок чтения 1 МиБ, дальше чтение прекращается
    let mut r = Endless { given: 0 };
    assert_eq!(
        check_artifact(&vm, &mut r, v(1, 0, 0), Some(Target::LinuxX86_64), false).err(),
        Some(UpdateError::NotInManifest)
    );
    assert!(r.given <= 1024 * 1024, "прочитано {}", r.given);
    assert!(r.given > 0);

    // манифест с большим файлом: читает до его размера и не дальше +1 блок
    let big = 3 * 1024 * 1024 + 5;
    let m = manifest(
        v(1, 0, 0),
        vec![chervo_update::Artifact {
            target: Target::Any,
            sha256: [7; 32],
            size: big,
            name: "big".to_owned(),
        }],
    )
    .to_canonical_bytes();
    let sig = sign(&test_key(1), key_id(1), &m, TRUSTED);
    let vm = verify_manifest(&keyset(1, 1), &m, &sig).unwrap();
    let mut r = Endless { given: 0 };
    assert_eq!(
        check_artifact(&vm, &mut r, v(0, 0, 0), None, false).err(),
        Some(UpdateError::NotInManifest)
    );
    assert!(r.given >= big, "прочитано {}", r.given);
    assert!(r.given <= big + 1024 * 1024, "прочитано {}", r.given);
}

#[test]
fn downgrade_rejected_unless_allowed() {
    let vm = signed_with(v(1, 0, 0));
    assert_eq!(
        check_artifact(
            &vm,
            &b"linux-bin"[..],
            v(2, 0, 0),
            Some(Target::LinuxX86_64),
            false
        )
        .err(),
        Some(UpdateError::Downgrade {
            running: v(2, 0, 0),
            offered: v(1, 0, 0)
        })
    );
    let r = check_artifact(
        &vm,
        &b"linux-bin"[..],
        v(2, 0, 0),
        Some(Target::LinuxX86_64),
        true,
    )
    .unwrap();
    assert_eq!(r.freshness, Freshness::OlderAllowed);
}

#[test]
fn artifact_path_reads_file() {
    let vm = signed_with(v(1, 2, 3));
    let dir = std::env::temp_dir().join(format!("chervo-update-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("chervo (1).exe"); // браузер переименовал: ищем по хэшу, не по имени
    std::fs::write(&file, b"win-bin").unwrap();
    let r =
        check_artifact_path(&vm, &file, v(1, 0, 0), Some(Target::WindowsX86_64), false).unwrap();
    assert_eq!(r.artifact.name, "chervo-windows.exe");
    // каталог и несуществующий путь: ошибка ввода-вывода
    assert!(matches!(
        check_artifact_path(&vm, &dir, v(1, 0, 0), None, false).err(),
        Some(UpdateError::Io(_))
    ));
    assert!(matches!(
        check_artifact_path(&vm, &dir.join("нет"), v(1, 0, 0), None, false).err(),
        Some(UpdateError::Io(std::io::ErrorKind::NotFound))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn error_display_has_no_input() {
    // Display не содержит байтов входа: проверяем на ошибке с «ядовитым» содержимым
    let mut l = sig_lines(&signed().2);
    l[0] = "untrusted comment: SECRET-MARKER".to_owned();
    l[1] = "SECRET-MARKER".to_owned();
    let (ks, m, _) = signed();
    let e = verify_manifest(&ks, &m, &join_lines(&l)).err().unwrap();
    assert!(!format!("{e} {e:?}").contains("SECRET-MARKER"));
    let e = Manifest::parse(b"SECRET-MARKER\n").err().unwrap();
    assert!(!format!("{e} {e:?}").contains("SECRET-MARKER"));
}
