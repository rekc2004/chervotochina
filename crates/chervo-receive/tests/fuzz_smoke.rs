//! Дымовой фаззинг санитайзера и плана: xorshift64*, без внешних пакетов.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000).
//! Свойства: нет паники; `Ok` держит инварианты, результат внутри корня, повторный проход
//! ничего не меняет; в плане нет двух имён с одинаковым `fold` в одном каталоге.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path};

use chervo_receive::{
    FileClass, ReceiveLimits, SafeRelPath, classify, fold, is_known_inert, is_portable_component,
    plan_offer, portable_component, sanitize_path, sanitize_relative_path,
};
use chervo_transfer::{OfferedFile, UntrustedName};
use unicode_normalization::UnicodeNormalization;

/// Длина в байтах после NFC: санитайзер не растит имя сверх неё (плюс `_` на компонент).
fn nfc_len(s: &str) -> usize {
    s.nfc().map(char::len_utf8).sum()
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

fn alphabet() -> Vec<char> {
    let mut a: Vec<char> = "/\\:.. ~0123456789<>\"|?*aAbBcCoOnNuUlLpPtTxXeE_-()gGzZiImM"
        .chars()
        .collect();
    a.extend([
        '\u{0}',
        '\u{1}',
        '\u{7}',
        '\n',
        '\u{1F}',
        '\u{7F}',
        '\u{80}',
        '\u{85}',
        '\u{9F}',
        '\u{B9}',
        '\u{B2}',
        '\u{B3}',
        '\u{DF}',
        '\u{438}',
        '\u{439}',
        '\u{306}',
        '\u{301}',
        '\u{338}',
        '\u{212A}',
        '\u{2126}',
        '\u{958}',
        '\u{1D161}',
        '\u{AC00}',
        '\u{1100}',
        '\u{1161}',
        '\u{11A8}',
        '\u{2764}',
        '\u{1F468}',
        '\u{1F525}',
        '\u{2600}',
        '\u{27BF}',
        '\u{1F000}',
        '\u{E000}',
        '\u{10FFFF}',
        // Все символы из правила R1.
        '\u{2215}',
        '\u{2044}',
        '\u{FF0F}',
        '\u{29F8}',
        '\u{FF3C}',
        '\u{29F5}',
        '\u{29F9}',
        '\u{FE68}',
        '\u{FF1A}',
        '\u{2236}',
        '\u{A789}',
        '\u{FE55}',
        '\u{FE13}',
        '\u{00AD}',
        '\u{034F}',
        '\u{061C}',
        '\u{115F}',
        '\u{1160}',
        '\u{17B4}',
        '\u{17B5}',
        '\u{180B}',
        '\u{180F}',
        '\u{200B}',
        '\u{200C}',
        '\u{200D}',
        '\u{200E}',
        '\u{200F}',
        '\u{202A}',
        '\u{202E}',
        '\u{2060}',
        '\u{206F}',
        '\u{3164}',
        '\u{FE00}',
        '\u{FE0E}',
        '\u{FE0F}',
        '\u{FEFF}',
        '\u{FFA0}',
        '\u{FFF0}',
        '\u{FFF8}',
        '\u{1D173}',
        '\u{1D17A}',
        '\u{E0000}',
        '\u{E0020}',
        '\u{E007F}',
        '\u{E0FFF}',
    ]);
    a
}

const SEEDS: &[&str] = &[
    "../../etc/passwd",
    "a/../../b",
    "/etc/passwd",
    "C:\\Windows\\x",
    "C:/Windows/x",
    "CON",
    "con.txt",
    "CON .txt",
    "NUL.tar.gz",
    "aux ",
    "nul.",
    "evil.exe . .",
    "file.txt:Zone.Identifier",
    "file.txt::$DATA",
    "a<b>c\"d|e?f*g",
    "PROGRA~1",
    ".bashrc",
    ".chervo-partial/x",
    "photo\u{202E}gpj.exe",
    "a\u{200B}b.txt",
    "\u{2764}\u{FE0F}.jpg",
    "\u{438}\u{306}.txt",
    "Desktop.ini",
    "x/CON/y.txt",
    "a\u{FF0F}b",
    "photo.jpg      .exe",
    "CLOC\u{212A}$",
    "x.exe..gz",
    "x.exe .gz",
    "x.exe. .gz",
    "x.exe.gz..gz",
    "x.iso. .xz",
];

fn random_input(rng: &mut Rng, alpha: &[char]) -> String {
    match rng.below(4) {
        0 => {
            let n = rng.below(48);
            let bytes: Vec<u8> = (0..n).map(|_| rng.next().to_le_bytes()[0]).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        1 | 2 => {
            let n = rng.below(60);
            (0..n)
                .map(|_| alpha.get(rng.below(alpha.len())).copied().unwrap_or('a'))
                .collect()
        }
        _ => {
            let mut chars: Vec<char> = SEEDS
                .get(rng.below(SEEDS.len()))
                .copied()
                .unwrap_or("a")
                .chars()
                .collect();
            for _ in 0..=rng.below(4) {
                let ch = alpha.get(rng.below(alpha.len())).copied().unwrap_or('a');
                let pos = rng.below(chars.len() + 1);
                match rng.below(3) {
                    0 => chars.insert(pos, ch),
                    1 if pos < chars.len() => {
                        chars.remove(pos);
                    }
                    _ if pos < chars.len() => {
                        if let Some(c) = chars.get_mut(pos) {
                            *c = ch;
                        }
                    }
                    _ => {}
                }
            }
            chars.into_iter().collect()
        }
    }
}

fn nfc_path_len(input: &str) -> usize {
    input.split('/').map(nfc_len).sum::<usize>() + input.matches('/').count()
}

fn check(input: &str, l: &ReceiveLimits, root: &Path) {
    let Ok((p, flags)) = sanitize_path(input, l) else {
        assert!(sanitize_relative_path(root, input, l).is_err());
        return;
    };
    let comps = p.components();
    let depth = comps.len();
    assert!(depth >= 1 && depth <= usize::from(l.max_depth), "{input:?}");
    for c in comps {
        assert!(is_portable_component(c), "{input:?} -> {c:?}");
        assert!(
            c.len() <= usize::from(l.max_name_bytes),
            "{input:?} -> {c:?}"
        );
        assert!(!c.is_empty() && !c.contains('/') && !c.contains('\\'));
    }
    let shown = p.display();
    assert!(
        shown.len() <= nfc_path_len(input) + depth,
        "grew: {input:?} -> {shown:?}"
    );
    // Внутри корня: ровно `depth` обычных компонентов.
    let joined = sanitize_relative_path(root, input, l).expect("same input");
    let rest = joined.strip_prefix(root).expect("inside root");
    let normal: Vec<Component<'_>> = rest.components().collect();
    assert_eq!(normal.len(), depth, "{input:?}");
    assert!(normal.iter().all(|c| matches!(c, Component::Normal(_))));
    // Идемпотентность.
    let (again, f2) = sanitize_path(&shown, l)
        .unwrap_or_else(|e| panic!("second pass failed {e:?}: {input:?} -> {shown:?}"));
    assert_eq!(again, p, "not idempotent: {input:?} -> {shown:?}");
    assert!(!f2.changed && !f2.suspicious, "{input:?} -> {shown:?}");
    assert_eq!(flags.changed, shown != input, "{input:?}");
    // Сторона отправителя согласована.
    if !input.contains('/') && usize::from(l.max_name_bytes) == 255 {
        assert_eq!(
            portable_component(input).as_deref(),
            Ok(shown.as_str()),
            "{input:?}"
        );
    }
}

fn iterations() -> u64 {
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Зерно ГПСЧ цели (этап 17, B3). Без `CHERVO_FUZZ_SEED` ровно `default`, как раньше. С ней
/// у каждой цели своё зерно (splitmix64 от `seed ^ default`), так что длинные прогоны идут по
/// новым последовательностям. Пустое значение считается незаданным; неразборное (не `u64`)
/// вызывает панику, чтобы прогон не пошёл молча по старому зерну.
fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[test]
fn fuzz_smoke_sanitizer() {
    let n = iterations();
    println!(
        "fuzz_smoke_sanitizer: os={} iterations={n}",
        std::env::consts::OS
    );
    let alpha = alphabet();
    let root = std::env::temp_dir();
    let default = ReceiveLimits::default();
    let small = ReceiveLimits {
        max_name_bytes: 14,
        max_path_bytes: 90,
        max_depth: 5,
        ..ReceiveLimits::default()
    };
    let mut rng = Rng(fuzz_seed(0x9E37_79B9_7F4A_7C15));
    let mut ok = 0u64;
    for i in 0..n {
        let input = random_input(&mut rng, &alpha);
        let l = if i % 4 == 3 { &small } else { &default };
        if sanitize_path(&input, l).is_ok() {
            ok += 1;
        }
        check(&input, l, &root);
    }
    println!("fuzz_smoke_sanitizer: accepted={ok} of {n}");
    assert!(ok > 0);
}

fn rel_key(parts: &[String], upto: usize) -> String {
    parts
        .iter()
        .take(upto)
        .map(|p| fold(p))
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn fuzz_smoke_plan() {
    let n = (iterations() / 50).max(100);
    println!("fuzz_smoke_plan: os={} offers={n}", std::env::consts::OS);
    let alpha = alphabet();
    let l = ReceiveLimits::default();
    let pieces = [
        "a",
        "A",
        "a.txt",
        "A.TXT",
        "a (2).txt",
        "\u{DF}",
        "SS",
        "ss.txt",
        "CON",
        "_CON",
        ".a",
        "_a",
        "dir",
        "Dir",
        "DIR (2)",
        "x.app",
        "k",
        "\u{212A}",
        "report",
        "Report (2)",
    ];
    let mut rng = Rng(fuzz_seed(0xD1B5_4A32_D192_ED03));
    let mut total_files = 0usize;
    for _ in 0..n {
        let count = 1 + rng.below(64);
        let mut files = Vec::new();
        for _ in 0..count {
            let name = if rng.below(2) == 0 {
                let depth = 1 + rng.below(3);
                (0..depth)
                    .map(|_| {
                        pieces
                            .get(rng.below(pieces.len()))
                            .copied()
                            .unwrap_or("a")
                            .to_owned()
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            } else {
                random_input(&mut rng, &alpha)
            };
            if sanitize_path(&name, &l).is_err() {
                continue;
            }
            files.push(OfferedFile {
                name: UntrustedName::new(&name).expect("valid"),
                size: 1,
            });
        }
        let plan = plan_offer(&files, &l).expect("all names sanitize");
        assert_eq!(plan.files.len(), files.len());
        total_files += files.len();
        let mut full_keys: HashSet<String> = HashSet::new();
        let mut dir_spelling: HashMap<String, String> = HashMap::new();
        let mut file_keys: HashSet<String> = HashSet::new();
        for (i, f) in plan.files.iter().enumerate() {
            assert_eq!(usize::try_from(f.index).ok(), Some(i));
            let parts = f.path.components();
            for c in parts {
                assert!(is_portable_component(c));
            }
            let key = rel_key(parts, parts.len());
            assert!(full_keys.insert(key.clone()), "duplicate by fold: {key}");
            file_keys.insert(key);
            for up in 1..parts.len() {
                let k = rel_key(parts, up);
                let spelled = parts.iter().take(up).cloned().collect::<Vec<_>>().join("/");
                let prev = dir_spelling.entry(k).or_insert_with(|| spelled.clone());
                assert_eq!(*prev, spelled, "directory spelled two ways");
            }
        }
        for k in dir_spelling.keys() {
            assert!(
                !file_keys.contains(k),
                "name is both file and directory: {k}"
            );
        }
        // Повторный план по уже итоговым именам ничего не меняет.
        let second: Vec<OfferedFile> = plan
            .files
            .iter()
            .map(|f| OfferedFile {
                name: UntrustedName::new(&f.path.display()).expect("valid"),
                size: 1,
            })
            .collect();
        let plan2 = plan_offer(&second, &l).expect("replan");
        for (a, b) in plan.files.iter().zip(&plan2.files) {
            assert_eq!(a.path, b.path);
            assert!(!b.flags.changed && !b.flags.renamed_in_offer);
            // Рев. 3, F3: `suspicious` остаётся только из-за не-ASCII в расширении
            // (то есть в последнем компоненте), не из-за невидимых символов. Рев. 6, M1: или
            // из-за хвостовых `.` и пробелов перед суффиксом (`x.exe .gz`).
            assert!(
                !b.flags.suspicious
                    || b.path.components().last().is_some_and(|c| {
                        !c.is_ascii()
                            || c.rsplit_once('.')
                                .is_some_and(|(s, _)| s.ends_with(['.', ' ']))
                    })
            );
        }
    }
    println!("fuzz_smoke_plan: files={total_files}");
}

/// Суффиксы сжатия, которые распаковщик снимает по одному (независимая копия списка).
fn is_compression(ext: &str) -> bool {
    matches!(
        fold(ext).as_str(),
        "gz" | "xz" | "bz2" | "zst" | "lz" | "lz4" | "z"
    )
}

fn single(name: &str, l: &ReceiveLimits) -> Option<SafeRelPath> {
    sanitize_path(name, l).ok().map(|(p, _)| p)
}

/// Рев. 6, M1: имена после снятия каждого суффикса сжатия, где основа очищена от хвостовых
/// `.` и пробелов, как это делает Windows при создании файла.
fn windows_peeled_stems(last: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = last.to_owned();
    for _ in 0..16 {
        let Some((stem, ext)) = cur.rsplit_once('.') else {
            break;
        };
        if !is_compression(ext) {
            break;
        }
        let clean = stem.trim_end_matches(['.', ' ']);
        if clean.is_empty() {
            break;
        }
        out.push(clean.to_owned());
        cur = clean.to_owned();
    }
    out
}

/// Свойство: если после нормализации хвостовых точек и пробелов у какой-либо снятой основы
/// получается опасный класс, исходное имя никогда не «заведомо безопасное».
fn check_inert(input: &str, l: &ReceiveLimits) {
    let Some(p) = single(input, l) else {
        return;
    };
    if !is_known_inert(&p) {
        return;
    }
    let Some(last) = p.components().last() else {
        return;
    };
    for stem in windows_peeled_stems(last) {
        if let Some(q) = single(&stem, l) {
            assert_eq!(
                classify(&q).class,
                FileClass::Ordinary,
                "known-inert {input:?} hides risky {stem:?}"
            );
        }
    }
}

#[test]
fn fuzz_smoke_known_inert_vs_windows_trim() {
    let n = iterations();
    println!("fuzz_smoke_known_inert: iterations={n}");
    let alpha = alphabet();
    let l = ReceiveLimits::default();
    let pieces = [
        "x", "photo", ".exe", ".jpg", ".iso", ".lnk", ".gz", ".xz", ".Z", ".zst", ".", "..", " ",
        ". ", " .", ".tar",
    ];
    let mut rng = Rng(fuzz_seed(0xA5A5_1234_DEAD_BEEF));
    let mut inert = 0u64;
    for _ in 0..n {
        let input = if rng.below(2) == 0 {
            let k = 1 + rng.below(7);
            (0..k)
                .map(|_| pieces.get(rng.below(pieces.len())).copied().unwrap_or("x"))
                .collect::<String>()
        } else {
            random_input(&mut rng, &alpha)
        };
        if single(&input, &l).is_some_and(|p| is_known_inert(&p)) {
            inert += 1;
        }
        check_inert(&input, &l);
    }
    println!("fuzz_smoke_known_inert: known-inert={inert} of {n}");
    assert!(inert > 0);
}
