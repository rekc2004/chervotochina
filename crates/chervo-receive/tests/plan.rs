//! План предложения: коллизии, слияние каталогов, лимиты. Без файловой системы.

use std::time::Instant;

use chervo_receive::{FileClass, OfferPlan, PathError, ReceiveLimits, plan_offer, plan_offer_in};
use chervo_transfer::{OfferedFile, UntrustedName};

fn offer(names: &[&str]) -> Vec<OfferedFile> {
    names
        .iter()
        .map(|n| OfferedFile {
            name: UntrustedName::new(n).expect("valid name"),
            size: 1,
        })
        .collect()
}

fn paths(plan: &OfferPlan) -> Vec<String> {
    plan.files.iter().map(|f| f.path.display()).collect()
}

fn plan(names: &[&str]) -> OfferPlan {
    plan_offer(&offer(names), &ReceiveLimits::default()).expect("plan")
}

#[test]
fn plan_case_collision_files() {
    let p = plan(&["a.txt", "A.TXT"]);
    assert_eq!(paths(&p), ["a.txt", "A (2).TXT"]);
    let first = p.files.first().expect("first").flags;
    let second = p.files.get(1).expect("second").flags;
    assert!(!first.changed && !first.renamed_in_offer);
    assert!(second.changed && second.renamed_in_offer);
    assert!(!p.auto_ok());
}

#[test]
fn plan_dirs_merge_by_fold() {
    let p = plan(&["Photos/1.jpg", "photos/2.jpg", "PHOTOS/sub/3.jpg"]);
    assert_eq!(
        paths(&p),
        ["Photos/1.jpg", "Photos/2.jpg", "Photos/sub/3.jpg"]
    );
    let f = p.files.get(1).expect("second").flags;
    assert!(f.changed && f.renamed_in_offer);
}

#[test]
fn plan_file_vs_dir() {
    let p = plan(&["report", "report/x"]);
    assert_eq!(paths(&p), ["report", "report (2)/x"]);
    let p = plan(&["report/x", "report"]);
    assert_eq!(paths(&p), ["report/x", "report (2)"]);
    // Следующие файлы renamed-каталога сливаются в него, а не плодят новые.
    let p = plan(&["report", "report/x", "Report/y", "report/z/w"]);
    assert_eq!(
        paths(&p),
        ["report", "report (2)/x", "report (2)/y", "report (2)/z/w"]
    );
    // Буквальное `report (2)` не затирает уже выбранное.
    let p = plan(&["report", "report/x", "report (2)"]);
    assert_eq!(paths(&p), ["report", "report (2)/x", "report (2) (2)"]);
}

#[test]
fn plan_exact_duplicate() {
    let p = plan(&["a.txt", "a.txt", "a.txt", "a (2).txt"]);
    assert_eq!(
        paths(&p),
        ["a.txt", "a (2).txt", "a (3).txt", "a (2) (2).txt"]
    );
    let p = plan(&["noext", "noext"]);
    assert_eq!(paths(&p), ["noext", "noext (2)"]);
}

#[test]
fn plan_sharp_s_and_kelvin() {
    let p = plan(&["\u{DF}.txt", "SS.txt"]);
    assert_eq!(paths(&p), ["\u{DF}.txt", "SS (2).txt"]);
    // U+212A KELVIN SIGN приводится к `K` уже санитайзером (NFC), затем это обычный дубль.
    let p = plan(&["\u{212A}.txt", "k.txt"]);
    assert_eq!(paths(&p), ["K.txt", "k (2).txt"]);
    let p = plan(&["k.txt", "\u{212A}.txt"]);
    assert_eq!(paths(&p), ["k.txt", "K (2).txt"]);
}

#[test]
fn plan_rewrite_collision() {
    let p = plan(&["CON", "_CON"]);
    assert_eq!(paths(&p), ["_CON", "_CON (2)"]);
    let p = plan(&[".a", "_a"]);
    assert_eq!(paths(&p), ["_a", "_a (2)"]);
}

fn same_name_offer(n: usize) -> Vec<OfferedFile> {
    (0..n)
        .map(|_| OfferedFile {
            name: UntrustedName::new("a.txt").expect("valid"),
            size: 1,
        })
        .collect()
}

#[test]
fn plan_10000_same_name_linear() {
    let files = same_name_offer(10_000);
    let t = Instant::now();
    let p = plan_offer(&files, &ReceiveLimits::default()).expect("plan");
    let el = t.elapsed();
    println!("plan_10000_same_name_linear: {el:?}");
    let limit = if cfg!(debug_assertions) { 10 } else { 1 };
    assert!(el.as_secs() < limit, "too slow: {el:?}");
    let mut seen = std::collections::HashSet::new();
    for f in &p.files {
        assert!(seen.insert(f.path.display()));
    }
    assert_eq!(seen.len(), 10_000);
    assert!(seen.contains("a (10000).txt"));
}

#[test]
fn plan_truncated_names_linear() {
    // Имена на пределе длины, отличающиеся только хвостом: после усечения основы
    // кандидаты разных имён совпадают; счётчик семейства держит работу линейной.
    let mut names = Vec::new();
    for i in 0..5_000u32 {
        let stem = format!("{}{:04}", "n".repeat(250), i);
        names.push(stem.clone());
        names.push(stem);
    }
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let files = offer(&refs);
    let t = Instant::now();
    let p = plan_offer(&files, &ReceiveLimits::default()).expect("plan");
    let el = t.elapsed();
    println!("plan_truncated_names_linear: {el:?}");
    let limit = if cfg!(debug_assertions) { 10 } else { 2 };
    assert!(el.as_secs() < limit, "too slow: {el:?}");
    let mut seen = std::collections::HashSet::new();
    for f in &p.files {
        let s = f.path.display();
        assert!(s.len() <= 255);
        assert!(seen.insert(s));
    }
}

#[test]
fn plan_limits() {
    let l = ReceiveLimits::default();
    let many: Vec<String> = (0..10_001).map(|i| format!("f{i}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        plan_offer(&offer(&refs), &l).map(|_| ()),
        Err(PathError::TooManyFiles)
    );
    assert_eq!(
        plan_offer(&offer(&refs[..10_000]), &l).map(|p| p.files.len()),
        Ok(10_000)
    );

    let small = ReceiveLimits {
        max_total_bytes: 100,
        ..l
    };
    let mut files = offer(&["a", "b"]);
    for f in &mut files {
        f.size = 60;
    }
    assert_eq!(
        plan_offer(&files, &small).map(|_| ()),
        Err(PathError::TooLarge)
    );
    for f in &mut files {
        f.size = 50;
    }
    assert_eq!(plan_offer(&files, &small).map(|p| p.total), Ok(100));

    let mut files = offer(&["a", "b"]);
    if let Some(f) = files.first_mut() {
        f.size = u64::MAX;
    }
    if let Some(f) = files.get_mut(1) {
        f.size = 1;
    }
    assert_eq!(plan_offer(&files, &l).map(|_| ()), Err(PathError::TooLarge));

    // Один враждебный путь отклоняет всё предложение.
    assert_eq!(
        plan_offer(&offer(&["ok.txt", "../x"]), &l).map(|_| ()),
        Err(PathError::DotComponent)
    );
    let bad = ReceiveLimits { max_files: 0, ..l };
    assert_eq!(
        plan_offer(&offer(&["a"]), &bad).map(|_| ()),
        Err(PathError::BadLimits)
    );
    // Пустое предложение допустимо.
    assert_eq!(plan_offer(&[], &l).map(|p| p.files.len()), Ok(0));
}

#[test]
fn plan_summary_fields() {
    let mut files = offer(&["a.txt", "photo.jpg.exe", "disk.iso"]);
    for (f, s) in files.iter_mut().zip([10u64, 20, 30]) {
        f.size = s;
    }
    let p = plan_offer(&files, &ReceiveLimits::default()).expect("plan");
    assert_eq!(p.total, 60);
    assert_eq!(p.max_class, FileClass::Executable);
    assert!(p.any_deceptive);
    assert!(!p.auto_ok());
    let idx: Vec<u32> = p.files.iter().map(|f| f.index).collect();
    assert_eq!(idx, [0, 1, 2]);
    let dbg = format!("{p:?} {:?}", p.files.first());
    assert!(!dbg.contains("a.txt"), "Debug must not print names: {dbg}");
}

#[test]
fn plan_long_names_stay_within_limit() {
    let long = format!("{}.txt", "x".repeat(251));
    let p = plan(&[long.as_str(), long.as_str(), long.as_str()]);
    let got = paths(&p);
    for (i, s) in got.iter().enumerate() {
        assert!(s.len() <= 255, "{i}: {}", s.len());
        assert!(s.ends_with(".txt"));
    }
    let uniq: std::collections::HashSet<_> = got.iter().collect();
    assert_eq!(uniq.len(), 3);
}

#[cfg(windows)]
#[test]
fn plan_long_path_flag() {
    use std::path::PathBuf;
    let l = ReceiveLimits::default();
    let files = offer(&["a/b/c.txt"]);
    let short_root = PathBuf::from(r"C:\Users\x\Downloads");
    let p = plan_offer_in(&files, &l, &short_root).expect("plan");
    assert!(!p.files.first().expect("f").flags.long_path);
    let long_root = PathBuf::from(format!(r"\\?\C:\{}", "d".repeat(260)));
    let p = plan_offer_in(&files, &l, &long_root).expect("plan");
    assert!(p.files.first().expect("f").flags.long_path);
    assert!(!p.auto_ok());
    // Ровно на границе с запасом на суффикс " (k)" при размещении (6 единиц для одиночного файла,
    // 12 для файла в каталоге верхнего уровня; Рев. 3, F6): 259 единиц нет, 260 да.
    let name = "e".repeat(10);
    let files = offer(&[name.as_str()]);
    let root259 = PathBuf::from(format!(r"C:\{}", "r".repeat(259 - 3 - 1 - 10 - 6)));
    let p = plan_offer_in(&files, &l, &root259).expect("plan");
    assert!(!p.files.first().expect("f").flags.long_path);
    let root260 = PathBuf::from(format!(r"C:\{}", "r".repeat(260 - 3 - 1 - 10 - 6)));
    let p = plan_offer_in(&files, &l, &root260).expect("plan");
    assert!(p.files.first().expect("f").flags.long_path);
    // Файл в каталоге верхнего уровня: запас 12 единиц (оба суффикса ` (999)`).
    let files = offer(&["d/eeeeeeeeee"]);
    let used = 3 + (1 + 1) + (1 + 10) + 12;
    let r259 = PathBuf::from(format!(r"C:\{}", "r".repeat(259 - used)));
    let p = plan_offer_in(&files, &l, &r259).expect("plan");
    assert!(!p.files.first().expect("f").flags.long_path);
    let r260 = PathBuf::from(format!(r"C:\{}", "r".repeat(260 - used)));
    let p = plan_offer_in(&files, &l, &r260).expect("plan");
    assert!(p.files.first().expect("f").flags.long_path);
}

#[cfg(not(windows))]
#[test]
fn plan_long_path_flag() {
    println!("plan_long_path_flag: skipped, long_path is computed on Windows only");
    let files = offer(&["a/b/c.txt"]);
    let root = std::path::PathBuf::from(format!("/{}", "d".repeat(400)));
    let p = plan_offer_in(&files, &ReceiveLimits::default(), &root).expect("plan");
    assert!(!p.files.first().expect("f").flags.long_path);
}
