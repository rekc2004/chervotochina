//! Таблица враждебных и переписываемых имён. Без файловой системы, ожидания одинаковы на
//! всех ОС (`std::env::consts::OS` печатается для сверки логов CI).

use std::path::{Component, Path};

use chervo_receive::{
    PathError, ReceiveLimits, is_portable_component, portable_component, sanitize_path,
    sanitize_relative_path,
};

enum Exp {
    Err(PathError),
    /// Итоговый путь и флаг `suspicious`.
    Out(String, bool),
}

fn err(input: &str, kind: PathError) -> (String, Exp) {
    (input.to_owned(), Exp::Err(kind))
}

fn to(input: &str, out: &str) -> (String, Exp) {
    (input.to_owned(), Exp::Out(out.to_owned(), false))
}

fn same(input: &str) -> (String, Exp) {
    to(input, input)
}

fn susp(input: &str, out: &str) -> (String, Exp) {
    (input.to_owned(), Exp::Out(out.to_owned(), true))
}

fn rows() -> Vec<(String, Exp)> {
    use PathError::*;
    let seventeen = vec!["a"; 17].join("/");
    let sixteen = vec!["a"; 16].join("/");
    let long_ok = format!("{}.jpg", "a".repeat(300));
    let long_ok_out = format!("{}.jpg", "a".repeat(251));
    let mut v = vec![
        // Отказ (H1-H7).
        err("../../etc/passwd", DotComponent),
        err("a/../../b", DotComponent),
        err("./a", DotComponent),
        err("a/./b", DotComponent),
        err("...", DotComponent),
        err(". .", DotComponent),
        err(" ", DotComponent),
        err("a/ /b", DotComponent),
        err("/etc/passwd", Absolute),
        err("//server/share", Absolute),
        err("C:\\Windows\\x", Backslash),
        err("\\\\server\\share\\x", Backslash),
        err("\\\\?\\C:\\x", Backslash),
        err("a\\b", Backslash),
        err("C:/Windows/x", Drive),
        err("c:x", Drive),
        err("a//b", EmptyComponent),
        err("a/", EmptyComponent),
        err("", Empty),
        err("a\u{7}b", Control),
        err("a\nb", Control),
        err("a\u{85}b", Control),
        err("a\u{7F}b", Control),
        err(&seventeen, TooDeep),
        err(&"a".repeat(1025), TooLong),
        // Переписывание: устройства Windows.
        to("CON", "_CON"),
        to("con.txt", "_con.txt"),
        to("CON .txt", "_CON .txt"),
        to("NUL.tar.gz", "_NUL.tar.gz"),
        to("COM1", "_COM1"),
        to("com\u{B9}.txt", "_com\u{B9}.txt"),
        to("LPT\u{B3}", "_LPT\u{B3}"),
        to("COM0", "_COM0"),
        to("CONIN$", "_CONIN$"),
        to("aux ", "_aux"),
        to("nul.", "_nul"),
        same("COM10"),
        same("CONSOLE.txt"),
        to("x/CON/y.txt", "x/_CON/y.txt"),
        to("CLOC\u{212A}$", "_CLOCK$"),
        to("Desktop.ini", "_Desktop.ini"),
        to("autorun.inf", "_autorun.inf"),
        // Точки и пробелы по краям.
        to("evil.exe.", "evil.exe"),
        to("evil.exe   ", "evil.exe"),
        to("evil.exe . .", "evil.exe"),
        to(" lead.txt", "lead.txt"),
        to("x/ y.txt", "x/y.txt"),
        to(". x", "_ x"),
        to(".bashrc", "_bashrc"),
        to(".chervo-partial/x", "_chervo-partial/x"),
        // Недопустимые символы.
        to("file.txt:Zone.Identifier", "file.txt_Zone.Identifier"),
        to("file.txt::$DATA", "file.txt__$DATA"),
        to("a<b>c\"d|e?f*g", "a_b_c_d_e_f_g"),
        to("ab:c.txt", "ab_c.txt"),
        err("a:b.txt", Drive),
        to("a\u{FF0F}b", "a_b"),
        to("a\u{2215}b", "a_b"),
        // 8.3.
        to("PROGRA~1", "PROGRA_1"),
        same("draft~v2.doc"),
        to("a~1.txt", "a_1.txt"),
        // Невидимые и направление текста.
        susp("photo\u{202E}gpj.exe", "photo_gpj.exe"),
        susp("a\u{200B}b.txt", "a_b.txt"),
        susp("\u{FEFF}x.txt", "_x.txt"),
        same("\u{2764}\u{FE0F}.jpg"),
        same("\u{1F468}\u{200D}\u{1F469}"),
        susp(
            "\u{2764}\u{FE0F}\u{200D}\u{1F525}",
            "\u{2764}\u{FE0F}_\u{1F525}",
        ),
        susp("\u{FE0F}x", "_x"),
        // Длина.
        (long_ok, Exp::Out(long_ok_out, false)),
        // Юникод остаётся.
        same(
            "\u{424}\u{43E}\u{442}\u{43E}/\u{41E}\u{442}\u{43F}\u{443}\u{441}\u{43A} 2024/IMG_0001.JPG",
        ),
        same("\u{65E5}\u{672C}\u{8A9E}.txt"),
        // NFC.
        to("\u{438}\u{306}.txt", "\u{439}.txt"),
        same("\u{439}.txt"),
        // Допустимые пути.
        same("a.txt"),
        same("a/b/c.txt"),
        same(&sixteen),
    ];
    v.push(same("dir/file with spaces.txt"));
    v
}

#[test]
fn hostile_table() {
    let l = ReceiveLimits::default();
    let table = rows();
    println!(
        "hostile_table: os={} rows={}",
        std::env::consts::OS,
        table.len()
    );
    for (input, exp) in &table {
        let got = sanitize_path(input, &l);
        match exp {
            Exp::Err(kind) => {
                assert_eq!(got.map(|_| ()), Err(*kind), "input {input:?}");
            }
            Exp::Out(out, suspicious) => {
                let (p, flags) = got.unwrap_or_else(|e| panic!("input {input:?}: {e:?}"));
                assert_eq!(&p.display(), out, "input {input:?}");
                assert_eq!(flags.changed, input != out, "changed, input {input:?}");
                assert_eq!(flags.suspicious, *suspicious, "suspicious, input {input:?}");
                assert!(!flags.renamed_in_offer && !flags.long_path, "{input:?}");
                for c in p.components() {
                    assert!(is_portable_component(c), "component of {input:?}");
                }
            }
        }
    }
}

#[test]
fn sanitize_idempotent() {
    let l = ReceiveLimits::default();
    for (input, exp) in rows() {
        if let Exp::Out(out, _) = exp {
            let (p, flags) = sanitize_path(&out, &l).expect("output is sanitizable");
            assert_eq!(p.display(), out, "second pass changed {input:?}");
            assert!(!flags.changed && !flags.suspicious, "{input:?}");
        }
    }
}

#[test]
fn portable_component_matches_sanitize() {
    let l = ReceiveLimits::default();
    for (input, exp) in rows() {
        if input.contains('/') {
            continue;
        }
        if let Exp::Out(out, _) = exp {
            assert_eq!(portable_component(&input), Ok(out), "input {input:?}");
            assert_eq!(
                sanitize_path(&input, &l).map(|(p, _)| p.display()),
                portable_component(&input)
            );
        } else if let Exp::Err(PathError::Drive) = exp {
            // Для одного локального компонента двоеточие просто заменяется.
            assert!(portable_component(&input).is_ok(), "input {input:?}");
        }
    }
    assert_eq!(portable_component(""), Err(PathError::Empty));
    assert_eq!(portable_component("a/b"), Err(PathError::EmptyComponent));
    assert_eq!(portable_component("a\\b"), Err(PathError::Backslash));
    assert_eq!(portable_component(".."), Err(PathError::DotComponent));
    assert_eq!(portable_component("a\u{1}"), Err(PathError::Control));
    assert_eq!(
        portable_component(&"a".repeat(1025)),
        Err(PathError::TooLong)
    );
    assert_eq!(portable_component("c:x").as_deref(), Ok("c_x"));
}

#[test]
fn output_components_are_normal_on_this_os() {
    let l = ReceiveLimits::default();
    let root = std::env::temp_dir();
    for (input, exp) in rows() {
        let Exp::Out(_, _) = exp else { continue };
        let (p, _) = sanitize_path(&input, &l).expect("ok row");
        let joined = sanitize_relative_path(&root, &input, &l).expect("ok row");
        let rest = joined.strip_prefix(&root).expect("starts with root");
        let comps: Vec<Component<'_>> = rest.components().collect();
        assert_eq!(comps.len(), p.components().len(), "input {input:?}");
        assert!(
            comps.iter().all(|c| matches!(c, Component::Normal(_))),
            "input {input:?}"
        );
        assert!(joined.starts_with(Path::new(&root)));
    }
}

#[test]
fn small_limits_hold() {
    let l = ReceiveLimits {
        max_name_bytes: 12,
        max_path_bytes: 100,
        max_depth: 3,
        ..ReceiveLimits::default()
    };
    let (p, f) =
        sanitize_path("CONOUT$.verylongextension/aaaaaaaaaaaaaaaaaaaaaaa.txt", &l).expect("fits");
    assert!(f.changed);
    for c in p.components() {
        assert!(c.len() <= 12, "{c:?}");
        assert!(is_portable_component(c));
    }
    let again = sanitize_path(&p.display(), &l).expect("idempotent").0;
    assert_eq!(again, p);
    assert_eq!(
        sanitize_path("a/b/c/d", &l).map(|_| ()),
        Err(PathError::TooDeep)
    );
}
