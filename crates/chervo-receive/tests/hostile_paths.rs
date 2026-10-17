//! Таблица враждебных и переписываемых имён. Без файловой системы, ожидания одинаковы на
//! всех ОС (`std::env::consts::OS` печатается для сверки логов CI).

use std::path::{Component, Path};

use chervo_receive::{
    PathError, ReceiveLimits, is_portable_component, portable_component, sanitize_path,
    sanitize_relative_path,
};

mod common;

use common::rows::{Exp, rows};

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
