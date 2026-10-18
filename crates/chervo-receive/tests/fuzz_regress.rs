//! Регрессии находок libFuzzer: входы из `tests/fixtures`. Принятый путь обязан укладываться во
//! все пределы (в том числе `max_path_bytes` и `max_name_bytes`) и быть идемпотентным.

use chervo_receive::{ReceiveLimits, is_portable_component, sanitize_path};

fn limit_sets() -> [(&'static str, ReceiveLimits); 2] {
    [
        ("default", ReceiveLimits::default()),
        (
            "small",
            ReceiveLimits {
                max_name_bytes: 14,
                max_path_bytes: 90,
                max_depth: 5,
                ..ReceiveLimits::default()
            },
        ),
    ]
}

/// Свойства принятого пути: пределы на ИТОГОВОМ результате и идемпотентность.
fn assert_properties(input: &str, name: &str, l: &ReceiveLimits) {
    let Ok((p, _)) = sanitize_path(input, l) else {
        return;
    };
    let shown = p.display();
    assert!(
        shown.len() <= usize::from(l.max_path_bytes),
        "{name}: output {} bytes > max_path_bytes {}",
        shown.len(),
        l.max_path_bytes
    );
    assert!(p.components().len() <= usize::from(l.max_depth), "{name}");
    for c in p.components() {
        assert!(c.len() <= usize::from(l.max_name_bytes), "{name}: {c:?}");
        assert!(is_portable_component(c), "{name}: {c:?}");
    }
    let (again, f2) = sanitize_path(&shown, l)
        .unwrap_or_else(|e| panic!("{name}: second pass must succeed: {e:?} ({shown:?})"));
    assert_eq!(again, p, "{name}: not idempotent");
    assert!(!f2.changed && !f2.suspicious, "{name}");
}

#[test]
fn fuzz_sanitizer_toolong_1_fixture() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fuzz-sanitizer-toolong-1.bin"
    ))
    .expect("fixture");
    let input = String::from_utf8_lossy(&data);
    for (name, l) in limit_sets() {
        assert_properties(&input, name, &l);
    }
}

/// Минимальные случаи: правка удлиняет путь (префикс `_` у зарезервированного имени, NFC).
#[test]
fn growing_rewrites_never_exceed_path_limit() {
    for (name, l) in limit_sets() {
        let max = usize::from(l.max_path_bytes);
        let depth = usize::from(l.max_depth);
        // Последний компонент `CON` растёт на `_`; вход ровно на пределе.
        let head = "a/".repeat(depth.min(3) - 1);
        let tail = "b".repeat(max - head.len() - 4);
        assert_properties(&format!("{head}{tail}/CON"), name, &l);
        assert_properties(&format!("{head}{tail}.CON"), name, &l);
        // Каждый компонент `CON.xx..` получает префикс `_`: итог на `depth` байт длиннее входа,
        // а вход укладывается в `max_path_bytes`.
        let n = ((max + 1) / depth - 1).min(usize::from(l.max_name_bytes) - 1);
        let comp = format!("CON.{}", "x".repeat(n - 4));
        let many = vec![comp; depth].join("/");
        assert!(many.len() <= max);
        assert_properties(&many, name, &l);
        // NFC удлиняет: U+0958 (3 байта) даёт 6.
        assert_properties(&"\u{958}".repeat(max / 3), name, &l);
    }
}
