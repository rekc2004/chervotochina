#![no_main]
//! Receive path sanitizer. Same entry point and invariants as `fuzz_smoke_sanitizer` (default and a
//! small limit set): an accepted path has 1..=max_depth components, each portable and within the
//! byte limit, and a second pass over its display form changes nothing.

use chervo_receive::{is_portable_component, sanitize_path, ReceiveLimits};
use libfuzzer_sys::fuzz_target;

fn check(input: &str, l: &ReceiveLimits) {
    let Ok((p, _flags)) = sanitize_path(input, l) else {
        return;
    };
    let comps = p.components();
    assert!(!comps.is_empty() && comps.len() <= usize::from(l.max_depth));
    for c in comps {
        assert!(is_portable_component(c), "{input:?} -> {c:?}");
        assert!(c.len() <= usize::from(l.max_name_bytes));
        assert!(!c.is_empty() && !c.contains('/') && !c.contains('\\'));
    }
    let shown = p.display();
    let (again, f2) = sanitize_path(&shown, l).expect("second pass must succeed");
    assert_eq!(again, p, "not idempotent: {input:?} -> {shown:?}");
    assert!(!f2.changed && !f2.suspicious);
}

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let default = ReceiveLimits::default();
    let small = ReceiveLimits {
        max_name_bytes: 14,
        max_path_bytes: 90,
        max_depth: 5,
        ..ReceiveLimits::default()
    };
    check(&input, &default);
    check(&input, &small);
});
