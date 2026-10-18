#![no_main]
//! Receive plan for an offer. Same entry points as `fuzz_smoke_plan`: input is split on '\n' into up
//! to 64 names; names that sanitize are offered (size 1). Property: planning an offer whose names all
//! sanitize never fails and keeps one planned file per offered file.

use chervo_receive::{plan_offer, sanitize_path, ReceiveLimits};
use chervo_transfer::{OfferedFile, UntrustedName};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let l = ReceiveLimits::default();
    let text = String::from_utf8_lossy(data);
    let mut files = Vec::new();
    for line in text.split('\n').take(64) {
        if sanitize_path(line, &l).is_err() {
            continue;
        }
        let Ok(name) = UntrustedName::new(line) else {
            continue;
        };
        files.push(OfferedFile { name, size: 1 });
    }
    if files.is_empty() {
        return;
    }
    let plan = plan_offer(&files, &l).expect("all names sanitize");
    assert_eq!(plan.files.len(), files.len());
});
