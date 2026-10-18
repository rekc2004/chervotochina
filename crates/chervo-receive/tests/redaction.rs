#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
//! Редакция вывода приёма (этап 17, B3, решение 1c; BRIEF 7, T4): `Debug` и `Display` типов
//! приёма не содержат имён файлов (в том числе очищенных), путей папки приёма и служебной
//! папки, адресов. Ошибки фиксированные.

mod common;
#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::path::PathBuf;
use std::sync::Arc;

use chervo_friends::Permission;
use chervo_receive::{
    AcceptIntoError, ChooseRootError, DiskSpace, PathError, ReceiveConfig, ReceiveDecision,
    ReceiveLimits, ReceivePlacement, ReceivePolicy, ReceiveRoot, RootError, SpaceCheck,
    SpaceShortfall, classify, plan_offer_for_root, sanitize_path,
};
use chervo_transfer::{OfferView, TransferError, TransferId, TransferKey};
use common::{Env, offered};
use redact_kit::{Needles, Out, assert_fixed_text, check};

const MARK: &str = "RCVMARK";

type SpaceFn = dyn Fn(&std::path::Path) -> Option<DiskSpace> + Send + Sync;

fn all_path_errors() -> Vec<PathError> {
    use PathError::*;
    vec![
        Empty,
        TooLong,
        Control,
        Backslash,
        Absolute,
        Drive,
        TooDeep,
        EmptyComponent,
        DotComponent,
        TooManyFiles,
        TooLarge,
        BadLimits,
    ]
}

fn all_root_errors() -> Vec<RootError> {
    use RootError::*;
    vec![
        NotAbsolute,
        NotDir,
        Shared,
        PartialNotPrivate,
        InsidePartial,
        Io(std::io::ErrorKind::NotFound),
        Io(std::io::ErrorKind::PermissionDenied),
    ]
}

#[test]
fn receive_types_hide_names_and_paths() {
    let env = Env::new("redact");
    let root_text = env.root.root().to_string_lossy().into_owned();
    let partial_text = env.root.partial_dir().to_string_lossy().into_owned();

    let files = offered(&[
        (&format!("{MARK}-dir/{MARK}-file.txt"), 10),
        (&format!("{MARK}.exe"), 20),
        (&format!("{MARK}/../{MARK}"), 1),
    ]);
    let limits = ReceiveLimits::default();
    let plan = plan_offer_for_root(&files[..2], &limits, &env.root).unwrap();
    let (safe, safe_flags) =
        sanitize_path(&format!("{MARK}-dir/{MARK}-file.txt"), &limits).unwrap();

    // место: общий том 100 байт, свободно 1, чтобы получить SpaceShortfall
    let probe: Arc<SpaceFn> = Arc::new(|_p: &std::path::Path| {
        Some(DiskSpace {
            total_bytes: 100,
            available_bytes: 1,
        })
    });
    let policy = ReceivePolicy::with_space_probe(env.root.clone(), &env.cfg, probe.clone());
    let place = ReceivePlacement::new(env.root.clone(), &env.cfg).with_space_probe(probe);
    let key = TransferKey {
        pair: chervo_identity::PairId::from_bytes([0x66; 16]),
        id: TransferId([9; 16]),
    };
    let view = OfferView {
        key,
        files: files[..2].to_vec(),
        total_size: 30,
        inbound: Vec::new(),
    };
    let decision = policy.evaluate(Permission::Ask, &view);
    let ReceiveDecision::InsufficientSpace(shortfall) = decision.clone() else {
        panic!("ожидалось InsufficientSpace: {decision:?}");
    };
    let check_result = policy.space_check(&view);
    assert!(matches!(check_result, SpaceCheck::Short(_)));

    let mut out = Out::new();
    out.dbg("ReceiveConfig", &env.cfg);
    out.dbg("ReceiveRoot", &env.root);
    out.dbg("ReceivePlacement", &place);
    out.dbg("ReceivePolicy", &policy);
    out.dbg("ReceiveLimits", &limits);
    out.dbg("SafeRelPath", &safe);
    out.dbg("OfferPlan", &plan);
    for f in &plan.files {
        out.dbg("PlannedFile", f);
        out.dbg("PlannedFile.flags", &f.flags);
        out.dbg("PlannedFile.kind", &f.kind);
    }
    out.dbg("ReceiveDecision", &decision);
    out.dbg("SpaceShortfall", &shortfall);
    out.dbg("SpaceCheck", &check_result);
    out.dbg("classify", &classify(&safe));
    out.dbg("NameFlags", &safe_flags);
    out.dbg(
        "hostile plan",
        &plan_offer_for_root(&files[2..], &limits, &env.root).map(|_| ()),
    );
    out.dbg(
        "hostile sanitize",
        &sanitize_path(&format!("{MARK}/../{MARK}"), &limits).map(|_| ()),
    );
    for e in all_path_errors() {
        out.err("PathError", &e);
    }
    for e in all_root_errors() {
        out.err("RootError", &e);
    }
    for e in [
        ChooseRootError::Plan(PathError::TooLong),
        ChooseRootError::Insufficient(shortfall.clone()),
    ] {
        out.dbg("ChooseRootError", &e);
    }
    for e in [
        AcceptIntoError::NoSuchOffer,
        AcceptIntoError::Root(ChooseRootError::Insufficient(shortfall.clone())),
        AcceptIntoError::Transfer(TransferError::Busy),
    ] {
        out.dbg("AcceptIntoError", &e);
    }
    let bad_root: PathBuf = PathBuf::from(format!("relative/{MARK}-dir"));
    out.dbg(
        "ReceiveRoot::open(relative)",
        &ReceiveRoot::open(&ReceiveConfig::new(bad_root)).map(|_| ()),
    );

    let mut n = Needles::new();
    n.add("name mark", MARK);
    n.add("receive root", root_text);
    n.add("partial dir", partial_text);
    n.add("tmp dir", "chervo-rcv-");
    n.bytes("pair", key.pair.as_bytes());
    check(&out, &n);
}

#[test]
fn receive_errors_have_fixed_text() {
    for e in all_path_errors() {
        assert_fixed_text("PathError display", &e.to_string());
        assert_fixed_text("PathError debug", &format!("{e:?}"));
    }
    for e in all_root_errors() {
        assert_fixed_text("RootError display", &e.to_string());
    }
    // `Io(kind)` печатает только вид ошибки ОС, без пути
    assert_eq!(
        format!("{:?}", RootError::Io(std::io::ErrorKind::NotFound)),
        "Io(NotFound)"
    );
    let _: Option<SpaceShortfall> = None;
}
