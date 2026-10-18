#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Редакция вывода передач (этап 17, B3, решение 1c; BRIEF 7, T4): `Debug` и `Display` типов с
//! именами, путями и `PairId` не содержат имён файлов, путей, `PairId`. События содержат
//! только ключ передачи и числа. Ошибки фиксированные. У `OfferedFile` нет `Debug` вовсе.
//! `RecvState`, `NamesFile` проверены в крейте (`src/tests/redaction.rs`).

#[path = "../../chervo-core/tests/support/redact_kit.rs"]
mod redact_kit;

use std::path::PathBuf;

use chervo_friends::Permission;
use chervo_identity::PairId;
use chervo_transfer::{
    BlockErrCode, CancelReason, CompletedFile, FailReason, FileErrCode, FileFailure,
    GeneratedNames, InboundReservation, OfferView, OfferedFile, PauseReason, PlaceError, Placed,
    ProtocolError, Side, SourceFile, StateError, TransferConfig, TransferError, TransferEvent,
    TransferId, TransferKey, TransferState, TransferStatus, UntrustedName, Verdict, block_len,
    file_root, layout, leaf_hash,
};
use redact_kit::{Needles, NoDebug, Out, Probe, assert_fixed_text, check};

const NAME: &str = "XFERMARK-secret.txt";
const DIR: &str = "XFERMARKDIR";

fn root_of(data: &[u8]) -> chervo_transfer::FileRoot {
    let size = data.len() as u64;
    let l = layout(size).unwrap();
    let leaves: Vec<_> = (0..l.block_count)
        .map(|i| {
            let len = block_len(size, l, i).unwrap() as usize;
            let start = i as usize * l.block_size as usize;
            leaf_hash(i, &data[start..start + len])
        })
        .collect();
    file_root(size, l, &leaves).unwrap()
}

fn all_protocol_errors() -> Vec<ProtocolError> {
    use ProtocolError::*;
    vec![
        TooLong,
        Malformed,
        UnknownType,
        BadVersion,
        TooLarge,
        BadName,
        UnsupportedCodec,
        Unexpected,
        TimedOut,
        Closed,
    ]
}

fn all_state_errors() -> Vec<StateError> {
    use StateError::*;
    vec![
        TooLong,
        Truncated,
        BadMagic,
        BadChecksum,
        Malformed,
        HashMismatch,
    ]
}

fn all_transfer_errors() -> Vec<TransferError> {
    use TransferError::*;
    vec![
        NotFriend,
        Busy,
        BadName,
        TooLarge,
        TooManyFiles,
        NoSuchTransfer,
        WrongState,
        Io,
        Shutdown,
    ]
}

#[test]
fn transfer_types_hide_names_paths_and_pairs() {
    let pair = PairId::from_bytes([0xB7; 16]);
    let key = TransferKey {
        pair,
        id: TransferId([0x31; 16]),
    };
    let src_path = PathBuf::from(format!("/home/user/{DIR}/{NAME}"));
    let partial = PathBuf::from(format!("/home/user/{DIR}/.chervo-partial"));
    let source = SourceFile {
        path: src_path.clone(),
        name: format!("{DIR}/{NAME}"),
    };
    let cfg = TransferConfig::new(partial.clone());
    let name = UntrustedName::new(&format!("{DIR}/{NAME}")).unwrap();
    let offer = OfferView {
        key,
        files: vec![OfferedFile {
            name: UntrustedName::new(NAME).unwrap(),
            size: 10,
        }],
        total_size: 10,
        inbound: vec![InboundReservation {
            partial_dir: partial.clone(),
            outstanding: 5,
        }],
    };
    let data = b"0123456789".to_vec();
    let completed = CompletedFile::new_for_test(
        key,
        0,
        UntrustedName::new(NAME).unwrap(),
        data.len() as u64,
        root_of(&data),
        partial.join("0.placing"),
    );
    let placed = Placed {
        path: src_path.clone(),
    };
    let generated = GeneratedNames {
        dest_dir: partial.clone(),
    };

    let mut out = Out::new();
    out.dbg("SourceFile", &source);
    out.dbg("TransferConfig", &cfg);
    out.dbg("UntrustedName", &name);
    out.dbg("OfferView", &offer);
    out.dbg("InboundReservation", &offer.inbound[0]);
    out.dbg("CompletedFile", &completed);
    out.dbg("Placed", &placed);
    out.dbg("GeneratedNames", &generated);
    out.dbg("TransferKey", &key);
    // все события: только ключ и числа
    let events = vec![
        TransferEvent::OfferReceived { key },
        TransferEvent::OfferAnswered {
            key,
            accepted: true,
        },
        TransferEvent::Started { key },
        TransferEvent::Progress {
            key,
            done: 1,
            total: 2,
        },
        TransferEvent::Verifying { key },
        TransferEvent::Preparing {
            key,
            hashed: 1,
            total: 2,
        },
        TransferEvent::FileReceived { key, index: 3 },
        TransferEvent::FileDelivered { key, index: 3 },
        TransferEvent::FileFailed {
            key,
            index: 3,
            reason: FileFailure::PlaceFailed,
        },
        TransferEvent::Paused {
            key,
            reason: PauseReason::DiskFull,
        },
        TransferEvent::Resumed { key },
        TransferEvent::Completed { key },
        TransferEvent::Cancelled {
            key,
            by: Side::Receiver,
        },
        TransferEvent::Failed {
            key,
            reason: FailReason::Limits,
        },
    ];
    for e in &events {
        out.dbg("TransferEvent", e);
    }
    out.dbg(
        "TransferStatus",
        &TransferStatus {
            side: Side::Sender,
            state: TransferState::Paused(PauseReason::Io),
            done: 1,
            total: 2,
        },
    );
    out.dbg("Permission", &Permission::Ask);
    out.dbg(
        "Verdict",
        &[
            Verdict::Accept,
            Verdict::Decline,
            Verdict::Busy,
            Verdict::Expired,
            Verdict::Limits,
        ],
    );
    out.dbg("CancelReason", &CancelReason::User);
    out.dbg("FileErrCode", &FileErrCode::ReadError);
    out.dbg("BlockErrCode", &BlockErrCode::ReadError);
    for e in all_protocol_errors() {
        out.err("ProtocolError", &e);
    }
    for e in all_state_errors() {
        out.err("StateError", &e);
    }
    for e in all_transfer_errors() {
        out.err("TransferError", &e);
    }
    for e in [
        PlaceError::Refused,
        PlaceError::Io(std::io::ErrorKind::NotFound),
        PlaceError::Io(std::io::ErrorKind::PermissionDenied),
    ] {
        out.err("PlaceError", &e);
    }
    out.dbg(
        "UntrustedName::new(empty)",
        &UntrustedName::new("").map(|_| ()),
    );

    let mut n = Needles::new();
    n.add("file name", "XFERMARK");
    n.add("dir name", DIR);
    n.add("home path", "/home/user");
    n.bytes("pair", pair.as_bytes());
    check(&out, &n);
}

#[test]
fn transfer_name_records_have_no_debug() {
    assert!(!Probe::<OfferedFile>::new().has_debug());
    assert!(Probe::<UntrustedName>::new().has_debug());
    assert!(Probe::<OfferView>::new().has_debug());
}

#[test]
fn transfer_errors_have_fixed_text() {
    for e in all_protocol_errors() {
        assert_fixed_text("ProtocolError display", &e.to_string());
        assert_fixed_text("ProtocolError debug", &format!("{e:?}"));
    }
    for e in all_state_errors() {
        assert_fixed_text("StateError display", &e.to_string());
        assert_fixed_text("StateError debug", &format!("{e:?}"));
    }
    for e in all_transfer_errors() {
        assert_fixed_text("TransferError display", &e.to_string());
        assert_fixed_text("TransferError debug", &format!("{e:?}"));
    }
    assert_fixed_text("PlaceError::Refused", &PlaceError::Refused.to_string());
    assert_fixed_text(
        "PlaceError::Io",
        &PlaceError::Io(std::io::ErrorKind::NotFound).to_string(),
    );
}
