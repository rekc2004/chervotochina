//! Готовые состояния модели для `--render-check`: по ним рисуется каждый экран (1-10) без узла,
//! ключей и файлов. Так CI на трёх ОС доказывает, что экраны рисуются; паника на любом экране
//! даёт ненулевой код выхода.

use std::path::PathBuf;

use chervo_core::{
    FailReason, FileKind, FriendStatus, InviteOutcome, KeyStoreKind, MapStatus, NatView, NodeError,
    NodeEvent, NodeWarning, PathKind, PauseReason, RootError, Side, SpaceView, TransferResult,
    TransferState,
};

use crate::main_model::{
    AddFriend, AddStage, AddrTokenDialog, Dialog, MainIntent, OfferUi, PasteDialog,
    RevocationDialog, Tab,
};
use crate::model::{ClockResult, Close, FriendEventKind, Intent, Model, Outcome, Page};
use crate::rows::{
    DiagRow, FileRow, FriendRow, Id, OfferRow, PickedPath, RetiredRow, RouterRow, SettingsRow,
    TransferRow,
};
use crate::settings_model::{ClockUi, SettingsIntent, UpnpUi};

fn friend(id: u32, name: &str, status: FriendStatus, online: bool) -> FriendRow {
    FriendRow {
        id: Id(id),
        name: name.to_owned(),
        status,
        online,
        auto_accept: false,
        key_problem: false,
        path: online.then_some(PathKind::Lan),
    }
}

fn offer(id: u32, name: &str, risky: bool, short: bool) -> OfferRow {
    OfferRow {
        id: Id(id),
        friend: "Маша".to_owned(),
        files: vec![
            FileRow {
                name: "фото/отпуск.jpg".to_owned(),
                size: 3_500_000,
                kind: FileKind::Safe,
                needs_question: false,
            },
            FileRow {
                name: name.to_owned(),
                size: 12_000_000,
                kind: if risky {
                    FileKind::ExecutableLike
                } else {
                    FileKind::Unknown
                },
                needs_question: true,
            },
        ],
        total: 15_500_000,
        space: SpaceView {
            needed: 20_000_000,
            available: Some(if short { 1_000_000 } else { 9_000_000_000 }),
            short,
        },
        needs_question: true,
        warnings: if risky {
            vec![
                chervo_core::texts::EXECUTABLE_TEXT,
                chervo_core::texts::DECEPTIVE_TEXT,
            ]
        } else {
            Vec::new()
        },
    }
}

fn transfer(id: u32, side: Side, state: TransferState) -> TransferRow {
    TransferRow {
        id: Id(id),
        friend: "Маша".to_owned(),
        side,
        state,
        done: 4_000_000,
        total: 10_000_000,
        pause: match state {
            TransferState::Paused(p) => Some(p),
            _ => None,
        },
        preparing: None,
        result: None,
        dest_root: (side == Side::Receiver).then(|| "D:/Приём/Маша".to_owned()),
    }
}

/// Открытый узел с богатым снимком: все состояния друзей, передач, предложений и настроек.
fn open_model(page: Page) -> Model {
    let mut m = Model::preview();
    m.node_open = true;
    m.page = page;
    let mut auto = friend(2, "Петя", FriendStatus::Active, false);
    auto.auto_accept = true;
    let mut broken = friend(6, "Оля", FriendStatus::Active, false);
    broken.key_problem = true;
    let mut preparing = transfer(13, Side::Sender, TransferState::Active);
    preparing.preparing = Some((2_000_000, 10_000_000));
    let mut done = transfer(14, Side::Receiver, TransferState::Finished);
    done.result = Some(TransferResult::Completed);
    let mut failed = transfer(15, Side::Sender, TransferState::Finished);
    failed.result = Some(TransferResult::Failed {
        reason: FailReason::Disconnected,
    });
    let mut cancelled = transfer(16, Side::Sender, TransferState::Finished);
    cancelled.result = Some(TransferResult::Cancelled { by_us: true });
    m.snapshot.friends = vec![
        friend(1, "Маша", FriendStatus::Active, true),
        auto,
        friend(3, "Коля", FriendStatus::Blocked, false),
        friend(4, "Вася", FriendStatus::RevokedByPeer, false),
        friend(5, "Старый друг", FriendStatus::Retired, false),
        broken,
    ];
    m.snapshot.transfers = vec![
        transfer(10, Side::Sender, TransferState::AwaitingAnswer),
        transfer(11, Side::Receiver, TransferState::Active),
        transfer(
            12,
            Side::Receiver,
            TransferState::Paused(PauseReason::Stalled),
        ),
        preparing,
        transfer(
            17,
            Side::Receiver,
            TransferState::Paused(PauseReason::DiskFull),
        ),
        transfer(18, Side::Receiver, TransferState::Paused(PauseReason::Io)),
        transfer(
            19,
            Side::Sender,
            TransferState::Paused(PauseReason::Disconnected),
        ),
        transfer(20, Side::Receiver, TransferState::AwaitingUser),
        done,
        failed,
        cancelled,
    ];
    m.snapshot.offers = vec![
        offer(20, "setup.exe", true, false),
        offer(21, "данные.bin", false, true),
    ];
    m.snapshot.active_transfers = 4;
    m.snapshot.settings = Some(SettingsRow {
        port: 50_000,
        receive_root: "D:/Приём".to_owned(),
        extra_roots: vec!["E:/Большой диск".to_owned()],
        min_free_percent: 5,
        manual_forward: Some(50_001),
        routers: vec![
            RouterRow {
                id: Id(0),
                permanent_ok: false,
                needs_permanent: false,
            },
            RouterRow {
                id: Id(1),
                permanent_ok: true,
                needs_permanent: false,
            },
        ],
        clock_offset_ms: 1500,
        ntp_servers: vec!["pool.ntp.org".to_owned(), "time.example".to_owned()],
        key_store: KeyStoreKind::CredentialManager,
        restart_needed: true,
    });
    m.snapshot.nat = Some(NatView::BehindCgnat);
    m.snapshot.mapping = Some(MapStatus::Mapped);
    m.snapshot.retired = vec![RetiredRow {
        id: Id(5),
        friend: "Старый друг".to_owned(),
        text: "ОТЗЫВ-1234567890".to_owned(),
    }];
    m.snapshot.diagnoses = vec![
        DiagRow {
            friend: Id(2),
            text: chervo_core::texts::CGNAT_TEXT,
            could_help: true,
            lan_hint: true,
        },
        DiagRow {
            friend: Id(6),
            text: chervo_core::texts::UNKNOWN_TEXT,
            could_help: false,
            lan_hint: false,
        },
    ];
    m
}

fn go(m: &mut Model, i: MainIntent) {
    m.update(Intent::Main(i));
}

/// Все экраны и их состояния.
pub fn all() -> Vec<Model> {
    let mut v: Vec<Model> = Vec::new();

    // экран 1: запуск и ошибки
    v.push(Model::start().0);
    v.push(Model::preview());
    for e in [
        NodeError::ReceiveRoot(RootError::OutsideProfile),
        NodeError::ReceiveRoot(RootError::NotDir),
        NodeError::AlreadyRunning,
        NodeError::KeyStoreLocked,
        NodeError::KeysLost,
        NodeError::RolledBack,
        NodeError::SettingsCorrupt,
        NodeError::PortInUse,
        NodeError::Io,
    ] {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::OpenFailed(e));
        v.push(m);
    }

    // экран 10: закрытие
    for c in [Close::Asking, Close::ShuttingDown] {
        let mut m = open_model(Page::Friends);
        m.close = c;
        v.push(m);
    }

    // экран 2: друзья и диалоги
    v.push(open_model(Page::Friends));
    let dialogs: Vec<Dialog> = vec![
        Dialog::Rename {
            friend: Id(1),
            text: "Маша".to_owned(),
        },
        Dialog::ConfirmRemove(Id(1)),
        Dialog::ConfirmRekey(Id(1)),
        Dialog::ConfirmRekeyAll,
        Dialog::Trust(Id(1)),
        Dialog::AddrToken(AddrTokenDialog {
            friend: Id(1),
            same_network: true,
            token: None,
            busy: false,
            error: None,
        }),
        Dialog::AddrToken(AddrTokenDialog {
            friend: Id(1),
            same_network: false,
            token: Some("CHERVO-ADDR-ABCDEFGH1234".to_owned()),
            busy: false,
            error: None,
        }),
        Dialog::PasteToken(PasteDialog {
            text: "вставленный текст".to_owned(),
            too_long: true,
            error: Some(chervo_core::texts::BAD_TOKEN_TEXT),
            busy: false,
        }),
        Dialog::Revocation(RevocationDialog {
            items: vec![
                ("Маша".to_owned(), "ОТЗЫВ-ABCDEF".to_owned()),
                ("Петя".to_owned(), "ОТЗЫВ-123456".to_owned()),
            ],
            rekey: true,
            failed: 1,
        }),
        Dialog::Revocation(RevocationDialog {
            items: vec![("Маша".to_owned(), "ОТЗЫВ-ABCDEF".to_owned())],
            rekey: false,
            failed: 0,
        }),
    ];
    for d in dialogs {
        let mut m = open_model(Page::Friends);
        m.dialog = d;
        v.push(m);
    }

    // экран 3: добавление друга
    let mut m = open_model(Page::AddFriend);
    v.push(open_model(Page::AddFriend));
    m.add = AddFriend {
        tab: Tab::Invite,
        same_network: true,
        manual_addr: "203.0.113.5:50000".to_owned(),
        error: Some(crate::texts::BAD_MANUAL_ADDR),
        ..AddFriend::default()
    };
    v.push(m);
    let mut m = open_model(Page::AddFriend);
    m.add = AddFriend {
        tab: Tab::Accept,
        paste: "приглашение".to_owned(),
        paste_too_long: true,
        ..AddFriend::default()
    };
    v.push(m);
    let mut m = open_model(Page::AddFriend);
    m.on_outcome(Outcome::InviteCreated(Ok((
        Id(1),
        "CHERVO1-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .to_owned(),
    ))));
    v.push(m);
    let mut m = open_model(Page::AddFriend);
    m.add.stage = AddStage::Waiting {
        invite: Id(2),
        token: None,
        qr: None,
    };
    v.push(m);
    let mut m = open_model(Page::AddFriend);
    m.on_outcome(Outcome::InviteSas {
        invite: Id(1),
        digits: "1234 5678".to_owned(),
        spoken: "1 2 3 4 5 6 7 8".to_owned(),
    });
    go(&mut m, MainIntent::SasNameEdited("Маша".to_owned()));
    v.push(m);
    for o in [
        InviteOutcome::Added,
        InviteOutcome::Declined,
        InviteOutcome::PeerUnreachable,
        InviteOutcome::Expired,
    ] {
        let mut m = open_model(Page::AddFriend);
        m.add.stage = AddStage::Waiting {
            invite: Id(1),
            token: None,
            qr: None,
        };
        m.on_outcome(Outcome::InviteFinished(o));
        v.push(m);
    }

    // экран 4: отправка
    v.push(open_model(Page::Send));
    let mut m = open_model(Page::Send);
    m.send.paths = vec![
        PickedPath {
            path: PathBuf::from("D:/Фото/отпуск.jpg"),
            is_dir: false,
            size: 3_500_000,
        },
        PickedPath {
            path: PathBuf::from("D:/Документы"),
            is_dir: true,
            size: 0,
        },
    ];
    m.send.friend = Some(Id(1));
    m.send.error = Some(crate::texts::SEND_NO_FILES);
    v.push(m);

    // экран 5: входящие
    v.push(open_model(Page::Offers));
    let mut m = open_model(Page::Offers);
    m.offer_ui.insert(
        Id(20),
        OfferUi {
            ack: true,
            busy: false,
        },
    );
    v.push(m);
    let mut m = open_model(Page::Offers);
    m.snapshot.offers.clear();
    v.push(m);

    // экран 6: передачи
    v.push(open_model(Page::Transfers));
    let mut m = open_model(Page::Transfers);
    m.snapshot.transfers.clear();
    v.push(m);

    // экран 7: диагностика
    v.push(open_model(Page::Diagnosis));
    for nat in [NatView::Public, NatView::Symmetric, NatView::Unknown] {
        let mut m = open_model(Page::Diagnosis);
        m.snapshot.nat = Some(nat);
        v.push(m);
    }

    // экран 8: настройки
    v.push(open_model(Page::Settings));
    let mut m = open_model(Page::Settings);
    go(
        &mut m,
        MainIntent::Settings(SettingsIntent::RootEdited("E:/общая".to_owned())),
    );
    m.settings_ui.root.outside_warning = true;
    m.settings_ui.root.error = Some(chervo_core::texts::ROOT_OUTSIDE_PROFILE_TEXT);
    m.settings_ui.min_free.error = Some(crate::texts::MIN_FREE_BAD);
    m.settings_ui.upnp = UpnpUi::Found;
    m.snapshot.mapping = Some(MapStatus::NeedPermanentConsent);
    if let Some(set) = m.snapshot.settings.as_mut() {
        set.routers[0].needs_permanent = true;
    }
    m.settings_ui.clock = ClockUi::Proposal(700_000);
    v.push(m);
    let mut m = open_model(Page::Settings);
    m.settings_ui.upnp = UpnpUi::Searching;
    m.settings_ui.clock = ClockUi::Syncing;
    v.push(m);
    let mut m = open_model(Page::Settings);
    m.settings_ui.upnp = UpnpUi::Message(crate::texts::UPNP_ALLOWED);
    m.settings_ui.clock = ClockUi::Message(crate::texts::CLOCK_APPLIED);
    m.snapshot.retired.clear();
    if let Some(s) = &mut m.snapshot.settings {
        s.routers.clear();
    }
    v.push(m);

    // экран 9: уведомления
    let mut m = open_model(Page::Friends);
    for e in [
        NodeEvent::Warning(NodeWarning::AnchorNotUpdated),
        NodeEvent::Warning(NodeWarning::RootUnavailable),
        NodeEvent::Internal,
        NodeEvent::OwnAddressChanged,
        NodeEvent::MappingChanged {
            status: MapStatus::Mapped,
        },
    ] {
        m.on_outcome(Outcome::Event(e));
    }
    for kind in [
        FriendEventKind::KeyProblem,
        FriendEventKind::ClockSkew,
        FriendEventKind::Unreachable {
            text: chervo_core::texts::UNKNOWN_TEXT,
            lan_hint: true,
        },
    ] {
        m.on_outcome(Outcome::FriendEvent {
            name: "Маша".to_owned(),
            kind,
        });
    }
    m.on_outcome(Outcome::AutoAccepted);
    m.on_outcome(Outcome::ClockSynced(Ok(ClockResult::Applied(0))));
    v.push(m);
    v
}
