//! Готовые состояния модели для `--render-check`: по ним рисуется каждый экран (1-10) без узла,
//! ключей и файлов. Так CI на трёх ОС доказывает, что экраны рисуются; паника на любом экране
//! даёт ненулевой код выхода.

use std::path::PathBuf;

use chervo_core::update::{
    CheckError, EmbeddedKey, FileVerdict, Freshness, KeyId, KeyRole, ReleaseCheck, Target,
    UpdateConsent, UpdateError, UpdateStatus, Version,
};
use chervo_core::{
    FailReason, FileKind, FriendStatus, InviteOutcome, KeyStoreKind, LanMode, LanStatus, MapStatus,
    NatView, NodeError, NodeEvent, NodeWarning, PathKind, PauseReason, RootError, Side, SpaceView,
    TransferResult, TransferState,
};

use crate::main_model::{
    AddFriend, AddStage, AddrTokenDialog, Dialog, MainIntent, OfferUi, PasteDialog,
    RevocationDialog, Tab,
};
use crate::model::{ClockResult, Close, FriendEventKind, Intent, Model, Outcome, Page};
use crate::rows::{
    DiagRow, FileRow, FriendRow, Id, LanRow, OfferRow, PickedPath, RetiredRow, RouterRow,
    SettingsRow, TransferRow,
};
use crate::settings_model::{ClockUi, SettingsIntent, UpnpUi};
use crate::update_model::{KeyRow, UpdateIntent};

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
        update_consent: UpdateConsent::Enabled,
        lan: LanRow {
            mode: LanMode::Listen,
            status: Some(LanStatus::Listening),
            addrs: vec![
                std::net::Ipv4Addr::new(172, 18, 0, 1),
                std::net::Ipv4Addr::new(192, 168, 1, 10),
            ],
        },
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

fn upd(m: &mut Model, i: UpdateIntent) {
    m.update(Intent::Main(MainIntent::Update(i)));
}

fn updates_page(consent: UpdateConsent) -> Model {
    let mut m = open_model(Page::Updates);
    if let Some(s) = m.snapshot.settings.as_mut() {
        s.update_consent = consent;
    }
    m.update.keys = vec![
        KeyRow {
            role: crate::texts::UPD_ROLE_PRIMARY,
            id: "0123456789ABCDEF".to_owned(),
        },
        KeyRow {
            role: crate::texts::UPD_ROLE_BACKUP,
            id: "FEDCBA9876543210".to_owned(),
        },
    ];
    m
}

/// Форма сверки с выбранными манифестом, подписью и файлами.
fn verify_form(files: &[&str]) -> Model {
    let mut m = updates_page(UpdateConsent::Enabled);
    upd(
        &mut m,
        UpdateIntent::PickManifest(PathBuf::from("D:/Загрузки/chervo-release.txt")),
    );
    upd(
        &mut m,
        UpdateIntent::PickSignature(PathBuf::from("D:/Загрузки/chervo-release.txt.minisig")),
    );
    upd(
        &mut m,
        UpdateIntent::AddFiles(
            files
                .iter()
                .map(|f| PathBuf::from(format!("D:/Загрузки/{f}")))
                .collect(),
        ),
    );
    m
}

fn verdict(name: &str, freshness: Freshness) -> Result<FileVerdict, UpdateError> {
    Ok(FileVerdict {
        name: name.to_owned(),
        target: Target::WindowsX86_64,
        freshness,
    })
}

fn release(files: Vec<Result<FileVerdict, UpdateError>>) -> ReleaseCheck {
    ReleaseCheck {
        version: Version {
            major: 0,
            minor: 2,
            patch: 0,
        },
        signer: EmbeddedKey {
            role: KeyRole::Primary,
            key_id: KeyId([1, 35, 69, 103, 137, 171, 205, 239]),
        },
        files,
    }
}

fn verified(m: &mut Model, r: Result<ReleaseCheck, UpdateError>) {
    upd(m, UpdateIntent::Verify);
    m.on_outcome(Outcome::ReleaseVerified(r));
}

/// Экран 11: «Обновления» (этап 19г-2).
fn update_states(v: &mut Vec<Model>) {
    let newer = Version {
        major: 9,
        minor: 8,
        patch: 7,
    };
    // карточка согласия поверх обычного окна
    let mut m = open_model(Page::Friends);
    if let Some(s) = m.snapshot.settings.as_mut() {
        s.update_consent = UpdateConsent::NotAsked;
    }
    v.push(m);
    // страница при каждом ответе
    for c in [
        UpdateConsent::NotAsked,
        UpdateConsent::Enabled,
        UpdateConsent::Disabled,
    ] {
        v.push(updates_page(c));
    }
    // идёт проверка
    let mut m = updates_page(UpdateConsent::Enabled);
    upd(&mut m, UpdateIntent::CheckNow);
    v.push(m);
    // карточка новой версии, затем с диалогом ссылки
    let mut m = open_model(Page::Friends);
    m.on_outcome(Outcome::UpdateChecked {
        manual: false,
        result: Ok(UpdateStatus::Newer(newer)),
    });
    v.push(m);
    let mut m = open_model(Page::Updates);
    m.on_outcome(Outcome::UpdateChecked {
        manual: true,
        result: Ok(UpdateStatus::Newer(newer)),
    });
    upd(&mut m, UpdateIntent::LinkOpen);
    v.push(m);
    // ручные итоги
    let manual: [Result<UpdateStatus, CheckError>; 4] = [
        Ok(UpdateStatus::UpToDate),
        Err(CheckError::Network),
        Err(CheckError::BadResponse),
        Err(CheckError::NoTrustedKeys),
    ];
    for result in manual {
        let mut m = updates_page(UpdateConsent::Enabled);
        upd(&mut m, UpdateIntent::CheckNow);
        m.on_outcome(Outcome::UpdateChecked {
            manual: true,
            result,
        });
        v.push(m);
    }
    let mut m = updates_page(UpdateConsent::Enabled);
    upd(&mut m, UpdateIntent::CheckNow);
    m.on_outcome(Outcome::UpdateSkipped);
    v.push(m);
    // форма сверки: заполненная и занятая
    v.push(verify_form(&["chervotochina-0.2.0-windows-x86_64.exe"]));
    let mut m = verify_form(&["chervotochina-0.2.0-windows-x86_64.exe"]);
    upd(&mut m, UpdateIntent::Verify);
    v.push(m);
    // успехи: новее, та же версия, откат разрешён (предупреждение)
    for fresh in [Freshness::Newer, Freshness::Same, Freshness::OlderAllowed] {
        let mut m = verify_form(&["chervotochina-0.2.0-windows-x86_64.exe"]);
        if fresh == Freshness::OlderAllowed {
            upd(&mut m, UpdateIntent::AllowDowngrade(true));
        }
        let name = "chervotochina-0.2.0-windows-x86_64.exe";
        verified(&mut m, Ok(release(vec![verdict(name, fresh)])));
        v.push(m);
    }
    // список не прошёл проверку подписи, нет вшитых ключей
    for e in [UpdateError::BadSignature, UpdateError::NoTrustedKeys] {
        let mut m = verify_form(&["chervotochina-0.2.0-windows-x86_64.exe"]);
        verified(&mut m, Err(e));
        v.push(m);
    }
    // по строке на каждую ошибку файла
    let mut m = verify_form(&["a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin"]);
    let running = Version {
        major: 2,
        minor: 0,
        patch: 0,
    };
    let errors = vec![
        Err(UpdateError::NotInManifest),
        Err(UpdateError::WrongTarget {
            expected: Some(Target::WindowsX86_64),
            found: Target::MacosAarch64,
        }),
        Err(UpdateError::SizeMismatch),
        Err(UpdateError::Downgrade {
            running,
            offered: newer,
        }),
        Err(UpdateError::TooLarge),
        Err(UpdateError::Io(std::io::ErrorKind::NotFound)),
    ];
    verified(&mut m, Ok(release(errors)));
    v.push(m);
    // ключи не вшиты
    let mut m = updates_page(UpdateConsent::Enabled);
    m.update.keys.clear();
    v.push(m);
    // имена с управляющими символами и символами направления письма
    let mut m = verify_form(&["evil\u{202E}gpj.exe\u{7}\u{2066}"]);
    let hostile = "x\u{202E}y\u{2066}z\u{7}.exe";
    verified(&mut m, Ok(release(vec![verdict(hostile, Freshness::Same)])));
    v.push(m);
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

    // экран 8, раздел «Локальная сеть»: режимы и все состояния службы поиска (13в)
    lan_states(&mut v);

    // экран 11: обновления
    update_states(&mut v);

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

/// Раздел «Локальная сеть»: каждое состояние службы, каждый режим, адреса и их отсутствие.
fn lan_states(v: &mut Vec<Model>) {
    let a = std::net::Ipv4Addr::new;
    let cases: [(LanMode, Option<LanStatus>, Vec<std::net::Ipv4Addr>); 9] = [
        (LanMode::Off, None, Vec::new()),
        (LanMode::Off, Some(LanStatus::Off), Vec::new()),
        (
            LanMode::Listen,
            Some(LanStatus::Listening),
            vec![a(192, 168, 1, 10)],
        ),
        (
            LanMode::Announce,
            Some(LanStatus::Announcing),
            vec![
                a(172, 18, 0, 1),
                a(192, 168, 1, 10),
                a(10, 0, 0, 5),
                a(192, 168, 56, 1),
            ],
        ),
        (LanMode::Listen, Some(LanStatus::NoPrivateRoute), Vec::new()),
        (LanMode::Announce, Some(LanStatus::PortBusy), Vec::new()),
        (LanMode::Listen, Some(LanStatus::Failed), Vec::new()),
        // VPN: адрес по умолчанию в туннеле, домашний интерфейс найден опросом маршрутов
        (
            LanMode::Listen,
            Some(LanStatus::Listening),
            vec![a(172, 18, 0, 1), a(192, 168, 31, 10)],
        ),
        (
            LanMode::Announce,
            Some(LanStatus::Announcing),
            vec![a(10, 1, 2, 3)],
        ),
    ];
    for (mode, status, addrs) in cases {
        let mut m = open_model(Page::Settings);
        if let Some(set) = m.snapshot.settings.as_mut() {
            set.lan = LanRow {
                mode,
                status,
                addrs,
            };
        }
        v.push(m);
    }
    // перед открытием настроек узел ещё не отдал снимок
    let mut m = open_model(Page::Settings);
    m.snapshot.settings = None;
    v.push(m);
}

#[cfg(test)]
mod tests {
    #[test]
    fn lan_states_cover_every_status_and_mode() {
        use chervo_core::{LanMode, LanStatus};
        let mut v = Vec::new();
        super::lan_states(&mut v);
        let rows: Vec<_> = v
            .iter()
            .filter_map(|m| m.snapshot.settings.as_ref().map(|s| s.lan.clone()))
            .collect();
        for st in [
            LanStatus::Off,
            LanStatus::NoPrivateRoute,
            LanStatus::PortBusy,
            LanStatus::Listening,
            LanStatus::Announcing,
            LanStatus::Failed,
        ] {
            assert!(rows.iter().any(|r| r.status == Some(st)), "{st:?}");
        }
        for mode in [LanMode::Off, LanMode::Listen, LanMode::Announce] {
            assert!(rows.iter().any(|r| r.mode == mode), "{mode:?}");
        }
        assert!(rows.iter().any(|r| r.status.is_none()));
        assert!(rows.iter().any(|r| r.addrs.len() >= 4));
    }

    #[test]
    fn update_states_are_at_least_20() {
        let mut v = Vec::new();
        super::update_states(&mut v);
        assert!(v.len() >= 20, "{}", v.len());
    }
}
