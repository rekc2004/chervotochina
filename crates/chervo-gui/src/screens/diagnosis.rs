//! Экран 7: диагностика. Причина по каждому другу без соединения (текст из ядра), сводка по
//! вашей сети, кнопка «Соединить». Сервер-посредник: только честный текст «появится в
//! следующей версии»; кнопки согласия, поля адреса сервера и любого пути к серверу нет.

use chervo_core::texts as core_texts;
use chervo_core::{FriendStatus, NatView};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::screens::common::warn;
use crate::texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

/// Короткая сводка о вашей сети по `NatView`; длинные объяснения берутся из ядра.
pub fn nat_text(n: NatView) -> &'static str {
    match n {
        NatView::NoIpv4 => texts::NAT_NO_IPV4,
        NatView::Public => texts::NAT_PUBLIC,
        NatView::PortMapped => texts::NAT_MAPPED,
        NatView::BehindCgnat => core_texts::CGNAT_TEXT,
        NatView::DoubleNat => core_texts::DOUBLE_NAT_TEXT,
        NatView::Conflicting => texts::NAT_CONFLICT,
        NatView::Symmetric => core_texts::SYMMETRIC_TEXT,
        NatView::Eim => texts::NAT_EIM,
        NatView::ManualForward => texts::NAT_MANUAL,
        _ => core_texts::UNKNOWN_TEXT,
    }
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    ui.heading(texts::DIAG_TITLE);
    ui.strong(texts::DIAG_NAT_TITLE);
    if let Some(n) = model.snapshot.nat {
        ui.label(nat_text(n));
    }
    if let Some(m) = model.snapshot.mapping {
        ui.label(core_texts::mapping_text(m));
    }
    if ui.button(texts::BTN_REFRESH_MAPPING).clicked() {
        out.push(main(MainIntent::Settings(
            crate::settings_model::SettingsIntent::MappingRefresh,
        )));
    }
    ui.separator();
    let friends: Vec<_> = model
        .snapshot
        .friends
        .iter()
        .filter(|f| f.status == FriendStatus::Active)
        .collect();
    if friends.is_empty() {
        ui.label(texts::DIAG_NO_FRIENDS);
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for f in friends {
            ui.group(|ui| {
                ui.strong(&f.name);
                if f.key_problem {
                    warn(ui, core_texts::KEY_LOST_TEXT);
                } else if f.online {
                    ui.label(texts::DIAG_CONNECTED);
                } else if let Some(d) = model.snapshot.diagnoses.iter().find(|d| d.friend == f.id) {
                    ui.label(d.text);
                    if d.lan_hint {
                        warn(ui, texts::LAN_EXPIRED_HINT);
                    }
                    if d.could_help {
                        // посредника в этой версии нет: ни кнопки, ни поля, только текст
                        ui.label(texts::MEDIATOR_LATER);
                    }
                } else {
                    ui.label(texts::DIAG_NO_REASON);
                }
                if !f.online && !f.key_problem && ui.button(texts::BTN_CONNECT).clicked() {
                    out.push(main(MainIntent::ConnectNow(f.id)));
                }
            });
        }
    });
    out
}
