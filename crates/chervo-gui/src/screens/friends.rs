//! Экран 2: друзья. Список с состоянием и действиями, диалоги (переименование, удаление,
//! отзыв ключа, вопрос о доверии для автоприёма, токен адреса). Только рисует и возвращает
//! намерения.

use chervo_core::texts as core_texts;
use chervo_core::{FriendStatus, PathKind};
use eframe::egui;

use crate::main_model::{Dialog, MAX_PASTE, MainIntent};
use crate::model::{Intent, Model, Page};
use crate::rows::FriendRow;
use crate::screens::common::{copy_box, warn};
use crate::texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    match &model.dialog {
        Dialog::None => list(ui, model, &mut out),
        d => dialog(ui, model, d, &mut out),
    }
    out
}

fn path_label(p: PathKind) -> &'static str {
    match p {
        PathKind::Lan => texts::PATH_LAN,
        PathKind::Ipv6 => texts::PATH_IPV6,
        PathKind::PortMapped => texts::PATH_MAPPED,
        PathKind::SimultaneousOpen => texts::PATH_DIRECT,
    }
}

fn status_label(s: FriendStatus) -> &'static str {
    match s {
        FriendStatus::Active => texts::STATE_ACTIVE,
        FriendStatus::Blocked => texts::STATE_BLOCKED,
        FriendStatus::RevokedByPeer => texts::STATE_REVOKED,
        FriendStatus::Retired => texts::STATE_RETIRED,
        _ => texts::STATE_ACTIVE,
    }
}

fn list(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    ui.horizontal(|ui| {
        if ui.button(texts::BTN_PASTE_FRIEND_TOKEN).clicked() {
            out.push(main(MainIntent::PasteTokenOpen));
        }
        if ui.button(texts::BTN_REKEY_ALL).clicked() {
            out.push(main(MainIntent::RekeyAllAsk));
        }
    });
    ui.separator();
    if model.snapshot.friends.is_empty() {
        ui.label(texts::FRIENDS_EMPTY);
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for f in &model.snapshot.friends {
            friend_row(ui, f, out);
        }
    });
}

fn friend_row(ui: &mut egui::Ui, f: &FriendRow, out: &mut Vec<Intent>) {
    ui.group(|ui| {
        ui.horizontal_wrapped(|ui| {
            ui.strong(&f.name);
            ui.label(status_label(f.status));
            if f.status == FriendStatus::Active {
                ui.label(if f.online {
                    texts::STATE_ONLINE
                } else {
                    texts::STATE_OFFLINE
                });
                if let Some(p) = f.path.filter(|_| f.online) {
                    ui.label(path_label(p));
                }
                if f.auto_accept {
                    ui.label(texts::AUTO_ON_LABEL);
                }
            }
        });
        if f.key_problem {
            warn(ui, core_texts::KEY_LOST_TEXT);
        }
        let usable = f.status == FriendStatus::Active && !f.key_problem;
        ui.horizontal_wrapped(|ui| {
            if usable {
                if ui.button(texts::BTN_SEND).clicked() {
                    out.push(main(MainIntent::FriendSend(f.id)));
                }
                if !f.online && ui.button(texts::BTN_CONNECT).clicked() {
                    out.push(main(MainIntent::ConnectNow(f.id)));
                }
                if ui.button(texts::BTN_DIAGNOSE).clicked() {
                    out.push(Intent::Go(Page::Diagnosis));
                }
            }
            if f.status != FriendStatus::Retired && ui.button(texts::BTN_RENAME).clicked() {
                out.push(main(MainIntent::RenameOpen(f.id)));
            }
            if f.status == FriendStatus::Active && ui.button(texts::BTN_BLOCK).clicked() {
                out.push(main(MainIntent::Block(f.id)));
            }
            if f.status == FriendStatus::Blocked && ui.button(texts::BTN_UNBLOCK).clicked() {
                out.push(main(MainIntent::Unblock(f.id)));
            }
            if matches!(f.status, FriendStatus::Active | FriendStatus::Blocked)
                && ui.button(texts::BTN_REKEY).clicked()
            {
                out.push(main(MainIntent::RekeyAsk(f.id)));
            }
            if f.status != FriendStatus::Retired && ui.button(texts::BTN_REMOVE).clicked() {
                out.push(main(MainIntent::RemoveAsk(f.id)));
            }
        });
        if usable {
            ui.horizontal_wrapped(|ui| {
                if f.auto_accept {
                    if ui.button(texts::BTN_AUTO_OFF).clicked() {
                        out.push(main(MainIntent::AutoAcceptOff(f.id)));
                    }
                } else if ui.button(texts::BTN_AUTO_ON).clicked() {
                    out.push(main(MainIntent::AutoAcceptAsk(f.id)));
                }
                if ui.button(texts::BTN_SEND_ADDR).clicked() {
                    out.push(main(MainIntent::AddrTokenOpen(f.id)));
                }
            });
        }
    });
}

fn friend_name(model: &Model, id: crate::rows::Id) -> &str {
    model
        .snapshot
        .friends
        .iter()
        .find(|f| f.id == id)
        .map_or("", |f| f.name.as_str())
}

fn dialog(ui: &mut egui::Ui, model: &Model, d: &Dialog, out: &mut Vec<Intent>) {
    match d {
        Dialog::None => {}
        Dialog::Rename { friend: _, text } => {
            ui.heading(texts::BTN_RENAME);
            let mut t = text.clone();
            if ui.text_edit_singleline(&mut t).changed() {
                out.push(main(MainIntent::RenameEdited(t)));
            }
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_SAVE).clicked() {
                    out.push(main(MainIntent::RenameSubmit));
                }
                if ui.button(texts::BTN_CANCEL).clicked() {
                    out.push(main(MainIntent::DialogClose));
                }
            });
        }
        Dialog::ConfirmRemove(id) => {
            ui.heading(friend_name(model, *id));
            ui.label(texts::CONFIRM_REMOVE);
            confirm_buttons(ui, texts::BTN_REMOVE, MainIntent::RemoveConfirm, out);
        }
        Dialog::ConfirmRekey(id) => {
            ui.heading(friend_name(model, *id));
            ui.label(texts::CONFIRM_REKEY);
            confirm_buttons(ui, texts::BTN_REKEY, MainIntent::RekeyConfirm, out);
        }
        Dialog::ConfirmRekeyAll => {
            ui.label(texts::CONFIRM_REKEY_ALL);
            confirm_buttons(ui, texts::BTN_REKEY_ALL, MainIntent::RekeyAllConfirm, out);
        }
        Dialog::Trust(id) => {
            ui.heading(friend_name(model, *id));
            ui.label(core_texts::TRUST_QUESTION_TEXT);
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_YES_TRUST).clicked() {
                    out.push(main(MainIntent::TrustYes));
                }
                if ui.button(texts::BTN_NO).clicked() {
                    out.push(main(MainIntent::DialogClose));
                }
            });
        }
        Dialog::Revocation(r) => {
            ui.label(if r.rekey {
                texts::REVOCATION_REKEY
            } else {
                texts::REVOCATION_REMOVED
            });
            if r.failed > 0 {
                warn(ui, texts::REKEY_PARTIAL);
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (name, text) in &r.items {
                    ui.add_space(6.0);
                    ui.strong(name);
                    copy_box(ui, text);
                }
            });
            ui.horizontal(|ui| {
                if r.rekey && ui.button(texts::BTN_NEW_INVITE).clicked() {
                    out.push(main(MainIntent::DialogClose));
                    out.push(Intent::Go(Page::AddFriend));
                }
                if ui.button(texts::BTN_OK).clicked() {
                    out.push(main(MainIntent::DialogClose));
                }
            });
        }
        Dialog::AddrToken(a) => {
            ui.heading(texts::ADDR_TOKEN_TITLE);
            ui.label(friend_name(model, a.friend));
            warn(ui, texts::IP_WARNING);
            match &a.token {
                None => {
                    let mut same = a.same_network;
                    if ui.checkbox(&mut same, texts::LABEL_SAME_NETWORK).changed() {
                        out.push(main(MainIntent::AddrTokenNetwork(same)));
                    }
                    if let Some(e) = a.error {
                        warn(ui, e);
                    }
                    if ui
                        .add_enabled(!a.busy, egui::Button::new(texts::BTN_CREATE_TOKEN))
                        .clicked()
                    {
                        out.push(main(MainIntent::AddrTokenIssue));
                    }
                }
                Some(t) => copy_box(ui, t),
            }
            if ui.button(texts::BTN_OK).clicked() {
                out.push(main(MainIntent::DialogClose));
            }
        }
        Dialog::PasteToken(p) => {
            ui.heading(texts::PASTE_TOKEN_TITLE);
            ui.label(texts::LABEL_PASTE_HERE);
            let mut t = p.text.clone();
            let edit = egui::TextEdit::singleline(&mut t)
                .desired_width(f32::INFINITY)
                .char_limit(MAX_PASTE + 1);
            if ui.add_enabled(!p.busy, edit).changed() {
                out.push(main(MainIntent::PasteTokenEdited(t)));
            }
            if p.too_long {
                warn(ui, core_texts::INPUT_TOO_LONG_TEXT);
            }
            if let Some(e) = p.error {
                warn(ui, e);
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!p.busy, egui::Button::new(texts::BTN_APPLY))
                    .clicked()
                {
                    out.push(main(MainIntent::PasteTokenSubmit));
                }
                if ui.button(texts::BTN_CANCEL).clicked() {
                    out.push(main(MainIntent::DialogClose));
                }
            });
        }
    }
}

fn confirm_buttons(ui: &mut egui::Ui, yes: &str, intent: MainIntent, out: &mut Vec<Intent>) {
    ui.horizontal(|ui| {
        if ui.button(yes).clicked() {
            out.push(main(intent));
        }
        if ui.button(texts::BTN_CANCEL).clicked() {
            out.push(main(MainIntent::DialogClose));
        }
    });
}
