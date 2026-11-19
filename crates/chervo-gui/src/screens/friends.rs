//! Экран 2: друзья. Список с состоянием и действиями, диалоги (переименование, удаление,
//! отзыв ключа, вопрос о доверии для автоприёма, новый адрес для друга, «Друг прислал мне
//! текст»). Только рисует и возвращает намерения.

use chervo_core::texts as core_texts;
use chervo_core::{FriendStatus, PathKind};
use eframe::egui;

use crate::main_model::{Dialog, MAX_PASTE, MainIntent, PasteDialog};
use crate::model::{Intent, Model, Section};
use crate::rows::FriendRow;
use crate::screens::common::{
    button_with_help, checkbox_with_help, copy_box, enabled_button_with_help, label_with_help,
    plain_button, warn,
};
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
    if model.snapshot.friends.is_empty() {
        ui.label(texts::FRIENDS_EMPTY);
        ui.horizontal_wrapped(|ui| {
            if button_with_help(ui, texts::BTN_INVITE_FRIEND, texts::HELP_INVITE_FRIEND).clicked() {
                out.push(Intent::GoSection(Section::AddFriend));
            }
            if button_with_help(ui, texts::BTN_FRIEND_TEXT, texts::HELP_FRIEND_TEXT).clicked() {
                out.push(main(MainIntent::FriendTextOpen));
            }
        });
        return;
    }
    if button_with_help(ui, texts::BTN_FRIEND_TEXT, texts::HELP_FRIEND_TEXT).clicked() {
        out.push(main(MainIntent::FriendTextOpen));
    }
    ui.separator();
    // прокрутку даёт вкладка целиком
    for f in &model.snapshot.friends {
        friend_row(ui, f, model.connecting.contains(&f.id), out);
    }
}

fn friend_row(ui: &mut egui::Ui, f: &FriendRow, connecting: bool, out: &mut Vec<Intent>) {
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
                if button_with_help(ui, texts::BTN_SEND, texts::HELP_FRIEND_SEND).clicked() {
                    out.push(main(MainIntent::FriendSend(f.id)));
                }
                if !f.online
                    && button_with_help(ui, texts::BTN_CONNECT, texts::HELP_CONNECT).clicked()
                {
                    out.push(main(MainIntent::ConnectNow(f.id)));
                }
                // С5: «Соединить» ничего не показывал
                if !f.online && connecting {
                    ui.spinner();
                    ui.label(texts::CONNECTING);
                }
                if button_with_help(ui, texts::BTN_DIAGNOSE, texts::HELP_DIAGNOSE).clicked() {
                    out.push(Intent::GoSection(Section::Diagnosis));
                }
            }
            if f.status != FriendStatus::Retired
                && button_with_help(ui, texts::BTN_RENAME, texts::HELP_RENAME).clicked()
            {
                out.push(main(MainIntent::RenameOpen(f.id)));
            }
            if f.status == FriendStatus::Active
                && button_with_help(ui, texts::BTN_BLOCK, texts::HELP_BLOCK).clicked()
            {
                out.push(main(MainIntent::Block(f.id)));
            }
            if f.status == FriendStatus::Blocked
                && button_with_help(ui, texts::BTN_UNBLOCK, texts::HELP_UNBLOCK).clicked()
            {
                out.push(main(MainIntent::Unblock(f.id)));
            }
            if matches!(f.status, FriendStatus::Active | FriendStatus::Blocked)
                && button_with_help(ui, texts::BTN_REKEY, texts::HELP_REKEY).clicked()
            {
                out.push(main(MainIntent::RekeyAsk(f.id)));
            }
            if f.status != FriendStatus::Retired
                && button_with_help(ui, texts::BTN_REMOVE, texts::HELP_REMOVE).clicked()
            {
                out.push(main(MainIntent::RemoveAsk(f.id)));
            }
        });
        if usable {
            ui.horizontal_wrapped(|ui| {
                if f.auto_accept {
                    if button_with_help(ui, texts::BTN_AUTO_OFF, texts::HELP_AUTO_OFF).clicked() {
                        out.push(main(MainIntent::AutoAcceptOff(f.id)));
                    }
                } else if button_with_help(ui, texts::BTN_AUTO_ON, texts::HELP_AUTO_ON).clicked() {
                    out.push(main(MainIntent::AutoAcceptAsk(f.id)));
                }
                if button_with_help(ui, texts::BTN_SEND_ADDR, texts::HELP_SEND_ADDR).clicked() {
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
            label_with_help(ui, texts::LABEL_NAME, texts::HELP_RENAME_FIELD);
            if ui.text_edit_singleline(&mut t).changed() {
                out.push(main(MainIntent::RenameEdited(t)));
            }
            ui.horizontal_wrapped(|ui| {
                if button_with_help(ui, texts::BTN_SAVE, texts::HELP_SAVE_NAME).clicked() {
                    out.push(main(MainIntent::RenameSubmit));
                }
                if plain_button(ui, texts::BTN_CANCEL).clicked() {
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
            ui.horizontal_wrapped(|ui| {
                if plain_button(ui, texts::BTN_YES_TRUST).clicked() {
                    out.push(main(MainIntent::TrustYes));
                }
                if plain_button(ui, texts::BTN_NO).clicked() {
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
            ui.horizontal_wrapped(|ui| {
                if r.rekey
                    && button_with_help(ui, texts::BTN_NEW_INVITE, texts::HELP_NEW_INVITE).clicked()
                {
                    out.push(main(MainIntent::DialogClose));
                    out.push(Intent::GoSection(Section::AddFriend));
                }
                if plain_button(ui, texts::BTN_OK).clicked() {
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
                    if checkbox_with_help(
                        ui,
                        true,
                        &mut same,
                        texts::LABEL_SAME_NETWORK,
                        texts::HELP_SAME_NETWORK,
                    )
                    .changed()
                    {
                        out.push(main(MainIntent::AddrTokenNetwork(same)));
                    }
                    if let Some(e) = a.error {
                        warn(ui, e);
                    }
                    if enabled_button_with_help(
                        ui,
                        !a.busy,
                        texts::BTN_CREATE_TOKEN,
                        texts::HELP_CREATE_TOKEN,
                    )
                    .clicked()
                    {
                        out.push(main(MainIntent::AddrTokenIssue));
                    }
                }
                Some(t) => copy_box(ui, t),
            }
            if plain_button(ui, texts::BTN_OK).clicked() {
                out.push(main(MainIntent::DialogClose));
            }
        }
        Dialog::FriendText(p) => friend_text_dialog(ui, p, out),
    }
}

/// «Друг прислал мне текст»: одно поле на приглашение, новый адрес и уведомление об удалении.
/// Показывается и на «Друзьях», и на «Добавить друга».
pub fn friend_text_dialog(ui: &mut egui::Ui, p: &PasteDialog, out: &mut Vec<Intent>) {
    ui.heading(texts::FRIEND_TEXT_TITLE);
    label_with_help(ui, texts::LABEL_PASTE_HERE, texts::HELP_PASTE_FIELD);
    let mut t = p.text.clone();
    // egui 0.37: `char_limit` действует только у однострочного поля. Предел на один символ
    // больше 4096, чтобы слишком длинный текст был виден как «слишком длинный».
    let edit = egui::TextEdit::singleline(&mut t)
        .desired_width(f32::INFINITY)
        .hint_text(texts::PASTE_HINT)
        .char_limit(MAX_PASTE + 1);
    if ui.add_enabled(!p.busy, edit).changed() {
        out.push(main(MainIntent::FriendTextEdited(t)));
    }
    // кнопки сразу под полем: при узком окне они не уходят за край (Ж5)
    ui.horizontal_wrapped(|ui| {
        if enabled_button_with_help(ui, !p.busy, texts::BTN_APPLY, texts::HELP_APPLY_TEXT).clicked()
        {
            out.push(main(MainIntent::FriendTextSubmit));
        }
        if plain_button(ui, texts::BTN_CANCEL).clicked() {
            out.push(main(MainIntent::DialogClose));
        }
    });
    if p.too_long {
        warn(ui, core_texts::INPUT_TOO_LONG_TEXT);
    }
    if let Some(e) = p.error {
        warn(ui, e);
    }
}

fn confirm_buttons(ui: &mut egui::Ui, yes: &str, intent: MainIntent, out: &mut Vec<Intent>) {
    ui.horizontal_wrapped(|ui| {
        if plain_button(ui, yes).clicked() {
            out.push(main(intent));
        }
        if plain_button(ui, texts::BTN_CANCEL).clicked() {
            out.push(main(MainIntent::DialogClose));
        }
    });
}
