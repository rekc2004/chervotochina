//! Экран 8: настройки. Папка приёма (с вопросом «вне профиля»), запас места, порт, ручной
//! проброс, роутеры (UPnP), часы, ключи, о программе. Сеть только по кнопкам «Найти роутер» и
//! «Сверить часы».

use chervo_core::texts as core_texts;
use chervo_core::{KeyStoreKind, MapStatus};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model, Page};
use crate::picker;
use crate::rows::SettingsRow;
use crate::screens::common::warn;
use crate::settings_model::{ClockUi, NumEdit, SettingsIntent as S, SettingsUi, UpnpUi};
use crate::texts;

fn s(i: S) -> Intent {
    Intent::Main(MainIntent::Settings(i))
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    egui::ScrollArea::vertical().show(ui, |ui| {
        if let Some(set) = &model.snapshot.settings {
            if set.restart_needed {
                warn(ui, texts::SET_RESTART);
            }
            folders(ui, set, &model.settings_ui, &mut out);
            ui.separator();
            numbers(ui, set, &model.settings_ui, &mut out);
            ui.separator();
            upnp(ui, model, set, &mut out);
            ui.separator();
            clock(ui, set, &model.settings_ui, &mut out);
            ui.separator();
            keys(ui, model, set, &mut out);
            ui.separator();
        }
        about(ui);
    });
    out
}

fn folders(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    let r = &st.root;
    ui.heading(texts::SET_TITLE_FOLDERS);
    ui.label(format!("{}: {}", texts::SET_CURRENT, set.receive_root));
    if !set.extra_roots.is_empty() {
        ui.label(texts::SET_EXTRA_FOLDERS);
        for p in &set.extra_roots {
            ui.label(p);
        }
    }
    ui.horizontal(|ui| {
        let mut text = r.text.clone().unwrap_or_default();
        if ui
            .add_enabled(
                !r.busy,
                egui::TextEdit::singleline(&mut text).desired_width(360.0),
            )
            .changed()
        {
            out.push(s(S::RootEdited(text)));
        }
        if ui
            .add_enabled(!r.busy, egui::Button::new(texts::BTN_PICK_FOLDER))
            .clicked()
            && let Some(p) = picker::pick_folder()
        {
            out.push(s(S::RootEdited(p.to_string_lossy().into_owned())));
        }
    });
    if let Some(e) = r.error {
        warn(ui, e);
    }
    if r.outside_warning {
        let mut checked = r.outside_confirmed;
        if ui
            .add_enabled(
                !r.busy,
                egui::Checkbox::new(&mut checked, texts::CHECK_NO_OTHER_USERS),
            )
            .changed()
        {
            out.push(s(S::RootOutsideChecked(checked)));
        }
    }
    let can = !r.busy && (!r.outside_warning || r.outside_confirmed);
    if ui
        .add_enabled(can, egui::Button::new(texts::BTN_CHANGE_FOLDER))
        .clicked()
    {
        out.push(s(S::RootSubmit));
    }
}

fn num_row(
    ui: &mut egui::Ui,
    label: &str,
    edit: &NumEdit,
    current: String,
    on_edit: fn(String) -> S,
    submit: S,
    out: &mut Vec<Intent>,
) {
    ui.label(label);
    ui.horizontal(|ui| {
        let mut text = edit.text.clone().unwrap_or(current);
        if ui
            .add(egui::TextEdit::singleline(&mut text).desired_width(100.0))
            .changed()
        {
            out.push(s(on_edit(text)));
        }
        if ui.button(texts::BTN_SAVE).clicked() {
            out.push(s(submit));
        }
    });
    if let Some(e) = edit.error {
        warn(ui, e);
    }
}

fn numbers(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    num_row(
        ui,
        texts::SET_MIN_FREE,
        &st.min_free,
        set.min_free_percent.to_string(),
        S::MinFreeEdited,
        S::MinFreeSubmit,
        out,
    );
    num_row(
        ui,
        texts::SET_PORT,
        &st.port,
        set.port.to_string(),
        S::PortEdited,
        S::PortSubmit,
        out,
    );
    num_row(
        ui,
        texts::SET_FORWARD,
        &st.forward,
        set.manual_forward
            .map(|p| p.to_string())
            .unwrap_or_default(),
        S::ForwardEdited,
        S::ForwardSubmit,
        out,
    );
}

fn upnp(ui: &mut egui::Ui, model: &Model, set: &SettingsRow, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_UPNP);
    if let Some(m) = model.snapshot.mapping {
        ui.label(core_texts::mapping_text(m));
    }
    let state = model.settings_ui.upnp;
    if ui
        .add_enabled(
            state != UpnpUi::Searching,
            egui::Button::new(texts::BTN_FIND_ROUTER),
        )
        .clicked()
    {
        out.push(s(S::UpnpFind));
    }
    match state {
        UpnpUi::Searching => {
            ui.spinner();
        }
        UpnpUi::Found => {
            ui.label(core_texts::ENABLE_ON_ROUTER_TEXT);
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_YES).clicked() {
                    out.push(s(S::UpnpAllowYes));
                }
                if ui.button(texts::BTN_NO).clicked() {
                    out.push(s(S::UpnpDecline));
                }
            });
        }
        UpnpUi::Message(t) => {
            ui.label(t);
        }
        UpnpUi::Idle => {}
    }
    // бессрочная аренда: вопрос только когда роутер этого потребовал
    if model.snapshot.mapping == Some(MapStatus::NeedPermanentConsent) {
        ui.label(core_texts::NEED_PERMANENT_TEXT);
        for r in &set.routers {
            if !r.permanent_ok && ui.button(texts::BTN_YES).clicked() {
                out.push(s(S::UpnpPermanentYes(r.id)));
            }
        }
    }
    ui.strong(texts::SET_ROUTERS);
    if set.routers.is_empty() {
        ui.label(texts::SET_NO_ROUTERS);
    }
    for (n, r) in set.routers.iter().enumerate() {
        ui.horizontal(|ui| {
            let mut t = format!("{} {}", texts::SET_ROUTER_ITEM, n + 1);
            if r.permanent_ok {
                t.push_str(", ");
                t.push_str(texts::SET_ROUTER_PERMANENT);
            }
            ui.label(t);
            if ui.button(texts::BTN_FORGET).clicked() {
                out.push(s(S::UpnpForget(r.id)));
            }
        });
    }
}

fn clock(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_CLOCK);
    ui.label(texts::SET_CLOCK_NOTE);
    ui.label(texts::clock_offset_text(set.clock_offset_ms));
    ui.label(format!(
        "{}: {}",
        texts::SET_NTP,
        set.ntp_servers.join(", ")
    ));
    ui.horizontal(|ui| {
        let busy = matches!(st.clock, ClockUi::Syncing | ClockUi::Proposal(_));
        if ui
            .add_enabled(!busy, egui::Button::new(texts::BTN_SYNC_CLOCK))
            .clicked()
        {
            out.push(s(S::ClockSync));
        }
        if ui
            .add_enabled(
                !matches!(st.clock, ClockUi::Syncing),
                egui::Button::new(texts::BTN_RESET_CLOCK),
            )
            .clicked()
        {
            out.push(s(S::ClockReset));
        }
    });
    match st.clock {
        ClockUi::Syncing => {
            ui.spinner();
        }
        ClockUi::Proposal(ms) => {
            warn(ui, &texts::clock_proposal_text(ms));
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_APPLY_OFFSET).clicked() {
                    out.push(s(S::ClockConfirm));
                }
                if ui.button(texts::BTN_CANCEL).clicked() {
                    out.push(s(S::ClockDismiss));
                }
            });
        }
        ClockUi::Message(t) => {
            ui.label(t);
        }
        ClockUi::Idle => {}
    }
}

fn store_name(k: KeyStoreKind) -> &'static str {
    match k {
        KeyStoreKind::CredentialManager => texts::KEYS_CREDENTIAL,
        KeyStoreKind::Keychain => texts::KEYS_KEYCHAIN,
        KeyStoreKind::SecretService => texts::KEYS_SECRET,
        _ => texts::KEYS_OTHER,
    }
}

fn keys(ui: &mut egui::Ui, model: &Model, set: &SettingsRow, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_KEYS);
    ui.label(format!(
        "{}: {}",
        texts::SET_KEY_STORE,
        store_name(set.key_store)
    ));
    // режима «локальные ключи» нет: ни переключателя, ни кнопки
    ui.label(texts::KEYS_LOCAL_UNAVAILABLE);
    if ui.button(texts::BTN_REKEY_ALL).clicked() {
        // диалог подтверждения живёт на экране «Друзья»
        out.push(Intent::Main(MainIntent::RekeyAllAsk));
        out.push(Intent::Go(Page::Friends));
    }
    ui.add_space(6.0);
    ui.strong(texts::SET_RETIRED);
    if model.snapshot.retired.is_empty() {
        ui.label(texts::SET_NO_RETIRED);
    }
    for r in &model.snapshot.retired {
        ui.group(|ui| {
            ui.strong(&r.friend);
            crate::screens::common::copy_box(ui, &r.text);
            if ui.button(texts::BTN_FORGET_RETIRED).clicked() {
                out.push(s(S::ForgetRetired(r.id)));
            }
        });
    }
}

fn about(ui: &mut egui::Ui) {
    ui.heading(texts::SET_TITLE_ABOUT);
    ui.label(format!(
        "{}: {}",
        texts::ABOUT_VERSION,
        chervo_core::VERSION
    ));
    ui.label(texts::ABOUT_LICENCES);
}
