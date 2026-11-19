//! Экран 8: настройки. Папка приёма (с вопросом «вне профиля»), запас места, порт, ручной
//! проброс, роутеры (UPnP), часы, ключи, о программе. Сеть только по кнопкам «Найти роутер» и
//! «Сверить часы».

use chervo_core::texts as core_texts;
use chervo_core::update::RELEASES_PAGE;
use chervo_core::{KeyStoreKind, LanMode, LanStatus};
use eframe::egui;

use crate::access_model::AccessIntent;
use crate::main_model::MainIntent;
use crate::model::{Intent, Model, Page};
use crate::picker;
use crate::rows::SettingsRow;
use crate::screens::common::{
    button_with_help, checkbox_with_help, copy_box, enabled_button_with_help, help_mark,
    label_with_help, plain_button, warn,
};
use crate::settings_model::{ClockUi, NumEdit, SettingsIntent as S, SettingsUi, UpnpUi};
use crate::texts;

fn s(i: S) -> Intent {
    Intent::Main(MainIntent::Settings(i))
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    // прокрутку даёт вкладка целиком
    if let Some(set) = &model.snapshot.settings {
        if set.restart_needed {
            warn(ui, texts::SET_RESTART);
        }
        folders(ui, set, &model.settings_ui, &mut out);
        ui.separator();
        numbers(ui, set, &model.settings_ui, &mut out);
        ui.separator();
        lan(ui, set, &mut out);
        ui.separator();
        external(ui, set, &model.settings_ui, &mut out);
        ui.separator();
        upnp(ui, model, set, &mut out);
        ui.separator();
        clock(ui, set, &model.settings_ui, &mut out);
        ui.separator();
        keys(ui, model, set, &mut out);
        ui.separator();
    }
    about(ui);
    ui.separator();
    crate::screens::update::section(ui, model, &mut out);
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
        // поле показывает текущую папку; правка применяется по Enter
        let mut text = r.text.clone().unwrap_or_else(|| set.receive_root.clone());
        let resp = ui.add_enabled(
            !r.busy,
            egui::TextEdit::singleline(&mut text).desired_width(360.0),
        );
        help_mark(ui, texts::HELP_SET_ROOT);
        if resp.changed() {
            out.push(s(S::RootEdited(text.clone())));
        }
        if resp.lost_focus()
            && ui.input(|i| i.key_pressed(egui::Key::Enter))
            && text.trim() != set.receive_root
        {
            out.push(s(S::RootEdited(text)));
            out.push(s(S::RootSubmit));
        }
        // выбор в окне сразу меняет папку, с теми же проверками, что и ввод пути
        if enabled_button_with_help(
            ui,
            !r.busy,
            texts::BTN_PICK_FOLDER,
            texts::HELP_SET_PICK_ROOT,
        )
        .clicked()
            && let Some(p) = picker::pick_folder()
        {
            out.push(s(S::RootEdited(p.to_string_lossy().into_owned())));
            out.push(s(S::RootSubmit));
        }
    });
    if let Some(e) = r.error {
        warn(ui, e);
    }
    if r.outside_warning {
        let mut checked = r.outside_confirmed;
        if checkbox_with_help(
            ui,
            !r.busy,
            &mut checked,
            texts::CHECK_NO_OTHER_USERS,
            texts::HELP_SET_OUTSIDE,
        )
        .changed()
        {
            out.push(s(S::RootOutsideChecked(checked)));
            if checked {
                // отметка ставится после отказа узла: сразу повторяем смену папки
                out.push(s(S::RootSubmit));
            }
        }
    }
}

fn num_row(
    ui: &mut egui::Ui,
    label: &str,
    help: &str,
    edit: &NumEdit,
    current: String,
    on_edit: fn(String) -> S,
    out: &mut Vec<Intent>,
) {
    label_with_help(ui, label, help);
    let mut text = edit.text.clone().unwrap_or(current);
    if ui
        .add(egui::TextEdit::singleline(&mut text).desired_width(100.0))
        .changed()
    {
        out.push(s(on_edit(text)));
    }
    if let Some(e) = edit.error {
        warn(ui, e);
    }
}

/// Запас места, порт и внешний порт: одна кнопка «Сохранить» на раздел. Сохраняются только
/// поля, которые правили.
fn numbers(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    num_row(
        ui,
        texts::SET_MIN_FREE,
        texts::HELP_SET_MIN_FREE,
        &st.min_free,
        set.min_free_percent.to_string(),
        S::MinFreeEdited,
        out,
    );
    num_row(
        ui,
        texts::SET_PORT,
        texts::HELP_SET_PORT,
        &st.port,
        set.port.to_string(),
        S::PortEdited,
        out,
    );
    num_row(
        ui,
        texts::ACC_MANUAL_FORWARD_LABEL,
        texts::HELP_SET_FORWARD,
        &st.forward,
        set.manual_forward
            .map(|p| p.to_string())
            .unwrap_or_default(),
        S::ForwardEdited,
        out,
    );
    let edited = st.min_free.text.is_some() || st.port.text.is_some() || st.forward.text.is_some();
    if enabled_button_with_help(ui, edited, texts::BTN_SAVE, texts::HELP_SET_SAVE).clicked() {
        if st.min_free.text.is_some() {
            out.push(s(S::MinFreeSubmit));
        }
        if st.port.text.is_some() {
            out.push(s(S::PortSubmit));
        }
        if st.forward.text.is_some() {
            out.push(s(S::ForwardSubmit));
        }
    }
}

/// Поиск друзей в локальной сети: три выбора, состояние, адреса поиска и подсказка про VPN.
/// Режим «Сообщать о себе» рассылает в сеть короткий маяк, поэтому выбирается только вручную.
fn lan(ui: &mut egui::Ui, set: &SettingsRow, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_LAN);
    for mode in [LanMode::Off, LanMode::Listen, LanMode::Announce] {
        let short = match mode {
            LanMode::Off => texts::LAN_SHORT_OFF,
            LanMode::Listen => texts::LAN_SHORT_LISTEN,
            _ => texts::LAN_SHORT_ANNOUNCE,
        };
        let help = match mode {
            LanMode::Off => texts::HELP_LAN_OFF,
            LanMode::Listen => texts::HELP_LAN_LISTEN,
            _ => texts::HELP_LAN_ANNOUNCE,
        };
        ui.horizontal(|ui| {
            if ui.radio(set.lan.mode == mode, short).clicked() {
                out.push(s(S::LanChoose(mode)));
            }
            help_mark(ui, help);
        });
    }
    ui.label(core_texts::lan_status_text(
        set.lan.status.unwrap_or(LanStatus::Off),
    ));
    ui.label(core_texts::VPN_HINT_TEXT);
    egui::CollapsingHeader::new(texts::DETAILS)
        .id_salt("lan-details")
        .default_open(false)
        .show(ui, |ui| {
            for mode in [LanMode::Off, LanMode::Listen, LanMode::Announce] {
                ui.label(core_texts::lan_mode_text(mode));
            }
            if !set.lan.addrs.is_empty() {
                let list: Vec<String> = set.lan.addrs.iter().map(ToString::to_string).collect();
                ui.label(format!(
                    "{}{}",
                    core_texts::ADDRS_PREFIX_TEXT,
                    list.join(", ")
                ));
            }
        });
}

/// «Связь через интернет»: адрес своего сервера, который подсказывает ваш адрес в интернете.
/// Пустая строка: ни одного пакета к серверу.
fn external(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_EXTERNAL);
    label_with_help(ui, texts::EXT_SERVER_LABEL, texts::EXT_SERVER_HINT);
    let mut text = st
        .echo
        .text
        .clone()
        .unwrap_or_else(|| set.echo_server.clone().unwrap_or_default());
    if ui
        .add(egui::TextEdit::singleline(&mut text).desired_width(360.0))
        .changed()
    {
        out.push(s(S::EchoEdited(text)));
    }
    if let Some(e) = st.echo.error {
        warn(ui, e);
    }
    ui.horizontal(|ui| {
        if enabled_button_with_help(
            ui,
            st.echo.text.is_some(),
            texts::BTN_SAVE,
            texts::HELP_EXT_SAVE,
        )
        .clicked()
        {
            out.push(s(S::EchoSave));
        }
        if enabled_button_with_help(
            ui,
            set.echo_server.is_some() || st.echo.text.is_some(),
            texts::BTN_CLEAR,
            texts::HELP_EXT_CLEAR,
        )
        .clicked()
        {
            out.push(s(S::EchoClear));
        }
    });
}

fn upnp(ui: &mut egui::Ui, model: &Model, set: &SettingsRow, out: &mut Vec<Intent>) {
    ui.heading(texts::SET_TITLE_UPNP);
    if button_with_help(ui, texts::BTN_OPEN_ACCESS, texts::HELP_OPEN_ACCESS).clicked() {
        out.push(Intent::Main(MainIntent::Access(AccessIntent::Open)));
    }
    if let Some(m) = model.snapshot.mapping {
        ui.label(core_texts::mapping_text(m));
    }
    let state = model.settings_ui.upnp;
    if enabled_button_with_help(
        ui,
        state != UpnpUi::Searching,
        texts::BTN_FIND_ROUTER,
        texts::HELP_FIND_ROUTER,
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
                if plain_button(ui, texts::BTN_YES).clicked() {
                    out.push(s(S::UpnpAllowYes));
                }
                if plain_button(ui, texts::BTN_NO).clicked() {
                    out.push(s(S::UpnpDecline));
                }
            });
        }
        UpnpUi::Message(t) => {
            ui.label(t);
        }
        UpnpUi::Idle => {}
    }
    // бессрочная аренда: один вопрос про тот роутер, который этого потребовал
    if let Some((n, r)) = set
        .routers
        .iter()
        .enumerate()
        .find(|(_, r)| r.needs_permanent)
    {
        ui.strong(format!("{} {}", texts::SET_ROUTER_ITEM, n + 1));
        ui.label(core_texts::NEED_PERMANENT_TEXT);
        if plain_button(ui, texts::BTN_YES).clicked() {
            out.push(s(S::UpnpPermanentYes(r.id)));
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
            if button_with_help(ui, texts::BTN_FORGET, texts::HELP_FORGET_ROUTER).clicked() {
                out.push(s(S::UpnpForget(r.id)));
            }
        });
    }
}

fn clock(ui: &mut egui::Ui, set: &SettingsRow, st: &SettingsUi, out: &mut Vec<Intent>) {
    ui.horizontal(|ui| {
        ui.heading(texts::SET_TITLE_CLOCK);
        help_mark(ui, texts::HELP_CLOCK_NOTE);
    });
    egui::CollapsingHeader::new(texts::DETAILS)
        .id_salt("clock-details")
        .default_open(false)
        .show(ui, |ui| {
            ui.label(texts::clock_offset_text(set.clock_offset_ms));
            ui.label(format!(
                "{}: {}",
                texts::SET_NTP,
                set.ntp_servers.join(", ")
            ));
        });
    ui.horizontal(|ui| {
        let busy = matches!(st.clock, ClockUi::Syncing | ClockUi::Proposal(_));
        if enabled_button_with_help(ui, !busy, texts::BTN_SYNC_CLOCK, texts::HELP_SYNC_CLOCK)
            .clicked()
        {
            out.push(s(S::ClockSync));
        }
        if enabled_button_with_help(
            ui,
            !matches!(st.clock, ClockUi::Syncing),
            texts::BTN_RESET_CLOCK,
            texts::HELP_RESET_CLOCK,
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
                if plain_button(ui, texts::BTN_APPLY_OFFSET).clicked() {
                    out.push(s(S::ClockConfirm));
                }
                if plain_button(ui, texts::BTN_CANCEL).clicked() {
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
    egui::CollapsingHeader::new(texts::DETAILS)
        .id_salt("keys-details")
        .default_open(false)
        .show(ui, |ui| {
            ui.label(format!(
                "{}: {}",
                texts::SET_KEY_STORE,
                store_name(set.key_store)
            ));
        });
    // режима «локальные ключи» нет: ни переключателя, ни кнопки
    if button_with_help(ui, texts::BTN_REKEY_ALL, texts::HELP_REKEY_ALL).clicked() {
        // диалог подтверждения живёт на вкладке «Друзья»
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
            if button_with_help(ui, texts::BTN_FORGET_RETIRED, texts::HELP_FORGET_RETIRED).clicked()
            {
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
    ui.label(texts::ABOUT_LICENCES.replace("{ver}", chervo_core::VERSION));
    copy_box(ui, RELEASES_PAGE);
}
