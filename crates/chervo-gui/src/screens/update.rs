//! Раздел «Обновления» (в «Настройках») и карточки (этап 19г-2): согласие на проверку новых версий, найденная
//! версия со ссылкой на страницу выпусков (текст и «Копировать», браузер не запускается),
//! офлайн-сверка скачанных файлов, вшитые ключи. Экран только рисует готовые строки модели и
//! возвращает намерения: ни файлов, ни сети, ни потоков здесь нет.

use chervo_core::update::{RELEASES_PAGE, UpdateConsent};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::picker;
use crate::screens::common::{
    button_with_help, checkbox_with_help, copy_box, enabled_button_with_help, help_mark,
    plain_button, warn,
};
use crate::texts;
use crate::update_model::{FileLine, UpdateIntent as U, VerifyResult};

fn u(i: U) -> Intent {
    Intent::Main(MainIntent::Update(i))
}

/// Карточка согласия вверху главного окна: не модальная, видна, пока ответа нет.
pub fn consent_card(ui: &mut egui::Ui, out: &mut Vec<Intent>) {
    ui.group(|ui| {
        ui.strong(texts::UPD_CONSENT_TITLE);
        ui.label(texts::UPD_CONSENT_TEXT);
        ui.horizontal_wrapped(|ui| {
            if button_with_help(ui, texts::BTN_UPD_ENABLE, texts::HELP_UPD_ENABLE).clicked() {
                out.push(u(U::SetConsent(true)));
            }
            if button_with_help(ui, texts::BTN_UPD_DISABLE, texts::HELP_UPD_DISABLE).clicked() {
                out.push(u(U::SetConsent(false)));
            }
        });
    });
}

/// Карточка «Вышла версия X.Y.Z» и диалог со ссылкой.
pub fn newer_card(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    let Some(v) = &model.update.newer else {
        return;
    };
    ui.group(|ui| {
        ui.strong(texts::upd_newer(v, chervo_core::VERSION));
        ui.horizontal_wrapped(|ui| {
            if button_with_help(ui, texts::BTN_UPD_WHERE, texts::HELP_UPD_WHERE).clicked() {
                out.push(u(U::LinkOpen));
            }
            if plain_button(ui, texts::NOTICES_HIDE).clicked() {
                out.push(u(U::DismissNewer));
            }
        });
        if model.update.link_open {
            ui.label(texts::UPD_LINK_TEXT);
            copy_box(ui, RELEASES_PAGE);
            if plain_button(ui, texts::BTN_OK).clicked() {
                out.push(u(U::LinkClose));
            }
        }
    });
}

/// Раздел «Обновления» в конце «Настроек»: согласие и проверка новых версий; сверка скачанных
/// файлов и вшитые ключи свёрнуты под «Для опытных».
pub fn section(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    check_section(ui, model, out);
    egui::CollapsingHeader::new(texts::UPD_EXPERT)
        .default_open(false)
        .show(ui, |ui| {
            verify_section(ui, model, out);
            ui.separator();
            keys_section(ui, model);
        });
}

fn check_section(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    ui.heading(texts::NAV_UPDATES);
    ui.label(format!("{}: {}", texts::UPD_RUNNING, chervo_core::VERSION));
    let consent = model.update_consent();
    let mut on = consent == UpdateConsent::Enabled;
    if checkbox_with_help(ui, true, &mut on, texts::UPD_TOGGLE, texts::HELP_UPD_TOGGLE).changed() {
        out.push(u(U::SetConsent(on)));
    }
    let can = consent == UpdateConsent::Enabled && !model.update.checking;
    if enabled_button_with_help(ui, can, texts::BTN_UPD_CHECK_NOW, texts::HELP_UPD_CHECK_NOW)
        .clicked()
    {
        out.push(u(U::CheckNow));
    }
    if consent != UpdateConsent::Enabled {
        ui.label(texts::UPD_CHECK_NEEDS_CONSENT);
    }
    if model.update.checking {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(texts::UPD_CHECKING);
        });
    }
    if let Some(s) = model.update.manual_status {
        ui.label(s.text());
    }
}

fn verify_section(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    let st = &model.update;
    ui.horizontal(|ui| {
        ui.heading(texts::UPD_VERIFY_TITLE);
        help_mark(ui, texts::HELP_UPD_VERIFY_SECTION);
    });
    ui.horizontal(|ui| {
        if enabled_button_with_help(
            ui,
            !st.busy,
            texts::BTN_UPD_PICK_MANIFEST,
            texts::HELP_UPD_PICK_MANIFEST,
        )
        .clicked()
            && let Some(p) = picker::pick_file()
        {
            out.push(u(U::PickManifest(p)));
        }
        if let Some((_, label)) = &st.manifest {
            ui.label(label);
        }
    });
    ui.horizontal(|ui| {
        if enabled_button_with_help(
            ui,
            !st.busy,
            texts::BTN_UPD_PICK_SIG,
            texts::HELP_UPD_PICK_SIG,
        )
        .clicked()
            && let Some(p) = picker::pick_file()
        {
            out.push(u(U::PickSignature(p)));
        }
        if let Some((_, label)) = &st.minisig {
            ui.label(label);
        }
    });
    ui.horizontal_wrapped(|ui| {
        if enabled_button_with_help(
            ui,
            !st.busy,
            texts::BTN_UPD_PICK_FILES,
            texts::HELP_UPD_PICK_FILES,
        )
        .clicked()
        {
            let picked = picker::pick_files()
                .into_iter()
                .filter(|p| !p.is_dir)
                .map(|p| p.path)
                .collect::<Vec<_>>();
            if !picked.is_empty() {
                out.push(u(U::AddFiles(picked)));
            }
        }
        if !st.files.is_empty()
            && enabled_button_with_help(
                ui,
                !st.busy,
                texts::BTN_REMOVE_ITEM,
                texts::HELP_UPD_CLEAR_FILES,
            )
            .clicked()
        {
            out.push(u(U::ClearFiles));
        }
    });
    for (_, label) in &st.files {
        ui.label(label);
    }
    let mut downgrade = st.allow_downgrade;
    if checkbox_with_help(
        ui,
        !st.busy,
        &mut downgrade,
        texts::UPD_ALLOW_DOWNGRADE,
        texts::HELP_UPD_DOWNGRADE,
    )
    .changed()
    {
        out.push(u(U::AllowDowngrade(downgrade)));
    }
    let ready = st.manifest.is_some() && st.minisig.is_some() && !st.files.is_empty() && !st.busy;
    if enabled_button_with_help(ui, ready, texts::BTN_UPD_VERIFY, texts::HELP_UPD_VERIFY).clicked()
    {
        out.push(u(U::Verify));
    }
    if st.busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(texts::UPD_CHECKING);
        });
    }
    match &st.result {
        None => {}
        Some(VerifyResult::Rejected(text)) => warn(ui, text),
        Some(VerifyResult::Checked {
            version,
            role,
            key_id,
            files,
        }) => {
            ui.label(texts::upd_signed_by(role, key_id, version));
            for line in files {
                file_line(ui, line);
            }
            if !files.is_empty() && files.iter().all(|l| l.ok) {
                ui.label(texts::UPD_REPLACE_HINT);
            }
        }
    }
}

fn file_line(ui: &mut egui::Ui, line: &FileLine) {
    let text = match &line.name {
        Some(name) => format!("{} ({name}): {}", line.label, line.text),
        None => format!("{}: {}", line.label, line.text),
    };
    if line.ok && !line.warn {
        ui.label(text);
    } else {
        warn(ui, &text);
    }
}

fn keys_section(ui: &mut egui::Ui, model: &Model) {
    ui.strong(texts::UPD_KEYS_TITLE);
    if model.update.keys.is_empty() {
        ui.label(texts::UPD_KEYS_NONE);
    }
    for k in &model.update.keys {
        ui.label(texts::upd_key_row(k.role, &k.id));
    }
}
