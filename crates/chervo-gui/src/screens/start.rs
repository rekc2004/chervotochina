//! Экран 1: запуск и ошибки запуска. Только рисует и возвращает намерения; решения принимает
//! модель.

use chervo_core::texts as core_texts;
use eframe::egui::{self, Color32, RichText};

use crate::model::{FirstRun, Intent, Problem, ProblemKind, Start};
use crate::{picker, texts};

const WARN: Color32 = Color32::from_rgb(200, 120, 0);

pub fn show(ui: &mut egui::Ui, start: &Start) -> Vec<Intent> {
    let mut out = Vec::new();
    match start {
        Start::Opening => {
            ui.add_space(24.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::STARTING);
            });
        }
        Start::FirstRun(f) => first_run(ui, f, &mut out),
        Start::Problem(p) => problem(ui, p, &mut out),
    }
    out
}

fn first_run(ui: &mut egui::Ui, f: &FirstRun, out: &mut Vec<Intent>) {
    ui.heading(texts::FIRST_RUN_TITLE);
    ui.add_space(8.0);
    // «Ключи хранятся в хранилище ОС» входит в этот текст ядра
    ui.label(core_texts::FIRST_RUN_TEXT);
    ui.add_space(12.0);
    ui.label(texts::FOLDER_LABEL);
    ui.horizontal(|ui| {
        let mut folder = f.folder.clone();
        let edit = ui.add_enabled(
            !f.busy,
            egui::TextEdit::singleline(&mut folder).desired_width(380.0),
        );
        if edit.changed() {
            out.push(Intent::FolderEdited(folder));
        }
        if ui
            .add_enabled(!f.busy, egui::Button::new(texts::BTN_PICK_FOLDER))
            .clicked()
            && let Some(path) = picker::pick_folder()
        {
            out.push(Intent::FolderPicked(path));
        }
    });
    if let Some(e) = f.error {
        ui.add_space(6.0);
        ui.label(RichText::new(e).color(WARN));
    }
    if f.outside_warning {
        let mut checked = f.outside_confirmed;
        if ui
            .add_enabled(
                !f.busy,
                egui::Checkbox::new(&mut checked, texts::CHECK_NO_OTHER_USERS),
            )
            .changed()
        {
            out.push(Intent::OutsideChecked(checked));
        }
    }
    ui.add_space(12.0);
    let can_submit = !f.busy && (!f.outside_warning || f.outside_confirmed);
    if ui
        .add_enabled(can_submit, egui::Button::new(texts::BTN_CONTINUE))
        .clicked()
    {
        out.push(Intent::SubmitFirstRun);
    }
}

fn problem(ui: &mut egui::Ui, p: &Problem, out: &mut Vec<Intent>) {
    let enabled = !p.busy;
    let (text, extra) = match p.kind {
        ProblemKind::AlreadyRunning => (core_texts::ALREADY_RUNNING_TEXT, None),
        ProblemKind::KeyStoreLocked => (
            core_texts::KEY_STORE_LOCKED_TEXT,
            cfg!(target_os = "linux").then_some(texts::LINUX_NO_SECRET_SERVICE),
        ),
        ProblemKind::KeysLost => (core_texts::KEYS_LOST_TEXT, Some(texts::START_OVER_WARNING)),
        ProblemKind::RolledBack => (core_texts::ROLLED_BACK_TEXT, None),
        ProblemKind::SettingsCorrupt => (core_texts::SETTINGS_CORRUPT_TEXT, None),
        ProblemKind::PortInUse => (core_texts::PORT_IN_USE_TEXT, None),
        ProblemKind::Other(t) => (t, None),
    };
    ui.add_space(8.0);
    ui.label(text);
    if let Some(x) = extra {
        ui.add_space(6.0);
        ui.label(x);
    }
    if let Some(n) = p.note {
        ui.add_space(6.0);
        ui.label(RichText::new(n).color(WARN));
    }
    ui.add_space(12.0);
    ui.horizontal(|ui| match p.kind {
        ProblemKind::AlreadyRunning => {
            if ui.button(texts::BTN_QUIT).clicked() {
                out.push(Intent::Quit);
            }
        }
        ProblemKind::KeyStoreLocked => {
            if cfg!(target_os = "linux")
                && ui
                    .add_enabled(enabled, egui::Button::new(texts::BTN_UNLOCK))
                    .clicked()
            {
                out.push(Intent::Unlock);
            }
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_RETRY))
                .clicked()
            {
                out.push(Intent::RetryOpen);
            }
        }
        ProblemKind::KeysLost => {
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_START_OVER))
                .clicked()
            {
                out.push(Intent::StartOver);
            }
        }
        ProblemKind::RolledBack => {
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_ACCEPT_OLDER))
                .clicked()
            {
                out.push(Intent::AcceptOlder);
            }
        }
        ProblemKind::SettingsCorrupt => {
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_RESET_SETTINGS))
                .clicked()
            {
                out.push(Intent::ResetSettings);
            }
        }
        ProblemKind::PortInUse => {
            ui.label(texts::PORT_LABEL);
            let mut port = p.port_text.clone();
            if ui
                .add_enabled(
                    enabled,
                    egui::TextEdit::singleline(&mut port).desired_width(80.0),
                )
                .changed()
            {
                out.push(Intent::PortEdited(port));
            }
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_USE_PORT))
                .clicked()
            {
                out.push(Intent::UsePort);
            }
        }
        ProblemKind::Other(_) => {
            if ui
                .add_enabled(enabled, egui::Button::new(texts::BTN_RETRY))
                .clicked()
            {
                out.push(Intent::RetryOpen);
            }
        }
    });
}
