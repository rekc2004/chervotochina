//! Экран 6: передачи. Ход, причина паузы, «Повторить», отмена, итог. Папка, куда легли файлы,
//! показана текстом с кнопкой «Копировать». Кнопка «Открыть папку» открывает в проводнике только
//! папку приёма из настроек (решение владельца 2026-11-18); файлы и пути от друга не
//! открываются, сам запуск делает узел.

use chervo_core::texts as core_texts;
use chervo_core::{PauseReason, Side, TransferState};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::rows::TransferRow;
use crate::screens::common::{button_with_help, copy_box, warn};
use crate::texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    // Н7: открывается только папка приёма из настроек; ошибка запуска показана рядом
    ui.horizontal_wrapped(|ui| {
        if button_with_help(ui, texts::BTN_OPEN_FOLDER, texts::HELP_OPEN_FOLDER).clicked() {
            out.push(main(MainIntent::OpenReceiveFolder));
        }
        if let Some(e) = model.folder_error {
            warn(ui, e);
        }
    });
    ui.separator();
    if model.snapshot.transfers.is_empty() {
        ui.label(texts::TRANSFERS_EMPTY);
        return out;
    }
    // прокрутку даёт вкладка целиком
    for t in model.snapshot.transfers.iter().rev() {
        row(ui, t, &mut out);
        ui.add_space(6.0);
    }
    out
}

fn pause_text(p: PauseReason) -> &'static str {
    match p {
        PauseReason::Disconnected => core_texts::DISCONNECTED_TEXT,
        PauseReason::DiskFull => core_texts::DISK_FULL_TEXT,
        PauseReason::Stalled => core_texts::STALLED_TEXT,
        _ => core_texts::IO_TEXT,
    }
}

fn row(ui: &mut egui::Ui, t: &TransferRow, out: &mut Vec<Intent>) {
    ui.group(|ui| {
        let side = match t.side {
            Side::Sender => texts::SIDE_SEND,
            _ => texts::SIDE_RECEIVE,
        };
        ui.strong(format!("{}: {}", side, t.friend));
        // итог важнее состояния
        if let Some(r) = t.result {
            ui.label(r.user_text());
        } else {
            let state = match t.state {
                TransferState::AwaitingAnswer => texts::STATE_AWAITING_ANSWER,
                TransferState::AwaitingUser => texts::STATE_AWAITING_USER,
                TransferState::Active => texts::STATE_ACTIVE_TRANSFER,
                TransferState::Paused(_) => texts::STATE_PAUSED,
                _ => texts::STATE_FINISHED,
            };
            ui.label(state);
            if let Some((done, total)) = t.preparing {
                ui.label(core_texts::PREPARING_TEXT);
                progress(ui, done, total);
            } else if t.total > 0 {
                progress(ui, t.done, t.total);
            }
            if let Some(p) = t.pause {
                warn(ui, pause_text(p));
            }
        }
        if let Some(root) = &t.dest_root {
            ui.label(texts::SAVED_TO);
            copy_box(ui, root);
        }
        if t.result.is_none() {
            ui.horizontal_wrapped(|ui| {
                if matches!(t.state, TransferState::Paused(_))
                    && button_with_help(ui, texts::BTN_RETRY_TRANSFER, texts::HELP_RETRY_TRANSFER)
                        .clicked()
                {
                    out.push(main(MainIntent::TransferRetry(t.id)));
                }
                if button_with_help(ui, texts::BTN_CANCEL_TRANSFER, texts::HELP_CANCEL_TRANSFER)
                    .clicked()
                {
                    out.push(main(MainIntent::TransferCancel(t.id)));
                }
            });
        }
    });
}

fn progress(ui: &mut egui::Ui, done: u64, total: u64) {
    let frac = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0) as f32
    };
    ui.add(egui::ProgressBar::new(frac).text(texts::progress_text(done, total)));
}
