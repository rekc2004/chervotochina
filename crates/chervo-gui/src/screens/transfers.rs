//! Экран 6: передачи. Ход, причина паузы, «Повторить», отмена, итог. Папка, куда легли файлы,
//! показана текстом с кнопкой «Копировать»; ничего не открывается и не запускается.

use chervo_core::texts as core_texts;
use chervo_core::{PauseReason, Side, TransferState};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::rows::TransferRow;
use crate::screens::common::{copy_box, warn};
use crate::texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    if model.snapshot.transfers.is_empty() {
        ui.label(texts::TRANSFERS_EMPTY);
        return out;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for t in model.snapshot.transfers.iter().rev() {
            row(ui, t, &mut out);
            ui.add_space(6.0);
        }
    });
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
            ui.horizontal(|ui| {
                if matches!(t.state, TransferState::Paused(_))
                    && ui.button(texts::BTN_RETRY_TRANSFER).clicked()
                {
                    out.push(main(MainIntent::TransferRetry(t.id)));
                }
                if ui.button(texts::BTN_CANCEL_TRANSFER).clicked() {
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
