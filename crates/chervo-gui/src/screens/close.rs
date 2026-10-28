//! Экран 10: закрытие. С активными передачами сначала вопрос, затем состояние «закрываем»,
//! пока фоновый поток останавливает узел (до 10 с на передачи и снятие проброса порта).

use eframe::egui;

use crate::model::{Close, Intent};
use crate::texts;

pub fn show(ui: &mut egui::Ui, close: Close) -> Vec<Intent> {
    let mut out = Vec::new();
    match close {
        Close::Asking => {
            ui.heading(texts::CLOSE_ASK_TITLE);
            ui.add_space(8.0);
            ui.label(texts::CLOSE_ASK_TEXT);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_CLOSE).clicked() {
                    out.push(Intent::CloseConfirmed);
                }
                if ui.button(texts::BTN_STAY).clicked() {
                    out.push(Intent::CloseCancelled);
                }
            });
        }
        Close::ShuttingDown | Close::Done | Close::None => {
            ui.add_space(24.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::CLOSING);
            });
        }
    }
    out
}
