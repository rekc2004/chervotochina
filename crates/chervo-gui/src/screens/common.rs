//! Общие мелочи экранов.

use eframe::egui::{self, Color32, RichText};

use crate::texts;

pub const WARN: Color32 = Color32::from_rgb(200, 120, 0);

pub fn warn(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(WARN));
}

/// Текст только для чтения с кнопкой «Копировать». Копирование идёт в системный буфер через
/// egui; исключение из истории буфера здесь недоступно (см. отчёт этапа).
pub fn copy_box(ui: &mut egui::Ui, text: &str) {
    let mut view = text;
    ui.add(
        egui::TextEdit::multiline(&mut view)
            .desired_width(f32::INFINITY)
            .desired_rows(3),
    );
    if ui.button(texts::BTN_COPY).clicked() {
        ui.ctx().copy_text(text.to_owned());
    }
}
