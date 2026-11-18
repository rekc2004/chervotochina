//! Общие мелочи экранов.

use eframe::egui::{self, Color32, RichText, Role, Sense, WidgetInfo};

use crate::texts;

pub const WARN: Color32 = Color32::from_rgb(200, 120, 0);

pub fn warn(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(WARN));
}

/// Значок «?»: описание всплывает при наведении (`Response::on_hover_text`). Одна функция на всю
/// программу (дополнение владельца 2026-11-18): пояснения к пунктам прячутся за значок, а не
/// занимают место на экране. Предупреждения, без которых действие небезопасно (`IP_WARNING`,
/// вопрос о роутере), под значок не прячутся: их показывает `warn` или обычный `label`.
pub fn help_mark(ui: &mut egui::Ui, help: &str) -> egui::Response {
    let response = ui
        .add(
            egui::Label::new(RichText::new(texts::HELP_MARK).strong())
                .selectable(false)
                .sense(Sense::hover()),
        )
        .on_hover_text(help);
    // экранному диктору значок читается как пояснение с его текстом
    response.widget_info(|| WidgetInfo::labeled(Role::Label, true, help));
    response
}

/// Подпись с «?» рядом: строка, где пояснение не занимает места.
pub fn label_with_help(ui: &mut egui::Ui, label: &str, help: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        help_mark(ui, help);
    });
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

/// Короткое значение в одну строку с кнопкой «Копировать» (шаги помощника): подпись сверху.
pub fn copy_line(ui: &mut egui::Ui, label: &str, value: &str) {
    if !label.is_empty() {
        ui.label(label);
    }
    ui.horizontal(|ui| {
        let mut view = value;
        ui.add(egui::TextEdit::singleline(&mut view).desired_width(220.0));
        if ui.button(texts::BTN_COPY).clicked() {
            ui.ctx().copy_text(value.to_owned());
        }
    });
}
