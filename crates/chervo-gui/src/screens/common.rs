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

/// Кнопка без «?»: только очевидные («Отмена», «Закрыть», «Готово», «Да»/«Нет» в вопросах
/// подтверждения). Всё остальное идёт через `button_with_help` и его родственников.
pub fn plain_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.button(label)
}

/// Кнопка с «?» рядом: значок и кнопка остаются одной группой при переносе строки.
pub fn button_with_help(ui: &mut egui::Ui, label: &str, help: &str) -> egui::Response {
    enabled_button_with_help(ui, true, label, help)
}

/// Пара «пункт + ?» в строке с переносом (`horizontal_wrapped`): вложенный `ui.horizontal` сам
/// на новую строку не переносится и уезжает за край окна (снимок владельца 2026-11-20). Поэтому
/// ширина пары оценивается заранее, и если она не помещается в остаток строки, строка
/// заканчивается. Вне строки с переносом ничего не делает.
fn wrap_before(ui: &mut egui::Ui, label: &str, style: egui::TextStyle, extra: f32) {
    if !ui.layout().main_wrap() {
        return;
    }
    let text_w = |t: egui::WidgetText, st: egui::TextStyle| {
        t.into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, st)
            .size()
            .x
    };
    let mark = text_w(
        RichText::new(texts::HELP_MARK).strong().into(),
        egui::TextStyle::Body,
    );
    let spacing = ui.spacing().item_spacing.x;
    let need = text_w(label.into(), style) + extra + spacing + mark + spacing;
    let at_line_start = ui.cursor().min.x <= ui.max_rect().min.x + 1.0;
    if !at_line_start && ui.available_width() < need {
        ui.end_row();
    }
}

/// Кнопка (может быть недоступной) с «?» рядом.
pub fn enabled_button_with_help(
    ui: &mut egui::Ui,
    enabled: bool,
    label: &str,
    help: &str,
) -> egui::Response {
    let pad = 2.0 * ui.spacing().button_padding.x;
    wrap_before(ui, label, egui::TextStyle::Button, pad);
    ui.horizontal(|ui| {
        let response = ui.add_enabled(enabled, egui::Button::new(label));
        help_mark(ui, help);
        response
    })
    .inner
}

/// Маленькая кнопка с «?» рядом (строки списков).
pub fn small_button_with_help(ui: &mut egui::Ui, label: &str, help: &str) -> egui::Response {
    let pad = 2.0 * ui.spacing().button_padding.x;
    wrap_before(ui, label, egui::TextStyle::Body, pad);
    ui.horizontal(|ui| {
        let response = ui.small_button(label);
        help_mark(ui, help);
        response
    })
    .inner
}

/// Галочка с «?» рядом.
pub fn checkbox_with_help(
    ui: &mut egui::Ui,
    enabled: bool,
    checked: &mut bool,
    label: &str,
    help: &str,
) -> egui::Response {
    let icon = ui.spacing().icon_width + ui.spacing().icon_spacing;
    wrap_before(ui, label, egui::TextStyle::Body, icon);
    ui.horizontal(|ui| {
        let response = ui.add_enabled(enabled, egui::Checkbox::new(checked, label));
        help_mark(ui, help);
        response
    })
    .inner
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
