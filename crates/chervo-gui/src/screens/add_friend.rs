//! Экран 3: добавить друга. Создание приглашения, кнопка «Друг прислал мне текст» (одно поле
//! для любого текста от друга), ожидание и экран проверочного кода (8 цифр группами 4+4,
//! подпись для диктора цифра за цифрой).

use std::time::{Duration, Instant};

use eframe::egui::{self, FontId, RichText, Role, Sense, WidgetInfo};

use crate::main_model::{AddFriend, AddStage, Dialog, MainIntent, SasState};
use crate::model::{Intent, Model};
use crate::qr::QrMatrix;
use crate::screens::common::{copy_box, warn};
use crate::screens::friends::friend_text_dialog;
use crate::texts;

/// Как часто перерисовывать окно, пока показан срок приглашения.
const VALID_REPAINT: Duration = Duration::from_secs(15);

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let a = &model.add;
    // поле «Друг прислал мне текст» открыто с этой вкладки: оно занимает место формы
    if let (Dialog::FriendText(p), AddStage::Form { .. }) = (&model.dialog, &a.stage) {
        friend_text_dialog(ui, p, &mut out);
        return out;
    }
    match &a.stage {
        AddStage::Form { busy } => form(ui, a, *busy, &mut out),
        AddStage::Waiting {
            token, qr, valid, ..
        } => waiting(ui, token.as_deref(), qr.as_ref(), *valid, &mut out),
        AddStage::Sas(s) => sas(ui, s, &mut out),
        AddStage::Finished(text) => {
            ui.label(*text);
            ui.add_space(8.0);
            if ui.button(texts::BTN_OK).clicked() {
                out.push(main(MainIntent::AddDone));
            }
        }
    }
    out
}

fn form(ui: &mut egui::Ui, a: &AddFriend, busy: bool, out: &mut Vec<Intent>) {
    // друг уже прислал текст: приглашение, новый адрес или уведомление об удалении
    if ui
        .add_enabled(!busy, egui::Button::new(texts::BTN_FRIEND_TEXT))
        .clicked()
    {
        out.push(main(MainIntent::FriendTextOpen));
    }
    ui.separator();
    let mut same = a.same_network;
    if ui
        .add_enabled(
            !busy,
            egui::Checkbox::new(&mut same, texts::LABEL_SAME_NETWORK),
        )
        .changed()
    {
        out.push(main(MainIntent::AddSameNetwork(same)));
    }
    ui.add_space(6.0);
    ui.label(texts::ADD_MANUAL_LABEL);
    let mut manual = a.manual_addr.clone();
    if ui
        .add_enabled(!busy, egui::TextEdit::singleline(&mut manual))
        .changed()
    {
        out.push(main(MainIntent::AddManualEdited(manual)));
    }
    warn(ui, texts::IP_WARNING);
    if let Some(e) = a.error {
        warn(ui, e);
    }
    ui.add_space(8.0);
    if ui
        .add_enabled(!busy, egui::Button::new(texts::BTN_CREATE_INVITE))
        .clicked()
    {
        out.push(main(MainIntent::AddCreate));
    }
}

fn waiting(
    ui: &mut egui::Ui,
    token: Option<&str>,
    qr: Option<&QrMatrix>,
    valid: Option<(Instant, u64)>,
    out: &mut Vec<Intent>,
) {
    match token {
        Some(t) => {
            ui.label(texts::INVITE_WAIT);
            if let Some((created, ttl)) = valid {
                let left = ttl.saturating_sub(created.elapsed().as_secs());
                ui.label(texts::invite_valid_text(left));
                if left > 0 {
                    ui.ctx().request_repaint_after(VALID_REPAINT);
                }
            }
            warn(ui, texts::IP_WARNING);
            copy_box(ui, t);
            if let Some(q) = qr {
                ui.add_space(8.0);
                draw_qr(ui, q);
            }
        }
        None => {
            ui.label(texts::INVITE_ACCEPT_WAIT);
        }
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.spinner();
        if ui.button(texts::BTN_CANCEL).clicked() {
            out.push(main(MainIntent::AddCancel));
        }
    });
}

fn draw_qr(ui: &mut egui::Ui, q: &QrMatrix) {
    let cell = 4.0_f32;
    let quiet = 4.0_f32;
    let side = (q.width as f32 + 2.0 * quiet) * cell;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(side, side), Sense::hover());
    // QR только для глаз; тот же текст доступен выше как обычный
    response.widget_info(|| WidgetInfo::labeled(Role::Image, true, "QR-код приглашения"));
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, egui::Color32::WHITE);
    for y in 0..q.width {
        for x in 0..q.width {
            if q.dark.get(y * q.width + x).copied().unwrap_or(false) {
                let min =
                    rect.min + egui::vec2((x as f32 + quiet) * cell, (y as f32 + quiet) * cell);
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }
    }
}

fn sas(ui: &mut egui::Ui, s: &SasState, out: &mut Vec<Intent>) {
    ui.heading(texts::SAS_TITLE);
    ui.label(texts::SAS_HINT);
    ui.add_space(12.0);
    // 8 цифр группами 4+4 крупно; диктор читает цифру за цифрой
    let digits = ui.label(RichText::new(&s.digits).font(FontId::monospace(56.0)));
    let digits = digits.interact(Sense::focusable_noninteractive());
    digits.widget_info(|| WidgetInfo::labeled(Role::Label, true, s.spoken.as_str()));
    ui.add_space(12.0);
    ui.label(texts::LABEL_NAME);
    let mut name = s.name.clone();
    if ui
        .add_enabled(!s.busy, egui::TextEdit::singleline(&mut name))
        .changed()
    {
        out.push(main(MainIntent::SasNameEdited(name)));
    }
    if let Some(e) = s.error {
        warn(ui, e);
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!s.busy, egui::Button::new(texts::BTN_SAS_MATCH))
            .clicked()
        {
            out.push(main(MainIntent::SasMatch));
        }
        if ui
            .add_enabled(!s.busy, egui::Button::new(texts::BTN_SAS_MISMATCH))
            .clicked()
        {
            out.push(main(MainIntent::SasMismatch));
        }
    });
    // после «Совпадает» кнопки серые: без этой строки кажется, что программа зависла
    if s.waiting {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(texts::SAS_WAITING);
        });
    }
}
