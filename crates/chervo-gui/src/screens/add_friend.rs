//! Экран 3: добавить друга. Вкладки «Пригласить» и «Принять приглашение», ожидание и экран
//! проверочного кода (8 цифр группами 4+4, подпись для диктора цифра за цифрой).

use eframe::egui::{self, FontId, RichText, Role, Sense, WidgetInfo};

use crate::main_model::{AddFriend, AddStage, MainIntent, SasState, Tab};
use crate::model::{Intent, Model};
use crate::qr::QrMatrix;
use crate::screens::common::{copy_box, warn};
use crate::texts;
use chervo_core::texts as core_texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let a = &model.add;
    match &a.stage {
        AddStage::Form { busy } => form(ui, a, *busy, &mut out),
        AddStage::Waiting { token, qr, .. } => waiting(ui, token.as_deref(), qr.as_ref(), &mut out),
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
    ui.horizontal(|ui| {
        if ui
            .selectable_label(a.tab == Tab::Invite, texts::ADD_TAB_INVITE)
            .clicked()
        {
            out.push(main(MainIntent::AddTab(Tab::Invite)));
        }
        if ui
            .selectable_label(a.tab == Tab::Accept, texts::ADD_TAB_ACCEPT)
            .clicked()
        {
            out.push(main(MainIntent::AddTab(Tab::Accept)));
        }
    });
    ui.separator();
    match a.tab {
        Tab::Invite => {
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
        Tab::Accept => {
            ui.label(texts::LABEL_PASTE_HERE);
            let mut paste = a.paste.clone();
            let edit = egui::TextEdit::multiline(&mut paste)
                .desired_width(f32::INFINITY)
                .desired_rows(5);
            if ui.add_enabled(!busy, edit).changed() {
                out.push(main(MainIntent::AddPasteEdited(paste)));
            }
            if a.paste_too_long {
                warn(ui, core_texts::INPUT_TOO_LONG_TEXT);
            }
            if let Some(e) = a.error {
                warn(ui, e);
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(!busy, egui::Button::new(texts::BTN_ACCEPT_INVITE))
                .clicked()
            {
                out.push(main(MainIntent::AddAcceptSubmit));
            }
        }
    }
}

fn waiting(ui: &mut egui::Ui, token: Option<&str>, qr: Option<&QrMatrix>, out: &mut Vec<Intent>) {
    match token {
        Some(t) => {
            ui.label(texts::INVITE_WAIT);
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
}
