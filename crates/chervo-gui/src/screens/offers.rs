//! Экран 5: входящие предложения. Показываются только санитизированные имена из плана приёма
//! (так их отдаёт узел), тип файла, предупреждения этапа 15, вопрос о доверии для рискованных
//! файлов, проверка места. Ничего не открывается и не запускается.

use chervo_core::FileKind;
use chervo_core::texts as core_texts;
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::rows::OfferRow;
use crate::screens::common::warn;
use crate::{picker, texts};

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    if model.snapshot.offers.is_empty() {
        ui.label(texts::OFFERS_EMPTY);
        return out;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for o in &model.snapshot.offers {
            offer(ui, model, o, &mut out);
            ui.add_space(8.0);
        }
    });
    out
}

fn kind_label(k: FileKind) -> &'static str {
    match k {
        FileKind::Safe => texts::KIND_SAFE,
        FileKind::ExecutableLike => texts::KIND_EXEC,
        _ => texts::KIND_UNKNOWN,
    }
}

fn offer(ui: &mut egui::Ui, model: &Model, o: &OfferRow, out: &mut Vec<Intent>) {
    let ui_state = model.offer_ui.get(&o.id).copied().unwrap_or_default();
    ui.group(|ui| {
        ui.strong(format!("{}: {}", texts::OFFER_FROM, o.friend));
        ui.label(texts::offer_summary(o.files.len(), o.total));
        // строки рисуются только видимые: в предложении может быть до 10 000 файлов
        let row_height = ui.text_style_height(&egui::TextStyle::Body);
        egui::ScrollArea::vertical()
            .id_salt(("offer-files", o.id.0))
            .max_height(180.0)
            .show_rows(ui, row_height, o.files.len(), |ui, range| {
                for f in &o.files[range] {
                    let mark = if f.needs_question {
                        texts::MARK_RISKY
                    } else {
                        ""
                    };
                    ui.label(format!(
                        "{mark}{} ({}, {})",
                        f.name,
                        texts::human_size(f.size),
                        kind_label(f.kind)
                    ));
                }
            });
        for w in &o.warnings {
            warn(ui, w);
        }
        // место: сколько нужно и сколько есть
        match o.space.available {
            Some(avail) => {
                ui.label(texts::space_line(o.space.needed, avail));
            }
            None => {
                ui.label(texts::OFFER_SPACE_UNKNOWN);
            }
        }
        if o.space.short {
            warn(ui, core_texts::CHOOSE_OTHER_FOLDER_TEXT);
        }
        if o.needs_question {
            let mut ack = ui_state.ack;
            if ui.checkbox(&mut ack, core_texts::ASK_FILE_TEXT).changed() {
                out.push(main(MainIntent::OfferAck(o.id, ack)));
            }
        }
        ui.horizontal_wrapped(|ui| {
            let can = !ui_state.busy && (!o.needs_question || ui_state.ack);
            if ui
                .add_enabled(can && !o.space.short, egui::Button::new(texts::BTN_ACCEPT))
                .clicked()
            {
                out.push(main(MainIntent::OfferAccept(o.id)));
            }
            if ui
                .add_enabled(can, egui::Button::new(texts::BTN_OTHER_FOLDER))
                .clicked()
                && let Some(root) = picker::pick_folder()
            {
                out.push(main(MainIntent::OfferAcceptInto { id: o.id, root }));
            }
            if ui
                .add_enabled(!ui_state.busy, egui::Button::new(texts::BTN_DECLINE))
                .clicked()
            {
                out.push(main(MainIntent::OfferDecline(o.id)));
            }
        });
    });
}
