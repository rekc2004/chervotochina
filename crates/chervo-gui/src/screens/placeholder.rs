//! Главное окно: навигация, уведомления и выбор экрана раздела. Разделы «Диагностика» и
//! «Настройки» пока заглушки (следующий шаг этапа 18).

use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model, Page};
use crate::screens::{add_friend, friends, offers, send, transfers};
use crate::texts;

const PAGES: [(Page, &str); 7] = [
    (Page::Friends, texts::NAV_FRIENDS),
    (Page::AddFriend, texts::NAV_ADD_FRIEND),
    (Page::Send, texts::NAV_SEND),
    (Page::Offers, texts::NAV_OFFERS),
    (Page::Transfers, texts::NAV_TRANSFERS),
    (Page::Diagnosis, texts::NAV_DIAGNOSIS),
    (Page::Settings, texts::NAV_SETTINGS),
];

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    ui.horizontal_wrapped(|ui| {
        for (page, label) in PAGES {
            let text = if page == Page::Offers && model.offers_waiting() > 0 {
                format!("{label} ({})", model.offers_waiting())
            } else {
                label.to_owned()
            };
            if ui.selectable_label(model.page == page, text).clicked() {
                out.push(Intent::Go(page));
            }
        }
    });
    ui.separator();
    if !model.notices.is_empty() {
        for notice in &model.notices {
            ui.label(*notice);
        }
        if ui.small_button(texts::NOTICES_HIDE).clicked() {
            out.push(Intent::Main(MainIntent::DismissNotices));
        }
        ui.separator();
    }
    match model.page {
        Page::Friends => out.extend(friends::show(ui, model)),
        Page::AddFriend => out.extend(add_friend::show(ui, model)),
        Page::Send => out.extend(send::show(ui, model)),
        Page::Offers => out.extend(offers::show(ui, model)),
        Page::Transfers => out.extend(transfers::show(ui, model)),
        Page::Diagnosis | Page::Settings => {
            ui.label(texts::PLACEHOLDER);
        }
    }
    out
}
