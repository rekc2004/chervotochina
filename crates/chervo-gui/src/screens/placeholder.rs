//! Заглушки разделов главного окна: содержимое экранов 2-9 добавляется следующими шагами
//! этапа 18. Здесь только навигация и признак того, что узел работает.

use eframe::egui;

use crate::model::{Intent, Model, Page};
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
            if ui.selectable_label(model.page == page, label).clicked() {
                out.push(Intent::Go(page));
            }
        }
    });
    ui.separator();
    for notice in &model.notices {
        ui.label(*notice);
    }
    let title = PAGES
        .iter()
        .find(|(p, _)| *p == model.page)
        .map_or("", |(_, l)| *l);
    ui.heading(title);
    ui.add_space(8.0);
    ui.label(texts::PLACEHOLDER);
    ui.add_space(8.0);
    ui.label(format!(
        "{}: {}",
        texts::FRIENDS_COUNT,
        model.snapshot.friends.len()
    ));
    ui.label(format!(
        "{}: {}",
        texts::ACTIVE_TRANSFERS,
        model.snapshot.active_transfers
    ));
    out
}
