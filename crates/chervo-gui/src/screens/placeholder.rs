//! Главное окно: навигация, уведомления (экран 9) и выбор экрана раздела.

use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model, Page};
use crate::screens::{add_friend, diagnosis, friends, offers, send, settings, transfers, update};
use crate::texts;

const PAGES: [(Page, &str); 8] = [
    (Page::Friends, texts::NAV_FRIENDS),
    (Page::AddFriend, texts::NAV_ADD_FRIEND),
    (Page::Send, texts::NAV_SEND),
    (Page::Offers, texts::NAV_OFFERS),
    (Page::Transfers, texts::NAV_TRANSFERS),
    (Page::Diagnosis, texts::NAV_DIAGNOSIS),
    (Page::Settings, texts::NAV_SETTINGS),
    (Page::Updates, texts::NAV_UPDATES),
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
    if model.consent_card_visible() {
        update::consent_card(ui, &mut out);
        ui.separator();
    }
    if model.update.newer.is_some() {
        update::newer_card(ui, model, &mut out);
        ui.separator();
    }
    if !model.notices.is_empty() {
        for notice in &model.notices {
            ui.label(notice);
        }
        if model.clock_hint && ui.button(texts::BTN_CLOCK_HINT).clicked() {
            out.push(Intent::Go(Page::Settings));
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
        Page::Diagnosis => out.extend(diagnosis::show(ui, model)),
        Page::Settings => out.extend(settings::show(ui, model)),
        Page::Updates => out.extend(update::show(ui, model)),
    }
    out
}
