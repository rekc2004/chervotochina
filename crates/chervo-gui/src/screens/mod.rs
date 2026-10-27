//! Экраны. Каждый только рисует состояние модели и возвращает намерения пользователя. Вызовов
//! узла здесь нет и быть не может (охрана `tests/ui_thread.rs`).

mod add_friend;
mod close;
mod common;
mod friends;
mod offers;
mod placeholder;
mod send;
mod start;
mod transfers;

use eframe::egui;

use crate::model::{Close, Intent, Model};

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    if model.close != Close::None {
        close::show(ui, model.close)
    } else if model.node_open {
        placeholder::show(ui, model)
    } else {
        start::show(ui, &model.start)
    }
}
