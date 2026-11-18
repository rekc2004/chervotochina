//! Экраны. Каждый только рисует состояние модели и возвращает намерения пользователя. Вызовов
//! узла здесь нет и быть не может (охрана `tests/ui_thread.rs`).

mod access;
mod add_friend;
mod close;
mod common;
mod diagnosis;
mod friends;
mod offers;
mod placeholder;
mod send;
mod settings;
mod start;
mod transfers;
mod update;

use eframe::egui;

use crate::model::{Close, Intent, Model};

#[cfg(test)]
pub use access::{gateway_url, manual_values};
#[cfg(test)]
pub use add_friend::invite_ext_note;

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    if model.close != Close::None {
        close::show(ui, model.close)
    } else if model.node_open {
        placeholder::show(ui, model)
    } else {
        start::show(ui, &model.start)
    }
}

/// Все тексты, которые экран рисует для этой модели (одной строкой), без всплывающих подсказок.
/// Для проверок «какая кнопка и какая подпись на экране» без окна и видеокарты.
#[cfg(test)]
pub fn rendered_texts(model: &Model) -> String {
    fn collect(shape: &egui::epaint::Shape, out: &mut String) {
        match shape {
            egui::epaint::Shape::Text(t) => {
                out.push_str(t.galley.text());
                out.push('\n');
            }
            egui::epaint::Shape::Vec(v) => {
                for s in v {
                    collect(s, out);
                }
            }
            _ => {}
        }
    }
    let ctx = egui::Context::default();
    let mut out = String::new();
    // второй кадр: раскладка устанавливается после первого
    for _ in 0..2 {
        out.clear();
        let mut full = ctx.run_ui(egui::RawInput::default(), |ui| {
            let _ = show(ui, model);
        });
        // картинки шрифта никому не нужны, но `Drop` требует их снять
        full.textures_delta.clear();
        for clipped in &full.shapes {
            collect(&clipped.shape, &mut out);
        }
    }
    out
}
