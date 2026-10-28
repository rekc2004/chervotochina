//! Экран 4: отправка. Выбор файлов и папок (диалог и перетаскивание, оно разбирается в
//! `app.rs`), выбор друга, итог выбора. Ход передачи виден на экране «Передачи».

use chervo_core::FriendStatus;
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::screens::common::warn;
use crate::{picker, texts};

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let s = &model.send;
    ui.heading(texts::SEND_TITLE);
    ui.label(texts::SEND_HINT);
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!s.busy, egui::Button::new(texts::BTN_PICK_FILES))
            .clicked()
        {
            let picked = picker::pick_files();
            if !picked.is_empty() {
                out.push(main(MainIntent::PathsAdded(picked)));
            }
        }
        if ui
            .add_enabled(!s.busy, egui::Button::new(texts::BTN_PICK_DIR))
            .clicked()
            && let Some(p) = picker::pick_dir_to_send()
        {
            out.push(main(MainIntent::PathsAdded(vec![p])));
        }
    });
    ui.add_space(6.0);
    let mut files = 0usize;
    let mut dirs = 0usize;
    let mut total = 0u64;
    for (i, p) in s.paths.iter().enumerate() {
        ui.horizontal(|ui| {
            let label = if p.is_dir {
                format!("[{}] {}", texts::FOLDER_WORD, p.path.display())
            } else {
                format!("{} ({})", p.path.display(), texts::human_size(p.size))
            };
            ui.label(label);
            if ui.small_button(texts::BTN_REMOVE_ITEM).clicked() {
                out.push(main(MainIntent::PathRemoved(i)));
            }
        });
        if p.is_dir {
            dirs += 1;
        } else {
            files += 1;
            total = total.saturating_add(p.size);
        }
    }
    if !s.paths.is_empty() {
        // папки считает узел при отправке: здесь размер только отдельных файлов
        ui.label(texts::send_summary(files, dirs, total));
    }
    ui.add_space(8.0);
    ui.label(texts::SEND_TO);
    let usable: Vec<_> = model
        .snapshot
        .friends
        .iter()
        .filter(|f| f.status == FriendStatus::Active && !f.key_problem)
        .collect();
    if usable.is_empty() {
        ui.label(texts::SEND_NO_ACTIVE_FRIENDS);
    }
    ui.horizontal_wrapped(|ui| {
        for f in usable {
            let label = if f.online {
                f.name.clone()
            } else {
                format!("{} ({})", f.name, texts::STATE_OFFLINE)
            };
            if ui.selectable_label(s.friend == Some(f.id), label).clicked() {
                out.push(main(MainIntent::SendFriend(f.id)));
            }
        }
    });
    if let Some(e) = s.error {
        warn(ui, e);
    }
    ui.add_space(8.0);
    if ui
        .add_enabled(!s.busy, egui::Button::new(texts::BTN_SEND))
        .clicked()
    {
        out.push(main(MainIntent::SendSubmit));
    }
    out
}
