//! Экран 4: отправка. Выбор файлов и папок (диалог и перетаскивание, оно разбирается в
//! `app.rs`), выбор друга, итог выбора. Ход передачи виден на экране «Передачи».

use chervo_core::FriendStatus;
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model, Section};
use crate::screens::common::{
    button_with_help, enabled_button_with_help, label_with_help, small_button_with_help, warn,
};
use crate::{picker, texts};

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let s = &model.send;
    // заголовок раздела и пояснение к нему рисует вкладка «Файлы»
    ui.horizontal_wrapped(|ui| {
        if enabled_button_with_help(ui, !s.busy, texts::BTN_PICK_FILES, texts::HELP_PICK_FILES)
            .clicked()
        {
            let picked = picker::pick_files();
            if !picked.is_empty() {
                out.push(main(MainIntent::PathsAdded(picked)));
            }
        }
        if enabled_button_with_help(ui, !s.busy, texts::BTN_PICK_DIR, texts::HELP_PICK_DIR)
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
            if small_button_with_help(ui, texts::BTN_REMOVE_ITEM, texts::HELP_REMOVE_ITEM).clicked()
            {
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
    label_with_help(ui, texts::SEND_TO, texts::HELP_SEND_TO);
    let usable: Vec<_> = model
        .snapshot
        .friends
        .iter()
        .filter(|f| f.status == FriendStatus::Active && !f.key_problem)
        .collect();
    if usable.is_empty() {
        ui.label(texts::SEND_NO_ACTIVE_FRIENDS);
        if button_with_help(ui, texts::BTN_GO_ADD_FRIEND, texts::HELP_GO_ADD_FRIEND).clicked() {
            out.push(Intent::GoSection(Section::AddFriend));
        }
    }
    ui.horizontal_wrapped(|ui| {
        for f in usable {
            let label = if f.online {
                f.name.clone()
            } else {
                format!("{} ({})", f.name, texts::STATE_OFFLINE)
            };
            let pick = ui.selectable_label(s.friend == Some(f.id), label); // без ?: «?» у подписи «Кому»
            if pick.clicked() {
                out.push(main(MainIntent::SendFriend(f.id)));
            }
        }
    });
    if let Some(e) = s.error {
        warn(ui, e);
    }
    ui.add_space(8.0);
    if enabled_button_with_help(
        ui,
        send_ready(model),
        texts::BTN_SEND,
        texts::HELP_SEND_FILES,
    )
    .clicked()
    {
        out.push(main(MainIntent::SendSubmit));
    }
    if let Some(why) = send_missing(model) {
        ui.label(why);
    }
    out
}

fn friend_chosen(model: &Model) -> bool {
    model.send.friend.is_some_and(|id| {
        model
            .snapshot
            .friends
            .iter()
            .any(|f| f.id == id && f.status == FriendStatus::Active && !f.key_problem)
    })
}

/// «Отправить» доступна, только когда выбраны файлы и друг (Ж6).
pub fn send_ready(model: &Model) -> bool {
    !model.send.busy && !model.send.paths.is_empty() && friend_chosen(model)
}

/// Чего не хватает для отправки; `None`, если всё выбрано.
pub fn send_missing(model: &Model) -> Option<&'static str> {
    match (model.send.paths.is_empty(), friend_chosen(model)) {
        (true, false) => Some(texts::SEND_MISSING_BOTH),
        (true, true) => Some(texts::SEND_NO_FILES),
        (false, false) => Some(texts::SEND_NO_FRIEND),
        (false, true) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::{FriendRow, Id, PickedPath};

    fn model_with_friend() -> Model {
        let mut m = Model::preview();
        m.snapshot.friends.push(FriendRow {
            id: Id(1),
            name: "Маша".to_owned(),
            status: FriendStatus::Active,
            online: true,
            auto_accept: false,
            key_problem: false,
            path: None,
        });
        m
    }

    #[test]
    fn send_is_disabled_until_files_and_friend_chosen() {
        let mut m = model_with_friend();
        assert!(!send_ready(&m));
        assert_eq!(send_missing(&m), Some(texts::SEND_MISSING_BOTH));
        m.send.friend = Some(Id(1));
        assert!(!send_ready(&m));
        assert_eq!(send_missing(&m), Some(texts::SEND_NO_FILES));
        m.send.friend = None;
        m.send.paths.push(PickedPath {
            path: "a.txt".into(),
            is_dir: false,
            size: 1,
        });
        assert!(!send_ready(&m));
        assert_eq!(send_missing(&m), Some(texts::SEND_NO_FRIEND));
        m.send.friend = Some(Id(1));
        assert!(send_ready(&m));
        assert_eq!(send_missing(&m), None);
        m.send.busy = true;
        assert!(!send_ready(&m));
    }
}
