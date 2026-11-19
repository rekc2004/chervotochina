//! Главное окно: три вкладки (Друзья, Файлы, Настройки), уведомления (экран 9) и выбор экрана.
//! Остальные экраны лежат разделами внутри вкладок (этап 18г).

use eframe::egui;

use crate::main_model::{Dialog, MainIntent};
use crate::model::{Intent, Model, Page, Section};
use crate::screens::common::{button_with_help, help_mark};
use crate::screens::{
    access, add_friend, diagnosis, friends, offers, send, settings, transfers, update,
};
use crate::texts;

/// Три вкладки главного окна: остальное лежит разделами внутри них.
const PAGES: [(Page, &str); 3] = [
    (Page::Friends, texts::NAV_FRIENDS),
    (Page::Files, texts::NAV_FILES),
    (Page::Settings, texts::NAV_SETTINGS),
];

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    ui.horizontal_wrapped(|ui| {
        for (page, label) in PAGES {
            // счётчик ожидающих входящих живёт на ярлыке вкладки «Файлы»
            let text = if page == Page::Files && model.offers_waiting() > 0 {
                format!("{label} ({})", model.offers_waiting())
            } else {
                label.to_owned()
            };
            let tab = ui.selectable_label(model.page == page, text); // без ?: очевидная
            if tab.clicked() {
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
        if model.clock_hint
            && button_with_help(ui, texts::BTN_CLOCK_HINT, texts::HELP_SYNC_CLOCK).clicked()
        {
            out.push(Intent::Go(Page::Settings));
        }
        let hide = ui.small_button(texts::NOTICES_HIDE); // без ?: очевидная
        if hide.clicked() {
            out.push(Intent::Main(MainIntent::DismissNotices));
        }
        ui.separator();
    }
    // помощник «Разрешить входящие подключения» занимает место вкладки, пока открыт
    if model.access.open {
        out.extend(access::show(ui, model));
        return out;
    }
    match model.page {
        Page::Friends => friends_tab(ui, model, &mut out),
        Page::Files => files_tab(ui, model, &mut out),
        Page::Settings => settings_tab(ui, model, &mut out),
    }
    // переход к разделу выполнен за этот кадр: отметка снимается
    if model.scroll_to.is_some() {
        out.push(Intent::SectionShown);
    }
    out
}

/// Заголовок раздела внутри вкладки; если к нему ведёт переход, вкладка прокручивается к нему.
fn section_heading(
    ui: &mut egui::Ui,
    model: &Model,
    section: Section,
    title: &str,
    help: Option<&str>,
) {
    let response = ui
        .horizontal(|ui| {
            let r = ui.heading(title);
            if let Some(help) = help {
                help_mark(ui, help);
            }
            r
        })
        .inner;
    if model.scroll_to == Some(section) {
        response.scroll_to_me(Some(egui::Align::TOP));
    }
}

/// «Друзья»: список, под ним сворачиваемый раздел «Добавить друга» (развёрнут, пока друзей нет).
fn friends_tab(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    // диалог (переименование, вопросы, «Друг прислал мне текст») занимает место всей вкладки
    if !matches!(model.dialog, Dialog::None) {
        out.extend(friends::show(ui, model));
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        out.extend(friends::show(ui, model));
        ui.separator();
        let no_friends = model.snapshot.friends.is_empty();
        let target = model.scroll_to == Some(Section::AddFriend);
        let mut header =
            egui::CollapsingHeader::new(egui::RichText::new(texts::NAV_ADD_FRIEND).heading())
                .id_salt(("add-friend-section", no_friends))
                .default_open(no_friends);
        if target {
            header = header.open(Some(true));
        }
        let shown = header.show(ui, |ui| {
            out.extend(add_friend::show(ui, model));
        });
        if target {
            shown.header_response.scroll_to_me(Some(egui::Align::TOP));
        }
    });
}

/// «Файлы»: входящие (только если есть), отправка, передачи.
fn files_tab(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        if model.offers_waiting() > 0 {
            section_heading(ui, model, Section::Offers, texts::NAV_OFFERS, None);
            out.extend(offers::show(ui, model));
            ui.separator();
        }
        section_heading(
            ui,
            model,
            Section::Send,
            texts::NAV_SEND,
            Some(texts::HELP_SEND_SECTION),
        );
        out.extend(send::show(ui, model));
        ui.separator();
        section_heading(ui, model, Section::Transfers, texts::NAV_TRANSFERS, None);
        out.extend(transfers::show(ui, model));
    });
}

/// «Настройки»: настройки с обновлениями, затем «Диагностика».
fn settings_tab(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        out.extend(settings::show(ui, model));
        ui.separator();
        section_heading(ui, model, Section::Diagnosis, texts::NAV_DIAGNOSIS, None);
        out.extend(diagnosis::show(ui, model));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_model::Dialog;

    #[test]
    fn no_updates_tab() {
        // вкладок ровно три; «Обновления» не вкладка, а раздел «Настроек»
        assert_eq!(PAGES.len(), 3);
        let labels: Vec<&str> = PAGES.iter().map(|(_, label)| *label).collect();
        assert_eq!(
            labels,
            [texts::NAV_FRIENDS, texts::NAV_FILES, texts::NAV_SETTINGS]
        );
        assert!(PAGES.iter().all(|(_, label)| *label != texts::NAV_UPDATES));
    }

    fn lines(m: &Model) -> Vec<String> {
        crate::screens::rendered_texts(m)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn has_line(seen: &[String], text: &str) -> bool {
        seen.iter().any(|l| l == text)
    }

    fn fixture(page: Page, pick: impl Fn(&Model) -> bool) -> Model {
        crate::fixtures::all()
            .into_iter()
            .find(|m| {
                m.node_open
                    && m.close == crate::model::Close::None
                    && !m.access.open
                    && m.page == page
                    && pick(m)
            })
            .expect("нет подходящей фикстуры")
    }

    #[test]
    fn go_section_opens_tab_and_flag_clears_after_one_frame() {
        let mut m = Model::preview();
        m.node_open = true;
        assert!(m.update(Intent::GoSection(Section::Transfers)).is_empty());
        assert_eq!(m.page, Page::Files);
        assert_eq!(m.scroll_to, Some(Section::Transfers));
        // диагностика лежит в «Настройках»: снимок перечитывается, как при обычном входе
        let cmds = m.update(Intent::GoSection(Section::Diagnosis));
        assert_eq!(m.page, Page::Settings);
        assert_eq!(cmds.len(), 1);
        // экран возвращает намерение, пока отметка стоит; после него отметки нет
        let out = show_once(&m);
        assert!(out.contains(&Intent::SectionShown));
        m.update(Intent::SectionShown);
        assert_eq!(m.scroll_to, None);
        assert!(!show_once(&m).contains(&Intent::SectionShown));
    }

    fn show_once(m: &Model) -> Vec<Intent> {
        let ctx = egui::Context::default();
        let mut out = Vec::new();
        let mut full = ctx.run_ui(egui::RawInput::default(), |ui| {
            out = show(ui, m);
        });
        full.textures_delta.clear();
        out
    }

    #[test]
    fn friends_tab_collapses_add_friend_only_when_friends_exist() {
        let mut m = fixture(Page::Friends, |m| {
            !m.snapshot.friends.is_empty()
                && matches!(m.dialog, Dialog::None)
                && m.scroll_to.is_none()
        });
        let seen = lines(&m);
        assert!(has_line(&seen, texts::NAV_ADD_FRIEND), "{seen:?}");
        assert!(!has_line(&seen, texts::BTN_CREATE_INVITE), "{seen:?}");
        // переход к разделу разворачивает его
        m.scroll_to = Some(Section::AddFriend);
        assert!(has_line(&lines(&m), texts::BTN_CREATE_INVITE));
        // друзей нет: раздел развёрнут сам
        m.scroll_to = None;
        m.snapshot.friends.clear();
        assert!(has_line(&lines(&m), texts::BTN_CREATE_INVITE));
    }

    #[test]
    fn files_tab_shows_incoming_only_when_waiting_and_counts_on_the_label() {
        let with = fixture(Page::Files, |m| !m.snapshot.offers.is_empty());
        let seen = lines(&with);
        for title in [texts::NAV_OFFERS, texts::NAV_SEND, texts::NAV_TRANSFERS] {
            assert!(has_line(&seen, title), "{title}: {seen:?}");
        }
        let label = format!("{} ({})", texts::NAV_FILES, with.offers_waiting());
        assert!(has_line(&seen, &label), "{label}: {seen:?}");
        let without = fixture(Page::Files, |m| m.snapshot.offers.is_empty());
        let seen = lines(&without);
        assert!(!has_line(&seen, texts::NAV_OFFERS), "{seen:?}");
        assert!(has_line(&seen, texts::NAV_SEND));
        assert!(has_line(&seen, texts::NAV_FILES));
    }

    #[test]
    fn settings_tab_holds_updates_and_diagnosis() {
        let m = fixture(Page::Settings, |m| m.snapshot.settings.is_some());
        let seen = lines(&m);
        assert!(has_line(&seen, texts::SET_TITLE_FOLDERS), "{seen:?}");
        assert!(has_line(&seen, texts::NAV_UPDATES));
        assert!(has_line(&seen, texts::NAV_DIAGNOSIS));
    }
}
