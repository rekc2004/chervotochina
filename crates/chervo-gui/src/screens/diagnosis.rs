//! Экран 7: диагностика. Причина по каждому другу без соединения (текст из ядра), сводка по
//! вашей сети, кнопка «Соединить». Сервер-посредник: только честный текст «появится в
//! следующей версии»; кнопки согласия, поля адреса сервера и любого пути к серверу нет.

use chervo_core::texts as core_texts;
use chervo_core::{FriendStatus, MapStatus, NatView};
use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::screens::common::warn;
use crate::texts;

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

/// Короткая сводка о вашей сети по `NatView`; длинные объяснения берутся из ядра.
pub fn nat_text(n: NatView) -> &'static str {
    match n {
        NatView::NoIpv4 => texts::NAT_NO_IPV4,
        NatView::Public => texts::NAT_PUBLIC,
        NatView::PortMapped => texts::NAT_MAPPED,
        NatView::BehindCgnat => core_texts::CGNAT_TEXT,
        NatView::DoubleNat => core_texts::DOUBLE_NAT_TEXT,
        NatView::Conflicting => texts::NAT_CONFLICT,
        NatView::Symmetric => core_texts::SYMMETRIC_TEXT,
        NatView::Eim => texts::NAT_EIM,
        NatView::ManualForward => texts::NAT_MANUAL,
        _ => texts::NAT_UNKNOWN,
    }
}

fn has_active_friends(model: &Model) -> bool {
    model
        .snapshot
        .friends
        .iter()
        .any(|f| f.status == FriendStatus::Active)
}

/// Текст под «Ваша сеть». При нуле друзей сеть ещё не проверялась: вместо вывода о сети
/// сообщаем об этом (Ж20).
pub fn net_text(model: &Model) -> Option<&'static str> {
    if !has_active_friends(model) {
        return Some(texts::DIAG_NET_NO_FRIENDS);
    }
    model.snapshot.nat.map(nat_text)
}

/// «Ещё раз» только если порт уже открывался: проброс удался или роутер уже разрешён.
pub fn refresh_label(model: &Model) -> &'static str {
    let opened = matches!(
        model.snapshot.mapping,
        Some(MapStatus::Mapped | MapStatus::MappedPermanent)
    ) || model
        .snapshot
        .settings
        .as_ref()
        .is_some_and(|s| !s.routers.is_empty());
    if opened {
        texts::BTN_REFRESH_MAPPING
    } else {
        texts::BTN_OPEN_PORT
    }
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    ui.heading(texts::DIAG_TITLE);
    ui.strong(texts::DIAG_NAT_TITLE);
    if let Some(t) = net_text(model) {
        ui.label(t);
    }
    if let Some(m) = model.snapshot.mapping {
        ui.label(core_texts::mapping_text(m));
    }
    if ui.button(refresh_label(model)).clicked() {
        out.push(main(MainIntent::Settings(
            crate::settings_model::SettingsIntent::MappingRefresh,
        )));
    }
    ui.separator();
    let friends: Vec<_> = model
        .snapshot
        .friends
        .iter()
        .filter(|f| f.status == FriendStatus::Active)
        .collect();
    if friends.is_empty() {
        ui.label(texts::DIAG_NO_FRIENDS);
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for f in friends {
            ui.group(|ui| {
                ui.strong(&f.name);
                if f.key_problem {
                    warn(ui, core_texts::KEY_LOST_TEXT);
                } else if f.online {
                    ui.label(texts::DIAG_CONNECTED);
                } else if let Some(d) = model.snapshot.diagnoses.iter().find(|d| d.friend == f.id) {
                    ui.label(d.text);
                    if d.lan_hint {
                        warn(ui, texts::LAN_EXPIRED_HINT);
                    }
                    if d.could_help {
                        // посредника в этой версии нет: ни кнопки, ни поля, только текст
                        ui.label(texts::MEDIATOR_LATER);
                    }
                } else {
                    ui.label(texts::DIAG_NO_REASON);
                }
                if !f.online && !f.key_problem && ui.button(texts::BTN_CONNECT).clicked() {
                    out.push(main(MainIntent::ConnectNow(f.id)));
                }
                // С5: до итога «Соединить» показывает, что попытка идёт
                if !f.online && model.connecting.contains(&f.id) {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(texts::CONNECTING);
                    });
                }
            });
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::{FriendRow, Id};

    fn friend() -> FriendRow {
        FriendRow {
            id: Id(1),
            name: "Маша".to_owned(),
            status: FriendStatus::Active,
            online: false,
            auto_accept: false,
            key_problem: false,
            path: None,
        }
    }

    #[test]
    fn zero_friends_never_show_friend_text_under_own_network() {
        let mut m = Model::preview();
        m.snapshot.nat = Some(NatView::Unknown);
        assert_eq!(net_text(&m), Some(texts::DIAG_NET_NO_FRIENDS));
        assert_ne!(net_text(&m), Some(core_texts::UNKNOWN_TEXT));
        assert_eq!(refresh_label(&m), texts::BTN_OPEN_PORT);
        // с другом неизвестное состояние сети тоже не говорит про друга
        m.snapshot.friends.push(friend());
        assert_eq!(net_text(&m), Some(texts::NAT_UNKNOWN));
        assert_ne!(nat_text(NatView::Unknown), core_texts::UNKNOWN_TEXT);
    }

    #[test]
    fn again_only_after_port_was_opened() {
        let mut m = Model::preview();
        assert_eq!(refresh_label(&m), texts::BTN_OPEN_PORT);
        m.snapshot.mapping = Some(MapStatus::Mapped);
        assert_eq!(refresh_label(&m), texts::BTN_REFRESH_MAPPING);
    }
}
