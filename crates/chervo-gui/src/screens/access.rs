//! Помощник «Разрешить входящие подключения» (этап 13д, Р10). Сначала попытка договориться с
//! роутером самой программой (поиск и вопрос только по кнопке), затем пошаговая инструкция со
//! значениями программы и «Копировать» у каждого, затем «Проверить». Только рисует и возвращает
//! намерения. Пояснения спрятаны за значок «?»; вопрос о роутере и заметные предупреждения
//! (VPN, общий адрес у провайдера) остаются на виду.

use std::time::Duration;

use chervo_core::NatView;
use chervo_core::texts as core_texts;
use eframe::egui;

use crate::access_model::{
    AccessIntent, AccessStage, AccessUi, CheckResult, CheckUi, check_fail_text,
};
use crate::main_model::MainIntent;
use crate::model::{Intent, Model};
use crate::screens::common::{copy_line, help_mark, warn};
use crate::settings_model::SettingsIntent;
use crate::texts;

/// Как часто перерисовывать окно, пока ждём ответа роутера.
const WAIT_REPAINT: Duration = Duration::from_millis(500);

fn acc(i: AccessIntent) -> Intent {
    Intent::Main(MainIntent::Access(i))
}

/// Адрес страницы роутера для шага 1 (`None`: адреса нет, показывается только подсказка).
pub fn gateway_url(a: &AccessUi) -> Option<String> {
    a.help
        .as_ref()
        .and_then(|h| h.gw)
        .map(|gw| format!("http://{gw}"))
}

/// Значения для шага 4 (подпись, значение), у каждого своя кнопка «Копировать». Пусто, пока
/// значения не получены от узла.
pub fn manual_values(a: &AccessUi) -> Vec<(&'static str, String)> {
    let Some(h) = &a.help else {
        return Vec::new();
    };
    let mut rows = vec![
        (texts::ACC_F_NAME, texts::ACC_V_NAME.to_owned()),
        (texts::ACC_F_PROTO, texts::ACC_V_PROTO.to_owned()),
        (texts::ACC_F_EXT_PORT, h.port.to_string()),
    ];
    for ip in &h.home {
        rows.push((texts::ACC_F_INT_IP, ip.to_string()));
    }
    rows.push((texts::ACC_F_INT_PORT, h.port.to_string()));
    rows
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let a = &model.access;
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(texts::ACC_TITLE);
            help_mark(ui, texts::ACC_INTRO);
        });
        if a.help.as_ref().is_some_and(|h| h.vpn) {
            warn(ui, texts::ACC_VPN);
        }
        if matches!(
            model.snapshot.nat,
            Some(NatView::BehindCgnat | NatView::DoubleNat)
        ) {
            warn(ui, texts::ACC_CGNAT);
        }
        ui.add_space(6.0);
        auto(ui, model, &mut out);
        ui.separator();
        manual(ui, a);
        ui.separator();
        check(ui, a, &mut out);
        ui.add_space(8.0);
        if ui.button(texts::BTN_CLOSE).clicked() {
            out.push(acc(AccessIntent::Close));
        }
    });
    out
}

/// Автоматическая попытка через роутер.
fn auto(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    let a = &model.access;
    let busy = matches!(
        a.stage,
        AccessStage::Searching | AccessStage::Asking | AccessStage::Waiting { .. }
    );
    if ui
        .add_enabled(!busy, egui::Button::new(texts::BTN_ACC_AUTO))
        .clicked()
    {
        out.push(acc(AccessIntent::AccessAuto));
    }
    match a.stage {
        AccessStage::Idle => {}
        AccessStage::Searching => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::ACC_SEARCHING);
            });
        }
        // вопрос с предупреждением «только дома» всегда на виду
        AccessStage::Asking => {
            ui.label(texts::ACC_ASK_ROUTER);
            ui.horizontal(|ui| {
                if ui.button(texts::BTN_ACC_ALLOW).clicked() {
                    out.push(acc(AccessIntent::AccessAllow));
                }
                if ui.button(texts::BTN_ACC_DENY).clicked() {
                    out.push(acc(AccessIntent::AccessDeny));
                }
            });
        }
        AccessStage::Waiting { deadline } => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::ACC_AUTO_WAIT);
            });
            permanent_question(ui, model, out);
            if std::time::Instant::now() >= deadline {
                out.push(acc(AccessIntent::AutoTimeout));
            }
            ui.ctx().request_repaint_after(WAIT_REPAINT);
        }
        AccessStage::Ok => {
            ui.label(texts::ACC_AUTO_OK);
        }
        AccessStage::Failed(status) => {
            warn(ui, texts::ACC_AUTO_FAILED);
            if let Some(t) = status {
                ui.small(t);
            }
        }
    }
    if let Some(m) = model.snapshot.mapping {
        ui.small(core_texts::mapping_text(m));
    }
}

/// Роутер потребовал бессрочную аренду: прежний вопрос 13а, один «да» на этот роутер.
fn permanent_question(ui: &mut egui::Ui, model: &Model, out: &mut Vec<Intent>) {
    let Some(set) = &model.snapshot.settings else {
        return;
    };
    if let Some(r) = set.routers.iter().find(|r| r.needs_permanent) {
        ui.label(core_texts::NEED_PERMANENT_TEXT);
        if ui.button(texts::BTN_YES).clicked() {
            out.push(Intent::Main(MainIntent::Settings(
                SettingsIntent::UpnpPermanentYes(r.id),
            )));
        }
    }
}

/// Пошаговая инструкция. Открыта сама, когда автоматически не получилось.
fn manual(ui: &mut egui::Ui, a: &AccessUi) {
    let failed = matches!(a.stage, AccessStage::Failed(_));
    egui::CollapsingHeader::new(texts::ACC_MANUAL_TITLE)
        .id_salt(("acc-manual", failed))
        .default_open(failed)
        .show(ui, |ui| {
            ui.label(texts::ACC_STEP1);
            if let Some(url) = gateway_url(a) {
                copy_line(ui, "", &url);
            }
            let exact = a.help.as_ref().is_some_and(|h| h.gw_exact);
            ui.small(if exact && gateway_url(a).is_some() {
                texts::ACC_GW_FOUND
            } else {
                texts::ACC_GW_GUESS
            });
            ui.label(texts::ACC_STEP2);
            ui.label(texts::ACC_STEP3);
            ui.horizontal(|ui| {
                ui.label(texts::ACC_STEP4);
                help_mark(ui, texts::ACC_RANGE_NOTE);
            });
            for (label, value) in manual_values(a) {
                copy_line(ui, label, &value);
            }
            if a.help.as_ref().is_some_and(|h| h.home.len() > 1) {
                ui.small(texts::ACC_INT_IP_MANY);
            }
            ui.horizontal(|ui| {
                ui.label(texts::ACC_STEP5);
                help_mark(ui, texts::ACC_KEEP_NOTE);
                help_mark(ui, texts::ACC_PORT_NOTE);
            });
        });
}

/// «Проверить» и «Правило создано».
fn check(ui: &mut egui::Ui, a: &AccessUi, out: &mut Vec<Intent>) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                a.check != CheckUi::Checking,
                egui::Button::new(texts::BTN_ACC_CHECK),
            )
            .clicked()
        {
            out.push(acc(AccessIntent::AccessCheck));
        }
        if ui.button(texts::BTN_ACC_DONE).clicked() {
            out.push(acc(AccessIntent::AccessDone));
        }
    });
    match a.check {
        CheckUi::Idle => {}
        CheckUi::Checking => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::ACC_CHECKING);
            });
        }
        CheckUi::Done(r) => {
            match r {
                CheckResult::Reachable(_) => {
                    ui.label(texts::ACC_CHECK_OK);
                }
                CheckResult::NotReachable(port) => {
                    warn(ui, &check_fail_text(port, &a.first_home()));
                }
                CheckResult::NoServer => {
                    ui.label(texts::ACC_CHECK_NO_SERVER);
                }
                CheckResult::Failed(t) => warn(ui, t),
            }
            ui.small(texts::ACC_CHECK_LIMIT);
        }
    }
    if a.done {
        ui.label(texts::ACC_DONE);
    }
    if let Some(e) = a.error {
        warn(ui, e);
    }
}
